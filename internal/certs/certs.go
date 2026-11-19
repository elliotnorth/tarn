// Package certs obtains and stores the wildcard certificate for tarn's zone,
// using ACME DNS-01 through Cloudflare.
package certs

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/acme/api"
	"github.com/go-acme/lego/v5/certcrypto"
	"github.com/go-acme/lego/v5/certificate"
	"github.com/go-acme/lego/v5/challenge/dns01"
	"github.com/go-acme/lego/v5/lego"
	"github.com/go-acme/lego/v5/providers/dns/cloudflare"
	"github.com/go-acme/lego/v5/registration"
)

// publicResolvers are used for every DNS lookup made during issuance. On a
// tailnet host the system resolver sends names under the zone to tarn itself
// through split DNS, and tarn would claim to be the zone apex, so the
// challenge record would be looked for in a Cloudflare zone that doesn't exist.
var publicResolvers = []string{"1.1.1.1:53", "8.8.8.8:53"}

// Config says what to issue and where to keep it.
type Config struct {
	Zone      string // e.g. t.example.com
	Email     string // optional ACME contact
	Token     string // Cloudflare API token (Zone:Read, DNS:Edit)
	Staging   bool   // use Let's Encrypt's staging service
	Dir       string // state directory
	ExportDir string // also write cert.pem and key.pem here (optional)

	// Obtain replaces the real ACME request and turns off ARI. For tests.
	Obtain func(ctx context.Context) (certPEM, keyPEM []byte, err error)
}

// How often a healthy certificate is re-checked, and how failures back off.
// Let's Encrypt blocks accounts that retry too hard.
const (
	checkEvery = 12 * time.Hour
	minBackoff = 15 * time.Minute
	maxBackoff = 12 * time.Hour
)

// Manager keeps a valid certificate on disk.
type Manager struct {
	cfg    Config
	root   string // staging/ or production/: account key and ledger
	dir    string // zones/<zone> under root: this name's certificate
	obtain func(ctx context.Context) (certPEM, keyPEM []byte, err error)
	ariDue func(ctx context.Context, leaf *x509.Certificate, now time.Time) bool
	now    func() time.Time
	cur    atomic.Pointer[tls.Certificate]

	check, minWait, maxWait time.Duration
	replaces                string // ARI ID of the certificate being renewed

	mu     sync.Mutex
	email  string
	status Status
	seen   bool // a successful check has been logged
}

// Status is what /healthz reports about the certificate.
type Status struct {
	Domain           string     `json:"domain"`
	Staging          bool       `json:"staging"`
	NotAfter         *time.Time `json:"not_after,omitempty"`
	LastIssued       *time.Time `json:"last_issued,omitempty"`  // since tarn started
	LastRenewed      *time.Time `json:"last_renewed,omitempty"` // replaced a working certificate unattended; kept across restarts
	RenewBy          *time.Time `json:"renew_by,omitempty"`     // two thirds of the lifetime; ARI may say earlier
	NextCheck        *time.Time `json:"next_check,omitempty"`
	LastError        string     `json:"last_error,omitempty"`
	ConsecutiveFails int        `json:"consecutive_failures"`
	IssuedThisWeek   int        `json:"issued_this_week"` // from the ledger, against Let's Encrypt's 5 a week
}

// New returns a Manager. Staging and production keep separate accounts and
// certificates, so switching between them never mixes the two.
func New(cfg Config) *Manager {
	sub := "production"
	if cfg.Staging {
		sub = "staging"
	}
	root := filepath.Join(cfg.Dir, sub)
	m := &Manager{
		cfg: cfg, root: root, dir: filepath.Join(root, "zones", cfg.Zone), email: cfg.Email, now: time.Now,
		check: checkEvery, minWait: minBackoff, maxWait: maxBackoff,
	}
	m.obtain = m.obtainACME
	m.ariDue = m.askARI
	if cfg.Obtain != nil {
		m.obtain = cfg.Obtain
		m.ariDue = func(context.Context, *x509.Certificate, time.Time) bool { return false }
	}
	m.status = Status{Domain: m.Domain(), Staging: cfg.Staging}
	if t, ok := m.readRenewed(); ok {
		m.status.LastRenewed = &t
	}
	return m
}

// Status returns a copy of the current certificate state.
func (m *Manager) Status() Status {
	m.mu.Lock()
	s := m.status
	m.mu.Unlock()
	s.IssuedThisWeek = m.IssuedThisWeek(m.now())
	return s
}

// Run keeps the certificate fresh until ctx ends. New certificates take effect
// without a restart. A failure is logged and retried with backoff; it never
// stops tarn, and the current certificate stays in use.
func (m *Manager) Run(ctx context.Context, log *slog.Logger) {
	wait := m.minWait
	for {
		now := m.now()
		leaf, issued, err := m.Ensure(ctx, now)
		if err == nil {
			if xerr := m.export(); xerr != nil {
				err = fmt.Errorf("export: %w", xerr)
			}
		}
		next := m.check
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			next = wait
			wait = min(wait*2, m.maxWait)
			log.Error("certificate update failed; keeping the current certificate", "domain", m.Domain(), "err", err, "retry_in", next)
		} else {
			wait = m.minWait
		}
		first := m.record(issued, err, now, next)
		if err == nil && (issued || first) {
			log.Info("certificate ready", "domain", m.Domain(), "issued", issued, "not_after", leaf.NotAfter, "staging", m.cfg.Staging)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(next):
		}
	}
}

// record updates Status and reports whether this is the first success.
func (m *Manager) record(issued bool, err error, now time.Time, next time.Duration) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if c := m.cur.Load(); c != nil {
		m.status.NotAfter = &c.Leaf.NotAfter
		by := renewBy(c.Leaf)
		m.status.RenewBy = &by
	}
	at := now.Add(next)
	m.status.NextCheck = &at
	if t, ok := m.readRenewed(); ok {
		m.status.LastRenewed = &t
	}
	if issued {
		m.status.LastIssued = &now
	}
	if err != nil {
		m.status.LastError = err.Error()
		m.status.ConsecutiveFails++
		return false
	}
	first := !m.seen
	m.seen = true
	m.status.LastError, m.status.ConsecutiveFails = "", 0
	return first
}

// Domain is the name the certificate covers.
func (m *Manager) Domain() string { return "*." + m.cfg.Zone }

// Ensure returns the stored certificate, issuing a new one first if it is
// missing, doesn't cover the zone or is past two thirds of its lifetime. It
// reports whether it issued one.
func (m *Manager) Ensure(ctx context.Context, now time.Time) (*x509.Certificate, bool, error) {
	if err := os.MkdirAll(m.dir, 0o700); err != nil {
		return nil, false, err
	}
	m.migrateLegacy()
	m.replaces = ""
	renewing := false
	if cert, err := m.load(); err == nil {
		m.cur.Store(cert) // an aging certificate is still better than none
		renewing = true
		if !needsIssue(cert.Leaf, m.Domain(), now) && !m.ariDue(ctx, cert.Leaf, now) {
			return cert.Leaf, false, nil
		}
		if id, err := api.MakeARICertID(cert.Leaf); err == nil {
			m.replaces = id
		}
	}

	if err := m.reserveIssue(now); err != nil {
		return nil, false, err
	}
	certPEM, keyPEM, err := m.obtain(ctx)
	if err != nil {
		return nil, false, err
	}
	// Refuse to replace a working pair with something unusable.
	pair, err := parsePair(certPEM, keyPEM)
	if err != nil {
		return nil, false, fmt.Errorf("issued certificate is unusable: %w", err)
	}
	// A crash between these two writes leaves a mismatched pair, which load
	// rejects, so the next start issues again.
	if err := writeFile(filepath.Join(m.dir, "key.pem"), keyPEM); err != nil {
		return nil, false, err
	}
	if err := writeFile(filepath.Join(m.dir, "cert.pem"), certPEM); err != nil {
		return nil, false, err
	}
	m.markIssued()
	if renewing {
		m.writeRenewed(now)
	}
	m.cur.Store(pair)
	return pair.Leaf, true, nil
}

// GetCertificate is for tls.Config. It fails until Ensure has a certificate.
func (m *Manager) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	if c := m.cur.Load(); c != nil {
		return c, nil
	}
	return nil, errors.New("no certificate yet")
}

// export copies the certificate to ExportDir if it has changed. The key goes
// first, so anything watching cert.pem sees a complete pair. Files are 0640:
// a setgid directory gives them the group of whatever reads them.
func (m *Manager) export() error {
	if m.cfg.ExportDir == "" {
		return nil
	}
	certPEM, err := os.ReadFile(filepath.Join(m.dir, "cert.pem"))
	if err != nil {
		return err
	}
	keyPEM, err := os.ReadFile(filepath.Join(m.dir, "key.pem"))
	if err != nil {
		return err
	}
	dst := filepath.Join(m.cfg.ExportDir, "cert.pem")
	if cur, err := os.ReadFile(dst); err == nil && bytes.Equal(cur, certPEM) {
		return nil
	}
	if err := writeFileMode(filepath.Join(m.cfg.ExportDir, "key.pem"), keyPEM, 0o640); err != nil {
		return err
	}
	return writeFileMode(dst, certPEM, 0o640)
}

func (m *Manager) load() (*tls.Certificate, error) {
	certPEM, err := os.ReadFile(filepath.Join(m.dir, "cert.pem"))
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(filepath.Join(m.dir, "key.pem"))
	if err != nil {
		return nil, err
	}
	return parsePair(certPEM, keyPEM)
}

func parsePair(certPEM, keyPEM []byte) (*tls.Certificate, error) {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	if pair.Leaf == nil {
		if pair.Leaf, err = x509.ParseCertificate(pair.Certificate[0]); err != nil {
			return nil, err
		}
	}
	return &pair, nil
}

// needsIssue reports whether leaf should be replaced. The two-thirds point
// follows the certificate's actual lifetime, so shorter CA lifetimes need no
// change here.
func needsIssue(leaf *x509.Certificate, domain string, now time.Time) bool {
	if needsIssueForName(leaf, domain) {
		return true
	}
	return !now.Before(renewBy(leaf))
}

// renewBy is when tarn renews at the latest: two thirds of the certificate's
// actual lifetime. ARI can ask for it sooner.
func renewBy(leaf *x509.Certificate) time.Time {
	return leaf.NotBefore.Add(leaf.NotAfter.Sub(leaf.NotBefore) * 2 / 3)
}

// The time of the last unattended renewal is kept beside the certificate, so
// the status page can show it after a restart.
func (m *Manager) renewedPath() string { return filepath.Join(m.dir, "last-renewal") }

func (m *Manager) readRenewed() (time.Time, bool) {
	b, err := os.ReadFile(m.renewedPath())
	if err != nil {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, strings.TrimSpace(string(b)))
	return t, err == nil
}

func (m *Manager) writeRenewed(now time.Time) {
	writeFile(m.renewedPath(), []byte(now.UTC().Format(time.RFC3339)+"\n")) // best effort: only for display
}

func needsIssueForName(leaf *x509.Certificate, domain string) bool {
	return !slices.Contains(leaf.DNSNames, domain)
}

func (m *Manager) obtainACME(ctx context.Context) ([]byte, []byte, error) {
	key, err := m.accountKey()
	if err != nil {
		return nil, nil, err
	}
	email := m.contact()
	user := &account{email: email, key: key}
	lc := lego.NewConfig(user)
	if m.cfg.Staging {
		lc.CADirURL = lego.DirectoryURLLetsEncryptStaging
	}
	client, err := lego.NewClient(lc)
	if err != nil {
		return nil, nil, fmt.Errorf("acme client: %w", err)
	}

	opts := dns01.NewOptions()
	opts.RecursiveNameservers = publicResolvers
	dns01.SetDefaultClient(dns01.NewClient(opts))

	cf := cloudflare.NewDefaultConfig()
	cf.AuthToken = m.cfg.Token
	cf.ZoneToken = m.cfg.Token
	provider, err := cloudflare.NewDNSProviderConfig(cf)
	if err != nil {
		return nil, nil, err
	}
	if err := client.Challenge.SetDNS01Provider(provider); err != nil {
		return nil, nil, err
	}

	// Registering again with an existing key returns the existing account.
	reg, err := client.Registration.Register(ctx, registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return nil, nil, fmt.Errorf("acme registration: %w", err)
	}
	user.reg = reg
	// Registering an existing key doesn't change its contact.
	if email != "" && !slices.Contains(reg.Contact, "mailto:"+email) {
		if _, err := client.Registration.UpdateRegistration(ctx, registration.RegisterOptions{TermsOfServiceAgreed: true}); err != nil {
			return nil, nil, fmt.Errorf("acme contact update: %w", err)
		}
	}

	req := certificate.ObtainRequest{
		Domains: []string{m.Domain()},
		KeyType: certcrypto.EC256,
		Bundle:  true,
		// Naming the certificate being replaced exempts an ARI renewal from
		// Let's Encrypt's rate limits.
		ReplacesCertID: m.replaces,
	}
	res, err := client.Certificate.Obtain(ctx, req)
	if err != nil && req.ReplacesCertID != "" && strings.Contains(err.Error(), "alreadyReplaced") {
		// A renewal was issued but never saved, for example a crash in between.
		req.ReplacesCertID = ""
		res, err = client.Certificate.Obtain(ctx, req)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("obtain %s: %w", m.Domain(), err)
	}
	return res.Certificate, res.PrivateKey, nil
}

// askARI asks the CA whether to renew now (RFC 9773). Any failure means "no",
// and the two-thirds rule in needsIssue still applies.
func (m *Manager) askARI(ctx context.Context, leaf *x509.Certificate, now time.Time) bool {
	key, err := m.accountKey()
	if err != nil {
		return false
	}
	lc := lego.NewConfig(&account{email: m.contact(), key: key})
	if m.cfg.Staging {
		lc.CADirURL = lego.DirectoryURLLetsEncryptStaging
	}
	client, err := lego.NewClient(lc)
	if err != nil {
		return false
	}
	info, err := client.Certificate.GetRenewalInfo(ctx, leaf)
	if err != nil {
		return false
	}
	return info.ShouldRenewAt(now, m.check) != nil
}

// accountKey loads the ACME account key, creating it on first use.
func (m *Manager) accountKey() (crypto.Signer, error) {
	path := filepath.Join(m.root, "account.key")
	data, err := os.ReadFile(path)
	if err == nil {
		return certcrypto.ParsePEMPrivateKey(data)
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	key, err := certcrypto.GeneratePrivateKey(certcrypto.EC256)
	if err != nil {
		return nil, err
	}
	if err := writeFile(path, certcrypto.PEMEncode(key)); err != nil {
		return nil, err
	}
	return key, nil
}

// account is the ACME user lego acts for.
type account struct {
	email string
	key   crypto.Signer
	reg   *acme.ExtendedAccount
}

func (a *account) GetEmail() string                       { return a.email }
func (a *account) GetRegistration() *acme.ExtendedAccount { return a.reg }
func (a *account) GetPrivateKey() crypto.Signer           { return a.key }

func writeFile(path string, data []byte) error { return writeFileMode(path, data, 0o600) }

// writeFileMode replaces path atomically (temp file, fsync, rename), so readers
// never see a half-written key or certificate.
func writeFileMode(path string, data []byte, mode os.FileMode) (err error) {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			f.Close()
			os.Remove(f.Name())
		}
	}()
	if err = f.Chmod(mode); err != nil && !errors.Is(err, errors.ErrUnsupported) {
		return err
	}
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	// Make the rename durable. Directories can't be synced on Windows.
	if d, derr := os.Open(dir); derr == nil {
		d.Sync()
		d.Close()
	}
	return nil
}
