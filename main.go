// Command tarn gives every device on a Tailscale network a name
// on your own domain: an authoritative DNS server for one zone answering
// <peer>.<zone> from the tailnet peer list, a wildcard certificate on that
// zone, and a reverse proxy for listed services.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"codeberg.org/miekg/dns/dnsutil"

	"golang.org/x/crypto/bcrypt"

	"github.com/elliotnorth/tarn/internal/certs"
	"github.com/elliotnorth/tarn/internal/dnsserver"
	"github.com/elliotnorth/tarn/internal/health"
	"github.com/elliotnorth/tarn/internal/index"
	"github.com/elliotnorth/tarn/internal/peers"
	"github.com/elliotnorth/tarn/internal/proxy"
	"github.com/elliotnorth/tarn/internal/settings"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

const minAdminPassword = 12

var refreshMu sync.Mutex

type config struct {
	zone         string
	listen       string
	source       string
	tailscale    string
	socket       string
	interval     time.Duration
	ttl          uint
	mgmt         string
	tokenFile    string
	metrics      bool
	cfTokenFile  string
	acmeEmail    string
	acmeStaging  bool
	stateDir     string
	servicesFile string
	exportDir    string
	adminFile    string
	configPath   string
	explicit     map[string]bool // flags given on the command line
	showVersion  bool
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "doctor":
			os.Exit(runDoctor(os.Args[2:], os.Stdout))
		case "status":
			os.Exit(runStatus(os.Args[2:], os.Stdout))
		case "backup":
			os.Exit(runBackup(os.Args[2:], os.Stdout))
		case "restore":
			os.Exit(runRestore(os.Args[2:], os.Stdout))
		}
	}
	var c config
	fs := flag.NewFlagSet("tarn", flag.ExitOnError)
	fs.StringVar(&c.zone, "zone", "", "DNS zone to serve, e.g. t.example.com (required)")
	fs.StringVar(&c.listen, "listen", "", "DNS listen address (default: this node's tailnet IPv4, port 53)")
	fs.StringVar(&c.source, "source", "cli", `where to read the peer list: "cli" (tailscale status --json) or "localapi" (tailscaled socket)`)
	fs.StringVar(&c.tailscale, "tailscale", "tailscale", "path to the tailscale binary (source=cli)")
	fs.StringVar(&c.socket, "socket", peers.DefaultSocket, "tailscaled LocalAPI socket (source=localapi)")
	fs.DurationVar(&c.interval, "interval", 30*time.Second, "peer list refresh interval")
	fs.UintVar(&c.ttl, "ttl", 60, "TTL in seconds for answers and negative caching")
	fs.StringVar(&c.mgmt, "mgmt", "127.0.0.1:9580", "management HTTP address for /healthz and /records (loopback only)")
	fs.StringVar(&c.tokenFile, "records-token-file", "", "file holding a bearer token required on /records (optional)")
	fs.BoolVar(&c.metrics, "metrics", false, "serve Prometheus metrics at /metrics on the management address")
	fs.StringVar(&c.cfTokenFile, "cloudflare-token-file", "", "file holding a Cloudflare API token; setting it turns on wildcard certificate issuance")
	fs.StringVar(&c.acmeEmail, "acme-email", "", "contact address for the ACME account (optional)")
	fs.BoolVar(&c.acmeStaging, "acme-staging", false, "use Let's Encrypt's staging service (certificates are not trusted)")
	fs.StringVar(&c.stateDir, "state-dir", "/var/lib/tarn", "directory for the ACME account, certificate and key")
	fs.StringVar(&c.servicesFile, "services-file", "", "file of \"name upstream-url\" lines to reverse-proxy on port 443 (needs -cloudflare-token-file)")
	fs.StringVar(&c.exportDir, "export-dir", "", "also write cert.pem and key.pem here for nginx or traefik (needs -cloudflare-token-file)")
	fs.StringVar(&c.adminFile, "admin-password-file", "", "file holding the status page password; setting it allows changing services from the page (needs -services-file)")
	fs.StringVar(&c.configPath, "config", "", "tarn's config file, in the state directory; needed to change settings from the page")
	fs.BoolVar(&c.showVersion, "version", false, "print the version and exit")
	fs.Parse(os.Args[1:])
	c.explicit = map[string]bool{}
	fs.Visit(func(f *flag.Flag) { c.explicit[f.Name] = true })

	if c.showVersion {
		fmt.Println("tarn", version)
		return
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(c, log); err != nil {
		log.Error("exiting", "err", err)
		os.Exit(1)
	}
}

// resolveConfig merges the config file under the flags: a flag given on the
// command line always wins.
func resolveConfig(c *config) (file settings.Values, exists bool, err error) {
	if c.configPath == "" {
		return file, false, nil
	}
	if file, exists, err = settings.Load(c.configPath); err != nil || !exists {
		return file, exists, err
	}
	take := func(name string, apply func()) {
		if !c.explicit[name] {
			apply()
		}
	}
	take("zone", func() { c.zone = file.Zone })
	take("listen", func() { c.listen = file.Listen })
	take("source", func() { c.source = file.Source })
	take("interval", func() { c.interval = time.Duration(file.IntervalSeconds) * time.Second })
	take("ttl", func() { c.ttl = uint(file.TTL) })
	take("acme-email", func() { c.acmeEmail = file.ACMEEmail })
	take("acme-staging", func() { c.acmeStaging = file.ACMEStaging })
	take("services-file", func() { c.servicesFile = file.ServicesFile })
	take("export-dir", func() { c.exportDir = file.ExportDir })
	return file, true, nil
}

// pinnedKeys names the settings the page must not change, because a flag would
// override them again at the next start.
func pinnedKeys(explicit map[string]bool) map[string]bool {
	out := map[string]bool{}
	for flagName, key := range map[string]string{
		"zone": keyZone, "listen": keyListen, "source": keySource, "interval": keyInterval, "ttl": keyTTL,
		"acme-email": keyEmail, "acme-staging": keyStaging, "records-token-file": "records_token",
	} {
		if explicit[flagName] {
			out[key] = true
		}
	}
	return out
}

func run(c config, log *slog.Logger) error {
	file, configExists, err := resolveConfig(&c)
	if err != nil {
		return fmt.Errorf("-config: %w", err)
	}
	zone, err := checkZone(c.zone)
	if err != nil {
		return err
	}
	if c.interval < time.Second {
		return errors.New("-interval must be at least 1s")
	}
	if c.ttl > 86400 {
		return errors.New("-ttl must be at most 86400")
	}
	if err := health.CheckLoopback(c.mgmt); err != nil {
		return err
	}
	token, err := readSecret("-records-token-file", c.tokenFile)
	if err != nil {
		return err
	}
	cfToken, err := readSecret("-cloudflare-token-file", c.cfTokenFile)
	if err != nil {
		return err
	}

	if c.exportDir != "" {
		if cfToken == "" {
			return errors.New("-export-dir needs -cloudflare-token-file for its certificate")
		}
		if st, err := os.Stat(c.exportDir); err != nil || !st.IsDir() {
			return fmt.Errorf("-export-dir %q must be an existing directory", c.exportDir)
		}
	}

	adminPassword, adminWarning := loadAdminPassword(c.adminFile)
	if file.AdminPasswordHash != "" {
		adminWarning = "" // a password set on the page doesn't need the file
	}
	// A password changed on the page is in the config file and beats the
	// credential file. To reset a forgotten one, delete that field.
	adminOn := adminPassword != "" || file.AdminPasswordHash != ""
	if adminOn && c.servicesFile == "" {
		adminOn, adminWarning = false, "Editing is off because -services-file isn't set."
	}
	if adminWarning != "" {
		log.Warn("editing from the status page is off", "reason", adminWarning)
	}

	var svc *proxy.Manager
	if c.servicesFile != "" {
		if cfToken == "" {
			return errors.New("-services-file needs -cloudflare-token-file for its certificate")
		}
		if svc, err = proxy.OpenManager(c.servicesFile, zone, log, adminOn || c.adminFile != ""); err != nil {
			return fmt.Errorf("-services-file: %w", err)
		}
	}

	sourceFor := func(name string) peers.Source {
		if name == "localapi" {
			return peers.LocalAPI{Socket: c.socket}
		}
		return peers.CLI{Path: c.tailscale}
	}
	if c.source != "cli" && c.source != "localapi" {
		return fmt.Errorf(`-source must be "cli" or "localapi", not %q`, c.source)
	}

	values := settings.Values{
		Zone: zone, Listen: c.listen, Source: c.source, IntervalSeconds: int(c.interval / time.Second), TTL: uint32(c.ttl),
		ACMEEmail: c.acmeEmail, ACMEStaging: c.acmeStaging, ServicesFile: c.servicesFile, ExportDir: c.exportDir,
		RecordsTokenSHA256: file.RecordsTokenSHA256, AdminPasswordHash: file.AdminPasswordHash,
	}
	if c.configPath != "" && !configExists {
		if err := settings.Save(c.configPath, values); err != nil {
			return fmt.Errorf("-config: %w", err)
		}
		log.Info("wrote the config file from the current flags", "path", c.configPath)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	store := &index.Store{}
	stats := &dnsserver.Stats{}
	rt := &controller{
		log: log, ctx: ctx, configPath: c.configPath, stateDir: c.stateDir, pinned: pinnedKeys(c.explicit),
		cfToken: cfToken, exportDir: c.exportDir, store: store, svc: svc, stats: stats, sourceFor: sourceFor,
		errc: make(chan error, 8), wake: make(chan struct{}, 1), now: time.Now, window: confirmWindow,
		bcryptCost: bcrypt.DefaultCost + 2, isLocal: isLocalAddr, v: values, listenAuto: c.listen == "",
		newCert: func(z string, staging bool, email string) *certs.Manager {
			return certs.New(certs.Config{Zone: z, Email: email, Token: cfToken, Staging: staging, Dir: c.stateDir, ExportDir: c.exportDir})
		},
	}
	rt.save = func(v settings.Values) error {
		if c.configPath == "" {
			return errors.New("no -config file")
		}
		return settings.Save(c.configPath, v)
	}
	if cfToken != "" {
		rt.cf = &certs.Cloudflare{Token: cfToken}
	}
	if c.configPath != "" {
		rt.history = settings.OpenHistory(filepath.Join(c.stateDir, "history"))
	}
	rt.setZones([]string{zone}, uint32(c.ttl))
	rt.interval.Store(int64(c.interval))
	rt.password.Store(&secret{hash: file.AdminPasswordHash, plain: adminPassword})
	managed := file.RecordsTokenSHA256
	if token != "" {
		managed = ""
	}
	rt.tokenHash.Store(&managed)
	rt.src.set(sourceFor(c.source))
	rt.dnsHandler = dnsserver.HandlerFor(rt.respondersNow, log)

	// First refresh happens before serving, so the default listen address can
	// come from this node's own tailnet IP.
	st, err := refresh(ctx, &rt.src, store, log, rt.names)
	if err != nil {
		return fmt.Errorf("first peer list read failed: %w", err)
	}

	if self, err := defaultListen(st); err == nil {
		rt.selfListen = self
	} else if c.listen == "" {
		return err
	}
	listen := c.listen
	if listen == "" {
		listen = rt.selfListen
	}
	var proxyAddr string
	if svc != nil {
		if proxyAddr, err = selfAddr(st, "443"); err != nil {
			return err
		}
	}
	go func() {
		if err := refreshLoop(ctx, &rt.src, store, log, rt.intervalNow, rt.wake, rt.watched, rt.names); err != nil {
			rt.errc <- err
		}
	}()

	mgmt := &health.Server{
		Store: store, Interval: c.interval, IntervalNow: rt.intervalNow, Token: token, TokenHash: rt.TokenHash,
		Version: version, Zone: zone, ZoneNow: rt.zoneNow, Log: log, AdminWarning: adminWarning,
		DNS:     func() any { return stats.Snapshot() },
		Metrics: c.metrics,
	}
	if svc != nil {
		mgmt.Services = func() any { return svc.List() }
	}
	if adminOn {
		mgmt.Admin = &health.Admin{Check: rt.CheckPassword, Put: rt.PutService, Delete: rt.DeleteService}
		if c.configPath != "" {
			mgmt.Admin.Control = rt
		}
		svc.OnChange = func() { refresh(ctx, &rt.src, store, log, rt.names) }
	}
	if cfToken != "" {
		cm := rt.newCert(zone, c.acmeStaging, c.acmeEmail)
		rt.certs.Replace(cm)
		rt.mu.Lock()
		rt.runCert(cm)
		rt.mu.Unlock()
		mgmt.TLS = rt.tlsStatus
	}

	// Management HTTP, loopback only.
	hs := &http.Server{
		Addr:              c.mgmt,
		Handler:           mgmt.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		if err := hs.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			rt.errc <- fmt.Errorf("management server: %w", err)
		}
	}()

	// DNS over UDP.
	ds, err := rt.startDNS(listen)
	if err != nil {
		return err
	}
	rt.mu.Lock()
	rt.ds, rt.listenAddr = ds, listen
	rt.mu.Unlock()
	log.Info("tarn started", "version", version, "zone", zone, "dns", listen, "mgmt", c.mgmt, "source", c.source, "config", c.configPath)

	// Issuance runs beside DNS and never stops it: a failure here must not
	// take names down, or cause a restart loop that hits CA rate limits.
	var ps *http.Server
	if cfToken != "" {
		if svc != nil {
			ps = &http.Server{
				Addr:              proxyAddr,
				Handler:           svc.Router(),
				TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: rt.certs.GetCertificate},
				ReadHeaderTimeout: 10 * time.Second,
				IdleTimeout:       2 * time.Minute,
			}
			go func() {
				if err := ps.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
					rt.errc <- fmt.Errorf("proxy on %s: %w", proxyAddr, err)
				}
			}()
			log.Info("proxy started", "addr", proxyAddr, "services", len(svc.Names()), "editable", adminOn)
		}
	}

	select {
	case <-ctx.Done():
		log.Info("shutting down")
	case err = <-rt.errc:
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	hs.Shutdown(shutdownCtx)
	if ps != nil {
		ps.Shutdown(shutdownCtx)
	}
	rt.mu.Lock()
	cur := rt.ds
	rt.mu.Unlock()
	rt.stopDNS(cur)
	return err
}

// refreshLoop re-reads the peer list every interval until ctx ends. If watched
// is set and this node's tailnet IP no longer matches it, tarn would answer
// nothing while still looking healthy, so the loop returns an error: tarn
// exits and systemd restarts it on the new address.
func refreshLoop(ctx context.Context, src peers.Source, store *index.Store, log *slog.Logger, interval func() time.Duration, wake <-chan struct{}, watched func() string, services func() []string) error {
	t := time.NewTimer(interval())
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-wake: // the interval changed
			t.Reset(interval())
		case <-t.C:
			st, err := refresh(ctx, src, store, log, services)
			t.Reset(interval())
			want := watched()
			if err != nil || want == "" {
				continue
			}
			if now, err := defaultListen(st); err == nil && now != want {
				return fmt.Errorf("this node's tailnet IP changed: listening on %s, now %s", want, now)
			}
		}
	}
}

// refresh reads the peer list once and swaps in a new index. On failure the
// last good index stays in place.
func refresh(ctx context.Context, src peers.Source, store *index.Store, log *slog.Logger, services func() []string) (*peers.Status, error) {
	// One at a time, so a slow older read can't undo a service just changed.
	refreshMu.Lock()
	defer refreshMu.Unlock()
	rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	st, err := src.Status(rctx)
	if err != nil {
		store.Fail(time.Now(), err)
		if store.Load() != nil { // the first read's failure is reported by run
			log.Warn("peer list refresh failed; keeping the last good index", "err", err)
		}
		return nil, err
	}
	var names []string
	if services != nil {
		names = services()
	}
	idx := index.Build(st, time.Now(), names...)
	prev := store.Load()
	store.Swap(idx)
	if prev == nil || prev.Len() != idx.Len() || len(prev.Collisions) != len(idx.Collisions) {
		log.Info("peer list loaded", "records", idx.Len(), "collisions", len(idx.Collisions), "skipped", len(idx.Skipped))
	}
	return st, nil
}

func checkZone(z string) (string, error) {
	z = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(z), "."))
	if z == "" {
		return "", errors.New("-zone is required, e.g. -zone t.example.com")
	}
	if !dnsutil.IsName(dnsutil.Fqdn(z)) || !strings.Contains(z, ".") {
		return "", fmt.Errorf("-zone %q is not a valid domain name with at least two labels", z)
	}
	for _, l := range strings.Split(z, ".") {
		if peers.Label(l) != l {
			return "", fmt.Errorf("-zone %q: label %q must be letters, digits and hyphens", z, l)
		}
	}
	return z, nil
}

func defaultListen(st *peers.Status) (string, error) { return selfAddr(st, "53") }

func selfAddr(st *peers.Status, port string) (string, error) {
	if st.Self == nil || len(st.Self.IPv4) == 0 {
		return "", errors.New("can't find this node's tailnet IPv4 address; set -listen explicitly")
	}
	return net.JoinHostPort(st.Self.IPv4[0].String(), port), nil
}

// loadAdminPassword never fails: a bad password file turns editing off with a
// warning on the page, because it must not take DNS down.
func loadAdminPassword(path string) (password, warning string) {
	pw, err := readSecret("-admin-password-file", path)
	if err != nil {
		return "", "Editing is off: " + err.Error()
	}
	if pw != "" && len(pw) < minAdminPassword {
		return "", fmt.Sprintf("Editing is off: the password in -admin-password-file must be at least %d characters.", minAdminPassword)
	}
	return pw, ""
}

func readSecret(flagName, path string) (string, error) {
	if path == "" {
		return "", nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("%s: %w", flagName, err)
	}
	t := strings.TrimSpace(string(b))
	if t == "" {
		return "", fmt.Errorf("%s is empty", flagName)
	}
	return t, nil
}
