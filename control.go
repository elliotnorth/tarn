package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/mail"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"codeberg.org/miekg/dns"
	"golang.org/x/crypto/bcrypt"

	"github.com/elliotnorth/tarn/internal/certs"
	"github.com/elliotnorth/tarn/internal/dnsserver"
	"github.com/elliotnorth/tarn/internal/health"
	"github.com/elliotnorth/tarn/internal/index"
	"github.com/elliotnorth/tarn/internal/peers"
	"github.com/elliotnorth/tarn/internal/proxy"
	"github.com/elliotnorth/tarn/internal/settings"
)

const (
	confirmWindow      = 60 * time.Second
	refreshCooldown    = 5 * time.Second
	cloudflareCooldown = 10 * time.Second
	minInterval        = 5
	maxInterval        = 3600
	maxPassword        = 72 // bcrypt's limit
	hidden             = "(hidden)"
)

// Setting keys. Anything else is refused, which is what keeps the tailscale
// binary, the management address, the state directory and the Cloudflare token
// out of the page's reach.
const (
	keyTTL      = "ttl"
	keyInterval = "interval"
	keySource   = "source"
	keyEmail    = "acme_email"
	keyZone     = "zone"
	keyListen   = "listen"
	keyStaging  = "staging"
	keyPassword = "password"
)

func isRisky(key string) bool {
	return key == keyZone || key == keyListen || key == keyStaging || key == keyPassword
}

type zoneChecker interface {
	Verify(ctx context.Context) error
	CheckZone(ctx context.Context, zone string) error
}

// swapSource lets the peer source change while the refresh loop runs.
type swapSource struct{ cur atomic.Pointer[peers.Source] }

func (s *swapSource) set(src peers.Source) { s.cur.Store(&src) }
func (s *swapSource) Status(ctx context.Context) (*peers.Status, error) {
	return (*s.cur.Load()).Status(ctx)
}

type secret struct {
	hash  string // bcrypt, from the config file
	plain string // from -admin-password-file, until the page changes it
}

// pendingChange is a risky change that is running but not saved. Nothing reaches
// the config file until Keep, so a crash also reverts it.
type pendingChange struct {
	key, oldText, newText, source string
	deadline                      time.Time
	timer                         *time.Timer
	commit                        func(*settings.Values)
	finish, undo                  func()
	confirmHash                   string // Keep must prove the new password
	waitCert, certDone            bool
	certErr                       string
}

// controller owns everything that can change while tarn runs. It is what the
// status page talks to, through health.Control.
type controller struct {
	log        *slog.Logger
	ctx        context.Context
	configPath string
	stateDir   string
	pinned     map[string]bool
	cfToken    string
	exportDir  string
	cf         zoneChecker
	src        swapSource
	store      *index.Store
	svc        *proxy.Manager
	stats      *dnsserver.Stats
	history    *settings.History
	sourceFor  func(name string) peers.Source
	certs      certs.Set
	newCert    func(zone string, staging bool, email string) *certs.Manager
	errc       chan error
	wake       chan struct{}
	dnsHandler dns.Handler

	// Replaced in tests.
	now        func() time.Time
	window     time.Duration
	bcryptCost int
	isLocal    func(netip.Addr) bool
	save       func(settings.Values) error

	responders atomic.Pointer[[]*dnsserver.Responder]
	interval   atomic.Int64 // nanoseconds
	password   atomic.Pointer[secret]
	tokenHash  atomic.Pointer[string]

	changeMu sync.Mutex     // one change at a time, including its network checks
	issuing  sync.WaitGroup // certificate attempts for pending changes

	mu             sync.Mutex
	v              settings.Values
	pending        *pendingChange
	cm             *certs.Manager
	cmCancel       context.CancelFunc
	ds             *dns.Server
	listenAddr     string
	selfListen     string
	listenAuto     bool
	tailnetBound   bool // the proxy or an extra DNS address is on the tailnet IP
	lastRefresh    time.Time
	lastCloudflare time.Time
	stopFns        sync.Map // *dns.Server -> func()
}

func (c *controller) setResponders(zones []string, ttl uint32) {
	list := make([]*dnsserver.Responder, len(zones))
	for i, z := range zones {
		list[i] = &dnsserver.Responder{Zone: z, TTL: ttl, Index: c.store.Load, Stats: c.stats}
	}
	c.responders.Store(&list)
}

func (c *controller) respondersNow() []*dnsserver.Responder { return *c.responders.Load() }

// setZones points DNS and the proxy at zones, the first being the main one.
// Both answer during a zone change, so the page stays reachable until Keep.
func (c *controller) setZones(zones []string, ttl uint32) {
	c.setResponders(zones, ttl)
	if c.svc != nil {
		c.svc.SetZones(zones...)
	}
}

func (c *controller) intervalNow() time.Duration { return time.Duration(c.interval.Load()) }

func (c *controller) zoneNow() string { return c.respondersNow()[0].Zone }

func (c *controller) names() []string {
	if c.svc == nil {
		return nil
	}
	return c.svc.Names()
}

func (c *controller) watched() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.listenAuto || c.tailnetBound {
		return c.selfListen
	}
	return ""
}

func (c *controller) nudge() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

// startDNS binds first, so a bad address fails here with nothing changed. It
// returns once the server is running, because Shutdown panics on a server whose
// goroutine hasn't got as far as initializing it.
func (c *controller) startDNS(addr string) (*dns.Server, error) {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("dns server on %s: %w", addr, err)
	}
	var stopped atomic.Bool
	started := make(chan struct{})
	failed := make(chan error, 1)
	ds := &dns.Server{PacketConn: pc, Net: "udp", Handler: c.dnsHandler,
		NotifyStartedFunc: func(context.Context) { close(started) }}
	go func() {
		err := ds.ListenAndServe()
		if err == nil || stopped.Load() {
			return
		}
		err = fmt.Errorf("dns server on %s: %w", addr, err)
		select {
		case <-started:
			c.errc <- err
		default:
			failed <- err
		}
	}()
	select {
	case <-started:
	case err := <-failed:
		pc.Close()
		return nil, err
	}
	c.stopFns.Store(ds, func() { stopped.Store(true) })
	return ds, nil
}

func (c *controller) stopDNS(ds *dns.Server) {
	if f, ok := c.stopFns.LoadAndDelete(ds); ok {
		f.(func())()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ds.Shutdown(ctx)
}

func (c *controller) runCert(m *certs.Manager) {
	ctx, cancel := context.WithCancel(c.ctx)
	c.cm, c.cmCancel = m, cancel
	go m.Run(ctx, c.log)
}

func (c *controller) tlsStatus() any {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cm.Status()
}

// CheckPassword reports whether pw is the page password.
func (c *controller) CheckPassword(pw string) bool {
	s := c.password.Load()
	if s.hash != "" {
		return bcrypt.CompareHashAndPassword([]byte(s.hash), []byte(pw)) == nil
	}
	a, b := sha256.Sum256([]byte(pw)), sha256.Sum256([]byte(s.plain))
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

// TokenHash is the hex SHA-256 of the page-managed records token, or "".
func (c *controller) TokenHash() string { return *c.tokenHash.Load() }

func (c *controller) valueOf(key string) string {
	switch key {
	case keyTTL:
		return strconv.FormatUint(uint64(c.v.TTL), 10)
	case keyInterval:
		return strconv.Itoa(c.v.IntervalSeconds)
	case keySource:
		return c.v.Source
	case keyEmail:
		return c.v.ACMEEmail
	case keyZone:
		return c.v.Zone
	case keyListen:
		return c.v.Listen
	case keyStaging:
		return strconv.FormatBool(c.v.ACMEStaging)
	}
	return ""
}

func (c *controller) current(key string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.valueOf(key)
}

// validate checks a new value and returns it normalized. It changes nothing.
func (c *controller) validate(ctx context.Context, req health.ChangeRequest) (string, error) {
	key, value := req.Key, strings.TrimSpace(req.Value)
	if key != keyTTL && key != keyInterval && key != keySource && key != keyEmail && !isRisky(key) {
		return "", fmt.Errorf("%q can't be changed from this page", key)
	}
	if c.pinned[key] {
		return "", fmt.Errorf("%s is set on the command line. Remove that flag to change it here", key)
	}
	if key != keyPassword && value == c.current(key) {
		return "", errors.New("that's already the current value")
	}
	switch key {
	case keyTTL:
		n, err := strconv.ParseUint(value, 10, 32)
		if err != nil || n > 86400 {
			return "", errors.New("TTL must be a whole number of seconds from 0 to 86400")
		}
		return strconv.FormatUint(n, 10), nil
	case keyInterval:
		n, err := strconv.Atoi(value)
		if err != nil || n < minInterval || n > maxInterval {
			return "", fmt.Errorf("the refresh interval must be from %d to %d seconds", minInterval, maxInterval)
		}
		return strconv.Itoa(n), nil
	case keySource:
		if value == "none" || c.current(keySource) == "none" {
			return "", errors.New("running without Tailscale is set with -source in the config file or on the command line, not from the page")
		}
		if value != "cli" && value != "localapi" {
			return "", errors.New(`the source must be "cli" or "localapi"`)
		}
		rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		if _, err := c.sourceFor(value).Status(rctx); err != nil {
			return "", fmt.Errorf("can't read the device list that way: %w", err)
		}
		return value, nil
	case keyEmail:
		if value != "" {
			if a, err := mail.ParseAddress(value); err != nil || a.Address != value {
				return "", errors.New("that isn't a valid email address")
			}
		}
		return value, nil
	case keyZone:
		zone, err := checkZone(value)
		if err != nil {
			return "", errors.New(strings.TrimPrefix(err.Error(), "-zone "))
		}
		if zone == c.current(keyZone) {
			return "", errors.New("that's already the current value")
		}
		if c.svc != nil {
			if err := c.svc.CheckZone(zone); err != nil {
				return "", err
			}
		}
		if c.cf != nil {
			if err := c.cf.CheckZone(ctx, zone); err != nil {
				return "", err
			}
		}
		return zone, nil
	case keyListen:
		return c.validateListen(value)
	case keyStaging:
		if value != "true" && value != "false" {
			return "", errors.New(`staging must be "true" or "false"`)
		}
		if c.cfToken == "" {
			return "", errors.New("HTTPS is off")
		}
		return value, nil
	case keyPassword:
		if !c.CheckPassword(req.CurrentPassword) {
			return "", errors.New("the current password is wrong")
		}
		if len(req.Value) < minAdminPassword || len(req.Value) > maxPassword {
			return "", fmt.Errorf("the new password must be %d to %d characters", minAdminPassword, maxPassword)
		}
		return req.Value, nil
	}
	return "", errors.New("unknown setting")
}

func (c *controller) validateListen(value string) (string, error) {
	if value == "" {
		c.mu.Lock()
		self := c.selfListen
		c.mu.Unlock()
		if self == "" {
			return "", errors.New("there's no tailnet IP to default to, so enter an address")
		}
		return "", nil
	}
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		host, port = strings.Trim(value, "[]"), "53"
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return "", errors.New("enter an IP address, with an optional port")
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return "", errors.New("that isn't a valid port")
	}
	if ip.IsUnspecified() || !c.isLocal(ip) {
		return "", fmt.Errorf("%s isn't an address on this machine", ip)
	}
	addr := net.JoinHostPort(ip.String(), port)
	if addr == c.current(keyListen) {
		return "", errors.New("that's already the current value")
	}
	return addr, nil
}

func isLocalAddr(ip netip.Addr) bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			if got, ok := netip.AddrFromSlice(n.IP); ok && got.Unmap() == ip.Unmap() {
				return true
			}
		}
	}
	return false
}

// Preview says what a change will do, without doing it.
func (c *controller) Preview(ctx context.Context, req health.ChangeRequest) (health.Preview, error) {
	if !c.changeMu.TryLock() {
		return health.Preview{}, errors.New("another change is in progress")
	}
	defer c.changeMu.Unlock()
	if err := c.notPending(); err != nil {
		return health.Preview{}, err
	}
	value, err := c.validate(ctx, req)
	if err != nil {
		return health.Preview{}, err
	}
	p := health.Preview{Key: req.Key, Risky: isRisky(req.Key)}
	if p.Risky {
		p.Notes = append(p.Notes, fmt.Sprintf("Tarn applies this now and undoes it after %d seconds unless you press Keep.", int(c.window.Seconds())))
	}
	switch req.Key {
	case keyZone:
		p.Summary = fmt.Sprintf("Move every name from %s to %s.", c.current(keyZone), value)
		c.certNotes(&p, value, c.current(keyStaging) == "true")
		p.Notes = append(p.Notes,
			"Services keep their short names under the new zone.",
			"After Keep, change split DNS "+c.dnsSettings()+" yourself. Tarn never touches the tailnet.",
			"Both names work until you press Keep. Keep ends the old one, so open the page on the new name afterwards.")
	case keyStaging:
		staging := value == "true"
		p.Summary = "Switch to Let's Encrypt's " + map[bool]string{true: "staging", false: "production"}[staging] + " service."
		c.certNotes(&p, c.current(keyZone), staging)
		if staging {
			p.Notes = append(p.Notes, "Staging certificates aren't trusted by browsers.")
		}
	case keyListen:
		shown := value
		if shown == "" {
			shown = "this machine's tailnet IP"
		}
		p.Summary = "Answer DNS on " + shown + "."
		p.Notes = append(p.Notes, "The old address keeps answering until you press Keep.", "If the address changes, update the nameserver "+c.dnsSettings()+".")
	case keyPassword:
		p.Summary = "Change the page password."
		p.Notes = append(p.Notes, "Every other signed-in browser is signed out.", "Keep asks for the new password, to prove you have it.")
	default:
		p.Summary = "This applies immediately."
	}
	return p, nil
}

// dnsSettings says where the tailnet's split DNS is set.
func (c *controller) dnsSettings() string {
	if idx := c.store.Load(); idx != nil && idx.SelfHosted {
		return "in Headscale's config.yaml"
	}
	return "in the Tailscale admin console"
}

func (c *controller) certNotes(p *health.Preview, zone string, staging bool) {
	if c.cfToken == "" {
		return
	}
	m := c.newCert(zone, staging, c.current(keyEmail))
	if !m.WillIssue(c.now()) {
		p.Notes = append(p.Notes, "A stored certificate for this will be reused, so none is issued.")
		return
	}
	p.Issues = true
	p.Notes = append(p.Notes, fmt.Sprintf("This uses 1 of Let's Encrypt's 5 certificates per week for %s. Tarn has used %d in the last 7 days.", m.Domain(), m.IssuedThisWeek(c.now())))
}

func (c *controller) notPending() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pending != nil {
		return errors.New("finish the change that's waiting for Keep first")
	}
	return nil
}

// Change applies a setting. Live settings are saved first and applied once
// saved. Risky ones run unsaved until Keep.
func (c *controller) Change(ctx context.Context, req health.ChangeRequest) (health.ChangeResult, error) {
	if !c.changeMu.TryLock() {
		return health.ChangeResult{}, errors.New("another change is in progress")
	}
	defer c.changeMu.Unlock()
	if err := c.notPending(); err != nil {
		return health.ChangeResult{}, err
	}
	value, err := c.validate(ctx, req)
	if err != nil {
		return health.ChangeResult{}, err
	}
	if isRisky(req.Key) {
		if err := c.startPending(req, value); err != nil {
			return health.ChangeResult{}, err
		}
		return health.ChangeResult{Status: "pending", LogoutOthers: req.Key == keyPassword}, nil
	}
	if err := c.applyLive(req.Key, value, req.Source); err != nil {
		return health.ChangeResult{}, err
	}
	return health.ChangeResult{Status: "applied"}, nil
}

func (c *controller) applyLive(key, value, source string) error {
	c.mu.Lock()
	old := c.valueOf(key)
	next := c.v
	switch key {
	case keyTTL:
		n, _ := strconv.ParseUint(value, 10, 32)
		next.TTL = uint32(n)
	case keyInterval:
		next.IntervalSeconds, _ = strconv.Atoi(value)
	case keySource:
		next.Source = value
	case keyEmail:
		next.ACMEEmail = value
	}
	if err := c.save(next); err != nil {
		c.mu.Unlock()
		return fmt.Errorf("can't save the config file: %w", err)
	}
	c.v = next
	cm := c.cm
	zone := next.Zone
	c.mu.Unlock()

	switch key {
	case keyTTL:
		c.setResponders([]string{zone}, next.TTL)
	case keyInterval:
		c.interval.Store(int64(next.IntervalSeconds) * int64(time.Second))
		c.nudge()
	case keySource:
		c.src.set(c.sourceFor(value))
	case keyEmail:
		if cm != nil {
			cm.SetEmail(value)
		}
	}
	c.record("setting", key, old, value, source, true)
	return nil
}

func (c *controller) record(kind, key, old, new, source string, undoable bool) {
	c.log.Info("change applied", "kind", kind, "key", key, "old", old, "new", new, "source", source)
	if c.history == nil {
		return
	}
	if err := c.history.Add(settings.Entry{Time: c.now(), Kind: kind, Key: key, Old: old, New: new, Source: source, Undoable: undoable}); err != nil {
		c.log.Warn("can't save the change history", "err", err)
	}
}

// startPending applies a risky change. Nothing is issued in a loop: a pending
// certificate is requested exactly once per change.
func (c *controller) startPending(req health.ChangeRequest, value string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	p := &pendingChange{key: req.Key, oldText: c.valueOf(req.Key), newText: value, source: req.Source, deadline: c.now().Add(c.window)}
	var err error
	switch req.Key {
	case keyZone:
		c.pendZone(p, value)
	case keyStaging:
		c.pendStaging(p, value == "true")
	case keyListen:
		err = c.pendListen(p, value)
	case keyPassword:
		err = c.pendPassword(p, value)
	}
	if err != nil {
		return err
	}
	c.pending = p
	p.timer = time.AfterFunc(c.window, func() { c.expire(p) })
	c.log.Info("change waiting for Keep", "key", p.key, "old", p.oldText, "new", p.newText, "source", p.source, "seconds", int(c.window.Seconds()))
	return nil
}

// issueOnce makes one attempt for a pending change.
func (c *controller) issueOnce(ctx context.Context, p *pendingChange, m *certs.Manager) {
	_, _, err := m.Ensure(ctx, c.now())
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pending != p { // startPending holds mu until pending is set
		return
	}
	p.certDone = true
	if err != nil {
		p.certErr = err.Error()
		c.log.Error("certificate for the pending change failed", "domain", m.Domain(), "err", err)
	}
}

func (c *controller) pendZone(p *pendingChange, zone string) {
	old, ttl := c.v.Zone, c.v.TTL
	c.setZones([]string{zone, old}, ttl)
	p.commit = func(v *settings.Values) { v.Zone = zone }
	var m *certs.Manager
	ctx, cancel := context.WithCancel(c.ctx)
	if c.cfToken != "" {
		m = c.newCert(zone, c.v.ACMEStaging, c.v.ACMEEmail)
		c.certs.Replace(m, c.cm)
		p.waitCert = true
		c.issuing.Go(func() { c.issueOnce(ctx, p, m) })
	}
	p.undo = func() {
		cancel()
		c.setZones([]string{old}, ttl)
		if m != nil {
			c.certs.Replace(c.cm)
		}
	}
	p.finish = func() {
		cancel()
		if m != nil {
			c.swapCert(m)
		}
		c.setZones([]string{zone}, c.v.TTL)
	}
}

func (c *controller) pendStaging(p *pendingChange, staging bool) {
	m := c.newCert(c.v.Zone, staging, c.v.ACMEEmail)
	ctx, cancel := context.WithCancel(c.ctx)
	c.certs.Replace(m, c.cm)
	p.waitCert = true
	c.issuing.Go(func() { c.issueOnce(ctx, p, m) })
	p.commit = func(v *settings.Values) { v.ACMEStaging = staging }
	p.undo = func() {
		cancel()
		c.certs.Replace(c.cm)
	}
	p.finish = func() {
		cancel()
		c.swapCert(m)
	}
}

// swapCert makes m the running Manager. It already holds a certificate, so its
// Run has nothing to request.
func (c *controller) swapCert(m *certs.Manager) {
	if c.cmCancel != nil {
		c.cmCancel()
	}
	c.runCert(m)
	c.certs.Replace(m)
}

func (c *controller) pendListen(p *pendingChange, value string) error {
	addr := value
	if addr == "" {
		addr = c.selfListen
	}
	if addr == c.listenAddr {
		return errors.New("tarn is already answering on that address")
	}
	ds, err := c.startDNS(addr)
	if err != nil {
		return err
	}
	old := c.ds
	p.commit = func(v *settings.Values) { v.Listen = value }
	p.undo = func() { c.stopDNS(ds) }
	p.finish = func() {
		c.stopDNS(old)
		c.ds, c.listenAddr, c.listenAuto = ds, addr, value == ""
	}
	return nil
}

func (c *controller) pendPassword(p *pendingChange, value string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(value), c.bcryptCost)
	if err != nil {
		return err
	}
	old := c.password.Load()
	c.password.Store(&secret{hash: string(hash)})
	p.oldText, p.newText = hidden, hidden
	p.confirmHash = string(hash)
	p.commit = func(v *settings.Values) { v.AdminPasswordHash = string(hash) }
	p.undo = func() { c.password.Store(old) }
	p.finish = func() {}
	return nil
}

// Keep saves a pending change. If it can't be saved, the change is undone.
func (c *controller) Keep(password, source string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	p := c.pending
	if p == nil {
		return errors.New("nothing is waiting for Keep")
	}
	if p.waitCert && !p.certDone {
		return errors.New("still waiting for the certificate")
	}
	if p.certErr != "" {
		return errors.New("the certificate failed, so this can't be kept: " + p.certErr)
	}
	if p.confirmHash != "" && bcrypt.CompareHashAndPassword([]byte(p.confirmHash), []byte(password)) != nil {
		return errors.New("that isn't the new password")
	}
	next := c.v
	p.commit(&next)
	if err := c.save(next); err != nil {
		p.timer.Stop()
		p.undo()
		c.pending = nil
		return fmt.Errorf("can't save the config file, so the change was undone: %w", err)
	}
	p.timer.Stop()
	c.v = next
	p.finish()
	c.pending = nil
	c.record("setting", p.key, p.oldText, p.newText, source, p.key != keyPassword)
	return nil
}

// Revert undoes a pending change straight away.
func (c *controller) Revert(source string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	p := c.pending
	if p == nil {
		return errors.New("nothing is waiting for Keep")
	}
	p.timer.Stop()
	p.undo()
	c.pending = nil
	c.log.Info("change undone", "key", p.key, "source", source)
	return nil
}

func (c *controller) expire(p *pendingChange) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pending != p {
		return
	}
	p.undo()
	c.pending = nil
	c.log.Warn("change undone: Keep wasn't pressed in time", "key", p.key, "old", p.oldText)
}

// SetRecordsToken turns the page-managed token on or off. The token exists in
// the reply and nowhere else: only its hash is stored.
func (c *controller) SetRecordsToken(enabled bool, source string) (string, error) {
	if c.pinned["records_token"] {
		return "", errors.New("the records token is set on the command line. Remove -records-token-file to manage it here")
	}
	if err := c.notPending(); err != nil {
		return "", err
	}
	token, sum := "", ""
	if enabled {
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			return "", err
		}
		token = hex.EncodeToString(raw)
		h := sha256.Sum256([]byte(token))
		sum = hex.EncodeToString(h[:])
	}
	c.mu.Lock()
	next := c.v
	next.RecordsTokenSHA256 = sum
	if err := c.save(next); err != nil {
		c.mu.Unlock()
		return "", fmt.Errorf("can't save the config file: %w", err)
	}
	c.v = next
	c.mu.Unlock()
	c.tokenHash.Store(&sum)
	state := map[bool]string{true: "on", false: "off"}[enabled]
	c.record("setting", "records_token", hidden, state, source, false)
	return token, nil
}

// RefreshNow re-reads the device list, at most once per cooldown.
func (c *controller) RefreshNow(ctx context.Context, source string) error {
	c.mu.Lock()
	if now := c.now(); now.Sub(c.lastRefresh) < refreshCooldown {
		c.mu.Unlock()
		return fmt.Errorf("%w: wait a few seconds", health.ErrRateLimited)
	} else {
		c.lastRefresh = now
	}
	c.mu.Unlock()
	_, err := refresh(ctx, &c.src, c.store, c.log, c.names)
	c.log.Info("device list refreshed from the page", "source", source)
	return err
}

// CheckCloudflare reports whether the token works. The page can never see it.
func (c *controller) CheckCloudflare(ctx context.Context) error {
	if c.cf == nil {
		return errors.New("HTTPS is off")
	}
	c.mu.Lock()
	if now := c.now(); now.Sub(c.lastCloudflare) < cloudflareCooldown {
		c.mu.Unlock()
		return fmt.Errorf("%w: wait a few seconds", health.ErrRateLimited)
	} else {
		c.lastCloudflare = now
	}
	c.mu.Unlock()
	return c.cf.Verify(ctx)
}

// PutService and DeleteService are the page's service edits, with history.
func (c *controller) PutService(name, upstream string, preserve bool, source string) error {
	if err := c.notPending(); err != nil {
		return err
	}
	name = strings.ToLower(name)
	old := c.upstreamOf(name)
	if err := c.svc.Put(name, upstream, preserve); err != nil {
		return err
	}
	c.record("service", name, old, c.upstreamOf(name), source, true)
	return nil
}

func (c *controller) DeleteService(name, source string) error {
	if err := c.notPending(); err != nil {
		return err
	}
	old := c.upstreamOf(name)
	if err := c.svc.Delete(name); err != nil {
		return err
	}
	c.record("service", name, old, "", source, true)
	return nil
}

// upstreamOf returns a service as one string, in the services file's form, for
// the history. Undo splits it again.
func (c *controller) upstreamOf(name string) string {
	for _, s := range c.svc.List() {
		if s.Name == name {
			if s.PreserveHost {
				return s.Upstream + " host=preserve"
			}
			return s.Upstream
		}
	}
	return ""
}

// History lists the changes, newest first.
func (c *controller) History() any {
	if c.history == nil {
		return []settings.Entry{}
	}
	return c.history.List()
}

// Undo applies an entry's old value as a new change, through the same checks.
func (c *controller) Undo(ctx context.Context, id, source string) (health.ChangeResult, error) {
	e, ok := c.history.Get(id)
	if !ok {
		return health.ChangeResult{}, errors.New("that change isn't in the history")
	}
	if !e.Undoable {
		return health.ChangeResult{}, errors.New("that change can't be undone")
	}
	if e.Kind == "service" {
		var err error
		if e.Old == "" {
			err = c.DeleteService(e.Key, source)
		} else {
			f := strings.Fields(e.Old)
			err = c.PutService(e.Key, f[0], len(f) > 1, source)
		}
		return health.ChangeResult{Status: "applied"}, err
	}
	return c.Change(ctx, health.ChangeRequest{Key: e.Key, Value: e.Old, Source: source})
}

// Settings is what the page shows.
func (c *controller) Settings() health.SettingsView {
	c.mu.Lock()
	defer c.mu.Unlock()
	v := health.SettingsView{
		Values: map[string]string{
			keyTTL: c.valueOf(keyTTL), keyInterval: c.valueOf(keyInterval), keySource: c.valueOf(keySource),
			keyEmail: c.valueOf(keyEmail), keyZone: c.valueOf(keyZone), keyListen: c.valueOf(keyListen), keyStaging: c.valueOf(keyStaging),
		},
		Pinned:       c.pinned,
		ListenNow:    c.listenAddr,
		HTTPS:        c.cfToken != "",
		TokenOn:      *c.tokenHash.Load() != "",
		TokenConsole: c.pinned["records_token"],
	}
	if p := c.pending; p != nil {
		v.Pending = &health.PendingView{
			Key: p.key, Old: p.oldText, New: p.newText,
			SecondsLeft:    max(0, int(p.deadline.Sub(c.now()).Seconds())+1),
			WaitingForCert: p.waitCert && !p.certDone,
			Error:          p.certErr,
			NeedsPassword:  p.confirmHash != "",
		}
	}
	return v
}
