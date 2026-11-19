package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/netip"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/elliotnorth/Tarn/internal/certs"
	"github.com/elliotnorth/Tarn/internal/dnsserver"
	"github.com/elliotnorth/Tarn/internal/health"
	"github.com/elliotnorth/Tarn/internal/index"
	"github.com/elliotnorth/Tarn/internal/peers"
	"github.com/elliotnorth/Tarn/internal/proxy"
	"github.com/elliotnorth/Tarn/internal/settings"
)

const firstPassword = "the first password"

type fakeCF struct{ err error }

func (f *fakeCF) Verify(context.Context) error            { return f.err }
func (f *fakeCF) CheckZone(context.Context, string) error { return f.err }

type rig struct {
	*controller
	config string
	cf     *fakeCF

	mu      sync.Mutex
	issued  map[string]int
	failing bool
}

func (r *rig) count(zone string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.issued[zone]
}

// zoneCert returns an error rather than failing t: it runs on the certificate
// goroutines, where t.Fatal isn't allowed.
func zoneCert(zone string) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "t"},
		DNSNames: []string{"*." + zone}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(90 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	k, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: k}), nil
}

type okSource struct{}

func (okSource) Status(context.Context) (*peers.Status, error) {
	p := peers.Peer{ID: "n0", Name: "tarn", Self: true, IPv4: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}
	return &peers.Status{Self: &p, Peers: []peers.Peer{p}}, nil
}

type badSource struct{}

func (badSource) Status(context.Context) (*peers.Status, error) {
	return nil, errors.New("no socket")
}

func freeUDP(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	return pc.LocalAddr().String()
}

func newRig(t *testing.T) *rig {
	t.Helper()
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, cancel := context.WithCancel(context.Background())

	svc, err := proxy.OpenManager(filepath.Join(dir, "services"), "t.example.com", log, true)
	if err != nil {
		t.Fatal(err)
	}
	r := &rig{config: filepath.Join(dir, "config"), cf: &fakeCF{}, issued: map[string]int{}}
	values := settings.Values{Zone: "t.example.com", Source: "cli", IntervalSeconds: 30, TTL: 60}
	if err := settings.Save(r.config, values); err != nil {
		t.Fatal(err)
	}
	store := &index.Store{}
	c := &controller{
		log: log, ctx: ctx, configPath: r.config, stateDir: dir, pinned: map[string]bool{}, cfToken: "x", cf: r.cf,
		store: store, svc: svc, stats: &dnsserver.Stats{}, history: settings.OpenHistory(filepath.Join(dir, "history")),
		errc: make(chan error, 8), wake: make(chan struct{}, 1), now: time.Now, window: time.Hour, // tests call expireNow
		bcryptCost: bcrypt.MinCost, isLocal: func(ip netip.Addr) bool { return ip.IsLoopback() }, v: values, listenAuto: true,
		save: func(v settings.Values) error { return settings.Save(r.config, v) },
		sourceFor: func(name string) peers.Source {
			if name == "localapi" {
				return badSource{}
			}
			return okSource{}
		},
	}
	c.newCert = func(z string, staging bool, email string) *certs.Manager {
		return certs.New(certs.Config{Zone: z, Email: email, Staging: staging, Dir: dir, Obtain: func(context.Context) ([]byte, []byte, error) {
			r.mu.Lock()
			defer r.mu.Unlock()
			if r.failing {
				return nil, nil, errors.New("validation failed")
			}
			r.issued[z]++
			return zoneCert(z)
		}})
	}
	r.controller = c
	// Finish any certificate write before t.TempDir is removed.
	t.Cleanup(func() {
		cancel()
		c.issuing.Wait()
	})
	c.setZones([]string{"t.example.com"}, 60)
	c.interval.Store(int64(30 * time.Second))
	c.password.Store(&secret{plain: firstPassword})
	empty := ""
	c.tokenHash.Store(&empty)
	c.src.set(okSource{})
	c.dnsHandler = dnsserver.HandlerFor(c.respondersNow, log)
	if _, err := refresh(ctx, &c.src, store, log, c.names); err != nil {
		t.Fatal(err)
	}
	addr := freeUDP(t)
	ds, err := c.startDNS(addr)
	if err != nil {
		t.Fatal(err)
	}
	c.ds, c.listenAddr, c.selfListen = ds, addr, addr
	t.Cleanup(func() {
		c.mu.Lock()
		cur := c.ds
		c.mu.Unlock()
		c.stopDNS(cur)
	})

	cm := c.newCert("t.example.com", false, "")
	c.certs.Replace(cm)
	c.mu.Lock()
	c.runCert(cm)
	c.mu.Unlock()
	waitFor(t, "the first certificate", cm.Ready)
	return r
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); !ok(); time.Sleep(2 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
	}
}

func (r *rig) change(key, value string) (health.ChangeResult, error) {
	return r.Change(context.Background(), health.ChangeRequest{Key: key, Value: value, Source: "100.64.0.9"})
}

func (r *rig) saved(t *testing.T) settings.Values {
	t.Helper()
	v, ok, err := settings.Load(r.config)
	if err != nil || !ok {
		t.Fatalf("load: %v %v", ok, err)
	}
	return v
}

func (r *rig) noPending() bool { return r.Settings().Pending == nil }

// expireNow does what the Keep timer does, without depending on how fast the
// host happens to be.
func (r *rig) expireNow(t *testing.T) {
	t.Helper()
	r.controller.mu.Lock()
	p := r.pending
	r.controller.mu.Unlock()
	if p == nil {
		t.Fatal("nothing is pending")
	}
	p.timer.Stop()
	r.expire(p)
}

func (r *rig) certDone() bool {
	p := r.Settings().Pending
	return p != nil && !p.WaitingForCert
}

// Shutdown panics if the server goroutine hasn't run yet. One CPU makes the
// new goroutine wait, which is how this showed up on a 1-vCPU host.
func TestDNSCanStopRightAfterStart(t *testing.T) {
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	c := &controller{log: log, ctx: context.Background(), errc: make(chan error, 8),
		dnsHandler: dnsserver.Handler(&dnsserver.Responder{Zone: "t.example.com"}, log)}
	for range 20 {
		ds, err := c.startDNS("127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		c.stopDNS(ds)
	}
}

func TestLiveSettingsApplyAndSave(t *testing.T) {
	r := newRig(t)
	for key, value := range map[string]string{keyTTL: "120", keyInterval: "45", keySource: "cli", keyEmail: "admin@example.com"} {
		if key == keySource {
			continue // already cli; covered below
		}
		res, err := r.change(key, value)
		if err != nil || res.Status != "applied" {
			t.Fatalf("%s: %+v, %v", key, res, err)
		}
	}
	if got := r.respondersNow()[0].TTL; got != 120 {
		t.Errorf("TTL = %d", got)
	}
	if got := r.intervalNow(); got != 45*time.Second {
		t.Errorf("interval = %v", got)
	}
	v := r.saved(t)
	if v.TTL != 120 || v.IntervalSeconds != 45 || v.ACMEEmail != "admin@example.com" {
		t.Errorf("saved = %+v", v)
	}
	if got := r.history.List(); len(got) != 3 || got[0].Source != "100.64.0.9" {
		t.Errorf("history = %+v", got)
	}
}

func TestRefusedSettings(t *testing.T) {
	r := newRig(t)
	for _, key := range []string{"tailscale", "tailscale_path", "socket", "mgmt", "state_dir", "cloudflare_token", "services_file", "export_dir", "records_token_sha256", "admin_password_hash"} {
		if _, err := r.change(key, "/bin/sh"); err == nil || !strings.Contains(err.Error(), "can't be changed") {
			t.Errorf("%s: %v", key, err)
		}
	}
	if _, err := r.Preview(context.Background(), health.ChangeRequest{Key: "tailscale", Value: "/bin/sh"}); err == nil {
		t.Error("Preview accepted a refused key")
	}
}

func TestBadValuesChangeNothing(t *testing.T) {
	r := newRig(t)
	for _, c := range [][2]string{
		{keyTTL, "-1"}, {keyTTL, "86401"}, {keyTTL, "abc"},
		{keyInterval, "4"}, {keyInterval, "3601"},
		{keySource, "exec"}, {keySource, "localapi"}, // this rig's localapi can't be read
		{keyEmail, "not an email"},
		{keyZone, "com"}, {keyZone, "bad_zone.example.com"},
		{keyListen, "8.8.8.8:53"}, {keyListen, "0.0.0.0:53"}, {keyListen, "not an ip"},
		{keyStaging, "maybe"},
		{keyTTL, "60"}, // no change
	} {
		if _, err := r.change(c[0], c[1]); err == nil {
			t.Errorf("%s=%q was accepted", c[0], c[1])
		}
	}
	if got := len(r.history.List()); got != 0 {
		t.Errorf("history has %d entries", got)
	}
	if !r.noPending() {
		t.Error("a change is pending")
	}
}

func TestPinnedSettingsAreRefused(t *testing.T) {
	r := newRig(t)
	r.pinned[keyZone], r.pinned["records_token"] = true, true
	if _, err := r.change(keyZone, "new.example.com"); err == nil || !strings.Contains(err.Error(), "command line") {
		t.Errorf("zone: %v", err)
	}
	if _, err := r.SetRecordsToken(true, "x"); err == nil {
		t.Error("the records token was changed")
	}
}

func TestFailedSaveChangesNothing(t *testing.T) {
	r := newRig(t)
	r.save = func(settings.Values) error { return errors.New("disk full") }
	if _, err := r.change(keyTTL, "120"); err == nil {
		t.Fatal("want an error")
	}
	if got := r.respondersNow()[0].TTL; got != 60 {
		t.Errorf("TTL = %d", got)
	}
	if r.Settings().Values[keyTTL] != "60" {
		t.Error("the value changed")
	}
}

func TestZoneRevertsWithoutKeep(t *testing.T) {
	r := newRig(t)
	res, err := r.change(keyZone, "new.example.com")
	if err != nil || res.Status != "pending" {
		t.Fatalf("%+v, %v", res, err)
	}
	if got := len(r.respondersNow()); got != 2 || r.zoneNow() != "new.example.com" {
		t.Errorf("zones during the wait: %d, %s", got, r.zoneNow())
	}
	if r.saved(t).Zone != "t.example.com" {
		t.Error("a pending zone reached the config file")
	}
	waitFor(t, "the certificate", r.certDone)
	r.expireNow(t)
	if got := r.respondersNow(); len(got) != 1 || got[0].Zone != "t.example.com" {
		t.Errorf("zones after revert: %+v", got)
	}
	if r.saved(t).Zone != "t.example.com" {
		t.Error("the config file changed")
	}
	if got := len(r.history.List()); got != 0 {
		t.Errorf("a reverted change is in the history: %d", got)
	}
	issued := r.count("new.example.com")
	if issued != 1 {
		t.Errorf("issued %d, want 1", issued)
	}

	// Trying again reuses the stored certificate.
	if _, err := r.change(keyZone, "new.example.com"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the certificate", r.certDone)
	if got := r.count("new.example.com"); got != issued {
		t.Errorf("issued %d, want %d", got, issued)
	}
}

func TestZoneKeep(t *testing.T) {
	r := newRig(t)
	if _, err := r.change(keyZone, "new.example.com"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the certificate", r.certDone)
	if err := r.Keep("", "100.64.0.9"); err != nil {
		t.Fatal(err)
	}
	if got := r.respondersNow(); len(got) != 1 || got[0].Zone != "new.example.com" {
		t.Errorf("zones: %+v", got)
	}
	if r.saved(t).Zone != "new.example.com" {
		t.Error("not saved")
	}
	if got := r.history.List(); len(got) != 1 || got[0].Old != "t.example.com" || got[0].New != "new.example.com" {
		t.Errorf("history: %+v", got)
	}
	st := r.tlsStatus().(certs.Status)
	if st.Domain != "*.new.example.com" {
		t.Errorf("status = %+v", st)
	}
}

func TestZoneRefusedWithoutCloudflareAccess(t *testing.T) {
	r := newRig(t)
	r.cf.err = errors.New("the token can't see that zone")
	ctx := context.Background()
	if _, err := r.Preview(ctx, health.ChangeRequest{Key: keyZone, Value: "new.example.com"}); err == nil {
		t.Error("Preview accepted it")
	}
	if _, err := r.change(keyZone, "new.example.com"); err == nil {
		t.Error("Change accepted it")
	}
	if !r.noPending() || r.count("new.example.com") != 0 {
		t.Error("something was applied or issued")
	}
}

func TestZoneRefusedIfAnUpstreamWouldLoop(t *testing.T) {
	r := newRig(t)
	if err := r.PutService("app", "https://app.other.example.com", false, "x"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.change(keyZone, "other.example.com"); err == nil || !strings.Contains(err.Error(), "loop") {
		t.Errorf("err = %v", err)
	}
}

func TestZonePreviewChecklist(t *testing.T) {
	r := newRig(t)
	p, err := r.Preview(context.Background(), health.ChangeRequest{Key: keyZone, Value: "new.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	all := strings.Join(p.Notes, " ")
	for _, want := range []string{"5 certificates", "split DNS", "short names", "Keep"} {
		if !strings.Contains(all, want) {
			t.Errorf("missing %q in %q", want, all)
		}
	}
	if !p.Risky || !p.Issues {
		t.Errorf("preview = %+v", p)
	}
	if r.count("new.example.com") != 0 || !r.noPending() {
		t.Error("Preview changed something")
	}
}

func TestKeepWaitsForTheCertificate(t *testing.T) {
	r := newRig(t)
	r.mu.Lock()
	r.failing = true
	r.mu.Unlock()
	if _, err := r.change(keyZone, "new.example.com"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the failed attempt", r.certDone)
	if err := r.Keep("", "x"); err == nil || !strings.Contains(err.Error(), "certificate failed") {
		t.Errorf("Keep = %v", err)
	}
	if err := r.Revert("x"); err != nil {
		t.Fatal(err)
	}
	if r.zoneNow() != "t.example.com" {
		t.Errorf("zone = %s", r.zoneNow())
	}
}

func TestStagingReusesStoredCertificate(t *testing.T) {
	r := newRig(t)
	if _, err := r.change(keyStaging, "true"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "staging", r.certDone)
	if err := r.Keep("", "x"); err != nil {
		t.Fatal(err)
	}
	if !r.saved(t).ACMEStaging {
		t.Error("not saved")
	}
	before := r.count("t.example.com")
	if _, err := r.change(keyStaging, "false"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "production", r.certDone)
	if got := r.count("t.example.com"); got != before {
		t.Errorf("issued %d more", got-before)
	}
}

func TestListenRevertAndKeep(t *testing.T) {
	r := newRig(t)
	addr := freeUDP(t)
	if _, err := r.change(keyListen, addr); err != nil {
		t.Fatal(err)
	}
	if _, err := net.ListenPacket("udp", addr); err == nil {
		t.Error("the new address isn't bound during the wait")
	}
	r.expireNow(t)
	waitFor(t, "the address to be free", func() bool {
		pc, err := net.ListenPacket("udp", addr)
		if err == nil {
			pc.Close()
		}
		return err == nil
	})
	if r.saved(t).Listen != "" || r.listenAddr == addr {
		t.Error("the listen address changed")
	}

	old := r.listenAddr
	if _, err := r.change(keyListen, addr); err != nil {
		t.Fatal(err)
	}
	if err := r.Keep("", "x"); err != nil {
		t.Fatal(err)
	}
	if r.saved(t).Listen != addr || r.listenAddr != addr {
		t.Errorf("saved %q, running %q", r.saved(t).Listen, r.listenAddr)
	}
	waitFor(t, "the old address to be free", func() bool {
		pc, err := net.ListenPacket("udp", old)
		if err == nil {
			pc.Close()
		}
		return err == nil
	})
}

func passwordChange(current, next string) health.ChangeRequest {
	return health.ChangeRequest{Key: keyPassword, Value: next, CurrentPassword: current, Source: "x"}
}

func TestPasswordChange(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	const next = "a much better password"
	if _, err := r.Change(ctx, passwordChange("wrong", next)); err == nil {
		t.Error("the wrong current password was accepted")
	}
	if _, err := r.Change(ctx, passwordChange(firstPassword, "short")); err == nil {
		t.Error("a short password was accepted")
	}
	if _, err := r.Change(ctx, passwordChange(firstPassword, strings.Repeat("x", maxPassword+1))); err == nil {
		t.Error("an overlong password was accepted")
	}
	res, err := r.Change(ctx, passwordChange(firstPassword, next))
	if err != nil || res.Status != "pending" || !res.LogoutOthers {
		t.Fatalf("%+v, %v", res, err)
	}
	if !r.Settings().Pending.NeedsPassword {
		t.Error("Keep should ask for the new password")
	}
	if err := r.Keep(firstPassword, "x"); err == nil {
		t.Error("Keep accepted the old password")
	}
	if err := r.Keep(next, "x"); err != nil {
		t.Fatal(err)
	}
	if !r.CheckPassword(next) || r.CheckPassword(firstPassword) {
		t.Error("the password didn't change")
	}
	if h := r.saved(t).AdminPasswordHash; h == "" || strings.Contains(h, next) {
		t.Errorf("hash = %q", h)
	}
}

// This one uses the real timer, and only asserts what's true once it has fired.
func TestPasswordRevertsWithoutKeep(t *testing.T) {
	r := newRig(t)
	r.window = 50 * time.Millisecond
	if _, err := r.Change(context.Background(), passwordChange(firstPassword, "a much better password")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the auto-revert", r.noPending)
	if !r.CheckPassword(firstPassword) {
		t.Error("the old password doesn't work")
	}
	if r.saved(t).AdminPasswordHash != "" {
		t.Error("the hash was saved")
	}
}

func TestPendingBlocksOtherChanges(t *testing.T) {
	r := newRig(t)
	if _, err := r.change(keyZone, "new.example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.change(keyTTL, "120"); err == nil {
		t.Error("a setting changed during the wait")
	}
	if err := r.PutService("app", "http://127.0.0.1:1", false, "x"); err == nil {
		t.Error("a service was added during the wait")
	}
	if err := r.DeleteService("app", "x"); err == nil {
		t.Error("a service was removed during the wait")
	}
	if _, err := r.SetRecordsToken(true, "x"); err == nil {
		t.Error("the token changed during the wait")
	}
	if err := r.Revert("x"); err != nil {
		t.Fatal(err)
	}
}

func TestFailedKeepSaveUndoesTheChange(t *testing.T) {
	r := newRig(t)
	if _, err := r.change(keyZone, "new.example.com"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the certificate", r.certDone)
	r.save = func(settings.Values) error { return errors.New("disk full") }
	if err := r.Keep("", "x"); err == nil || !strings.Contains(err.Error(), "undone") {
		t.Fatalf("Keep = %v", err)
	}
	if r.zoneNow() != "t.example.com" || !r.noPending() {
		t.Errorf("zone = %s", r.zoneNow())
	}
}

func TestRecordsTokenShownOnceAndHashed(t *testing.T) {
	r := newRig(t)
	token, err := r.SetRecordsToken(true, "x")
	if err != nil || len(token) != 64 {
		t.Fatalf("%q, %v", token, err)
	}
	if h := r.saved(t).RecordsTokenSHA256; h == "" || h == token {
		t.Errorf("stored %q", h)
	}
	if !r.Settings().TokenOn {
		t.Error("TokenOn is false")
	}
	b, _ := json.Marshal(r.Settings())
	if strings.Contains(string(b), token) {
		t.Error("the token is in the settings view")
	}
	if _, err := r.SetRecordsToken(false, "x"); err != nil {
		t.Fatal(err)
	}
	if r.TokenHash() != "" || r.saved(t).RecordsTokenSHA256 != "" {
		t.Error("the token is still on")
	}
}

func TestHistoryHoldsNoSecrets(t *testing.T) {
	r := newRig(t)
	token, _ := r.SetRecordsToken(true, "x")
	const next = "a much better password"
	if _, err := r.Change(context.Background(), passwordChange(firstPassword, next)); err != nil {
		t.Fatal(err)
	}
	if err := r.Keep(next, "x"); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(r.history.List())
	for _, secret := range []string{token, next, firstPassword, "$2a$"} {
		if strings.Contains(string(b), secret) {
			t.Errorf("history contains %q: %s", secret, b)
		}
	}
	for _, e := range r.history.List() {
		if e.Undoable {
			t.Errorf("%s should not be undoable", e.Key)
		}
	}
}

func TestUndo(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	if _, err := r.change(keyTTL, "120"); err != nil {
		t.Fatal(err)
	}
	res, err := r.Undo(ctx, r.history.List()[0].ID, "x")
	if err != nil || res.Status != "applied" {
		t.Fatalf("%+v, %v", res, err)
	}
	if r.respondersNow()[0].TTL != 60 || r.saved(t).TTL != 60 {
		t.Error("TTL wasn't restored")
	}
	if got := len(r.history.List()); got != 2 {
		t.Errorf("an undo should be a change: %d entries", got)
	}

	if err := r.PutService("app", "http://127.0.0.1:1", false, "x"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Undo(ctx, r.history.List()[0].ID, "x"); err != nil {
		t.Fatal(err)
	}
	if len(r.svc.List()) != 0 {
		t.Error("the added service wasn't removed")
	}

	// A risky setting goes through Keep again.
	if _, err := r.change(keyZone, "new.example.com"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the certificate", r.certDone)
	if err := r.Keep("", "x"); err != nil {
		t.Fatal(err)
	}
	res, err = r.Undo(ctx, r.history.List()[0].ID, "x")
	if err != nil || res.Status != "pending" {
		t.Fatalf("%+v, %v", res, err)
	}
	if err := r.Revert("x"); err != nil {
		t.Fatal(err)
	}

	if _, err := r.Undo(ctx, "missing", "x"); err == nil {
		t.Error("undo of an unknown entry")
	}
}

func TestUndoKeepsPreserveHost(t *testing.T) {
	r := newRig(t)
	if err := r.PutService("photos", "http://100.64.0.5:3200", true, "x"); err != nil {
		t.Fatal(err)
	}
	if err := r.PutService("photos", "http://100.64.0.6:3200", false, "x"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Undo(context.Background(), r.history.List()[0].ID, "x"); err != nil {
		t.Fatal(err)
	}
	got := r.svc.List()[0]
	if got.Upstream != "http://100.64.0.5:3200" || !got.PreserveHost {
		t.Errorf("service = %+v", got)
	}
}

func TestRefreshNowIsRateLimited(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	if err := r.RefreshNow(ctx, "x"); err != nil {
		t.Fatal(err)
	}
	if err := r.RefreshNow(ctx, "x"); !errors.Is(err, health.ErrRateLimited) {
		t.Errorf("err = %v", err)
	}
	r.lastRefresh = time.Now().Add(-refreshCooldown)
	if err := r.RefreshNow(ctx, "x"); err != nil {
		t.Error(err)
	}
}

func TestResolveConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	c := config{configPath: path, zone: "flag.example.com", explicit: map[string]bool{"zone": true}}
	if _, exists, err := resolveConfig(&c); exists || err != nil {
		t.Fatalf("first start: %v, %v", exists, err)
	}
	if err := settings.Save(path, settings.Values{Zone: "file.example.com", Source: "localapi", IntervalSeconds: 45, TTL: 90}); err != nil {
		t.Fatal(err)
	}
	c = config{configPath: path, zone: "flag.example.com", ttl: 60, explicit: map[string]bool{"zone": true}}
	if _, exists, err := resolveConfig(&c); !exists || err != nil {
		t.Fatalf("%v, %v", exists, err)
	}
	if c.zone != "flag.example.com" {
		t.Errorf("an explicit flag should win: %s", c.zone)
	}
	if c.source != "localapi" || c.interval != 45*time.Second || c.ttl != 90 {
		t.Errorf("config = %+v", c)
	}
	p := pinnedKeys(map[string]bool{"zone": true, "records-token-file": true, "mgmt": true})
	if !p[keyZone] || !p["records_token"] || len(p) != 2 {
		t.Errorf("pinned = %v", p)
	}
}
