package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/elliotnorth/tarn/internal/doctor"
	"github.com/elliotnorth/tarn/internal/peers"
	"github.com/elliotnorth/tarn/internal/proxy"
	"github.com/elliotnorth/tarn/internal/settings"
	"github.com/elliotnorth/tarn/internal/setup"
)

func TestNeedsSetup(t *testing.T) {
	fresh := config{configPath: "/var/lib/tarn/config"}
	if !needsSetup(fresh, false) {
		t.Error("fresh install with -config should run setup")
	}
	if needsSetup(fresh, true) {
		t.Error("an existing config should start normally")
	}
	if needsSetup(config{configPath: "/x", zone: "t.example.com"}, false) {
		t.Error("an explicit -zone should start normally")
	}
	if needsSetup(config{}, false) {
		t.Error("without -config, a missing zone is still an error")
	}
}

func TestFinishSetup(t *testing.T) {
	dir := t.TempDir()
	c := config{configPath: filepath.Join(dir, "config"), stateDir: dir, source: "cli", interval: 30 * time.Second, ttl: 60}
	if _, err := setupCode(dir); err != nil {
		t.Fatal(err)
	}
	a := setup.Answers{Zone: "t.example.com", Token: "cf-token", Password: "correct horse battery", Email: "me@example.com"}
	if err := finishSetup(c, a, bcrypt.MinCost); err != nil {
		t.Fatal(err)
	}

	v, ok, err := settings.Load(c.configPath)
	if err != nil || !ok {
		t.Fatalf("config: %v %v", ok, err)
	}
	if v.Zone != "t.example.com" || !v.ACMEStaging || v.ACMEEmail != "me@example.com" || v.ServicesFile != filepath.Join(dir, "services") || v.IntervalSeconds != 30 || v.TTL != 60 {
		t.Errorf("config %+v", v)
	}
	if bcrypt.CompareHashAndPassword([]byte(v.AdminPasswordHash), []byte(a.Password)) != nil {
		t.Error("password hash doesn't match")
	}
	if strings.Contains(mustRead(t, c.configPath), "cf-token") || strings.Contains(mustRead(t, c.configPath), a.Password) {
		t.Error("a secret is in the config file")
	}

	// The token lands where normal startup looks for it, owner-only.
	if p := stateTokenFile(dir); p == "" || strings.TrimSpace(mustRead(t, p)) != "cf-token" {
		t.Errorf("token file %q", p)
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(filepath.Join(dir, tokenFileName)); fi.Mode().Perm() != 0o600 {
			t.Errorf("token mode %v", fi.Mode().Perm())
		}
	}
	// An empty services file the page can add to.
	if _, err := proxy.LoadServices(v.ServicesFile, "t.example.com"); err != nil {
		t.Errorf("services file: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, setupCodeFileName)); !os.IsNotExist(err) {
		t.Error("setup code left behind")
	}

	// Next start: no setup, and the config fills in the zone.
	c2 := config{configPath: c.configPath, stateDir: dir, explicit: map[string]bool{}}
	_, exists, err := resolveConfig(&c2)
	if err != nil || needsSetup(c2, exists) || c2.zone != "t.example.com" || !c2.acmeStaging {
		t.Errorf("after setup: exists=%v err=%v zone=%q staging=%v", exists, err, c2.zone, c2.acmeStaging)
	}
}

func TestFinishSetupKeepsExistingServices(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "services"), []byte("vault http://100.64.0.5:8080\n"), 0o600)
	c := config{configPath: filepath.Join(dir, "config"), stateDir: dir, source: "cli", interval: 30 * time.Second}
	if err := finishSetup(c, setup.Answers{Zone: "t.example.com", Token: "x", Password: "correct horse battery"}, bcrypt.MinCost); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(mustRead(t, filepath.Join(dir, "services")), "vault") {
		t.Error("an existing services file was overwritten")
	}
}

func TestSetupCodeStaysTheSame(t *testing.T) {
	dir := t.TempDir()
	a, err := setupCode(dir)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := setupCode(dir)
	if a != b || len(a) != 14 {
		t.Errorf("codes %q %q", a, b)
	}
	if readSetupCode(dir) != a {
		t.Error("tarn status can't read it back")
	}
}

func TestSetupStatus(t *testing.T) {
	var out bytes.Buffer
	writeSetupStatus(&out, &doctor.Health{Version: "v0.5.0", SetupURL: "http://100.64.0.1/"}, "ABCD-EFGH-JKLM")
	if !strings.Contains(out.String(), "http://100.64.0.1/") || !strings.Contains(out.String(), "ABCD-EFGH-JKLM") {
		t.Errorf("status:\n%s", out.String())
	}
	out.Reset()
	writeSetupStatus(&out, &doctor.Health{SetupURL: "http://100.64.0.1/"}, "")
	if !strings.Contains(out.String(), "sudo tarn status") {
		t.Errorf("without root:\n%s", out.String())
	}
}

func mustRead(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

type fixedSource struct{ st *peers.Status }

func (f fixedSource) Status(context.Context) (*peers.Status, error) { return f.st, nil }

// TestRunSetupEndToEnd drives the wizard over real HTTP on loopback, standing
// in for the tailnet address, and checks tarn would restart into normal mode.
func TestRunSetupEndToEnd(t *testing.T) {
	dir := t.TempDir()
	c := config{configPath: filepath.Join(dir, "config"), stateDir: dir, source: "cli", interval: 30 * time.Second, ttl: 60, mgmt: "127.0.0.1:0"}
	self := peers.Peer{ID: "n1", Name: "tarn", Self: true, IPv4: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}
	restarted := make(chan struct{})
	oldRestart, oldCheck := restartSelf, checkSetupToken
	restartSelf = func() error { close(restarted); return nil }
	checkSetupToken = func(_ context.Context, token, zone string) error {
		if token != "good" {
			return errors.New("no")
		}
		return nil
	}
	t.Cleanup(func() { restartSelf, checkSetupToken = oldRestart, oldCheck })

	errc := make(chan error, 1)
	go func() {
		errc <- runSetup(c, slog.New(slog.DiscardHandler), fixedSource{&peers.Status{Self: &self, Peers: []peers.Peer{self}}})
	}()

	// Port 80 if this machine allows it, else 9581.
	var base string
	for deadline := time.Now().Add(5 * time.Second); base == "" && time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		for _, port := range []string{"80", "9581"} {
			u := "http://127.0.0.1:" + port
			if resp, err := http.Get(u + "/"); err == nil {
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				if strings.Contains(string(body), "Set up tarn") {
					base = u
					break
				}
			}
		}
	}
	if base == "" {
		t.Fatal("setup page never came up")
	}
	code := readSetupCode(dir)
	post := func(path string, body map[string]string) int {
		body["code"] = code
		b, _ := json.Marshal(body)
		req, _ := http.NewRequest(http.MethodPost, base+path, bytes.NewReader(b))
		req.Header.Set("X-Tarn-Request", "1")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if c := post("/setup/token", map[string]string{"zone": "t.example.com", "token": "good"}); c != 200 {
		t.Fatalf("token: %d", c)
	}
	if c := post("/setup/finish", map[string]string{"zone": "t.example.com", "token": "good", "password": "correct horse battery"}); c != 200 {
		t.Fatalf("finish: %d", c)
	}
	select {
	case <-restarted:
	case err := <-errc:
		t.Fatalf("runSetup returned without restarting: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("no restart after setup")
	}
	if <-errc != nil {
		t.Error("runSetup failed after restart")
	}
	if v, ok, _ := settings.Load(c.configPath); !ok || v.Zone != "t.example.com" {
		t.Errorf("config after setup: %+v", v)
	}
	if _, err := http.Get(base + "/"); err == nil {
		t.Error("the setup page is still up after setup")
	}
}
