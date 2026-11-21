package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/elliotnorth/tarn/internal/peers"
)

func TestListenList(t *testing.T) {
	self := peers.Peer{Self: true, IPv4: []netip.Addr{netip.MustParseAddr("100.64.0.1")}}
	st := &peers.Status{Self: &self}
	cases := []struct {
		list string
		want []string
	}{
		{"", []string{"100.64.0.1:443"}},
		{"192.168.2.24", []string{"192.168.2.24:443"}},
		{"tailnet, 192.168.2.24:8443,192.168.2.24:8443", []string{"100.64.0.1:443", "192.168.2.24:8443"}},
		{"[fd00::1]:443,::ffff:10.0.0.1", []string{"[fd00::1]:443", "10.0.0.1:443"}},
	}
	for _, c := range cases {
		got, err := listenList("-proxy-listen", c.list, "443", st)
		if err != nil || !slices.Equal(got, c.want) {
			t.Errorf("%q: %v %v, want %v", c.list, got, err, c.want)
		}
	}
	if _, err := listenList("-proxy-listen", "tarn.lan", "443", st); err == nil {
		t.Error("hostname accepted")
	}
	if _, err := listenList("-proxy-listen", "", "443", &peers.Status{}); err == nil {
		t.Error("no tailnet IP, but no error")
	}
}

func TestCheckNoTailscale(t *testing.T) {
	ok := config{source: "none", listen: "192.168.2.24:53", proxyListen: "192.168.2.24", answer: "192.168.2.24"}
	if a, err := checkNoTailscale(ok, true); err != nil || len(a) != 1 {
		t.Fatalf("%v %v", a, err)
	}
	// Today's Tailscale setup needs none of the new flags.
	if a, err := checkNoTailscale(config{source: "cli"}, true); err != nil || a != nil {
		t.Fatalf("%v %v", a, err)
	}
	cases := map[string]func(*config){
		"-listen":       func(c *config) { c.listen = "" },
		"-proxy-listen": func(c *config) { c.proxyListen = "" },
		`"tailnet"`:     func(c *config) { c.listenExtra = "tailnet" },
		"-answer":       func(c *config) { c.answer = "" },
		"IPv4":          func(c *config) { c.answer = "fd00::1" },
		`"cli"`:         func(c *config) { c.source = "static" },
		"-hosts-file":   func(c *config) { c.hostsFile = filepath.Join(t.TempDir(), "missing") },
		"an IP address": func(c *config) { c.listenExtra = "router.lan" },
	}
	for want, breakIt := range cases {
		c := ok
		breakIt(&c)
		if _, err := checkNoTailscale(c, true); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v", want, err)
		}
	}
	// Without services, the proxy flags aren't needed.
	c := ok
	c.proxyListen, c.answer = "", ""
	if _, err := checkNoTailscale(c, false); err != nil {
		t.Error(err)
	}
}

func freePort(t *testing.T, network string) string {
	t.Helper()
	if network == "udp" {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer pc.Close()
		return pc.LocalAddr().String()
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

// tarn runs with no Tailscale at all: names come from the hosts file, it
// answers on two addresses, and /healthz says which mode it's in.
func TestRunWithoutTailscale(t *testing.T) {
	dir := t.TempDir()
	hosts := filepath.Join(dir, "hosts")
	os.WriteFile(hosts, []byte("phone 10.8.0.2\n"), 0o644)
	c := config{
		zone: "t.example.com", source: "none", tailscale: filepath.Join(dir, "no-tailscale-here"),
		listen: freePort(t, "udp"), listenExtra: freePort(t, "udp"), hostsFile: hosts,
		interval: time.Hour, ttl: 60, mgmt: freePort(t, "tcp"), stateDir: filepath.Join(dir, "state"),
		explicit: map[string]bool{}, // no Cloudflare token, so HTTPS is off
	}
	go func() {
		if err := run(c, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
			t.Errorf("run: %v", err)
		}
	}()

	var h struct {
		Status string `json:"status"`
		Mode   mode   `json:"mode"`
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		resp, err := http.Get("http://" + c.mgmt + "/healthz")
		if err == nil {
			json.NewDecoder(resp.Body).Decode(&h)
			resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("tarn didn't start:", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if h.Status != "ok" || h.Mode.Source != "none" || !slices.Equal(h.Mode.DNS, []string{c.listen, c.listenExtra}) {
		t.Fatalf("healthz %+v", h)
	}
	for _, addr := range []string{c.listen, c.listenExtra} {
		r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "udp", addr)
		}}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		ips, err := r.LookupHost(ctx, "phone.t.example.com")
		cancel()
		if err != nil || len(ips) != 1 || ips[0] != "10.8.0.2" {
			t.Errorf("%s: %v %v", addr, ips, err)
		}
	}
}

func TestConfigFileKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	os.WriteFile(path, []byte(`{"zone":"t.example.com","source":"none","interval_seconds":30,"ttl":60,
		"listen":"192.168.2.24:53","listen_extra":"tailnet","proxy_listen":"192.168.2.24","answer":"192.168.2.24","hosts_file":"/etc/tarn/hosts"}`), 0o600)
	c := config{configPath: path, proxyListen: "10.0.0.1", explicit: map[string]bool{"proxy-listen": true}}
	if _, _, err := resolveConfig(&c); err != nil {
		t.Fatal(err)
	}
	if c.source != "none" || c.listenExtra != "tailnet" || c.answer != "192.168.2.24" || c.hostsFile != "/etc/tarn/hosts" {
		t.Errorf("%+v", c)
	}
	if c.proxyListen != "10.0.0.1" {
		t.Errorf("the flag should win, got %q", c.proxyListen)
	}
}
