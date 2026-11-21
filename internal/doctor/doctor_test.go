package doctor

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/elliotnorth/tarn/internal/peers"
)

var now = time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)

type fakeCF struct{ verify, zone error }

func (f fakeCF) Verify(context.Context) error            { return f.verify }
func (f fakeCF) CheckZone(context.Context, string) error { return f.zone }

// healthy returns a machine where every check passes.
func healthy() *Env {
	after := now.Add(60 * 24 * time.Hour)
	self := peers.Peer{Name: "tarn", Self: true, IPv4: []netip.Addr{netip.MustParseAddr("100.64.0.1")}}
	return &Env{
		Now: func() time.Time { return now },
		Health: func(context.Context) (*Health, error) {
			return &Health{Status: "ok", Version: "v1", Zone: "t.example.com", Records: 3, TLS: &TLSState{Domain: "*.t.example.com", NotAfter: &after}}, nil
		},
		Services: func(context.Context) ([]Service, error) {
			return []Service{{Name: "app", Upstream: "https://app.example-tailnet.ts.net"}}, nil
		},
		Tailscale: func(context.Context) (*peers.Status, error) { return &peers.Status{Self: &self}, nil },
		HasTUN:    func() bool { return true },
		CheckDNS:  func(context.Context, string, string) error { return nil },
		PortFree:  func(string) error { return nil },
		SplitDNS: func(context.Context) (string, error) {
			return "Split DNS Routes:\n  - t.example.com -> 100.64.0.1\n", nil
		},
		Cloudflare: func() (Zone, error) { return fakeCF{}, nil },
		Reach:      func(context.Context, string) error { return nil },
		ServerTime: func(context.Context) (time.Time, error) { return now, nil },
	}
}

// headscale makes the machine's tailnet a Headscale one with this base_domain.
func headscale(e *Env, suffix string) {
	st, _ := e.Tailscale(context.Background())
	st.MagicDNSSuffix = suffix
	e.Tailscale = func(context.Context) (*peers.Status, error) { return st, nil }
}

func find(t *testing.T, rs []Result, name string) Result {
	t.Helper()
	for _, r := range rs {
		if r.Name == name {
			return r
		}
	}
	t.Fatalf("no %q check in %+v", name, rs)
	return Result{}
}

func TestHealthyMachinePasses(t *testing.T) {
	for _, r := range Run(context.Background(), healthy()) {
		if r.Level != OK {
			t.Errorf("%s: %+v", r.Name, r)
		}
	}
}

// Each broken case must fail its own check and print a fix naming the remedy.
func TestBrokenMachines(t *testing.T) {
	notRunning := func(e *Env) {
		e.Health = func(context.Context) (*Health, error) { return nil, errors.New("refused") }
		e.Zone = "t.example.com"
	}
	cases := []struct {
		name, check, fix string
		breakIt          func(*Env)
	}{
		{"no TUN", "TUN device", "lxc.mount.entry: /dev/net/tun", func(e *Env) { e.HasTUN = func() bool { return false } }},
		{"tailscale down", "Tailscale", "tailscale up", func(e *Env) {
			e.Tailscale = func(context.Context) (*peers.Status, error) { return nil, errors.New("not running") }
		}},
		{"port 53 taken", "DNS port", "ss -lunp", func(e *Env) {
			notRunning(e)
			e.PortFree = func(string) error { return errors.New("address already in use") }
		}},
		{"something else on 53", "DNS port", "ss -lunp", func(e *Env) {
			e.CheckDNS = func(context.Context, string, string) error { return errors.New("something else answered") }
		}},
		{"wrong token scope", "Cloudflare token", "DNS > Edit", func(e *Env) {
			e.Cloudflare = func() (Zone, error) { return fakeCF{zone: errors.New("the token can't edit DNS")}, nil }
		}},
		{"dead token", "Cloudflare token", "new token", func(e *Env) {
			e.Cloudflare = func() (Zone, error) { return fakeCF{verify: errors.New("Invalid API Token")}, nil }
		}},
		{"split DNS missing", "Split DNS", "Restrict to domain", func(e *Env) {
			e.SplitDNS = func(context.Context) (string, error) { return "Split DNS Routes:\n", nil }
		}},
		{"split DNS old IP", "Split DNS", "change the nameserver", func(e *Env) {
			e.SplitDNS = func(context.Context) (string, error) { return "t.example.com -> 100.64.0.99\n", nil }
		}},
		{"split DNS missing on Headscale", "Split DNS", `nameservers: split:, set "t.example.com": ["100.64.0.1"]`, func(e *Env) {
			headscale(e, "hs.example.com")
			e.SplitDNS = func(context.Context) (string, error) { return "Split DNS Routes:\n", nil }
		}},
		{"zone inside MagicDNS", "Split DNS", "base_domain", func(e *Env) { headscale(e, "example.com") }},
		{"upstream down", "Service app", "Is the app running", func(e *Env) {
			e.Reach = func(context.Context, string) error { return errors.New("no answer") }
		}},
		{"clock skew", "Clock", "timedatectl", func(e *Env) {
			e.ServerTime = func(context.Context) (time.Time, error) { return now.Add(10 * time.Minute), nil }
		}},
		{"renewal failing", "Certificate", "Cloudflare token", func(e *Env) {
			after := now.Add(10 * 24 * time.Hour)
			e.Health = func(context.Context) (*Health, error) {
				return &Health{Status: "ok", Zone: "t.example.com", TLS: &TLSState{NotAfter: &after, Error: "rate limited"}}, nil
			}
		}},
		{"tarn not running", "tarn", "systemctl status", notRunning},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := healthy()
			c.breakIt(e)
			rs := Run(context.Background(), e)
			r := find(t, rs, c.check)
			if r.Level != Fail {
				t.Errorf("%s: level %v, detail %q", c.check, r.Level, r.Detail)
			}
			if !strings.Contains(r.Fix, c.fix) {
				t.Errorf("fix %q doesn't mention %q", r.Fix, c.fix)
			}
			if !Failed(rs) {
				t.Error("Failed = false")
			}
		})
	}
}

func TestWarningsDontFail(t *testing.T) {
	e := healthy()
	e.Cloudflare = func() (Zone, error) { return nil, ErrNeedsRoot }
	rs := Run(context.Background(), e)
	if r := find(t, rs, "Cloudflare token"); r.Level != Warn || !strings.Contains(r.Detail, "sudo") {
		t.Errorf("%+v", r)
	}
	if Failed(rs) {
		t.Error("a warning counted as a failure")
	}
}

func TestNoTokenSkipsCloudflare(t *testing.T) {
	e := healthy()
	e.Cloudflare = func() (Zone, error) { return nil, nil }
	for _, r := range Run(context.Background(), e) {
		if r.Name == "Cloudflare token" {
			t.Errorf("%+v", r)
		}
	}
}

func TestSplitDNSRoute(t *testing.T) {
	text := "Split DNS Routes:\n  - t.example.com -> 100.64.0.10\n  - other.example.com -> 100.64.0.1\n"
	if r, line := SplitDNSRoute(text, "t.example.com", "100.64.0.1"); r != RouteOther || line != "- t.example.com -> 100.64.0.10" {
		t.Errorf("prefix address counted as a match: %v %q", r, line)
	}
	if r, _ := SplitDNSRoute(text, "t.example.com", "100.64.0.10"); r != RouteOK {
		t.Errorf("exact address: %v", r)
	}
	if r, _ := SplitDNSRoute(text, "example.com", "100.64.0.1"); r != RouteMissing {
		t.Errorf("parent zone matched a subdomain route: %v", r)
	}
	if r, _ := SplitDNSRoute(text, "x.example.com", "100.64.0.1"); r != RouteMissing {
		t.Errorf("missing zone: %v", r)
	}
}

func TestHeadscalePasses(t *testing.T) {
	e := healthy()
	headscale(e, "hs.example.com")
	rs := Run(context.Background(), e)
	for _, r := range rs {
		if r.Level != OK {
			t.Errorf("%s: %+v", r.Name, r)
		}
	}
	if r := find(t, rs, "Tailscale"); !strings.Contains(r.Detail, "self-hosted") {
		t.Errorf("detail %q", r.Detail)
	}
}
