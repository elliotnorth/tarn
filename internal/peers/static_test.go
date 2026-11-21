package peers

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseHosts(t *testing.T) {
	ps, err := ParseHosts([]byte("# WireGuard clients\nPhone 10.8.0.2\nnas 192.168.2.10 fd00::10 192.168.2.10 # dup\n\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 2 || ps[0].Name != "phone" || ps[0].ID != "hosts:phone" || !ps[0].Online {
		t.Fatalf("got %+v", ps)
	}
	if len(ps[1].IPv4) != 1 || len(ps[1].IPv6) != 1 {
		t.Errorf("nas addresses %v %v", ps[1].IPv4, ps[1].IPv6)
	}
	for _, bad := range []string{"phone", "my_phone 10.0.0.1", "a 10.0.0.1\na 10.0.0.2", "a nope", "a fe80::1%eth0"} {
		if _, err := ParseHosts([]byte(bad)); err == nil {
			t.Errorf("%q: no error", bad)
		}
	}
}

func TestParseIPv4List(t *testing.T) {
	got, err := ParseIPv4List(" 192.168.2.24, 10.8.0.1,192.168.2.24")
	if err != nil || len(got) != 2 || got[0].String() != "10.8.0.1" {
		t.Fatalf("%v %v", got, err)
	}
	for _, bad := range []string{"fd00::1", "0.0.0.0", "127.0.0.1", "nope"} {
		if _, err := ParseIPv4List(bad); err == nil {
			t.Errorf("%q: no error", bad)
		}
	}
}

type fixed struct {
	st  *Status
	err error
}

func (f fixed) Status(context.Context) (*Status, error) { return f.st, f.err }

func TestExtras(t *testing.T) {
	ctx := context.Background()
	hosts := filepath.Join(t.TempDir(), "hosts")
	os.WriteFile(hosts, []byte("phone 10.8.0.2\n"), 0o644)
	answer := []netip.Addr{netip.MustParseAddr("192.168.2.24")}

	// Without Tailscale: only the hosts file, and services at -answer.
	st, err := Extras{Source: None{}, HostsFile: hosts, Answer: answer}.Status(ctx)
	if err != nil || len(st.Peers) != 1 || st.Self != nil || st.ServiceIPv4[0] != answer[0] {
		t.Fatalf("%+v %v", st, err)
	}

	// Beside Tailscale: tailnet devices kept, Self still found.
	self := Peer{ID: "n1", Name: "tarn", Self: true, IPv4: []netip.Addr{netip.MustParseAddr("100.64.0.1")}}
	inner := &Status{Peers: []Peer{self}}
	inner.Self = &inner.Peers[0]
	st, err = Extras{Source: fixed{st: inner}, HostsFile: hosts}.Status(ctx)
	if err != nil || len(st.Peers) != 2 || st.Self == nil || st.Self.Name != "tarn" || st.ServiceIPv4 != nil {
		t.Fatalf("%+v %v", st, err)
	}
	if len(inner.Peers) != 1 {
		t.Error("the inner status was changed")
	}

	// A broken hosts file fails the refresh, so the last good list stays.
	os.WriteFile(hosts, []byte("phone\n"), 0o644)
	if _, err := (Extras{Source: None{}, HostsFile: hosts}).Status(ctx); err == nil || !strings.Contains(err.Error(), "line 1") {
		t.Errorf("err = %v", err)
	}
	if _, err := (Extras{Source: fixed{err: errors.New("down")}}).Status(ctx); err == nil {
		t.Error("inner error lost")
	}
}
