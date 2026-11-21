package peers

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"os"
	"strings"
)

// None is the source for running without Tailscale: an empty device list
// that never fails. Names then come only from the services and hosts files.
type None struct{}

func (None) Status(context.Context) (*Status, error) { return &Status{}, nil }

// Extras wraps a source with the parts of the device list tarn's own flags
// decide: fixed device records from a hosts file, and the addresses service
// names resolve to.
type Extras struct {
	Source
	HostsFile string       // "name address..." lines, read on every refresh; optional
	Answer    []netip.Addr // IPv4 addresses for service names; empty means this node's tailnet IPv4
}

func (e Extras) Status(ctx context.Context) (*Status, error) {
	st, err := e.Source.Status(ctx)
	if err != nil {
		return nil, err
	}
	if e.HostsFile != "" {
		b, err := os.ReadFile(e.HostsFile)
		if err != nil {
			return nil, fmt.Errorf("hosts file: %w", err)
		}
		hosts, err := ParseHosts(b)
		if err != nil {
			return nil, fmt.Errorf("hosts file %s: %w", e.HostsFile, err)
		}
		// Copy, so a source that hands out a shared Status isn't changed.
		cp := *st
		cp.Peers = append(append([]Peer(nil), st.Peers...), hosts...)
		for i := range cp.Peers {
			if cp.Peers[i].Self {
				cp.Self = &cp.Peers[i]
			}
		}
		st = &cp
	}
	if len(e.Answer) > 0 {
		st.ServiceIPv4 = e.Answer
	}
	return st, nil
}

// HostIDPrefix starts the ID of every device from the hosts file. It sorts
// before Tailscale's node IDs, so a hosts file entry keeps its name when a
// tailnet device has the same one, and the clash is reported.
const HostIDPrefix = "hosts:"

// ParseHosts reads lines of "name address [address...]", with # comments.
// Names are single DNS labels; addresses are IPv4 or IPv6.
func ParseHosts(b []byte) ([]Peer, error) {
	var out []Peer
	seen := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for n := 1; sc.Scan(); n++ {
		line, _, _ := strings.Cut(sc.Text(), "#")
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if len(f) < 2 {
			return nil, fmt.Errorf("line %d: want a name and at least one address", n)
		}
		name := strings.ToLower(f[0])
		if Label(name) != name {
			return nil, fmt.Errorf("line %d: %q must be one label of letters, digits and hyphens", n, f[0])
		}
		if seen[name] {
			return nil, fmt.Errorf("line %d: %s is listed twice", n, name)
		}
		seen[name] = true
		p := Peer{ID: HostIDPrefix + name, Name: name, Online: true}
		for _, s := range f[1:] {
			a, err := netip.ParseAddr(s)
			if err != nil || a.Zone() != "" {
				return nil, fmt.Errorf("line %d: %q is not an IP address", n, s)
			}
			a = a.Unmap()
			if a.Is4() {
				p.IPv4 = append(p.IPv4, a)
			} else {
				p.IPv6 = append(p.IPv6, a)
			}
		}
		p.IPv4, p.IPv6 = sortDedupe(p.IPv4), sortDedupe(p.IPv6)
		out = append(out, p)
	}
	return out, sc.Err()
}

// ParseIPv4List reads a comma-separated list of IPv4 addresses, as -answer takes.
func ParseIPv4List(s string) ([]netip.Addr, error) {
	var out []netip.Addr
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		a, err := netip.ParseAddr(f)
		if err != nil || !a.Is4() {
			return nil, fmt.Errorf("%q is not an IPv4 address", f)
		}
		if a.IsUnspecified() || a.IsMulticast() || a.IsLoopback() {
			return nil, fmt.Errorf("%s can't be reached by other devices", a)
		}
		out = append(out, a)
	}
	return sortDedupe(out), nil
}
