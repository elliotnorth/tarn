// Package peers reads the tailnet peer list. It only ever reads tailnet state;
// nothing in this package can change it.
package peers

import (
	"context"
	"net/netip"
	"strings"
)

// Peer is one tailnet node, reduced to what tarn needs to answer DNS.
type Peer struct {
	ID     string       // stable node ID, used to break name collisions deterministically
	Name   string       // a single valid, lowercase DNS label
	IPv4   []netip.Addr // deduplicated and sorted
	IPv6   []netip.Addr // deduplicated and sorted
	Online bool
	Self   bool // the node tarn is running on
}

// Status is a parsed peer list snapshot.
type Status struct {
	Self  *Peer  // nil if the status had no usable self node
	Peers []Peer // all usable nodes, including Self
	// Skipped lists nodes that had no usable name or address, as "id: reason".
	Skipped []string
	// MagicDNSSuffix is the tailnet's own DNS domain, lowercase with no
	// trailing dot: <tailnet>.ts.net on Tailscale, base_domain on Headscale.
	MagicDNSSuffix string
}

// SelfHosted reports whether the tailnet runs on a control server other than
// Tailscale's, such as Headscale. Every Tailscale tailnet has a ts.net suffix.
// It is false when the suffix isn't known.
func (s *Status) SelfHosted() bool {
	d := s.MagicDNSSuffix
	return d != "" && d != "ts.net" && !strings.HasSuffix(d, ".ts.net") && !strings.HasSuffix(d, ".tailscale.net")
}

// Overlaps reports whether zone is the MagicDNS suffix or inside it. MagicDNS
// answers those names itself, so split DNS to tarn would never be asked.
func (s *Status) Overlaps(zone string) bool {
	d, z := s.MagicDNSSuffix, strings.ToLower(strings.TrimSuffix(zone, "."))
	return d != "" && z != "" && (z == d || strings.HasSuffix(z, "."+d))
}

// Source produces peer list snapshots.
type Source interface {
	Status(ctx context.Context) (*Status, error)
}
