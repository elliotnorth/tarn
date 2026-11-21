package peers

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"
)

// node is the subset of `tailscale status --json` that tarn reads. Everything
// else is ignored on purpose (including the deprecated Capabilities fields), so
// format changes elsewhere in the document can't break parsing.
type node struct {
	ID           string   `json:"ID"`
	HostName     string   `json:"HostName"`
	DNSName      string   `json:"DNSName"`
	TailscaleIPs []string `json:"TailscaleIPs"`
	Online       bool     `json:"Online"`
}

type status struct {
	BackendState   string          `json:"BackendState"`
	Self           *node           `json:"Self"`
	Peer           map[string]node `json:"Peer"`
	CurrentTailnet *struct {
		MagicDNSSuffix string `json:"MagicDNSSuffix"`
	} `json:"CurrentTailnet"`
}

// ParseStatus parses `tailscale status --json` output (which is also what the
// LocalAPI /localapi/v0/status endpoint returns).
//
// It is tolerant by design: names come from the first label of DNSName with
// HostName as the fallback,
// IPs may carry a /32 or /128 suffix, duplicates are removed, names are
// lowercased, and nodes without a usable name or address are skipped and
// reported rather than failing the whole parse.
func ParseStatus(data []byte) (*Status, error) {
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf")) // tolerate a UTF-8 BOM
	var raw status
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse tailscale status: %w", err)
	}
	// A stopped node still reports its last-known peers and IPs, which would
	// look like a healthy list. A missing field is tolerated.
	if raw.BackendState != "" && raw.BackendState != "Running" {
		return nil, fmt.Errorf("tailscale is not running (BackendState=%s)", raw.BackendState)
	}
	if raw.Self == nil && len(raw.Peer) == 0 {
		return nil, errors.New("parse tailscale status: no Self and no Peer entries")
	}

	st := &Status{}
	if raw.CurrentTailnet != nil {
		st.MagicDNSSuffix = raw.CurrentTailnet.MagicDNSSuffix
	}
	if st.MagicDNSSuffix == "" && raw.Self != nil {
		// Older clients: the suffix is the self name minus its first label.
		_, st.MagicDNSSuffix, _ = strings.Cut(strings.TrimSuffix(strings.TrimSpace(raw.Self.DNSName), "."), ".")
	}
	st.MagicDNSSuffix = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(st.MagicDNSSuffix), "."))
	add := func(n node, self bool) {
		p, err := toPeer(n)
		if err != nil {
			id := n.ID
			if id == "" {
				id = "(no id)"
			}
			st.Skipped = append(st.Skipped, id+": "+err.Error())
			return
		}
		p.Self = self
		st.Peers = append(st.Peers, p)
	}

	if raw.Self != nil {
		add(*raw.Self, true)
	}
	// Map order is random; sort keys so output is deterministic.
	keys := make([]string, 0, len(raw.Peer))
	for k := range raw.Peer {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		add(raw.Peer[k], false)
	}
	// Point Self at its entry now that the slice won't grow any more.
	for i := range st.Peers {
		if st.Peers[i].Self {
			st.Self = &st.Peers[i]
		}
	}
	return st, nil
}

// toPeer names a node after the first label of its DNSName (its MagicDNS name,
// which is what the admin console shows, follows renames there, and is already
// made unique by the control server). HostName (the OS hostname) is only a
// fallback, for nodes whose DNSName is empty or unusable.
func toPeer(n node) (Peer, error) {
	first, _, _ := strings.Cut(strings.TrimSuffix(strings.TrimSpace(n.DNSName), "."), ".")
	name := Label(first)
	if name == "" {
		name = Label(n.HostName)
	}
	if name == "" {
		return Peer{}, fmt.Errorf("no usable name (HostName %q, DNSName %q)", n.HostName, n.DNSName)
	}

	p := Peer{ID: n.ID, Name: name, Online: n.Online}
	for _, s := range n.TailscaleIPs {
		a, ok := parseAddr(s)
		if !ok {
			continue
		}
		if a.Is4() {
			p.IPv4 = append(p.IPv4, a)
		} else {
			p.IPv6 = append(p.IPv6, a)
		}
	}
	p.IPv4 = sortDedupe(p.IPv4)
	p.IPv6 = sortDedupe(p.IPv6)
	if len(p.IPv4) == 0 && len(p.IPv6) == 0 {
		return Peer{}, errors.New("no usable tailnet IPs")
	}
	return p, nil
}

// parseAddr accepts "100.64.0.1", "100.64.0.1/32" and the IPv6 equivalents.
func parseAddr(s string) (netip.Addr, bool) {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '/'); i >= 0 {
		pfx, err := netip.ParsePrefix(s)
		if err != nil || pfx.Bits() != pfx.Addr().BitLen() {
			return netip.Addr{}, false // only host routes are node addresses
		}
		return pfx.Addr().Unmap(), true
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

func sortDedupe(as []netip.Addr) []netip.Addr {
	slices.SortFunc(as, func(a, b netip.Addr) int { return a.Compare(b) })
	return slices.Compact(as)
}

// Label turns a hostname into a single valid lowercase DNS label (RFC 1123:
// letters, digits and hyphens, 1–63 characters, no leading or trailing
// hyphen). Runs of other characters such as spaces, underscores, dots and
// non-ASCII become one hyphen. It returns "" if nothing usable is left.
func Label(s string) string {
	var b strings.Builder
	hyphen := false
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			hyphen = false
		default:
			if !hyphen && b.Len() > 0 {
				b.WriteByte('-')
				hyphen = true
			}
		}
	}
	out := strings.Trim(b.String(), "-")
	if len(out) > 63 {
		out = strings.TrimRight(out[:63], "-")
	}
	return out
}
