package main

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"

	"github.com/elliotnorth/tarn/internal/peers"
)

// mode is /healthz's "mode": where the device list comes from and every
// address tarn answers on, so status and doctor can describe a setup without
// Tailscale.
type mode struct {
	Source string       `json:"source"`
	DNS    []string     `json:"dns"`
	Proxy  []string     `json:"proxy,omitempty"`
	Answer []netip.Addr `json:"answer,omitempty"` // where service names point, if not the tailnet IP
}

// tailnetWord stands for this node's tailnet IPv4 in -proxy-listen and
// -listen-extra, so one list can hold both old and new addresses.
const tailnetWord = "tailnet"

// checkNoTailscale validates the flags for running with or without Tailscale
// and returns the -answer addresses. Without Tailscale there is no tailnet IP
// to default to, so every address must be given.
func checkNoTailscale(c config, proxying bool) ([]netip.Addr, error) {
	switch c.source {
	case "cli", "localapi", "none":
	default:
		return nil, fmt.Errorf(`-source must be "cli", "localapi" or "none", not %q`, c.source)
	}
	answer, err := peers.ParseIPv4List(c.answer)
	if err != nil {
		return nil, fmt.Errorf("-answer: %w", err)
	}
	for _, f := range []struct{ name, value, port string }{
		{"-listen-extra", c.listenExtra, "53"}, {"-proxy-listen", c.proxyListen, "443"},
	} {
		if _, err := listenList(f.name, f.value, f.port, nil); err != nil && !errors.Is(err, errNoTailnet) {
			return nil, err
		}
	}
	if c.hostsFile != "" {
		b, err := os.ReadFile(c.hostsFile)
		if err != nil {
			return nil, fmt.Errorf("-hosts-file: %w", err)
		}
		if _, err := peers.ParseHosts(b); err != nil {
			return nil, fmt.Errorf("-hosts-file %s: %w", c.hostsFile, err)
		}
	}
	if c.source != "none" {
		return answer, nil
	}
	if c.listen == "" {
		return nil, errors.New("-source none needs -listen, the address to answer DNS on, such as -listen 192.168.1.10:53")
	}
	if usesTailnet(c.listenExtra) {
		return nil, errors.New(`-source none has no tailnet IP, so -listen-extra can't use "tailnet"`)
	}
	if proxying {
		if c.proxyListen == "" || usesTailnet(c.proxyListen) {
			return nil, errors.New("-source none needs -proxy-listen, the address for HTTPS, such as -proxy-listen 192.168.1.10")
		}
		if len(answer) == 0 {
			return nil, errors.New("-source none needs -answer, the IPv4 address service names resolve to, such as -answer 192.168.1.10")
		}
	}
	return answer, nil
}

var errNoTailnet = errors.New("no tailnet IP")

// listenList turns a comma-separated list of addresses into host:port
// strings. An address without a port gets port. "tailnet" is this node's
// tailnet IPv4, from st. An empty list means just the tailnet IP.
func listenList(flagName, list, port string, st *peers.Status) ([]string, error) {
	items := splitList(list)
	if len(items) == 0 {
		items = []string{tailnetWord}
	}
	var out []string
	for _, it := range items {
		var addr string
		if it == tailnetWord {
			if st == nil || st.Self == nil || len(st.Self.IPv4) == 0 {
				return nil, fmt.Errorf("%s: %w; can't find this node's tailnet IPv4 address", flagName, errNoTailnet)
			}
			addr = net.JoinHostPort(st.Self.IPv4[0].String(), port)
		} else {
			host, p, err := net.SplitHostPort(it)
			if err != nil {
				host, p = strings.Trim(it, "[]"), port
			}
			ip, err := netip.ParseAddr(host)
			if err != nil || ip.Zone() != "" {
				return nil, fmt.Errorf("%s: %q must be an IP address, optionally with a port", flagName, it)
			}
			if p == "" {
				p = port
			}
			addr = net.JoinHostPort(ip.Unmap().String(), p)
		}
		if !slices.Contains(out, addr) {
			out = append(out, addr)
		}
	}
	return out, nil
}

// usesTailnet reports whether a list names the tailnet IP.
func usesTailnet(list string) bool {
	items := splitList(list)
	return slices.Contains(items, tailnetWord)
}

func splitList(s string) []string {
	var out []string
	for _, f := range strings.Split(s, ",") {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}
