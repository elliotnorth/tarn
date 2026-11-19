// Package doctor checks that a machine can run tarn, and says how to fix what
// it finds. Every check is read-only, apart from the Cloudflare check, which
// creates and deletes one TXT record because Cloudflare has no dry run.
package doctor

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/elliotnorth/Tarn/internal/peers"
)

// Level is a check's result.
type Level int

const (
	OK Level = iota
	Warn
	Fail
)

// Result is one check.
type Result struct {
	Name   string
	Level  Level
	Detail string
	Fix    string
}

// Health is the part of /healthz that doctor and status read.
type Health struct {
	Status      string            `json:"status"`
	Version     string            `json:"version"`
	Zone        string            `json:"zone"`
	Records     int               `json:"records"`
	LastRefresh *time.Time        `json:"last_refresh"`
	LastError   string            `json:"last_error"`
	DNS         map[string]uint64 `json:"dns"`
	Collisions  []struct {
		Name string `json:"name"`
	} `json:"collisions"`
	Skipped []string  `json:"skipped"`
	TLS     *TLSState `json:"tls"`
}

// TLSState is /healthz's certificate section.
type TLSState struct {
	Domain      string     `json:"domain"`
	Staging     bool       `json:"staging"`
	NotAfter    *time.Time `json:"not_after"`
	RenewBy     *time.Time `json:"renew_by"`
	LastRenewed *time.Time `json:"last_renewed"`
	Fails       int        `json:"consecutive_failures"`
	Error       string     `json:"last_error"`
}

// Service is one entry of /services.
type Service struct {
	Name     string `json:"name"`
	Upstream string `json:"upstream"`
}

// ErrNeedsRoot means a check needs a file only root can read.
var ErrNeedsRoot = errors.New("run with sudo to check this")

// Zone can check a Cloudflare token.
type Zone interface {
	Verify(ctx context.Context) error
	CheckZone(ctx context.Context, zone string) error
}

// Env is everything the checks touch, so they can be tested on broken machines.
type Env struct {
	Now        func() time.Time
	Zone       string // used when tarn isn't running
	Listen     string // tarn's configured DNS address, if not the tailnet IP
	Health     func(ctx context.Context) (*Health, error)
	Services   func(ctx context.Context) ([]Service, error)
	Tailscale  func(ctx context.Context) (*peers.Status, error)
	HasTUN     func() bool
	CheckDNS   func(ctx context.Context, addr, zone string) error // tarn answers on addr
	PortFree   func(addr string) error                            // addr can be bound
	SplitDNS   func(ctx context.Context) (string, error)          // text of `tailscale dns status`
	Cloudflare func() (Zone, error)                               // nil, nil when no token is configured
	Reach      func(ctx context.Context, url string) error
	ServerTime func(ctx context.Context) (time.Time, error)
}

const maxClockSkew = 2 * time.Minute

const tunFix = `Tailscale needs /dev/net/tun. In a Proxmox LXC, add these two lines to /etc/pve/lxc/<id>.conf on the host, then restart the container:
      lxc.cgroup2.devices.allow: c 10:200 rwm
      lxc.mount.entry: /dev/net/tun dev/net/tun none bind,create=file`

// Run makes every check, in the order a person would fix them.
func Run(ctx context.Context, e *Env) []Result {
	var out []Result
	add := func(r Result) { out = append(out, r) }

	if e.HasTUN() {
		add(Result{Name: "TUN device", Detail: "/dev/net/tun is present"})
	} else {
		add(Result{Name: "TUN device", Level: Fail, Detail: "/dev/net/tun is missing", Fix: tunFix})
	}

	selfIP := ""
	st, err := e.Tailscale(ctx)
	switch {
	case err != nil:
		add(Result{Name: "Tailscale", Level: Fail, Detail: err.Error(), Fix: "Install Tailscale and run: sudo tailscale up"})
	case st.Self == nil || len(st.Self.IPv4) == 0:
		add(Result{Name: "Tailscale", Level: Fail, Detail: "this machine has no tailnet IPv4 address", Fix: "Run: sudo tailscale up"})
	default:
		selfIP = st.Self.IPv4[0].String()
		add(Result{Name: "Tailscale", Detail: "connected as " + selfIP})
	}

	health, healthErr := e.Health(ctx)
	zone := e.Zone
	switch {
	case healthErr != nil:
		add(Result{Name: "tarn", Level: Fail, Detail: "tarn isn't answering on its status port", Fix: "Check: systemctl status tarn, then: journalctl -u tarn -n 30"})
	case health.Status == "ok":
		zone = health.Zone
		add(Result{Name: "tarn", Detail: fmt.Sprintf("running %s, serving %d names", health.Version, health.Records)})
	default:
		zone = health.Zone
		add(Result{Name: "tarn", Level: Fail, Detail: fmt.Sprintf("status is %s: %s", health.Status, health.LastError), Fix: "tarn can't read the device list. Check: tailscale status"})
	}

	add(dnsPort(ctx, e, selfIP, zone, healthErr == nil))
	add(splitDNS(ctx, e, zone, selfIP))
	if healthErr == nil && health.TLS != nil {
		add(certificate(e, health.TLS))
	}
	if r, ok := cloudflare(ctx, e, zone); ok {
		add(r)
	}
	if healthErr == nil {
		out = append(out, upstreams(ctx, e)...)
	}
	add(clock(ctx, e))
	return out
}

func dnsPort(ctx context.Context, e *Env, selfIP, zone string, running bool) Result {
	r := Result{Name: "DNS port"}
	addr := e.Listen
	if addr == "" && selfIP != "" {
		addr = selfIP + ":53"
	}
	const see = "See what's on the port: sudo ss -lunp 'sport = :53'"
	switch {
	case addr == "":
		r.Level, r.Detail = Warn, "skipped, no tailnet IP"
	case running:
		if err := e.CheckDNS(ctx, addr, zone); err != nil {
			r.Level, r.Detail, r.Fix = Fail, fmt.Sprintf("tarn isn't answering on %s: %v", addr, err), see
		} else {
			r.Detail = "tarn answers on " + addr
		}
	default:
		if err := e.PortFree(addr); err != nil {
			r.Level, r.Detail = Fail, fmt.Sprintf("can't use %s: %v", addr, err)
			r.Fix = see + ", then limit that server to its own addresses (dnsmasq or Pi-hole: bind-interfaces)"
		} else {
			r.Detail = addr + " is free"
		}
	}
	return r
}

func splitDNS(ctx context.Context, e *Env, zone, ip string) Result {
	r := Result{Name: "Split DNS"}
	if zone == "" {
		r.Level, r.Detail = Warn, "skipped, zone not known"
		return r
	}
	text, err := e.SplitDNS(ctx)
	if err != nil {
		r.Level, r.Detail = Warn, "can't read tailscale dns status: "+err.Error()
		return r
	}
	for _, line := range strings.Split(text, "\n") {
		if !strings.Contains(line, zone) || !strings.Contains(line, "100.") {
			continue
		}
		if ip != "" && !strings.Contains(line, ip) {
			r.Level, r.Detail = Fail, "the route points at another address: "+strings.TrimSpace(line)
			r.Fix = fmt.Sprintf("In the Tailscale admin console, change the nameserver for %s to %s", zone, ip)
			return r
		}
		r.Detail = "route for " + zone + " is present"
		return r
	}
	r.Level, r.Detail = Fail, "no route for "+zone
	r.Fix = fmt.Sprintf("In the Tailscale admin console, under DNS, add a custom nameserver %s, turn on Restrict to domain, and enter %s", ip, zone)
	return r
}

func certificate(e *Env, t *TLSState) Result {
	r := Result{Name: "Certificate"}
	if t.NotAfter == nil {
		r.Level, r.Detail = Fail, "no certificate yet"
		if t.Error != "" {
			r.Detail += ": " + t.Error
		}
		r.Fix = "Check the Cloudflare token, then: journalctl -u tarn | grep certificate"
		return r
	}
	if t.Error != "" {
		r.Level, r.Detail = Fail, "renewal is failing: "+t.Error
		r.Fix = "Check the Cloudflare token. tarn keeps retrying with backoff"
		return r
	}
	left := int(t.NotAfter.Sub(e.Now()).Hours() / 24)
	switch {
	case left < 0:
		r.Level, r.Detail = Fail, "expired"
		r.Fix = "Check: journalctl -u tarn | grep certificate"
	case t.Staging:
		r.Level, r.Detail = Warn, fmt.Sprintf("a staging certificate, so browsers won't trust it (%d days left)", left)
	default:
		r.Detail = fmt.Sprintf("%s, %d days left", t.Domain, left)
	}
	return r
}

func cloudflare(ctx context.Context, e *Env, zone string) (Result, bool) {
	r := Result{Name: "Cloudflare token"}
	cf, err := e.Cloudflare()
	switch {
	case errors.Is(err, ErrNeedsRoot):
		r.Level, r.Detail = Warn, err.Error()
		return r, true
	case err != nil:
		r.Level, r.Detail = Fail, err.Error()
		return r, true
	case cf == nil:
		return r, false
	}
	if err := cf.Verify(ctx); err != nil {
		r.Level, r.Detail = Fail, err.Error()
		r.Fix = "Create a new token with Zone > Zone > Read and Zone > DNS > Edit, for your domain"
		return r, true
	}
	if zone != "" {
		if err := cf.CheckZone(ctx, zone); err != nil {
			r.Level, r.Detail = Fail, err.Error()
			r.Fix = "The token needs Zone > Zone > Read and Zone > DNS > Edit, for the domain holding " + zone
			return r, true
		}
	}
	r.Detail = "works, and can edit DNS for " + zone
	return r, true
}

func upstreams(ctx context.Context, e *Env) []Result {
	list, err := e.Services(ctx)
	if err != nil {
		return []Result{{Name: "Services", Level: Warn, Detail: "can't list them: " + err.Error()}}
	}
	var out []Result
	for _, s := range list {
		r := Result{Name: "Service " + s.Name, Detail: "answers at " + s.Upstream}
		if err := e.Reach(ctx, s.Upstream); err != nil {
			r.Level, r.Detail = Fail, err.Error()
			r.Fix = "Is the app running? Check that this machine can reach " + s.Upstream
		}
		out = append(out, r)
	}
	return out
}

func clock(ctx context.Context, e *Env) Result {
	r := Result{Name: "Clock", Detail: "in sync"}
	remote, err := e.ServerTime(ctx)
	if err != nil {
		r.Level, r.Detail = Warn, "can't compare with an internet time: "+err.Error()
		return r
	}
	skew := e.Now().Sub(remote)
	if skew < 0 {
		skew = -skew
	}
	if skew > maxClockSkew {
		r.Level, r.Detail = Fail, "the clock is off by "+skew.Round(time.Second).String()
		r.Fix = "Certificates fail with a wrong clock. Run: sudo timedatectl set-ntp true (in an LXC, fix the host's clock)"
	}
	return r
}

// Failed reports whether any check failed.
func Failed(results []Result) bool {
	for _, r := range results {
		if r.Level == Fail {
			return true
		}
	}
	return false
}
