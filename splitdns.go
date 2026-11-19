package main

import (
	"context"
	"log/slog"
	"os/exec"
	"sync/atomic"
	"time"

	"github.com/elliotnorth/tarn/internal/doctor"
	"github.com/elliotnorth/tarn/internal/index"
)

// splitDNSWarning is shown at the top of the status page when the tailnet's
// split DNS route for the zone points somewhere other than tarn, which is
// what happens after tarn's machine gets a new tailnet IP.
type splitDNSWarning struct {
	Zone    string    `json:"zone"`
	Route   string    `json:"route"` // the route as `tailscale dns status` prints it
	Want    string    `json:"want"`  // tarn's address
	Checked time.Time `json:"checked"`
}

// splitDNSWatch checks the route every few minutes. It only ever reports a
// route that exists and is wrong: a missing route can also mean this machine
// runs with --accept-dns=false, so `tarn doctor` reports that instead.
type splitDNSWatch struct {
	status func(ctx context.Context) (string, error) // `tailscale dns status`
	zone   func() string
	store  *index.Store
	log    *slog.Logger
	warn   atomic.Pointer[splitDNSWarning]
}

func newSplitDNSWatch(tailscale string, zone func() string, store *index.Store, log *slog.Logger) *splitDNSWatch {
	return &splitDNSWatch{
		status: func(ctx context.Context) (string, error) {
			ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			b, err := exec.CommandContext(ctx, tailscale, "dns", "status").Output()
			return string(b), err
		},
		zone: zone, store: store, log: log,
	}
}

// selfIP is this machine's first tailnet IPv4, from the record index.
func selfIP(store *index.Store) string {
	for _, r := range store.Load().Records() {
		if r.Self && len(r.IPv4) > 0 {
			return r.IPv4[0].String()
		}
	}
	return ""
}

func (w *splitDNSWatch) check(ctx context.Context, now time.Time) {
	ip, zone := selfIP(w.store), w.zone()
	if ip == "" || zone == "" {
		return
	}
	text, err := w.status(ctx)
	if err != nil {
		return // no tailscale CLI here, or it failed; nothing to say
	}
	route, line := doctor.SplitDNSRoute(text, zone, ip)
	if route != doctor.RouteOther {
		if w.warn.Swap(nil) != nil {
			w.log.Info("split DNS points at tarn again", "zone", zone, "ip", ip)
		}
		return
	}
	if old := w.warn.Load(); old == nil || old.Route != line || old.Want != ip {
		w.log.Warn("split DNS points at another address; change the nameserver in the Tailscale admin console", "zone", zone, "route", line, "want", ip)
	}
	w.warn.Store(&splitDNSWarning{Zone: zone, Route: line, Want: ip, Checked: now})
}

func (w *splitDNSWatch) run(ctx context.Context, every time.Duration) {
	for {
		w.check(ctx, time.Now())
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}

// current is the warning for /healthz, or nil when there is none.
func (w *splitDNSWatch) current() any {
	if p := w.warn.Load(); p != nil {
		return p
	}
	return nil
}
