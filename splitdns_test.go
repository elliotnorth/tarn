package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/elliotnorth/tarn/internal/index"
	"github.com/elliotnorth/tarn/internal/peers"
)

func TestSplitDNSWatch(t *testing.T) {
	store := &index.Store{}
	self := peers.Peer{ID: "n1", Name: "tarn", Self: true, IPv4: []netip.Addr{netip.MustParseAddr("100.64.0.1")}}
	store.Swap(index.Build(&peers.Status{Self: &self, Peers: []peers.Peer{self}}, time.Now()))

	text, fail := "", error(nil)
	w := &splitDNSWatch{
		status: func(context.Context) (string, error) { return text, fail },
		zone:   func() string { return "t.example.com" },
		store:  store,
		log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	ctx := context.Background()

	text = "Split DNS Routes:\n  - t.example.com -> 100.64.0.1\n"
	w.check(ctx, time.Now())
	if w.current() != nil {
		t.Errorf("right route warned: %+v", w.current())
	}

	// The machine's old address is still in the admin console.
	text = "Split DNS Routes:\n  - t.example.com -> 100.64.0.9\n"
	w.check(ctx, time.Now())
	got, ok := w.current().(*splitDNSWarning)
	if !ok || got.Want != "100.64.0.1" || got.Route != "- t.example.com -> 100.64.0.9" {
		t.Fatalf("wrong route: %#v", w.current())
	}

	// A failing CLI says nothing new either way.
	fail = errors.New("no tailscale")
	w.check(ctx, time.Now())
	if w.current() == nil {
		t.Error("a failed check cleared the warning")
	}
	fail = nil

	// No route at all may just be --accept-dns=false: no banner.
	text = "Split DNS Routes:\n"
	w.check(ctx, time.Now())
	if w.current() != nil {
		t.Errorf("missing route warned: %+v", w.current())
	}
}
