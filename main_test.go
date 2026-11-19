package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/elliotnorth/Tarn/internal/index"
	"github.com/elliotnorth/Tarn/internal/peers"
	"github.com/elliotnorth/Tarn/internal/proxy"
)

// scriptSource returns its results in order, then repeats the last one.
type scriptSource struct {
	n     atomic.Int32
	steps []func() (*peers.Status, error)
}

func (s *scriptSource) Status(context.Context) (*peers.Status, error) {
	i := int(s.n.Add(1)) - 1
	if i >= len(s.steps) {
		i = len(s.steps) - 1
	}
	return s.steps[i]()
}

func selfAt(ip string) func() (*peers.Status, error) {
	return func() (*peers.Status, error) {
		p := peers.Peer{ID: "n0", Name: "tarn", Self: true, IPv4: []netip.Addr{netip.MustParseAddr(ip)}}
		return &peers.Status{Self: &p, Peers: []peers.Peer{p}}, nil
	}
}

func TestRefreshLoopExitsWhenIPChanges(t *testing.T) {
	src := &scriptSource{steps: []func() (*peers.Status, error){
		selfAt("100.64.0.7"),
		func() (*peers.Status, error) { return nil, errors.New("tailscale is not running") },
		func() (*peers.Status, error) { return &peers.Status{}, nil }, // no Self: can't tell, keep going
		selfAt("100.64.0.9"),
	}}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := refreshLoop(ctx, src, &index.Store{}, log, func() time.Duration { return time.Millisecond }, nil, func() string { return "100.64.0.7:53" }, nil)
	if err == nil || !strings.Contains(err.Error(), "100.64.0.9:53") {
		t.Fatalf("err = %v, want an IP-changed error naming the new address", err)
	}
	if got := src.n.Load(); got != 4 {
		t.Errorf("read the peer list %d times, want 4", got)
	}
}

func TestRefreshLoopIgnoresChangeWithExplicitListen(t *testing.T) {
	src := &scriptSource{steps: []func() (*peers.Status, error){selfAt("100.64.0.9")}}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err := refreshLoop(ctx, src, &index.Store{}, log, func() time.Duration { return time.Millisecond }, nil, func() string { return "" }, nil); err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
}

func TestCheckZone(t *testing.T) {
	good := map[string]string{
		"t.example.com":   "t.example.com",
		"T.Example.COM.":  "t.example.com",
		" home.lan.test ": "home.lan.test",
	}
	for in, want := range good {
		if got, err := checkZone(in); err != nil || got != want {
			t.Errorf("checkZone(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "com", "a..b", "under_score.example.com", "-x.example.com", "sp ace.example.com"} {
		if _, err := checkZone(in); err == nil {
			t.Errorf("checkZone(%q) succeeded, want error", in)
		}
	}
}

func TestDefaultListen(t *testing.T) {
	st := &peers.Status{Self: &peers.Peer{IPv4: []netip.Addr{netip.MustParseAddr("100.64.0.7")}}}
	if got, err := defaultListen(st); err != nil || got != "100.64.0.7:53" {
		t.Errorf("defaultListen = %q, %v", got, err)
	}
	if _, err := defaultListen(&peers.Status{}); err == nil {
		t.Error("defaultListen without Self should fail")
	}
}

// A change from the status page must reach DNS without waiting for a poll.
func TestServiceChangeRebuildsDNS(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc, err := proxy.OpenManager(filepath.Join(t.TempDir(), "services"), "t.example.com", log, true)
	if err != nil {
		t.Fatal(err)
	}
	src := &scriptSource{steps: []func() (*peers.Status, error){selfAt("100.64.0.7")}}
	store := &index.Store{}
	ctx := context.Background()
	if _, err := refresh(ctx, src, store, log, svc.Names); err != nil {
		t.Fatal(err)
	}
	svc.OnChange = func() { refresh(ctx, src, store, log, svc.Names) }

	if err := svc.Put("app", "http://127.0.0.1:1", false); err != nil {
		t.Fatal(err)
	}
	r, ok := store.Load().Lookup("app")
	if !ok || !r.Service || r.IPv4[0] != netip.MustParseAddr("100.64.0.7") {
		t.Fatalf("after Put: %+v, %v", r, ok)
	}
	if err := svc.Delete("app"); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.Load().Lookup("app"); ok {
		t.Error("the name still resolves after Delete")
	}
}
