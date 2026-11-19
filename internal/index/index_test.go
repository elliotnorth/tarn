package index

import (
	"errors"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/elliotnorth/tarn/internal/peers"
)

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

func TestBuildServices(t *testing.T) {
	self := peers.Peer{ID: "n1", Name: "tarn", Self: true, IPv4: []netip.Addr{addr("100.64.0.1")}, IPv6: []netip.Addr{addr("fd7a:115c:a1e0::1")}}
	st := &peers.Status{Self: &self, Peers: []peers.Peer{
		self,
		{ID: "n2", Name: "nextcloud", IPv4: []netip.Addr{addr("100.64.0.2")}},
		{ID: "n3", Name: "laptop", IPv4: []netip.Addr{addr("100.64.0.3")}},
	}}
	idx := Build(st, time.Now(), "nextcloud", "vault")
	if idx.Len() != 4 {
		t.Fatalf("Len = %d, want 4", idx.Len())
	}
	for _, name := range []string{"nextcloud", "vault"} {
		r, ok := idx.Lookup(name)
		if !ok || !r.Service || len(r.IPv4) != 1 || r.IPv4[0] != addr("100.64.0.1") || len(r.IPv6) != 0 {
			t.Errorf("%s = %+v, %v; want a service on tarn's IPv4 only", name, r, ok)
		}
	}
	if r, _ := idx.Lookup("laptop"); r.Service || r.IPv4[0] != addr("100.64.0.3") {
		t.Errorf("laptop = %+v", r)
	}

	// With no Self address to point at, a same-named device keeps its name.
	noSelf := Build(&peers.Status{Peers: st.Peers}, time.Now(), "nextcloud", "vault")
	if r, ok := noSelf.Lookup("nextcloud"); !ok || r.Service {
		t.Errorf("nextcloud without Self = %+v, %v", r, ok)
	}
	if _, ok := noSelf.Lookup("vault"); ok {
		t.Error("vault should not resolve without a Self address")
	}
}

func TestBuildAndLookup(t *testing.T) {
	st := &peers.Status{Peers: []peers.Peer{
		{ID: "n2", Name: "laptop", IPv4: []netip.Addr{addr("100.64.0.2")}, Online: true},
		{ID: "n1", Name: "box", IPv4: []netip.Addr{addr("100.64.0.1")}, IPv6: []netip.Addr{addr("fd7a:115c:a1e0::1")}, Self: true},
	}}
	idx := Build(st, time.Unix(1000, 0))

	if idx.Len() != 2 {
		t.Fatalf("Len = %d", idx.Len())
	}
	r, ok := idx.Lookup("LapTop")
	if !ok || r.ID != "n2" || !r.Online {
		t.Fatalf("Lookup(LapTop) = %+v, %v", r, ok)
	}
	if _, ok := idx.Lookup("missing"); ok {
		t.Error("Lookup(missing) found something")
	}
	if recs := idx.Records(); recs[0].Name != "box" || recs[1].Name != "laptop" {
		t.Errorf("Records not sorted: %+v", recs)
	}
}

func TestCollisionsAreDeterministic(t *testing.T) {
	mk := func(ids ...string) *peers.Status {
		st := &peers.Status{}
		for i, id := range ids {
			st.Peers = append(st.Peers, peers.Peer{ID: id, Name: "peer1", IPv4: []netip.Addr{addr("100.64.0." + string(rune('1'+i)))}})
		}
		return st
	}
	a := Build(mk("nC", "nA", "nB"), time.Now())
	b := Build(mk("nB", "nC", "nA"), time.Now())

	ra, _ := a.Lookup("peer1")
	rb, _ := b.Lookup("peer1")
	if ra.ID != "nA" || rb.ID != "nA" {
		t.Fatalf("winner = %s / %s, want nA both times", ra.ID, rb.ID)
	}
	if len(a.Collisions) != 1 || len(a.Collisions[0].Losers) != 2 {
		t.Fatalf("Collisions = %+v", a.Collisions)
	}
}

func TestGoldenCollisions(t *testing.T) {
	data, err := os.ReadFile("../../golden/status-1.104.4.json")
	if err != nil {
		t.Fatal(err)
	}
	st, err := peers.ParseStatus(data)
	if err != nil {
		t.Fatal(err)
	}
	idx := Build(st, time.Now())
	if idx.Len() != 2 {
		t.Fatalf("got %d records, want 2 (self-test and peer1)", idx.Len())
	}
	if len(idx.Collisions) != 1 || len(idx.Collisions[0].Losers) != 5 {
		t.Fatalf("Collisions = %+v, want peer1 with 5 losers", idx.Collisions)
	}
}

func TestNilIndex(t *testing.T) {
	var idx *Index
	if _, ok := idx.Lookup("x"); ok || idx.Len() != 0 || idx.Records() != nil {
		t.Error("nil index should be empty")
	}
}

func TestStoreKeepsLastGood(t *testing.T) {
	var s Store
	if s.Load() != nil {
		t.Fatal("new store should be empty")
	}
	good := Build(&peers.Status{Peers: []peers.Peer{{ID: "n1", Name: "a", IPv4: []netip.Addr{addr("100.64.0.1")}}}}, time.Unix(10, 0))
	s.Swap(good)
	s.Fail(time.Unix(20, 0), errors.New("tailscaled not running"))

	if s.Load() != good {
		t.Error("a failed refresh replaced the last good index")
	}
	h := s.Health()
	if h.LastError == "" || h.ConsecutiveFails != 1 || !h.LastOK.Equal(time.Unix(10, 0)) || !h.LastTry.Equal(time.Unix(20, 0)) {
		t.Errorf("Health = %+v", h)
	}
	s.Swap(good)
	if h := s.Health(); h.LastError != "" || h.ConsecutiveFails != 0 {
		t.Errorf("Health after recovery = %+v", h)
	}
}
