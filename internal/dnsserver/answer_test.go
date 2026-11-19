package dnsserver

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"

	"codeberg.org/miekg/dns"

	"github.com/elliotnorth/Tarn/internal/index"
	"github.com/elliotnorth/Tarn/internal/peers"
)

func testIndex() *index.Index {
	a := netip.MustParseAddr
	return index.Build(&peers.Status{Peers: []peers.Peer{
		{ID: "n1", Name: "box", IPv4: []netip.Addr{a("100.64.0.1")}, IPv6: []netip.Addr{a("fd7a:115c:a1e0::1")}, Self: true},
		{ID: "n2", Name: "laptop", IPv4: []netip.Addr{a("100.64.0.2")}},
		{ID: "n3", Name: "v6only", IPv6: []netip.Addr{a("fd7a:115c:a1e0::3")}},
	}}, time.Unix(1700000000, 0))
}

func responder(idx *index.Index) *Responder {
	return &Responder{Zone: "t.example.com", TTL: 60, Index: func() *index.Index { return idx }}
}

func TestAnswerTable(t *testing.T) {
	r := responder(testIndex())
	cases := []struct {
		name    string
		qname   string
		qtype   uint16
		class   uint16
		rcode   uint16
		out     Outcome
		answers int
		soa     bool // SOA expected in the authority section
		aa      bool
	}{
		{"A for a peer", "laptop.t.example.com", dns.TypeA, dns.ClassINET, dns.RcodeSuccess, Answered, 1, false, true},
		{"case-insensitive", "LAPTOP.T.Example.COM", dns.TypeA, dns.ClassINET, dns.RcodeSuccess, Answered, 1, false, true},
		{"AAAA for a peer", "box.t.example.com", dns.TypeAAAA, dns.ClassINET, dns.RcodeSuccess, Answered, 1, false, true},
		{"AAAA for a v4-only peer is NODATA", "laptop.t.example.com", dns.TypeAAAA, dns.ClassINET, dns.RcodeSuccess, NoData, 0, true, true},
		{"A for a v6-only peer is NODATA", "v6only.t.example.com", dns.TypeA, dns.ClassINET, dns.RcodeSuccess, NoData, 0, true, true},
		{"other type on a peer is REFUSED", "box.t.example.com", dns.TypeMX, dns.ClassINET, dns.RcodeRefused, Refused, 0, false, false},
		{"TXT on a peer is REFUSED", "box.t.example.com", dns.TypeTXT, dns.ClassINET, dns.RcodeRefused, Refused, 0, false, false},
		{"unknown peer is NXDOMAIN", "nope.t.example.com", dns.TypeA, dns.ClassINET, dns.RcodeNameError, NXDomain, 0, true, true},
		{"unknown peer, other type, is NXDOMAIN", "nope.t.example.com", dns.TypeMX, dns.ClassINET, dns.RcodeNameError, NXDomain, 0, true, true},
		{"two labels below the zone is NXDOMAIN", "a.box.t.example.com", dns.TypeA, dns.ClassINET, dns.RcodeNameError, NXDomain, 0, true, true},
		{"apex SOA", "t.example.com", dns.TypeSOA, dns.ClassINET, dns.RcodeSuccess, Answered, 1, false, true},
		{"apex NS", "t.example.com", dns.TypeNS, dns.ClassINET, dns.RcodeSuccess, Answered, 1, false, true},
		{"apex A is NODATA", "t.example.com", dns.TypeA, dns.ClassINET, dns.RcodeSuccess, NoData, 0, true, true},
		{"apex MX is REFUSED", "t.example.com", dns.TypeMX, dns.ClassINET, dns.RcodeRefused, Refused, 0, false, false},
		{"outside the zone is REFUSED", "example.com", dns.TypeA, dns.ClassINET, dns.RcodeRefused, Refused, 0, false, false},
		{"lookalike zone is REFUSED", "box.xt.example.com", dns.TypeA, dns.ClassINET, dns.RcodeRefused, Refused, 0, false, false},
		{"recursion attempt is REFUSED", "www.google.com", dns.TypeA, dns.ClassINET, dns.RcodeRefused, Refused, 0, false, false},
		{"class CHAOS is REFUSED", "box.t.example.com", dns.TypeA, dns.ClassCHAOS, dns.RcodeRefused, Refused, 0, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := dns.NewMsg(c.qname, c.qtype, c.class)
			m, out := r.Reply(req)
			if m.Rcode != c.rcode || out != c.out {
				t.Fatalf("rcode=%d out=%d, want rcode=%d out=%d", m.Rcode, out, c.rcode, c.out)
			}
			if len(m.Answer) != c.answers {
				t.Errorf("answers = %v, want %d", m.Answer, c.answers)
			}
			hasSOA := len(m.Ns) == 1 && dns.RRToType(m.Ns[0]) == dns.TypeSOA
			if hasSOA != c.soa {
				t.Errorf("authority = %v, want SOA=%v", m.Ns, c.soa)
			}
			if m.Authoritative != c.aa {
				t.Errorf("AA = %v, want %v", m.Authoritative, c.aa)
			}
			if !m.Response || m.ID != req.ID || m.RecursionAvailable {
				t.Errorf("bad header: response=%v id=%d/%d ra=%v", m.Response, m.ID, req.ID, m.RecursionAvailable)
			}
		})
	}
}

func TestAnswerContents(t *testing.T) {
	r := responder(testIndex())
	m, _ := r.Reply(dns.NewMsg("laptop.t.example.com", dns.TypeA))
	a, ok := m.Answer[0].(*dns.A)
	if !ok || a.Addr != netip.MustParseAddr("100.64.0.2") || a.Hdr.TTL != 60 {
		t.Fatalf("answer = %v", m.Answer[0])
	}

	m, _ = r.Reply(dns.NewMsg("nope.t.example.com", dns.TypeA))
	soa := m.Ns[0].(*dns.SOA)
	if soa.Hdr.Name != "t.example.com." || soa.Minttl != 60 || soa.Serial != 1700000000 {
		t.Fatalf("SOA = %v", soa)
	}
}

func TestNotImplementedOpcode(t *testing.T) {
	req := dns.NewMsg("box.t.example.com", dns.TypeA)
	req.Opcode = dns.OpcodeNotify
	if m, out := responder(testIndex()).Reply(req); m.Rcode != dns.RcodeNotImplemented || out != NotImpl {
		t.Fatalf("rcode = %d", m.Rcode)
	}
}

func TestNoIndexYetIsServFail(t *testing.T) {
	m, out := responder(nil).Reply(dns.NewMsg("box.t.example.com", dns.TypeA))
	if m.Rcode != dns.RcodeServerFailure || out != ServFail {
		t.Fatalf("rcode = %d, want SERVFAIL before the first refresh", m.Rcode)
	}
	// Out-of-zone is still refused, even before the first refresh.
	if m, _ := responder(nil).Reply(dns.NewMsg("example.org", dns.TypeA)); m.Rcode != dns.RcodeRefused {
		t.Fatalf("rcode = %d, want REFUSED", m.Rcode)
	}
}

func TestEDNS(t *testing.T) {
	req := dns.NewMsg("box.t.example.com", dns.TypeA)
	req.UDPSize = 4096
	if m, _ := responder(testIndex()).Reply(req); m.UDPSize != ednsSize {
		t.Fatalf("UDPSize = %d, want %d", m.UDPSize, ednsSize)
	}
}

// TestOverUDP runs the real server on localhost and queries it over the wire.
func TestOverUDP(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("can't listen on UDP: %v", err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	started := make(chan struct{})
	resp := responder(testIndex())
	resp.Stats = &Stats{}
	srv := &dns.Server{PacketConn: pc, Net: "udp", Handler: Handler(resp, log),
		NotifyStartedFunc: func(context.Context) { close(started) }}
	go srv.ListenAndServe()
	defer srv.Shutdown(context.Background())
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("server didn't start")
	}

	c := new(dns.Client)
	ask := func(name string, qtype uint16) *dns.Msg {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		resp, _, err := c.Exchange(ctx, dns.NewMsg(name, qtype), "udp", pc.LocalAddr().String())
		if err != nil {
			t.Fatalf("exchange %s: %v", name, err)
		}
		return resp
	}

	if m := ask("box.t.example.com", dns.TypeA); m.Rcode != dns.RcodeSuccess || len(m.Answer) != 1 {
		t.Errorf("A box: %v", m)
	}
	if got := resp.Stats.Snapshot()["answered"]; got != 1 {
		t.Errorf("answered = %d, want 1", got)
	}
	if m := ask("laptop.t.example.com", dns.TypeAAAA); m.Rcode != dns.RcodeSuccess || len(m.Answer) != 0 || len(m.Ns) != 1 {
		t.Errorf("AAAA laptop (NODATA): %v", m)
	}
	if m := ask("nope.t.example.com", dns.TypeA); m.Rcode != dns.RcodeNameError {
		t.Errorf("A nope: %v", m)
	}
	if m := ask("www.google.com", dns.TypeA); m.Rcode != dns.RcodeRefused {
		t.Errorf("A google: %v", m)
	}
}

func TestLimiter(t *testing.T) {
	l := &limiter{max: 2, per: time.Minute}
	t0 := time.Unix(0, 0)
	l.allow(t0)
	l.allow(t0)
	if ok, _ := l.allow(t0); ok {
		t.Fatal("third event in the window was allowed")
	}
	ok, dropped := l.allow(t0.Add(time.Minute))
	if !ok || dropped != 1 {
		t.Fatalf("next window: ok=%v dropped=%d, want true, 1", ok, dropped)
	}
}
