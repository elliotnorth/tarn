package dnsserver

import (
	"strings"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// FuzzReply feeds arbitrary bytes to the responder the way the UDP server
// would: unpack, reply, pack. Beyond not panicking, it checks the rules that
// keep tarn from becoming an open resolver or leaking anything outside its
// zone.
//
// Run longer by hand with:
//
//	go test -run '^$' -fuzz FuzzReply -fuzztime 5m ./internal/dnsserver
func FuzzReply(f *testing.F) {
	seeds := []struct {
		name  string
		qtype uint16
	}{
		{"laptop.t.example.com", dns.TypeA},
		{"box.t.example.com", dns.TypeAAAA},
		{"v6only.t.example.com", dns.TypeA},
		{"nope.t.example.com", dns.TypeA},
		{"a.box.t.example.com", dns.TypeA},
		{"t.example.com", dns.TypeSOA},
		{"t.example.com", dns.TypeNS},
		{"t.example.com", dns.TypeMX},
		{"box.t.example.com", dns.TypeTXT},
		{"www.google.com", dns.TypeA},
		{"box.xt.example.com", dns.TypeA},
		{"LAPTOP.T.EXAMPLE.COM", dns.TypeANY},
	}
	for _, s := range seeds {
		m := dns.NewMsg(s.name, s.qtype)
		m.ID = 0x1234
		if err := m.Pack(); err != nil {
			f.Fatalf("pack seed %s: %v", s.name, err)
		}
		f.Add(append([]byte(nil), m.Data...))
	}
	f.Add([]byte{})
	f.Add(make([]byte, 12)) // a bare header with no question

	withIndex := responder(testIndex())
	noIndex := responder(nil)
	zone := withIndex.zone()

	f.Fuzz(func(t *testing.T, b []byte) {
		req := &dns.Msg{Data: append([]byte(nil), b...)}
		if err := req.Unpack(); err != nil {
			return // the server drops what it can't unpack
		}

		for _, r := range []*Responder{withIndex, noIndex} {
			m, out, _ := r.packed(req)
			if m == nil {
				t.Fatal("no reply could be packed")
			}

			if m.ID != req.ID {
				t.Fatalf("reply ID %d, request ID %d", m.ID, req.ID)
			}
			if !m.Response {
				t.Fatal("reply does not have QR set")
			}

			inZone := false
			if len(req.Question) == 1 {
				q := req.Question[0].Header()
				inZone = q.Class == dns.ClassINET && dnsutil.IsBelow(zone, strings.ToLower(q.Name))
			}

			// Outside the zone: refused, with nothing in any section.
			if !inZone && req.Opcode == dns.OpcodeQuery {
				if out != Refused || len(m.Answer) != 0 || len(m.Ns) != 0 {
					t.Fatalf("question outside the zone got outcome %d with %d answers, %d authority",
						out, len(m.Answer), len(m.Ns))
				}
				if m.Authoritative {
					t.Fatal("authoritative bit set outside the zone")
				}
			}

			// Every record tarn returns is in its zone and is one of the
			// four types it serves.
			for _, rr := range append(append([]dns.RR(nil), m.Answer...), m.Ns...) {
				name := strings.ToLower(rr.Header().Name)
				if !dnsutil.IsBelow(zone, name) {
					t.Fatalf("record %q is outside the zone", name)
				}
				switch dns.RRToType(rr) {
				case dns.TypeA, dns.TypeAAAA, dns.TypeSOA, dns.TypeNS:
				default:
					t.Fatalf("unexpected record type %s", dnsutil.TypeToString(dns.RRToType(rr)))
				}
			}
			if len(m.Extra) != 0 {
				t.Fatalf("additional section has %d records", len(m.Extra))
			}
		}
	})
}
