// Package dnsserver answers DNS queries for exactly one zone from the record
// index. It is authoritative only and never recurses or forwards.
package dnsserver

import (
	"strings"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"

	"github.com/elliotnorth/tarn/internal/index"
)

// ednsSize is the UDP payload size tarn advertises when the client uses EDNS.
const ednsSize = 1232

// Responder builds replies. It holds no per-query state.
type Responder struct {
	Zone  string              // zone apex, e.g. "t.example.com"
	TTL   uint32              // TTL on positive answers and the SOA minimum (negative caching)
	Index func() *index.Index // current index; may return nil before the first refresh
	Stats *Stats              // reply totals; optional
}

// Outcome classifies a reply for logging.
type Outcome int

const (
	Answered Outcome = iota
	NoData
	NXDomain
	Refused
	NotImpl
	ServFail
)

func (r *Responder) zone() string { return strings.ToLower(dnsutil.Fqdn(r.Zone)) }

// Reply builds the response to req. It does not pack the message.
//
//	outside the zone, or not class IN    REFUSED, nothing else
//	apex SOA / NS                        the record
//	apex A / AAAA                        NODATA with SOA
//	apex, other types                    REFUSED
//	known peer, A or AAAA                its addresses, or NODATA with SOA
//	known peer, other types              REFUSED
//	unknown name in the zone             NXDOMAIN with SOA
//	no peer list loaded yet              SERVFAIL
//	not a query, or not one question     NOTIMP / FORMERR
func (r *Responder) Reply(req *dns.Msg) (*dns.Msg, Outcome) {
	m := replyTo(req)
	if req.UDPSize > 0 {
		m.UDPSize = ednsSize
	}

	if req.Opcode != dns.OpcodeQuery {
		m.Rcode = dns.RcodeNotImplemented
		return m, NotImpl
	}
	if len(req.Question) != 1 {
		m.Rcode = dns.RcodeFormatError
		return m, Refused
	}
	q := req.Question[0]
	qname := strings.ToLower(q.Header().Name)
	qtype := dns.RRToType(q)
	zone := r.zone()

	// Outside our zone, or not class IN: refuse. No recursion, ever.
	if q.Header().Class != dns.ClassINET || !dnsutil.IsBelow(zone, qname) {
		m.Rcode = dns.RcodeRefused
		return m, Refused
	}
	m.Authoritative = true

	idx := r.Index()
	if idx == nil {
		// Never loaded a peer list: say so instead of a confident NXDOMAIN.
		m.Authoritative = false
		m.Rcode = dns.RcodeServerFailure
		return m, ServFail
	}

	// Zone apex.
	if qname == zone {
		switch qtype {
		case dns.TypeSOA:
			m.Answer = []dns.RR{r.soa(idx)}
			return m, Answered
		case dns.TypeNS:
			m.Answer = []dns.RR{r.ns()}
			return m, Answered
		case dns.TypeA, dns.TypeAAAA:
			m.Ns = []dns.RR{r.soa(idx)}
			return m, NoData
		default:
			m.Authoritative = false
			m.Rcode = dns.RcodeRefused
			return m, Refused
		}
	}

	// Exactly one label below the apex is a possible peer name.
	label, rest, _ := strings.Cut(qname, ".")
	rec, ok := idx.Lookup(label)
	if rest != zone || !ok {
		m.Rcode = dns.RcodeNameError
		m.Ns = []dns.RR{r.soa(idx)}
		return m, NXDomain
	}

	hdr := dns.Header{Name: q.Header().Name, TTL: r.TTL, Class: dns.ClassINET}
	switch qtype {
	case dns.TypeA:
		for _, a := range rec.IPv4 {
			m.Answer = append(m.Answer, &dns.A{Hdr: hdr, A: rdata.A{Addr: a}})
		}
	case dns.TypeAAAA:
		for _, a := range rec.IPv6 {
			m.Answer = append(m.Answer, &dns.AAAA{Hdr: hdr, AAAA: rdata.AAAA{Addr: a}})
		}
	default:
		// Only A and AAAA are served.
		m.Authoritative = false
		m.Rcode = dns.RcodeRefused
		return m, Refused
	}
	if len(m.Answer) == 0 {
		m.Ns = []dns.RR{r.soa(idx)}
		return m, NoData
	}
	return m, Answered
}

func (r *Responder) soa(idx *index.Index) dns.RR {
	zone := r.zone()
	return &dns.SOA{
		Hdr: dns.Header{Name: zone, TTL: r.TTL, Class: dns.ClassINET},
		SOA: rdata.SOA{
			Ns:      zone,
			Mbox:    "hostmaster." + zone,
			Serial:  uint32(idx.Built.Unix()),
			Refresh: 3600,
			Retry:   600,
			Expire:  86400,
			Minttl:  r.TTL,
		},
	}
}

func (r *Responder) ns() dns.RR {
	zone := r.zone()
	return &dns.NS{Hdr: dns.Header{Name: zone, TTL: r.TTL, Class: dns.ClassINET}, NS: rdata.NS{Ns: zone}}
}

// replyTo starts the reply to req: the ID, opcode and question are copied, and
// for a query so are the RecursionDesired, CheckingDisabled and DO bits. It is
// tarn's own because dnsutil.SetReply now turns the request itself into the
// reply, and Reply still reads req after building m.
func replyTo(req *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.ID = req.ID
	m.Response = true
	m.Opcode = req.Opcode
	if m.Opcode == dns.OpcodeQuery {
		m.RecursionDesired = req.RecursionDesired
		m.CheckingDisabled = req.CheckingDisabled
		m.Security = req.Security
	}
	m.Rcode = dns.RcodeSuccess
	m.Question = req.Question
	return m
}
