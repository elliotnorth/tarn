package dnsserver

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// Handler returns a dns.Handler that answers with r and logs refused and
// failed queries, rate limited. Successful queries are never logged: a full
// who-asked-for-what log is a liability.
func Handler(r *Responder, log *slog.Logger) dns.Handler {
	list := []*Responder{r}
	return HandlerFor(func() []*Responder { return list }, log)
}

// pick returns the responder for the zone req asks about, or the first one,
// which refuses anything outside its zone.
func pick(list []*Responder, req *dns.Msg) *Responder {
	if len(list) > 1 && len(req.Question) == 1 {
		q := strings.ToLower(req.Question[0].Header().Name)
		for _, r := range list {
			if dnsutil.IsBelow(r.zone(), q) {
				return r
			}
		}
	}
	return list[0]
}

// HandlerFor is Handler for responders that can change while running. More than
// one is only used while a zone change waits to be confirmed.
func HandlerFor(get func() []*Responder, log *slog.Logger) dns.Handler {
	lim := &limiter{max: 20, per: time.Minute}
	return dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, req *dns.Msg) {
		r := pick(get(), req)
		m, out, packErr := r.packed(req)
		if r.Stats != nil {
			r.Stats.add(out)
		}
		if out == Refused || out == NotImpl || out == ServFail {
			if ok, dropped := lim.allow(time.Now()); ok {
				qname, qtype := "", uint16(0)
				if len(req.Question) == 1 {
					qname, qtype = dnsutil.Question(req)
				}
				attrs := []any{
					"rcode", dnsutil.RcodeToString(m.Rcode),
					"name", qname,
					"type", dnsutil.TypeToString(qtype),
					"client", dnsutil.RemoteIP(w),
				}
				if packErr != nil {
					attrs = append(attrs, "pack_err", packErr)
				}
				if dropped > 0 {
					attrs = append(attrs, "suppressed", dropped)
				}
				log.Info("query not answered", attrs...)
			}
		}
		if m == nil {
			return
		}
		io.Copy(w, m)
	})
}

// packed builds and packs the reply to req. Some questions unpack but can't be
// packed again, such as a label holding a literal dot. Those get a bare
// FORMERR with no question section, counted as refused, so the client gets an
// answer and the failure goes through the rate-limited log. m is nil only if
// even that can't be packed.
func (r *Responder) packed(req *dns.Msg) (m *dns.Msg, out Outcome, packErr error) {
	m, out = r.Reply(req)
	if packErr = m.Pack(); packErr == nil {
		return m, out, nil
	}
	f := new(dns.Msg)
	f.ID = req.ID
	f.Response = true
	f.Opcode = req.Opcode
	f.Rcode = dns.RcodeFormatError
	if err := f.Pack(); err != nil {
		return nil, Refused, packErr
	}
	return f, Refused, packErr
}

// limiter allows max events per window and counts the ones it suppressed.
type limiter struct {
	mu      sync.Mutex
	max     int
	per     time.Duration
	start   time.Time
	n       int
	dropped int
}

func (l *limiter) allow(now time.Time) (bool, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.start) >= l.per {
		l.start, l.n = now, 0
	}
	if l.n >= l.max {
		l.dropped++
		return false, 0
	}
	l.n++
	d := l.dropped
	l.dropped = 0
	return true, d
}
