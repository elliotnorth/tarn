package dnsserver

import "sync/atomic"

// Stats counts replies by outcome. It holds totals only, never names or
// clients: a who-asked-for-what record is a liability.
type Stats struct {
	counts [ServFail + 1]atomic.Uint64
}

func (s *Stats) add(o Outcome) { s.counts[o].Add(1) }

// Snapshot returns the current totals.
func (s *Stats) Snapshot() map[string]uint64 {
	return map[string]uint64{
		"answered":        s.counts[Answered].Load(),
		"no_data":         s.counts[NoData].Load(),
		"nxdomain":        s.counts[NXDomain].Load(),
		"refused":         s.counts[Refused].Load(),
		"not_implemented": s.counts[NotImpl].Load(),
		"servfail":        s.counts[ServFail].Load(),
	}
}
