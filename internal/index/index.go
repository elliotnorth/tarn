// Package index holds the in-memory DNS record index built from a peer list.
// An Index is immutable once built; Store swaps whole indexes atomically so
// readers never see a half-built one.
package index

import (
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/elliotnorth/Tarn/internal/peers"
)

// Record is what tarn answers for one name.
type Record struct {
	Name    string       `json:"name"`
	IPv4    []netip.Addr `json:"ipv4,omitempty"`
	IPv6    []netip.Addr `json:"ipv6,omitempty"`
	Online  bool         `json:"online"`
	Self    bool         `json:"self,omitempty"`
	Service bool         `json:"service,omitempty"`
	ID      string       `json:"id"`
}

// Collision records a name claimed by more than one node.
type Collision struct {
	Name   string   `json:"name"`
	Winner string   `json:"winner"` // node ID that got the name
	Losers []string `json:"losers"` // node IDs that were dropped
}

// Index is an immutable snapshot of records.
type Index struct {
	Built      time.Time
	records    []Record // sorted by name
	byName     map[string]int
	Collisions []Collision
	Skipped    []string
}

// Build creates an index from a parsed status.
//
// Name collisions are resolved deterministically: the node with the smallest
// ID keeps the name and the others are dropped and reported. Offline
// nodes are kept, since tailnet IPs are stable.
//
// Each service name resolves to this node's own IPv4 address, where the proxy
// listens, and replaces any device of the same name. There is no AAAA for
// a service because the proxy is IPv4-only, like the DNS listener.
func Build(st *peers.Status, now time.Time, services ...string) *Index {
	var proxyIPs []netip.Addr
	if st.Self != nil {
		proxyIPs = st.Self.IPv4
	}
	isService := map[string]bool{}
	if len(proxyIPs) > 0 {
		for _, s := range services {
			isService[s] = true
		}
	}

	groups := map[string][]peers.Peer{}
	for _, p := range st.Peers {
		name := strings.ToLower(p.Name)
		if !isService[name] {
			groups[name] = append(groups[name], p)
		}
	}

	idx := &Index{Built: now, byName: make(map[string]int, len(groups)), Skipped: st.Skipped}
	names := make([]string, 0, len(groups)+len(isService))
	for n := range groups {
		names = append(names, n)
	}
	for n := range isService {
		names = append(names, n)
	}
	sort.Strings(names)

	for _, name := range names {
		if isService[name] {
			idx.byName[name] = len(idx.records)
			idx.records = append(idx.records, Record{Name: name, IPv4: proxyIPs, Online: true, Service: true, ID: "service"})
			continue
		}
		g := groups[name]
		sort.Slice(g, func(i, j int) bool { return g[i].ID < g[j].ID })
		w := g[0]
		if len(g) > 1 {
			c := Collision{Name: name, Winner: w.ID}
			for _, l := range g[1:] {
				c.Losers = append(c.Losers, l.ID)
			}
			idx.Collisions = append(idx.Collisions, c)
		}
		idx.byName[name] = len(idx.records)
		idx.records = append(idx.records, Record{
			Name: name, IPv4: w.IPv4, IPv6: w.IPv6, Online: w.Online, Self: w.Self, ID: w.ID,
		})
	}
	return idx
}

// Lookup finds a record by name, case-insensitively.
func (i *Index) Lookup(name string) (Record, bool) {
	if i == nil {
		return Record{}, false
	}
	n, ok := i.byName[strings.ToLower(name)]
	if !ok {
		return Record{}, false
	}
	return i.records[n], true
}

// Records returns all records sorted by name. The slice must not be modified.
func (i *Index) Records() []Record {
	if i == nil {
		return nil
	}
	return i.records
}

// Len is the number of records.
func (i *Index) Len() int {
	if i == nil {
		return 0
	}
	return len(i.records)
}

// Store holds the current index plus refresh health. It is safe for
// concurrent use.
type Store struct {
	cur atomic.Pointer[Index]

	mu        sync.Mutex
	lastTry   time.Time
	lastOK    time.Time
	lastErr   string
	failCount int
}

// Load returns the current index, or nil before the first successful refresh.
func (s *Store) Load() *Index { return s.cur.Load() }

// Swap publishes a new index after a successful refresh.
func (s *Store) Swap(idx *Index) {
	s.cur.Store(idx)
	s.mu.Lock()
	s.lastTry, s.lastOK, s.lastErr, s.failCount = idx.Built, idx.Built, "", 0
	s.mu.Unlock()
}

// Fail records a failed refresh. The last good index stays in place.
func (s *Store) Fail(at time.Time, err error) {
	s.mu.Lock()
	s.lastTry, s.lastErr = at, err.Error()
	s.failCount++
	s.mu.Unlock()
}

// Health is a point-in-time view of refresh state.
type Health struct {
	LastTry          time.Time
	LastOK           time.Time
	LastError        string
	ConsecutiveFails int
}

// Health returns the current refresh state.
func (s *Store) Health() Health {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Health{LastTry: s.lastTry, LastOK: s.lastOK, LastError: s.lastErr, ConsecutiveFails: s.failCount}
}
