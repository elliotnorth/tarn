// Package health serves the loopback-only management endpoints /healthz and
// /records.
package health

import (
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/elliotnorth/tarn/internal/index"
)

//go:embed ui.html
var uiPage []byte

// Server builds the management HTTP handler.
type Server struct {
	Store        *index.Store
	Interval     time.Duration // peer refresh interval; data older than 3× this is stale
	Token        string        // optional bearer token required on /records
	Version      string
	Zone         string
	ZoneNow      func() string        // the live zone; overrides Zone
	IntervalNow  func() time.Duration // the live interval; overrides Interval
	TokenHash    func() string        // hex SHA-256 of a page-managed records token, or ""
	DNS          func() any           // reply totals for /healthz; nil when off
	Services     func() any           // proxied services for /services; nil when none
	TLS          func() any           // certificate state for /healthz; nil when off
	SplitDNS     func() any           // a wrong split DNS route for /healthz, or nil
	Now          func() time.Time     // for tests; time.Now if nil
	Admin        *Admin               // changes from the status page; nil when off
	AdminWarning string               // why editing is off, shown on the page
	Metrics      bool                 // serve /metrics (Prometheus text)
	Log          *slog.Logger         // sign-ins and refused requests; discarded if nil

	mu       sync.Mutex
	sessions map[string]time.Time

	loginMu   sync.Mutex // one password check at a time; also guards the counters
	fails     int
	failStart time.Time

	auditMu    sync.Mutex
	auditStart time.Time
	auditN     int
}

func (s *Server) zone() string {
	if s.ZoneNow != nil {
		return s.ZoneNow()
	}
	return s.Zone
}

func (s *Server) interval() time.Duration {
	if s.IntervalNow != nil {
		return s.IntervalNow()
	}
	return s.Interval
}

func (s *Server) managedToken() string {
	if s.TokenHash != nil {
		return s.TokenHash()
	}
	return ""
}

func (s *Server) tokenOn() bool { return s.Token != "" || s.managedToken() != "" }

func (s *Server) tokenMatches(got string) bool {
	if s.Token != "" {
		return subtle.ConstantTimeCompare([]byte(got), []byte(s.Token)) == 1
	}
	sum := sha256.Sum256([]byte(got))
	return subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum[:])), []byte(s.managedToken())) == 1
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Handler returns the HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.healthz)
	mux.HandleFunc("GET /records", s.records)
	mux.HandleFunc("GET /services", s.services)
	mux.HandleFunc("GET /metrics", s.metrics)
	mux.HandleFunc("GET /{$}", s.ui)
	s.adminRoutes(mux)
	return mux
}

type healthzResp struct {
	Status           string            `json:"status"` // ok, stale, starting
	Version          string            `json:"version"`
	Zone             string            `json:"zone,omitempty"`
	Records          int               `json:"records"`
	LastRefresh      *time.Time        `json:"last_refresh,omitempty"`
	LastAttempt      *time.Time        `json:"last_attempt,omitempty"`
	LastError        string            `json:"last_error,omitempty"`
	ConsecutiveFails int               `json:"consecutive_failures"`
	Collisions       []index.Collision `json:"collisions,omitempty"`
	Skipped          []string          `json:"skipped,omitempty"`
	DNS              any               `json:"dns,omitempty"`
	TLS              any               `json:"tls,omitempty"`
	SplitDNS         any               `json:"split_dns,omitempty"`
	SelfHosted       bool              `json:"self_hosted,omitempty"` // Headscale or similar, not Tailscale
}

func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	// Open on loopback for monitoring. Through the proxy it needs sign-in.
	if viaProxy(r) && !s.authorized(w, r) {
		return
	}
	h := s.Store.Health()
	idx := s.Store.Load()
	resp := healthzResp{
		Version:          s.Version,
		Zone:             s.zone(),
		Records:          idx.Len(),
		LastError:        h.LastError,
		ConsecutiveFails: h.ConsecutiveFails,
	}
	if !h.LastOK.IsZero() {
		resp.LastRefresh = &h.LastOK
	}
	if !h.LastTry.IsZero() {
		resp.LastAttempt = &h.LastTry
	}
	if idx != nil {
		resp.Collisions, resp.Skipped, resp.SelfHosted = idx.Collisions, idx.Skipped, idx.SelfHosted
	}
	if s.DNS != nil {
		resp.DNS = s.DNS()
	}
	if s.TLS != nil {
		resp.TLS = s.TLS()
	}
	if s.SplitDNS != nil {
		resp.SplitDNS = s.SplitDNS()
	}

	code := http.StatusOK
	switch {
	case idx == nil:
		resp.Status, code = "starting", http.StatusServiceUnavailable
	case s.now().Sub(h.LastOK) > 3*s.interval():
		resp.Status, code = "stale", http.StatusServiceUnavailable
	default:
		resp.Status = "ok"
	}
	writeJSON(w, code, resp)
}

// authorized lets a request read the JSON endpoints, answering 401 if not. A
// session or the records token always works. With no token set, loopback is
// open but the proxy is not: "tarn http://127.0.0.1:9580" in the services file
// publishes this port to the tailnet.
func (s *Server) authorized(w http.ResponseWriter, r *http.Request) bool {
	if s.validSession(r) {
		return true
	}
	if s.tokenOn() {
		if got, ok := bearer(r); ok && s.tokenMatches(got) {
			return true
		}
	} else if !viaProxy(r) {
		return true
	}
	w.Header().Set("WWW-Authenticate", `Bearer realm="tarn"`)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
	return false
}

// ui serves the read-only status page. The page has no data of its own: it
// reads the JSON endpoints, so the token still protects the device list.
func (s *Server) ui(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; form-action 'none'; base-uri 'none'; frame-ancestors 'none'")
	w.Write(uiPage)
}

func (s *Server) services(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(w, r) {
		return
	}
	var list any = []struct{}{}
	if s.Services != nil {
		list = s.Services()
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) records(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(w, r) {
		return
	}
	recs := s.Store.Load().Records()
	if recs == nil {
		recs = []index.Record{}
	}
	writeJSON(w, http.StatusOK, recs)
}

func bearer(r *http.Request) (string, bool) {
	const p = "Bearer "
	h := r.Header.Get("Authorization")
	if len(h) <= len(p) || h[:len(p)] != p {
		return "", false
	}
	return h[len(p):], true
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

// CheckLoopback returns an error unless addr ("host:port") is on a loopback
// address. Management endpoints must never be reachable from the tailnet.
func CheckLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("management address %q: %w", addr, err)
	}
	if host == "localhost" {
		return nil
	}
	a, err := netip.ParseAddr(host)
	if err != nil || !a.IsLoopback() {
		return fmt.Errorf("management address %q must be a loopback address such as 127.0.0.1", addr)
	}
	return nil
}
