package health

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/elliotnorth/tarn/internal/index"
	"github.com/elliotnorth/tarn/internal/peers"
)

func get(t *testing.T, h http.Handler, path, token string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var body map[string]any
	json.Unmarshal(rec.Body.Bytes(), &body)
	return rec, body
}

func storeAt(built time.Time) *index.Store {
	s := &index.Store{}
	s.Swap(index.Build(&peers.Status{Peers: []peers.Peer{
		{ID: "n1", Name: "box", IPv4: []netip.Addr{netip.MustParseAddr("100.64.0.1")}},
	}}, built))
	return s
}

func TestHealthz(t *testing.T) {
	now := time.Unix(1000, 0)

	// Before the first refresh.
	srv := &Server{Store: &index.Store{}, Interval: 30 * time.Second, Now: func() time.Time { return now }}
	rec, body := get(t, srv.Handler(), "/healthz", "")
	if rec.Code != http.StatusServiceUnavailable || body["status"] != "starting" {
		t.Errorf("starting: %d %v", rec.Code, body)
	}

	// Fresh data.
	srv.Store = storeAt(now.Add(-10 * time.Second))
	rec, body = get(t, srv.Handler(), "/healthz", "")
	if rec.Code != http.StatusOK || body["status"] != "ok" || body["records"] != 1.0 {
		t.Errorf("ok: %d %v", rec.Code, body)
	}

	// Refreshes failing for longer than 3 intervals.
	srv.Store = storeAt(now.Add(-2 * time.Minute))
	srv.Store.Fail(now, errors.New("tailscaled not running"))
	rec, body = get(t, srv.Handler(), "/healthz", "")
	if rec.Code != http.StatusServiceUnavailable || body["status"] != "stale" || body["last_error"] != "tailscaled not running" {
		t.Errorf("stale: %d %v", rec.Code, body)
	}
}

func TestRecordsToken(t *testing.T) {
	srv := &Server{Store: storeAt(time.Now()), Interval: 30 * time.Second, Token: "s3cret"}
	h := srv.Handler()

	if rec, _ := get(t, h, "/records", ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("no token: %d", rec.Code)
	}
	if rec, _ := get(t, h, "/records", "wrong"); rec.Code != http.StatusUnauthorized {
		t.Errorf("wrong token: %d", rec.Code)
	}
	rec, _ := get(t, h, "/records", "s3cret")
	if rec.Code != http.StatusOK {
		t.Fatalf("right token: %d", rec.Code)
	}
	var recs []index.Record
	if err := json.Unmarshal(rec.Body.Bytes(), &recs); err != nil || len(recs) != 1 || recs[0].Name != "box" {
		t.Errorf("records = %s (%v)", rec.Body, err)
	}
}

func TestRecordsNoToken(t *testing.T) {
	srv := &Server{Store: &index.Store{}, Interval: time.Second}
	rec, _ := get(t, srv.Handler(), "/records", "")
	if rec.Code != http.StatusOK || rec.Body.String() != "[]\n" {
		t.Errorf("empty records: %d %q", rec.Code, rec.Body)
	}
}

func TestCheckLoopback(t *testing.T) {
	for addr, ok := range map[string]bool{
		"127.0.0.1:9580": true, "[::1]:9580": true, "localhost:9580": true,
		"100.64.0.1:9580": false, "0.0.0.0:9580": false, ":9580": false, "nonsense": false,
	} {
		if err := CheckLoopback(addr); (err == nil) != ok {
			t.Errorf("CheckLoopback(%q) = %v", addr, err)
		}
	}
}

func TestUI(t *testing.T) {
	srv := &Server{Store: &index.Store{}, Interval: time.Second, Token: "s3cret"}
	h := srv.Handler()

	// The page itself holds no data, so it needs no token.
	rec, _ := get(t, h, "/", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "<title>tarn</title>") {
		t.Fatalf("GET / = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q", ct)
	}
	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "connect-src 'self'") {
		t.Errorf("CSP = %q", csp)
	}
	if rec, _ := get(t, h, "/nope", ""); rec.Code != http.StatusNotFound {
		t.Errorf("GET /nope = %d, want 404", rec.Code)
	}
	if strings.Contains(string(uiPage), "innerHTML =") {
		t.Error("the page must not build markup from strings")
	}
}

func TestServices(t *testing.T) {
	srv := &Server{Store: &index.Store{}, Interval: time.Second, Token: "s3cret",
		Services: func() any {
			return []map[string]string{{"name": "app", "upstream": "https://app.example-tailnet.ts.net"}}
		}}
	h := srv.Handler()
	if rec, _ := get(t, h, "/services", ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("no token: %d, want 401", rec.Code)
	}
	rec, _ := get(t, h, "/services", "s3cret")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "app.example-tailnet.ts.net") {
		t.Errorf("with token: %d %s", rec.Code, rec.Body)
	}

	none := (&Server{Store: &index.Store{}, Interval: time.Second}).Handler()
	if rec, _ := get(t, none, "/services", ""); rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Errorf("no services: %d %q", rec.Code, rec.Body)
	}
}

func TestHealthzZoneAndDNS(t *testing.T) {
	srv := &Server{Store: storeAt(time.Now()), Interval: 30 * time.Second, Zone: "t.example.com",
		DNS: func() any { return map[string]uint64{"answered": 3} }}
	_, body := get(t, srv.Handler(), "/healthz", "")
	if body["zone"] != "t.example.com" {
		t.Errorf("zone = %v", body["zone"])
	}
	if d, _ := body["dns"].(map[string]any); d["answered"] != float64(3) {
		t.Errorf("dns = %v", body["dns"])
	}
}
