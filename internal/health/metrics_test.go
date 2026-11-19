package health

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/elliotnorth/tarn/internal/certs"
	"github.com/elliotnorth/tarn/internal/index"
)

func TestMetricsOffByDefault(t *testing.T) {
	srv := &Server{Store: storeAt(time.Now()), Interval: 30 * time.Second}
	if rec, _ := get(t, srv.Handler(), "/metrics", ""); rec.Code != http.StatusNotFound {
		t.Errorf("metrics off: %d", rec.Code)
	}
}

func TestMetrics(t *testing.T) {
	now := time.Unix(1000, 0)
	notAfter := time.Unix(5000, 0)
	srv := &Server{
		Store: storeAt(now.Add(-10 * time.Second)), Interval: 30 * time.Second,
		Version: "v0.4.1", Metrics: true, Token: "s3cret",
		Now: func() time.Time { return now },
		DNS: func() any { return map[string]uint64{"answered": 7, "refused": 2} },
		TLS: func() any { return certs.Status{NotAfter: &notAfter, ConsecutiveFails: 3} },
	}

	// Open on loopback even with a records token, like /healthz.
	rec, _ := get(t, srv.Handler(), "/metrics", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("loopback: %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain; version=0.0.4") {
		t.Errorf("content type %q", ct)
	}
	body := rec.Body.String()
	for _, want := range []string{
		`tarn_build_info{version="v0.4.1"} 1`,
		"tarn_records 1\n",
		"tarn_peer_refresh_last_success_timestamp_seconds 990\n",
		"tarn_peer_refresh_consecutive_failures 0\n",
		"tarn_peer_data_fresh 1\n",
		`tarn_dns_replies_total{outcome="answered"} 7`,
		`tarn_dns_replies_total{outcome="refused"} 2`,
		"# TYPE tarn_dns_replies_total counter\n",
		"tarn_cert_not_after_timestamp_seconds 5000\n",
		"tarn_cert_renew_by_timestamp_seconds 0\n",
		"tarn_cert_consecutive_failures 3\n",
		"tarn_cert_staging 0\n",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in:\n%s", want, body)
		}
	}
	if strings.Contains(body, "box") || strings.Contains(body, "100.64.") {
		t.Errorf("metrics leak device names or addresses:\n%s", body)
	}
}

func TestMetricsThroughProxy(t *testing.T) {
	srv := &Server{Store: storeAt(time.Now()), Interval: 30 * time.Second, Metrics: true}
	h := srv.Handler()
	req := func(token string) int {
		r := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		r.Header.Set("X-Forwarded-For", "100.64.0.9")
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec.Code
	}

	// No token configured: the proxy still needs sign-in.
	if code := req(""); code != http.StatusUnauthorized {
		t.Errorf("proxy, no token set: %d", code)
	}
	srv.Token = "s3cret"
	if code := req("wrong"); code != http.StatusUnauthorized {
		t.Errorf("proxy, wrong token: %d", code)
	}
	if code := req("s3cret"); code != http.StatusOK {
		t.Errorf("proxy, right token: %d", code)
	}
}

func TestMetricsStarting(t *testing.T) {
	// Before the first refresh: no index, no timestamps, not fresh.
	srv := &Server{Store: &index.Store{}, Interval: 30 * time.Second, Metrics: true}
	rec, _ := get(t, srv.Handler(), "/metrics", "")
	body := rec.Body.String()
	for _, want := range []string{
		"tarn_records 0\n",
		"tarn_peer_refresh_last_success_timestamp_seconds 0\n",
		"tarn_peer_data_fresh 0\n",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in:\n%s", want, body)
		}
	}
	if strings.Contains(body, "tarn_cert_") || strings.Contains(body, "tarn_dns_") {
		t.Errorf("cert or DNS metrics without a source:\n%s", body)
	}
}
