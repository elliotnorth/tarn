package certs

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestIssueLimitPerWeek(t *testing.T) {
	c, k := selfSigned(t, "*.t.example.com")
	m, n := manager(t, c, k, nil)
	m.ariDue = func(context.Context, *x509.Certificate, time.Time) bool { return true }
	for i := 0; i < maxIssuedPerWeek; i++ {
		if _, issued, err := m.Ensure(context.Background(), t0.Add(time.Duration(i)*2*time.Hour)); err != nil || !issued {
			t.Fatalf("issue %d: issued=%v err=%v", i, issued, err)
		}
	}
	_, _, err := m.Ensure(context.Background(), t0.Add(24*time.Hour))
	if err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Fatalf("err = %v, want a refusal", err)
	}
	if *n != maxIssuedPerWeek {
		t.Errorf("issued %d, want %d", *n, maxIssuedPerWeek)
	}
	if got := m.IssuedThisWeek(t0.Add(24 * time.Hour)); got != maxIssuedPerWeek {
		t.Errorf("IssuedThisWeek = %d", got)
	}
	// The limit is a sliding window.
	if _, issued, err := m.Ensure(context.Background(), t0.Add(8*24*time.Hour)); err != nil || !issued {
		t.Errorf("a week later: issued=%v err=%v", issued, err)
	}
}

func TestIssueLimitPerHourCountsFailures(t *testing.T) {
	m, n := manager(t, nil, nil, errors.New("validation failed"))
	for i := 0; i < maxAttemptsPerHour; i++ {
		m.Ensure(context.Background(), t0.Add(time.Duration(i)*time.Minute))
	}
	_, _, err := m.Ensure(context.Background(), t0.Add(10*time.Minute))
	if err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Fatalf("err = %v, want a refusal", err)
	}
	if *n != maxAttemptsPerHour {
		t.Errorf("tried %d times, want %d", *n, maxAttemptsPerHour)
	}
}

func TestZonesKeepSeparateCertificates(t *testing.T) {
	dir := t.TempDir()
	a1, a2 := selfSigned(t, "*.a.example.com")
	b1, b2 := selfSigned(t, "*.b.example.com")
	mk := func(zone string, c, k []byte) (*Manager, *int) {
		m := New(Config{Zone: zone, Staging: true, Dir: dir})
		n := 0
		m.obtain = func(context.Context) ([]byte, []byte, error) { n++; return c, k, nil }
		m.ariDue = func(context.Context, *x509.Certificate, time.Time) bool { return false }
		return m, &n
	}
	ma, na := mk("a.example.com", a1, a2)
	mb, _ := mk("b.example.com", b1, b2)
	for _, m := range []*Manager{ma, mb} {
		if _, _, err := m.Ensure(context.Background(), t0); err != nil {
			t.Fatal(err)
		}
	}
	// Going back to the first zone reuses its certificate.
	again, nAgain := mk("a.example.com", a1, a2)
	if again.WillIssue(t0) {
		t.Error("WillIssue with a stored certificate")
	}
	if _, issued, err := again.Ensure(context.Background(), t0); err != nil || issued {
		t.Errorf("revert: issued=%v err=%v", issued, err)
	}
	if *na != 1 || *nAgain != 0 {
		t.Errorf("issued %d and %d, want 1 and 0", *na, *nAgain)
	}

	var set Set
	set.Replace(mb, ma)
	for name, want := range map[string]string{"x.a.example.com": "*.a.example.com", "x.b.example.com": "*.b.example.com", "": "*.b.example.com"} {
		c, err := set.GetCertificate(&tls.ClientHelloInfo{ServerName: name})
		if err != nil || c.Leaf.DNSNames[0] != want {
			t.Errorf("%q: %v, %v", name, c, err)
		}
	}
}

func TestLegacyLayoutIsCopied(t *testing.T) {
	c, k := selfSigned(t, "*.t.example.com")
	m, n := manager(t, c, k, nil)
	if err := os.MkdirAll(m.root, 0o700); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(m.root, "cert.pem"), c, 0o600)
	os.WriteFile(filepath.Join(m.root, "key.pem"), k, 0o600)
	if _, issued, err := m.Ensure(context.Background(), t0); err != nil || issued {
		t.Fatalf("issued=%v err=%v", issued, err)
	}
	if *n != 0 {
		t.Errorf("issued %d, want 0", *n)
	}
	if _, err := os.Stat(filepath.Join(m.root, "cert.pem")); err != nil {
		t.Error("the old copy should stay, so an older tarn still works")
	}
}

func TestCloudflareCheck(t *testing.T) {
	created, deleted := 0, 0
	readOnly := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer s3cr3t" {
			t.Errorf("Authorization = %q", r.Header.Get("Authorization"))
		}
		reply := func(ok bool, res any, msg string) {
			out := map[string]any{"success": ok, "result": res, "errors": []map[string]string{}}
			if msg != "" {
				out["errors"] = []map[string]string{{"message": msg}}
			}
			json.NewEncoder(w).Encode(out)
		}
		switch {
		case r.URL.Path == "/user/tokens/verify":
			reply(true, map[string]string{"status": "active"}, "")
		case r.URL.Path == "/zones" && r.URL.Query().Get("name") == "example.com":
			reply(true, []map[string]string{{"id": "z1"}}, "")
		case r.URL.Path == "/zones":
			reply(true, []map[string]string{}, "")
		case r.Method == "POST" && r.URL.Path == "/zones/z1/dns_records":
			if readOnly {
				w.WriteHeader(403)
				reply(false, nil, "Authentication error")
				return
			}
			created++
			reply(true, map[string]string{"id": "r1"}, "")
		case r.Method == "DELETE" && r.URL.Path == "/zones/z1/dns_records/r1":
			deleted++
			reply(true, map[string]string{"id": "r1"}, "")
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL)
		}
	}))
	defer srv.Close()
	cf := &Cloudflare{Token: "s3cr3t", BaseURL: srv.URL}
	ctx := context.Background()

	if err := cf.Verify(ctx); err != nil {
		t.Error(err)
	}
	if err := cf.CheckZone(ctx, "t2.example.com"); err != nil {
		t.Error(err)
	}
	if created != 1 || deleted != 1 {
		t.Errorf("created %d, deleted %d", created, deleted)
	}
	if err := cf.CheckZone(ctx, "t.other.test"); err == nil || !strings.Contains(err.Error(), "can't see") {
		t.Errorf("unknown zone: %v", err)
	}
	readOnly = true
	if err := cf.CheckZone(ctx, "t2.example.com"); err == nil || !strings.Contains(err.Error(), "can't edit") {
		t.Errorf("read-only token: %v", err)
	}
	if err := cf.CheckZone(ctx, "t2.example.com"); err != nil && strings.Contains(err.Error(), "s3cr3t") {
		t.Errorf("the token leaked into an error: %v", err)
	}
}
