package certs

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 8, 0, 0, 0, 0, time.UTC)

// selfSigned returns a PEM certificate and key valid for 90 days from t0.
func selfSigned(t *testing.T, names ...string) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		DNSNames:     names,
		NotBefore:    t0,
		NotAfter:     t0.Add(90 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

// manager returns a Manager whose issuance is counted and faked.
func manager(t *testing.T, certPEM, keyPEM []byte, issueErr error) (*Manager, *int) {
	t.Helper()
	m := New(Config{Zone: "t.example.com", Staging: true, Dir: t.TempDir()})
	n := 0
	m.obtain = func(context.Context) ([]byte, []byte, error) {
		n++
		return certPEM, keyPEM, issueErr
	}
	m.ariDue = func(context.Context, *x509.Certificate, time.Time) bool { return false }
	m.now = func() time.Time { return t0 }
	return m, &n
}

func TestRunBacksOffThenRecovers(t *testing.T) {
	c, k := selfSigned(t, "*.t.example.com")
	m, _ := manager(t, nil, nil, nil)
	m.check, m.minWait, m.maxWait = time.Hour, time.Millisecond, 2*time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	calls := 0
	m.obtain = func(context.Context) ([]byte, []byte, error) {
		calls++
		if calls < 3 {
			return nil, nil, errors.New("temporary")
		}
		cancel() // stop Run after this success
		return c, k, nil
	}
	m.Run(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)))

	if calls != 3 {
		t.Errorf("tried %d times, want 3", calls)
	}
	s := m.Status()
	if s.NotAfter == nil || s.LastIssued == nil || s.LastError != "" || s.ConsecutiveFails != 0 {
		t.Errorf("Status = %+v", s)
	}
	if s.Domain != "*.t.example.com" || !s.Staging {
		t.Errorf("Status = %+v", s)
	}
}

func TestExport(t *testing.T) {
	c, k := selfSigned(t, "*.t.example.com")
	m, _ := manager(t, c, k, nil)
	m.cfg.ExportDir = t.TempDir()
	cert, key := filepath.Join(m.cfg.ExportDir, "cert.pem"), filepath.Join(m.cfg.ExportDir, "key.pem")

	if _, _, err := m.Ensure(context.Background(), t0); err != nil {
		t.Fatal(err)
	}
	if err := m.export(); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(cert); string(b) != string(c) {
		t.Error("cert.pem differs from the issued certificate")
	}
	if runtime.GOOS != "windows" {
		for _, f := range []string{cert, key} {
			if st, err := os.Stat(f); err != nil || st.Mode().Perm() != 0o640 {
				t.Errorf("%s: mode %v, err %v; want 640", f, st.Mode().Perm(), err)
			}
		}
	}

	// An unchanged certificate is left alone, so a reload isn't triggered.
	os.Remove(key)
	if err := m.export(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(key); err == nil {
		t.Error("export rewrote an unchanged certificate")
	}

	// A changed certificate is copied again.
	os.WriteFile(cert, []byte("old"), 0o640)
	if err := m.export(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(key); err != nil {
		t.Error("export did not copy a changed certificate")
	}
}

func TestRunRecordsExportFailure(t *testing.T) {
	c, k := selfSigned(t, "*.t.example.com")
	m, _ := manager(t, c, k, nil)
	m.cfg.ExportDir = filepath.Join(t.TempDir(), "missing")
	m.minWait, m.maxWait = time.Hour, time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		m.Run(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)))
		close(done)
	}()
	for deadline := time.Now().Add(5 * time.Second); m.Status().ConsecutiveFails == 0; {
		if time.Now().After(deadline) {
			t.Fatal("no failure recorded")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
	s := m.Status()
	if s.LastIssued == nil || s.NotAfter == nil {
		t.Errorf("Status = %+v; the certificate was issued despite the export failure", s)
	}
	if c, err := m.GetCertificate(nil); err != nil || c == nil {
		t.Errorf("GetCertificate = %v, %v", c, err)
	}
}

func TestRunRecordsFailure(t *testing.T) {
	m, _ := manager(t, nil, nil, errors.New("no token"))
	m.minWait, m.maxWait = time.Hour, time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		m.Run(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)))
		close(done)
	}()
	for deadline := time.Now().Add(5 * time.Second); m.Status().ConsecutiveFails == 0; {
		if time.Now().After(deadline) {
			t.Fatal("no failure recorded")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
	if s := m.Status(); s.LastError != "no token" || s.ConsecutiveFails != 1 || s.NotAfter != nil {
		t.Errorf("Status = %+v", s)
	}
}

func TestEnsureRenewsWhenARISaysSo(t *testing.T) {
	c, k := selfSigned(t, "*.t.example.com")
	m, n := manager(t, c, k, nil)
	if _, _, err := m.Ensure(context.Background(), t0); err != nil {
		t.Fatal(err)
	}
	m.ariDue = func(context.Context, *x509.Certificate, time.Time) bool { return true }
	if _, issued, err := m.Ensure(context.Background(), t0.Add(time.Hour)); err != nil || !issued {
		t.Errorf("issued=%v err=%v, want a renewal", issued, err)
	}
	if *n != 2 {
		t.Errorf("issued %d times, want 2", *n)
	}
}

func TestEnsureIssuesOnceThenReuses(t *testing.T) {
	c, k := selfSigned(t, "*.t.example.com")
	m, n := manager(t, c, k, nil)

	leaf, issued, err := m.Ensure(context.Background(), t0.Add(time.Hour))
	if err != nil || !issued || leaf == nil {
		t.Fatalf("first Ensure: leaf=%v issued=%v err=%v", leaf, issued, err)
	}
	if _, issued, err = m.Ensure(context.Background(), t0.Add(2*time.Hour)); err != nil || issued {
		t.Fatalf("second Ensure: issued=%v err=%v", issued, err)
	}
	if *n != 1 {
		t.Errorf("issued %d times, want 1", *n)
	}
	if c, err := m.GetCertificate(nil); err != nil || c == nil {
		t.Errorf("GetCertificate = %v, %v", c, err)
	}
	if filepath.Base(m.root) != "staging" {
		t.Errorf("root = %s, want a staging directory", m.root)
	}
	if runtime.GOOS != "windows" {
		for _, f := range []string{"cert.pem", "key.pem"} {
			st, err := os.Stat(filepath.Join(m.dir, f))
			if err != nil {
				t.Fatal(err)
			}
			if st.Mode().Perm() != 0o600 {
				t.Errorf("%s mode = %o, want 600", f, st.Mode().Perm())
			}
		}
	}
}

func TestEnsureRenewsAfterTwoThirds(t *testing.T) {
	c, k := selfSigned(t, "*.t.example.com")
	m, n := manager(t, c, k, nil)
	if _, _, err := m.Ensure(context.Background(), t0); err != nil {
		t.Fatal(err)
	}
	if _, issued, _ := m.Ensure(context.Background(), t0.Add(59*24*time.Hour)); issued {
		t.Error("issued before the two-thirds point")
	}
	if _, issued, _ := m.Ensure(context.Background(), t0.Add(60*24*time.Hour)); !issued {
		t.Error("did not issue at the two-thirds point")
	}
	if *n != 2 {
		t.Errorf("issued %d times, want 2", *n)
	}
}

func TestGetCertificateBeforeIssue(t *testing.T) {
	m, _ := manager(t, nil, nil, nil)
	if _, err := m.GetCertificate(nil); err == nil {
		t.Error("want an error before any certificate exists")
	}
}

func TestEnsureServesAgingCertWhenRenewalFails(t *testing.T) {
	c, k := selfSigned(t, "*.t.example.com")
	m, _ := manager(t, c, k, nil)
	if _, _, err := m.Ensure(context.Background(), t0); err != nil {
		t.Fatal(err)
	}
	fresh := New(Config{Zone: "t.example.com", Staging: true, Dir: m.cfg.Dir})
	fresh.obtain = func(context.Context) ([]byte, []byte, error) { return nil, nil, errors.New("rate limited") }
	fresh.ariDue = func(context.Context, *x509.Certificate, time.Time) bool { return false }
	if _, _, err := fresh.Ensure(context.Background(), t0.Add(80*24*time.Hour)); err == nil {
		t.Fatal("want the issuance error")
	}
	if c, err := fresh.GetCertificate(nil); err != nil || c == nil {
		t.Errorf("GetCertificate = %v, %v; want the aging certificate", c, err)
	}
}

func TestEnsureReissuesForOtherZone(t *testing.T) {
	c, k := selfSigned(t, "*.old.example.com")
	m, _ := manager(t, c, k, nil)
	if err := os.MkdirAll(m.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if !needsIssue(mustLeaf(t, c, k), m.Domain(), t0) {
		t.Error("a certificate for another zone should need issuing")
	}
}

func TestEnsureKeepsWorkingPairOnFailure(t *testing.T) {
	c, k := selfSigned(t, "*.t.example.com")
	m, _ := manager(t, c, k, nil)
	if _, _, err := m.Ensure(context.Background(), t0); err != nil {
		t.Fatal(err)
	}
	want, _ := os.ReadFile(filepath.Join(m.dir, "cert.pem"))

	late := t0.Add(80 * 24 * time.Hour)
	m.obtain = func(context.Context) ([]byte, []byte, error) { return nil, nil, errors.New("rate limited") }
	if _, _, err := m.Ensure(context.Background(), late); err == nil {
		t.Error("want the issuance error")
	}
	m.obtain = func(context.Context) ([]byte, []byte, error) { return []byte("junk"), []byte("junk"), nil }
	if _, _, err := m.Ensure(context.Background(), late); err == nil {
		t.Error("want an error for an unusable certificate")
	}
	got, _ := os.ReadFile(filepath.Join(m.dir, "cert.pem"))
	if string(got) != string(want) {
		t.Error("the stored certificate was replaced")
	}
}

func TestEnsureReissuesMismatchedPair(t *testing.T) {
	c, k := selfSigned(t, "*.t.example.com")
	_, otherKey := selfSigned(t, "*.t.example.com")
	m, n := manager(t, c, k, nil)
	if _, _, err := m.Ensure(context.Background(), t0); err != nil {
		t.Fatal(err)
	}
	if err := writeFile(filepath.Join(m.dir, "key.pem"), otherKey); err != nil {
		t.Fatal(err)
	}
	if _, issued, err := m.Ensure(context.Background(), t0); err != nil || !issued {
		t.Errorf("issued=%v err=%v, want a fresh issue", issued, err)
	}
	if *n != 2 {
		t.Errorf("issued %d times, want 2", *n)
	}
}

func TestAccountKeyPersists(t *testing.T) {
	m := New(Config{Zone: "t.example.com", Dir: t.TempDir()})
	if filepath.Base(m.root) != "production" {
		t.Errorf("root = %s, want a production directory", m.root)
	}
	if err := os.MkdirAll(m.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	a, err := m.accountKey()
	if err != nil {
		t.Fatal(err)
	}
	b, err := m.accountKey()
	if err != nil {
		t.Fatal(err)
	}
	if !a.Public().(*ecdsa.PublicKey).Equal(b.Public()) {
		t.Error("account key changed between calls")
	}
}

func TestWriteFileLeavesNoTempFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x")
	for _, s := range []string{"one", "two"} {
		if err := writeFile(path, []byte(s)); err != nil {
			t.Fatal(err)
		}
	}
	if b, _ := os.ReadFile(path); string(b) != "two" {
		t.Errorf("content = %q", b)
	}
	if es, _ := os.ReadDir(dir); len(es) != 1 {
		t.Errorf("%d files in dir, want 1", len(es))
	}
}

func mustLeaf(t *testing.T, c, k []byte) *x509.Certificate {
	t.Helper()
	p, err := parsePair(c, k)
	if err != nil {
		t.Fatal(err)
	}
	return p.Leaf
}

func TestRenewalIsRecordedAndSurvivesRestart(t *testing.T) {
	c, k := selfSigned(t, "*.t.example.com")
	m, _ := manager(t, c, k, nil)
	if _, _, err := m.Ensure(context.Background(), t0); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.readRenewed(); ok {
		t.Fatal("the first certificate counted as a renewal")
	}
	at := t0.Add(60 * 24 * time.Hour)
	if _, issued, err := m.Ensure(context.Background(), at); err != nil || !issued {
		t.Fatalf("issued=%v err=%v, want a renewal", issued, err)
	}
	if got, ok := m.readRenewed(); !ok || !got.Equal(at) {
		t.Fatalf("renewal recorded as %v %v, want %v", got, ok, at)
	}

	// A new Manager on the same directory, as after a restart.
	again := New(Config{Zone: "t.example.com", Staging: true, Dir: filepath.Dir(m.root)})
	if again.root != m.root {
		t.Fatalf("root %s, want %s", again.root, m.root)
	}
	if s := again.Status(); s.LastRenewed == nil || !s.LastRenewed.Equal(at) {
		t.Fatalf("after restart LastRenewed = %v", s.LastRenewed)
	}
}

func TestStatusShowsRenewByAndNextCheck(t *testing.T) {
	c, k := selfSigned(t, "*.t.example.com")
	m, _ := manager(t, c, k, nil)
	if _, _, err := m.Ensure(context.Background(), t0); err != nil {
		t.Fatal(err)
	}
	m.record(false, nil, t0, 12*time.Hour)
	s := m.Status()
	if want := t0.Add(60 * 24 * time.Hour); s.RenewBy == nil || !s.RenewBy.Equal(want) {
		t.Errorf("RenewBy = %v, want %v", s.RenewBy, want)
	}
	if want := t0.Add(12 * time.Hour); s.NextCheck == nil || !s.NextCheck.Equal(want) {
		t.Errorf("NextCheck = %v, want %v", s.NextCheck, want)
	}
}
