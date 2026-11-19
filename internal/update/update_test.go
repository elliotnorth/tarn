package update

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeRelease serves a signed release the way GitHub lays one out.
type fakeRelease struct {
	tag  string
	bin  []byte
	sums []byte
	sig  []byte
	pub  ed25519.PublicKey
	hits []string
	srv  *httptest.Server
}

func newRelease(t *testing.T, tag string, bin []byte) *fakeRelease {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sum := sha256.Sum256(bin)
	sums := []byte(hex.EncodeToString(sum[:]) + "  tarn-linux-amd64\n" + strings.Repeat("0", 64) + "  install.sh\n")
	r := &fakeRelease{tag: tag, bin: bin, sums: sums, sig: ed25519.Sign(priv, sums), pub: pub}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.hits = append(r.hits, req.URL.Path)
		dl := "/download/" + r.tag + "/"
		switch {
		case req.URL.Path == "/latest":
			w.Header().Set("Location", "https://github.com/elliotnorth/tarn/releases/tag/"+r.tag)
			w.WriteHeader(http.StatusFound)
		case req.URL.Path == dl+"SHA256SUMS":
			w.Write(r.sums)
		case req.URL.Path == dl+"SHA256SUMS.sig":
			w.Write(r.sig)
		case req.URL.Path == dl+"tarn-linux-amd64":
			w.Write(r.bin)
		default:
			http.NotFound(w, req)
		}
	}))
	t.Cleanup(r.srv.Close)
	return r
}

type harness struct {
	u        *Updater
	exe      string
	calls    []string
	health   func(n int) (Health, error)
	healthN  int
	versions map[string]string // binary contents -> what -version prints
}

func newHarness(t *testing.T, r *fakeRelease) *harness {
	t.Helper()
	exe := filepath.Join(t.TempDir(), "tarn")
	if err := os.WriteFile(exe, []byte("old binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	h := &harness{exe: exe, versions: map[string]string{"old binary": "tarn v0.4.0\n"}}
	h.versions[string(r.bin)] = "tarn " + r.tag + "\n"
	var out bytes.Buffer
	h.u = &Updater{
		Client: r.srv.Client(), Repo: r.srv.URL, Key: r.pub, Arch: "amd64",
		Exe: exe, Current: "v0.4.0", Wait: 50 * time.Millisecond, Poll: time.Millisecond, Out: &out,
		Systemctl: func(args ...string) error {
			h.calls = append(h.calls, strings.Join(args, " "))
			return nil
		},
		VersionOf: func(path string) (string, error) {
			b, err := os.ReadFile(path)
			if err != nil {
				return "", err
			}
			v, ok := h.versions[string(b)]
			if !ok {
				return "", errors.New("exec format error")
			}
			return v, nil
		},
		Health: func(context.Context) (Health, error) {
			h.healthN++
			return h.health(h.healthN)
		},
	}
	// By default: healthy as whatever binary is in place.
	h.health = func(int) (Health, error) {
		b, _ := os.ReadFile(exe)
		v := strings.TrimSpace(strings.TrimPrefix(h.versions[string(b)], "tarn "))
		return Health{Version: v, Status: "ok"}, nil
	}
	return h
}

func (h *harness) installed(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(h.exe)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestLatestTag(t *testing.T) {
	r := newRelease(t, "v0.4.1", []byte("new"))
	h := newHarness(t, r)
	tag, err := h.u.LatestTag(context.Background())
	if err != nil || tag != "v0.4.1" {
		t.Fatalf("%q %v", tag, err)
	}
	r.tag = "v0.4.1/../../evil"
	if _, err := h.u.LatestTag(context.Background()); err == nil {
		t.Error("a path in the tag was accepted")
	}
}

func TestUpdateHappyPath(t *testing.T) {
	r := newRelease(t, "v0.4.1", []byte("new binary"))
	h := newHarness(t, r)
	ctx := context.Background()
	bin, err := h.u.Download(ctx, "v0.4.1")
	if err != nil {
		t.Fatal(err)
	}
	if err := h.u.Install(ctx, "v0.4.1", bin); err != nil {
		t.Fatal(err)
	}
	if h.installed(t) != "new binary" {
		t.Errorf("installed %q", h.installed(t))
	}
	if b, _ := os.ReadFile(h.exe + ".previous"); string(b) != "old binary" {
		t.Errorf("previous %q", b)
	}
	if _, err := os.Stat(h.exe + ".new"); !os.IsNotExist(err) {
		t.Error(".new left behind")
	}
	if strings.Join(h.calls, ",") != "is-active --quiet tarn,restart tarn" {
		t.Errorf("systemctl calls %v", h.calls)
	}
}

func TestBadSignatureChangesNothing(t *testing.T) {
	r := newRelease(t, "v0.4.1", []byte("new binary"))
	r.sig[0] ^= 1
	h := newHarness(t, r)
	if _, err := h.u.Download(context.Background(), "v0.4.1"); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("err %v", err)
	}
	for _, p := range r.hits {
		if strings.HasSuffix(p, "tarn-linux-amd64") {
			t.Error("downloaded the binary before checking the signature")
		}
	}
}

func TestBadChecksum(t *testing.T) {
	r := newRelease(t, "v0.4.1", []byte("new binary"))
	r.bin = []byte("tampered binary")
	h := newHarness(t, r)
	if _, err := h.u.Download(context.Background(), "v0.4.1"); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("err %v", err)
	}
}

func TestOtherKeyRejected(t *testing.T) {
	r := newRelease(t, "v0.4.1", []byte("new binary"))
	h := newHarness(t, r)
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	h.u.Key = other
	if _, err := h.u.Download(context.Background(), "v0.4.1"); err == nil {
		t.Fatal("a release signed by another key was accepted")
	}
}

func TestNoBinaryForArch(t *testing.T) {
	r := newRelease(t, "v0.4.1", []byte("new binary"))
	h := newHarness(t, r)
	h.u.Arch = "riscv64"
	if _, err := h.u.Download(context.Background(), "v0.4.1"); err == nil || !strings.Contains(err.Error(), "no tarn-linux-riscv64") {
		t.Fatalf("err %v", err)
	}
}

func TestBinaryThatWontRunIsNotInstalled(t *testing.T) {
	r := newRelease(t, "v0.4.1", []byte("wrong arch"))
	h := newHarness(t, r)
	delete(h.versions, "wrong arch")
	err := h.u.Install(context.Background(), "v0.4.1", r.bin)
	if err == nil || !strings.Contains(err.Error(), "Nothing was changed") {
		t.Fatalf("err %v", err)
	}
	if h.installed(t) != "old binary" || len(h.calls) != 0 {
		t.Errorf("installed %q, calls %v", h.installed(t), h.calls)
	}
	if _, err := os.Stat(h.exe + ".new"); !os.IsNotExist(err) {
		t.Error(".new left behind")
	}
}

func TestUnhealthyReleaseRollsBack(t *testing.T) {
	r := newRelease(t, "v0.4.1", []byte("broken binary"))
	h := newHarness(t, r)
	base := h.health
	h.health = func(n int) (Health, error) {
		if h.installed(t) == "broken binary" {
			return Health{}, errors.New("connection refused")
		}
		return base(n)
	}
	err := h.u.Install(context.Background(), "v0.4.1", r.bin)
	if err == nil || !strings.Contains(err.Error(), "rolled back to v0.4.0, which is running") {
		t.Fatalf("err %v", err)
	}
	if h.installed(t) != "old binary" {
		t.Errorf("installed %q after rollback", h.installed(t))
	}
	if strings.Join(h.calls, ",") != "is-active --quiet tarn,restart tarn,restart tarn" {
		t.Errorf("systemctl calls %v", h.calls)
	}
}

func TestStaleBeforeStaysAcceptable(t *testing.T) {
	// Tailscale is down: old and new both report stale. That's not the
	// update's fault, so it must not roll back.
	r := newRelease(t, "v0.4.1", []byte("new binary"))
	h := newHarness(t, r)
	base := h.health
	h.health = func(n int) (Health, error) {
		hl, err := base(n)
		hl.Status = "stale"
		return hl, err
	}
	if err := h.u.Install(context.Background(), "v0.4.1", r.bin); err != nil {
		t.Fatal(err)
	}
	if h.installed(t) != "new binary" {
		t.Error("rolled back a stale-but-answering update")
	}
}

func TestNotRunningIsNotStarted(t *testing.T) {
	r := newRelease(t, "v0.4.1", []byte("new binary"))
	h := newHarness(t, r)
	h.u.Systemctl = func(args ...string) error {
		h.calls = append(h.calls, strings.Join(args, " "))
		if args[0] == "is-active" {
			return errors.New("inactive")
		}
		return nil
	}
	if err := h.u.Install(context.Background(), "v0.4.1", r.bin); err != nil {
		t.Fatal(err)
	}
	if strings.Join(h.calls, ",") != "is-active --quiet tarn" {
		t.Errorf("calls %v", h.calls)
	}
}

func TestCompare(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"v0.4.0", "v0.4.1", -1}, {"v0.10.0", "v0.9.9", 1}, {"v1.0.0", "v1.0.0", 0},
		{"v0.5.0-rc1", "v0.5.0", -1}, {"v0.5.0", "v0.5.0-rc1", 1}, {"v0.5.0-rc1", "v0.5.0-rc2", -1},
	} {
		if got, ok := Compare(c.a, c.b); !ok || got != c.want {
			t.Errorf("Compare(%s, %s) = %d %v", c.a, c.b, got, ok)
		}
	}
	if _, ok := Compare("dev", "v0.4.1"); ok {
		t.Error("dev compared as a tag")
	}
}

func TestParsePublicKey(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(pub)
	got, err := ParsePublicKey(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	if err != nil || !got.Equal(pub) {
		t.Fatalf("%v %v", got, err)
	}
	if _, err := ParsePublicKey([]byte("nope")); err == nil {
		t.Error("garbage accepted")
	}
}
