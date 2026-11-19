package setup

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type fixture struct {
	srv      *Server
	h        http.Handler
	finished []Answers
	cfCalls  int
	now      time.Time
}

func newFixture() *fixture {
	f := &fixture{now: time.Unix(1000, 0)}
	f.srv = &Server{
		Code: "ABCD-EFGH-JKLM", IP: "100.64.0.1", MinPassword: 12,
		CheckZone: func(z string) (string, error) {
			z = strings.ToLower(strings.TrimSpace(z))
			if !strings.Contains(z, ".") {
				return "", errors.New("bad zone")
			}
			return z, nil
		},
		CheckToken: func(_ context.Context, tok, zone string) error {
			f.cfCalls++
			if tok != "good-token" {
				return errors.New("the token is invalid")
			}
			return nil
		},
		Finish: func(a Answers) error { f.finished = append(f.finished, a); return nil },
		Now:    func() time.Time { return f.now },
	}
	f.h = f.srv.Handler()
	return f
}

func (f *fixture) post(path string, body map[string]string, mod ...func(*http.Request)) (int, map[string]string) {
	b, _ := json.Marshal(body)
	r := httptest.NewRequest(http.MethodPost, "http://100.64.0.1:9581"+path, strings.NewReader(string(b)))
	r.Header.Set("X-Tarn-Request", "1")
	for _, m := range mod {
		m(r)
	}
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, r)
	var out map[string]string
	json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func TestHappyPath(t *testing.T) {
	f := newFixture()
	// Codes are forgiving about case, spaces and dashes.
	if code, out := f.post("/setup/code", map[string]string{"code": "abcd efgh jklm"}); code != 200 || out["ip"] != "100.64.0.1" {
		t.Fatalf("code: %d %v", code, out)
	}
	if code, out := f.post("/setup/token", map[string]string{"code": "ABCDEFGHJKLM", "zone": " T.Example.com ", "token": "good-token"}); code != 200 || out["zone"] != "t.example.com" {
		t.Fatalf("token: %d %v", code, out)
	}
	code, out := f.post("/setup/finish", map[string]string{"code": "ABCD-EFGH-JKLM", "zone": "t.example.com", "token": "good-token", "password": "correct horse battery", "email": "me@example.com"})
	if code != 200 || len(f.finished) != 1 {
		t.Fatalf("finish: %d %v", code, out)
	}
	if a := f.finished[0]; a.Zone != "t.example.com" || a.Token != "good-token" || a.Password != "correct horse battery" || a.Email != "me@example.com" {
		t.Errorf("answers %+v", a)
	}
	if f.cfCalls != 1 {
		t.Errorf("Cloudflare checked %d times, want once", f.cfCalls)
	}
	if !f.srv.Done() {
		t.Error("not done")
	}
	// Single use.
	if code, _ := f.post("/setup/finish", map[string]string{"code": "ABCD-EFGH-JKLM", "zone": "t.example.com", "token": "good-token", "password": "another long password"}); code != http.StatusGone {
		t.Errorf("second finish: %d", code)
	}
}

func TestFinishNeedsCheckedToken(t *testing.T) {
	f := newFixture()
	body := map[string]string{"code": "ABCD-EFGH-JKLM", "zone": "t.example.com", "token": "good-token", "password": "correct horse battery"}
	if code, out := f.post("/setup/finish", body); code != 400 || !strings.Contains(out["error"], "check the Cloudflare token") {
		t.Fatalf("unchecked token: %d %v", code, out)
	}
	f.post("/setup/token", map[string]string{"code": "ABCD-EFGH-JKLM", "zone": "t.example.com", "token": "good-token"})
	// A token checked for one zone doesn't count for another.
	body["zone"] = "other.example.com"
	if code, _ := f.post("/setup/finish", body); code != 400 {
		t.Errorf("token checked for another zone: %d", code)
	}
	body["zone"], body["password"] = "t.example.com", "short"
	if code, out := f.post("/setup/finish", body); code != 400 || !strings.Contains(out["error"], "12 to 72") {
		t.Errorf("short password: %d %v", code, out)
	}
	if len(f.finished) != 0 {
		t.Error("finished anyway")
	}
}

func TestBadToken(t *testing.T) {
	f := newFixture()
	if code, out := f.post("/setup/token", map[string]string{"code": "ABCD-EFGH-JKLM", "zone": "t.example.com", "token": "nope"}); code != 400 || out["error"] != "the token is invalid" {
		t.Errorf("%d %v", code, out)
	}
}

func TestWrongCodesLockOut(t *testing.T) {
	f := newFixture()
	for i := 0; i < maxFails; i++ {
		if code, _ := f.post("/setup/code", map[string]string{"code": "WRONG"}); code != http.StatusForbidden {
			t.Fatalf("wrong code %d: %d", i, code)
		}
	}
	// Even the right code is refused while locked.
	if code, _ := f.post("/setup/code", map[string]string{"code": "ABCD-EFGH-JKLM"}); code != http.StatusTooManyRequests {
		t.Fatalf("locked: %d", code)
	}
	f.now = f.now.Add(failWindow + time.Second)
	if code, _ := f.post("/setup/code", map[string]string{"code": "ABCD-EFGH-JKLM"}); code != 200 {
		t.Errorf("after the window: %d", code)
	}
}

func TestForgeryChecks(t *testing.T) {
	f := newFixture()
	good := map[string]string{"code": "ABCD-EFGH-JKLM"}
	for name, mod := range map[string]func(*http.Request){
		"no header":    func(r *http.Request) { r.Header.Del("X-Tarn-Request") },
		"named host":   func(r *http.Request) { r.Host = "evil.example.com" },
		"other origin": func(r *http.Request) { r.Header.Set("Origin", "http://evil.example.com") },
	} {
		if code, _ := f.post("/setup/code", good, mod); code != http.StatusForbidden {
			t.Errorf("%s: %d", name, code)
		}
	}
	if code, _ := f.post("/setup/code", good, func(r *http.Request) { r.Header.Set("Origin", "http://100.64.0.1:9581") }); code != 200 {
		t.Errorf("same origin: %d", code)
	}
}

func TestNewCode(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		c := NewCode()
		if len(c) != 14 || c[4] != '-' || c[9] != '-' || strings.ContainsAny(c, "01IOL") {
			t.Fatalf("code %q", c)
		}
		seen[c] = true
	}
	if len(seen) != 100 {
		t.Error("repeated codes")
	}
}

func TestPage(t *testing.T) {
	f := newFixture()
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://100.64.0.1:9581/", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "Set up tarn") || rec.Header().Get("Content-Security-Policy") == "" {
		t.Errorf("page: %d", rec.Code)
	}
}
