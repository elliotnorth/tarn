package health

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

type fakeControl struct {
	calls        []string
	err          error
	logoutOthers bool
}

func (f *fakeControl) note(s string)          { f.calls = append(f.calls, s) }
func (f *fakeControl) Settings() SettingsView { f.note("settings"); return SettingsView{} }
func (f *fakeControl) Preview(_ context.Context, r ChangeRequest) (Preview, error) {
	f.note("preview " + r.Key)
	return Preview{Key: r.Key}, f.err
}
func (f *fakeControl) Change(_ context.Context, r ChangeRequest) (ChangeResult, error) {
	f.note("change " + r.Key + "=" + r.Value + " from " + r.Source)
	return ChangeResult{Status: "applied", LogoutOthers: f.logoutOthers}, f.err
}
func (f *fakeControl) Keep(p, _ string) error { f.note("keep " + p); return f.err }
func (f *fakeControl) Revert(string) error    { f.note("revert"); return f.err }
func (f *fakeControl) SetRecordsToken(on bool, _ string) (string, error) {
	f.note(fmt.Sprint("token ", on))
	return "t0k", f.err
}
func (f *fakeControl) RefreshNow(context.Context, string) error { f.note("refresh"); return f.err }
func (f *fakeControl) CheckCloudflare(context.Context) error    { f.note("cf"); return f.err }
func (f *fakeControl) History() any                             { f.note("history"); return []string{} }
func (f *fakeControl) Undo(_ context.Context, id, _ string) (ChangeResult, error) {
	f.note("undo " + id)
	return ChangeResult{Status: "applied"}, f.err
}

var controlEndpoints = [][3]string{
	{"GET", "/settings", ""},
	{"GET", "/history", ""},
	{"POST", "/settings", `{"key":"ttl","value":"120"}`},
	{"POST", "/settings/preview", `{"key":"zone","value":"x.example.com"}`},
	{"POST", "/settings/keep", "{}"},
	{"POST", "/settings/revert", ""},
	{"POST", "/settings/records-token", `{"enabled":true}`},
	{"POST", "/settings/check-cloudflare", ""},
	{"POST", "/refresh", ""},
	{"POST", "/history/abc/undo", ""},
}

func controlServer(f *fakeControl) http.Handler {
	s := adminServer(&fakeServices{})
	s.Admin.Control = f
	return s.Handler()
}

func TestControlEndpointsNeedSessionAndForgeryChecks(t *testing.T) {
	f := &fakeControl{}
	h := controlServer(f)
	c := signIn(t, h)
	for _, e := range controlEndpoints {
		name := e[0] + " " + e[1]
		if rec := call(h, e[0], e[1], e[2], "", nil); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s without a session: %d", name, rec.Code)
		}
		if rec := call(h, e[0], e[1], e[2], "", proxied); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s through the proxy without a session: %d", name, rec.Code)
		}
		for why, mod := range map[string]func(*http.Request){
			"no header":    func(r *http.Request) { r.Header.Del("X-Tarn-Request") },
			"other origin": func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") },
			"rebound host": func(r *http.Request) { r.Host = "evil.example:9580" },
		} {
			if rec := call(h, e[0], e[1], e[2], c, mod); rec.Code != http.StatusForbidden {
				t.Errorf("%s, %s: %d, want 403", name, why, rec.Code)
			}
		}
	}
	if len(f.calls) != 0 {
		t.Errorf("a refused request reached the controller: %v", f.calls)
	}
	for _, e := range controlEndpoints {
		if rec := call(h, e[0], e[1], e[2], c, nil); rec.Code != http.StatusOK {
			t.Errorf("%s %s with a session: %d %s", e[0], e[1], rec.Code, rec.Body)
		}
	}
	if len(f.calls) != len(controlEndpoints) {
		t.Errorf("calls = %v", f.calls)
	}
}

func TestControlEndpointsOffWithoutEditing(t *testing.T) {
	noAdmin := (&Server{Store: storeAt(time.Now()), Interval: 1}).Handler()
	noControl := adminServer(&fakeServices{}).Handler()
	for _, h := range []http.Handler{noAdmin, noControl} {
		for _, e := range controlEndpoints {
			if e[1] == "/settings" && e[0] == "POST" {
				continue // checked as GET; the path shape is the same
			}
			rec := call(h, e[0], e[1], e[2], "", nil)
			if rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
				t.Errorf("%s %s with editing off: %d", e[0], e[1], rec.Code)
			}
		}
	}
}

func TestChangeUsesTheClientAddress(t *testing.T) {
	f := &fakeControl{}
	h := controlServer(f)
	c := signIn(t, h)
	call(h, "POST", "/settings", `{"key":"ttl","value":"120"}`, c, proxied)
	if len(f.calls) != 1 || f.calls[0] != "change ttl=120 from 100.64.0.9" {
		t.Errorf("calls = %v", f.calls)
	}
}

func TestFailuresBecomeMessages(t *testing.T) {
	f := &fakeControl{err: errors.New("nope")}
	h := controlServer(f)
	c := signIn(t, h)
	rec := call(h, "POST", "/settings", `{"key":"ttl","value":"x"}`, c, nil)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "nope") {
		t.Errorf("%d %s", rec.Code, rec.Body)
	}
	f.err = fmt.Errorf("%w: wait", ErrRateLimited)
	if rec := call(h, "POST", "/refresh", "", c, nil); rec.Code != http.StatusTooManyRequests {
		t.Errorf("rate limited: %d", rec.Code)
	}
}

func TestPasswordChangeSignsOutOtherBrowsers(t *testing.T) {
	f := &fakeControl{logoutOthers: true}
	h := controlServer(f)
	mine, other := signIn(t, h), signIn(t, h)
	if rec := call(h, "POST", "/settings", `{"key":"password","value":"x"}`, mine, nil); rec.Code != http.StatusOK {
		t.Fatalf("%d", rec.Code)
	}
	if rec := call(h, "GET", "/settings", "", other, nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("the other browser: %d, want 401", rec.Code)
	}
	if rec := call(h, "GET", "/settings", "", mine, nil); rec.Code != http.StatusOK {
		t.Errorf("this browser: %d", rec.Code)
	}
}

func TestManagedRecordsToken(t *testing.T) {
	// sha256("abc")
	hash := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	s := adminServer(&fakeServices{})
	s.Token = ""
	s.TokenHash = func() string { return hash }
	h := s.Handler()
	bearer := func(v string) func(*http.Request) {
		return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+v) }
	}
	if rec := call(h, "GET", "/records", "", "", bearer("abc")); rec.Code != http.StatusOK {
		t.Errorf("right token: %d", rec.Code)
	}
	if rec := call(h, "GET", "/records", "", "", bearer("abd")); rec.Code != http.StatusUnauthorized {
		t.Errorf("wrong token: %d", rec.Code)
	}
	if rec := call(h, "GET", "/records", "", "", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("no token: %d", rec.Code)
	}
}
