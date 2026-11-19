package health

import (
	"bytes"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/elliotnorth/Tarn/internal/index"
)

const pw = "correct horse battery"

type fakeServices struct {
	put, del []string
	err      error
}

func adminServer(f *fakeServices) *Server {
	return &Server{Store: &index.Store{}, Interval: time.Second, Zone: "t.example.com", Token: "s3cret", Admin: &Admin{
		Password: pw,
		Put: func(n, u string, p bool, _ string) error {
			if p {
				u += " host=preserve"
			}
			f.put = append(f.put, n+"="+u)
			return f.err
		},
		Delete: func(n, _ string) error { f.del = append(f.del, n); return f.err },
	}}
}

func call(h http.Handler, method, path, body, cookie string, mod func(*http.Request)) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Host = "127.0.0.1:9580"
	r.Header.Set("X-Tarn-Request", "1")
	if cookie != "" {
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: cookie})
	}
	if mod != nil {
		mod(r)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func signIn(t *testing.T, h http.Handler) string {
	t.Helper()
	rec := call(h, "POST", "/login", `{"password":"`+pw+`"}`, "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("login = %d %s", rec.Code, rec.Body)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie {
			if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Secure {
				t.Errorf("cookie flags: %+v", c)
			}
			return c.Value
		}
	}
	t.Fatal("no session cookie")
	return ""
}

func TestChangesNeedASession(t *testing.T) {
	f := &fakeServices{}
	h := adminServer(f).Handler()
	if rec := call(h, "PUT", "/services/app", `{"upstream":"http://x"}`, "", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("no session: %d", rec.Code)
	}
	if rec := call(h, "DELETE", "/services/app", "", "made-up", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("fake session: %d", rec.Code)
	}
	if len(f.put)+len(f.del) != 0 {
		t.Errorf("changes ran: %v %v", f.put, f.del)
	}
}

func TestSignInThenChange(t *testing.T) {
	f := &fakeServices{}
	h := adminServer(f).Handler()
	c := signIn(t, h)

	if rec := call(h, "PUT", "/services/App", `{"upstream":" http://x:1 "}`, c, nil); rec.Code != http.StatusOK {
		t.Fatalf("put = %d %s", rec.Code, rec.Body)
	}
	if len(f.put) != 1 || f.put[0] != "app=http://x:1" {
		t.Errorf("put = %v", f.put)
	}
	if rec := call(h, "DELETE", "/services/app", "", c, nil); rec.Code != http.StatusOK {
		t.Fatalf("delete = %d", rec.Code)
	}

	// A bad value comes back as a message the page can show.
	f.err = errors.New("that isn't a valid address")
	rec := call(h, "PUT", "/services/app", `{"upstream":"x"}`, c, nil)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "valid address") {
		t.Errorf("error = %d %s", rec.Code, rec.Body)
	}

	if rec := call(h, "POST", "/logout", "", c, nil); rec.Code != http.StatusOK {
		t.Fatalf("logout = %d", rec.Code)
	}
	if rec := call(h, "DELETE", "/services/app", "", c, nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("after logout: %d", rec.Code)
	}
}

func TestPutPassesPreserveHost(t *testing.T) {
	f := &fakeServices{}
	h := adminServer(f).Handler()
	c := signIn(t, h)
	if rec := call(h, "PUT", "/services/photos", `{"upstream":"http://100.64.0.5:3200","preserve_host":true}`, c, nil); rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if len(f.put) != 1 || f.put[0] != "photos=http://100.64.0.5:3200 host=preserve" {
		t.Errorf("put = %v", f.put)
	}
}

func TestForgedRequestsAreRefused(t *testing.T) {
	f := &fakeServices{}
	h := adminServer(f).Handler()
	c := signIn(t, h)
	cases := map[string]func(*http.Request){
		"no custom header": func(r *http.Request) { r.Header.Del("X-Tarn-Request") },
		"other origin":     func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") },
		"bad origin":       func(r *http.Request) { r.Header.Set("Origin", "://") },
		"rebound host":     func(r *http.Request) { r.Host = "evil.example:9580" },
		"proxied, other origin": func(r *http.Request) {
			r.Header.Set("X-Forwarded-Host", "tarn.t.example.com")
			r.Header.Set("Origin", "https://evil.example")
		},
	}
	for name, mod := range cases {
		if rec := call(h, "DELETE", "/services/app", "", c, mod); rec.Code != http.StatusForbidden {
			t.Errorf("%s: %d, want 403", name, rec.Code)
		}
	}
	if len(f.del) != 0 {
		t.Errorf("a forged request got through: %v", f.del)
	}

	// The real page, through tarn's proxy.
	rec := call(h, "DELETE", "/services/app", "", c, func(r *http.Request) {
		r.Header.Set("X-Forwarded-Host", "tarn.t.example.com")
		r.Header.Set("Origin", "https://tarn.t.example.com")
	})
	if rec.Code != http.StatusOK {
		t.Errorf("same origin through the proxy: %d %s", rec.Code, rec.Body)
	}
}

func TestLoginLimit(t *testing.T) {
	now := time.Unix(1000, 0)
	srv := adminServer(&fakeServices{})
	srv.Now = func() time.Time { return now }
	h := srv.Handler()
	for i := 0; i < maxLoginFails; i++ {
		if rec := call(h, "POST", "/login", `{"password":"wrong"}`, "", nil); rec.Code != http.StatusUnauthorized {
			t.Fatalf("try %d: %d", i, rec.Code)
		}
	}
	// Even the right password waits once the limit is reached.
	if rec := call(h, "POST", "/login", `{"password":"`+pw+`"}`, "", nil); rec.Code != http.StatusTooManyRequests {
		t.Errorf("over the limit: %d", rec.Code)
	}
	now = now.Add(loginWindow)
	signIn(t, h)
}

func TestSessionExpires(t *testing.T) {
	now := time.Unix(1000, 0)
	srv := adminServer(&fakeServices{})
	srv.Now = func() time.Time { return now }
	h := srv.Handler()
	c := signIn(t, h)
	now = now.Add(sessionLife)
	if rec := call(h, "DELETE", "/services/app", "", c, nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("expired session: %d", rec.Code)
	}
}

func TestSecureCookieThroughProxy(t *testing.T) {
	h := adminServer(&fakeServices{}).Handler()
	rec := call(h, "POST", "/login", `{"password":"`+pw+`"}`, "", func(r *http.Request) { r.Header.Set("X-Forwarded-Proto", "https") })
	if cs := rec.Result().Cookies(); len(cs) != 1 || !cs[0].Secure {
		t.Errorf("cookies = %+v", cs)
	}
}

func TestSessionUnlocksTheLists(t *testing.T) {
	h := adminServer(&fakeServices{}).Handler()
	if rec := call(h, "GET", "/records", "", "", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("no session: %d", rec.Code)
	}
	c := signIn(t, h)
	if rec := call(h, "GET", "/records", "", c, nil); rec.Code != http.StatusOK {
		t.Errorf("with session: %d", rec.Code)
	}
}

func TestCantChangeTheServiceInUse(t *testing.T) {
	f := &fakeServices{}
	h := adminServer(f).Handler()
	c := signIn(t, h)
	via := func(r *http.Request) { r.Header.Set("X-Forwarded-Host", "tarn.t.example.com") }
	if rec := call(h, "DELETE", "/services/tarn", "", c, via); rec.Code != http.StatusBadRequest {
		t.Errorf("delete in use: %d", rec.Code)
	}
	if rec := call(h, "PUT", "/services/tarn", `{"upstream":"http://x"}`, c, via); rec.Code != http.StatusBadRequest {
		t.Errorf("put in use: %d", rec.Code)
	}
	if len(f.put)+len(f.del) != 0 {
		t.Errorf("changes ran: %v %v", f.put, f.del)
	}
	if rec := call(h, "DELETE", "/services/other", "", c, via); rec.Code != http.StatusOK {
		t.Errorf("delete another: %d", rec.Code)
	}
}

func TestSessionCarriesTheWarning(t *testing.T) {
	srv := &Server{Store: &index.Store{}, Interval: time.Second, AdminWarning: "Editing is off: too short"}
	rec, body := get(t, srv.Handler(), "/session", "")
	if rec.Code != http.StatusOK || body["warning"] != "Editing is off: too short" {
		t.Errorf("%d %v", rec.Code, body)
	}
}

func TestEditingOffByDefault(t *testing.T) {
	h := (&Server{Store: &index.Store{}, Interval: time.Second}).Handler()
	if rec := call(h, "POST", "/login", `{"password":"x"}`, "", nil); rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("login with editing off: %d", rec.Code)
	}
	rec, body := get(t, h, "/session", "")
	if rec.Code != http.StatusOK || body["editable"] != false {
		t.Errorf("session = %d %v", rec.Code, body)
	}
}

func proxied(r *http.Request) {
	r.Header.Set("X-Forwarded-For", "100.64.0.9")
	r.Header.Set("X-Forwarded-Host", "tarn.t.example.com")
	r.Header.Set("Origin", "https://tarn.t.example.com")
}

// A wrong password from the real page must reach the password check: it gets
// the wrong-password answer and counts toward the lockout. Only a request that
// isn't from the page is refused first, with 403.
func TestWrongPasswordFromThePage(t *testing.T) {
	now := time.Unix(1000, 0)
	srv := adminServer(&fakeServices{})
	srv.Now = func() time.Time { return now }
	h := srv.Handler()

	noHeader := func(r *http.Request) { proxied(r); r.Header.Del("X-Tarn-Request") }
	if rec := call(h, "POST", "/login", `{"password":"wrong"}`, "", noHeader); rec.Code != http.StatusForbidden {
		t.Errorf("without the page's header: %d, want 403", rec.Code)
	}
	for i := 0; i < maxLoginFails; i++ {
		rec := call(h, "POST", "/login", `{"password":"wrong"}`, "", proxied)
		if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "Wrong password") {
			t.Fatalf("try %d: %d %s", i, rec.Code, rec.Body)
		}
	}
	if rec := call(h, "POST", "/login", `{"password":"wrong"}`, "", proxied); rec.Code != http.StatusTooManyRequests {
		t.Errorf("after the limit: %d, want 429", rec.Code)
	}
}

func TestSignInsAreLogged(t *testing.T) {
	var buf bytes.Buffer
	srv := adminServer(&fakeServices{})
	srv.Log = slog.New(slog.NewTextHandler(&buf, nil))
	h := srv.Handler()

	call(h, "POST", "/login", `{"password":"wrong"}`, "", proxied)
	call(h, "POST", "/login", `{"password":"`+pw+`"}`, "", proxied)
	for i := 0; i < maxLoginFails+1; i++ {
		call(h, "POST", "/login", `{"password":"wrong"}`, "", proxied)
	}
	call(h, "POST", "/login", "", "", func(r *http.Request) { r.Header.Del("X-Tarn-Request") })

	out := buf.String()
	for _, want := range []string{"sign-in failed", "sign-in succeeded", "sign-in locked out", "request refused", "source=100.64.0.9"} {
		if !strings.Contains(out, want) {
			t.Errorf("log is missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, pw) || strings.Contains(out, "wrong\"") {
		t.Errorf("a password reached the log:\n%s", out)
	}
}

func TestProxyNeedsSignIn(t *testing.T) {
	via := func(r *http.Request) { r.Header.Set("X-Forwarded-For", "100.64.0.9") }

	// No token and no session: open on loopback, closed through the proxy.
	open := adminServer(&fakeServices{})
	open.Token = ""
	h := open.Handler()
	for _, path := range []string{"/healthz", "/records", "/services"} {
		if rec := call(h, "GET", path, "", "", via); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s through the proxy: %d, want 401", path, rec.Code)
		}
		if rec := call(h, "GET", path, "", "", nil); rec.Code == http.StatusUnauthorized {
			t.Errorf("%s on loopback: %d", path, rec.Code)
		}
	}
	c := signIn(t, h)
	for _, path := range []string{"/healthz", "/records", "/services"} {
		if rec := call(h, "GET", path, "", c, via); rec.Code == http.StatusUnauthorized {
			t.Errorf("%s with a session: %d", path, rec.Code)
		}
	}
	// The page and its sign-in state stay reachable, or nobody could sign in.
	for _, path := range []string{"/", "/session"} {
		if rec := call(h, "GET", path, "", "", via); rec.Code != http.StatusOK {
			t.Errorf("%s through the proxy: %d, want 200", path, rec.Code)
		}
	}

	// A records token also works through the proxy.
	tok := adminServer(&fakeServices{}).Handler()
	bearer := func(r *http.Request) { via(r); r.Header.Set("Authorization", "Bearer s3cret") }
	if rec := call(tok, "GET", "/records", "", "", bearer); rec.Code != http.StatusOK {
		t.Errorf("token through the proxy: %d", rec.Code)
	}
	// Plain /healthz on loopback needs nothing, even with a token set.
	if rec := call(tok, "GET", "/healthz", "", "", nil); rec.Code == http.StatusUnauthorized {
		t.Errorf("healthz on loopback: %d", rec.Code)
	}
}
