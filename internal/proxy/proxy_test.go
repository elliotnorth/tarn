package proxy

import (
	"bufio"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
)

const zone = "t.example.com"

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestParseServices(t *testing.T) {
	got, err := ParseServices(strings.NewReader(`
# comment
Nextcloud  https://nextcloud.example-tailnet.ts.net
vault http://100.64.0.5:8080/
`), zone)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(Names(got), []string{"nextcloud", "vault"}) {
		t.Errorf("names = %v", Names(got))
	}
	if got[1].Upstream.String() != "http://100.64.0.5:8080" {
		t.Errorf("upstream = %s", got[1].Upstream)
	}
}

func TestParseServicesErrors(t *testing.T) {
	for _, doc := range []string{
		"oneword",
		"a http://x extra",
		"under_score http://x",
		"a ftp://x",
		"a x.example.net",
		"a http://user:pw@x",
		"a http://x/path",
		"a http://x?q=1",
		"a http://x\na http://y",
		"a https://b.t.example.com",
		"a https://T.EXAMPLE.COM.",
	} {
		if _, err := ParseServices(strings.NewReader(doc), zone); err == nil {
			t.Errorf("ParseServices(%q) succeeded, want error", doc)
		}
	}
}

func TestServiceName(t *testing.T) {
	cases := map[string]string{
		"nextcloud.t.example.com":     "nextcloud",
		"NextCloud.T.Example.Com:443": "nextcloud",
		"nextcloud.t.example.com.":    "nextcloud",
		"t.example.com":               "",
		"a.b.t.example.com":           "",
		"nextcloud.other.example.com": "",
		"xt.example.com":              "",
		"100.64.0.1:443":              "",
	}
	for in, want := range cases {
		if got := serviceName(in, zone); got != want {
			t.Errorf("serviceName(%q) = %q, want %q", in, got, want)
		}
	}
}

func handlerFor(t *testing.T, upstream string) http.Handler {
	t.Helper()
	u, err := url.Parse(upstream)
	if err != nil {
		t.Fatal(err)
	}
	return Handler(zone, []Service{{Name: "app", Upstream: u}}, quiet())
}

func TestHandlerForwards(t *testing.T) {
	var got *http.Request
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r
		w.Header().Set("X-From", "upstream")
		io.WriteString(w, "hello")
	}))
	defer up.Close()

	req := httptest.NewRequest("GET", "https://app.t.example.com/a/b?c=d", nil)
	req.Header.Set("X-Forwarded-Host", "spoofed.example.net")
	rec := httptest.NewRecorder()
	handlerFor(t, up.URL).ServeHTTP(rec, req)

	if rec.Code != 200 || rec.Body.String() != "hello" || rec.Header().Get("X-From") != "upstream" {
		t.Fatalf("response = %d %q", rec.Code, rec.Body)
	}
	if want := strings.TrimPrefix(up.URL, "http://"); got.Host != want {
		t.Errorf("upstream saw Host %q, want its own name %q", got.Host, want)
	}
	if got.URL.RequestURI() != "/a/b?c=d" {
		t.Errorf("path = %q", got.URL.RequestURI())
	}
	if h := got.Header.Get("X-Forwarded-Host"); h != "app.t.example.com" {
		t.Errorf("X-Forwarded-Host = %q", h)
	}
	if p := got.Header.Get("X-Forwarded-Proto"); p != "https" {
		t.Errorf("X-Forwarded-Proto = %q", p)
	}
}

func TestHandlerUnknownName(t *testing.T) {
	h := handlerFor(t, "http://127.0.0.1:1")
	for _, target := range []string{"https://other.t.example.com/", "https://t.example.com/", "https://a.app.t.example.com/"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", target, nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s: code = %d, want 404", target, rec.Code)
		}
	}
}

func TestHandlerUpstreamDown(t *testing.T) {
	up := httptest.NewServer(http.NotFoundHandler())
	addr := up.URL
	up.Close()
	rec := httptest.NewRecorder()
	handlerFor(t, addr).ServeHTTP(rec, httptest.NewRequest("GET", "https://app.t.example.com/", nil))
	if rec.Code != http.StatusBadGateway {
		t.Errorf("code = %d, want 502", rec.Code)
	}
}

// TestHandlerUpgrade checks that a WebSocket-style upgrade passes through.
func TestHandlerUpgrade(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "websocket" {
			t.Errorf("Upgrade = %q", r.Header.Get("Upgrade"))
		}
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
		rw.Flush()
		line, _ := rw.ReadString('\n')
		rw.WriteString("echo:" + line)
		rw.Flush()
	}))
	defer up.Close()

	front := httptest.NewServer(handlerFor(t, up.URL))
	defer front.Close()

	c, err := net.Dial("tcp", strings.TrimPrefix(front.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "GET / HTTP/1.1\r\nHost: app.t.example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
	r := bufio.NewReader(c)
	resp, err := http.ReadResponse(r, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	io.WriteString(c, "ping\n")
	if line, _ := r.ReadString('\n'); line != "echo:ping\n" {
		t.Errorf("echo = %q", line)
	}
}
