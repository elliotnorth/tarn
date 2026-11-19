package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

const photoHost = "photos.t.example.com"

var (
	creds   = aws.Credentials{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "secret-example"}
	signed0 = time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
)

func s3Options(o *v4.SignerOptions) { o.DisableURIPathEscaping = true } // S3 signs the path as sent

func presign(t *testing.T, method, target string, headers http.Header) string {
	t.Helper()
	r, err := http.NewRequest(method, "http://"+photoHost+target, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Header = headers.Clone()
	if r.Header == nil {
		r.Header = http.Header{}
	}
	q := r.URL.Query()
	q.Set("X-Amz-Expires", "3600")
	r.URL.RawQuery = q.Encode()
	uri, _, err := v4.NewSigner().PresignHTTP(context.Background(), creds, r, "UNSIGNED-PAYLOAD", "s3", "us-east-1", signed0, s3Options)
	if err != nil {
		t.Fatal(err)
	}
	return uri
}

// verifySignature is what S3 does: it recomputes the signature from only what
// arrived on the wire.
func verifySignature(r *http.Request) error {
	q := r.URL.Query()
	want := q.Get("X-Amz-Signature")
	if want == "" {
		return errors.New("no signature")
	}
	at, err := time.Parse("20060102T150405Z", q.Get("X-Amz-Date"))
	if err != nil {
		return err
	}
	var kept []string
	for _, p := range strings.Split(strings.SplitN(r.RequestURI, "?", 2)[1], "&") {
		if !strings.HasPrefix(p, "X-Amz-Signature=") {
			kept = append(kept, p)
		}
	}
	path, _, _ := strings.Cut(r.RequestURI, "?")
	again, err := http.NewRequest(r.Method, "http://"+r.Host+path+"?"+strings.Join(kept, "&"), nil)
	if err != nil {
		return err
	}
	again.Host = r.Host
	for _, h := range strings.Split(q.Get("X-Amz-SignedHeaders"), ";") {
		if h != "host" {
			again.Header[http.CanonicalHeaderKey(h)] = r.Header.Values(h)
		}
	}
	uri, _, err := v4.NewSigner().PresignHTTP(context.Background(), creds, again, "UNSIGNED-PAYLOAD", "s3", "us-east-1", at, s3Options)
	if err != nil {
		return err
	}
	u, err := url.Parse(uri)
	if err != nil {
		return err
	}
	if got := u.Query().Get("X-Amz-Signature"); got != want {
		return fmt.Errorf("signature mismatch for host %q, target %q", r.Host, r.RequestURI)
	}
	return nil
}

// storage is a fake S3: it refuses anything whose signature doesn't verify.
func storage(t *testing.T, handle func(http.ResponseWriter, *http.Request)) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := verifySignature(r); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		if handle != nil {
			handle(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func front(t *testing.T, upstream string, preserve bool) *httptest.Server {
	t.Helper()
	u, err := url.Parse(upstream)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(Handler(zone, []Service{{Name: "photos", Upstream: u, PreserveHost: preserve}}, quiet()))
	t.Cleanup(srv.Close)
	return srv
}

// through sends a presigned request to tarn, as a browser would.
func through(t *testing.T, f *httptest.Server, method, uri string, body io.Reader, headers http.Header) *http.Response {
	t.Helper()
	r, err := http.NewRequest(method, uri, body)
	if err != nil {
		t.Fatal(err)
	}
	r.Host = photoHost
	r.URL.Host = strings.TrimPrefix(f.URL, "http://")
	for k, v := range headers {
		r.Header[k] = v
	}
	resp, err := f.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func TestPresignedURLsSurvive(t *testing.T) {
	for _, target := range []string{
		"/bucket/plain.jpg",
		"/bucket/with%20space.jpg",
		"/bucket/plus%2Bsign.jpg",
		"/bucket/plus+literal.jpg",
		"/bucket/slash%2Finside.jpg",
		"/bucket/%E6%97%A5%E6%9C%AC%E8%AA%9E.jpg",
		"/bucket/%C3%A9%20%2B%2F%20mixed.jpg",
		"//double//slash.jpg",
	} {
		up := storage(t, nil)
		f := front(t, up.URL, true)
		if resp := through(t, f, "GET", presign(t, "GET", target, nil), nil, nil); resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			t.Errorf("%s: %d %s", target, resp.StatusCode, b)
		}
	}
}

// Rewriting the host is exactly what breaks signed links, so the test must fail
// without host=preserve or it proves nothing.
func TestDefaultModeBreaksSignatures(t *testing.T) {
	up := storage(t, nil)
	f := front(t, up.URL, false)
	if resp := through(t, f, "GET", presign(t, "GET", "/bucket/a.jpg", nil), nil, nil); resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestTamperingIsStillCaught(t *testing.T) {
	up := storage(t, nil)
	f := front(t, up.URL, true)
	uri := strings.Replace(presign(t, "GET", "/bucket/a.jpg", nil), "/a.jpg", "/b.jpg", 1)
	if resp := through(t, f, "GET", uri, nil, nil); resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestMultipartPartUpload(t *testing.T) {
	part := bytes.Repeat([]byte("part data "), 1000)
	sum := fmt.Sprintf("%x", sha256.Sum256(part))
	var gotType, gotMD5, gotLength string
	var gotSum, gotQuery string
	up := storage(t, func(w http.ResponseWriter, r *http.Request) {
		gotType, gotMD5, gotLength = r.Header.Get("Content-Type"), r.Header.Get("Content-MD5"), fmt.Sprint(r.ContentLength)
		gotQuery = r.URL.RawQuery
		h := sha256.New()
		io.Copy(h, r.Body)
		gotSum = hex.EncodeToString(h.Sum(nil))
		w.Header().Set("ETag", `"abc"`)
	})
	f := front(t, up.URL, true)
	headers := http.Header{"Content-Type": {"application/octet-stream"}, "Content-Md5": {"Q2hlY2sgSW50ZWdyaXR5IQ=="}}
	uri := presign(t, "PUT", "/bucket/video.mp4?partNumber=7&uploadId=abc%2Bdef%3D", headers)
	resp := through(t, f, "PUT", uri, bytes.NewReader(part), headers)
	if resp.StatusCode != http.StatusOK || resp.Header.Get("ETag") != `"abc"` {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	if gotSum != sum || gotLength != fmt.Sprint(len(part)) {
		t.Errorf("body changed: length %s", gotLength)
	}
	if gotType != "application/octet-stream" || gotMD5 != "Q2hlY2sgSW50ZWdyaXR5IQ==" {
		t.Errorf("headers changed: %q %q", gotType, gotMD5)
	}
	if !strings.Contains(gotQuery, "uploadId=abc%2Bdef%3D") || !strings.Contains(gotQuery, "partNumber=7") {
		t.Errorf("query = %q", gotQuery)
	}
}

// pattern is a reader that makes a large body without holding it in memory.
type pattern struct {
	left int64
	sum  interface{ Write([]byte) (int, error) }
}

func (p *pattern) Read(b []byte) (int, error) {
	if p.left == 0 {
		return 0, io.EOF
	}
	if int64(len(b)) > p.left {
		b = b[:p.left]
	}
	for i := range b {
		b[i] = byte(p.left - int64(i))
	}
	p.left -= int64(len(b))
	p.sum.Write(b)
	return len(b), nil
}

func TestLargeStreamedUploadAndDownload(t *testing.T) {
	const size = 32 << 20
	sent, got, back := sha256.New(), sha256.New(), sha256.New()
	up := storage(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PUT" {
			if n, _ := io.Copy(got, r.Body); n != size {
				t.Errorf("received %d bytes", n)
			}
			return
		}
		io.Copy(w, &pattern{left: size, sum: io.Discard})
	})
	f := front(t, up.URL, true)
	// Unknown length, so it's streamed chunked, with no buffering by tarn.
	resp := through(t, f, "PUT", presign(t, "PUT", "/bucket/big.bin", nil), io.MultiReader(&pattern{left: size, sum: sent}), nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("upload: %d", resp.StatusCode)
	}
	if !bytes.Equal(sent.Sum(nil), got.Sum(nil)) {
		t.Error("the upload was altered")
	}
	resp = through(t, f, "GET", presign(t, "GET", "/bucket/big.bin", nil), nil, nil)
	if n, _ := io.Copy(back, resp.Body); n != size {
		t.Errorf("downloaded %d bytes", n)
	}
	if !bytes.Equal(sent.Sum(nil), back.Sum(nil)) {
		t.Error("the download was altered")
	}
}

func TestRangeRequests(t *testing.T) {
	content := []byte("0123456789abcdefghij")
	var gotRange string
	up := storage(t, func(w http.ResponseWriter, r *http.Request) {
		gotRange = r.Header.Get("Range")
		http.ServeContent(w, r, "v.mp4", signed0, bytes.NewReader(content))
	})
	f := front(t, up.URL, true)
	resp := through(t, f, "GET", presign(t, "GET", "/bucket/v.mp4", nil), nil, http.Header{"Range": {"bytes=5-9"}})
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusPartialContent || string(body) != "56789" {
		t.Fatalf("%d %q", resp.StatusCode, body)
	}
	if resp.Header.Get("Content-Range") != "bytes 5-9/20" || gotRange != "bytes=5-9" {
		t.Errorf("Content-Range %q, Range %q", resp.Header.Get("Content-Range"), gotRange)
	}
}

func TestNoCompressionIsAdded(t *testing.T) {
	var seen []string
	var present bool
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen, present = r.Header["Accept-Encoding"]
		w.Write([]byte("body"))
	}))
	defer up.Close()
	f := front(t, up.URL, true)
	raw := func(extra string) {
		c, err := net.Dial("tcp", strings.TrimPrefix(f.URL, "http://"))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		fmt.Fprintf(c, "GET /a HTTP/1.1\r\nHost: %s\r\n%sConnection: close\r\n\r\n", photoHost, extra)
		io.Copy(io.Discard, c)
	}
	raw("")
	if present {
		t.Errorf("Accept-Encoding was added: %v", seen)
	}
	raw("Accept-Encoding: identity\r\n")
	if len(seen) != 1 || seen[0] != "identity" {
		t.Errorf("Accept-Encoding = %v", seen)
	}
}

// The golden list: tarn must not change a single byte of the request target.
func TestRequestTargetIsByteExact(t *testing.T) {
	var gotURI, gotHost string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotURI, gotHost = r.RequestURI, r.Host
	}))
	defer up.Close()
	f := front(t, up.URL, true)
	for _, target := range []string{
		"/",
		"/a/b.jpg",
		"//a//b/../c",
		"//leading%2Fescaped",
		"/./a/../b",
		"/a%2Fb",
		"/a%2fb",
		"/a+b",
		"/a%2Bb",
		"/a%20b",
		"/a%7Eb",
		"/~a",
		"/%E6%97%A5%E6%9C%AC",
		"/\xe6\x97\xa5\xe6\x9c\xac",
		"/p?",
		"/p?a=1&a=2&b",
		"/p?x=a+b&y=%2B&z=%2f",
		"/p?w=1;2&v=3",
		"/p?bad=%zz&next=1",
		"/p?b=2&a=1",
		"/p?X-Amz-Signature=ABC&X-Amz-Date=20261108T120000Z",
	} {
		gotURI, gotHost = "", ""
		c, err := net.Dial("tcp", strings.TrimPrefix(f.URL, "http://"))
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target, photoHost)
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		c.Close()
		if err != nil {
			t.Fatalf("%q: %v", target, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%q: status %d", target, resp.StatusCode)
		}
		if gotURI != target {
			t.Errorf("target changed: sent %q, upstream saw %q", target, gotURI)
		}
		if gotHost != photoHost {
			t.Errorf("%q: Host = %q", target, gotHost)
		}
	}
}

func TestPreserveOption(t *testing.T) {
	got, err := ParseServices(strings.NewReader(`
a http://100.64.0.5:3200 host=preserve
b http://100.64.0.6:3200 host=upstream
c https://c.example-tailnet.ts.net
`), zone)
	if err != nil {
		t.Fatal(err)
	}
	if !got[0].PreserveHost || got[1].PreserveHost || got[2].PreserveHost {
		t.Errorf("services = %+v", got)
	}
	for _, doc := range []string{"a http://x host=other", "a http://x preserve", "a http://x host=preserve extra"} {
		if _, err := ParseServices(strings.NewReader(doc), zone); err == nil {
			t.Errorf("%q was accepted", doc)
		}
	}
}

func TestPlainHTTPOnlyToPrivateAddresses(t *testing.T) {
	for _, up := range []string{
		"http://127.0.0.1:9580", "http://[::1]:80", "http://10.0.0.5", "http://172.16.0.1", "http://192.168.1.5:3200",
		"http://100.64.0.5:3200", "http://100.127.255.254", "http://[fd7a:115c:a1e0::5]:3200",
		"http://nas.local:80", // a name is checked when connecting
		"https://8.8.8.8", "https://public.example.net",
	} {
		if _, err := parseUpstream(up, zone); err != nil {
			t.Errorf("%s was refused: %v", up, err)
		}
	}
	for _, up := range []string{
		"http://8.8.8.8", "http://100.128.0.1", "http://[2001:4860:4860::8888]",
		"http://169.254.169.254", "http://[fe80::1]", "http://[::ffff:8.8.8.8]",
	} {
		_, err := parseUpstream(up, zone)
		if err == nil || !strings.Contains(err.Error(), "unencrypted") {
			t.Errorf("%s: err = %v", up, err)
		}
	}
}

func TestPlainHTTPCheckedWhenConnecting(t *testing.T) {
	if err := refusePublic("tcp4", "93.184.216.34:80", nil); err == nil || !strings.Contains(err.Error(), "unencrypted") {
		t.Errorf("public: %v", err)
	}
	if err := refusePublic("tcp4", "100.64.0.5:3200", nil); err != nil {
		t.Errorf("tailnet: %v", err)
	}
	if !plainAllowed(netip.MustParseAddr("::ffff:192.168.1.5")) {
		t.Error("an IPv4-mapped private address should be allowed")
	}
}

func TestManagerKeepsPreserveHost(t *testing.T) {
	m, path := newManager(t, "")
	if err := m.Put("photos", "http://100.64.0.5:3200", true); err != nil {
		t.Fatal(err)
	}
	if err := m.Put("web", "https://web.example-tailnet.ts.net", false); err != nil {
		t.Fatal(err)
	}
	again, err := OpenManager(path, zone, quiet(), false)
	if err != nil {
		t.Fatal(err)
	}
	list := again.List()
	if !list[0].PreserveHost || list[1].PreserveHost {
		t.Errorf("list = %+v", list)
	}
	if err := m.Put("bad", "http://8.8.8.8", false); err == nil {
		t.Error("a public plain-HTTP upstream was accepted")
	}
}
