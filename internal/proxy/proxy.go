// Package proxy is tarn's reverse proxy: it maps <service>.<zone> to the
// upstream URLs listed in the services file.
package proxy

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/elliotnorth/tarn/internal/peers"
)

// Service is one line of the services file.
type Service struct {
	Name         string
	Upstream     *url.URL
	PreserveHost bool // forward the request byte for byte, for apps that sign URLs
}

// LoadServices reads the services file at path.
func LoadServices(path, zone string) ([]Service, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseServices(f, zone)
}

// ParseServices reads lines of "name upstream-url", with an optional
// "host=preserve" or "host=upstream" after them. Blank lines and lines starting
// with # are ignored. Any bad line is an error, so a typo stops tarn
// at startup rather than quietly dropping a service.
func ParseServices(r io.Reader, zone string) ([]Service, error) {
	var out []Service
	seen := map[string]bool{}
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 && len(fields) != 3 {
			return nil, fmt.Errorf("line %d: want \"name upstream-url\", optionally followed by host=preserve", n)
		}
		preserve := false
		if len(fields) == 3 {
			switch fields[2] {
			case "host=preserve":
				preserve = true
			case "host=upstream":
			default:
				return nil, fmt.Errorf("line %d: unknown option %q", n, fields[2])
			}
		}
		name := strings.ToLower(fields[0])
		if peers.Label(name) != name {
			return nil, fmt.Errorf("line %d: %q is not a valid DNS label", n, fields[0])
		}
		if seen[name] {
			return nil, fmt.Errorf("line %d: duplicate service %q", n, name)
		}
		seen[name] = true
		u, err := parseUpstream(fields[1], zone)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", n, err)
		}
		out = append(out, Service{Name: name, Upstream: u, PreserveHost: preserve})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func parseUpstream(s, zone string) (*url.URL, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("upstream %q: %w", s, err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return nil, fmt.Errorf("upstream %q: want http:// or https:// and a host", s)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, fmt.Errorf("upstream %q: only a scheme, host and port are allowed", s)
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if host == zone || strings.HasSuffix(host, "."+zone) {
		return nil, fmt.Errorf("upstream %q: is inside the zone, so it would loop back to tarn", s)
	}
	if ip, err := netip.ParseAddr(u.Hostname()); err == nil && u.Scheme == "http" && !plainAllowed(ip) {
		return nil, fmt.Errorf("upstream %q: %w", s, errPublicPlain)
	}
	u.Path = ""
	return u, nil
}

var (
	errPublicPlain = errors.New("plain http would send traffic unencrypted over the internet. Use https://, or a tailnet or private address")
	tailnetV4      = netip.MustParsePrefix("100.64.0.0/10")
)

// plainAllowed says whether plain HTTP may go to ip: the tailnet (encrypted by
// WireGuard), a private LAN, or this machine. Link-local is left out, which
// also keeps cloud metadata addresses unreachable.
func plainAllowed(ip netip.Addr) bool {
	ip = ip.Unmap()
	return ip.IsLoopback() || ip.IsPrivate() || tailnetV4.Contains(ip)
}

// refusePublic runs on every plain-HTTP connection, after DNS, because a
// hostname can resolve to anything by the time tarn connects.
func refusePublic(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return err
	}
	if !plainAllowed(ip) {
		return fmt.Errorf("%s: %w", ip, errPublicPlain)
	}
	return nil
}

// Names returns the service names.
func Names(services []Service) []string {
	names := make([]string, len(services))
	for i, s := range services {
		names[i] = s.Name
	}
	return names
}

// Handler routes each request by its Host header. Unknown names get 404.
func Handler(zone string, services []Service, log *slog.Logger) http.Handler {
	r := NewRouter(zone, log)
	r.Set(services)
	return r
}

func newProxy(s Service, transport http.RoundTripper, log *slog.Logger) *httputil.ReverseProxy {
	// SetURL makes the upstream see its own name as the host (and in SNI),
	// which `tailscale serve` needs. The name the user typed goes in
	// X-Forwarded-Host. Client-sent X-Forwarded-* headers are dropped.
	rewrite := func(pr *httputil.ProxyRequest) {
		pr.SetURL(s.Upstream)
		pr.SetXForwarded()
	}
	var flush time.Duration
	if s.PreserveHost {
		rewrite = func(pr *httputil.ProxyRequest) { preserveRequest(pr, s.Upstream) }
		flush = -1 // stream every write, for video
	}
	return &httputil.ReverseProxy{
		Transport:     transport,
		ErrorLog:      slog.NewLogLogger(log.Handler(), slog.LevelWarn),
		FlushInterval: flush,
		Rewrite:       rewrite,
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			log.Warn("upstream failed", "service", s.Name, "err", err)
			http.Error(w, "upstream unavailable", http.StatusBadGateway)
		},
	}
}

// preserveRequest sends the request target exactly as the client wrote it. A
// signature covers the host, path and query, so re-encoding any of them breaks
// it. net/url would normalize the path, and ReverseProxy drops query parameters
// it can't parse, so this works from the raw request line. Only unsigned
// X-Forwarded-* headers are added.
func preserveRequest(pr *httputil.ProxyRequest, upstream *url.URL) {
	out := pr.Out.URL
	out.Scheme, out.Host = upstream.Scheme, upstream.Host
	pr.Out.Host = pr.In.Host

	path, query, hasQuery := strings.Cut(pr.In.RequestURI, "?")
	if !strings.HasPrefix(path, "/") { // absolute-form request line
		path, query, hasQuery = pr.In.URL.EscapedPath(), pr.In.URL.RawQuery, pr.In.URL.ForceQuery || pr.In.URL.RawQuery != ""
	}
	out.RawQuery, out.ForceQuery = query, hasQuery && query == ""
	out.Path, out.RawPath, out.Opaque = "", "", ""
	if strings.HasPrefix(path, "//") {
		// Opaque would be read as a network path and gain a scheme.
		out.RawPath = path
		out.Path, _ = url.PathUnescape(path)
	} else {
		out.Opaque = path
	}
	pr.SetXForwarded()
}

// serviceName returns the single label below zone, or "" if host isn't one.
func serviceName(host, zone string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	label, ok := strings.CutSuffix(host, "."+zone)
	if !ok || strings.Contains(label, ".") {
		return ""
	}
	return label
}
