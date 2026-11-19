package proxy

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Router is the live HTTP handler. Set swaps the routes without dropping
// requests already in flight.
type Router struct {
	zones      atomic.Pointer[[]string]
	log        *slog.Logger
	transports [2][2]*http.Transport // by [plain HTTP][preserve host]
	proxies    atomic.Pointer[map[string]*httputil.ReverseProxy]
}

// NewRouter returns a Router with no routes.
func NewRouter(zone string, log *slog.Logger) *Router {
	r := &Router{log: log}
	for _, plain := range []bool{false, true} {
		for _, preserve := range []bool{false, true} {
			r.transports[b2i(plain)][b2i(preserve)] = newTransport(plain, preserve)
		}
	}
	r.SetZones(zone)
	r.Set(nil)
	return r
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func newTransport(plain, preserve bool) *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy = nil // upstreams are on the tailnet; ignore *_PROXY settings
	if plain {
		t.DialContext = (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second, Control: refusePublic}).DialContext
	}
	t.DisableCompression = preserve // Go would otherwise add Accept-Encoding: gzip
	return t
}

// SetZones replaces the zones served. More than one is only used while a zone
// change waits to be confirmed.
func (rt *Router) SetZones(zones ...string) { rt.zones.Store(&zones) }

// Set replaces the routes.
func (rt *Router) Set(services []Service) {
	m := make(map[string]*httputil.ReverseProxy, len(services))
	for _, s := range services {
		m[s.Name] = newProxy(s, rt.transports[b2i(s.Upstream.Scheme == "http")][b2i(s.PreserveHost)], rt.log)
	}
	rt.proxies.Store(&m)
}

func (rt *Router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var p *httputil.ReverseProxy
	for _, z := range *rt.zones.Load() {
		if p = (*rt.proxies.Load())[serviceName(r.Host, z)]; p != nil {
			break
		}
	}
	if p == nil {
		http.NotFound(w, r)
		return
	}
	p.ServeHTTP(w, r)
}

// Info is one service as shown to the status page.
type Info struct {
	Name         string `json:"name"`
	Upstream     string `json:"upstream"`
	PreserveHost bool   `json:"preserve_host,omitempty"`
}

// Manager owns the services file and keeps the Router in step with it.
type Manager struct {
	OnChange func() // called after a change, to rebuild DNS

	path   string
	zone   string
	log    *slog.Logger
	router *Router

	mu       sync.Mutex
	services []Service
}

// OpenManager loads the services file. An editable file may be missing or
// empty, because services can be added from the status page.
func OpenManager(path, zone string, log *slog.Logger, editable bool) (*Manager, error) {
	services, err := LoadServices(path, zone)
	if err != nil && !(editable && errors.Is(err, fs.ErrNotExist)) {
		return nil, err
	}
	if len(services) == 0 && !editable {
		return nil, errors.New("no services listed")
	}
	m := &Manager{path: path, zone: zone, log: log, router: NewRouter(zone, log), services: services}
	m.router.Set(services)
	return m, nil
}

// CheckZone refuses a zone that would make an upstream loop back to tarn.
func (m *Manager) CheckZone(zone string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range m.services {
		if _, err := parseUpstream(s.Upstream.String(), zone); err != nil {
			return fmt.Errorf("service %s: %w", s.Name, err)
		}
	}
	return nil
}

// SetZones changes the zones served, the first being the main one.
func (m *Manager) SetZones(zones ...string) {
	m.mu.Lock()
	m.zone = zones[0]
	m.mu.Unlock()
	m.router.SetZones(zones...)
}

// Router returns the live handler.
func (m *Manager) Router() *Router { return m.router }

// Names returns the current service names.
func (m *Manager) Names() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return Names(m.services)
}

// List returns the current services.
func (m *Manager) List() []Info {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Info, len(m.services))
	for i, s := range m.services {
		out[i] = Info{s.Name, s.Upstream.String(), s.PreserveHost}
	}
	return out
}

// Put adds a service, or changes the upstream of an existing one. The input
// goes through the same checks as the file does.
func (m *Manager) Put(name, upstream string, preserve bool) error {
	if strings.ContainsAny(name+upstream, " \t\r\n") {
		return errors.New("names and addresses can't contain spaces")
	}
	m.mu.Lock()
	zone := m.zone
	m.mu.Unlock()
	line := name + " " + upstream
	if preserve {
		line += " host=preserve"
	}
	parsed, err := ParseServices(strings.NewReader(line), zone)
	if err != nil {
		return errors.New(strings.TrimPrefix(err.Error(), "line 1: "))
	}
	if len(parsed) != 1 {
		return errors.New("enter a service name and an address")
	}
	s := parsed[0]

	m.mu.Lock()
	next := slices.Clone(m.services)
	verb := "service added"
	if i := slices.IndexFunc(next, func(o Service) bool { return o.Name == s.Name }); i >= 0 {
		next[i] = s
		verb = "service changed"
	} else {
		next = append(next, s)
	}
	err = m.commit(next)
	m.mu.Unlock()
	if err != nil {
		return err
	}
	m.log.Info(verb, "service", s.Name, "upstream", s.Upstream.String())
	m.changed()
	return nil
}

// Delete removes a service.
func (m *Manager) Delete(name string) error {
	m.mu.Lock()
	i := slices.IndexFunc(m.services, func(o Service) bool { return o.Name == name })
	if i < 0 {
		m.mu.Unlock()
		return fmt.Errorf("no service named %q", name)
	}
	err := m.commit(slices.Delete(slices.Clone(m.services), i, i+1))
	m.mu.Unlock()
	if err != nil {
		return err
	}
	m.log.Info("service removed", "service", name)
	m.changed()
	return nil
}

// commit saves first, so a failed write changes nothing. Callers hold mu.
func (m *Manager) commit(next []Service) error {
	var b strings.Builder
	b.WriteString("# Managed by tarn's status page. One \"name upstream-url\" per line.\n")
	for _, s := range next {
		opt := ""
		if s.PreserveHost {
			opt = " host=preserve"
		}
		fmt.Fprintf(&b, "%s %s%s\n", s.Name, s.Upstream, opt)
	}
	if err := writeAtomic(m.path, []byte(b.String())); err != nil {
		return fmt.Errorf("can't save the services file (is it in tarn's state directory?): %w", err)
	}
	m.services = next
	m.router.Set(next)
	return nil
}

func (m *Manager) changed() {
	if m.OnChange != nil {
		m.OnChange()
	}
}

func writeAtomic(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name()) // fails harmlessly after the rename
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
