// Package setup serves the first-run wizard: a fresh install has no zone, so
// instead of failing, tarn asks for one in the browser.
//
// The wizard listens on plain HTTP on the tailnet address, where WireGuard
// encrypts it, and only for as long as setup takes. Every request needs the
// one-time setup code, which is written to the state directory and the log, so
// only someone who can read those on the machine can finish setup.
package setup

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"
)

//go:embed setup.html
var page []byte

// Answers is what the wizard collects.
type Answers struct {
	Zone     string
	Token    string // Cloudflare API token
	Password string // status page password, plain; the caller hashes it
	Email    string // ACME contact, optional
}

// Server is the wizard's HTTP side.
type Server struct {
	Code string // the one-time setup code
	IP   string // tarn's tailnet IPv4, shown in the split DNS step

	// CheckZone normalizes and validates a zone, such as t.example.com.
	CheckZone func(zone string) (string, error)
	// CheckToken proves the token can make the DNS records issuance needs.
	CheckToken func(ctx context.Context, token, zone string) error
	// Finish saves the answers. After it returns nil, the wizard is done.
	Finish func(Answers) error

	MinPassword int
	Log         *slog.Logger
	Now         func() time.Time

	mu        sync.Mutex
	fails     []time.Time
	done      bool
	tokenSeen map[string]string // zone+token checked OK, so Finish needn't call Cloudflare again
}

const (
	maxFails   = 5
	failWindow = 15 * time.Minute
)

// NewCode makes a setup code: 12 characters from an alphabet without look-alikes,
// about 60 bits, shown in groups of four.
func NewCode() string {
	const alphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
	var s strings.Builder
	b := make([]byte, 1)
	for n := 0; n < 12; {
		rand.Read(b)
		if int(b[0]) >= 256/len(alphabet)*len(alphabet) {
			continue // keep every character equally likely
		}
		if n > 0 && n%4 == 0 {
			s.WriteByte('-')
		}
		s.WriteByte(alphabet[int(b[0])%len(alphabet)])
		n++
	}
	return s.String()
}

func normCode(c string) string {
	return strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(c)))
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Handler serves the page and the API.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Type", "text/html; charset=utf-8")
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; form-action 'none'; base-uri 'none'; frame-ancestors 'none'")
		w.Write(page)
	})
	mux.HandleFunc("POST /setup/code", s.guard(func(w http.ResponseWriter, r *http.Request, req request) {
		reply(w, http.StatusOK, map[string]any{"ip": s.IP})
	}))
	mux.HandleFunc("POST /setup/token", s.guard(s.token))
	mux.HandleFunc("POST /setup/finish", s.guard(s.finish))
	return mux
}

type request struct {
	Code     string `json:"code"`
	Zone     string `json:"zone"`
	Token    string `json:"token"`
	Password string `json:"password"`
	Email    string `json:"email"`
}

func reply(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, msg string) {
	reply(w, code, map[string]string{"error": msg})
}

// guard runs the checks every request needs: the anti-forgery header, an IP
// literal as the Host (a DNS-rebinding page would send its own name), a
// matching Origin, the lockout, and the setup code.
func (s *Server) guard(next func(http.ResponseWriter, *http.Request, request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			host = r.Host
		}
		_, ipErr := netip.ParseAddr(strings.Trim(host, "[]"))
		switch {
		case r.Header.Get("X-Tarn-Request") != "1", ipErr != nil, !sameOrigin(r):
			s.log().Warn("setup request refused", "source", r.RemoteAddr, "host", r.Host)
			fail(w, http.StatusForbidden, "request refused")
			return
		}
		var req request
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&req); err != nil {
			fail(w, http.StatusBadRequest, "unreadable request")
			return
		}

		s.mu.Lock()
		if s.done {
			s.mu.Unlock()
			fail(w, http.StatusGone, "setup is already finished")
			return
		}
		now := s.now()
		recent := s.fails[:0]
		for _, t := range s.fails {
			if now.Sub(t) < failWindow {
				recent = append(recent, t)
			}
		}
		s.fails = recent
		if len(recent) >= maxFails {
			s.mu.Unlock()
			s.log().Warn("setup locked after wrong codes", "source", r.RemoteAddr)
			fail(w, http.StatusTooManyRequests, "too many wrong codes. Try again in 15 minutes")
			return
		}
		if subtle.ConstantTimeCompare([]byte(normCode(req.Code)), []byte(normCode(s.Code))) != 1 {
			s.fails = append(s.fails, now)
			s.mu.Unlock()
			s.log().Warn("wrong setup code", "source", r.RemoteAddr)
			fail(w, http.StatusForbidden, "that isn't the setup code")
			return
		}
		s.mu.Unlock()
		next(w, r, req)
	}
}

func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	return err == nil && strings.EqualFold(u.Host, r.Host)
}

func (s *Server) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.New(slog.DiscardHandler)
}

// token checks the zone and the token together, since a token is only good
// for the zones it can edit.
func (s *Server) token(w http.ResponseWriter, r *http.Request, req request) {
	zone, err := s.CheckZone(req.Zone)
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	tok := strings.TrimSpace(req.Token)
	if tok == "" {
		fail(w, http.StatusBadRequest, "paste the Cloudflare token")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if err := s.CheckToken(ctx, tok, zone); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	s.mu.Lock()
	if s.tokenSeen == nil {
		s.tokenSeen = map[string]string{}
	}
	s.tokenSeen[zone] = tok
	s.mu.Unlock()
	reply(w, http.StatusOK, map[string]string{"zone": zone})
}

func (s *Server) finish(w http.ResponseWriter, r *http.Request, req request) {
	zone, err := s.CheckZone(req.Zone)
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	tok := strings.TrimSpace(req.Token)
	s.mu.Lock()
	checked := s.tokenSeen[zone] == tok && tok != ""
	s.mu.Unlock()
	if !checked {
		fail(w, http.StatusBadRequest, "check the Cloudflare token first")
		return
	}
	if n := len(req.Password); n < s.MinPassword || n > 72 {
		fail(w, http.StatusBadRequest, fmt.Sprintf("the password must be %d to 72 characters", s.MinPassword))
		return
	}
	email := strings.TrimSpace(req.Email)
	if email != "" && (!strings.Contains(email, "@") || strings.ContainsAny(email, " \t\r\n")) {
		fail(w, http.StatusBadRequest, "that email address doesn't look right")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done {
		fail(w, http.StatusGone, "setup is already finished")
		return
	}
	if err := s.Finish(Answers{Zone: zone, Token: tok, Password: req.Password, Email: email}); err != nil {
		s.log().Error("setup couldn't save", "err", err)
		fail(w, http.StatusInternalServerError, "couldn't save the settings: "+err.Error())
		return
	}
	s.done = true
	s.log().Info("setup finished", "zone", zone, "source", r.RemoteAddr)
	reply(w, http.StatusOK, map[string]string{"zone": zone, "ip": s.IP})
}

// Done reports whether setup has finished.
func (s *Server) Done() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.done
}

// ErrNoAddress means tarn can't find its tailnet address to listen on yet.
var ErrNoAddress = errors.New("can't find this machine's tailnet IPv4 address; is Tailscale up?")
