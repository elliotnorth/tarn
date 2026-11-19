package health

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

const (
	sessionCookie = "tarn_session"
	sessionLife   = 12 * time.Hour
	maxLoginFails = 5
	loginWindow   = time.Minute
	maxAuditLines = 20 // per loginWindow
)

// Admin turns on changes from the status page. A change can repoint any name
// on the tailnet, so every change needs a password session.
type Admin struct {
	Password string                     // used when Check is nil
	Check    func(password string) bool // optional; overrides Password
	Put      func(name, upstream string, preserveHost bool, source string) error
	Delete   func(name, source string) error
	Control  Control // settings and history; nil when there's no config file
}

type session struct {
	Editable bool   `json:"editable"`
	SignedIn bool   `json:"signed_in"`
	Control  bool   `json:"control"`
	Warning  string `json:"warning,omitempty"`
}

func (s *Server) sessionState(r *http.Request) session {
	return session{Editable: s.Admin != nil, SignedIn: s.validSession(r), Control: s.Admin != nil && s.Admin.Control != nil, Warning: s.AdminWarning}
}

func (s *Server) adminRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /session", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.sessionState(r))
	})
	if s.Admin == nil {
		return
	}
	mux.HandleFunc("POST /login", s.mutation(false, s.login))
	mux.HandleFunc("POST /logout", s.mutation(true, s.logout))
	mux.HandleFunc("PUT /services/{name}", s.mutation(true, s.putService))
	mux.HandleFunc("DELETE /services/{name}", s.mutation(true, s.deleteService))
	if s.Admin.Control != nil {
		s.controlRoutes(mux)
	}
}

// mutation applies the checks every state-changing request must pass.
//
// Forged cross-site requests can't set the custom header without a CORS
// preflight, which tarn never approves. The Host check stops DNS rebinding,
// where a hostile site's name is pointed at 127.0.0.1.
func (s *Server) mutation(needSession bool, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reason := ""
		switch {
		case r.Header.Get("X-Tarn-Request") != "1":
			reason = "missing X-Tarn-Request header"
		case !loopbackHost(r.Host):
			reason = "Host is not loopback"
		case !sameOrigin(r):
			reason = "Origin does not match"
		}
		if reason != "" {
			s.audit(slog.LevelWarn, "request refused", "reason", reason, "method", r.Method, "path", r.URL.Path, "source", source(r))
			writeError(w, http.StatusForbidden, "request refused")
			return
		}
		if needSession && !s.validSession(r) {
			s.audit(slog.LevelWarn, "change refused: not signed in", "method", r.Method, "path", r.URL.Path, "source", source(r))
			writeError(w, http.StatusUnauthorized, "sign in first")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		next(w, r)
	}
}

// source is the client's address. Behind tarn's proxy that is the last
// X-Forwarded-For entry: the proxy drops whatever the client sent and adds the
// real one, and the management port itself only listens on loopback.
func source(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[len(parts)-1])
	}
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return h
	}
	return r.RemoteAddr
}

func viaProxy(r *http.Request) bool { return r.Header.Get("X-Forwarded-For") != "" }

func (s *Server) logger() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.New(slog.DiscardHandler)
}

// audit logs refused or failed attempts, rate limited so a hostile page can't
// flood the journal.
func (s *Server) audit(level slog.Level, msg string, attrs ...any) {
	s.auditMu.Lock()
	now := s.now()
	if now.Sub(s.auditStart) >= loginWindow {
		s.auditStart, s.auditN = now, 0
	}
	s.auditN++
	ok := s.auditN <= maxAuditLines
	s.auditMu.Unlock()
	if ok {
		s.logger().Log(context.Background(), level, msg, attrs...)
	}
}

func loopbackHost(host string) bool {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if host == "localhost" {
		return true
	}
	a, err := netip.ParseAddr(host)
	return err == nil && a.IsLoopback()
}

// sameOrigin compares Origin with the host the browser is actually on, which
// is X-Forwarded-Host when the page is reached through tarn's proxy.
func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	want := r.Header.Get("X-Forwarded-Host")
	if want == "" {
		want = r.Host
	}
	return strings.EqualFold(u.Host, want)
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "bad request")
		return
	}
	now := s.now()
	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	if now.Sub(s.failStart) >= loginWindow {
		s.failStart, s.fails = now, 0
	}
	if s.fails >= maxLoginFails {
		s.audit(slog.LevelWarn, "sign-in locked out", "source", source(r))
		writeError(w, http.StatusTooManyRequests, "Too many wrong passwords. Wait a minute and try again.")
		return
	}
	if !s.passwordOK(body.Password) {
		s.fails++
		s.audit(slog.LevelWarn, "sign-in failed", "source", source(r), "failures_this_minute", s.fails)
		writeError(w, http.StatusUnauthorized, "Wrong password.")
		return
	}
	s.fails = 0

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		writeError(w, http.StatusInternalServerError, "can't start a session")
		return
	}
	id := hex.EncodeToString(raw)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sessions == nil {
		s.sessions = map[string]time.Time{}
	}
	for k, exp := range s.sessions {
		if now.After(exp) {
			delete(s.sessions, k)
		}
	}
	s.sessions[id] = now.Add(sessionLife)
	s.logger().Info("sign-in succeeded", "source", source(r))
	http.SetCookie(w, s.cookie(r, id, int(sessionLife/time.Second)))
	writeJSON(w, http.StatusOK, session{Editable: true, SignedIn: true})
}

func (s *Server) passwordOK(password string) bool {
	if s.Admin.Check != nil {
		return s.Admin.Check(password)
	}
	got, want := sha256.Sum256([]byte(password)), sha256.Sum256([]byte(s.Admin.Password))
	return subtle.ConstantTimeCompare(got[:], want[:]) == 1
}

// dropOtherSessions signs out every browser except the one making r.
func (s *Server) dropOtherSessions(r *http.Request) {
	c, err := r.Cookie(sessionCookie)
	s.mu.Lock()
	defer s.mu.Unlock()
	for id := range s.sessions {
		if err != nil || id != c.Value {
			delete(s.sessions, id)
		}
	}
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.mu.Lock()
		delete(s.sessions, c.Value)
		s.mu.Unlock()
	}
	http.SetCookie(w, s.cookie(r, "", -1))
	writeJSON(w, http.StatusOK, session{Editable: true})
}

func (s *Server) cookie(r *http.Request, value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name: sessionCookie, Value: value, Path: "/", MaxAge: maxAge,
		HttpOnly: true, SameSite: http.SameSiteStrictMode,
		Secure: r.Header.Get("X-Forwarded-Proto") == "https", // plain HTTP on loopback
	}
}

func (s *Server) validSession(r *http.Request) bool {
	if s.Admin == nil {
		return false
	}
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.sessions[c.Value]
	return ok && s.now().Before(exp)
}

func (s *Server) putService(w http.ResponseWriter, r *http.Request) {
	name := strings.ToLower(r.PathValue("name"))
	var body struct {
		Upstream     string `json:"upstream"`
		PreserveHost bool   `json:"preserve_host"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "bad request")
		return
	}
	if s.viaService(w, r, name) {
		return
	}
	s.apply(w, s.Admin.Put(name, strings.TrimSpace(body.Upstream), body.PreserveHost, source(r)))
}

func (s *Server) deleteService(w http.ResponseWriter, r *http.Request) {
	name := strings.ToLower(r.PathValue("name"))
	if s.viaService(w, r, name) {
		return
	}
	s.apply(w, s.Admin.Delete(name, source(r)))
}

// viaService refuses to change the service this page is being viewed through,
// which would lock the user out of the page. It reports whether it refused.
func (s *Server) viaService(w http.ResponseWriter, r *http.Request, name string) bool {
	host := r.Header.Get("X-Forwarded-Host")
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if !strings.EqualFold(host, name+"."+s.zone()) {
		return false
	}
	writeError(w, http.StatusBadRequest, "You're viewing this page through that service, so it can't be changed from here.")
	return true
}

func (s *Server) apply(w http.ResponseWriter, err error) {
	if err != nil {
		writeFailure(w, err)
		return
	}
	writeJSON(w, http.StatusOK, struct{}{})
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
