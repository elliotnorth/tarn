package health

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
)

// ErrRateLimited marks a request refused for coming too soon.
var ErrRateLimited = errors.New("too soon")

// ChangeRequest asks for one setting to change.
type ChangeRequest struct {
	Key             string `json:"key"`
	Value           string `json:"value"`
	CurrentPassword string `json:"current_password,omitempty"`
	Source          string `json:"-"`
}

// ChangeResult says how a change went. Status is "applied", or "pending" when
// it needs Keep.
type ChangeResult struct {
	Status       string `json:"status"`
	LogoutOthers bool   `json:"-"`
}

// Preview says what a change will do.
type Preview struct {
	Key     string   `json:"key"`
	Risky   bool     `json:"risky"`
	Issues  bool     `json:"issues_certificate"`
	Summary string   `json:"summary"`
	Notes   []string `json:"notes"`
}

// PendingView is a change waiting for Keep.
type PendingView struct {
	Key            string `json:"key"`
	Old            string `json:"old"`
	New            string `json:"new"`
	SecondsLeft    int    `json:"seconds_left"`
	WaitingForCert bool   `json:"waiting_for_certificate"`
	NeedsPassword  bool   `json:"needs_password"`
	Error          string `json:"error,omitempty"`
}

// SettingsView is what the Settings tab shows. It never holds a secret.
type SettingsView struct {
	Values       map[string]string `json:"values"`
	Pinned       map[string]bool   `json:"pinned"`
	ListenNow    string            `json:"listen_now"`
	HTTPS        bool              `json:"https"`
	TokenOn      bool              `json:"records_token_on"`
	TokenConsole bool              `json:"records_token_console"`
	Pending      *PendingView      `json:"pending,omitempty"`
}

// Control is what the page can change. Implementations must refuse anything
// outside the allowed settings.
type Control interface {
	Settings() SettingsView
	Preview(ctx context.Context, req ChangeRequest) (Preview, error)
	Change(ctx context.Context, req ChangeRequest) (ChangeResult, error)
	Keep(password, source string) error
	Revert(source string) error
	SetRecordsToken(enabled bool, source string) (string, error)
	RefreshNow(ctx context.Context, source string) error
	CheckCloudflare(ctx context.Context) error
	History() any
	Undo(ctx context.Context, id, source string) (ChangeResult, error)
}

func writeFailure(w http.ResponseWriter, err error) {
	code := http.StatusBadRequest
	if errors.Is(err, ErrRateLimited) {
		code = http.StatusTooManyRequests
	}
	writeError(w, code, err.Error())
}

// Every route here needs a session and passes the forgery checks, reads
// included. They exist only when editing is on.
func (s *Server) controlRoutes(mux *http.ServeMux) {
	ctl := s.Admin.Control
	guard := func(method, path string, h http.HandlerFunc) { mux.HandleFunc(method+" "+path, s.mutation(true, h)) }

	guard("GET", "/settings", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, http.StatusOK, ctl.Settings()) })
	guard("GET", "/history", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, http.StatusOK, ctl.History()) })

	guard("POST", "/settings/preview", func(w http.ResponseWriter, r *http.Request) {
		req, ok := readChange(w, r)
		if !ok {
			return
		}
		p, err := ctl.Preview(r.Context(), req)
		if err != nil {
			writeFailure(w, err)
			return
		}
		writeJSON(w, http.StatusOK, p)
	})
	guard("POST", "/settings", func(w http.ResponseWriter, r *http.Request) {
		req, ok := readChange(w, r)
		if !ok {
			return
		}
		s.finishChange(w, r)(ctl.Change(r.Context(), req))
	})
	guard("POST", "/settings/keep", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Password string `json:"password"`
		}
		json.NewDecoder(r.Body).Decode(&body) // the password is optional
		s.apply(w, ctl.Keep(body.Password, source(r)))
	})
	guard("POST", "/settings/revert", func(w http.ResponseWriter, r *http.Request) { s.apply(w, ctl.Revert(source(r))) })
	guard("POST", "/settings/records-token", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Enabled bool `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, "bad request")
			return
		}
		token, err := ctl.SetRecordsToken(body.Enabled, source(r))
		if err != nil {
			writeFailure(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"token": token})
	})
	guard("POST", "/settings/check-cloudflare", func(w http.ResponseWriter, r *http.Request) { s.apply(w, ctl.CheckCloudflare(r.Context())) })
	guard("POST", "/refresh", func(w http.ResponseWriter, r *http.Request) { s.apply(w, ctl.RefreshNow(r.Context(), source(r))) })
	guard("POST", "/history/{id}/undo", func(w http.ResponseWriter, r *http.Request) {
		s.finishChange(w, r)(ctl.Undo(r.Context(), r.PathValue("id"), source(r)))
	})
}

func readChange(w http.ResponseWriter, r *http.Request) (ChangeRequest, bool) {
	var req ChangeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad request")
		return req, false
	}
	req.Source = source(r)
	return req, true
}

func (s *Server) finishChange(w http.ResponseWriter, r *http.Request) func(ChangeResult, error) {
	return func(res ChangeResult, err error) {
		if err != nil {
			writeFailure(w, err)
			return
		}
		if res.LogoutOthers {
			s.dropOtherSessions(r)
		}
		writeJSON(w, http.StatusOK, res)
	}
}
