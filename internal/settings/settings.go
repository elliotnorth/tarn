// Package settings stores the config file and change history tarn owns in its
// state directory.
package settings

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Values is the config file. Bootstrap settings (the management address, the
// state directory, credential files, and the tailscale binary and socket) are
// deliberately absent, so a page password can't make tarn run or write
// anything new.
type Values struct {
	Zone            string `json:"zone"`
	Listen          string `json:"listen,omitempty"` // empty: the tailnet IP, port 53
	Source          string `json:"source"`
	IntervalSeconds int    `json:"interval_seconds"`
	TTL             uint32 `json:"ttl"`
	ACMEEmail       string `json:"acme_email,omitempty"`
	ACMEStaging     bool   `json:"acme_staging,omitempty"`
	ServicesFile    string `json:"services_file,omitempty"`
	ExportDir       string `json:"export_dir,omitempty"`

	// Hashes only. The records token is shown once and never stored.
	RecordsTokenSHA256 string `json:"records_token_sha256,omitempty"`
	AdminPasswordHash  string `json:"admin_password_hash,omitempty"`
}

// Load reads the config file. A missing file returns ok=false and no error. An
// unknown field is an error, so a hand-edited typo isn't silently ignored.
func Load(path string) (v Values, ok bool, err error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return Values{}, false, nil
	}
	if err != nil {
		return Values{}, false, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		return Values{}, false, fmt.Errorf("%s: %w", path, err)
	}
	return v, true, nil
}

// Save replaces the config file atomically. It is owner-only because it holds
// the password hash.
func Save(path string, v Values) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(path, append(b, '\n'))
}

func writeAtomic(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name()) // fails harmlessly after the rename
	if err := f.Chmod(0o600); err != nil && !errors.Is(err, errors.ErrUnsupported) {
		f.Close()
		return err
	}
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

// MaxHistory is how many changes are kept.
const MaxHistory = 50

// Entry is one change. Callers must never put a secret in Old or New.
type Entry struct {
	ID       string    `json:"id"`
	Time     time.Time `json:"time"`
	Kind     string    `json:"kind"` // "setting" or "service"
	Key      string    `json:"key"`
	Old      string    `json:"old"`
	New      string    `json:"new"`
	Source   string    `json:"source"`
	Undoable bool      `json:"undoable"`
}

// History is the last MaxHistory changes, saved after each one.
type History struct {
	path    string
	mu      sync.Mutex
	entries []Entry // oldest first
}

// OpenHistory loads the file. A damaged history must not stop tarn, so it
// starts empty instead.
func OpenHistory(path string) *History {
	h := &History{path: path}
	if b, err := os.ReadFile(path); err == nil {
		json.Unmarshal(b, &h.entries)
	}
	return h
}

// Add appends an entry, giving it an ID.
func (h *History) Add(e Entry) error {
	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err != nil {
		return err
	}
	e.ID = hex.EncodeToString(raw)
	h.mu.Lock()
	defer h.mu.Unlock()
	h.entries = append(h.entries, e)
	if len(h.entries) > MaxHistory {
		h.entries = h.entries[len(h.entries)-MaxHistory:]
	}
	b, err := json.Marshal(h.entries)
	if err != nil {
		return err
	}
	return writeAtomic(h.path, b)
}

// List returns the entries, newest first.
func (h *History) List() []Entry {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]Entry, len(h.entries))
	for i, e := range h.entries {
		out[len(out)-1-i] = e
	}
	return out
}

// Get finds an entry.
func (h *History) Get(id string) (Entry, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, e := range h.entries {
		if e.ID == id {
			return e, true
		}
	}
	return Entry{}, false
}
