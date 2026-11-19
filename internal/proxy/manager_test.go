package proxy

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func newManager(t *testing.T, initial string) (*Manager, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "services")
	if initial != "" {
		if err := os.WriteFile(path, []byte(initial), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	m, err := OpenManager(path, zone, quiet(), true)
	if err != nil {
		t.Fatal(err)
	}
	return m, path
}

func TestOpenManagerRequirements(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "services")
	if _, err := OpenManager(missing, zone, quiet(), false); err == nil {
		t.Error("a missing read-only file should be an error")
	}
	m, err := OpenManager(missing, zone, quiet(), true)
	if err != nil || len(m.List()) != 0 {
		t.Errorf("a missing editable file should be empty: %v, %v", m, err)
	}
	empty := filepath.Join(t.TempDir(), "services")
	os.WriteFile(empty, []byte("# nothing\n"), 0o600)
	if _, err := OpenManager(empty, zone, quiet(), false); err == nil {
		t.Error("an empty read-only file should be an error")
	}
}

func TestManagerPutRoutesLiveAndPersists(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("from upstream"))
	}))
	defer up.Close()

	m, path := newManager(t, "old http://127.0.0.1:1\n")
	changes := 0
	m.OnChange = func() { changes++ }

	serve := func(host string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		m.Router().ServeHTTP(rec, httptest.NewRequest("GET", "https://"+host+"/", nil))
		return rec
	}
	if rec := serve("app.t.example.com"); rec.Code != http.StatusNotFound {
		t.Fatalf("before Put: %d", rec.Code)
	}
	if err := m.Put("App", up.URL, false); err != nil {
		t.Fatal(err)
	}
	if rec := serve("app.t.example.com"); rec.Code != http.StatusOK || rec.Body.String() != "from upstream" {
		t.Errorf("after Put: %d %q", rec.Code, rec.Body)
	}
	if !slices.Equal(m.Names(), []string{"old", "app"}) {
		t.Errorf("names = %v", m.Names())
	}

	// Changing an existing service keeps one entry.
	if err := m.Put("old", "https://new.example-tailnet.ts.net", false); err != nil {
		t.Fatal(err)
	}
	if got := m.List()[0]; got.Upstream != "https://new.example-tailnet.ts.net" || len(m.List()) != 2 {
		t.Errorf("list = %v", m.List())
	}

	// A restart reads back the same services.
	again, err := OpenManager(path, zone, quiet(), false)
	if err != nil || !slices.Equal(again.Names(), []string{"old", "app"}) {
		t.Fatalf("reopen: %v, %v", again, err)
	}

	if err := m.Delete("app"); err != nil {
		t.Fatal(err)
	}
	if rec := serve("app.t.example.com"); rec.Code != http.StatusNotFound {
		t.Errorf("after Delete: %d", rec.Code)
	}
	if changes != 3 {
		t.Errorf("OnChange ran %d times, want 3", changes)
	}
	if es, _ := os.ReadDir(filepath.Dir(path)); len(es) != 1 {
		t.Errorf("%d files left, want 1", len(es))
	}
}

func TestManagerRejectsBadInput(t *testing.T) {
	m, _ := newManager(t, "keep http://127.0.0.1:1\n")
	for _, c := range [][2]string{
		{"bad name", "http://x"},
		{"under_score", "http://x"},
		{"a", "ftp://x"},
		{"a", "http://x\nb http://evil"},
		{"a", "https://b.t.example.com"},
		{"", "http://x"},
	} {
		if err := m.Put(c[0], c[1], false); err == nil {
			t.Errorf("Put(%q, %q) succeeded", c[0], c[1])
		}
	}
	if err := m.Delete("missing"); err == nil {
		t.Error("Delete of an unknown service should fail")
	}
	if !slices.Equal(m.Names(), []string{"keep"}) {
		t.Errorf("names = %v", m.Names())
	}
}

func TestManagerFailedSaveChangesNothing(t *testing.T) {
	m, path := newManager(t, "keep http://127.0.0.1:1\n")
	os.RemoveAll(filepath.Dir(path)) // saving is now impossible
	err := m.Put("new", "http://127.0.0.1:2", false)
	if err == nil || !strings.Contains(err.Error(), "can't save") {
		t.Fatalf("err = %v", err)
	}
	if !slices.Equal(m.Names(), []string{"keep"}) {
		t.Errorf("names = %v", m.Names())
	}
}
