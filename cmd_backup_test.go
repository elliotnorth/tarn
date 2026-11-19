package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestServicesFlagFromUnit(t *testing.T) {
	cases := map[string]string{
		"ExecStart=/usr/local/bin/tarn -zone t.example.com -services-file /etc/tarn-services\n":        "/etc/tarn-services",
		"ExecStart=/usr/local/bin/tarn --services-file=/etc/svc -zone z\n":                             "/etc/svc",
		"# ExecStart=/usr/local/bin/tarn -services-file /old\nExecStart=/usr/local/bin/tarn -zone z\n": "",
		"ExecStart=/usr/local/bin/tarn -zone z\n":                                                      "",
	}
	for unit, want := range cases {
		got := ""
		if m := servicesFlag.FindStringSubmatch(unit); m != nil {
			got = m[1]
		}
		if got != want {
			t.Errorf("%q: got %q, want %q", unit, got, want)
		}
	}
}

func TestRestoreRefusesWhileRunning(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	os.MkdirAll(state, 0o700)
	os.WriteFile(filepath.Join(state, "config"), []byte("KEEP"), 0o600)

	var out bytes.Buffer
	code := runRestore([]string{"-state-dir", state, "-mgmt", strings.TrimPrefix(srv.URL, "http://"), filepath.Join(dir, "x.tar.gz")}, &out)
	if code == 0 || !strings.Contains(out.String(), "tarn is running") {
		t.Fatalf("code %d, output %q", code, out.String())
	}
	if b, _ := os.ReadFile(filepath.Join(state, "config")); string(b) != "KEEP" {
		t.Fatal("state changed")
	}
}

func TestBackupRestoreCommands(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	os.MkdirAll(filepath.Join(state, "production"), 0o700)
	os.WriteFile(filepath.Join(state, "production", "account.key"), []byte("ACCOUNT"), 0o600)
	os.WriteFile(filepath.Join(state, "config"), []byte(`{}`), 0o600)
	svc := filepath.Join(dir, "services")
	os.WriteFile(svc, []byte("vault http://100.64.0.5:8080\n"), 0o600)
	archive := filepath.Join(dir, "b.tar.gz")

	var out bytes.Buffer
	if code := runBackup([]string{"-state-dir", state, "-config", filepath.Join(state, "config"), "-services-file", svc, "-o", archive}, &out); code != 0 {
		t.Fatalf("backup: %s", out.String())
	}
	if code := runBackup([]string{"-state-dir", state, "-config", filepath.Join(state, "config"), "-o", archive}, &out); code == 0 {
		t.Fatal("backup overwrote an existing archive")
	}

	os.RemoveAll(state)
	os.Remove(svc)
	out.Reset()
	if code := runRestore([]string{"-state-dir", state, "-services-file", svc, "-mgmt", "127.0.0.1:1", archive}, &out); code != 0 {
		t.Fatalf("restore: %s", out.String())
	}
	if b, _ := os.ReadFile(filepath.Join(state, "production", "account.key")); string(b) != "ACCOUNT" {
		t.Fatal("account key not restored")
	}
	if b, _ := os.ReadFile(svc); !strings.HasPrefix(string(b), "vault") {
		t.Fatal("services file not restored")
	}
}
