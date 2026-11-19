package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/elliotnorth/tarn/internal/doctor"
)

func TestWriteStatus(t *testing.T) {
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	read := now.Add(-12 * time.Second)
	after := now.Add(60 * 24 * time.Hour)
	h := &doctor.Health{Status: "ok", Version: "v1", Zone: "t.example.com", Records: 3, LastRefresh: &read,
		DNS: map[string]uint64{"answered": 5, "no_data": 1, "nxdomain": 2, "refused": 3},
		TLS: &doctor.TLSState{Domain: "*.t.example.com", NotAfter: &after}}
	var b bytes.Buffer
	writeStatus(&b, h, []doctor.Service{{Name: "app", Upstream: "https://app.example-tailnet.ts.net"}}, nil, now)
	for _, want := range []string{"tarn v1: ok", "read 12s ago", "6 answered", "60 days left", "app.t.example.com -> https://app.example-tailnet.ts.net"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("missing %q in:\n%s", want, b.String())
		}
	}
	b.Reset()
	writeStatus(&b, h, nil, errors.New("this needs the records token"), now)
	if !strings.Contains(b.String(), "records token") {
		t.Errorf("%s", b.String())
	}
}

func TestWriteStatusRenewal(t *testing.T) {
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	soon, by, renewed := now.Add(10*24*time.Hour), now.Add(-20*24*time.Hour), now.Add(-70*24*time.Hour)
	h := &doctor.Health{Status: "ok", Version: "v1", Zone: "t.example.com",
		TLS: &doctor.TLSState{Domain: "*.t.example.com", NotAfter: &soon, RenewBy: &by, Fails: 3, Error: "token rejected"}}

	var b bytes.Buffer
	writeStatus(&b, h, nil, nil, now)
	for _, want := range []string{"not renewed by itself yet", "renews by 2026-10-19", "URGENT"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("missing %q in:\n%s", want, b.String())
		}
	}

	h.TLS.LastRenewed, h.TLS.Fails = &renewed, 0
	b.Reset()
	writeStatus(&b, h, nil, nil, now)
	if !strings.Contains(b.String(), "renewed by itself 2026-08-30") || strings.Contains(b.String(), "URGENT") {
		t.Errorf("unexpected:\n%s", b.String())
	}
}

func TestCredentialLine(t *testing.T) {
	unit := "[Service]\nLoadCredential=admin:/etc/tarn/admin-password\nLoadCredential=cloudflare:/etc/tarn/cloudflare-token\n"
	m := credentialLine.FindStringSubmatch(unit)
	if m == nil || m[1] != "/etc/tarn/cloudflare-token" {
		t.Errorf("got %v", m)
	}
}

// A bad password file must turn editing off, never stop tarn and take DNS down.
func TestBadAdminPasswordFileDisablesEditing(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	for path, want := range map[string]string{
		filepath.Join(dir, "missing"):           "",
		write("short", "tooshort"):              "",
		write("empty", "\n"):                    "",
		write("good", "a long enough password"): "a long enough password",
	} {
		got, warning := loadAdminPassword(path)
		if got != want {
			t.Errorf("%s: password %q", path, got)
		}
		if (want == "") != (warning != "") {
			t.Errorf("%s: warning %q", path, warning)
		}
	}
	if got, warning := loadAdminPassword(""); got != "" || warning != "" {
		t.Errorf("no file: %q %q", got, warning)
	}
}
