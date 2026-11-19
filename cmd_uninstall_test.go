package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fakeInstall(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, p := range []string{
		"usr/local/bin/tarn", "usr/local/bin/tarn.previous",
		"etc/systemd/system/tarn.service", "etc/systemd/system/tarn.service.d/https.conf",
		"var/lib/private/tarn/config", "etc/tarn/cloudflare-token", "etc/tarn-services",
		"usr/local/bin/other-tool",
	} {
		full := filepath.Join(root, p)
		os.MkdirAll(filepath.Dir(full), 0o755)
		if err := os.WriteFile(full, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func exists(root, p string) bool {
	_, err := os.Lstat(filepath.Join(root, p))
	return err == nil
}

func TestUninstallListsFirst(t *testing.T) {
	root := fakeInstall(t)
	var out bytes.Buffer
	var calls []string
	code := uninstall(root, "/usr/local/bin/tarn", false, false, &out, func(a ...string) error {
		calls = append(calls, strings.Join(a, " "))
		return nil
	})
	if code != 1 || len(calls) != 0 || !exists(root, "usr/local/bin/tarn") {
		t.Fatalf("without -yes it acted: code %d calls %v", code, calls)
	}
	if !strings.Contains(out.String(), "/etc/systemd/system/tarn.service.d") || !strings.Contains(out.String(), "-purge") {
		t.Errorf("plan:\n%s", out.String())
	}
}

func TestUninstallKeepsStateWithoutPurge(t *testing.T) {
	root := fakeInstall(t)
	var out bytes.Buffer
	var calls []string
	code := uninstall(root, "/usr/local/bin/tarn", false, true, &out, func(a ...string) error {
		calls = append(calls, strings.Join(a, " "))
		return nil
	})
	if code != 0 {
		t.Fatalf("code %d:\n%s", code, out.String())
	}
	for _, gone := range []string{"usr/local/bin/tarn", "usr/local/bin/tarn.previous", "etc/systemd/system/tarn.service", "etc/systemd/system/tarn.service.d"} {
		if exists(root, gone) {
			t.Errorf("%s still there", gone)
		}
	}
	for _, kept := range []string{"var/lib/private/tarn/config", "etc/tarn/cloudflare-token", "etc/tarn-services", "usr/local/bin/other-tool"} {
		if !exists(root, kept) {
			t.Errorf("%s removed without -purge", kept)
		}
	}
	if strings.Join(calls, ",") != "disable --now tarn,daemon-reload" {
		t.Errorf("calls %v", calls)
	}
}

func TestUninstallPurge(t *testing.T) {
	root := fakeInstall(t)
	var out bytes.Buffer
	if code := uninstall(root, "/usr/local/bin/tarn", true, true, &out, func(...string) error { return nil }); code != 0 {
		t.Fatalf("code %d:\n%s", code, out.String())
	}
	for _, gone := range []string{"var/lib/private/tarn", "etc/tarn", "etc/tarn-services"} {
		if exists(root, gone) {
			t.Errorf("%s still there after purge", gone)
		}
	}
	if !exists(root, "usr/local/bin/other-tool") || !exists(root, "var/lib") {
		t.Error("purge removed something that isn't tarn's")
	}
}
