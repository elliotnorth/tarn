package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)

// fill creates a state directory shaped like a real one.
func fill(t *testing.T, dir string) {
	t.Helper()
	files := map[string]string{
		"config":                   `{"zone":"t.example.com"}`,
		"history":                  "[]",
		"production/account.key":   "ACCOUNT KEY",
		"production/issuance.json": "{}",
		"production/zones/t.example.com/cert.pem": "CERT",
		"production/zones/t.example.com/key.pem":  "KEY",
		"staging/zones/t.example.com/cert.pem":    "STAGING CERT",
	}
	for name, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestRoundTrip(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "tarn")
	fill(t, state)
	services := filepath.Join(root, "tarn-services")
	os.WriteFile(services, []byte("vault http://100.64.0.5:8080\n"), 0o600)

	var buf bytes.Buffer
	m, err := Create(&buf, state, services, "v0.4.0", now)
	if err != nil {
		t.Fatal(err)
	}
	if m.ServicesFile != services {
		t.Fatalf("services file not recorded: %q", m.ServicesFile)
	}

	// Lose everything, then restore.
	os.RemoveAll(state)
	os.Remove(services)
	res, err := Restore(bytes.NewReader(buf.Bytes()), state, services, now)
	if err != nil {
		t.Fatal(err)
	}
	if res.Previous != "" {
		t.Fatalf("nothing to move aside, but got %q", res.Previous)
	}
	if res.Services != services {
		t.Fatalf("services file written to %q", res.Services)
	}
	if got := read(t, filepath.Join(state, "production", "zones", "t.example.com", "key.pem")); got != "KEY" {
		t.Fatalf("key = %q", got)
	}
	if got := read(t, filepath.Join(state, "production", "account.key")); got != "ACCOUNT KEY" {
		t.Fatalf("account key = %q", got)
	}
	if got := read(t, services); !strings.HasPrefix(got, "vault ") {
		t.Fatalf("services = %q", got)
	}
	if runtime.GOOS != "windows" {
		fi, _ := os.Stat(filepath.Join(state, "production", "account.key"))
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("account key mode %v", fi.Mode().Perm())
		}
		fi, _ = os.Stat(state)
		if fi.Mode().Perm() != 0o700 {
			t.Fatalf("state dir mode %v", fi.Mode().Perm())
		}
	}
}

func TestServicesInsideStateIsNotSavedTwice(t *testing.T) {
	state := filepath.Join(t.TempDir(), "tarn")
	fill(t, state)
	inside := filepath.Join(state, "services")
	os.WriteFile(inside, []byte("x http://100.64.0.1\n"), 0o600)
	m, err := Create(&bytes.Buffer{}, state, inside, "v", now)
	if err != nil {
		t.Fatal(err)
	}
	if m.ServicesFile != "" {
		t.Fatalf("services file inside the state dir recorded separately: %q", m.ServicesFile)
	}
}

func TestRestoreKeepsCurrentStateAndExistingServices(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "tarn")
	fill(t, state)
	services := filepath.Join(root, "svc")
	os.WriteFile(services, []byte("old\n"), 0o600)
	var buf bytes.Buffer
	if _, err := Create(&buf, state, services, "v", now); err != nil {
		t.Fatal(err)
	}

	// Things change after the backup.
	os.WriteFile(filepath.Join(state, "config"), []byte("NEWER"), 0o600)
	os.WriteFile(services, []byte("newer\n"), 0o600)

	res, err := Restore(&buf, state, services, now)
	if err != nil {
		t.Fatal(err)
	}
	if res.Previous == "" || read(t, filepath.Join(res.Previous, "config")) != "NEWER" {
		t.Fatal("the state before the restore wasn't kept")
	}
	if read(t, filepath.Join(state, "config")) == "NEWER" {
		t.Fatal("config wasn't restored")
	}
	if res.ServicesSkipped != services || read(t, services) != "newer\n" {
		t.Fatal("an existing services file was overwritten")
	}
	if read(t, filepath.Join(state, "restored-services")) != "old\n" {
		t.Fatal("the saved services file wasn't left in the state directory")
	}
}

func TestRestoreThroughSymlink(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "private", "tarn")
	fill(t, real)
	link := filepath.Join(root, "tarn")
	if err := os.Symlink(real, link); err != nil {
		t.Skip("symlinks not available:", err)
	}
	var buf bytes.Buffer
	if _, err := Create(&buf, link, "", "v", now); err != nil {
		t.Fatal(err)
	}
	if _, err := Restore(&buf, link, "", now); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(link)
	if err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("the state directory link was replaced")
	}
	if read(t, filepath.Join(link, "production", "zones", "t.example.com", "cert.pem")) != "CERT" {
		t.Fatal("restore didn't land behind the link")
	}
}

type entry struct {
	name, body string
	typ        byte
	link       string
}

func archive(t *testing.T, manifest *Manifest, entries ...entry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if manifest != nil {
		b, _ := json.Marshal(manifest)
		tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: manifestName, Mode: 0o600, Size: int64(len(b))})
		tw.Write(b)
	}
	for _, e := range entries {
		typ := e.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		h := &tar.Header{Typeflag: typ, Name: e.name, Mode: 0o600, Linkname: e.link}
		if typ == tar.TypeReg {
			h.Size = int64(len(e.body))
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		tw.Write([]byte(e.body))
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func TestRestoreRefusesHostileArchives(t *testing.T) {
	good := &Manifest{Format: Format}
	cases := map[string][]byte{
		"not gzip":          []byte("hello"),
		"no manifest":       archive(t, nil, entry{name: "state/config", body: "x"}),
		"newer format":      archive(t, &Manifest{Format: Format + 1}, entry{name: "state/config", body: "x"}),
		"dot dot":           archive(t, good, entry{name: "state/../../evil", body: "x"}),
		"leading dot dot":   archive(t, good, entry{name: "../evil", body: "x"}),
		"absolute":          archive(t, good, entry{name: "/etc/evil", body: "x"}),
		"backslash":         archive(t, good, entry{name: `state\..\..\evil`, body: "x"}),
		"outside state":     archive(t, good, entry{name: "elsewhere/x", body: "x"}),
		"symlink":           archive(t, good, entry{name: "state/link", typ: tar.TypeSymlink, link: "/etc/passwd"}),
		"hard link":         archive(t, good, entry{name: "state/link", typ: tar.TypeLink, link: "state/config"}),
		"device":            archive(t, good, entry{name: "state/dev", typ: tar.TypeChar}),
		"too large":         archive(t, good, entry{name: "state/big", body: strings.Repeat("x", maxFile+1)}),
		"services, no path": archive(t, good, entry{name: "services", body: "x"}),
		"duplicate file":    archive(t, good, entry{name: "state/config", body: "a"}, entry{name: "state/config", body: "b"}),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			state := filepath.Join(root, "tarn")
			fill(t, state)
			if _, err := Restore(bytes.NewReader(data), state, "", now); err == nil {
				t.Fatal("restore accepted it")
			}
			// The old state is untouched and nothing was left behind.
			if read(t, filepath.Join(state, "production", "zones", "t.example.com", "key.pem")) != "KEY" {
				t.Fatal("the current state changed")
			}
			left, _ := os.ReadDir(root)
			if len(left) != 1 {
				var names []string
				for _, e := range left {
					names = append(names, e.Name())
				}
				t.Fatalf("left behind: %v", names)
			}
		})
	}
}

// The archive's own idea of where the services file goes is never used.
func TestRestoreIgnoresArchiveServicesPath(t *testing.T) {
	root := t.TempDir()
	evil := filepath.Join(root, "planted")
	data := archive(t, &Manifest{Format: Format, ServicesFile: evil},
		entry{name: "state/config", body: "{}"}, entry{name: "services", body: "x"})
	state := filepath.Join(root, "tarn")
	if _, err := Restore(bytes.NewReader(data), state, "", now); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(evil); err == nil {
		t.Fatal("restore wrote to the path named in the archive")
	}
	if read(t, filepath.Join(state, "restored-services")) != "x" {
		t.Fatal("services file not kept in the state directory")
	}
}

func TestCreateMissingStateDir(t *testing.T) {
	if _, err := Create(&bytes.Buffer{}, filepath.Join(t.TempDir(), "nope"), "", "v", now); err == nil {
		t.Fatal("no error for a missing state directory")
	}
}

// FuzzRestore checks that no archive, however odd, writes outside the
// directory it restores into.
func FuzzRestore(f *testing.F) {
	var buf bytes.Buffer
	dir := f.TempDir()
	state := filepath.Join(dir, "seed")
	os.MkdirAll(filepath.Join(state, "production"), 0o700)
	os.WriteFile(filepath.Join(state, "production", "account.key"), []byte("k"), 0o600)
	if _, err := Create(&buf, state, "", "v", now); err != nil {
		f.Fatal(err)
	}
	f.Add(buf.Bytes())
	f.Fuzz(func(t *testing.T, data []byte) {
		root := t.TempDir()
		target := filepath.Join(root, "box", "tarn")
		os.MkdirAll(filepath.Dir(target), 0o700)
		Restore(bytes.NewReader(data), target, "", now)
		entries, _ := os.ReadDir(root)
		if len(entries) != 1 || entries[0].Name() != "box" {
			t.Fatalf("restore wrote outside its parent: %v", entries)
		}
	})
}
