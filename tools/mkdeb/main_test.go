package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func testOptions(t *testing.T) options {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "tarn-linux-amd64")
	if err := os.WriteFile(bin, []byte("fake binary, odd length"), 0o755); err != nil {
		t.Fatal(err)
	}
	return options{
		bin: bin, arch: "amd64", version: "v0.4.1",
		unit: "../../deploy/tarn.service", license: "../../LICENSE",
		out: dir, mtime: time.Unix(1700000000, 0),
	}
}

// readAr splits an ar archive into its members, checking the format dpkg
// expects: the magic, 60-byte headers and even padding.
func readAr(t *testing.T, b []byte) (names []string, bodies map[string][]byte) {
	t.Helper()
	if !bytes.HasPrefix(b, []byte("!<arch>\n")) {
		t.Fatal("no ar magic")
	}
	b = b[8:]
	bodies = map[string][]byte{}
	for len(b) > 0 {
		if len(b) < 60 || string(b[58:60]) != "`\n" {
			t.Fatalf("bad ar header %q", b[:min(60, len(b))])
		}
		name := strings.TrimSpace(string(b[:16]))
		size, err := strconv.Atoi(strings.TrimSpace(string(b[48:58])))
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, name)
		bodies[name] = b[60 : 60+size]
		b = b[60+size+size%2:]
	}
	return names, bodies
}

func readTarGz(t *testing.T, b []byte) map[string]*tar.Header {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if gz.Name != "" || !gz.ModTime.IsZero() {
		t.Errorf("gzip header has name %q time %v", gz.Name, gz.ModTime)
	}
	tr := tar.NewReader(gz)
	out := map[string]*tar.Header{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(tr)
		h.PAXRecords = map[string]string{"body": string(body)}
		out[h.Name] = h
	}
}

func TestBuild(t *testing.T) {
	o := testOptions(t)
	path, err := build(o)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(path) != "tarn_0.4.1_amd64.deb" {
		t.Errorf("name %s", path)
	}
	raw, _ := os.ReadFile(path)
	names, bodies := readAr(t, raw)
	if strings.Join(names, " ") != "debian-binary control.tar.gz data.tar.gz" {
		t.Fatalf("members %v", names)
	}
	if string(bodies["debian-binary"]) != "2.0\n" {
		t.Errorf("debian-binary %q", bodies["debian-binary"])
	}

	ctl := readTarGz(t, bodies["control.tar.gz"])
	control := ctl["./control"].PAXRecords["body"]
	for _, want := range []string{"Package: tarn\n", "Version: 0.4.1\n", "Architecture: amd64\n", "Depends: systemd\n"} {
		if !strings.Contains(control, want) {
			t.Errorf("control lacks %q:\n%s", want, control)
		}
	}
	for _, s := range []string{"./postinst", "./prerm", "./postrm"} {
		h := ctl[s]
		if h == nil || h.Mode != 0o755 || !strings.HasPrefix(h.PAXRecords["body"], "#!/bin/sh\n") {
			t.Errorf("%s: %+v", s, h)
		}
		if strings.Contains(h.PAXRecords["body"], "\r") {
			t.Errorf("%s has CR line endings", s)
		}
	}

	data := readTarGz(t, bodies["data.tar.gz"])
	want := map[string]int64{
		"./usr/": 0o755, "./usr/bin/": 0o755, "./usr/bin/tarn": 0o755,
		"./usr/lib/systemd/system/tarn.service": 0o644,
		"./usr/lib/sysusers.d/tarn.conf":        0o644,
		"./usr/share/doc/tarn/copyright":        0o644,
	}
	for name, mode := range want {
		h := data[name]
		if h == nil {
			t.Errorf("missing %s", name)
			continue
		}
		if h.Mode != mode || h.Uid != 0 || h.Gid != 0 || h.Uname != "root" || !h.ModTime.Equal(o.mtime) {
			t.Errorf("%s: mode %o uid %d gid %d uname %s time %v", name, h.Mode, h.Uid, h.Gid, h.Uname, h.ModTime)
		}
	}
	for name := range data {
		if strings.HasPrefix(name, "./etc/") || strings.HasPrefix(name, "./var/") {
			t.Errorf("package ships %s: config and state are the admin's", name)
		}
	}
	unit := data["./usr/lib/systemd/system/tarn.service"].PAXRecords["body"]
	if !strings.Contains(unit, "ExecStart=/usr/bin/tarn ") || !strings.Contains(unit, "\nUser=tarn\nGroup=tarn\n") || strings.Contains(unit, "DynamicUser") {
		t.Errorf("unit not adapted:\n%s", unit)
	}
	if !strings.Contains(data["./usr/share/doc/tarn/copyright"].PAXRecords["body"], "AFFERO") {
		t.Error("copyright lacks the license text")
	}

	// Same inputs, same bytes.
	o2 := o
	o2.out = t.TempDir()
	path2, err := build(o2)
	if err != nil {
		t.Fatal(err)
	}
	raw2, _ := os.ReadFile(path2)
	if !bytes.Equal(raw, raw2) {
		t.Error("two builds differ")
	}
}

func TestDebVersion(t *testing.T) {
	for in, want := range map[string]string{
		"v0.4.1": "0.4.1", "0.4.1": "0.4.1", "v0.5.0-rc1": "0.5.0~rc1",
	} {
		if got, err := debVersion(in); err != nil || got != want {
			t.Errorf("%s: %q %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "v", "main", "v1.0 ", "v1.0-a-b", "v1_0"} {
		if got, err := debVersion(bad); err == nil {
			t.Errorf("%q accepted as %q", bad, got)
		}
	}
}

func TestAdaptUnitCatchesDrift(t *testing.T) {
	if _, err := adaptUnit("[Service]\nExecStart=/usr/local/bin/tarn -x\nUser=nobody\n"); err == nil {
		t.Error("a unit without DynamicUser=yes was accepted")
	}
	if _, err := adaptUnit("[Service]\nExecStart=/opt/tarn -x\nDynamicUser=yes\n"); err == nil {
		t.Error("a unit with another binary path was accepted")
	}
}

func TestBadArch(t *testing.T) {
	o := testOptions(t)
	o.arch = "armv7"
	if _, err := build(o); err == nil {
		t.Error("armv7 accepted; Debian calls it armhf")
	}
}
