// Command mkdeb builds tarn's optional .deb from a release binary.
//
//	mkdeb -bin dist/tarn-linux-amd64 -arch amd64 -version v0.4.1 -o dist/
//
// The package runs tarn as a fixed "tarn" system user instead of the release
// unit's DynamicUser, and holds no secrets: no token, password or config. It is
// written here rather than with dpkg-deb so that it builds the same bytes on
// any machine, including from Windows, and so that it can be tested.
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

//go:embed postinst
var postinst string

//go:embed prerm
var prerm string

//go:embed postrm
var postrm string

// sysusers creates the user and group; the state directory itself is made
// by systemd's StateDirectory= on first start.
const sysusers = "u tarn - \"tarn DNS and HTTPS for the tailnet\" /var/lib/tarn\n"

func main() {
	var o options
	flag.StringVar(&o.bin, "bin", "", "linux tarn binary to package")
	flag.StringVar(&o.arch, "arch", "", "Debian architecture: amd64, arm64 or armhf")
	flag.StringVar(&o.version, "version", "", "version, with or without the leading v")
	flag.StringVar(&o.unit, "unit", "deploy/tarn.service", "release systemd unit to adapt")
	flag.StringVar(&o.license, "license", "LICENSE", "license text for the copyright file")
	flag.StringVar(&o.out, "o", ".", "directory to write the .deb to")
	flag.Parse()

	// SOURCE_DATE_EPOCH is the reproducible-builds convention; the release
	// workflow sets it to the tagged commit's time.
	o.mtime = time.Unix(0, 0)
	if s := os.Getenv("SOURCE_DATE_EPOCH"); s != "" {
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			fail(fmt.Errorf("SOURCE_DATE_EPOCH: %w", err))
		}
		o.mtime = time.Unix(n, 0)
	}

	path, err := build(o)
	if err != nil {
		fail(err)
	}
	fmt.Println(path)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "mkdeb:", err)
	os.Exit(1)
}

type options struct {
	bin, arch, version, unit, license, out string
	mtime                                  time.Time
}

func build(o options) (string, error) {
	switch o.arch {
	case "amd64", "arm64", "armhf":
	default:
		return "", fmt.Errorf("-arch must be amd64, arm64 or armhf, not %q", o.arch)
	}
	version, err := debVersion(o.version)
	if err != nil {
		return "", err
	}
	bin, err := os.ReadFile(o.bin)
	if err != nil {
		return "", err
	}
	unitSrc, err := os.ReadFile(o.unit)
	if err != nil {
		return "", err
	}
	unit, err := adaptUnit(string(unitSrc))
	if err != nil {
		return "", err
	}
	license, err := os.ReadFile(o.license)
	if err != nil {
		return "", err
	}

	data := []file{
		{name: "usr/bin/tarn", mode: 0o755, body: bin},
		{name: "usr/lib/systemd/system/tarn.service", mode: 0o644, body: []byte(unit)},
		{name: "usr/lib/sysusers.d/tarn.conf", mode: 0o644, body: []byte(sysusers)},
		{name: "usr/share/doc/tarn/copyright", mode: 0o644, body: copyright(license)},
	}
	size := 0
	for _, f := range data {
		size += (len(f.body) + 1023) / 1024
	}
	control := fmt.Sprintf(`Package: tarn
Version: %s
Architecture: %s
Maintainer: tarn <https://github.com/elliotnorth/tarn/issues>
Installed-Size: %d
Depends: systemd
Section: net
Priority: optional
Homepage: https://github.com/elliotnorth/tarn
Description: DNS names and HTTPS for your tailnet
 tarn answers DNS for a subdomain with your tailnet's device names, gets a
 wildcard certificate for it, and can reverse-proxy services over HTTPS.
`, version, o.arch, size)

	ctl := []file{
		{name: "control", mode: 0o644, body: []byte(control)},
		{name: "postinst", mode: 0o755, body: []byte(postinst)},
		{name: "prerm", mode: 0o755, body: []byte(prerm)},
		{name: "postrm", mode: 0o755, body: []byte(postrm)},
	}

	ctlTar, err := tarGz(ctl, o.mtime)
	if err != nil {
		return "", err
	}
	dataTar, err := tarGz(data, o.mtime)
	if err != nil {
		return "", err
	}

	var deb bytes.Buffer
	deb.WriteString("!<arch>\n")
	for _, m := range []struct {
		name string
		body []byte
	}{
		{"debian-binary", []byte("2.0\n")},
		{"control.tar.gz", ctlTar},
		{"data.tar.gz", dataTar},
	} {
		arMember(&deb, m.name, m.body, o.mtime)
	}

	path := filepath.Join(o.out, fmt.Sprintf("tarn_%s_%s.deb", version, o.arch))
	if err := os.WriteFile(path, deb.Bytes(), 0o644); err != nil {
		return "", err
	}
	return path, nil
}

// debVersion turns a tag into a Debian version: v0.4.1 is 0.4.1, and a
// pre-release such as v0.5.0-rc1 sorts before 0.5.0 as 0.5.0~rc1.
func debVersion(v string) (string, error) {
	v = strings.TrimPrefix(v, "v")
	if v == "" || v[0] < '0' || v[0] > '9' {
		return "", fmt.Errorf("-version %q must start with a digit", v)
	}
	v = strings.Replace(v, "-", "~", 1)
	for _, r := range v {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || strings.ContainsRune(".+~", r)) {
			return "", fmt.Errorf("-version %q has a character Debian doesn't allow: %q", v, r)
		}
	}
	return v, nil
}

// adaptUnit turns the release unit into the package's: the binary is in
// /usr/bin, and tarn runs as the tarn user instead of a dynamic one. Each
// change must apply exactly once, so a reworded release unit fails the build
// instead of producing a package that silently differs.
func adaptUnit(u string) (string, error) {
	for _, r := range [][2]string{
		{"ExecStart=/usr/local/bin/tarn ", "ExecStart=/usr/bin/tarn "},
		{"\nDynamicUser=yes\n", "\nUser=tarn\nGroup=tarn\n"},
	} {
		if n := strings.Count(u, r[0]); n != 1 {
			return "", fmt.Errorf("the release unit has %q %d times, want once", strings.TrimSpace(r[0]), n)
		}
		u = strings.Replace(u, r[0], r[1], 1)
	}
	return u, nil
}

func copyright(license []byte) []byte {
	var b bytes.Buffer
	b.WriteString("Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/\n")
	b.WriteString("Upstream-Name: tarn\nSource: https://github.com/elliotnorth/tarn\n\n")
	b.WriteString("Files: *\nLicense: AGPL-3.0-or-later\n")
	for _, line := range strings.Split(strings.TrimRight(string(license), "\n"), "\n") {
		line = strings.TrimRight(line, " \r")
		if line == "" {
			line = "."
		}
		b.WriteString(" " + line + "\n")
	}
	return b.Bytes()
}

type file struct {
	name string
	mode int64
	body []byte
}

// tarGz writes files with their parent directories, owned by root, all with
// the same time, and a gzip header without a name or time.
func tarGz(files []file, mtime time.Time) ([]byte, error) {
	var buf bytes.Buffer
	gz, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	tw := tar.NewWriter(gz)
	hdr := func(name string, mode int64, typ byte, size int) *tar.Header {
		return &tar.Header{
			Name: name, Mode: mode, Typeflag: typ, Size: int64(size),
			ModTime: mtime, Uname: "root", Gname: "root", Format: tar.FormatGNU,
		}
	}
	seen := map[string]bool{}
	for _, f := range files {
		if strings.HasPrefix(f.name, "/") || strings.Contains(f.name, "..") {
			return nil, errors.New("bad path " + f.name)
		}
		parts := strings.Split(f.name, "/")
		for i := 1; i < len(parts); i++ {
			dir := "./" + strings.Join(parts[:i], "/") + "/"
			if !seen[dir] {
				seen[dir] = true
				if err := tw.WriteHeader(hdr(dir, 0o755, tar.TypeDir, 0)); err != nil {
					return nil, err
				}
			}
		}
		if err := tw.WriteHeader(hdr("./"+f.name, f.mode, tar.TypeReg, len(f.body))); err != nil {
			return nil, err
		}
		if _, err := tw.Write(f.body); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// arMember appends one member in the common ar format dpkg reads.
func arMember(w io.Writer, name string, body []byte, mtime time.Time) {
	fmt.Fprintf(w, "%-16s%-12d%-6d%-6d%-8s%-10d`\n", name, mtime.Unix(), 0, 0, "100644", len(body))
	w.Write(body)
	if len(body)%2 == 1 {
		w.Write([]byte{'\n'})
	}
}
