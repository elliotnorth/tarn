// Package update replaces the running tarn binary with a signed release, and
// puts the old one back if the new one doesn't come up healthy.
//
// Nothing here runs on its own: tarn never checks for updates in the
// background. It only runs when someone types `tarn update`.
package update

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Repo is where releases live.
const Repo = "https://github.com/elliotnorth/tarn/releases"

// The largest file a release download may be. tarn is ~15 MB.
const maxDownload = 128 << 20

var tagPattern = regexp.MustCompile(`^v(\d+)\.(\d+)\.(\d+)(-[0-9A-Za-z.]+)?$`)

// ParsePublicKey reads the PEM release key.
func ParsePublicKey(pemBytes []byte) (ed25519.PublicKey, error) {
	b, _ := pem.Decode(pemBytes)
	if b == nil {
		return nil, errors.New("release key: no PEM block")
	}
	k, err := x509.ParsePKIXPublicKey(b.Bytes)
	if err != nil {
		return nil, fmt.Errorf("release key: %w", err)
	}
	pub, ok := k.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("release key isn't Ed25519")
	}
	return pub, nil
}

// Health is what Updater needs from /healthz.
type Health struct {
	Version string
	Status  string // ok, stale, starting
}

// Updater holds everything an update touches, so tests can swap each part.
type Updater struct {
	Client  *http.Client
	Repo    string // releases URL; Repo unless testing
	Key     ed25519.PublicKey
	Arch    string // amd64, arm64 or armv7
	Exe     string // the installed binary
	Current string // the running version

	// Systemctl runs systemctl with these arguments.
	Systemctl func(args ...string) error
	// VersionOf runs a binary with -version and returns what it printed.
	VersionOf func(path string) (string, error)
	// Health reads /healthz; any error means no answer.
	Health func(ctx context.Context) (Health, error)

	Wait time.Duration // how long the new binary has to become healthy
	Poll time.Duration
	Out  io.Writer
}

func (u *Updater) say(format string, a ...any) { fmt.Fprintf(u.Out, format+"\n", a...) }

// LatestTag asks GitHub which tag "latest" points at, from the redirect,
// without following it.
func (u *Updater) LatestTag(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, u.Repo+"/latest", nil)
	if err != nil {
		return "", err
	}
	c := *u.Client
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := c.Do(req)
	if err != nil {
		return "", fmt.Errorf("can't reach %s: %w", u.Repo, err)
	}
	resp.Body.Close()
	loc := resp.Header.Get("Location")
	i := strings.LastIndex(loc, "/tag/")
	if resp.StatusCode/100 != 3 || i < 0 {
		return "", fmt.Errorf("can't tell the latest release from %s (HTTP %d)", u.Repo, resp.StatusCode)
	}
	tag := loc[i+len("/tag/"):]
	if !tagPattern.MatchString(tag) {
		return "", fmt.Errorf("the latest release has an unexpected tag %q", tag)
	}
	return tag, nil
}

func (u *Updater) get(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := u.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxDownload+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxDownload {
		return nil, fmt.Errorf("%s is too large", url)
	}
	return b, nil
}

// Download fetches tag's binary for u.Arch and checks it against the signed
// checksums. Nothing it returns has been trusted before both checks pass.
func (u *Updater) Download(ctx context.Context, tag string) ([]byte, error) {
	if !tagPattern.MatchString(tag) {
		return nil, fmt.Errorf("%q isn't a release tag like v0.4.1", tag)
	}
	base := u.Repo + "/download/" + tag + "/"
	sums, err := u.get(ctx, base+"SHA256SUMS")
	if err != nil {
		return nil, fmt.Errorf("can't download the checksums: %w", err)
	}
	sig, err := u.get(ctx, base+"SHA256SUMS.sig")
	if err != nil {
		return nil, fmt.Errorf("can't download the signature: %w", err)
	}
	if !ed25519.Verify(u.Key, sums, sig) {
		return nil, errors.New("the release signature is wrong. Nothing was changed")
	}
	name := "tarn-linux-" + u.Arch
	want, err := sumFor(sums, name)
	if err != nil {
		return nil, err
	}
	bin, err := u.get(ctx, base+name)
	if err != nil {
		return nil, fmt.Errorf("can't download %s: %w", name, err)
	}
	got := sha256.Sum256(bin)
	if hex.EncodeToString(got[:]) != want {
		return nil, fmt.Errorf("the checksum of %s is wrong. Nothing was changed", name)
	}
	return bin, nil
}

func sumFor(sums []byte, name string) (string, error) {
	for _, line := range strings.Split(string(sums), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == name && len(f[0]) == 64 {
			return strings.ToLower(f[0]), nil
		}
	}
	return "", fmt.Errorf("the release has no %s", name)
}

// Compare orders two tags, -1, 0 or 1. A pre-release sorts before its
// release. It reports false if either isn't a tag.
func Compare(a, b string) (int, bool) {
	ma, mb := tagPattern.FindStringSubmatch(a), tagPattern.FindStringSubmatch(b)
	if ma == nil || mb == nil {
		return 0, false
	}
	for i := 1; i <= 3; i++ {
		x, _ := strconv.Atoi(ma[i])
		y, _ := strconv.Atoi(mb[i])
		if x != y {
			if x < y {
				return -1, true
			}
			return 1, true
		}
	}
	switch {
	case ma[4] == mb[4]:
		return 0, true
	case ma[4] == "":
		return 1, true
	case mb[4] == "":
		return -1, true
	}
	return strings.Compare(ma[4], mb[4]), true
}

// Install puts bin in place of u.Exe, restarts tarn if it was running, and
// rolls back if the new version isn't healthy within u.Wait. The old binary
// stays next to it as <exe>.previous.
func (u *Updater) Install(ctx context.Context, tag string, bin []byte) error {
	dir := filepath.Dir(u.Exe)
	next, prev := u.Exe+".new", u.Exe+".previous"

	if err := writeFile(next, bin); err != nil {
		return fmt.Errorf("can't write %s: %w (run with sudo)", next, err)
	}
	defer os.Remove(next) // gone after the rename; cleans up on failure
	// A binary that can't even print its version, or prints another one,
	// never replaces the working one.
	if v, err := u.VersionOf(next); err != nil || !strings.Contains(v, tag) {
		return fmt.Errorf("the downloaded binary doesn't run here (%q, %v). Nothing was changed", strings.TrimSpace(v), err)
	}

	// Health before the change decides what counts as healthy after it: if
	// Tailscale is already down, "stale" is the best the new one can do.
	before, _ := u.Health(ctx)
	running := u.Systemctl("is-active", "--quiet", "tarn") == nil

	os.Remove(prev)
	if err := os.Link(u.Exe, prev); err != nil {
		if err := copyFile(u.Exe, prev); err != nil {
			return fmt.Errorf("can't keep the old binary as %s: %w", prev, err)
		}
	}
	if err := os.Rename(next, u.Exe); err != nil {
		return fmt.Errorf("can't replace %s: %w", u.Exe, err)
	}
	syncDir(dir)
	u.say("Installed %s in %s. The old binary is %s.", tag, u.Exe, prev)

	if !running {
		u.say("tarn wasn't running, so nothing was restarted.")
		return nil
	}
	if err := u.Systemctl("restart", "tarn"); err != nil {
		return u.rollback(ctx, prev, fmt.Errorf("restart failed: %w", err))
	}
	u.say("Restarted tarn. Waiting for it to answer...")
	if err := u.waitHealthy(ctx, tag, before.Status == "ok"); err != nil {
		return u.rollback(ctx, prev, err)
	}
	u.say("tarn %s is running.", tag)
	return nil
}

func (u *Updater) waitHealthy(ctx context.Context, tag string, needOK bool) error {
	deadline := time.Now().Add(u.Wait)
	last := "no answer"
	for {
		h, err := u.Health(ctx)
		switch {
		case err != nil:
			last = "no answer"
		case h.Version != tag:
			last = "still answering as " + h.Version
		case h.Status == "ok" || !needOK && h.Status != "starting":
			return nil
		default:
			last = "status " + h.Status
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the new version wasn't healthy after %s (%s)", u.Wait, last)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(u.Poll):
		}
	}
}

func (u *Updater) rollback(ctx context.Context, prev string, cause error) error {
	u.say("%v. Rolling back.", cause)
	if err := os.Rename(prev, u.Exe); err != nil {
		return fmt.Errorf("%w; rollback failed too: %v. Put %s back by hand", cause, err, prev)
	}
	syncDir(filepath.Dir(u.Exe))
	if err := u.Systemctl("restart", "tarn"); err != nil {
		return fmt.Errorf("%w; rolled back to %s, but the restart failed: %v", cause, u.Current, err)
	}
	if err := u.waitHealthy(ctx, u.Current, false); err != nil {
		return fmt.Errorf("%w; rolled back to %s, which isn't answering either: %v", cause, u.Current, err)
	}
	return fmt.Errorf("%w; rolled back to %s, which is running", cause, u.Current)
}

func writeFile(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func copyFile(from, to string) error {
	b, err := os.ReadFile(from)
	if err != nil {
		return err
	}
	return writeFile(to, b)
}

func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
}
