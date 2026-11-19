package main

import (
	"context"
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/elliotnorth/tarn/internal/doctor"
	"github.com/elliotnorth/tarn/internal/update"
)

//go:embed deploy/release.pub
var releaseKey []byte

// installedExe is the binary being run, with symlinks resolved.
func installedExe() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(exe)
}

// fromDeb reports whether dpkg owns path, so apt has to change it.
func fromDeb(path string) bool {
	return exec.Command("dpkg-query", "-S", path).Run() == nil
}

func releaseArch() (string, error) {
	switch runtime.GOARCH {
	case "amd64", "arm64":
		return runtime.GOARCH, nil
	case "arm":
		return "armv7", nil
	}
	return "", fmt.Errorf("there are no releases for %s", runtime.GOARCH)
}

// runUpdate implements `tarn update`.
func runUpdate(args []string, out io.Writer) int {
	fs := flag.NewFlagSet("tarn update", flag.ExitOnError)
	want := fs.String("version", "", "install this release, such as v0.4.1 (default: the latest)")
	mgmt := fs.String("mgmt", "127.0.0.1:9580", "tarn's management address, to check it after the restart")
	fs.Parse(args)

	fail := func(err error) int {
		fmt.Fprintln(out, "tarn update:", err)
		return 1
	}
	if runtime.GOOS != "linux" {
		return fail(errors.New("tarn runs on Linux only"))
	}
	arch, err := releaseArch()
	if err != nil {
		return fail(err)
	}
	exe, err := installedExe()
	if err != nil {
		return fail(err)
	}
	if fromDeb(exe) {
		return fail(fmt.Errorf("%s came from the .deb. Download the new .deb from %s and install it with apt", exe, update.Repo))
	}
	key, err := update.ParsePublicKey(releaseKey)
	if err != nil {
		return fail(err)
	}

	o := cliOptions{mgmt: *mgmt}
	u := &update.Updater{
		Client: &http.Client{Timeout: 2 * time.Minute}, Repo: update.Repo, Key: key, Arch: arch,
		Exe: exe, Current: version, Wait: 60 * time.Second, Poll: time.Second, Out: out,
		Systemctl: func(args ...string) error { return exec.Command("systemctl", args...).Run() },
		VersionOf: func(path string) (string, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			b, err := exec.CommandContext(ctx, path, "-version").Output()
			return string(b), err
		},
		Health: func(ctx context.Context) (update.Health, error) {
			var h doctor.Health
			err := getJSON(ctx, o, "/healthz", &h)
			return update.Health{Version: h.Version, Status: h.Status}, err
		},
	}

	ctx := context.Background()
	tag := *want
	if tag == "" {
		if tag, err = u.LatestTag(ctx); err != nil {
			return fail(err)
		}
		switch c, ok := update.Compare(version, tag); {
		case !ok:
			return fail(fmt.Errorf("this tarn (%s) was built from source. Update it with git, or pass -version %s to switch to the release", version, tag))
		case c == 0:
			fmt.Fprintf(out, "tarn %s is the latest release.\n", version)
			return 0
		case c > 0:
			fmt.Fprintf(out, "tarn %s is newer than the latest release, %s. Nothing to do.\n", version, tag)
			return 0
		}
	} else if c, ok := update.Compare(version, tag); ok && c == 0 {
		fmt.Fprintf(out, "tarn %s is already installed.\n", version)
		return 0
	} else if ok && c > 0 {
		fmt.Fprintf(out, "Going back from %s to %s.\n", version, tag)
	}

	fmt.Fprintf(out, "Downloading tarn %s for linux/%s...\n", tag, arch)
	bin, err := u.Download(ctx, tag)
	if err != nil {
		return fail(err)
	}
	if err := u.Install(ctx, tag, bin); err != nil {
		return fail(err)
	}
	return 0
}
