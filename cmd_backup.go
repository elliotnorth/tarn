package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"time"

	"github.com/elliotnorth/tarn/internal/backup"
	"github.com/elliotnorth/tarn/internal/settings"
)

// servicesFlag finds -services-file in the systemd unit, where the README's
// setup puts it.
var servicesFlag = regexp.MustCompile(`(?m)^ExecStart=.*\s-{1,2}services-file[= ](\S+)`)

// servicesPath works out where the services file is: the flag, then the
// config file, then the systemd unit.
func servicesPath(flagValue, config string) string {
	if flagValue != "" {
		return flagValue
	}
	if v, ok, err := settings.Load(config); err == nil && ok && v.ServicesFile != "" {
		return v.ServicesFile
	}
	if b, err := exec.Command("systemctl", "cat", "tarn").Output(); err == nil {
		if m := servicesFlag.FindSubmatch(b); m != nil {
			return string(m[1])
		}
	}
	return ""
}

// runBackup implements `tarn backup`.
func runBackup(args []string, out io.Writer) int {
	flags := flag.NewFlagSet("tarn backup", flag.ExitOnError)
	stateDir := flags.String("state-dir", "/var/lib/tarn", "tarn's state directory")
	config := flags.String("config", "/var/lib/tarn/config", "tarn's config file")
	services := flags.String("services-file", "", "services file (default: from the config file or the systemd unit)")
	output := flags.String("o", "", "archive to write (default: tarn-backup-<date>.tar.gz here)")
	flags.Parse(args)

	name := *output
	if name == "" {
		name = "tarn-backup-" + time.Now().Format("2006-01-02-150405") + ".tar.gz"
	}
	svc := servicesPath(*services, *config)

	// O_EXCL: never overwrite, and the archive holds private keys, so 0600.
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		fmt.Fprintf(out, "Can't create %s: %v\n", name, err)
		return 1
	}
	m, err := backup.Create(f, *stateDir, svc, version, time.Now())
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(name)
		if errors.Is(err, fs.ErrPermission) {
			fmt.Fprintln(out, "Permission denied. The state directory is only readable by root: run it with sudo.")
		} else {
			fmt.Fprintf(out, "Backup failed: %v\n", err)
		}
		return 1
	}

	fmt.Fprintf(out, "Saved %s\n", name)
	fmt.Fprintf(out, "  state directory: %s\n", m.StateDir)
	if m.ServicesFile != "" {
		fmt.Fprintf(out, "  services file:   %s\n", m.ServicesFile)
	}
	fmt.Fprintln(out, "It holds your certificate keys and ACME account key. Keep it somewhere private.")
	fmt.Fprintln(out, "The Cloudflare token isn't included. Keep a copy of it separately.")
	return 0
}

// runRestore implements `tarn restore`.
func runRestore(args []string, out io.Writer) int {
	flags := flag.NewFlagSet("tarn restore", flag.ExitOnError)
	stateDir := flags.String("state-dir", "/var/lib/tarn", "tarn's state directory")
	services := flags.String("services-file", "", "where to put the saved services file, if the backup has one and nothing is there yet")
	mgmt := flags.String("mgmt", "127.0.0.1:9580", "tarn's management address, to check it's stopped")
	flags.Usage = func() {
		fmt.Fprintln(flags.Output(), "Usage: tarn restore [flags] <backup.tar.gz>")
		flags.PrintDefaults()
	}
	flags.Parse(args)
	if flags.NArg() != 1 {
		flags.Usage()
		return 2
	}

	if running(*mgmt) {
		fmt.Fprintln(out, "tarn is running. Stop it first: sudo systemctl stop tarn")
		return 1
	}

	f, err := os.Open(flags.Arg(0))
	if err != nil {
		fmt.Fprintf(out, "Can't open the backup: %v\n", err)
		return 1
	}
	defer f.Close()

	res, err := backup.Restore(f, *stateDir, *services, time.Now())
	if err != nil {
		if errors.Is(err, fs.ErrPermission) {
			fmt.Fprintln(out, "Permission denied: run it with sudo.")
		} else {
			fmt.Fprintf(out, "Restore failed, nothing was changed: %v\n", err)
		}
		return 1
	}

	m := res.Manifest
	fmt.Fprintf(out, "Restored %s (made %s by tarn %s)\n", *stateDir, m.Created.Local().Format("2006-01-02 15:04"), m.TarnVersion)
	if res.Previous != "" {
		fmt.Fprintf(out, "  the old state is in %s; delete it once tarn works\n", res.Previous)
	}
	switch {
	case res.Services != "":
		fmt.Fprintf(out, "  services file written to %s\n", res.Services)
	case res.ServicesSkipped != "":
		fmt.Fprintf(out, "  %s already exists and was left alone; the saved one is restored-services in the state directory\n", res.ServicesSkipped)
	case m.ServicesFile != "":
		fmt.Fprintf(out, "  the saved services file (originally %s) is restored-services in the state directory.\n", m.ServicesFile)
		fmt.Fprintln(out, "  Copy it into place, or restore again with -services-file <path>")
	}
	fmt.Fprintln(out, "Start tarn: sudo systemctl start tarn")
	return 0
}

// running reports whether something answers on tarn's management port.
func running(mgmt string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+mgmt+"/healthz", nil)
	if err != nil {
		return false
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return true
}
