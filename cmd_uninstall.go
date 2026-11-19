package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
)

// uninstallPlan lists what `tarn uninstall` removes, under root ("" on a real
// system), keeping only paths that exist. State, the token and the password
// go only with purge.
func uninstallPlan(root, exe string, purge bool) []string {
	paths := []string{
		"/etc/systemd/system/tarn.service",
		"/etc/systemd/system/tarn.service.d",
		"/etc/systemd/system/multi-user.target.wants/tarn.service",
		exe,
		exe + ".previous",
	}
	if purge {
		paths = append(paths, "/var/lib/tarn", "/var/lib/private/tarn", "/etc/tarn", "/etc/tarn-services")
	}
	var out []string
	for _, p := range paths {
		if _, err := os.Lstat(filepath.Join(root, p)); err == nil {
			out = append(out, p)
		}
	}
	return out
}

// runUninstall implements `tarn uninstall`.
func runUninstall(args []string, out io.Writer) int {
	fs := flag.NewFlagSet("tarn uninstall", flag.ExitOnError)
	purge := fs.Bool("purge", false, "also delete the certificate, its key, the config, the services file and /etc/tarn")
	yes := fs.Bool("yes", false, "do it; without this, only list what would be removed")
	fs.Parse(args)

	exe, err := installedExe()
	if err != nil {
		fmt.Fprintln(out, "tarn uninstall:", err)
		return 1
	}
	if fromDeb(exe) {
		fmt.Fprintln(out, "tarn came from the .deb. Remove it with: sudo apt remove tarn (or apt purge tarn to delete its state too)")
		return 1
	}
	return uninstall("", exe, *purge, *yes, out, func(args ...string) error {
		return exec.Command("systemctl", args...).Run()
	})
}

func uninstall(root, exe string, purge, yes bool, out io.Writer, systemctl func(...string) error) int {
	plan := uninstallPlan(root, exe, purge)
	if !yes {
		fmt.Fprintln(out, "This stops tarn and removes:")
		for _, p := range plan {
			fmt.Fprintln(out, "  "+p)
		}
		if !purge {
			fmt.Fprintln(out, "It keeps the certificate and config in /var/lib/tarn, and /etc/tarn. Add -purge to delete those too.")
		}
		fmt.Fprintln(out, "Run again with -yes to do it.")
		return 1
	}
	if root == "" && os.Geteuid() != 0 {
		fmt.Fprintln(out, "tarn uninstall: run this with sudo")
		return 1
	}

	systemctl("disable", "--now", "tarn") // fine if it was never enabled
	failed := false
	for _, p := range plan {
		if err := os.RemoveAll(filepath.Join(root, p)); err != nil && !errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(out, "Couldn't remove %s: %v\n", p, err)
			failed = true
			continue
		}
		fmt.Fprintln(out, "Removed", p)
	}
	systemctl("daemon-reload")
	if failed {
		return 1
	}
	fmt.Fprintln(out, "tarn is uninstalled. Remove its nameserver from your tailnet's DNS settings too.")
	return 0
}
