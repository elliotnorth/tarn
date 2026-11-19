//go:build unix

package main

import (
	"os"
	"syscall"
)

// restartProcess replaces this process with a fresh copy of itself, keeping the
// PID, so systemd sees one long-running service.
func restartProcess() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	return syscall.Exec(exe, os.Args, os.Environ())
}
