//go:build !unix

package main

import "errors"

func restartProcess() error {
	return errors.New("setup finished; start tarn again")
}
