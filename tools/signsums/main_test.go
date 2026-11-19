package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSignAndVerify(t *testing.T) {
	dir := t.TempDir()
	priv, pub, sums := filepath.Join(dir, "k"), filepath.Join(dir, "p"), filepath.Join(dir, "SHA256SUMS")
	if err := generate(priv, pub); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(sums, []byte("abc  tarn\n"), 0o644)
	key, _ := os.ReadFile(priv)
	if err := signFile(sums, string(key)); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(sums)
	sig, _ := os.ReadFile(sums + ".sig")
	if !ed25519.Verify(readPublic(t, pub), data, sig) {
		t.Error("the signature doesn't verify")
	}
	if ed25519.Verify(readPublic(t, pub), []byte("changed"), sig) {
		t.Error("a changed file verified")
	}
	if err := signFile(sums, "not a key"); err == nil {
		t.Error("a bad key was accepted")
	}
}

func readPublic(t *testing.T, path string) ed25519.PublicKey {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(b)
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return k.(ed25519.PublicKey)
}

// The installer carries its own copy of the key, so the two must never differ.
func TestInstallerHasTheReleaseKey(t *testing.T) {
	pub, err := os.ReadFile("../../deploy/release.pub")
	if err != nil {
		t.Fatal(err)
	}
	readPublic(t, "../../deploy/release.pub")
	script, err := os.ReadFile("../../deploy/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	norm := func(b []byte) string { return strings.ReplaceAll(string(b), "\r\n", "\n") }
	if !strings.Contains(norm(script), strings.TrimSpace(norm(pub))) {
		t.Error("deploy/install.sh doesn't contain deploy/release.pub")
	}
}
