// Command signsums makes and uses the Ed25519 key that signs release checksums.
//
//	signsums -genkey PRIVATE PUBLIC   writes a new key pair
//	signsums -sign FILE               signs FILE to FILE.sig, with the key in $TARN_RELEASE_KEY
//
// Plain Ed25519 is used so that the installer can verify with openssl and tarn
// itself with the standard library.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
)

func main() {
	genkey := flag.Bool("genkey", false, "write a new key pair to the two paths given")
	sign := flag.String("sign", "", "file to sign")
	flag.Parse()

	var err error
	switch {
	case *genkey && flag.NArg() == 2:
		err = generate(flag.Arg(0), flag.Arg(1))
	case *sign != "":
		err = signFile(*sign, os.Getenv("TARN_RELEASE_KEY"))
	default:
		err = errors.New("usage: signsums -genkey PRIVATE PUBLIC | signsums -sign FILE")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "signsums:", err)
		os.Exit(1)
	}
}

func generate(privatePath, publicPath string) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return err
	}
	seed := base64.StdEncoding.EncodeToString(priv.Seed()) + "\n"
	if err := os.WriteFile(privatePath, []byte(seed), 0o600); err != nil {
		return err
	}
	return os.WriteFile(publicPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o644)
}

func signFile(path, key string) error {
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(key))
	if err != nil || len(seed) != ed25519.SeedSize {
		return errors.New("TARN_RELEASE_KEY isn't a valid signing key")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return os.WriteFile(path+".sig", ed25519.Sign(ed25519.NewKeyFromSeed(seed), data), 0o644)
}
