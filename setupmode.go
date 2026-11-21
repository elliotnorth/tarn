package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/elliotnorth/tarn/internal/certs"
	"github.com/elliotnorth/tarn/internal/peers"
	"github.com/elliotnorth/tarn/internal/settings"
	"github.com/elliotnorth/tarn/internal/setup"
)

// Files tarn creates and owns in its state directory during setup.
const (
	tokenFileName     = "cloudflare-token"
	servicesFileName  = "services"
	setupCodeFileName = "setup-code"
)

// needsSetup reports whether this is a fresh install waiting for the wizard:
// it runs with -config, there's no config file yet, and no zone was given.
func needsSetup(c config, configExists bool) bool {
	return c.configPath != "" && !configExists && c.zone == ""
}

// stateTokenFile is the Cloudflare token setup saved, if there is one.
func stateTokenFile(stateDir string) string {
	p := filepath.Join(stateDir, tokenFileName)
	if _, err := os.Stat(p); err == nil {
		return p
	}
	return ""
}

// setupCode returns the code saved in the state directory, making one the
// first time, so it stays the same across restarts until setup is done.
func setupCode(stateDir string) (string, error) {
	p := filepath.Join(stateDir, setupCodeFileName)
	if b, err := os.ReadFile(p); err == nil && len(strings.TrimSpace(string(b))) == 14 {
		return strings.TrimSpace(string(b)), nil
	}
	code := setup.NewCode()
	if err := writeSecretFile(p, code+"\n"); err != nil {
		return "", fmt.Errorf("can't save the setup code in %s: %w", stateDir, err)
	}
	return code, nil
}

// writeSecretFile writes an owner-only file atomically.
func writeSecretFile(path, data string) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err := f.Chmod(0o600); err != nil && !errors.Is(err, errors.ErrUnsupported) {
		f.Close()
		return err
	}
	if _, err := f.WriteString(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

// finishSetup writes what the wizard collected: the token and an empty
// services file in the state directory, and the config file pointing at them.
// Certificates start on staging, so a mistake can't use up Let's Encrypt's
// weekly limit; the status page switches to a trusted certificate.
func finishSetup(c config, a setup.Answers, cost int) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(a.Password), cost)
	if err != nil {
		return err
	}
	if err := writeSecretFile(filepath.Join(c.stateDir, tokenFileName), a.Token+"\n"); err != nil {
		return err
	}
	services := filepath.Join(c.stateDir, servicesFileName)
	if _, err := os.Stat(services); errors.Is(err, os.ErrNotExist) {
		if err := writeSecretFile(services, "# Managed by tarn's status page. One \"name upstream-url\" per line.\n"); err != nil {
			return err
		}
	}
	v := settings.Values{
		Zone: a.Zone, Listen: c.listen, Source: c.source, IntervalSeconds: int(c.interval / time.Second), TTL: uint32(c.ttl),
		ACMEEmail: a.Email, ACMEStaging: true, ServicesFile: services, AdminPasswordHash: string(hash),
	}
	if err := settings.Save(c.configPath, v); err != nil {
		return err
	}
	os.Remove(filepath.Join(c.stateDir, setupCodeFileName))
	return nil
}

// runSetup serves the wizard until it finishes, then starts tarn again with
// the new config.
func runSetup(c config, log *slog.Logger, src peers.Source) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	sctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	st, err := src.Status(sctx)
	cancel()
	if err != nil {
		return fmt.Errorf("setup: %w", err)
	}
	if st.Self == nil || len(st.Self.IPv4) == 0 {
		return setup.ErrNoAddress
	}
	ip := st.Self.IPv4[0].String()
	code, err := setupCode(c.stateDir)
	if err != nil {
		return err
	}

	// Port 80 makes the address short to type; anything else on it is fine.
	ln, err := net.Listen("tcp", net.JoinHostPort(ip, "80"))
	if err != nil {
		if ln, err = net.Listen("tcp", net.JoinHostPort(ip, "9581")); err != nil {
			return fmt.Errorf("setup: can't listen on %s port 80 or 9581: %w", ip, err)
		}
	}
	url := "http://" + ip + "/"
	if _, port, _ := net.SplitHostPort(ln.Addr().String()); port != "80" {
		url = "http://" + net.JoinHostPort(ip, port) + "/"
	}

	srv := &setup.Server{
		Code: code, IP: ip, Headscale: st.SelfHosted(), MinPassword: minAdminPassword, Log: log,
		CheckZone: func(zone string) (string, error) {
			zone, err := checkZone(zone)
			if err == nil && st.Overlaps(zone) {
				err = fmt.Errorf("%s is inside your tailnet's own DNS domain, %s, which answers those names itself. Use a zone outside it", zone, st.MagicDNSSuffix)
			}
			return zone, err
		},
		CheckToken: checkSetupToken,
		Finish:     func(a setup.Answers) error { return finishSetup(c, a, bcrypt.DefaultCost+2) },
	}
	done := make(chan struct{})
	finish := srv.Finish
	srv.Finish = func(a setup.Answers) error {
		if err := finish(a); err != nil {
			return err
		}
		close(done)
		return nil
	}

	web := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go web.Serve(ln)
	defer web.Close()

	// The loopback port says what's going on, for `tarn status` and doctor.
	mgmt := &http.Server{Addr: c.mgmt, ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprintf(w, "{\"status\":\"setup\",\"version\":%q,\"setup_url\":%q}\n", version, url)
	})}
	go mgmt.ListenAndServe()
	defer mgmt.Close()

	log.Warn("tarn needs setting up: open the setup page from a device on your tailnet and enter the code",
		"url", url, "code", code, "code_file", filepath.Join(c.stateDir, setupCodeFileName))

	select {
	case <-ctx.Done():
		return nil
	case <-done:
	}
	time.Sleep(time.Second) // let the last answer reach the browser
	web.Close()
	mgmt.Close()
	log.Info("setup finished; starting tarn with the new config")
	return restartSelf()
}

// checkSetupToken proves a Cloudflare token can do what issuance needs; tests
// replace it.
var checkSetupToken = func(ctx context.Context, token, zone string) error {
	cf := &certs.Cloudflare{Token: token}
	if err := cf.Verify(ctx); err != nil {
		return fmt.Errorf("Cloudflare doesn't accept that token: %w", err)
	}
	return cf.CheckZone(ctx, zone)
}

// restartSelf starts tarn afresh after setup; tests replace it.
var restartSelf = restartProcess
