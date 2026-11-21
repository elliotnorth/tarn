package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"codeberg.org/miekg/dns"

	"github.com/elliotnorth/tarn/internal/certs"
	"github.com/elliotnorth/tarn/internal/doctor"
	"github.com/elliotnorth/tarn/internal/peers"
	"github.com/elliotnorth/tarn/internal/settings"
)

type cliOptions struct {
	mgmt, tailscale, config, tokenFile, stateDir string
}

func parseCLI(name string, args []string) cliOptions {
	var o cliOptions
	fs := flag.NewFlagSet("tarn "+name, flag.ExitOnError)
	fs.StringVar(&o.mgmt, "mgmt", "127.0.0.1:9580", "tarn's management address")
	fs.StringVar(&o.tailscale, "tailscale", "tailscale", "path to the tailscale binary")
	fs.StringVar(&o.config, "config", "/var/lib/tarn/config", "tarn's config file")
	fs.StringVar(&o.stateDir, "state-dir", "/var/lib/tarn", "tarn's state directory")
	fs.StringVar(&o.tokenFile, "cloudflare-token-file", "", "Cloudflare token (default: read from the systemd unit)")
	fs.Parse(args)
	return o
}

func getJSON(ctx context.Context, o cliOptions, path string, into any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+o.mgmt+path, nil)
	if err != nil {
		return err
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return errors.New("this needs the records token")
	}
	return json.NewDecoder(resp.Body).Decode(into) // /healthz is JSON even on 503
}

// runDoctor implements `tarn doctor`. The exit code is 1 if a check failed.
func runDoctor(args []string, out io.Writer) int {
	results := doctor.Run(context.Background(), realEnv(parseCLI("doctor", args)))
	marks := map[doctor.Level]string{doctor.OK: "[ ok ]", doctor.Warn: "[warn]", doctor.Fail: "[FAIL]"}
	for _, r := range results {
		fmt.Fprintf(out, "%s %s: %s\n", marks[r.Level], r.Name, r.Detail)
		if r.Fix != "" {
			fmt.Fprintf(out, "       Fix: %s\n", r.Fix)
		}
	}
	if doctor.Failed(results) {
		return 1
	}
	return 0
}

// runStatus implements `tarn status`.
func runStatus(args []string, out io.Writer) int {
	o := parseCLI("status", args)
	ctx := context.Background()
	var h doctor.Health
	if err := getJSON(ctx, o, "/healthz", &h); err != nil {
		fmt.Fprintln(out, "tarn isn't answering. Check: systemctl status tarn, or run: tarn doctor")
		return 1
	}
	if h.Status == "setup" {
		writeSetupStatus(out, &h, readSetupCode(o.stateDir))
		return 0
	}
	var services []doctor.Service
	serr := getJSON(ctx, o, "/services", &services)
	writeStatus(out, &h, services, serr, time.Now())
	if h.Status != "ok" {
		return 1
	}
	return 0
}

func writeStatus(out io.Writer, h *doctor.Health, services []doctor.Service, serr error, now time.Time) {
	fmt.Fprintf(out, "tarn %s: %s\n", h.Version, h.Status)
	fmt.Fprintf(out, "Zone:         %s (%d names)\n", h.Zone, h.Records)
	if h.LastRefresh != nil {
		fmt.Fprintf(out, "Device list:  read %s ago\n", now.Sub(*h.LastRefresh).Round(time.Second))
	}
	if h.LastError != "" {
		fmt.Fprintf(out, "              last error: %s\n", h.LastError)
	}
	fmt.Fprintf(out, "DNS answers:  %d answered, %d unknown names, %d refused, %d failed\n",
		h.DNS["answered"]+h.DNS["no_data"], h.DNS["nxdomain"], h.DNS["refused"], h.DNS["servfail"]+h.DNS["not_implemented"])
	if t := h.TLS; t != nil {
		if t.NotAfter == nil {
			fmt.Fprintln(out, "Certificate:  none yet")
		} else {
			mode := ""
			if t.Staging {
				mode = " (staging)"
			}
			fmt.Fprintf(out, "Certificate:  %s%s, %d days left (expires %s)\n", t.Domain, mode, int(t.NotAfter.Sub(now).Hours()/24), t.NotAfter.Format("2006-01-02"))
			renewed := "not renewed by itself yet"
			if t.LastRenewed != nil {
				renewed = "renewed by itself " + t.LastRenewed.Format("2006-01-02")
			}
			if t.RenewBy != nil {
				renewed += "; renews by " + t.RenewBy.Format("2006-01-02") + " at the latest"
			}
			fmt.Fprintf(out, "              %s\n", renewed)
			if t.Fails > 0 && t.NotAfter.Sub(now) < 14*24*time.Hour {
				fmt.Fprintln(out, "              URGENT: renewal is failing with under 14 days left. Run: sudo tarn doctor")
			}
		}
		if t.Error != "" {
			fmt.Fprintf(out, "              failing: %s\n", t.Error)
		}
	}
	switch {
	case serr != nil:
		fmt.Fprintf(out, "Services:     %v\n", serr)
	case len(services) == 0:
		fmt.Fprintln(out, "Services:     none")
	default:
		fmt.Fprintln(out, "Services:")
		for _, s := range services {
			fmt.Fprintf(out, "  %s.%s -> %s\n", s.Name, h.Zone, s.Upstream)
		}
	}
	for _, c := range h.Collisions {
		if c.Service {
			fmt.Fprintf(out, "Name clash:   the service %q hides a device of that name. Rename one of them\n", c.Name)
		} else {
			where := "in the Tailscale admin console"
			if h.SelfHosted {
				where = "with: headscale nodes rename"
			}
			fmt.Fprintf(out, "Name clash:   two devices want %q. Rename one %s\n", c.Name, where)
		}
	}
	for _, s := range h.Skipped {
		fmt.Fprintf(out, "Skipped:      %s\n", s)
	}
}

var credentialLine = regexp.MustCompile(`(?m)^LoadCredential=cloudflare:(\S+)`)

func realEnv(o cliOptions) *doctor.Env {
	env := &doctor.Env{
		Now: time.Now,
		Health: func(ctx context.Context) (*doctor.Health, error) {
			var h doctor.Health
			return &h, getJSON(ctx, o, "/healthz", &h)
		},
		Services: func(ctx context.Context) ([]doctor.Service, error) {
			var s []doctor.Service
			return s, getJSON(ctx, o, "/services", &s)
		},
		Tailscale: peers.CLI{Path: o.tailscale}.Status,
		HasTUN: func() bool {
			_, err := os.Stat("/dev/net/tun")
			return err == nil
		},
		CheckDNS: askSOA,
		PortFree: func(addr string) error {
			pc, err := net.ListenPacket("udp", addr)
			if errors.Is(err, syscall.EACCES) {
				return nil // only means this shell isn't root; the service has the capability
			}
			if err != nil {
				return err
			}
			return pc.Close()
		},
		SplitDNS: func(ctx context.Context) (string, error) {
			b, err := exec.CommandContext(ctx, o.tailscale, "dns", "status").CombinedOutput()
			return string(b), err
		},
		Cloudflare: func() (doctor.Zone, error) { return cloudflareFor(o) },
		Reach:      reach,
		ServerTime: internetTime,
	}
	if v, ok, err := settings.Load(o.config); err == nil && ok {
		env.Zone, env.Listen = v.Zone, v.Listen
	}
	return env
}

func askSOA(ctx context.Context, addr, zone string) error {
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	reply, _, err := new(dns.Client).Exchange(cctx, dns.NewMsg(zone+".", dns.TypeSOA), "udp", addr)
	if err != nil {
		return err
	}
	if !reply.Authoritative || reply.Rcode != dns.RcodeSuccess {
		return errors.New("something else answered")
	}
	return nil
}

func cloudflareFor(o cliOptions) (doctor.Zone, error) {
	path := o.tokenFile
	if path == "" {
		if b, err := exec.Command("systemctl", "cat", "tarn").Output(); err == nil {
			if m := credentialLine.FindSubmatch(b); m != nil {
				path = string(m[1])
			}
		}
	}
	if path == "" {
		// Saved by the setup wizard. Reading it needs root, like the state
		// directory itself.
		path = filepath.Join(o.stateDir, tokenFileName)
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrPermission) {
		return nil, doctor.ErrNeedsRoot
	}
	if err != nil {
		return nil, fmt.Errorf("can't read the token file %s", path)
	}
	return &certs.Cloudflare{Token: strings.TrimSpace(string(b))}, nil
}

func noRedirects(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

func reach(ctx context.Context, url string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second, CheckRedirect: noRedirects}).Do(req)
	if err != nil {
		return fmt.Errorf("no answer from %s", url)
	}
	resp.Body.Close()
	return nil // any HTTP answer means it's up
}

// internetTime reads the Date header over plain HTTP. TLS would fail when the
// clock is wrong, which is the case this exists to catch, and nothing else from
// the response is used.
func internetTime(ctx context.Context) (time.Time, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, "http://cloudflare.com/", nil)
	if err != nil {
		return time.Time{}, err
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second, CheckRedirect: noRedirects}).Do(req)
	if err != nil {
		return time.Time{}, errors.New("no internet time source reachable")
	}
	resp.Body.Close()
	return http.ParseTime(resp.Header.Get("Date"))
}

// readSetupCode reads the setup code tarn saved, which needs root.
func readSetupCode(stateDir string) string {
	b, err := os.ReadFile(filepath.Join(stateDir, setupCodeFileName))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func writeSetupStatus(out io.Writer, h *doctor.Health, code string) {
	fmt.Fprintf(out, "tarn %s is waiting to be set up.\n", h.Version)
	fmt.Fprintf(out, "Open %s from a device on your tailnet", h.SetupURL)
	if code == "" {
		fmt.Fprintln(out, ". Run sudo tarn status to see the setup code.")
		return
	}
	fmt.Fprintf(out, " and enter the code:\n\n    %s\n", code)
}
