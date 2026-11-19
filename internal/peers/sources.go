package peers

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"strings"
)

// maxStatusBytes caps how much status output tarn will read.
const maxStatusBytes = 32 << 20

// CLI reads the peer list by running `tailscale status --json`.
type CLI struct {
	Path string // path to the tailscale binary; "tailscale" if empty

	preArgs []string // for tests: arguments placed before "status --json"
}

func (c CLI) Status(ctx context.Context) (*Status, error) {
	path := c.Path
	if path == "" {
		path = "tailscale"
	}
	cmd := exec.CommandContext(ctx, path, append(c.preArgs, "status", "--json")...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &limitedWriter{w: &stdout, n: maxStatusBytes}
	cmd.Stderr = &limitedWriter{w: &stderr, n: 4096}
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			return nil, fmt.Errorf("%s status --json: %w: %s", path, err, msg)
		}
		return nil, fmt.Errorf("%s status --json: %w", path, err)
	}
	return ParseStatus(stdout.Bytes())
}

// DefaultSocket is tailscaled's LocalAPI socket on Linux.
const DefaultSocket = "/var/run/tailscale/tailscaled.sock"

// LocalAPI reads the peer list straight from tailscaled's LocalAPI over its
// unix socket. It returns the same document as the CLI, without starting a
// process every poll and without depending on the tailscale.com module.
type LocalAPI struct {
	Socket string // unix socket path; DefaultSocket if empty

	// For tests: override how the request is made.
	client  *http.Client
	baseURL string
}

func (l LocalAPI) Status(ctx context.Context) (*Status, error) {
	client, base := l.client, l.baseURL
	if client == nil {
		sock := l.Socket
		if sock == "" {
			sock = DefaultSocket
		}
		client = &http.Client{Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sock)
			},
		}}
		// tailscaled checks the Host header on LocalAPI requests.
		base = "http://local-tailscaled.sock"
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/localapi/v0/status", nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("localapi status: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxStatusBytes))
	if err != nil {
		return nil, fmt.Errorf("localapi status: read: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("localapi status: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body[:min(len(body), 200)])))
	}
	return ParseStatus(body)
}

// limitedWriter stops accepting data after n bytes, so a misbehaving binary
// can't make tarn buffer unbounded output.
type limitedWriter struct {
	w io.Writer
	n int
}

var errTooLarge = errors.New("output too large")

func (l *limitedWriter) Write(p []byte) (int, error) {
	if len(p) > l.n {
		l.w.Write(p[:l.n])
		l.n = 0
		return 0, errTooLarge
	}
	l.n -= len(p)
	return l.w.Write(p)
}
