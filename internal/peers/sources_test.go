package peers

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

const sampleStatus = `{"Self": {"ID": "n0", "HostName": "box", "TailscaleIPs": ["100.64.0.1"]},
  "Peer": {"k": {"ID": "n1", "HostName": "laptop", "TailscaleIPs": ["100.64.0.2"]}}}`

func TestLocalAPI(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/localapi/v0/status" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, sampleStatus)
	}))
	defer srv.Close()

	st, err := LocalAPI{client: srv.Client(), baseURL: srv.URL}.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Peers) != 2 || st.Self.Name != "box" {
		t.Fatalf("unexpected status: %+v", st)
	}
}

func TestLocalAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "access denied", http.StatusForbidden)
	}))
	defer srv.Close()

	_, err := LocalAPI{client: srv.Client(), baseURL: srv.URL}.Status(context.Background())
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v, want an HTTP 403 error", err)
	}
}

// TestHelperProcess is not a real test: TestCLI runs the test binary as a
// fake `tailscale` command.
func TestHelperProcess(t *testing.T) {
	switch os.Getenv("TARN_FAKE_TAILSCALE") {
	case "ok":
		fmt.Print(sampleStatus)
		os.Exit(0)
	case "fail":
		fmt.Fprint(os.Stderr, "failed to connect to local tailscaled")
		os.Exit(1)
	}
}

func fakeTailscale(t *testing.T, mode string) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("TARN_FAKE_TAILSCALE", mode)
	return exe
}

func cliWithArgs(path string, pre ...string) CLI { return CLI{Path: path, preArgs: pre} }

func TestCLI(t *testing.T) {
	// The fake binary ignores "status --json" and runs only TestHelperProcess.
	exe := fakeTailscale(t, "ok")
	st, err := cliWithArgs(exe, "-test.run=^TestHelperProcess$").Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Peers) != 2 {
		t.Fatalf("got %d peers, want 2", len(st.Peers))
	}
}

func TestCLIFailure(t *testing.T) {
	exe := fakeTailscale(t, "fail")
	_, err := cliWithArgs(exe, "-test.run=^TestHelperProcess$").Status(context.Background())
	if err == nil || !strings.Contains(err.Error(), "failed to connect") {
		t.Fatalf("err = %v, want the stderr message included", err)
	}
}
