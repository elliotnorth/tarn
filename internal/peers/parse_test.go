package peers

import (
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestParseGolden(t *testing.T) {
	files, err := filepath.Glob("../../golden/status-*.json")
	if err != nil || len(files) == 0 {
		t.Fatalf("no golden fixtures found: %v", err)
	}
	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			data, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			st, err := ParseStatus(data)
			if err != nil {
				t.Fatalf("ParseStatus: %v", err)
			}
			if st.Self == nil || !st.Self.Self {
				t.Fatal("no Self node")
			}
			if len(st.Peers) == 0 {
				t.Fatal("no peers")
			}
			for _, p := range st.Peers {
				if p.Name == "" || p.Name != Label(p.Name) {
					t.Errorf("peer %s has invalid name %q", p.ID, p.Name)
				}
				if len(p.IPv4)+len(p.IPv6) == 0 {
					t.Errorf("peer %s has no addresses", p.ID)
				}
				for _, a := range p.IPv4 {
					if !netip.MustParsePrefix("100.64.0.0/10").Contains(a) {
						t.Errorf("peer %s: IPv4 %s outside the tailnet range", p.ID, a)
					}
				}
			}
		})
	}
}

func TestParseGolden1104(t *testing.T) {
	data, err := os.ReadFile("../../golden/status-1.104.4.json")
	if err != nil {
		t.Fatal(err)
	}
	st, err := ParseStatus(data)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(st.Peers); got != 7 {
		t.Fatalf("got %d nodes, want 7 (self + 6 peers)", got)
	}
	if st.Self.Name != "self-test" {
		t.Errorf("self name = %q, want self-test", st.Self.Name)
	}
	want := []netip.Addr{netip.MustParseAddr("100.64.0.2")}
	if !slices.Equal(st.Self.IPv4, want) {
		t.Errorf("self IPv4 = %v, want %v", st.Self.IPv4, want)
	}
	n := 0
	for _, p := range st.Peers {
		if p.Name == "peer1" {
			n++
		}
	}
	if n != 6 {
		t.Errorf("got %d peers named peer1, want 6", n)
	}
}

// TestParseGolden1105 is a real Linux capture (scrubbed) from the first field
// install: two phones share the OS hostname "Phone" and a PC was renamed.
func TestParseGolden1105(t *testing.T) {
	data, err := os.ReadFile("../../golden/status-1.104.5.json")
	if err != nil {
		t.Fatal(err)
	}
	st, err := ParseStatus(data)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Peer{}
	for _, p := range st.Peers {
		if _, dup := got[p.Name]; dup {
			t.Errorf("duplicate name %q", p.Name)
		}
		got[p.Name] = p
	}
	want := []string{"ente", "laptop", "nextcloud", "pc", "phone", "phone-1", "tarn", "vaultwarden"}
	var names []string
	for n := range got {
		names = append(names, n)
	}
	slices.Sort(names)
	if !slices.Equal(names, want) {
		t.Fatalf("names = %v, want %v", names, want)
	}
	if st.Self == nil || st.Self.Name != "tarn" {
		t.Errorf("Self = %+v, want tarn", st.Self)
	}
	if got["laptop"].Online {
		t.Error("laptop should be offline")
	}
	if want := netip.MustParseAddr("100.64.0.1"); !slices.Equal(got["tarn"].IPv4, []netip.Addr{want}) {
		t.Errorf("tarn IPv4 = %v, want %v", got["tarn"].IPv4, want)
	}
	if len(st.Skipped) != 0 {
		t.Errorf("Skipped = %v", st.Skipped)
	}
}

// TestParseNames uses a synthetic fixture where HostName and DNSName differ,
// modelled on a real tailnet: a renamed Windows PC and two
// phones with the same OS hostname that MagicDNS had already made unique.
func TestParseNames(t *testing.T) {
	data, err := os.ReadFile("../../golden/status-synthetic-names.json")
	if err != nil {
		t.Fatal(err)
	}
	st, err := ParseStatus(data)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, p := range st.Peers {
		names = append(names, p.Name)
	}
	slices.Sort(names)
	want := []string{"nas", "pc", "phone", "phone-1", "tarn"}
	if !slices.Equal(names, want) {
		t.Errorf("names = %v, want %v", names, want)
	}
}

func TestParseRules(t *testing.T) {
	doc := `{
	  "Self": {"ID": "n0", "HostName": "Tarn-Box", "DNSName": "tarn-box.example.ts.net.",
	           "TailscaleIPs": ["100.64.0.1/32", "fd7a:115c:a1e0::1/128", "100.64.0.1"]},
	  "Peer": {
	    "k1": {"ID": "n1", "HostName": "", "DNSName": "laptop.example.ts.net.", "TailscaleIPs": ["100.64.0.2"], "Online": true},
	    "k2": {"ID": "n2", "HostName": "Owner's Phone", "TailscaleIPs": ["100.64.0.3"]},
	    "k3": {"ID": "n3", "HostName": "my_nas", "TailscaleIPs": ["fd7a:115c:a1e0::4"]},
	    "k4": {"ID": "n4", "HostName": "noaddr", "TailscaleIPs": ["garbage", "100.64.0.0/10"]},
	    "k5": {"ID": "n5", "HostName": "", "DNSName": "", "TailscaleIPs": ["100.64.0.5"]},
	    "k6": {"ID": "n6", "HostName": "localhost", "DNSName": "nas2.example.ts.net.", "TailscaleIPs": ["100.64.0.6"],
	           "Capabilities": ["x"], "SomeFutureField": {"a": 1}}
	  }
	}`
	st, err := ParseStatus([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Peer{}
	for _, p := range st.Peers {
		got[p.ID] = p
	}

	check := func(id, name string) {
		t.Helper()
		if got[id].Name != name {
			t.Errorf("%s: name = %q, want %q", id, got[id].Name, name)
		}
	}
	check("n0", "tarn-box")      // DNSName's first label, lowercased
	check("n1", "laptop")        // DNSName's first label
	check("n2", "owner-s-phone") // no DNSName: HostName, punctuation becomes hyphens
	check("n3", "my-nas")        // no DNSName: HostName, underscore becomes a hyphen
	check("n6", "nas2")          // DNSName wins over HostName

	self := got["n0"]
	if len(self.IPv4) != 1 || len(self.IPv6) != 1 {
		t.Errorf("self addresses not deduped / suffix not stripped: v4=%v v6=%v", self.IPv4, self.IPv6)
	}
	if st.Self == nil || st.Self.ID != "n0" {
		t.Errorf("Self = %+v", st.Self)
	}
	if !got["n1"].Online {
		t.Error("n1 should be online")
	}
	if _, ok := got["n4"]; ok {
		t.Error("n4 has no usable address and should be skipped")
	}
	if _, ok := got["n5"]; ok {
		t.Error("n5 has no usable name and should be skipped")
	}
	if len(st.Skipped) != 2 {
		t.Errorf("Skipped = %v, want 2 entries", st.Skipped)
	}
}

func TestParseErrors(t *testing.T) {
	for _, doc := range []string{``, `not json`, `{}`, `{"Peer": {}}`} {
		if _, err := ParseStatus([]byte(doc)); err == nil {
			t.Errorf("ParseStatus(%q) succeeded, want error", doc)
		}
	}
}

func TestParseBackendState(t *testing.T) {
	const body = `"Self": {"ID": "n0", "DNSName": "a.example.ts.net.", "TailscaleIPs": ["100.64.0.1"]}}`
	for _, state := range []string{"Stopped", "NeedsLogin", "NeedsMachineAuth", "Starting", "NoState"} {
		_, err := ParseStatus([]byte(`{"BackendState": "` + state + `", ` + body))
		if err == nil || !strings.Contains(err.Error(), "BackendState="+state) {
			t.Errorf("%s: err = %v, want a not-running error", state, err)
		}
	}
	for _, doc := range []string{`{"BackendState": "Running", ` + body, `{` + body} {
		if _, err := ParseStatus([]byte(doc)); err != nil {
			t.Errorf("ParseStatus(%s): %v", doc, err)
		}
	}
}

func TestParseBOM(t *testing.T) {
	doc := "\xef\xbb\xbf" + `{"Self": {"ID": "n0", "HostName": "a", "TailscaleIPs": ["100.64.0.1"]}}`
	if _, err := ParseStatus([]byte(doc)); err != nil {
		t.Fatal(err)
	}
}

func TestLabel(t *testing.T) {
	cases := map[string]string{
		"web":                          "web",
		"Web-01":                       "web-01",
		"--x--":                        "x",
		"a  b":                         "a-b",
		"café":                         "caf",
		"日本":                           "",
		"":                             "",
		strings.Repeat("a", 70):        strings.Repeat("a", 63),
		strings.Repeat("a", 62) + "-b": strings.Repeat("a", 62),
	}
	for in, want := range cases {
		if got := Label(in); got != want {
			t.Errorf("Label(%q) = %q, want %q", in, got, want)
		}
	}
}
