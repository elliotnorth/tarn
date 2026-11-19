package update

import (
	"context"
	"net/http"
	"os"
	"testing"
	"time"
)

// TestLiveRelease checks the published latest release against the real key.
// It downloads from GitHub, so it only runs with TARN_LIVE=1.
func TestLiveRelease(t *testing.T) {
	if os.Getenv("TARN_LIVE") != "1" {
		t.Skip("set TARN_LIVE=1 to check the published release")
	}
	pemBytes, err := os.ReadFile("../../deploy/release.pub")
	if err != nil {
		t.Fatal(err)
	}
	key, err := ParsePublicKey(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	u := &Updater{Client: &http.Client{Timeout: 2 * time.Minute}, Repo: Repo, Key: key, Arch: "amd64"}
	ctx := context.Background()
	tag, err := u.LatestTag(ctx)
	if err != nil {
		t.Fatal(err)
	}
	bin, err := u.Download(ctx, tag)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%s: %d bytes, signature and checksum good", tag, len(bin))
}
