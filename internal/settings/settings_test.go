package settings

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestSaveAndLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	if _, ok, err := Load(path); ok || err != nil {
		t.Fatalf("missing file: ok=%v err=%v", ok, err)
	}
	want := Values{Zone: "t.example.com", Source: "cli", IntervalSeconds: 30, TTL: 60, ACMEStaging: true}
	if err := Save(path, want); err != nil {
		t.Fatal(err)
	}
	got, ok, err := Load(path)
	if err != nil || !ok || got != want {
		t.Fatalf("got %+v, %v, %v", got, ok, err)
	}
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
			t.Errorf("mode = %o, want 600", st.Mode().Perm())
		}
	}
	if es, _ := os.ReadDir(filepath.Dir(path)); len(es) != 1 {
		t.Errorf("%d files, want 1", len(es))
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	os.WriteFile(path, []byte(`{"zone":"t.example.com","tailscale_path":"/bin/sh"}`), 0o600)
	if _, _, err := Load(path); err == nil {
		t.Error("an unknown field should be an error")
	}
}

func TestHistoryKeepsTheLastFifty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history")
	h := OpenHistory(path)
	for i := 0; i < MaxHistory+5; i++ {
		if err := h.Add(Entry{Time: time.Unix(int64(i), 0), Kind: "setting", Key: "ttl", New: fmt.Sprint(i)}); err != nil {
			t.Fatal(err)
		}
	}
	list := OpenHistory(path).List() // reloaded from disk
	if len(list) != MaxHistory || list[0].New != fmt.Sprint(MaxHistory+4) || list[len(list)-1].New != "5" {
		t.Fatalf("len=%d first=%s last=%s", len(list), list[0].New, list[len(list)-1].New)
	}
	if e, ok := h.Get(list[3].ID); !ok || e.New != list[3].New {
		t.Errorf("Get = %+v, %v", e, ok)
	}
	if _, ok := h.Get("nope"); ok {
		t.Error("Get of an unknown ID")
	}
}

func TestDamagedHistoryStartsEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history")
	os.WriteFile(path, []byte("not json"), 0o600)
	if got := OpenHistory(path).List(); len(got) != 0 {
		t.Errorf("list = %v", got)
	}
}
