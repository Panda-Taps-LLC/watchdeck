package userconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAutostartRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "watchdeck", "config.yaml")
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, set := c.AutostartUI(); set {
		t.Fatal("missing file: autostart reported as set")
	}
	if err := SetAutostartUI(path, false); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("stat = %v, %v; want 0600", fi, err)
	}
	c, err = Load(path)
	if on, set := c.AutostartUI(); err != nil || !set || on {
		t.Fatalf("after false: on=%v set=%v err=%v", on, set, err)
	}
	// other keys survive a rewrite
	if err := os.WriteFile(path, []byte("future: {x: 1}\nui:\n  autostart: false\n  port: 4000\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SetAutostartUI(path, true); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	for _, want := range []string{"future:", "port: 4000", "autostart: true"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("rewritten file lacks %q:\n%s", want, b)
		}
	}
	if err := os.WriteFile(path, []byte("ui: [\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("broken file: want an error")
	}
}

func TestInstalledAtRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "watchdeck", "config.yaml")
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := c.InstalledAt(); ok {
		t.Fatal("missing file: installed_at reported as set")
	}
	want := time.Date(2026, 10, 19, 8, 30, 15, 0, time.UTC)
	if err := SetInstalledAt(path, want); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("stat = %v, %v; want 0600", fi, err)
	}
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), "installed_at: \"2026-10-19T08:30:15Z\"") && !strings.Contains(string(b), "installed_at: 2026-10-19T08:30:15Z") {
		t.Errorf("file does not hold an RFC 3339 installed_at:\n%s", b)
	}
	c, err = Load(path)
	got, ok := c.InstalledAt()
	if err != nil || !ok || !got.Equal(want) {
		t.Fatalf("InstalledAt = %v, %v (err %v); want %v", got, ok, err, want)
	}
	// a rewrite of another key keeps it, and the reverse
	if err := SetAutostartUI(path, true); err != nil {
		t.Fatal(err)
	}
	c, _ = Load(path)
	if got, ok := c.InstalledAt(); !ok || !got.Equal(want) {
		t.Fatalf("after SetAutostartUI: %v, %v", got, ok)
	}
	if on, set := c.AutostartUI(); !on || !set {
		t.Fatalf("autostart lost: %v %v", on, set)
	}
}

func TestInstalledAtNeverOverwritten(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	first := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	if err := SetInstalledAt(path, first); err != nil {
		t.Fatal(err)
	}
	if err := SetInstalledAt(path, first.Add(48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	c, _ := Load(path)
	if got, ok := c.InstalledAt(); !ok || !got.Equal(first) {
		t.Fatalf("second set changed the value: %v, %v; want %v", got, ok, first)
	}
	// a value that does not parse is not a recorded date: it is replaced
	if err := os.WriteFile(path, []byte("installed_at: yesterday\nui:\n  autostart: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := c.InstalledAt(); ok {
		t.Fatal("unparseable installed_at reported as set")
	}
	if err := SetInstalledAt(path, first); err != nil {
		t.Fatal(err)
	}
	c, _ = Load(path)
	if got, ok := c.InstalledAt(); !ok || !got.Equal(first) {
		t.Fatalf("after replacing a bad value: %v, %v", got, ok)
	}
	if on, set := c.AutostartUI(); !on || !set {
		t.Fatal("other keys lost")
	}
}

func TestInstalledAtUnquotedHandWritten(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	want := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	if err := os.WriteFile(path, []byte("installed_at: 2026-10-01T00:00:00Z\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if got, ok := c.InstalledAt(); err != nil || !ok || !got.Equal(want) {
		t.Fatalf("Load unquoted: %v %v %v", got, ok, err)
	}
	if err := SetInstalledAt(path, want.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	c, _ = Load(path)
	if got, ok := c.InstalledAt(); !ok || !got.Equal(want) {
		t.Fatalf("unquoted value overwritten: %v %v", got, ok)
	}
}

func TestInstalledAtKeepsUnknownKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("# note\nfuture_key: keep-me\nui:\n  autostart: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SetInstalledAt(path, time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	for _, want := range []string{"future_key: keep-me", "autostart: true", "installed_at:"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("rewritten file lacks %q:\n%s", want, b)
		}
	}
}
