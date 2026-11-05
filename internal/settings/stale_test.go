package settings

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestInstallRepointsMissingBinary: hooks that name a binary which is gone
// (brew upgrade + cleanup, a moved build) are repointed at the new binary in
// place, reported as Updated, and a second install changes nothing. A hook
// whose binary still exists is left alone.
func TestInstallRepointsMissingBinary(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "new", "watchdeck")
	if err := os.MkdirAll(filepath.Dir(bin), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	gone := filepath.Join(dir, "Cellar", "watchdeck", "0.1.0", "bin", "watchdeck")
	p := filepath.Join(dir, "settings.json")
	if _, err := Install(p, gone); err != nil {
		t.Fatal(err)
	}
	plan, err := Plan(p, bin, false)
	if err != nil || len(plan) != HookCount || !strings.HasPrefix(plan[0], "(update) hooks.PreToolUse: "+gone+" -> "+bin) {
		t.Fatalf("plan = %v, %v", plan, err)
	}
	ch, err := Install(p, bin)
	if err != nil {
		t.Fatal(err)
	}
	if !ch.Changed() || len(ch.Updated) != HookCount || len(ch.Added) != 0 || ch.Backup == "" {
		t.Fatalf("install over a missing binary = %+v", ch)
	}
	if want := "hooks.PreToolUse: " + gone + " -> " + bin + " hook (matcher Bash)"; ch.Updated[0] != want {
		t.Fatalf("updated[0] = %q, want %q", ch.Updated[0], want)
	}
	st, err := Inspect(p)
	if err != nil || !st.Complete || st.HookCommand != bin {
		t.Fatalf("status = %+v, %v", st, err)
	}
	if ch, _ := Install(p, bin); ch.Changed() {
		t.Fatalf("second install changed: %+v", ch)
	}
	// a binary that still exists is someone's choice: never repointed
	other := filepath.Join(dir, "other", "watchdeck")
	if ch, _ := Install(p, other); ch.Changed() {
		t.Fatalf("install from another path changed a live hook: %+v", ch)
	}
}
