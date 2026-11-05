package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Panda-Taps-LLC/watchdeck/internal/manifest"
)

// TestAllowRewritesV1AsV2WithBackup: `watchdeck allow` over a v1
// overrides file keeps the old bytes in overrides.yaml.bak-<ts>, writes
// policy file v2 (0600), and the hook's reader (manifest.LoadOverrides)
// sees the old grants plus the new one.
func TestAllowRewritesV1AsV2WithBackup(t *testing.T) {
	e := newTestEnv(t)
	dir := filepath.Join(e.cfg, "watchdeck")
	path := filepath.Join(dir, "overrides.yaml")
	v1 := "version: 1\nskills:\n  pdf:\n    network: localhost\n"
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(v1), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := cmdAllow([]string{"docx", "--network", "all"}); code != 0 {
		t.Fatalf("allow exit %d", code)
	}
	baks, _ := filepath.Glob(path + ".bak-v1-*") // the v1 → v2 conversion backup
	if len(baks) != 1 {
		t.Fatalf("backups = %v", baks)
	}
	if b, _ := os.ReadFile(baks[0]); string(b) != v1 {
		t.Errorf("backup = %q", b)
	}
	text, _ := os.ReadFile(path)
	if !strings.Contains(string(text), "\nversion: 2\n") {
		t.Fatalf("not v2:\n%s", text)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", fi.Mode().Perm())
	}
	user, _, err := manifest.LoadOverrides(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	if n := user.Skills["pdf"].Network; n == nil || *n != manifest.NetLocalhost {
		t.Errorf("pdf lost: %+v", user.Skills)
	}
	if n := user.Skills["docx"].Network; n == nil || *n != manifest.NetAll {
		t.Errorf("docx not granted: %+v", user.Skills)
	}
	// A no-op edit writes nothing and takes no backup.
	if code := cmdAllow([]string{"docx", "--network", "all"}); code != 0 {
		t.Fatalf("allow exit %d", code)
	}
	if baks2, _ := filepath.Glob(path + ".bak-*"); len(baks2) != 1 {
		t.Errorf("no-op took a backup: %v", baks2)
	}
	// An invalid edit is exit 3 with manifest.Apply's message and leaves the file.
	if code := cmdAllow([]string{"docx", "--write", "~/.ssh"}); code != 3 {
		t.Errorf("deny path exit %d", code)
	}
	if after, _ := os.ReadFile(path); string(after) != string(text) {
		t.Error("refused edit changed the file")
	}
}
