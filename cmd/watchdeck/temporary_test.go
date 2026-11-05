package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Panda-Taps-LLC/watchdeck/internal/manifest"
	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
	"github.com/Panda-Taps-LLC/watchdeck/internal/policy"
)

func overridesPath(e testEnv) string { return filepath.Join(e.cfg, paths.BinaryName, "overrides.yaml") }

func fileTemps(t *testing.T, e testEnv) []manifest.Temporary {
	t.Helper()
	f, _, err := policy.LoadFile(overridesPath(e))
	if err != nil {
		t.Fatal(err)
	}
	return f.Temporary
}

// TestRulesPauseAndResume: pause asks (no terminal and no --yes writes
// nothing), writes one temporary per row, refuses a native row; resume
// ends one entry or all.
func TestRulesPauseAndResume(t *testing.T) {
	e := rulesEnv(t)
	const row = "pack:pipe-to-shell/curl-pipe-shell"
	if code, out, _ := call(t, rulesCmd, "pause", row, "--for", "1h"); code != 1 || !strings.Contains(out, "Not applied") {
		t.Fatalf("no tty: exit %d\n%s", code, out)
	}
	if _, err := os.Stat(overridesPath(e)); err == nil {
		t.Fatal("no tty but the overrides file was written")
	}
	for _, bad := range [][]string{{"pause", row}, {"pause", row, "--for", "2h", "--yes"}, {"pause", "--for", "1h", "--yes"}, {"pause", row, "--for"}} {
		if code, _, _ := call(t, rulesCmd, bad...); code != 3 {
			t.Errorf("%q: exit %d, want 3", bad, code)
		}
	}
	code, out, errs := call(t, rulesCmd, "pause", row, "pack:secrets-read/ssh-private-key", "--for", "session=s1", "--yes")
	if code != 0 || !strings.Contains(out, "paused "+row) {
		t.Fatalf("pause: exit %d\n%s%s", code, out, errs)
	}
	temps := fileTemps(t, e)
	if len(temps) != 2 || temps[0].Session != "s1" || temps[0].Rule != "pipe-to-shell/curl-pipe-shell" {
		t.Fatalf("temporaries %+v", temps)
	}
	if !strings.Contains(out, temps[0].ID) {
		t.Fatalf("output does not name the id:\n%s", out)
	}
	code, _, errs = call(t, rulesCmd, "pause", "native:user:permissions.deny:abcd1234", "--for", "1h", "--yes")
	if code != 2 || !strings.Contains(errs, "Claude Code's own rule; change it in Claude Code") {
		t.Fatalf("native row: exit %d %s", code, errs)
	}
	if len(fileTemps(t, e)) != 2 {
		t.Fatal("native row wrote")
	}
	code, out, errs = call(t, rulesCmd, "resume", temps[0].ID, "--yes")
	if code != 0 || !strings.Contains(out, "resumed "+temps[0].ID) {
		t.Fatalf("resume: exit %d\n%s%s", code, out, errs)
	}
	if got := fileTemps(t, e); len(got) != 1 || got[0].ID != temps[1].ID {
		t.Fatalf("after resume %+v", got)
	}
	if code, _, _ := call(t, rulesCmd, "resume", temps[0].ID, "--yes"); code != 2 {
		t.Fatalf("resume absent: exit %d", code)
	}
	if code, _, _ := call(t, rulesCmd, "resume", "--yes"); code != 3 {
		t.Fatalf("resume nothing: exit %d", code)
	}
	if code, out, errs := call(t, rulesCmd, "resume", "all", "--yes"); code != 0 || len(fileTemps(t, e)) != 0 {
		t.Fatalf("resume all: exit %d\n%s%s", code, out, errs)
	}
}

// TestRulesPauseListReadOnly: --list prints the temporaries in force and
// writes nothing.
func TestRulesPauseListReadOnly(t *testing.T) {
	e := rulesEnv(t)
	code, out, _ := call(t, rulesCmd, "pause", "--list")
	if code != 0 || !strings.Contains(out, "no temporaries") {
		t.Fatalf("empty: exit %d\n%s", code, out)
	}
	if _, err := os.Stat(overridesPath(e)); err == nil {
		t.Fatal("--list wrote the overrides file")
	}
	if code, _, errs := call(t, rulesCmd, "pause", "pack:pipe-to-shell/curl-pipe-shell", "--for", "8h", "--yes"); code != 0 {
		t.Fatalf("pause: %s", errs)
	}
	before, _ := os.ReadFile(overridesPath(e))
	code, out, _ = call(t, rulesCmd, "pause", "--list")
	id := fileTemps(t, e)[0].ID
	if code != 0 || !strings.Contains(out, id) || !strings.Contains(out, "pipe-to-shell/curl-pipe-shell") || !strings.Contains(out, "until") {
		t.Fatalf("list: exit %d\n%s", code, out)
	}
	if after, _ := os.ReadFile(overridesPath(e)); string(after) != string(before) {
		t.Fatal("--list changed the file")
	}
	if code, _, _ := call(t, rulesCmd, "pause", "--list", "--for", "1h"); code != 3 {
		t.Fatalf("--list with more: exit %d", code)
	}
}

// TestAllowForWritesTemporaryGrant: allow --for writes a grant temporary
// (never the permanent grant), and refuses auto_allow and narrowing flags.
func TestAllowForWritesTemporaryGrant(t *testing.T) {
	e := newTestEnv(t)
	if code := cmdAllow([]string{"web", "--network", "all", "--write", "./out", "--for", "1h"}); code != 0 {
		t.Fatalf("allow --for exit %d", code)
	}
	temps := fileTemps(t, e)
	if len(temps) != 1 || temps[0].Kind != manifest.TempGrant || temps[0].Skill != "web" || temps[0].Grant == nil ||
		temps[0].Grant.Network == nil || *temps[0].Grant.Network != manifest.NetAll || len(temps[0].Grant.Write) != 1 || temps[0].Grant.AutoAllow != nil {
		t.Fatalf("temporaries %+v", temps)
	}
	f, _, _ := policy.LoadFile(overridesPath(e))
	if len(f.Subjects) != 0 {
		t.Fatalf("permanent grant written: %+v", f.Subjects)
	}
	for _, bad := range [][]string{
		{"web", "--auto", "--for", "1h"},
		{"web", "--no-auto", "--network", "all", "--for", "1h"},
		{"web", "--network", "none", "--for", "1h"},
		{"web", "--remove-write", "./out", "--for", "1h"},
		{"web", "--reset", "--for", "1h"},
		{"web", "--no-caches", "--for", "1h"},
		{"web", "--network", "all", "--for", "9h"},
		{"web", "--network", "all", "--for", "soon"},
		{"web", "--for", "1h"},
		{"*", "--network", "all", "--for", "1h"},
	} {
		if code := cmdAllow(bad); code != 3 {
			t.Errorf("%q: exit %d, want 3", bad, code)
		}
	}
	if len(fileTemps(t, e)) != 1 {
		t.Fatal("a refused --for wrote")
	}
}
