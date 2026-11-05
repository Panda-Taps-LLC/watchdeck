package runner

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

func stubAccountHome(t *testing.T, home string, err error) {
	t.Helper()
	old := accountHome
	accountHome = func() (string, error) { return home, err }
	t.Cleanup(func() { accountHome = old })
}

// TestRunDenyPaths: ~/.claude.json and its existing siblings always; the
// darwin pattern; $CLAUDE_CONFIG_DIR's file and (relocated) dir; the dir
// skipped when it holds a home or the cwd; the account home's built-in
// denies when $HOME is elsewhere; fail closed on a relative
// CLAUDE_CONFIG_DIR or an unreadable account home.
func TestRunDenyPaths(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	h := filepath.Join(root, "h")
	os.MkdirAll(h, 0o700)
	os.WriteFile(filepath.Join(h, ".claude.json.backup"), []byte("{}"), 0o600)
	env := func(environ map[string]string) Env {
		return Env{Home: h, Cwd: filepath.Join(root, "p"), Environ: environ}
	}
	stubAccountHome(t, h, nil)

	x, err := runDeny(env(nil))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{filepath.Join(h, ".claude.json"), filepath.Join(h, ".claude.json.backup"), filepath.Join(h, ".local", "state", "watchdeck")} {
		if !slices.Contains(x.Paths, want) {
			t.Errorf("missing %s in %q", want, x.Paths)
		}
	}
	if runtime.GOOS == "darwin" && !slices.Contains(x.Patterns, h+"/.claude.json*") {
		t.Errorf("patterns %q", x.Patterns)
	}
	if runtime.GOOS != "darwin" && len(x.Patterns) != 0 {
		t.Errorf("patterns on %s: %q", runtime.GOOS, x.Patterns)
	}

	cd := filepath.Join(root, "c")
	x, _ = runDeny(env(map[string]string{"CLAUDE_CONFIG_DIR": cd}))
	if !slices.Contains(x.Paths, cd) || !slices.Contains(x.Paths, filepath.Join(cd, ".claude.json")) {
		t.Errorf("relocated: %q", x.Paths)
	}
	x, _ = runDeny(env(map[string]string{"CLAUDE_CONFIG_DIR": filepath.Join(h, ".claude")}))
	if slices.Contains(x.Paths, filepath.Join(h, ".claude")) {
		t.Errorf("default dir added as extra: %q", x.Paths)
	}
	for _, c := range []string{h, root, filepath.Join(root, "p")} {
		x, _ = runDeny(env(map[string]string{"CLAUDE_CONFIG_DIR": c}))
		if slices.Contains(x.Paths, c) {
			t.Errorf("CLAUDE_CONFIG_DIR=%s holding home or cwd denied whole", c)
		}
		if !slices.Contains(x.Paths, filepath.Join(c, ".claude.json")) {
			t.Errorf("CLAUDE_CONFIG_DIR=%s: its .claude.json not denied", c)
		}
	}
	if _, err := runDeny(env(map[string]string{"CLAUDE_CONFIG_DIR": "rel"})); err == nil {
		t.Error("relative CLAUDE_CONFIG_DIR accepted")
	}

	// $HOME redirected: the account home's denies stay.
	real := filepath.Join(root, "real")
	stubAccountHome(t, real, nil)
	x, _ = runDeny(env(nil))
	for _, want := range []string{filepath.Join(real, ".ssh"), filepath.Join(real, ".claude"), filepath.Join(real, ".claude.json"), filepath.Join(real, ".netrc"), filepath.Join(real, ".local", "state", "watchdeck"), filepath.Join(h, ".claude.json")} {
		if !slices.Contains(x.Paths, want) {
			t.Errorf("redirected HOME: missing %s", want)
		}
	}
	stubAccountHome(t, "", errors.New("no entry"))
	if _, err := runDeny(env(nil)); err == nil || !strings.Contains(err.Error(), "user database") {
		t.Errorf("unreadable account home: %v", err)
	}
}

// TestAccountHomeIgnoresHOME: the real lookup does not follow $HOME.
func TestAccountHomeIgnoresHOME(t *testing.T) {
	want, err := accountHome()
	if err != nil {
		t.Skipf("no user database entry: %v", err)
	}
	t.Setenv("HOME", "/nonexistent/elsewhere")
	got, err := accountHome()
	if err != nil || got != want {
		t.Errorf("with HOME moved: %q %v, want %q", got, err, want)
	}
}
