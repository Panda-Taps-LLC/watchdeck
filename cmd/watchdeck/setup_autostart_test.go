package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Panda-Taps-LLC/watchdeck/internal/userconfig"
)

// TestSetupAsksAutostart: a "y" on a terminal saves ui.autostart: true and
// says when it takes effect; "n" saves false; --yes asks nothing and keeps
// the current answer.
func TestSetupAsksAutostart(t *testing.T) {
	e := newTestEnv(t)
	passSelfTest(t)
	cfgPath := filepath.Join(e.cfg, "watchdeck", "config.yaml")
	autostart := func() (bool, bool) {
		cfg, err := userconfig.Load(cfgPath)
		if err != nil {
			t.Fatal(err)
		}
		return cfg.AutostartUI()
	}

	// "y" for the rules, "y" for the hooks, "y" for autostart
	c, out := testConsole("y\ny\ny\n", true, false)
	if code := runSetup(c, setupOptions{}); code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if on, set := autostart(); !on || !set {
		t.Fatalf("autostart after y: on=%v set=%v\n%s", on, set, out)
	}
	if !strings.Contains(out.String(), "Start the dashboard automatically with each Claude Code session? [y/N]") ||
		!strings.Contains(out.String(), "The session hook starts it") {
		t.Fatalf("output:\n%s", out)
	}
	if fi, err := os.Stat(cfgPath); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("config.yaml: %v %v", err, fi)
	}

	// rerun: rules and hooks already set; the question defaults to the saved answer
	c, out = testConsole("n\n", true, false)
	if code := runSetup(c, setupOptions{}); code != 0 {
		t.Fatalf("rerun exit %d\n%s", code, out)
	}
	if !strings.Contains(out.String(), "session? [Y/n]") {
		t.Fatalf("default not the saved answer:\n%s", out)
	}
	if on, _ := autostart(); on {
		t.Fatalf("n did not turn autostart off:\n%s", out)
	}

	// --yes: nothing asked, nothing written
	before, _ := os.ReadFile(cfgPath)
	c, out = testConsole("", false, true)
	if code := runSetup(c, setupOptions{}); code != 0 {
		t.Fatalf("--yes exit %d\n%s", code, out)
	}
	after, _ := os.ReadFile(cfgPath)
	if string(after) != string(before) || strings.Contains(out.String(), "[y/N]") || !strings.Contains(out.String(), "autostart with each Claude Code session: off") {
		t.Fatalf("--yes changed or asked:\n%s", out)
	}
}
