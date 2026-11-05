//go:build darwin

package runner

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Panda-Taps-LLC/watchdeck/internal/activity"
)

// TestMCPRefusesHomeCwd: a server whose working directory is the home
// directory does not start (its cwd write grant would cover all of home)
// unless the wrapped command carries --allow-home-cwd.
func TestMCPRefusesHomeCwd(t *testing.T) {
	f := newFixture(t)
	f.writePolicy(t, launchPolicy)
	f.env.Cwd = f.home
	marker := filepath.Join(f.home, "ran")
	var errb bytes.Buffer
	code := RunMCP(context.Background(), MCPOptions{Server: "canary", Argv: []string{"/usr/bin/touch", marker}, Env: f.env, Environ: f.environ,
		Stdin: strings.NewReader(""), Stdout: &bytes.Buffer{}, Stderr: &errb, ActivityPath: f.activity})
	if code != ExitPolicy || !strings.Contains(errb.String(), "--allow-home-cwd") {
		t.Fatalf("exit %d: %q", code, errb.String())
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the server ran")
	}
	if r := f.lastRun(t); r.Outcome != activity.OutcomePolicyError {
		t.Errorf("record %+v", r)
	}
	code = RunMCP(context.Background(), MCPOptions{Server: "canary", Argv: []string{"/usr/bin/touch", marker}, Env: f.env, Environ: f.environ,
		Stdin: strings.NewReader(""), Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}, ActivityPath: f.activity, AllowHomeCwd: true})
	if code != 0 {
		t.Fatalf("allowed: exit %d", code)
	}
	// The run record lists the full deny set, the extra denies included.
	r := f.lastRun(t)
	if r.Effective == nil || !slices.Contains(r.Effective.Deny, filepath.Join(f.home, ".claude.json")) {
		t.Errorf("record deny list lacks ~/.claude.json: %+v", r.Effective)
	}
}
