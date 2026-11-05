package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Panda-Taps-LLC/watchdeck/internal/activity"
	"github.com/Panda-Taps-LLC/watchdeck/internal/mcpconfig"
	"github.com/Panda-Taps-LLC/watchdeck/internal/policy"
)

// TestMCPWrapRollsBackWhenPolicySaveFails: the policy subject is saved
// after the config; if that save fails the config change and the wrap
// record are undone.
func TestMCPWrapRollsBackWhenPolicySaveFails(t *testing.T) {
	e, cfg, golden, bin := mcpTestEnv(t)
	old := savePolicy
	savePolicy = func(string, policy.File) (string, error) { return "", errors.New("disk full (test)") }
	defer func() { savePolicy = old }()
	code, _, errs := call(t, mcpCmd, "wrap", "canary", "--yes", "--binary", bin)
	if code != 2 || !strings.Contains(errs, "rolled back") {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if b, _ := os.ReadFile(cfg); !bytes.Equal(b, golden) {
		t.Error("config not rolled back")
	}
	st, _ := mcpconfig.LoadState(filepath.Join(e.state, "watchdeck", mcpconfig.StateFile))
	if len(st.Servers) != 0 {
		t.Errorf("wrap record left: %+v", st)
	}
}

// TestMCPWrapAllowHomeCwd writes the flag into the wrapped args.
func TestMCPWrapAllowHomeCwd(t *testing.T) {
	_, cfg, _, bin := mcpTestEnv(t)
	if code, _, errs := call(t, mcpCmd, "wrap", "canary", "--yes", "--allow-home-cwd", "--binary", bin); code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	data, _ := os.ReadFile(cfg)
	s, _ := mcpconfig.Find(data, "canary")
	if !s.Wrapped() || strings.Join(s.Args[:5], " ") != "run --subject mcp:canary --allow-home-cwd --" {
		t.Errorf("args %q", s.Args)
	}
}

// TestMCPRelativeClaudeConfigDirRefused: a relative CLAUDE_CONFIG_DIR is
// refused by the mcp commands (and by run, see runner.runDeny).
func TestMCPRelativeClaudeConfigDirRefused(t *testing.T) {
	_, _, _, bin := mcpTestEnv(t)
	t.Setenv("CLAUDE_CONFIG_DIR", "relative/dir")
	if code, _, errs := call(t, mcpCmd, "wrap", "canary", "--yes", "--binary", bin); code != 2 || !strings.Contains(errs, "not an absolute path") {
		t.Errorf("exit %d: %s", code, errs)
	}
}

// TestRunMCPUsageIsRecorded: a malformed run --subject mcp: line still
// leaves a usage record.
func TestRunMCPUsageIsRecorded(t *testing.T) {
	e := newTestEnv(t)
	if code := cmdRun([]string{"--subject", "mcp:x", "--"}); code != 3 {
		t.Fatalf("exit %d", code)
	}
	res, err := activity.Read(e.activityPath(), activity.ReadOptions{})
	if err != nil || len(res.Records) != 1 || res.Records[0].Outcome != activity.OutcomeUsage {
		t.Fatalf("records %+v %v", res.Records, err)
	}
}
