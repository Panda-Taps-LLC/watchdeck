package main

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestHookHarnessFlag: `watchdeck hook --harness codex` stores codex; the
// default stores claude-code.
func TestHookHarnessFlag(t *testing.T) {
	bin := testBinary(t)
	newTestEnv(t)
	hp, _, err := hostPaths()
	if err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, bin, args...)
		cmd.Stdin = strings.NewReader(sessionStartPayload)
		if err := cmd.Run(); err != nil {
			t.Fatal(err)
		}
	}
	run("hook")
	run("hook", "--harness", "codex")
	b, err := os.ReadFile(hp.Sessions)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) < 2 || !strings.Contains(lines[0], `"harness":"claude-code"`) || !strings.Contains(lines[len(lines)-1], `"harness":"codex"`) {
		t.Fatalf("sessions log:\n%s", b)
	}
}

func TestParseHarness(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{nil, "claude-code"},
		{[]string{"--harness", "codex"}, "codex"},
		{[]string{"--harness=codex-cli2"}, "codex-cli2"},
		{[]string{"--harness", ""}, "claude-code"},
		{[]string{"--harness="}, "claude-code"},
		{[]string{"--harness", "--other"}, "claude-code"},
		{[]string{"--harness", "Codex"}, "claude-code"},
		{[]string{"--harness", "a b"}, "claude-code"},
		{[]string{"--harness", strings.Repeat("a", 33)}, "claude-code"},
		{[]string{"--harness", strings.Repeat("a", 32)}, strings.Repeat("a", 32)},
		{[]string{"--harness"}, "claude-code"},
	} {
		if got := parseHarness(tc.args); got != tc.want {
			t.Errorf("parseHarness(%q) = %q, want %q", tc.args, got, tc.want)
		}
	}
}
