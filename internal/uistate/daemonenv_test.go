package uistate

import (
	"slices"
	"testing"
)

func TestDaemonEnvAllowlist(t *testing.T) {
	in := []string{
		"PATH=/usr/bin", "HOME=/h", "LANG=C", "LC_ALL=C", "XDG_STATE_HOME=/s",
		"WATCHDECK_ACTIVITY=/a", "CLAUDE_CONFIG_DIR=/c", "BROWSER=x", "TZ=UTC",
		"ANTHROPIC_API_KEY=fake", "CLAUDE_PROJECT_DIR=/p", "CLAUDE_ENV_FILE=/e", "AWS_SECRET_ACCESS_KEY=fake", "garbage",
	}
	if e := DaemonEnv([]string{"ANTHROPIC_API_KEY=fake"}); e == nil || len(e) != 0 {
		t.Fatalf("no allowlisted vars must give an empty, non-nil env, got %#v", e)
	}
	got := DaemonEnv(in)
	for _, want := range in[:9] {
		if !slices.Contains(got, want) {
			t.Errorf("dropped %q", want)
		}
	}
	for _, bad := range in[9:] {
		if slices.Contains(got, bad) {
			t.Errorf("kept %q", bad)
		}
	}
}
