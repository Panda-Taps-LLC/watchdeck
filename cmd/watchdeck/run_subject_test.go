package main

import (
	"testing"

	"github.com/Panda-Taps-LLC/watchdeck/internal/runner"
)

// TestRunSubjectFlag: --subject KIND:NAME parsing (M6.3). A malformed value
// is a usage error, an unknown kind or an unknown command subject a policy
// error (125); skill: is an alias of --skill.
func TestRunSubjectFlag(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("WATCHDECK_ACTIVITY", "off")
	cases := []struct {
		args []string
		want int
	}{
		{[]string{"--subject", "nocolon", "-c", "true"}, runner.ExitUsage},
		{[]string{"--subject", "command:", "-c", "true"}, runner.ExitUsage},
		{[]string{"--subject", "mcpx:thing", "-c", "true"}, runner.ExitPolicy},
		{[]string{"--subject", "command:a", "--subject", "command:b", "-c", "true"}, runner.ExitUsage},
		{[]string{"--subject", "command:a", "--skill", "pdf", "-c", "true"}, runner.ExitUsage},
		{[]string{"--subject", "command:nope", "-c", "true"}, runner.ExitPolicy},
		{[]string{"--subject", "skill:nope", "-c", "true"}, runner.ExitPolicy},
	}
	for _, c := range cases {
		if got := cmdRun(c.args); got != c.want {
			t.Errorf("run %v = %d, want %d", c.args, got, c.want)
		}
	}
}
