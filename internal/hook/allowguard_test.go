package hook

import (
	"strings"
	"testing"
)

// TestModelTypedAllowAsks: a `watchdeck allow` in a Bash call always asks
// (review 2026-10-14). The former /watchdeck:allow slash command's (removed 2026-10-18)
// allowed-tools pre-approval stayed active for the model's reply turn, so without this a
// model could widen any grant with no prompt.
func TestModelTypedAllowAsks(t *testing.T) {
	f := newFx(t)
	for _, cmd := range []string{
		"watchdeck allow '*' --network all --auto",
		"watchdeck allow pdf --write ~/Library/LaunchAgents",
		"watchdeck   allow pdf --show",
		"/usr/local/bin/watchdeck allow pdf --auto",
		`watch''deck all\ow pdf --auto`,
		"true && watchdeck allow pdf --auto",
	} {
		out := Decide(f.in(cmd), f.env)
		if got := decisionOf(out); got != Ask {
			t.Errorf("%s: %s, want ask (%+v)", cmd, got, out)
			continue
		}
		if !strings.Contains(out.HookSpecificOutput.PermissionDecisionReason, "watchdeck allow") {
			t.Errorf("%s: reason %q", cmd, out.HookSpecificOutput.PermissionDecisionReason)
		}
		if out.HookSpecificOutput.UpdatedInput != nil {
			t.Errorf("%s: rewrote a model-typed allow", cmd)
		}
	}
	for _, cmd := range []string{"watchdeck status", "echo allow", "watchdeck doctor"} {
		if got := decisionOf(Decide(f.in(cmd), f.env)); got != "none" {
			t.Errorf("%s: %s, want none", cmd, got)
		}
	}
}
