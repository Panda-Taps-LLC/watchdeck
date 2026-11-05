package sessionsapi

import (
	"testing"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/activity"
)

// TestShadowRecordIsNotADenial (Plan 06 Task 6, S2): the two shadow record
// shapes (a silent observation with decision "shadow", and a printed
// sandbox ask that carries would: deny) count as decisions but never as
// denials on GET /api/sessions. Fixture A has one denial and two
// decisions of its own.
func TestShadowRecordIsNotADenial(t *testing.T) {
	root, home, p := newFixture(t)
	ts := time.Now().UTC().Format(time.RFC3339Nano)
	appendAct(t, p, activity.Record{Kind: activity.KindDecision, TS: ts, SessionID: sidA, ToolUseID: "toolu_shadow_silent", ToolName: "Write",
		Decision: activity.DecisionShadow, Shadow: true, Would: "deny", WouldReason: "tool gate files (user file): deny Write on ~/.zshrc",
		Enforcement: activity.EnforcementGate, Subject: &activity.Subject{Kind: "tool", Name: "files"}, Target: "~/.zshrc", Cwd: cwdA})
	appendAct(t, p, activity.Record{Kind: activity.KindDecision, TS: ts, SessionID: sidA, ToolUseID: "toolu_shadow_rewrite",
		Decision: "ask", Rewritten: "watchdeck run --skill web -c 'python3 get.py'", Shadow: true, Would: "deny",
		Enforcement: activity.EnforcementSandbox, Subject: &activity.Subject{Kind: "skill", Name: "web"}, Skills: []string{"web"}, Command: "python3 get.py", Cwd: cwdA})
	e := serve(t, root, home, p, envOpts{})
	for _, r := range e.list(t, "").Sessions {
		if r.ID != sidA {
			continue
		}
		if r.Decisions != 4 {
			t.Fatalf("fixture A decisions = %d, want 4 (the shadow records were not read)", r.Decisions)
		}
		if r.Denials != 1 {
			t.Errorf("fixture A denials = %d, want 1: an observed verdict counted as a denial", r.Denials)
		}
		return
	}
	t.Fatal("fixture A missing from /api/sessions")
}
