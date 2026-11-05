package sessionsapi

import (
	"path/filepath"
	"testing"

	"github.com/Panda-Taps-LLC/watchdeck/internal/activity"
)

// TestRuleHitsCounted (M6.4): rule hits on decision and rule_log records are
// counted per rule; a gate deny counts as a denial.
func TestRuleHitsCounted(t *testing.T) {
	p := filepath.Join(t.TempDir(), "activity.jsonl")
	sid := "11111111-2222-4333-8444-555555555555"
	hit := activity.RuleHit{Pack: "secrets-read", ID: "dotenv", Version: 1, Severity: "medium", Action: "log"}
	for _, r := range []activity.Record{
		{Kind: activity.KindRuleLog, SessionID: sid, Command: "cat .env", Rules: []activity.RuleHit{hit}},
		{Kind: activity.KindRuleLog, SessionID: sid, Command: "cat .env", Rules: []activity.RuleHit{hit}},
		{Kind: activity.KindDecision, SessionID: sid, ToolName: "Write", Decision: "deny", Enforcement: activity.EnforcementGate,
			Subject: &activity.Subject{Kind: "tool", Name: "files"}, Target: "~/.zshrc",
			Rules: []activity.RuleHit{{Pack: "persistence", ID: "shell-rc-write", Action: "log", Severity: "medium"}}},
	} {
		if err := activity.Append(p, r); err != nil {
			t.Fatal(err)
		}
	}
	g := newActAgg()
	g.update(p)
	s := g.sessions[sid]
	if s == nil {
		t.Fatal("no session")
	}
	if s.denials != 1 || s.lastDenial == nil || s.lastDenial.Skill != "tool files" {
		t.Fatalf("denials %d %+v", s.denials, s.lastDenial)
	}
	if h := s.ruleHits["secrets-read/dotenv"]; h == nil || h.Count != 2 || h.Action != "log" {
		t.Fatalf("dotenv hits %+v", h)
	}
	if h := s.ruleHits["persistence/shell-rc-write"]; h == nil || h.Count != 1 {
		t.Fatalf("shell-rc hits %+v", h)
	}
}
