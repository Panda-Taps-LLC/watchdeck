package mapmodel

import (
	"reflect"
	"testing"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/activity"
)

// TestGateAndRuleLogOnMap (M6.4): a gate's deny on Write, an MCP gate ask
// and a log-only rule hit become calls of the right tool with a rule-hit
// badge and the deciding subject, in both views.
func TestGateAndRuleLogOnMap(t *testing.T) {
	now := time.Date(2026, 10, 14, 9, 0, 0, 0, time.UTC)
	ts := func(s int) string { return now.Add(time.Duration(s) * time.Second).Format(time.RFC3339Nano) }
	sid := "c0000000-0000-4000-8000-00000000000c"
	recs := []activity.Record{
		{V: 1, Kind: activity.KindDecision, TS: ts(1), SessionID: sid, ToolUseID: "toolu_w", ToolName: "Write", Decision: "deny",
			Reason: "watchdeck: denied by policy: tool gate files", Enforcement: activity.EnforcementGate,
			Subject: &activity.Subject{Kind: "tool", Name: "files"}, Target: "~/.zshrc",
			Rules: []activity.RuleHit{{Pack: "persistence", ID: "shell-rc-write", Action: "log", Severity: "medium"}}},
		{V: 1, Kind: activity.KindDecision, TS: ts(2), SessionID: sid, ToolUseID: "toolu_m", ToolName: "mcp__github__create_issue", Decision: "ask",
			Enforcement: activity.EnforcementGate, Subject: &activity.Subject{Kind: "mcp", Name: "github"}},
		{V: 1, Kind: activity.KindRuleLog, TS: ts(3), SessionID: sid, ToolUseID: "toolu_b", ToolName: "Bash", Command: "cat .env",
			Enforcement: activity.EnforcementGate, Rules: []activity.RuleHit{{Pack: "secrets-read", ID: "dotenv", Action: "log", Severity: "medium"}}},
	}
	g := Build(nil, recs, nil, Options{SessionID: sid, Cwd: "/Users/you/proj", Now: now.Add(time.Hour)})
	w := node(g, "tool:Write")
	if w == nil || w.RuleHits != 1 || !reflect.DeepEqual(w.Subjects, []string{"tool files (gate)"}) {
		t.Fatalf("Write node: %+v", w)
	}
	if d, ok := w.Detail.(*ToolDetail); !ok || d.Policy.Deny != 1 || len(d.Rules) != 1 || d.Rules[0].Name != "persistence/shell-rc-write: log" {
		t.Fatalf("Write detail: %+v", w.Detail)
	}
	var mcp *Node
	for i := range g.Nodes {
		if g.Nodes[i].Kind == "mcp" {
			mcp = &g.Nodes[i]
		}
	}
	if mcp == nil || !reflect.DeepEqual(mcp.Subjects, []string{"mcp github (gate)"}) {
		t.Fatalf("mcp node: %+v", mcp)
	}
	if b := node(g, "tool:Bash"); b == nil || b.RuleHits != 1 {
		t.Fatalf("Bash node: %+v", b)
	}
	if g.Totals.Deny != 1 || g.Totals.Ask != 1 {
		t.Fatalf("totals: %+v", g.Totals)
	}

	// a Skill call an agent gate denied: one call, not two
	sk := append(append([]activity.Record(nil), recs...),
		activity.Record{V: 1, Kind: activity.KindSkillInvoked, TS: ts(4), SessionID: sid, ToolUseID: "toolu_s", ToolName: "Skill", Skill: "web"},
		activity.Record{V: 1, Kind: activity.KindDecision, TS: ts(4), SessionID: sid, ToolUseID: "toolu_s", ToolName: "Skill", Decision: "deny",
			Enforcement: activity.EnforcementGate, Subject: &activity.Subject{Kind: "agent", Name: "explorer"}})
	gs := Build(nil, sk, nil, Options{SessionID: sid, Cwd: "/Users/you/proj", Now: now.Add(time.Hour)})
	n := 0
	for _, tk := range gs.Ticks {
		if tk.ID == "toolu_s" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("gated Skill call appears %d times", n)
	}

	tl := Build(nil, recs, nil, Options{SessionID: sid, Cwd: "/Users/you/proj", Now: now.Add(time.Hour), View: ViewTimeline})
	found := false
	for _, n := range tl.Nodes {
		if n.ToolUseID == "toolu_w" {
			d, _ := n.Detail.(*EventDetail)
			found = d != nil && n.RuleHits == 1 && d.Subject == "tool files (gate)" && d.Target == "~/.zshrc" && n.Tone == "deny"
		}
	}
	if !found {
		t.Fatal("timeline Write event lacks badge, subject or target")
	}
}
