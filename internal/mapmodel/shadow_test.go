package mapmodel

import (
	"strings"
	"testing"

	"github.com/Panda-Taps-LLC/watchdeck/internal/activity"
	"github.com/Panda-Taps-LLC/watchdeck/internal/transcript"
)

// TestMapShadowLabel (Plan 06 Task 6, S2): an observed verdict is labelled,
// never counted. A Write call joined to a silent shadow record gets the
// gate label "observed: would deny" in grey, no policy, no hook authority,
// and BlockedCalls stays 0; a skill call whose rewrite also carried a
// shadowed gate keeps its own gate label with " · observed: would deny"
// after it, on the skill_run edge.
func TestMapShadowLabel(t *testing.T) {
	silent := activity.Record{V: 1, Kind: activity.KindDecision, TS: fmtTS(at(1)), SessionID: sidS, ToolUseID: "toolu_w", ToolName: "Write",
		Cwd: "/Users/you/proj", Decision: activity.DecisionShadow, Shadow: true, Would: "deny",
		WouldReason: "tool gate files (user file): deny Write on ~/.zshrc", Enforcement: activity.EnforcementGate,
		Subject: &activity.Subject{Kind: "tool", Name: "files"}, Target: "~/.zshrc"}
	b := newSess().call(1, transcript.MainAgentID, "toolu_w", "Write", "").result(1.2, transcript.MainAgentID, "toolu_w", "File created", false)

	v := judge(&call{dec: &silent}, false)
	if v.gate != "observed: would deny" || v.gateTone != "grey" || v.gatePolicy != "" || v.policy == PolicyDeny || v.blocked {
		t.Errorf("silent verdict = gate %q tone %q gatePolicy %q policy %q blocked %v", v.gate, v.gateTone, v.gatePolicy, v.policy, v.blocked)
	}

	for _, view := range []string{ViewTopology, ViewTimeline} {
		g := Build(b.s, []activity.Record{silent}, nil, optsA(b.s, view, false))
		if g.Totals.BlockedCalls != 0 || g.Totals.Deny != 0 || g.Totals.Ask != 0 {
			t.Errorf("%s: totals %+v: an observed verdict was counted", view, g.Totals)
		}
		if g.Totals.ByAuthority[AuthorityHook] != 0 {
			t.Errorf("%s: authority hook on an observed call: %+v", view, g.Totals.ByAuthority)
		}
		if view != ViewTimeline {
			continue
		}
		found := false
		for _, n := range g.Nodes {
			if n.ToolUseID != "toolu_w" || n.Kind != "tool" {
				continue
			}
			found = true
			d, _ := n.Detail.(*EventDetail)
			if d == nil || d.Decision != "observed: would deny" || n.Tone == "deny" || n.Authority == AuthorityHook {
				t.Errorf("timeline Write event: tone %q authority %q detail %+v", n.Tone, n.Authority, d)
			}
			// The canvas shows the observation without a click: the node's
			// sub-line, beside the authority word the dashboard prints.
			if !strings.Contains(n.Sub, "observed: would deny") {
				t.Errorf("timeline Write event sub %q lacks the observation", n.Sub)
			}
		}
		if !found {
			t.Error("timeline has no Write event")
		}
	}

	// The same call enforced (a real gate deny): its sub-line has no
	// observation, and it is a blocked call.
	enforced := silent
	enforced.Decision, enforced.Shadow, enforced.Would, enforced.WouldReason = "deny", false, "", ""
	ge := Build(b.s, []activity.Record{enforced}, nil, optsA(b.s, ViewTimeline, false))
	for _, n := range ge.Nodes {
		if n.ToolUseID == "toolu_w" && n.Kind == "tool" && strings.Contains(n.Sub, "observed") {
			t.Errorf("enforced Write event sub %q carries an observation", n.Sub)
		}
	}
	if ge.Totals.BlockedCalls != 1 {
		t.Errorf("enforced deny BlockedCalls = %d, want 1", ge.Totals.BlockedCalls)
	}

	// A shadowed ask the person approved: the approval belongs to the ask,
	// the observation comes last.
	ap := dec("toolu_a", 2, "ask", "canary-request", probeNet)
	ap.Shadow, ap.Would, ap.Enforcement = true, "deny", activity.EnforcementSandbox
	ran := run("toolu_a", 3, "ok", 0, "canary-request", probeNet)
	ca := &call{dec: &ap, run: &ran}
	ca.v = judge(ca, false)
	if got, want := decisionWords(ca), "ask ✓ · approved by you · observed: would deny"; got != want {
		t.Errorf("decisionWords = %q, want %q", got, want)
	}

	// A skill call whose sandbox ask also carried a shadowed gate deny.
	rw := dec("toolu_s", 2, "ask", "canary-request", probeNet)
	rw.Shadow, rw.Would, rw.Enforcement = true, "deny", activity.EnforcementSandbox
	sb := newSess().call(2, transcript.MainAgentID, "toolu_s", "Bash", probeNet)
	g := Build(sb.s, []activity.Record{rw}, declaredA(t), optsA(sb.s, ViewTopology, false))
	var label, tone string
	for _, e := range g.Edges {
		if e.Kind == "skill_run" {
			label, tone = e.Label, e.Tone
		}
	}
	if !strings.HasSuffix(label, " · observed: would deny") || !strings.HasPrefix(label, "ask") || tone != "ask" {
		t.Errorf("skill_run edge label %q tone %q, want the ask label with the observed suffix", label, tone)
	}
	if g.Totals.BlockedCalls != 0 || g.Totals.Deny != 0 {
		t.Errorf("shadowed rewrite totals %+v", g.Totals)
	}
}
