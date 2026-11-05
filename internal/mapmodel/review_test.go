package mapmodel

import (
	"fmt"
	"strings"
	"testing"

	"github.com/Panda-Taps-LLC/watchdeck/internal/activity"
)

// D1: the sandbox node's sub2 is the last run's exit and duration, even
// when the run was denied; the denial is the tone.
func TestSandboxSub2IsExitAndDuration(t *testing.T) {
	s := loadA(t)
	g := Build(s, recsA(t), declaredA(t), optsA(s, ViewTopology, false))
	sb := node(g, "sandbox")
	if sb.Sub2 != "exit 0 · 0.4 s" || sb.Tone != "deny" {
		t.Errorf("sandbox sub2 %q tone %q", sb.Sub2, sb.Tone)
	}
}

// D3: You's approvals count asks with a joined run that auto mode did not
// answer; auto-mode asks are worded "approved in auto mode".
func TestApprovalsAndAutoMode(t *testing.T) {
	b := newSess().prompt(0, "go").
		call(1, "main", "toolu_you", "Bash", probeNet).result(3, "main", "toolu_you", "ok", false).
		call(4, "main", "toolu_auto", "Bash", probeNet).result(6, "main", "toolu_auto", "ok", false).
		call(7, "main", "toolu_inf", "Bash", probeNet).result(9, "main", "toolu_inf", "ok", false)
	auto := dec("toolu_auto", 4, "ask", "canary-request", probeNet)
	auto.PermMode = "auto"
	autoRun := run("toolu_auto", 5, activity.OutcomeOK, 0, "canary-request", probeNet)
	autoRun.PermMode = "auto"
	recs := []activity.Record{
		dec("toolu_you", 1, "ask", "canary-request", probeNet), run("toolu_you", 2, activity.OutcomeOK, 0, "canary-request", probeNet),
		auto, autoRun,
		dec("toolu_inf", 7, "ask", "canary-request", probeNet), // no run: inferred approval
	}
	g := Build(b.s, recs, declaredA(t), Options{Now: at(3600)})
	if you := node(g, "you"); you.Sub != "1 prompt · 1 approval" {
		t.Errorf("you sub %q", you.Sub)
	}
	tl := Build(b.s, recs, declaredA(t), Options{View: ViewTimeline, Now: at(3600)})
	for id, want := range map[string]string{
		"toolu_you":  "ask ✓ · approved by you",
		"toolu_auto": "ask ✓ · approved in auto mode",
		"toolu_inf":  "ask ✓ (inferred) · approved by you (read from the result; no run record)",
	} {
		d := skillDetail(t, tl, "ev:"+id+":skill:canary-request")
		if !strings.HasPrefix(d.Decision, want) {
			t.Errorf("%s decision %q, want prefix %q", id, d.Decision, want)
		}
		if d.Inferred != (id == "toolu_inf") {
			t.Errorf("%s inferred %v", id, d.Inferred)
		}
	}
	// Fixture A's subagent ask ran under permission_mode auto.
	s := loadA(t)
	ga := Build(s, recsA(t), declaredA(t), optsA(s, ViewTopology, false))
	if you := node(ga, "you"); you.Sub != "1 prompt · 0 approvals" {
		t.Errorf("fixture A you sub %q", you.Sub)
	}
}

// The winning hint's stream reaches the card.
func TestOutcomeStream(t *testing.T) {
	s := loadA(t)
	g := Build(s, recsA(t), declaredA(t), optsA(s, ViewTopology, false))
	if o := skillDetail(t, g, "skill:canary-request").Outcome; o.Evidence != EvidenceHint || o.Stream != "stdout" {
		t.Errorf("outcome %+v", o)
	}
	if o := skillDetail(t, g, "skill:canary-basic").Outcome; o.Stream != "" {
		t.Errorf("result_text outcome carries a stream: %+v", o)
	}
}

// B4 note: without a Declared entry there is no fix, even when a record
// lists ungranted items (they may be stale after a grant).
func TestNoFixWithoutDeclared(t *testing.T) {
	s := loadA(t)
	g := Build(s, recsA(t), nil, optsA(s, ViewTopology, false))
	d := skillDetail(t, g, "skill:canary-request")
	if d.Fix != "" || d.Grant != nil || d.Requested[0] != "not loaded" {
		t.Errorf("fix %q grant %+v requested %v", d.Fix, d.Grant, d.Requested)
	}
}

// D5: five consecutive no-opinion Greps merge into one event that lists
// every id, and every one of the five ticks names that event.
func TestMergedEventTicks(t *testing.T) {
	b := newSess()
	var ids []string
	for i := 0; i < 5; i++ {
		id := fmt.Sprintf("toolu_g%d", i)
		ids = append(ids, id)
		b.call(float64(1+i), "main", id, "Grep", "")
	}
	b.call(10, "main", "toolu_read", "Read", "")
	g := Build(b.s, nil, nil, Options{View: ViewTimeline, Now: at(3600)})
	ev := node(g, "ev:toolu_g0")
	if ev == nil || ev.Sub != "Grep ×5" {
		t.Fatalf("merged event %+v", ev)
	}
	if d := ev.Detail.(*EventDetail); strings.Join(d.ToolUseIDs, ",") != strings.Join(ids, ",") || d.Calls != 5 {
		t.Errorf("merged detail %+v", d)
	}
	for _, tk := range g.Ticks {
		want := "ev:toolu_g0"
		if tk.ID == "toolu_read" {
			want = "ev:toolu_read"
		}
		if tk.Node != want {
			t.Errorf("tick %s node %q, want %q", tk.ID, tk.Node, want)
		}
	}
	for i := 1; i < 5; i++ {
		if node(g, "ev:"+ids[i]) != nil {
			t.Errorf("absorbed call %s has its own event", ids[i])
		}
	}
}

// D4: in the timeline no edge pill overlaps an event's label (or shape).
func TestTimelinePillsClearLabels(t *testing.T) {
	sa := loadA(t)
	cases := map[string]Graph{}
	for _, hide := range []bool{false, true} {
		cases[fmt.Sprint("A hide=", hide)] = Build(sa, recsA(t), declaredA(t), optsA(sa, ViewTimeline, hide))
	}
	sb := loadB(t)
	cases["B"] = Build(sb, nil, nil, Options{View: ViewTimeline, Now: sb.LastEvent.Add(3600e9)})
	// A session with long commands in both lanes.
	long := "python3 .claude/skills/canary-request/scripts/probe.py net --and a long tail of arguments"
	b := newSess().prompt(0, "go").
		call(1, "main", "toolu_m", "Bash", long).result(2, "main", "toolu_m", "net: DENIED(1)", false).
		sub("s1", "Explore", 3, 9, "toolu_sp").
		call(4, "s1", "toolu_s", "Bash", long).result(5, "s1", "toolu_s", "ok", false).ret(10, "toolu_sp")
	recs := []activity.Record{
		dec("toolu_m", 1, "ask", "canary-request", long), run("toolu_m", 1.5, activity.OutcomeOK, 0, "canary-request", long),
		dec("toolu_s", 4, "allow", "canary-request", long), run("toolu_s", 4.5, activity.OutcomeOK, 0, "canary-request", long, netHint()),
	}
	recs[2].AgentID = "s1"
	cases["long"] = Build(b.s, recs, declaredA(t), Options{View: ViewTimeline, Now: at(3600)})
	for name, g := range cases {
		pills := 0
		for _, e := range g.Edges {
			if e.Label == "" {
				continue
			}
			pills++
			w := textW(e.Label, charPill) + pillPad
			p := box{e.LX - w/2, e.LY - pillH/2, e.LX + w/2, e.LY + pillH/2}
			for _, n := range g.Nodes {
				if p.hits(labelBox(n)) {
					t.Errorf("%s: pill %q of %s covers the label of %s", name, e.Label, e.ID, n.ID)
				}
				if p.hits(nodeBox(n)) {
					t.Errorf("%s: pill %q of %s covers node %s", name, e.Label, e.ID, n.ID)
				}
			}
		}
		if pills == 0 {
			t.Errorf("%s: no pills checked", name)
		}
	}
}
