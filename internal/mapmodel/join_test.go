package mapmodel

import (
	"strings"
	"testing"

	"github.com/Panda-Taps-LLC/watchdeck/internal/activity"
)

// TestJoinByIDFixtureA: fixture A's decisions meet the transcript by
// tool_use_id, the subagent's by id too, and its runs carry write-time ids.
func TestJoinByIDFixtureA(t *testing.T) {
	s := loadA(t)
	g := Build(s, recsA(t), declaredA(t), optsA(s, ViewTimeline, false))
	for _, id := range []string{"ev:" + idMainProbe + ":skill:canary-basic", "ev:" + idSubGrep + ":skill:canary-request"} {
		d := skillDetail(t, g, id)
		if d.Joined != "decision joined by tool_use_id; run joined at write time" {
			t.Errorf("%s joined %q", id, d.Joined)
		}
	}
	// The subagent's call sits in the subagent's lane.
	n := node(g, "ev:"+idSubGrep+":tool")
	if n == nil || n.X != laneSub0 {
		t.Fatalf("subagent call event %+v", n)
	}
	tg := Build(s, recsA(t), declaredA(t), optsA(s, ViewTopology, false))
	if d := skillDetail(t, tg, "skill:canary-request"); d.CalledBy != "Explore via Bash, once" {
		t.Errorf("called_by %q", d.CalledBy)
	}
}

// TestJoinRunFallbackInOrder: two identical commands 3 s apart, runs
// without ids: activity.Join gives each run to its own decision.
func TestJoinRunFallbackInOrder(t *testing.T) {
	b := newSess().
		call(1, "main", "toolu_1", "Bash", probeNet).result(2.5, "main", "toolu_1", "ok", false).
		call(4, "main", "toolu_2", "Bash", probeNet).result(5.5, "main", "toolu_2", "ok", false)
	recs := []activity.Record{
		dec("toolu_1", 1, "allow", "canary-request", probeNet),
		run("", 2, activity.OutcomeOK, 0, "canary-request", probeNet),
		dec("toolu_2", 4, "allow", "canary-request", probeNet),
		run("", 5, activity.OutcomeFailed, 7, "canary-request", probeNet),
	}
	g := Build(b.s, recs, declaredA(t), Options{View: ViewTimeline, Now: at(3600)})
	for id, want := range map[string]string{"toolu_1": "exit 0", "toolu_2": "exit 7"} {
		d := skillDetail(t, g, "ev:"+id+":skill:canary-request")
		if d.Outcome.Label != want || !strings.Contains(d.Joined, "run joined by command match") {
			t.Errorf("%s: outcome %q joined %q, want %q", id, d.Outcome.Label, d.Joined, want)
		}
	}
}

// TestJoinDecisionByCommand: a decision without a tool_use_id meets the
// Bash call with the same command within 60 s; one 2 minutes away does not.
func TestJoinDecisionByCommand(t *testing.T) {
	b := newSess().
		call(10, "main", "toolu_near", "Bash", probeNet).result(12, "main", "toolu_near", "ok", false).
		call(300, "main", "toolu_far", "Bash", "python3 other.py")
	near := dec("", 9, "allow", "canary-request", probeNet)
	far := dec("", 180, "allow", "canary-request", "python3 other.py")
	g := Build(b.s, []activity.Record{near, far}, declaredA(t), Options{View: ViewTimeline, Now: at(3600)})
	d := skillDetail(t, g, "ev:toolu_near:skill:canary-request")
	if d.Joined != "decision joined by command match" {
		t.Errorf("near joined %q", d.Joined)
	}
	if node(g, "ev:toolu_far") == nil {
		t.Error("the far Bash call should stay a plain no-opinion call")
	}
	// The far decision shows as its own activity-only call.
	found := false
	for _, tk := range g.Ticks {
		if strings.HasPrefix(tk.ID, "rec-") && tk.Policy == PolicyAllow {
			found = true
		}
	}
	if !found {
		t.Errorf("the unmatched decision is missing from the ticks: %+v", g.Ticks)
	}
}

// TestUnmatchedRunOnSandboxOnly: a run no decision claims (no session id
// after the join) belongs to its cwd's direct pseudo-session only. There it
// counts on the sandbox node and the skill, draws no Bash edge, and is a
// "caller unknown" event in the timeline. A real session never takes it in,
// even when it falls in the session's window and cwd.
func TestUnmatchedRunOnSandboxOnly(t *testing.T) {
	b := newSess().call(1, "main", "toolu_R", "Read", "")
	r := run("", 5, activity.OutcomeOK, 0, "canary-request", probeNet)
	g := Build(b.s, []activity.Record{r}, declaredA(t), Options{Cwd: "/Users/you/proj", Now: at(3600)})
	if node(g, "sandbox") != nil || node(g, "skill:canary-request") != nil {
		t.Fatal("a real session took in a run that carries no session id")
	}

	direct := Options{SessionID: "direct:0123456789ab", Cwd: "/Users/you/proj", Now: at(3600)}
	g = Build(nil, []activity.Record{r}, declaredA(t), direct)
	sb := node(g, "sandbox")
	if sb == nil || sb.Count != 1 {
		t.Fatalf("sandbox %+v", sb)
	}
	if edge(g, "e:skill_run:tool:Bash~skill:canary-request") != nil {
		t.Error("a Bash edge for a run with no caller")
	}
	if edge(g, "e:sandbox:skill:canary-request~sandbox") == nil {
		t.Error("no skill→sandbox edge for the run")
	}
	if d := skillDetail(t, g, "skill:canary-request"); !strings.HasPrefix(d.CalledBy, "caller unknown") {
		t.Errorf("called_by %q", d.CalledBy)
	}
	direct.View = ViewTimeline
	tl := Build(nil, []activity.Record{r}, declaredA(t), direct)
	if n := node(tl, "ev:run:0"); n == nil || !strings.HasPrefix(n.Sub, "run, caller unknown") || n.X != 890 {
		t.Errorf("orphan run event %+v", n)
	}
	// A record that carries a session id never lands in a direct session.
	mine := run("toolu_R", 5, activity.OutcomeOK, 0, "canary-request", probeNet)
	direct.View = ViewTopology
	if g := Build(nil, []activity.Record{mine}, declaredA(t), direct); node(g, "sandbox") != nil {
		t.Error("a session's run was drawn in a direct pseudo-session")
	}
}

// TestOtherSessionsRecordsIgnored: records of another session never show,
// but they still take part in the run↔decision join.
func TestOtherSessionsRecordsIgnored(t *testing.T) {
	b := newSess().call(1, "main", "toolu_1", "Bash", probeNet).result(3, "main", "toolu_1", "ok", false)
	mine := dec("toolu_1", 1, "allow", "canary-request", probeNet)
	theirs := dec("toolu_9", 1.5, "allow", "canary-request", probeNet)
	theirs.SessionID = "d0000000-0000-4000-8000-00000000000d"
	r := run("", 2, activity.OutcomeOK, 0, "canary-request", probeNet) // newest candidate is theirs
	g := Build(b.s, []activity.Record{mine, theirs, r}, declaredA(t), Options{Now: at(3600)})
	if len(g.Ticks) != 1 {
		t.Fatalf("ticks %+v", g.Ticks)
	}
	if node(g, "sandbox") != nil {
		t.Error("the other session's run was drawn here")
	}
}

// TestSubagentAttributionWithoutTranscript: under --no-transcripts a
// decision's agent_id makes the subagent node and carries the call.
func TestSubagentAttributionWithoutTranscript(t *testing.T) {
	recs := recsA(t)
	g := Build(nil, recs, declaredA(t), Options{SessionID: sidA, Cwd: "/Users/you/proj", NoTranscripts: true, Now: at(3600)})
	a := node(g, "agent:a3033ade8c1d9c1a5")
	if a == nil || a.Label != "Explore" || a.Count != 1 {
		t.Fatalf("subagent from agent_id: %+v", a)
	}
	if m := node(g, "agent:main"); m == nil || m.Count != 1 || m.Detail.(*AgentDetail).Model != "model:unknown" {
		t.Errorf("main agent %+v", m)
	}
}
