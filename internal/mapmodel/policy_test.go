package mapmodel

import (
	"strings"
	"testing"

	"github.com/Panda-Taps-LLC/watchdeck/internal/activity"
)

// TestPolicyPrecedence is §3.3 and cross-phase decision 3 as a table: one
// Bash call per case, the policy on its tick, the outcome on the skill card,
// and which edges are drawn.
func TestPolicyPrecedence(t *testing.T) {
	const id = "toolu_P"
	type res struct {
		text  string
		isErr bool
	}
	cases := []struct {
		name     string
		result   *res
		hook     [2]string // transcript hook attachment: decision, rewrite
		recs     []activity.Record
		live     bool
		policy   string
		label    string // outcome label on the skill card
		evidence string
		gate     string // label on Bash→skill
		sandbox  bool   // a skill→sandbox edge exists
		flags    string // u(nsandboxed) d(otted) p(ending)
	}{
		{
			name:   "allow plus failed run with a network hint is deny (hint)",
			result: &res{"Traceback ... PermissionError", true},
			recs:   []activity.Record{dec(id, 1, "allow", "canary-request", probeNet), run(id, 3, activity.OutcomeFailed, 1, "canary-request", probeNet, netHint())},
			policy: PolicyDeny, label: "DENIED network", evidence: EvidenceHint, gate: "allow", sandbox: true,
		},
		{
			name:   "ok run without hints but result text net: DENIED(1) is deny (result_text)",
			result: &res{"net: DENIED(1)", false},
			recs:   []activity.Record{dec(id, 1, "allow", "canary-request", probeNet), run(id, 3, activity.OutcomeOK, 0, "canary-request", probeNet)},
			policy: PolicyDeny, label: "DENIED network", evidence: EvidenceResultText, gate: "allow", sandbox: true,
		},
		{
			name:   "ok run with write-cwd: ALLOWED is allow",
			result: &res{"write-cwd: ALLOWED", false},
			recs:   []activity.Record{dec(id, 1, "allow", "canary-request", probeNet), run(id, 3, activity.OutcomeOK, 0, "canary-request", probeNet)},
			policy: PolicyAllow, label: "exit 0", evidence: EvidenceRun, gate: "allow", sandbox: true,
		},
		{
			name:   "an unknown-kind hint is named by a later hint's probe label",
			result: &res{"done", false},
			recs: []activity.Record{dec(id, 1, "ask", "canary-request", probeNet), run(id, 3, activity.OutcomeOK, 0, "canary-request", probeNet,
				activity.Hint{Kind: activity.HintUnknown, Line: "Traceback", Stream: "stderr"},
				activity.Hint{Kind: activity.HintUnknown, Label: "net", Line: "net: DENIED(1)", Stream: "stdout"})},
			policy: PolicyDeny, label: "DENIED network", evidence: EvidenceHint, gate: "ask ✓", sandbox: true,
		},
		{
			name:   "an unknown-kind hint without a label is just DENIED",
			result: &res{"done", false},
			recs: []activity.Record{dec(id, 1, "ask", "canary-request", probeNet), run(id, 3, activity.OutcomeOK, 0, "canary-request", probeNet,
				activity.Hint{Kind: activity.HintUnknown, Line: "something odd", Stream: "stderr"})},
			policy: PolicyDeny, label: "DENIED", evidence: EvidenceHint, gate: "ask ✓", sandbox: true,
		},
		{
			name:   "a hint beats the result text",
			result: &res{"write-home: DENIED(1)", false},
			recs:   []activity.Record{dec(id, 1, "ask", "canary-request", probeNet), run(id, 3, activity.OutcomeOK, 0, "canary-request", probeNet, netHint())},
			policy: PolicyDeny, label: "DENIED network", evidence: EvidenceHint, gate: "ask ✓", sandbox: true,
		},
		{
			name:   "a denied record beats everything and draws no sandbox edge",
			result: &res{"net: DENIED(1)", false},
			recs: []activity.Record{dec(id, 1, "allow", "canary-request", probeNet), run(id, 3, activity.OutcomeOK, 0, "canary-request", probeNet, netHint()),
				{V: 1, Kind: activity.KindDenied, TS: fmtTS(at(2)), SessionID: sidS, ToolUseID: id, ToolName: "Bash", Skills: []string{"canary-request"}, Reason: "auto mode classifier"}},
			policy: PolicyDeny, label: "BLOCKED auto mode classifier", evidence: EvidenceDenied, gate: "BLOCKED auto mode classifier", sandbox: false,
		},
		{
			name:   "low-confidence ask (no rewrite) is unsandboxed with no sandbox edge",
			result: &res{"net: DENIED(1)", false},
			recs: []activity.Record{func() activity.Record {
				r := dec(id, 1, "ask", "canary-request", probeNet)
				r.Rewritten, r.Confidence = "", "low"
				return r
			}()},
			policy: PolicyAsk, label: "ask (unsandboxed)", gate: "ask (unsandboxed)", sandbox: false, flags: "ui", // never has a run record: approval read from the result
		},
		{
			name:   "ask with a rejection result and no run is rejected",
			result: &res{"The user doesn't want to proceed with this tool use. The tool use was rejected (eg. if it was a file edit, the new_string was NOT written to the file).", true},
			recs:   []activity.Record{dec(id, 1, "ask", "canary-request", probeNet)},
			policy: PolicyAsk, label: "ask ✗", gate: "ask ✗", sandbox: false, flags: "d",
		},
		{
			name: "ask in a live session with no answer is pending",
			recs: []activity.Record{dec(id, 1, "ask", "canary-request", probeNet)},
			live: true, policy: PolicyAsk, label: "ask …", gate: "ask …", sandbox: false, flags: "p",
		},
		{
			name:   "no_sandbox outcome is deny NOT SANDBOXED exit 126",
			result: &res{"watchdeck: could not apply the sandbox", true},
			recs:   []activity.Record{dec(id, 1, "ask", "canary-request", probeNet), run(id, 3, activity.OutcomeNoSandbox, 126, "canary-request", probeNet)},
			policy: PolicyDeny, label: "NOT SANDBOXED exit 126", evidence: EvidenceRun, gate: "ask ✓", sandbox: true,
		},
		{
			name:   "policy_error outcome is deny POLICY ERROR exit 125",
			result: &res{"watchdeck: malformed manifest", true},
			recs:   []activity.Record{dec(id, 1, "allow", "canary-request", probeNet), run(id, 3, activity.OutcomePolicyError, 125, "canary-request", probeNet)},
			policy: PolicyDeny, label: "POLICY ERROR exit 125", evidence: EvidenceRun, gate: "allow", sandbox: true,
		},
		{
			name:   "a failed run without hints is a plain failure, not a denial",
			result: &res{"Traceback: ValueError", true},
			recs:   []activity.Record{dec(id, 1, "allow", "canary-request", probeNet), run(id, 3, activity.OutcomeFailed, 1, "canary-request", probeNet)},
			policy: PolicyAllow, label: "exit 1", evidence: EvidenceRun, gate: "allow", sandbox: true,
		},
		{
			name:   "hook attachment alone: ask with a rewrite and a denial in the result",
			result: &res{"net: DENIED(1)", false},
			hook:   [2]string{"ask", rewriteOf("canary-request", probeNet)},
			policy: PolicyDeny, label: "DENIED network", evidence: EvidenceResultText, gate: "ask ✓ (inferred)", flags: "i", // checked in TestHookAttachmentAloneInferredRun
		},
		{
			name:   "hook attachment alone: allow with a quiet result",
			result: &res{"done", false},
			hook:   [2]string{"allow", rewriteOf("canary-request", probeNet)},
			policy: PolicyAllow, label: "ran", evidence: EvidenceHook, gate: "allow",
		},
		{
			name:   "an activity ask with a result but no joined run is approved, marked inferred",
			result: &res{"net: DENIED(1)", false},
			recs:   []activity.Record{dec(id, 1, "ask", "canary-request", probeNet)},
			policy: PolicyAsk, label: "ask ✓ (inferred)", gate: "ask ✓ (inferred)", sandbox: false, flags: "i",
		},
		{
			name:   "an activity decision beats the hook attachment",
			result: &res{"done", false},
			hook:   [2]string{"allow", rewriteOf("canary-request", probeNet)},
			recs:   []activity.Record{dec(id, 1, "ask", "canary-request", probeNet), run(id, 3, activity.OutcomeOK, 0, "canary-request", probeNet)},
			policy: PolicyAsk, label: "exit 0", evidence: EvidenceRun, gate: "ask ✓", sandbox: true,
		},
		{
			name:   "no record and no attachment is none",
			result: &res{"net: DENIED(1)", false},
			policy: PolicyNone,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := newSess().call(1, "main", id, "Bash", probeNet)
			if tc.hook[0] != "" {
				b.hook(id, tc.hook[0], tc.hook[1])
			}
			if tc.result != nil {
				b.result(4, "main", id, tc.result.text, tc.result.isErr)
			}
			o := Options{Cwd: "/Users/you/proj", Now: at(3600)}
			if tc.live {
				o.Now = at(5)
			}
			g := Build(b.s, tc.recs, declaredA(t), o)
			if got := g.Ticks[0].Policy; got != tc.policy {
				t.Fatalf("policy %q, want %q", got, tc.policy)
			}
			if tc.policy == PolicyNone || len(tc.recs) == 0 {
				return // no record names a skill: the tick carries the policy, there is no skill node
			}
			d := skillDetail(t, g, "skill:canary-request")
			if d.Outcome.Label != tc.label || d.Outcome.Evidence != tc.evidence {
				t.Errorf("outcome %q evidence %q, want %q %q", d.Outcome.Label, d.Outcome.Evidence, tc.label, tc.evidence)
			}
			gate := edge(g, "e:skill_run:tool:Bash~skill:canary-request")
			if gate == nil || gate.Label != tc.gate {
				t.Fatalf("gate edge %+v, want label %q", gate, tc.gate)
			}
			flags := ""
			if gate.Unsandboxed {
				flags += "u"
			}
			if gate.Dotted {
				flags += "d"
			}
			if gate.Pending {
				flags += "p"
			}
			if gate.Inferred {
				flags += "i"
			}
			if flags != tc.flags {
				t.Errorf("gate flags %q, want %q", flags, tc.flags)
			}
			sb := edge(g, "e:sandbox:skill:canary-request~sandbox")
			if (sb != nil) != tc.sandbox {
				t.Errorf("sandbox edge present=%v, want %v", sb != nil, tc.sandbox)
			}
			if sb != nil && tc.policy == PolicyDeny && (sb.Cut == nil || !sb.Flow || sb.Tone != "deny") {
				t.Errorf("denied sandbox edge without cut/flow: %+v", sb)
			}
		})
	}
}

// TestHookAttachmentAloneInferredRun: with no activity at all, a rewritten
// call whose result came back still reaches the sandbox node (the run
// record is missing, the transcript shows it ran).
func TestHookAttachmentAloneInferredRun(t *testing.T) {
	const id = "toolu_H"
	b := newSess().call(1, "main", id, "Bash", probeNet).hook(id, "ask", rewriteOf("canary-request", probeNet)).result(3, "main", id, "net: DENIED(1)", false)
	g := Build(b.s, nil, nil, Options{Now: at(3600)})
	if g.Ticks[0].Policy != PolicyDeny {
		t.Fatalf("policy %s", g.Ticks[0].Policy)
	}
	// The skill comes from the rewrite; the cut from the result text.
	d := skillDetail(t, g, "skill:canary-request")
	if d.Outcome.Label != "DENIED network" || d.Outcome.Evidence != EvidenceResultText {
		t.Errorf("outcome %+v", d.Outcome)
	}
	if d.Inferred != true {
		t.Error("skill detail not marked inferred")
	}
	if e := edge(g, "e:skill_run:tool:Bash~skill:canary-request"); e == nil || e.Label != "ask ✓ (inferred)" || !e.Inferred {
		t.Errorf("gate edge %+v", e)
	}
	if e := edge(g, "e:sandbox:skill:canary-request~sandbox"); e == nil || e.Cut == nil {
		t.Errorf("sandbox edge %+v", e)
	}
	if sb := node(g, "sandbox"); sb == nil || sb.Count != 1 || sb.Sub != "OS sandbox · 1 run" {
		t.Errorf("sandbox %+v", sb)
	}
}

func TestRewriteSkills(t *testing.T) {
	for in, want := range map[string]string{
		"watchdeck run --skill a -c 'x'":                     "a",
		"watchdeck run --skill a --skill b -c 'x --skill c'": "a,b",
		"/opt/bin/watchdeck run --skill=a -c 'x'":            "a",
		"watchdeck run --other a -c 'x'":                     "",
		"python3 x.py":                                       "",
		"watchdeck run --skill a":                            "",
	} {
		if got := strings.Join(rewriteSkills(in), ","); got != want {
			t.Errorf("%q → %q, want %q", in, got, want)
		}
	}
}

func TestScanResult(t *testing.T) {
	for _, tc := range []struct {
		text, label    string
		tried, reached int
	}{
		{"net: DENIED(1)", "DENIED network", 1, 0},
		{"write-home: DENIED(13)\nwrite-cwd: ALLOWED", "DENIED write", 1, 1},
		{"read-secret: DENIED(1)", "DENIED read", 1, 0},
		{"subprocess: DENIED(1)", "DENIED exec", 1, 0},
		{"custom: DENIED(1)", "DENIED (script reported)", 1, 0},
		{"PermissionError: [Errno 1] Operation not permitted", "DENIED (script reported)", 1, 0},
		{"net: ALLOWED", "", 0, 1},
		{"all good", "", 0, 0},
	} {
		label, tried, reached := scanResult(tc.text)
		if label != tc.label || len(tried) != tc.tried || len(reached) != tc.reached {
			t.Errorf("%q: %q %v %v", tc.text, label, tried, reached)
		}
	}
}

func TestLiveWindow(t *testing.T) {
	b := newSess().call(1, "main", "toolu_L", "Read", "")
	if g := Build(b.s, nil, nil, Options{Now: at(1 + 29)}); !g.Session.Live {
		t.Error("29 s after the last event should be live")
	}
	if g := Build(b.s, nil, nil, Options{Now: at(1).Add(LiveWindow)}); g.Session.Live {
		t.Error("30 s after the last event should not be live")
	}
	if g := Build(b.s, nil, nil, Options{}); g.Session.Live {
		t.Error("zero Now is never live")
	}
}
