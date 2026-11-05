package mapmodel

import (
	"strings"
	"testing"

	"github.com/Panda-Taps-LLC/watchdeck/internal/activity"
	"github.com/Panda-Taps-LLC/watchdeck/internal/transcript"
)

const sidDeny = "d484a6af-2106-45c4-9d15-1c2212b76809"

func loadDeny(t *testing.T) *transcript.Session {
	return loadFixture(t, "e2e-deny", "-Users-you-proj", sidDeny)
}

// callsOf assembles a session's calls without laying anything out.
func callsOf(t *testing.T, s *transcript.Session, recs []activity.Record) []*call {
	t.Helper()
	m := assemble(s, recs, optsA(s, ViewTopology, false))
	m.judgeAll()
	return m.calls
}

// TestAuthorityOfFixtureDeny: the real capture's four denial shapes, built
// with no activity records (watchdeck's hook was not installed).
func TestAuthorityOfFixtureDeny(t *testing.T) {
	s := loadDeny(t)
	calls := callsOf(t, s, nil)
	want := []struct {
		tool, key, authority string
		rejected             bool
	}{
		{"Bash", "rule-deny-marker", AuthorityDenyRule, true},
		{"Read", "SECRET.md", AuthorityDenyRule, true},
		{"Bash", "classifier-deny-marker", AuthorityClassifier, true},
		{"Bash", "echo done", AuthorityAuto, false},
	}
	if len(calls) != len(want) {
		t.Fatalf("got %d calls, want %d", len(calls), len(want))
	}
	for _, w := range want {
		var c *call
		for _, x := range calls {
			if x.tool == w.tool && (strings.Contains(x.command, w.key) || strings.Contains(x.path, w.key)) {
				c = x
			}
		}
		if c == nil {
			t.Fatalf("no %s call for %q", w.tool, w.key)
		}
		a, rej := authorityOf(c)
		if a != w.authority || rej != w.rejected {
			t.Errorf("%s %q: authorityOf = %q, %v; want %q, %v", w.tool, w.key, a, rej, w.authority, w.rejected)
		}
		if c.v.authority != w.authority {
			t.Errorf("%s %q: verdict authority = %q, want %q", w.tool, w.key, c.v.authority, w.authority)
		}
	}
	g := Build(s, nil, nil, optsA(s, ViewTopology, false))
	by := map[string]int{}
	for _, tk := range g.Ticks {
		if tk.Authority == "" {
			t.Errorf("tick %s has no authority", tk.ID)
		}
		by[tk.Authority]++
	}
	if by[AuthorityDenyRule] != 2 || by[AuthorityClassifier] != 1 || by[AuthorityAuto] != 1 {
		t.Errorf("tick authorities = %v", by)
	}
	if got := g.Totals.ByAuthority; got[AuthorityDenyRule] != 2 || got[AuthorityClassifier] != 1 || got[AuthorityAuto] != 1 || len(got) != 3 {
		t.Errorf("Totals.ByAuthority = %v", got)
	}
}

// TestAuthorityOfFixtureCanary: fixture A with its activity log. The
// fixture's Read and Grep results carry accept/config/rule (allow_rule);
// the Agent spawn and the subagent handback carry accept/config/classifier
// (auto). Both skill Bash calls were refused by the sandbox at run time
// (the main one by its result text, the subagent's by a run hint), which
// outranks the hook's decision.
func TestAuthorityOfFixtureCanary(t *testing.T) {
	s := loadA(t)
	want := map[string]string{
		idMainProbe:                      AuthoritySandbox,
		"toolu_01PEzFa65hdCYERmSZVb9Yej": AuthorityAllowRule, // Read
		"toolu_01FZL82cF5JL9ZMVa4U5Psu4": AuthorityAuto,      // Agent
		"toolu_01ArKPuK8AHT3nxPPygzf3GY": AuthorityAllowRule, // Grep
		idSubGrep:                        AuthoritySandbox,
		"toolu_01H9WTdMTLtDoVTWanw2vecL": AuthorityAuto, // SubagentHandback
	}
	for _, view := range []string{ViewTopology, ViewTimeline} {
		g := Build(s, recsA(t), declaredA(t), optsA(s, view, false))
		if len(g.Ticks) != len(want) {
			t.Fatalf("%s: %d ticks, want %d", view, len(g.Ticks), len(want))
		}
		for _, tk := range g.Ticks {
			if tk.Authority != want[tk.ID] {
				t.Errorf("%s: %s %s authority = %q, want %q", view, tk.Tool, tk.ID, tk.Authority, want[tk.ID])
			}
			if tk.Authority == AuthorityNone {
				t.Errorf("%s: %s %s has a result but authority none", view, tk.Tool, tk.ID)
			}
		}
	}
	// Without the sandbox's refusal the skill call is the hook's.
	for _, c := range callsOf(t, s, recsA(t)) {
		if c.id != idMainProbe {
			continue
		}
		c.res = &resultView{text: "net: ALLOWED"}
		if a, _ := authorityOf(c); a != AuthorityHook {
			t.Errorf("main probe without a sandbox denial: %q, want hook", a)
		}
	}
}

// TestAuthorityPrecedence: first match wins, in the brief's order.
func TestAuthorityPrecedence(t *testing.T) {
	const id = "toolu_A"
	errRes := &resultView{text: "", isError: true}
	cases := []struct {
		name      string
		c         call
		authority string
		rejected  bool
	}{
		{"denied record is the classifier",
			call{denied: &activity.Record{Kind: activity.KindDenied, ToolUseID: id}, authority: transcript.Authority{Decision: "accept", Source: "config", ReasonType: "rule"}},
			AuthorityClassifier, true},
		{"hook deny is the hook",
			call{dec: &activity.Record{Kind: activity.KindDecision, Decision: "deny"}, authority: transcript.Authority{Decision: "reject", Source: "config", ReasonType: "subcommandResults", DenialKind: "permission-rule"}},
			AuthorityHook, true},
		{"hook ask is the hook",
			call{hookDecision: "ask", res: &resultView{text: "ok"}, authority: transcript.Authority{Decision: "accept", Source: "user", ReasonType: "prompt"}},
			AuthorityHook, false},
		{"hook allow with a rewrite is the hook",
			call{dec: &activity.Record{Kind: activity.KindDecision, Decision: "allow", Rewritten: "watchdeck run --skill x -c 'y'"}, authority: transcript.Authority{Decision: "accept", Source: "hook", ReasonType: "hook"}},
			AuthorityHook, false},
		{"reject config subcommandResults is a deny rule",
			call{authority: transcript.Authority{Decision: "reject", Source: "config", ReasonType: "subcommandResults"}, res: errRes},
			AuthorityDenyRule, true},
		{"permission-rule denial kind is a deny rule",
			call{authority: transcript.Authority{Decision: "reject", DenialKind: "permission-rule"}, res: errRes},
			AuthorityDenyRule, true},
		{"automode-blocked is the classifier",
			call{authority: transcript.Authority{Decision: "reject", Source: "config", ReasonType: "classifier", DenialKind: "automode-blocked"}, res: errRes},
			AuthorityClassifier, true},
		{"reject classifier without a denial kind is the classifier",
			call{authority: transcript.Authority{Decision: "reject", Source: "config", ReasonType: "classifier"}, res: errRes},
			AuthorityClassifier, true},
		{"reject user prompt is the user, rejected",
			call{authority: transcript.Authority{Decision: "reject", Source: "user", ReasonType: "prompt"}, res: errRes},
			AuthorityUser, true},
		{"accept user prompt is the user",
			call{authority: transcript.Authority{Decision: "accept", Source: "user", ReasonType: "prompt"}, res: &resultView{}},
			AuthorityUser, false},
		{"accept config rule is an allow rule",
			call{authority: transcript.Authority{Decision: "accept", Source: "config", ReasonType: "rule"}, res: &resultView{}},
			AuthorityAllowRule, false},
		{"accept config classifier is auto",
			call{authority: transcript.Authority{Decision: "accept", Source: "config", ReasonType: "classifier"}, res: &resultView{}},
			AuthorityAuto, false},
		{"an accepted call whose tool failed is still auto",
			call{authority: transcript.Authority{Decision: "accept", Source: "config", ReasonType: "classifier"}, res: errRes, errText: "file not found"},
			AuthorityAuto, false},
		{"error text naming the permission settings is a deny rule",
			call{res: errRes, errText: "File is in a directory that is denied by your permission settings."},
			AuthorityDenyRule, true},
		{"an error with no decision fields is blocked, reason unknown",
			call{res: errRes, errText: "anything"},
			AuthorityBlocked, false},
		// final review, 2026-10-19
		{"a hook decision with no watchdeck record is the hook",
			call{authority: transcript.Authority{Decision: "accept", Source: "hook", ReasonType: "hook"}, res: &resultView{}},
			AuthorityHook, false},
		{"an unrecognised reject is blocked, rejected",
			call{authority: transcript.Authority{Decision: "reject", Source: "config", ReasonType: "somethingNew"}, res: errRes},
			AuthorityBlocked, true},
		{"an accept with an unknown reason type that failed is not blocked (none: no accept label fits)",
			call{authority: transcript.Authority{Decision: "accept", Source: "config", ReasonType: "somethingNew"}, res: errRes, errText: "file not found"},
			AuthorityNone, false},
		{"a plain failed command with no decision fields is none, not blocked",
			call{res: errRes, errText: "Exit code 1\nls: x: No such file or directory"},
			AuthorityNone, false},
		{"a sandbox denial on the run outranks the hook",
			call{dec: &activity.Record{Kind: activity.KindDecision, Decision: "allow", Rewritten: "watchdeck run --skill canary-request -c 'x'"},
				run: &activity.Record{Kind: activity.KindRun, Outcome: activity.OutcomeFailed, Exit: intp(1), Hints: []activity.Hint{netHint()}}},
			AuthoritySandbox, false},
		{"result text DENIED on a run outranks the hook",
			call{dec: &activity.Record{Kind: activity.KindDecision, Decision: "ask", Rewritten: "watchdeck run --skill canary-request -c 'x'"},
				run: &activity.Record{Kind: activity.KindRun, Outcome: activity.OutcomeOK, Exit: intp(0)}, res: &resultView{text: "net: DENIED(1)"}},
			AuthoritySandbox, false},
		{"nothing is none",
			call{},
			AuthorityNone, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := tc.c
			c.id, c.tool = id, "Bash"
			a, rej := authorityOf(&c)
			if a != tc.authority || rej != tc.rejected {
				t.Errorf("authorityOf = %q, %v; want %q, %v", a, rej, tc.authority, tc.rejected)
			}
			if v := judge(&c, false); v.authority != tc.authority {
				t.Errorf("judge authority = %q, want %q", v.authority, tc.authority)
			}
		})
	}
}

// TestIsRejectionIsFallbackOnly: the result text guess is used only when
// the transcript recorded no verdict.
func TestIsRejectionIsFallbackOnly(t *testing.T) {
	text := "The user doesn't want to proceed with this tool use. The tool use was rejected."
	base := call{id: "toolu_R", tool: "Bash", hookDecision: "ask", res: &resultView{text: text, isError: true}}

	known := base
	known.authority = transcript.Authority{Decision: "accept", Source: "config", ReasonType: "classifier"}
	if _, rej := authorityOf(&known); rej {
		t.Error("authorityOf: an accepted call read as rejected from its result text")
	}
	if v := judge(&known, false); v.rejected {
		t.Errorf("judge: an accepted call is rejected (gate %q)", v.gate)
	}

	unknown := base
	if _, rej := authorityOf(&unknown); !rej {
		t.Error("authorityOf: with no verdict the result text is not used")
	}
	if v := judge(&unknown, false); !v.rejected || v.gate != "ask ✗" {
		t.Errorf("judge without a verdict: rejected %v gate %q", v.rejected, v.gate)
	}
}

// TestTimelineRowNamesAuthority: a row watchdeck did not check names who
// decided it in Node.Authority (the dashboard prints the word; since Plan
// 04 Task 10 the row's text no longer carries the raw word), and calls
// decided by different authorities are never merged.
func TestTimelineRowNamesAuthority(t *testing.T) {
	s := loadDeny(t)
	g := Build(s, nil, nil, optsA(s, ViewTimeline, false))
	got := map[string]string{} // row text → authority
	for _, n := range g.Nodes {
		if n.Event && n.Kind == "tool" {
			got[n.Sub] = n.Authority
		}
	}
	for sub, w := range map[string]string{
		"echo rule-deny-marker":       AuthorityDenyRule,
		"SECRET.md":                   AuthorityDenyRule,
		"echo classifier-deny-marker": AuthorityClassifier,
		"echo done":                   AuthorityAuto,
	} {
		if a, ok := got[sub]; !ok || a != w {
			t.Errorf("row %q: authority %q (present %v), want %q; rows %v", sub, a, ok, w, got)
		}
	}
	a := &call{agent: "main", tool: "Read", v: verdict{policy: PolicyNone, authority: AuthorityAllowRule}}
	b := &call{agent: "main", tool: "Read", v: verdict{policy: PolicyNone, authority: AuthorityBlocked}}
	if mergeable(a, b) {
		t.Error("an allow_rule Read merged with a blocked Read")
	}
}

// TestTotalsBlockedCalls: blocked_calls counts the calls refused before
// they ran by a native deny rule, the auto-mode check or watchdeck's hook.
// The deny capture has no activity records, so its policy counts (and so
// denials) are all zero while two deny-rule refusals and one auto-mode
// block stand; the map header reads blocked_calls, so it never says
// "denied 0" beside "Deny rule 2" (Plan 05 Task 6, 2026-10-20).
func TestTotalsBlockedCalls(t *testing.T) {
	s := loadDeny(t)
	for _, view := range []string{ViewTopology, ViewTimeline} {
		g := Build(s, nil, nil, optsA(s, view, false))
		tt := g.Totals
		if tt.Allow != 0 || tt.Ask != 0 || tt.Deny != 0 || tt.Denials != 0 {
			t.Errorf("%s: allow/ask/deny/denials = %d/%d/%d/%d, want all 0 (policy counts unchanged)", view, tt.Allow, tt.Ask, tt.Deny, tt.Denials)
		}
		if tt.BlockedCalls != 3 {
			t.Errorf("%s: BlockedCalls = %d, want 3 (2 deny rule + 1 auto-mode block)", view, tt.BlockedCalls)
		}
	}
}

// TestBlockedCallsSources: a hook deny counts once (authority hook, policy
// deny); a call with a PermissionDenied record counts once (authority
// classifier, policy deny); a sandbox refusal and a hook ask do not count.
func TestBlockedCallsSources(t *testing.T) {
	m := &model{calls: []*call{
		{v: verdict{authority: AuthorityDenyRule}},
		{v: verdict{authority: AuthorityClassifier, policy: PolicyDeny}},
		{v: verdict{authority: AuthorityHook, policy: PolicyDeny}},
		{v: verdict{authority: AuthorityHook, policy: PolicyAsk}},
		{v: verdict{authority: AuthoritySandbox, policy: PolicyDeny}},
		{v: verdict{authority: AuthorityAuto, policy: PolicyAllow}},
		{v: verdict{authority: AuthorityUser, authRejected: true}},    // a person's "No": counted
		{v: verdict{authority: AuthorityUser}},                        // a person's yes: not counted
		{v: verdict{authority: AuthorityBlocked, authRejected: true}}, // an unrecognised rejection: counted
		{v: verdict{authority: AuthorityBlocked}},                     // an error without decision fields: not counted
		{v: verdict{authority: AuthorityHook, authRejected: true}},    // another hook's refusal, no policy: not counted
	}}
	if got := m.totals().BlockedCalls; got != 5 {
		t.Errorf("BlockedCalls = %d, want 5", got)
	}
}
