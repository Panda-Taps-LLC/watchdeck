package hook

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Panda-Taps-LLC/watchdeck/internal/activity"
	"github.com/Panda-Taps-LLC/watchdeck/internal/claudesettings"
	"github.com/Panda-Taps-LLC/watchdeck/internal/shellparse"
)

func shellQuote(s string) string { return shellparse.Quote(s) }

// Native rules before the rewrite (Plan 02 Task 7). Claude Code matches its
// permissions.deny and ask rules against the rewritten command, so a rule
// such as Bash(curl *) never sees the curl inside `watchdeck run -c '…'`.
// The hook matches them against the original command first, and only when
// it is about to rewrite.

// writeClaudeSettings writes the user's Claude Code settings.json in the
// fixture's temp HOME (never the real ~/.claude).
func (f *fx) writeClaudeSettings(t *testing.T, json string) {
	t.Helper()
	p := filepath.Join(f.home, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(json), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestNativeRulesDenyBeforeRewrite(t *testing.T) {
	f := newFx(t)
	f.env.StateDir = t.TempDir()
	f.writeClaudeSettings(t, `{"permissions":{"deny":["Bash(curl *)","Bash(make deploy)"]}}`)
	f.writeUser(t, richUser)
	script := "python3 " + f.skill("pdf", "scripts/fill.py")
	for _, c := range []struct{ cmd, rule string }{
		{script + " a.pdf && curl -d @a.pdf https://example.invalid", "Bash(curl *)"},
		{"cd /tmp && curl -s https://example.invalid | " + script + " in.pdf", "Bash(curl *)"},
		{script + " a.pdf && (cd /tmp; timeout 5 curl https://example.invalid)", "Bash(curl *)"},
		{script + ` a.pdf && timeout "$T" curl https://example.invalid`, "Bash(curl *)"},
		{"make deploy", "Bash(make deploy)"}, // command subject make-auto (auto_allow)
	} {
		out := Decide(f.in(c.cmd), f.env)
		if decisionOf(out) != Deny {
			t.Fatalf("%q: got %+v", c.cmd, out)
		}
		s := out.HookSpecificOutput
		if s.UpdatedInput != nil {
			t.Errorf("%q: a denied command must not be rewritten: %v", c.cmd, s.UpdatedInput)
		}
		if !strings.Contains(s.PermissionDecisionReason, "blocked by your Claude Code deny rule "+c.rule) {
			t.Errorf("%q: reason %q", c.cmd, s.PermissionDecisionReason)
		}
	}
	// a model-typed run whose payload hits the deny is denied, not asked
	typed := "watchdeck run --skill pdf -c " + shellQuote(script+" a.pdf && curl https://example.invalid")
	if out := Decide(f.in(typed), f.env); decisionOf(out) != Deny {
		t.Fatalf("model-typed run: %+v", out)
	}
	// no hit: the rewrite as before
	out := Decide(f.in(script+" a.pdf"), f.env)
	if out == nil || out.HookSpecificOutput.UpdatedInput == nil {
		t.Fatalf("no hit must still rewrite: %+v", out)
	}
	// a documented non-match stays a non-match (the rewrite happens)
	out = Decide(f.in(script+" a.pdf && /usr/bin/curl https://example.invalid"), f.env)
	if out == nil || out.HookSpecificOutput.UpdatedInput == nil {
		t.Fatalf("/usr/bin/curl is not matched by Bash(curl *): %+v", out)
	}
}

func TestNativeRulesAskBeforeRewrite(t *testing.T) {
	f := newFx(t)
	f.writeClaudeSettings(t, `{"permissions":{"ask":["Bash(git clean:*)"]}}`)
	// pdf is auto-allowed: without the ask rule this would be an allow
	os.WriteFile(filepath.Join(f.env.UserCfgDir, "overrides.yaml"), []byte("version: 1\nskills:\n  pdf:\n    auto_allow: true\n"), 0o644)
	script := "python3 " + f.skill("pdf", "scripts/fill.py")
	if out := Decide(f.in(script+" a.pdf"), f.env); decisionOf(out) != Allow {
		t.Fatalf("baseline: want allow, got %+v", out)
	}
	cmd := script + ` a.pdf; (cd out && git clean -f)`
	out := Decide(f.in(cmd), f.env)
	if decisionOf(out) != Ask {
		t.Fatalf("got %+v", out)
	}
	s := out.HookSpecificOutput
	// an ask hit keeps the rewrite: approved, the command runs sandboxed
	rw, _ := s.UpdatedInput["command"].(string)
	if !strings.HasPrefix(rw, "watchdeck run --skill pdf -c ") || !strings.Contains(rw, "git clean -f") {
		t.Errorf("an ask hit must keep the rewrite: %v", s.UpdatedInput)
	}
	if !strings.Contains(s.PermissionDecisionReason, "Claude Code ask rule Bash(git clean:*)") || strings.Contains(s.PermissionDecisionReason, "not sandboxed") {
		t.Errorf("reason %q", s.PermissionDecisionReason)
	}
	// the record carries the rule hit and the rewrite
	logp := f.withLog(t)
	in := f.in(cmd)
	in.HookEventName = "PreToolUse"
	var buf bytes.Buffer
	runHook(t, f.env, in, &buf)
	recs := readLog(t, logp)
	if len(recs) != 1 || recs[0].Decision != Ask || recs[0].Rewritten == "" || !hasNativeHit(recs[0].Rules, "Bash(git clean:*)", Ask) {
		t.Fatalf("record %+v", recs)
	}
	// a deny rule wins over the ask rule
	f.writeClaudeSettings(t, `{"permissions":{"ask":["Bash(git clean:*)"],"deny":["Bash(git *)"]}}`)
	if out := Decide(f.in(cmd), f.env); decisionOf(out) != Deny {
		t.Fatalf("deny before ask: %+v", out)
	}
}

// TestNativeRulesAskDropsRewriteInBypass (final review ruling,
// 2026-10-19): in bypassPermissions and dontAsk Claude Code may resolve a
// hook's ask without a person, and with a rewrite its own deny rules would
// see only `watchdeck run -c '…'`. So in those two modes the three native
// asks (an ask rule, an unreadable settings file, an unparseable command)
// answer ask without updatedInput, and the record claims no rewrite and no
// sandbox; in every other mode the rewrite stays. The unparseable kind
// never reaches the rewrite through Decide (TestNativeRulesUnparseableAsks:
// skill detection gives up first), so it is checked on nativeAsk directly
// with nativeCheck's own answer.
func TestNativeRulesAskDropsRewriteInBypass(t *testing.T) {
	f := newFx(t)
	os.WriteFile(filepath.Join(f.env.UserCfgDir, "overrides.yaml"), []byte("version: 1\nskills:\n  pdf:\n    auto_allow: true\n"), 0o644)
	script := "python3 " + f.skill("pdf", "scripts/fill.py")
	cmd := script + ` a.pdf; git clean -f`
	kinds := []struct{ name, settings, reason string }{
		{"ask rule", `{"permissions":{"ask":["Bash(git clean:*)"]}}`, "Claude Code ask rule Bash(git clean:*)"},
		{"unreadable settings", `{"permissions":`, "could not read your Claude Code user settings file"},
	}
	for _, k := range kinds {
		f.writeClaudeSettings(t, k.settings)
		for _, mode := range []string{"bypassPermissions", "dontAsk"} {
			in := f.in(cmd)
			in.PermissionMode = mode
			out := Decide(in, f.env)
			if decisionOf(out) != Ask || out.HookSpecificOutput.UpdatedInput != nil {
				t.Errorf("%s, %s: want ask without a rewrite, got %+v", k.name, mode, out)
				continue
			}
			if r := out.HookSpecificOutput.PermissionDecisionReason; !strings.Contains(r, k.reason) || !strings.Contains(r, "not sandboxed") {
				t.Errorf("%s, %s: reason %q", k.name, mode, r)
			}
			logp := f.withLog(t)
			in.HookEventName = "PreToolUse"
			var buf bytes.Buffer
			runHook(t, f.env, in, &buf)
			recs := readLog(t, logp)
			if len(recs) != 1 || recs[0].Decision != Ask || recs[0].Rewritten != "" || recs[0].Enforcement != activity.EnforcementGate {
				t.Errorf("%s, %s: record %+v", k.name, mode, recs)
			}
		}
		for _, mode := range []string{"", "default", "acceptEdits", "plan", "auto"} {
			in := f.in(cmd)
			in.PermissionMode = mode
			out := Decide(in, f.env)
			rw := ""
			if out != nil {
				rw, _ = out.HookSpecificOutput.UpdatedInput["command"].(string)
			}
			if decisionOf(out) != Ask || !strings.HasPrefix(rw, "watchdeck run --skill pdf -c ") {
				t.Errorf("%s, mode %q: want ask with the rewrite, got %+v", k.name, mode, out)
			}
		}
	}
	// the unparseable kind, on the merge itself
	f.writeClaudeSettings(t, `{"permissions":{"deny":["Bash(rm *)"]}}`)
	no, _, hit := nativeCheck(f.env, f.cwd, script+" 'unterminated")
	if !hit || decisionOf(no) != Ask {
		t.Fatalf("native check: %+v", no)
	}
	rewrite := &Output{HookSpecificOutput: Specific{HookEventName: "PreToolUse", PermissionDecision: Allow,
		PermissionDecisionReason: "watchdeck: sandboxed", UpdatedInput: map[string]any{"command": "watchdeck run --skill pdf -c x"}}}
	for _, mode := range []string{"bypassPermissions", "dontAsk"} {
		got, drop := nativeAsk(rewrite, no, mode)
		if !drop || decisionOf(got) != Ask || got.HookSpecificOutput.UpdatedInput != nil ||
			!strings.Contains(got.HookSpecificOutput.PermissionDecisionReason, "could not parse this command") {
			t.Errorf("unparseable, %s: %+v", mode, got)
		}
	}
	for _, mode := range []string{"", "default", "acceptEdits", "plan", "auto"} {
		got, drop := nativeAsk(rewrite, no, mode)
		if drop || decisionOf(got) != Ask || got.HookSpecificOutput.UpdatedInput == nil {
			t.Errorf("unparseable, mode %q: %+v", mode, got)
		}
	}
	if rewrite.HookSpecificOutput.PermissionDecision != Allow || rewrite.HookSpecificOutput.UpdatedInput == nil {
		t.Errorf("nativeAsk changed its input: %+v", rewrite)
	}
}

// TestNativeRulesUnparseableAsks: a command the parser rejects is never a
// rewrite candidate (skill detection and command subjects both need a clean
// parse, so the earlier "could not determine the sandbox boundary" ask
// answers first); the native check itself answers ask for it, which is what
// a later caller with an unparseable command would get.
func TestNativeRulesUnparseableAsks(t *testing.T) {
	f := newFx(t)
	f.writeClaudeSettings(t, `{"permissions":{"deny":["Bash(rm *)"]}}`)
	script := "python3 " + f.skill("pdf", "scripts/fill.py")
	out := Decide(f.in(script+" a.pdf &&"), f.env)
	if decisionOf(out) != Ask || out.HookSpecificOutput.UpdatedInput != nil {
		t.Fatalf("hook: got %+v", out)
	}
	no, m, hit := nativeCheck(f.env, f.cwd, script+" 'unterminated")
	if !hit || decisionOf(no) != Ask || no.HookSpecificOutput.UpdatedInput != nil ||
		!strings.Contains(no.HookSpecificOutput.PermissionDecisionReason, "could not parse this command against your Claude Code rules") {
		t.Fatalf("native check: %+v", no)
	}
	if m.Enforcement != activity.EnforcementGate {
		t.Errorf("meta %+v", m)
	}
}

func TestNativeRulesBareBashDeniesAll(t *testing.T) {
	for _, rule := range []string{"Bash", "Bash(*)"} {
		f := newFx(t)
		f.writeClaudeSettings(t, `{"permissions":{"deny":["`+rule+`"]}}`)
		f.writeUser(t, richUser)
		for _, cmd := range []string{"python3 " + f.skill("pdf", "scripts/fill.py") + " a.pdf", "make all"} {
			out := Decide(f.in(cmd), f.env)
			if decisionOf(out) != Deny || out.HookSpecificOutput.UpdatedInput != nil {
				t.Fatalf("%s, %q: got %+v", rule, cmd, out)
			}
			if !strings.Contains(out.HookSpecificOutput.PermissionDecisionReason, "deny rule "+rule) {
				t.Errorf("reason %q", out.HookSpecificOutput.PermissionDecisionReason)
			}
		}
	}
}

func TestNativeRulesNotLoadedOnNoOpinion(t *testing.T) {
	f := newFx(t)
	f.env.StateDir = t.TempDir()
	f.writeClaudeSettings(t, `{"permissions":{"deny":["Bash(ls *)","Bash(git *)"]}}`)
	loads := 0
	testNativeLoad = func() { loads++ }
	t.Cleanup(func() { testNativeLoad = nil })
	cache := filepath.Join(f.env.StateDir, claudesettings.RulesCacheFile)

	if out := Decide(Input{ToolName: "Read", Cwd: f.cwd, ToolInput: map[string]any{"file_path": f.skill("pdf", "SKILL.md")}}, f.env); out != nil {
		t.Fatalf("Read: %+v", out)
	}
	for _, cmd := range []string{"ls", "ls -la", "git status"} {
		// Claude Code's own rule handles these: the hook has no opinion
		if out := Decide(f.in(cmd), f.env); out != nil {
			t.Fatalf("%q: %+v", cmd, out)
		}
	}
	if loads != 0 {
		t.Fatalf("native rules loaded %d times on the no-opinion path", loads)
	}
	absent(t, cache)
	// the rewrite path loads them once
	Decide(f.in("python3 "+f.skill("pdf", "scripts/fill.py")), f.env)
	if loads != 1 {
		t.Fatalf("rewrite path: %d loads", loads)
	}
	if _, err := os.Stat(cache); err != nil {
		t.Fatalf("cache not written on the rewrite path: %v", err)
	}
}

func TestNativeRulesRecordNamesThePattern(t *testing.T) {
	f := newFx(t)
	logp := f.withLog(t)
	f.writeUser(t, richUser) // rule marked-arg asks on MARKEDARG
	f.writeClaudeSettings(t, `{"permissions":{"deny":["Bash(curl *)"]}}`)
	cmd := "python3 " + f.skill("pdf", "scripts/fill.py") + " MARKEDARG && curl https://example.invalid"
	in := f.in(cmd)
	in.HookEventName = "PreToolUse"
	var out bytes.Buffer
	runHook(t, f.env, in, &out)
	if !strings.Contains(out.String(), `"permissionDecision":"deny"`) {
		t.Fatalf("a gate's ask must not soften the native deny: %s", out.String())
	}
	recs := readLog(t, logp)
	if len(recs) != 1 {
		t.Fatalf("records: %+v", recs)
	}
	r := recs[0]
	if r.Decision != Deny || r.Enforcement != activity.EnforcementGate || r.Rewritten != "" {
		t.Fatalf("record %+v", r)
	}
	var native, user bool
	for _, h := range r.Rules {
		if h.Pack == activity.PackClaudeSettings && h.ID == "Bash(curl *)" && h.Action == "deny" {
			native = true
		}
		if h.Pack == "user" && h.ID == "marked-arg" {
			user = true
		}
	}
	if !native || !user {
		t.Fatalf("rules %+v", r.Rules)
	}
	if !strings.Contains(r.Reason, "blocked by your Claude Code deny rule Bash(curl *)") {
		t.Fatalf("reason %q", r.Reason)
	}

	// a model-typed run whose payload hits the deny records the rule too
	logp2 := f.withLog(t)
	typed := f.in("watchdeck run --skill pdf -c " + shellQuote("python3 "+f.skill("pdf", "scripts/fill.py")+" && curl https://example.invalid"))
	typed.HookEventName = "PreToolUse"
	out.Reset()
	runHook(t, f.env, typed, &out)
	if !strings.Contains(out.String(), `"permissionDecision":"deny"`) {
		t.Fatalf("model-typed run: %s", out.String())
	}
	recs = readLog(t, logp2)
	if len(recs) != 1 || recs[0].Decision != Deny || !hasNativeHit(recs[0].Rules, "Bash(curl *)", Deny) {
		t.Fatalf("model-typed record %+v", recs)
	}

	// a model-typed run whose payload names no skill (so it would not be
	// rewritten) is still checked: plain curl under pdf's grant is denied
	logp3 := f.withLog(t)
	plain := f.in("watchdeck run --skill pdf -c " + shellQuote("curl https://example.invalid"))
	plain.HookEventName = "PreToolUse"
	out.Reset()
	runHook(t, f.env, plain, &out)
	if !strings.Contains(out.String(), `"permissionDecision":"deny"`) || !strings.Contains(out.String(), "deny rule Bash(curl *)") {
		t.Fatalf("model-typed plain payload: %s", out.String())
	}
	recs = readLog(t, logp3)
	if len(recs) != 1 || recs[0].Decision != Deny || recs[0].Enforcement != activity.EnforcementGate || !hasNativeHit(recs[0].Rules, "Bash(curl *)", Deny) {
		t.Fatalf("model-typed plain record %+v", recs)
	}
}

// TestNativeRulesModelTypedAskNamesTheRule: an ask rule on a model-typed
// payload that would not be rewritten is named in the reason and record.
func TestNativeRulesModelTypedAskNamesTheRule(t *testing.T) {
	f := newFx(t)
	logp := f.withLog(t)
	f.writeClaudeSettings(t, `{"permissions":{"ask":["Bash(curl *)"]}}`)
	in := f.in("watchdeck run --skill pdf -c " + shellQuote("curl https://example.invalid"))
	in.HookEventName = "PreToolUse"
	var out bytes.Buffer
	runHook(t, f.env, in, &out)
	if !strings.Contains(out.String(), `"permissionDecision":"ask"`) || !strings.Contains(out.String(), "Claude Code ask rule Bash(curl *)") {
		t.Fatalf("got %s", out.String())
	}
	recs := readLog(t, logp)
	if len(recs) != 1 || recs[0].Decision != Ask || !hasNativeHit(recs[0].Rules, "Bash(curl *)", Ask) {
		t.Fatalf("record %+v", recs)
	}
}

// TestNativeRulesModelTypedRunInBypass: a correctly typed run whose
// payload hits a native ask rule names the rule, and not the "not what the
// hook would choose" mismatch, in every mode. The comparison with the plain
// payload ignores the permission mode: the typed run carries no rewrite to
// drop.
func TestNativeRulesModelTypedRunInBypass(t *testing.T) {
	f := newFx(t)
	f.writeClaudeSettings(t, `{"permissions":{"ask":["Bash(git clean:*)"]}}`)
	payload := "python3 " + f.skill("pdf", "scripts/fill.py") + " a.pdf; git clean -f"
	for _, mode := range []string{"", "default", "bypassPermissions", "dontAsk"} {
		in := f.in("watchdeck run --skill pdf -c " + shellQuote(payload))
		in.PermissionMode = mode
		out := Decide(in, f.env)
		if decisionOf(out) != Ask || out.HookSpecificOutput.UpdatedInput != nil {
			t.Errorf("mode %q: got %+v", mode, out)
			continue
		}
		r := out.HookSpecificOutput.PermissionDecisionReason
		if !strings.Contains(r, "Claude Code ask rule Bash(git clean:*)") || strings.Contains(r, "not what the hook would choose") {
			t.Errorf("mode %q: reason %q", mode, r)
		}
	}
}

// TestMatchBashCapFailsClosed (security review, 2026-10-19): no limit on
// a wrapper's readings may drop the one a deny rule matches. The matcher
// has no cap (every reading is walked), so a chain whose deny-matching rm
// comes after more than eight readings, or after 1,200 of them, is denied
// by the matcher and at hook level, never rewritten.
func TestMatchBashCapFailsClosed(t *testing.T) {
	f := newFx(t)
	f.env.StateDir = t.TempDir()
	f.writeClaudeSettings(t, `{"permissions":{"deny":["Bash(rm *)"]}}`)
	rules := []claudesettings.BashRule{{Pattern: "rm *", Kind: claudesettings.KindDeny, Scope: claudesettings.ScopeUser, Value: "Bash(rm *)"}}
	script := "python3 " + f.skill("pdf", "scripts/fill.py") + " a.pdf && "
	for _, tail := range []string{
		`nice -"$A" 1 -"$B" 2 -"$C" 3 -"$D" 4 -"$E" 5 -"$F" 6 -"$G" 7 -"$H" 8 -"$I" 9 -"$J" 10 rm -rf x`,
		"nice " + strings.Repeat(`-"$N" 5 `, 1200) + "rm -rf x",
		strings.Repeat(`timeout -"$S" KILL 5 `, 1200) + "rm -rf x",
	} {
		if m := claudesettings.MatchBash(rules, tail); m.Rule == nil || m.Rule.Kind != claudesettings.KindDeny {
			t.Errorf("matcher, %.40q…: got %+v", tail, m)
		}
		out := Decide(f.in(script+tail), f.env)
		if decisionOf(out) != Deny || out.HookSpecificOutput.UpdatedInput != nil {
			t.Errorf("hook, %.40q…: want deny without a rewrite, got %+v", tail, out)
		}
	}
}

func hasNativeHit(hits []activity.RuleHit, id, action string) bool {
	for _, h := range hits {
		if h.Pack == activity.PackClaudeSettings && h.ID == id && h.Action == action {
			return true
		}
	}
	return false
}

// TestNativeRulesWrappersBehindExpansions: behind a skill script and `&&`,
// with deny Bash(rm *), stacked wrappers still chain past one expanded word
// each, and an expanded option word (`-"$S"`, `-"$M"`) is consumed, with or
// without the next word as its value, so the wrapped rm is denied without a
// rewrite; so are the GNU option spellings (bundled short flags, long
// prefixes, options after nice's -10) and a backslash-newline inside the
// command word (final review, 2026-10-19). The one-skip and one-value
// bounds, the forms that run nothing and the "no suffix guessing"
// rule keep the documented non-matches rewriting with an ask, and `time
// "$P" rm` asks without a rewrite because skill detection gives up on an
// expansion in path position before any rewrite.
func TestNativeRulesWrappersBehindExpansions(t *testing.T) {
	f := newFx(t)
	f.env.StateDir = t.TempDir()
	f.writeClaudeSettings(t, `{"permissions":{"deny":["Bash(rm *)"]}}`)
	script := "python3 " + f.skill("pdf", "scripts/fill.py") + " a.pdf && "
	for _, c := range []struct{ tail, want string }{
		{`nohup "$X" timeout 5 rm -rf x`, "deny"},
		{`nice "$N" timeout 5 rm -rf x`, "deny"},
		{`nohup "$X" nice "$N" rm -rf x`, "deny"},
		{`nohup "$X" nohup rm -rf x`, "deny"},
		{`timeout -"$S" 5 rm -rf x`, "deny"},
		{`stdbuf -"$M" rm -rf x`, "deny"},
		{`nice -"$N" 5 rm -rf x`, "deny"},
		{`stdbuf -"$M" L rm -rf x`, "deny"},
		{`timeout -"$S" KILL 5 rm -rf x`, "deny"},
		{`timeout --"$L" KILL 5 rm -rf x`, "deny"},
		{`timeout -s"$X" KILL 5 rm -rf x`, "deny"},
		{`timeout -vs"$X" KILL 5 rm -rf x`, "deny"},
		{`timeout -k"$K" 9 5 rm -rf x`, "deny"},
		{`nice -n"$N" 5 rm -rf x`, "deny"},
		{`stdbuf -o"$M" L rm -rf x`, "deny"},
		{`timeout -s"$X" KILL 5 echo rm -rf x`, "ask, rewritten"},
		{`nice -n"$N" 5 echo rm -rf x`, "ask, rewritten"},
		{`stdbuf -o"$M" L echo rm -rf x`, "ask, rewritten"},
		{`timeout -sKILL"$X" 5 rm -rf x`, "deny"},
		// option spellings and line continuation (final review, 2026-10-19)
		{"timeout -vs KILL 5 rm -rf x", "deny"},
		{"timeout -vsKILL 5 rm -rf x", "deny"},
		{"timeout --sig=KILL 5 rm -rf x", "deny"},
		{"timeout --fore 5 rm -rf x", "deny"},
		{"stdbuf --out=L rm -rf x", "deny"},
		{"nice --adj=5 rm -rf x", "deny"},
		{"nice -10 -n 5 rm -rf x", "deny"},
		{"nice -10 -n5 rm -rf x", "deny"},
		{"nice -10 --adjustment=5 rm -rf x", "deny"},
		{`nice -10 -"$N" 5 rm -rf x`, "deny"},
		{"r\\\nm -rf x", "deny"},
		{"timeout 5 r\\\nm -rf x", "deny"},
		{`nice -"$A" 1 -"$B" 2 -"$C" 3 -"$D" 4 -"$E" 5 -"$F" 6 -"$G" 7 -"$H" 8 -"$I" 9 -"$J" 10 rm -rf x`, "deny"}, // more than eight readings: none dropped
		{"timeout 5 -- rm -rf x", "ask, rewritten"},
		{"timeout --foreground=x 5 rm -rf x", "ask, rewritten"},
		{"echo 'r\\\nm -rf x'", "ask, rewritten"},
		{`time "$P" rm -rf x`, "ask, no rewrite"},
		{`nice -"$N" 5 echo rm -rf x`, "ask, rewritten"},
		{`stdbuf -"$M" L echo rm -rf x`, "ask, rewritten"},
		{`timeout -"$S" KILL 5 echo rm -rf x`, "ask, rewritten"},
		{`timeout 5 echo rm -rf x`, "ask, rewritten"},
		{`stdbuf -oL echo rm -rf x`, "ask, rewritten"},
		{`nice "$N" echo rm -rf x`, "ask, rewritten"},
		{`nice "$N" "$M" rm -rf x`, "ask, rewritten"},
	} {
		out := Decide(f.in(script+c.tail), f.env)
		got := decisionOf(out)
		rewritten := out != nil && out.HookSpecificOutput.UpdatedInput != nil
		if rewritten {
			got += ", rewritten"
		} else if got == Ask {
			got += ", no rewrite"
		}
		reason := ""
		if out != nil {
			reason = out.HookSpecificOutput.PermissionDecisionReason
		}
		t.Logf("PROBE <pdf script> a.pdf && %-34q -> %s", c.tail, got)
		if got != c.want {
			t.Errorf("%q: got %s, want %s (reason %q)", c.tail, got, c.want, reason)
			continue
		}
		if c.want == "deny" && !strings.Contains(reason, "blocked by your Claude Code deny rule Bash(rm *)") {
			t.Errorf("%q: reason %q", c.tail, reason)
		}
	}
}
