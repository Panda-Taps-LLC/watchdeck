package prove

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/activity"
	"github.com/Panda-Taps-LLC/watchdeck/internal/demo"
	"github.com/Panda-Taps-LLC/watchdeck/internal/hook"
	"github.com/Panda-Taps-LLC/watchdeck/internal/lifecycle"
	"github.com/Panda-Taps-LLC/watchdeck/internal/manifest"
	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
	"github.com/Panda-Taps-LLC/watchdeck/internal/policy"
	"github.com/Panda-Taps-LLC/watchdeck/internal/rules"
)

// fakeEnv is a demo tree that exists only as names (no Prepare).
func fakeEnv() *demo.Env {
	return &demo.Env{Base: "/b", Home: "/b/home", Cwd: "/b/proj", SkillDir: "/b/home/.claude/skills/" + demo.Skill,
		XDGConfig: "/b/xdg/config", XDGCache: "/b/xdg/cache", XDGState: "/b/xdg/state", ClaudeDir: "/b/home/.claude",
		Activity: "/b/xdg/state/" + paths.BinaryName + "/activity.jsonl"}
}

// out renders a hook reply as the hook prints it.
func out(decision, reason, rewrite string) string {
	s := hook.Specific{HookEventName: "PreToolUse", PermissionDecision: decision, PermissionDecisionReason: reason}
	if rewrite != "" {
		s.UpdatedInput = map[string]any{"command": rewrite}
	}
	b, err := json.Marshal(hook.Output{HookSpecificOutput: s})
	if err != nil {
		panic(err)
	}
	return string(b) + "\n"
}

// replies returns a hook function answering the given replies in turn (the
// last one repeats) and a counter of calls.
func replies(rs ...reply) (func([]byte) reply, *int) {
	n := 0
	return func([]byte) reply {
		r := rs[min(n, len(rs)-1)]
		n++
		return r
	}, &n
}

func TestProvePolicyFileParses(t *testing.T) {
	f, err := manifest.ParsePolicyFile([]byte(PolicyYAML))
	if err != nil {
		t.Fatalf("PolicyYAML does not parse: %v\n%s", err, PolicyYAML)
	}
	if f.RuleOverrides[RuleID].Action != "deny" {
		t.Fatalf("override = %+v", f.RuleOverrides[RuleID])
	}
	if !strings.Contains(PolicyYAML, "mode: enforce\n") {
		t.Fatalf("PolicyYAML has no explicit mode: enforce line:\n%s", PolicyYAML)
	}
	if f.Mode != "" {
		t.Fatalf("Mode = %q, want \"\" (enforce normalises to empty)", f.Mode)
	}
	cfg := policy.FileRulesConfig(f)
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	pack, rule, _ := strings.Cut(RuleID, "/")
	find := func(hits []rules.Hit) *rules.Hit {
		for i := range hits {
			if hits[i].Pack == pack && hits[i].Rule == rule {
				return &hits[i]
			}
		}
		return nil
	}
	in := rules.Input{FilePath: "~/.ssh/id_fake"}
	if h := find(rules.Eval(cfg, "Read", in)); h == nil || h.Action != rules.Deny {
		t.Fatalf("with the throwaway policy: hit %+v, want deny", h)
	}
	if h := find(rules.Eval(rules.Config{}, "Read", in)); h == nil || h.Action != rules.Ask {
		t.Fatalf("without it: hit %+v, want ask (the override is what flips it)", h)
	}
}

func TestProvePayloads(t *testing.T) {
	e := fakeEnv()
	var in hook.Input
	if err := json.Unmarshal(BashPayload(e, "/usr/bin/python3"), &in); err != nil {
		t.Fatal(err)
	}
	if in.ToolName != "Bash" || in.Cwd != "/b/proj" || in.ToolUseID != BashToolUseID || in.PermissionMode != "default" ||
		in.HookEventName != "PreToolUse" || in.SessionID != SessionID || in.TranscriptPath != "/b/transcript.jsonl" ||
		in.ToolInput["command"] != e.ProbeCommand("/usr/bin/python3") {
		t.Fatalf("bash payload: %+v", in)
	}
	if strings.Contains(string(BashPayload(e, "python3")), "tool_response") {
		t.Fatal("payload carries tool_response")
	}
	in = hook.Input{}
	if err := json.Unmarshal(ReadPayload(e), &in); err != nil {
		t.Fatal(err)
	}
	if in.ToolName != "Read" || in.ToolInput["file_path"] != "/b/home/.ssh/id_fake" || in.ToolUseID != ReadToolUseID || in.Cwd != "/b/proj" {
		t.Fatalf("read payload: %+v", in)
	}
	if !lifecycle.ValidID(SessionID) {
		t.Fatalf("SessionID %q is not a valid session id", SessionID)
	}
}

func TestProveChildEnvDropsProjectDir(t *testing.T) {
	env := ChildEnv(fakeEnv(), []string{"PATH=/usr/bin", "CLAUDE_PROJECT_DIR=/x", "HOME=/Users/you"})
	if !slices.Contains(env, "PATH=/usr/bin") || !slices.Contains(env, "HOME=/b/home") {
		t.Fatalf("env %v", env)
	}
	for _, kv := range env {
		if strings.HasPrefix(kv, "CLAUDE_PROJECT_DIR=") || kv == "HOME=/Users/you" {
			t.Fatalf("env keeps %q: %v", kv, env)
		}
	}
}

func TestProveParseReply(t *testing.T) {
	r, err := parseReply([]byte("  \n"))
	if err != nil || !r.Empty {
		t.Fatalf("blank: %+v %v", r, err)
	}
	if _, err := parseReply([]byte("nope")); err == nil || !strings.Contains(err.Error(), "not a hook reply") {
		t.Fatalf("garbage: %v", err)
	}
	r, err = parseReply([]byte(out("deny", "no", "")))
	if err != nil || r.Output == nil || r.Output.HookSpecificOutput.PermissionDecision != "deny" {
		t.Fatalf("deny: %+v %v", r, err)
	}
	r, err = parseReply([]byte(out("ask", "x", "a b c")))
	if err != nil || rewriteOf(r) != "a b c" {
		t.Fatalf("rewrite: %+v %v", r, err)
	}
}

func TestProveJudgeRewrite(t *testing.T) {
	good := RewritePrefix() + "'python3 probe.py net --strict'"
	cases := []struct {
		name   string
		rs     []reply
		status Status
		want   string
		calls  int
	}{
		{"empty", []reply{{}}, Fail, "no opinion", 1},
		{"start error", []reply{{StartErr: errors.New("no such file")}}, Fail, "could not start the registered hook", 1},
		{"timeout", []reply{{TimedOut: true}}, Fail, "did not answer within", 1},
		{"exit 2", []reply{{Exit: 2, Stderr: "boom\nmore"}}, Fail, "exited 2", 1},
		{"garbage", []reply{{Stdout: "hello"}}, Fail, "not a hook reply", 1},
		{"deny", []reply{{Stdout: out("deny", "managed Bash(python3 *) deny", "")}}, Fail, "managed Bash(python3 *) deny", 1},
		{"ask without rewrite", []reply{{Stdout: out("ask", "hmm", "")}}, Fail, "without a rewrite", 1},
		{"index", []reply{{Stdout: out("ask", "cannot load the skill index", "")}}, Fail, "the canary lives in", 1},
		{"invalid policy", []reply{{Stdout: out("ask", "your policy file is invalid", "")}}, Fail, "throwaway policy did not parse", 1},
		{"slow twice", []reply{{Stdout: out("ask", hook.SlowReason, "")}}, Fail, "watchdog twice", 2},
		{"slow then good", []reply{{Stdout: out("ask", hook.SlowReason, "")}, {Stdout: out("ask", "r", good)}}, Pass, "rewritten to", 2},
		{"wrong prefix", []reply{{Stdout: out("ask", "r", "other run x")}}, Fail, "does not start with", 1},
		{"good ask", []reply{{Stdout: out("ask", "r", good)}}, Pass, "rewritten to " + paths.BinaryName + " run --skill " + demo.Skill + " … (ask) by /x/" + paths.BinaryName + " hook", 1},
		{"good allow", []reply{{Stdout: out("allow", "r", good)}}, Pass, "(allow)", 1},
		{"rewrite without a decision", []reply{{Stdout: out("", "r", good)}}, Fail, "the hook rewrote without a permissionDecision ({\"hookSpecificOutput\"", 1},
		{"benign payload", []reply{{Stdout: out("ask", "r", RewritePrefix()+"'true'")}}, Fail, "the rewrite's -c payload is not the canary's command: 'true'", 1},
		{"chained payload", []reply{{Stdout: out("ask", "r", good+"; true")}}, Fail, "the rewrite's -c payload is not the canary's command: 'python3 probe.py net --strict'; true", 1},
		{"payload with an extra word", []reply{{Stdout: out("ask", "r", good+" x")}}, Fail, "payload is not the canary's command", 1},
		{"other quoting, same command", []reply{{Stdout: out("ask", "r", RewritePrefix()+"\"python3 probe.py net --strict\"")}}, Pass, "rewritten to", 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			call, n := replies(c.rs...)
			leg, rewrite, decision := judgeRewrite(call, []byte("{}"), "python3 probe.py net --strict", "/x/"+paths.BinaryName+" hook", "/b/skill")
			if leg.Name != LegRewrite || leg.Status != c.status || !strings.Contains(leg.Message, c.want) {
				t.Fatalf("got %+v; want %s containing %q", leg, c.status, c.want)
			}
			if *n != c.calls {
				t.Fatalf("calls %d, want %d", *n, c.calls)
			}
			if c.status == Pass && (!strings.HasPrefix(rewrite, RewritePrefix()) || !strings.Contains(rewrite, "python3 probe.py net --strict") || decision == "") {
				t.Fatalf("rewrite %q decision %q", rewrite, decision)
			}
			if c.status == Fail && rewrite != "" {
				t.Fatalf("a failed leg returned rewrite %q", rewrite)
			}
		})
	}
}

func TestProveJudgeRun(t *testing.T) {
	exit1 := 1
	net := activity.Hint{Kind: "network", Errno: 1}
	joined := &activity.Record{Kind: activity.KindRun, Outcome: activity.OutcomeFailed, Exit: &exit1, Backend: "seatbelt",
		Hints: []activity.Hint{net}, ToolUseID: BashToolUseID, JoinedBy: activity.JoinedByWrite}
	unjoined := *joined
	unjoined.ToolUseID, unjoined.JoinedBy = "", ""
	readerJoined := *joined
	readerJoined.JoinedBy = activity.JoinedByHeuristic
	okRec := *joined
	okRec.Outcome = activity.OutcomeOK
	noHint := *joined
	noHint.Hints = []activity.Hint{{Kind: "write"}}
	denied := "net: DENIED(1)\n"
	trailer := paths.Trailer + "could not apply the sandbox (nested sandbox)\n"
	cases := []struct {
		name   string
		ro     runOutcome
		rec    *activity.Record
		nested bool
		status Status
		want   string
	}{
		{"nested", runOutcome{}, nil, true, Warn, "not run: already inside a sandbox"},
		{"timeout", runOutcome{TimedOut: true}, nil, false, Fail, "did not finish within"},
		{"start", runOutcome{StartErr: errors.New("x")}, nil, false, Fail, "could not start /bin/bash"},
		{"127", runOutcome{Exit: 127, Binary: "/opt/x/" + paths.BinaryName}, nil, false, Fail, "exit 127: a program on the rewrite's path was not found (usually " + paths.BinaryName + "; the registered hook is /opt/x/" + paths.BinaryName + "): put it on PATH as " + paths.BinaryName + ", or rerun " + paths.BinaryName + " setup from the one on PATH"},
		{"126", runOutcome{Exit: 126, Stderr: "noise\n" + trailer}, nil, false, Fail, "could not apply the sandbox (exit 126): " + paths.Trailer + "could not apply"},
		{"125", runOutcome{Exit: 125, Stderr: paths.Trailer + "unknown skill\n"}, nil, false, Fail, "policy error"},
		{"3", runOutcome{Exit: 3}, nil, false, Fail, "no sandbox backend"},
		{"0", runOutcome{Exit: 0, Stdout: "net: ALLOWED\n"}, nil, false, Fail, "reached the network (exit 0; stdout: net: ALLOWED)"},
		{"1 no denial", runOutcome{Exit: 1, Stderr: "Traceback\n"}, nil, false, Fail, "without a network denial: Traceback"},
		{"1 no record", runOutcome{Exit: 1, Stdout: denied}, nil, false, Fail, "no run record"},
		{"1 ok record", runOutcome{Exit: 1, Stdout: denied}, &okRec, false, Fail, "expected failed"},
		{"1 no network hint", runOutcome{Exit: 1, Stdout: denied}, &noHint, false, Fail, "with hints write"},
		{"1 unjoined", runOutcome{Exit: 1, Stdout: denied}, &unjoined, false, Fail, "not joined"},
		{"1 joined by the reader only", runOutcome{Exit: 1, Stdout: denied}, &readerJoined, false, Fail, "joined_by heuristic"},
		{"1 joined", runOutcome{Exit: 1, Stdout: denied}, joined, false, Pass, "net: DENIED, errno 1, backend seatbelt); run record joined"},
		{"1 joined, other binary on PATH", runOutcome{Exit: 1, Stdout: denied, Binary: "/a/" + paths.BinaryName, PathBinary: "/b/" + paths.BinaryName}, joined, false, Pass, "note: PATH ran /b/"},
		{"other exit", runOutcome{Exit: 9, Stderr: "odd\n"}, nil, false, Fail, "exit 9: odd"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			leg := judgeRun(c.ro, c.rec, c.nested)
			if leg.Name != LegSandbox || leg.Status != c.status || !strings.Contains(leg.Message, c.want) {
				t.Fatalf("got %+v; want %s containing %q", leg, c.status, c.want)
			}
		})
	}
	same := judgeRun(runOutcome{Exit: 1, Stdout: denied, Binary: "/a/x", PathBinary: "/a/x"}, joined, false)
	if strings.Contains(same.Message, "note:") {
		t.Fatalf("same binary still noted: %s", same.Message)
	}
}

func TestProveJudgeRead(t *testing.T) {
	cases := []struct {
		name   string
		r      reply
		status Status
		want   string
	}{
		{"empty", reply{}, Fail, "no opinion on a Read of ~/.ssh/id_fake"},
		{"exit", reply{Exit: 1, Stderr: "x"}, Fail, "exited 1"},
		{"start error", reply{StartErr: errors.New("no such file")}, Fail, "could not start the registered hook (/x/" + paths.BinaryName + " hook): no such file"},
		{"garbage", reply{Stdout: "?"}, Fail, "not a hook reply"},
		{"ask", reply{Stdout: out("ask", "hmm", "")}, Fail, "asked instead of denying (hmm)"},
		{"ask invalid", reply{Stdout: out("ask", "your policy file is invalid", "")}, Fail, "throwaway policy did not parse"},
		{"allow", reply{Stdout: out("allow", "", "")}, Fail, "allowed a Read"},
		{"deny rule", reply{Stdout: out("deny", paths.BinaryName+": denied by policy: "+RuleID+" (critical, deny): x | more", "")}, Pass, "was denied (" + paths.BinaryName + ": denied by policy: " + RuleID + " (critical, deny): x); Claude Code sends Read calls"},
		{"deny other", reply{Stdout: out("deny", "managed Read deny", "")}, Pass, "something other than " + RuleID},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			call, _ := replies(c.r)
			leg := judgeRead(call, []byte("{}"), "/x/"+paths.BinaryName+" hook")
			if leg.Name != LegReadRule || leg.Status != c.status || !strings.Contains(leg.Message, c.want) {
				t.Fatalf("got %+v; want %s containing %q", leg, c.status, c.want)
			}
		})
	}
}

func TestProveShadowLeg(t *testing.T) {
	f := "~/.config/" + paths.BinaryName + "/overrides.yaml"
	if l := shadowLeg(Shadow{}); l.Name != LegShadow || l.Status != Pass || !strings.Contains(l.Message, "no policy file") {
		t.Fatalf("none: %+v", l)
	}
	if l := shadowLeg(Shadow{File: f}); l.Status != Pass || !strings.Contains(l.Message, f) {
		t.Fatalf("file: %+v", l)
	}
	l := shadowLeg(Shadow{On: true, File: f})
	if l.Status != Fail || !strings.Contains(l.Message, "shadow mode is on") || !strings.Contains(l.Message, paths.BinaryName+" rules shadow off") {
		t.Fatalf("on: %+v", l)
	}
	if l := shadowLeg(Shadow{Err: errors.New("boom"), File: f}); l.Status != Fail || !strings.Contains(l.Message, "boom") {
		t.Fatalf("err: %+v", l)
	}
}

func TestProveRegistrationAndOrder(t *testing.T) {
	names := func(r Result) []string {
		var s []string
		for _, l := range r.Legs {
			s = append(s, l.Name)
		}
		return s
	}
	want := []string{LegRegistration, LegRewrite, LegSandbox, LegReadRule, LegShadow}
	r := run(context.Background(), Options{HookErr: "no hooks registered in x: run it"}, nil)
	if !slices.Equal(names(r), want) || r.OK() {
		t.Fatalf("legs %v ok %v", names(r), r.OK())
	}
	for _, l := range r.Legs[1:4] {
		if l.Status != Fail || l.Message != "not run (prove: registration failed)" {
			t.Fatalf("%+v", l)
		}
	}
	if r.Legs[0].Status != Fail || r.Legs[0].Message != "no hooks registered in x: run it" || r.Legs[4].Status != Pass {
		t.Fatalf("%+v", r.Legs)
	}
	r = run(context.Background(), Options{Hook: Hook{Text: "/x hook", File: "~/s.json"}, PrepareErr: errors.New("disk full")}, nil)
	if !slices.Equal(names(r), want) || r.Legs[0].Status != Pass || !strings.Contains(r.Legs[0].Message, "~/s.json: /x hook (timeout 10 s)") ||
		!strings.Contains(r.Legs[0].Message, "shell form") {
		t.Fatalf("%+v", r.Legs)
	}
	for _, l := range r.Legs[1:4] {
		if l.Status != Fail || l.Message != "not run: could not prepare the throwaway tree: disk full" {
			t.Fatalf("%+v", l)
		}
	}
}

func TestProveRunWritesOnlyThePolicyFile(t *testing.T) {
	if fi, err := os.Stat("/var/tmp"); err != nil || !fi.IsDir() {
		t.Skip("no /var/tmp")
	}
	e, err := demo.Prepare()
	if err != nil {
		t.Fatal(err)
	}
	defer e.Remove()
	walk := func() map[string]bool {
		m := map[string]bool{}
		filepath.WalkDir(e.Base, func(p string, d fs.DirEntry, err error) error {
			if err == nil {
				m[p] = true
			}
			return nil
		})
		return m
	}
	before := walk()
	call, n := replies(reply{})
	res := run(context.Background(), Options{Hook: Hook{Argv: []string{"/nonexistent"}, Binary: "/nonexistent", Text: "/nonexistent hook"},
		Env: e, Environ: os.Environ(), Python: "/usr/bin/python3"}, call)
	if res.OK() || *n != 2 { // one Bash call, one Read call
		t.Fatalf("ok %v calls %d legs %+v", res.OK(), *n, res.Legs)
	}
	after := walk()
	var added []string
	for p := range after {
		if !before[p] {
			added = append(added, p)
		}
	}
	policyFile := filepath.Join(e.Cfg, "overrides.yaml")
	if len(added) != 1 || added[0] != policyFile {
		t.Fatalf("added %v; want only %s", added, policyFile)
	}
	fi, err := os.Stat(policyFile)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("policy file: %v %v", fi, err)
	}
	if b, _ := os.ReadFile(policyFile); string(b) != PolicyYAML {
		t.Fatalf("policy file text %q", b)
	}
}

func TestProveDeadline(t *testing.T) {
	s := time.Second
	cases := []struct {
		name string
		got  time.Duration
		want time.Duration
	}{
		{"arithmetic", ProveDeadline(10*s, 20*s), 4*10*s + 20*s + 5*s},
		{"defaults", Options{}.Deadline(), 4*DefaultHookTimeout + DefaultRunTimeout + 5*s},
		{"registered 15 s", Options{Hook: Hook{Timeout: 15 * s}}.Deadline(), 4*15*s + DefaultRunTimeout + 5*s},
		{"registered 120 s is capped", Options{Hook: Hook{Timeout: 120 * s}}.Deadline(), 4*MaxHookTimeout + DefaultRunTimeout + 5*s},
		{"overrides", Options{Hook: Hook{Timeout: 120 * s}, HookTimeout: s, RunTimeout: 2 * s}.Deadline(), 4*s + 2*s + 5*s},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s: %s, want %s", c.name, c.got, c.want)
		}
	}
	if MaxHookTimeout != 30*s {
		t.Fatalf("MaxHookTimeout %s, want 30s", MaxHookTimeout)
	}
	if got := hookTimeout(Hook{Timeout: 120 * s}); got != MaxHookTimeout {
		t.Fatalf("the call timeout for a 120 s registration is %s, want the cap", got)
	}
	if m := registrationLeg(Hook{Text: "/x hook", File: "~/s.json", Timeout: 120 * s, Binary: "/x"}).Message; !strings.Contains(m, "(timeout 120 s capped at 30 s for the proof)") {
		t.Fatalf("capped registration message: %q", m)
	}
	if m := registrationLeg(Hook{Text: "/x hook", File: "~/s.json", Timeout: 30 * s, Binary: "/x"}).Message; !strings.Contains(m, "(timeout 30 s)") || strings.Contains(m, "capped") {
		t.Fatalf("uncapped registration message: %q", m)
	}
}
