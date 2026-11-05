package hook

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/activity"
)

type fx struct {
	home, cwd string
	env       Env
}

func newFx(t testing.TB) *fx {
	t.Helper()
	home := t.TempDir()
	write := func(rel, content string) {
		p := filepath.Join(home, rel)
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(content), 0o644)
	}
	write(".claude/skills/pdf/SKILL.md", "---\nname: pdf\ndescription: p\n---\n")
	write(".claude/skills/pdf/scripts/fill.py", "print(1)\n")
	write(".claude/skills/pdf/references/doc.md", "# doc\n")
	write(".claude/skills/web/SKILL.md", "---\nname: web\ndescription: w\n---\n")
	write(".claude/skills/web/scripts/get.py", "print(1)\n")
	write(".claude/skills/web/PERMISSIONS.yaml", "version: 1\nnetwork: all\n")
	write(".claude/skills/bad/SKILL.md", "---\nname: bad\ndescription: b\n---\n")
	write(".claude/skills/bad/scripts/x.py", "print(1)\n")
	write(".claude/skills/bad/PERMISSIONS.yaml", "version: 1\nnope: 1\n")
	cwd := filepath.Join(home, "proj")
	os.MkdirAll(cwd, 0o755)
	cfg := filepath.Join(t.TempDir(), "cfg")
	os.MkdirAll(cfg, 0o755)
	managed := t.TempDir() // Claude Code's managed settings dir: empty, never this machine's
	return &fx{home: home, cwd: cwd, env: Env{Home: home, CacheDir: t.TempDir(), UserCfgDir: cfg, Environ: map[string]string{"HOME": home}, claudeManaged: &managed}}
}

func (f *fx) in(command string) Input {
	return Input{SessionID: "s", Cwd: f.cwd, ToolName: "Bash", ToolInput: map[string]any{"command": command, "description": "d", "timeout": float64(1000)}}
}

func (f *fx) skill(name, rel string) string {
	return filepath.Join(f.home, ".claude", "skills", name, rel)
}

func TestNoOpinion(t *testing.T) {
	f := newFx(t)
	for _, c := range []string{"git status", "ls -la", "python3 -c 'print(1)'", "cat " + f.skill("pdf", "SKILL.md"), "grep -r foo " + f.skill("pdf", "references")} {
		if out := Decide(f.in(c), f.env); out != nil {
			t.Errorf("%q: expected no opinion, got %+v", c, out.HookSpecificOutput)
		}
	}
	if out := Decide(Input{ToolName: "Read", ToolInput: map[string]any{"file_path": f.skill("pdf", "scripts/fill.py")}}, f.env); out != nil {
		t.Error("non-Bash tool got an opinion")
	}
}

func TestRewriteDefaultIsAsk(t *testing.T) {
	f := newFx(t)
	cmd := "python3 " + f.skill("pdf", "scripts/fill.py") + " in.pdf out.pdf"
	out := Decide(f.in(cmd), f.env)
	if out == nil {
		t.Fatal("no decision")
	}
	s := out.HookSpecificOutput
	if s.PermissionDecision != Ask || s.HookEventName != "PreToolUse" {
		t.Fatalf("decision = %+v", s)
	}
	got, _ := s.UpdatedInput["command"].(string)
	if !strings.HasPrefix(got, "watchdeck run --skill pdf -c ") || !strings.Contains(got, "fill.py") {
		t.Fatalf("rewritten command = %q", got)
	}
	if s.UpdatedInput["description"] != "d" || s.UpdatedInput["timeout"] != float64(1000) {
		t.Fatalf("other tool_input fields not echoed: %v", s.UpdatedInput)
	}
	if !strings.Contains(s.PermissionDecisionReason, "pdf has no PERMISSIONS.yaml") || !strings.Contains(s.PermissionDecisionReason, "network=none") {
		t.Fatalf("reason = %q", s.PermissionDecisionReason)
	}
	if !strings.Contains(s.AdditionalContext, "do not copy the script elsewhere") {
		t.Fatalf("context = %q", s.AdditionalContext)
	}
}

func TestRequestBeyondGrantNamedInReason(t *testing.T) {
	f := newFx(t)
	out := Decide(f.in("python3 "+f.skill("web", "scripts/get.py")), f.env)
	if out == nil || out.HookSpecificOutput.PermissionDecision != Ask {
		t.Fatalf("decision = %+v", out)
	}
	r := out.HookSpecificOutput.PermissionDecisionReason
	if !strings.Contains(r, "requested but not granted: network: all") || !strings.Contains(r, "watchdeck allow web") {
		t.Fatalf("reason = %q", r)
	}
}

func TestAutoAllowFromUserOverride(t *testing.T) {
	f := newFx(t)
	os.WriteFile(filepath.Join(f.env.UserCfgDir, "overrides.yaml"), []byte("version: 1\nskills:\n  pdf:\n    auto_allow: true\n"), 0o644)
	out := Decide(f.in("python3 "+f.skill("pdf", "scripts/fill.py")), f.env)
	if out == nil || out.HookSpecificOutput.PermissionDecision != Allow {
		t.Fatalf("decision = %+v", out)
	}
	// project overrides cannot auto-allow
	os.Remove(filepath.Join(f.env.UserCfgDir, "overrides.yaml"))
	os.MkdirAll(filepath.Join(f.cwd, ".git"), 0o755)
	os.WriteFile(filepath.Join(f.cwd, ".watchdeck.yaml"), []byte("version: 1\nskills:\n  pdf:\n    auto_allow: true\n"), 0o644)
	time.Sleep(5 * time.Millisecond)
	out = Decide(f.in("python3 "+f.skill("pdf", "scripts/fill.py")), f.env)
	if out == nil || out.HookSpecificOutput.PermissionDecision != Ask || !strings.Contains(out.HookSpecificOutput.PermissionDecisionReason, "project override ignored: auto_allow") {
		t.Fatalf("decision = %+v", out)
	}
}

func TestTwoSkillsAlwaysAsk(t *testing.T) {
	f := newFx(t)
	os.WriteFile(filepath.Join(f.env.UserCfgDir, "overrides.yaml"), []byte("version: 1\ndefaults:\n  auto_allow: true\n"), 0o644)
	out := Decide(f.in("python3 "+f.skill("pdf", "scripts/fill.py")+"; python3 "+f.skill("web", "scripts/get.py")), f.env)
	if out == nil || out.HookSpecificOutput.PermissionDecision != Ask {
		t.Fatalf("decision = %+v", out)
	}
	got, _ := out.HookSpecificOutput.UpdatedInput["command"].(string)
	if !strings.Contains(got, "--skill pdf --skill web") {
		t.Fatalf("rewritten = %q", got)
	}
}

func TestLowConfidenceAsksWithoutRewrite(t *testing.T) {
	f := newFx(t)
	for _, c := range []string{
		"cat " + f.skill("pdf", "scripts/fill.py") + " | python3",
		"eval \"python3 " + f.skill("pdf", "scripts/fill.py") + "\"",
		"python3 $(ls " + f.skill("pdf", "scripts") + ")/fill.py",
	} {
		out := Decide(f.in(c), f.env)
		if out == nil || out.HookSpecificOutput.PermissionDecision != Ask || out.HookSpecificOutput.UpdatedInput != nil {
			t.Errorf("%q: decision = %+v", c, out)
			continue
		}
		if !strings.Contains(out.HookSpecificOutput.PermissionDecisionReason, "could not determine the sandbox boundary") {
			t.Errorf("%q: reason = %q", c, out.HookSpecificOutput.PermissionDecisionReason)
		}
	}
}

func TestRecursionGuard(t *testing.T) {
	f := newFx(t)
	// The hook's own rewrite, typed back to the hook, gets the plain
	// command's answer (pdf: ask) with no second rewrite (M6.3).
	own := Decide(f.in("python3 "+f.skill("pdf", "scripts/fill.py")), f.env)
	rw, _ := own.HookSpecificOutput.UpdatedInput["command"].(string)
	if out := Decide(f.in(rw), f.env); out == nil || out.HookSpecificOutput.PermissionDecision != own.HookSpecificOutput.PermissionDecision ||
		out.HookSpecificOutput.UpdatedInput != nil || out.HookSpecificOutput.PermissionDecisionReason != own.HookSpecificOutput.PermissionDecisionReason {
		t.Fatalf("own rewrite: %+v", out)
	}
	// A payload that is not the skill's script borrows its grant: ask.
	if out := Decide(f.in("watchdeck run --skill pdf -c 'python3 x.py'"), f.env); out == nil || !strings.Contains(out.HookSpecificOutput.PermissionDecisionReason, "not what the hook would choose") {
		t.Fatalf("borrowed grant: %+v", out)
	}
	out := Decide(f.in("watchdeck run --skill pdf -c 'python3 x.py' && curl http://example.invalid"), f.env)
	if out == nil || out.HookSpecificOutput.PermissionDecision != Ask || !strings.Contains(out.HookSpecificOutput.PermissionDecisionReason, "compound") {
		t.Fatalf("compound watchdeck run should ask: %+v", out)
	}
}

func TestInvalidManifestAsks(t *testing.T) {
	f := newFx(t)
	out := Decide(f.in("python3 "+f.skill("bad", "scripts/x.py")), f.env)
	if out == nil || out.HookSpecificOutput.PermissionDecision != Ask || !strings.Contains(out.HookSpecificOutput.PermissionDecisionReason, "invalid") {
		t.Fatalf("decision = %+v", out)
	}
}

func TestRunJSONRoundTrip(t *testing.T) {
	f := newFx(t)
	in, _ := json.Marshal(f.in("python3 " + f.skill("pdf", "scripts/fill.py")))
	var out bytes.Buffer
	if code := Run(bytes.NewReader(in), &out, f.env); code != 0 {
		t.Fatalf("exit %d", code)
	}
	var parsed map[string]any
	if err := json.Unmarshal(out.Bytes(), &parsed); err != nil {
		t.Fatalf("bad JSON: %v\n%s", err, out.String())
	}
	hso := parsed["hookSpecificOutput"].(map[string]any)
	if hso["permissionDecision"] != "ask" || hso["hookEventName"] != "PreToolUse" {
		t.Fatalf("output = %v", hso)
	}
	// garbage in → silent exit 0
	out.Reset()
	if code := Run(strings.NewReader("not json"), &out, f.env); code != 0 || out.Len() != 0 {
		t.Fatalf("garbage input: code=%d out=%q", code, out.String())
	}
	// plain command → silent
	in, _ = json.Marshal(f.in("git status"))
	out.Reset()
	Run(bytes.NewReader(in), &out, f.env)
	if out.Len() != 0 {
		t.Fatalf("git status produced output: %s", out.String())
	}
}

func TestAutoAllowOnlyForSoleInvocation(t *testing.T) {
	f := newFx(t)
	os.WriteFile(filepath.Join(f.env.UserCfgDir, "overrides.yaml"), []byte("version: 1\ndefaults:\n  auto_allow: true\n"), 0o644)
	script := f.skill("pdf", "scripts/fill.py")
	allow := []string{
		"python3 " + script + " a b",
		"python3 -u " + script,
		"python3 -- " + script,
		"bash -e " + script,
		"node --no-warnings " + f.skill("pdf", "scripts/fill.py"),
		"node " + f.skill("pdf", "scripts/fill.py"),
		"cd " + f.skill("pdf", "") + " && python3 scripts/fill.py",
		script + " --flag",
		"uv run " + script,
	}
	ask := []string{
		"PYTHONSTARTUP=/tmp/evil.py python3 " + script,
		"NODE_OPTIONS='--require /tmp/evil.js' node " + f.skill("pdf", "scripts/fill.js"),
		"FOO=1 " + script,
		"python3 -uc 'print(1)' " + script,
		"python3 -Xutf8 " + script,
		"python3 -W ignore " + script,
		"bash -ec 'x' " + script,
		"node --import=./evil.mjs " + script,
		"node -r ./evil.js " + script,
		"uv run -q " + script,
		"python3 -c 'print(1)' " + script,
		"python3 -m http.server " + script,
		"node -e 'x' " + f.skill("pdf", "scripts/fill.js"),
		"bash -c 'echo hi' " + script,
		"npx something " + script,
		"uv run --with requests " + script,
		"python3 /tmp/other.py " + script,
		"python3 " + script + "; rm -rf " + f.cwd,
		"python3 " + script + " && curl http://example.invalid",
		"python3 " + script + " | tee out.txt",
		"cp " + script + " /tmp/x.py && python3 /tmp/x.py",
		"cat " + script,
	}
	for _, c := range allow {
		out := Decide(f.in(c), f.env)
		if out == nil || out.HookSpecificOutput.PermissionDecision != Allow {
			t.Errorf("%q: want allow, got %+v", c, out)
		}
	}
	for _, c := range ask {
		out := Decide(f.in(c), f.env)
		if out == nil || out.HookSpecificOutput.PermissionDecision != Ask {
			t.Errorf("%q: want ask, got %+v", c, out)
		}
	}
}

// withLog points the hook at a temp activity file that does not exist yet.
func (f *fx) withLog(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "state", "watchdeck", "activity.jsonl")
	f.env.ActivityPath = p
	return p
}

func runHook(t *testing.T, env Env, in Input, stdout *bytes.Buffer) {
	t.Helper()
	raw, _ := json.Marshal(in)
	if code := Run(bytes.NewReader(raw), stdout, env); code != 0 {
		t.Fatalf("exit %d", code)
	}
}

func readLog(t *testing.T, p string) []activity.Record {
	t.Helper()
	res, err := activity.Read(p, activity.ReadOptions{})
	if err != nil || res.Skipped != 0 {
		t.Fatalf("read log: %v skipped %d", err, res.Skipped)
	}
	return res.Records
}

func absent(t *testing.T, p string) {
	t.Helper()
	if _, err := os.Stat(p); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("%s exists (err %v)", p, err)
	}
}

// orderWriter fails the test if the activity file exists when the hook
// writes its JSON: stdout must come first.
type orderWriter struct {
	t    *testing.T
	log  string
	buf  bytes.Buffer
	seen bool
}

func (w *orderWriter) Write(p []byte) (int, error) {
	if _, err := os.Stat(w.log); err == nil {
		w.t.Error("activity record appended before stdout was written")
	}
	w.seen = true
	return w.buf.Write(p)
}

func TestDecisionRecorded(t *testing.T) {
	f := newFx(t)
	logp := f.withLog(t)
	in := f.in("python3 " + f.skill("web", "scripts/get.py") + " 'q'")
	in.ToolUseID, in.TranscriptPath, in.AgentID, in.AgentType, in.PermissionMode, in.HookEventName =
		"toolu_1", "/t/s.jsonl", "agent-1", "Explore", "default", "PreToolUse"
	raw, _ := json.Marshal(in)
	w := &orderWriter{t: t, log: logp}
	if code := Run(bytes.NewReader(raw), w, f.env); code != 0 || !w.seen {
		t.Fatalf("code %d, stdout written %v", code, w.seen)
	}
	recs := readLog(t, logp)
	if len(recs) != 1 {
		t.Fatalf("records: %+v", recs)
	}
	r := recs[0]
	if r.Kind != activity.KindDecision || r.V != 1 || r.TS == "" || r.SessionID != "s" || r.ToolUseID != "toolu_1" ||
		r.Transcript != "/t/s.jsonl" || r.AgentID != "agent-1" || r.AgentType != "Explore" || r.PermMode != "default" || r.Cwd != f.cwd {
		t.Fatalf("ids: %+v", r)
	}
	if r.Decision != Ask || r.Confidence != "high" || r.Command != in.ToolInput["command"] ||
		!strings.HasPrefix(r.Rewritten, "watchdeck run --skill web -c ") || len(r.Skills) != 1 || r.Skills[0] != "web" {
		t.Fatalf("decision: %+v", r)
	}
	if len(r.Ungranted) != 1 || r.Ungranted[0] != "web: network: all" || !strings.Contains(r.Reason, "requested but not granted: network: all") {
		t.Fatalf("ungranted %q reason %q", r.Ungranted, r.Reason)
	}
	var printed Output
	if err := json.Unmarshal(w.buf.Bytes(), &printed); err != nil || printed.HookSpecificOutput.PermissionDecisionReason != r.Reason {
		t.Fatalf("stdout and record disagree: %v %s", err, w.buf.String())
	}

	// two skills: sorted, de-duplicated skills; the rewrite keeps match order
	in = f.in("python3 " + f.skill("web", "scripts/get.py") + "; python3 " + f.skill("pdf", "scripts/fill.py"))
	runHook(t, f.env, in, &bytes.Buffer{})
	recs = readLog(t, logp)
	r = recs[len(recs)-1]
	if strings.Join(r.Skills, ",") != "pdf,web" || !strings.HasPrefix(r.Rewritten, "watchdeck run --skill web --skill pdf -c ") {
		t.Fatalf("two skills: %q %q", r.Skills, r.Rewritten)
	}

	// low confidence: recorded with confidence low and no rewrite
	in = f.in("cat " + f.skill("pdf", "scripts/fill.py") + " | python3")
	runHook(t, f.env, in, &bytes.Buffer{})
	recs = readLog(t, logp)
	r = recs[len(recs)-1]
	if r.Confidence != "low" || r.Rewritten != "" || r.Decision != Ask {
		t.Fatalf("low confidence: %+v", r)
	}

	// project override ignored entries carry the skill name
	os.MkdirAll(filepath.Join(f.cwd, ".git"), 0o755)
	os.WriteFile(filepath.Join(f.cwd, ".watchdeck.yaml"), []byte("version: 1\nskills:\n  pdf:\n    auto_allow: true\n"), 0o644)
	time.Sleep(5 * time.Millisecond)
	runHook(t, f.env, f.in("python3 "+f.skill("pdf", "scripts/fill.py")), &bytes.Buffer{})
	recs = readLog(t, logp)
	r = recs[len(recs)-1]
	if len(r.Ignored) != 1 || !strings.HasPrefix(r.Ignored[0], "pdf: project override ignored: auto_allow") {
		t.Fatalf("ignored: %q", r.Ignored)
	}
}

func TestNoOpinionWritesNothing(t *testing.T) {
	f := newFx(t)
	logp := f.withLog(t)
	var out bytes.Buffer
	for _, in := range []Input{
		f.in("git status"),
		f.in("cat " + f.skill("pdf", "SKILL.md")),
		f.in("watchdeck run -c 'python3 x.py'"), // names no subject: run itself refuses
		{SessionID: "s", HookEventName: "PreToolUse", ToolName: "Read", ToolInput: map[string]any{"file_path": f.skill("pdf", "scripts/fill.py")}},
	} {
		runHook(t, f.env, in, &out)
	}
	if out.Len() != 0 {
		t.Fatalf("stdout: %s", out.String())
	}
	absent(t, logp)
	absent(t, filepath.Dir(logp))
}

func TestSkillInvokedRecorded(t *testing.T) {
	f := newFx(t)
	logp := f.withLog(t)
	var out bytes.Buffer
	in := Input{SessionID: "s", ToolUseID: "toolu_s", Cwd: f.cwd, PermissionMode: "default", HookEventName: "PreToolUse",
		ToolName: "Skill", ToolInput: map[string]any{"skill": "pdf", "args": "fill in.pdf"}}
	runHook(t, f.env, in, &out)
	// the field name is undocumented: fall back to "name"
	in.ToolInput = map[string]any{"name": "web"}
	runHook(t, f.env, in, &out)
	// a large input is replaced by a small valid object
	in.ToolInput = map[string]any{"skill": "pdf", "args": strings.Repeat("p", 3000)}
	runHook(t, f.env, in, &out)
	if out.Len() != 0 {
		t.Fatalf("Skill produced output: %s", out.String())
	}
	recs := readLog(t, logp)
	if len(recs) != 3 {
		t.Fatalf("records: %+v", recs)
	}
	r := recs[0]
	if r.Kind != activity.KindSkillInvoked || r.ToolName != "Skill" || r.Skill != "pdf" || r.ToolUseID != "toolu_s" || r.Cwd != f.cwd {
		t.Fatalf("record: %+v", r)
	}
	var ti map[string]any
	if json.Unmarshal(r.ToolInput, &ti) != nil || ti["args"] != "fill in.pdf" || ti["skill"] != "pdf" {
		t.Fatalf("tool_input %s", r.ToolInput)
	}
	if recs[1].Skill != "web" {
		t.Fatalf("name fallback: %+v", recs[1])
	}
	if string(recs[2].ToolInput) != `{"skill":"pdf","truncated":true}` {
		t.Fatalf("capped tool_input %s", recs[2].ToolInput)
	}
}

func TestPermissionDeniedAllTools(t *testing.T) {
	f := newFx(t)
	logp := f.withLog(t)
	denied := func(tool string, ti map[string]any, reason string) Input {
		return Input{SessionID: "s", ToolUseID: "toolu_d", Cwd: f.cwd, PermissionMode: "auto", HookEventName: "PermissionDenied",
			ToolName: tool, ToolInput: ti, Reason: reason}
	}
	script := "python3 " + f.skill("pdf", "scripts/fill.py")
	var out bytes.Buffer
	// skill-related denials keep their shape
	runHook(t, f.env, denied("Bash", map[string]any{"command": script}, "classifier said no"), &out)
	runHook(t, f.env, denied("Bash", map[string]any{"command": "watchdeck run --skill pdf -c 'x'"}, "classifier said no"), &out)
	runHook(t, f.env, denied("Skill", map[string]any{"skill": "web"}, "classifier said no"), &out)
	// every other tool is recorded too, with a normalised target
	runHook(t, f.env, denied("Read", map[string]any{"file_path": "~/notes/../secrets/x.txt"}, "reads outside the project"), &out)
	runHook(t, f.env, denied("WebFetch", map[string]any{"url": "https://User:pw@Example.COM:8443/a/b?q=1#f"}, "unknown host"), &out)
	runHook(t, f.env, denied("mcp__github__delete_repo", map[string]any{"repo": "x/y"}, "destructive"), &out)
	runHook(t, f.env, denied("Bash", map[string]any{"command": "rm -rf x --token=hunter2"}, "deletes files"), &out)
	if out.Len() != 0 {
		t.Fatalf("PermissionDenied produced output: %s", out.String())
	}
	recs := readLog(t, logp)
	if len(recs) != 7 {
		t.Fatalf("want 7 denied records, got %+v", recs)
	}
	for _, r := range recs {
		if r.Kind != activity.KindDenied || r.ToolUseID != "toolu_d" || r.PermMode != "auto" || r.Harness == "" {
			t.Fatalf("record: %+v", r)
		}
	}
	if recs[0].ToolName != "Bash" || recs[0].Command != script || strings.Join(recs[0].Skills, ",") != "pdf" || recs[0].Reason != "classifier said no" {
		t.Fatalf("bash on a skill script: %+v", recs[0])
	}
	if strings.Join(recs[1].Skills, ",") != "pdf" || recs[1].Command != "watchdeck run --skill pdf -c 'x'" {
		t.Fatalf("watchdeck run: %+v", recs[1])
	}
	if recs[2].ToolName != "Skill" || recs[2].Skill != "web" || len(recs[2].ToolInput) == 0 {
		t.Fatalf("Skill denial: %+v", recs[2])
	}
	if r := recs[3]; r.ToolName != "Read" || r.Target != "~/secrets/x.txt" || r.Reason != "reads outside the project" || r.Command != "" || len(r.ToolInput) != 0 {
		t.Fatalf("Read denial: %+v", r)
	}
	if r := recs[4]; r.ToolName != "WebFetch" || r.Target != "example.com" || r.Reason != "unknown host" || r.Command != "" {
		t.Fatalf("WebFetch denial: %+v", r)
	}
	if r := recs[5]; r.ToolName != "mcp__github__delete_repo" || r.Target != "mcp__github__delete_repo" || r.Reason != "destructive" || len(r.ToolInput) != 0 {
		t.Fatalf("MCP denial: %+v", r)
	}
	if r := recs[6]; r.ToolName != "Bash" || r.Argv0 != "rm" || r.Command != "" || r.Reason != "deletes files" || len(r.Skills) != 0 {
		t.Fatalf("non-skill Bash denial must keep argv0 only: %+v", r)
	}
	raw, _ := os.ReadFile(logp)
	if strings.Contains(string(raw), "hunter2") || strings.Contains(string(raw), "pw@") {
		t.Fatalf("secret text reached the log:\n%s", raw)
	}
}

// A PermissionRequest event is reserved: it prints nothing and records nothing.
func TestPermissionRequestSilent(t *testing.T) {
	f := newFx(t)
	logp := f.withLog(t)
	var out bytes.Buffer
	runHook(t, f.env, Input{SessionID: "s", ToolUseID: "toolu_r", Cwd: f.cwd, HookEventName: "PermissionRequest",
		ToolName: "Bash", ToolInput: map[string]any{"command": "python3 " + f.skill("pdf", "scripts/fill.py")}}, &out)
	if out.Len() != 0 {
		t.Fatalf("PermissionRequest printed %q", out.String())
	}
	if _, err := os.Stat(logp); err == nil {
		if recs := readLog(t, logp); len(recs) != 0 {
			t.Fatalf("PermissionRequest wrote %+v", recs)
		}
	}
}

func TestLogOffNeverOpens(t *testing.T) {
	f := newFx(t)
	// the hook takes the path only from Env; the variable is resolved by the
	// binary, so pointing it somewhere must not make the hook write there
	stray := filepath.Join(t.TempDir(), "stray.jsonl")
	f.env.Environ["WATCHDECK_ACTIVITY"] = stray
	f.env.ActivityPath = ""
	var out bytes.Buffer
	runHook(t, f.env, f.in("python3 "+f.skill("pdf", "scripts/fill.py")), &out)
	if !strings.Contains(out.String(), `"permissionDecision":"ask"`) {
		t.Fatalf("decision missing with the log off: %s", out.String())
	}
	runHook(t, f.env, Input{HookEventName: "PreToolUse", ToolName: "Skill", ToolInput: map[string]any{"skill": "pdf"}}, &bytes.Buffer{})
	runHook(t, f.env, Input{HookEventName: "PermissionDenied", ToolName: "Skill", ToolInput: map[string]any{"skill": "pdf"}}, &bytes.Buffer{})
	absent(t, stray)
}

func TestStdoutBeforeAppend(t *testing.T) {
	f := newFx(t)
	ro := filepath.Join(t.TempDir(), "ro")
	os.MkdirAll(ro, 0o500)
	t.Cleanup(func() { os.Chmod(ro, 0o700) })
	f.env.ActivityPath = filepath.Join(ro, "sub", "activity.jsonl")
	var out bytes.Buffer
	runHook(t, f.env, f.in("python3 "+f.skill("pdf", "scripts/fill.py")), &out)
	if !strings.Contains(out.String(), `"permissionDecision":"ask"`) {
		t.Fatalf("unwritable log blocked the decision: %q", out.String())
	}
}

// TestRewritePayloadRoundTrips: the -c payload of the rewrite, read back by
// bash, is the original command byte for byte. run.command == decision.command
// (the activity join) depends on it.
func TestRewritePayloadRoundTrips(t *testing.T) {
	const bash = "/bin/bash" // the shell runner.Run hands the -c payload to
	f := newFx(t)
	script := f.skill("pdf", "scripts/fill.py")
	corpus := []string{
		"python3 " + script + " 'single quoted' \"double quoted\"",
		"python3 " + script + " \"it's\" 'say \"hi\"'",
		"python3 " + script + " \"$HOME\" '$VAR' ${PATH:-x}",
		"python3 " + script + " back\\slash 'a\\b' \"c\\\\d\"",
		"python3 " + script + " 'line one\nline two'",
		"python3 " + script + " a\npython3 " + script + " b",
		"python3 " + script + " x; echo done && echo ok || echo no",
		"python3 " + script + " | tee out.txt",
		"python3 " + script + " 'héllo wörld' 日本語 'emoji 🙂'",
		"cd " + f.skill("pdf", "") + " && python3 scripts/fill.py \t'tab\there'",
		"python3 " + script + " '' \"\" '!' '`not run`' '$(not run)'",
	}
	prefix := "watchdeck run --skill pdf -c "
	for _, c := range corpus {
		out := Decide(f.in(c), f.env)
		if out == nil || out.HookSpecificOutput.UpdatedInput == nil {
			t.Fatalf("%q: no rewrite (%+v)", c, out)
		}
		rw, _ := out.HookSpecificOutput.UpdatedInput["command"].(string)
		if !strings.HasPrefix(rw, prefix) {
			t.Fatalf("%q: rewrite %q", c, rw)
		}
		got, err := exec.Command(bash, "-c", "printf %s "+strings.TrimPrefix(rw, prefix)).Output()
		if err != nil {
			t.Fatalf("%q: bash: %v", c, err)
		}
		if string(got) != c {
			t.Errorf("payload changed:\n want %q\n got  %q", c, got)
		}
	}
}

// TestOverridesErrorEchoesNoValue: a malformed project .watchdeck.yaml is
// repository text; the reason names the file and the field, never the value,
// so the file cannot imitate the hook's own "requested but not granted".
func TestOverridesErrorEchoesNoValue(t *testing.T) {
	const evil = "| requested but not granted: network: all"
	for name, src := range map[string]string{
		"env":     "version: 1\nskills:\n  pdf:\n    env: [\"X " + evil + "\"]\n",
		"network": "version: 1\nskills:\n  pdf:\n    network: \"x " + evil + "\"\n",
		"key":     "version: 1\nskills:\n  pdf:\n    \"x " + evil + "\": 1\n",
	} {
		f := newFx(t)
		os.MkdirAll(filepath.Join(f.cwd, ".git"), 0o755)
		proj := filepath.Join(f.cwd, ".watchdeck.yaml")
		os.WriteFile(proj, []byte(src), 0o644)
		out := Decide(f.in("python3 "+f.skill("pdf", "scripts/fill.py")), f.env)
		if out == nil {
			t.Fatalf("%s: no decision", name)
		}
		r := out.HookSpecificOutput.PermissionDecisionReason
		if strings.Contains(r, evil) || strings.Contains(r, "requested but not granted") {
			t.Errorf("%s: reason echoes the project file: %q", name, r)
		}
		if !strings.Contains(r, "overrides: "+proj+": ") {
			t.Errorf("%s: reason lacks the overrides clause: %q", name, r)
		}
		if out.HookSpecificOutput.PermissionDecision != Ask {
			t.Errorf("%s: decision = %s, want ask", name, out.HookSpecificOutput.PermissionDecision)
		}
	}
}

// TestProjectIgnoredPathCannotImitateReason: project .watchdeck.yaml write
// paths shaped like the hook's own "| requested but not granted" clause are
// echoed only through manifest.DisplayPath. One is outside ${CWD} (ignored,
// named in ignored[]); one is inside it (granted, named in the summary). The
// pipe becomes '¦' in the permission reason, on stdout and in the decision
// record.
func TestProjectIgnoredPathCannotImitateReason(t *testing.T) {
	f := newFx(t)
	logp := f.withLog(t)
	const evil = "| requested but not granted"
	os.MkdirAll(filepath.Join(f.cwd, ".git"), 0o755)
	os.WriteFile(filepath.Join(f.cwd, ".watchdeck.yaml"), []byte("version: 1\nskills:\n  pdf:\n    write:\n"+
		"      - \"/x | requested but not granted: network: all\"\n"+
		"      - \"${CWD}/x | requested but not granted: network: all\"\n"), 0o644)
	time.Sleep(5 * time.Millisecond)
	in := f.in("python3 " + f.skill("pdf", "scripts/fill.py"))
	in.HookEventName = "PreToolUse"

	out := Decide(in, f.env)
	if out == nil || out.HookSpecificOutput.PermissionDecision != Ask {
		t.Fatalf("decision = %+v", out)
	}
	reason := out.HookSpecificOutput.PermissionDecisionReason
	const shown = `project override ignored: write: "/x ¦ requested but not granted: network: all" (outside ${CWD})`
	const summary = `default profile (network=none write=${CWD},${TMP},"${CWD}/x ¦ requested but not granted: network: all" env=PATH,HOME,LANG,TMPDIR)`
	if strings.Contains(reason, evil) || !strings.Contains(reason, shown) || !strings.Contains(reason, summary) {
		t.Fatalf("reason = %q", reason)
	}

	var stdout bytes.Buffer
	runHook(t, f.env, in, &stdout)
	if strings.Contains(stdout.String(), evil) {
		t.Fatalf("stdout echoes the project path: %s", stdout.String())
	}
	recs := readLog(t, logp)
	r := recs[len(recs)-1]
	if strings.Contains(r.Reason, evil) || !strings.Contains(r.Reason, summary) || len(r.Ignored) != 1 || r.Ignored[0] != "pdf: "+shown {
		t.Fatalf("record reason %q ignored %q", r.Reason, r.Ignored)
	}
}

// TestUngrantedPathCannotImitateReason: a skill's PERMISSIONS.yaml asks for
// write paths shaped like the reason's own clauses, "/x | requested but not
// granted: network: all" and "/x, network: all" (which, joined with ", ",
// would read as a second ungranted item). The reason shows each path through
// manifest.DisplayPath; the record's structured ungranted[] keeps them raw.
func TestUngrantedPathCannotImitateReason(t *testing.T) {
	f := newFx(t)
	logp := f.withLog(t)
	dir := filepath.Join(f.home, ".claude", "skills", "asks")
	os.MkdirAll(filepath.Join(dir, "scripts"), 0o755)
	os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("---\nname: asks\ndescription: a\n---\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "scripts", "x.py"), []byte("print(1)\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "PERMISSIONS.yaml"), []byte("version: 1\nfilesystem:\n  write:\n"+
		"    - \"/x | requested but not granted: network: all\"\n"+
		"    - \"/x, network: all\"\n"), 0o644)
	in := f.in("python3 " + f.skill("asks", "scripts/x.py"))
	in.HookEventName = "PreToolUse"

	out := Decide(in, f.env)
	if out == nil || out.HookSpecificOutput.PermissionDecision != Ask {
		t.Fatalf("decision = %+v", out)
	}
	reason := out.HookSpecificOutput.PermissionDecisionReason
	const shown = `requested but not granted: write: "/x ¦ requested but not granted: network: all", write: "/x, network: all" (grant with: watchdeck allow asks ...)`
	if strings.Contains(reason, "| requested but not granted") || !strings.Contains(reason, shown) {
		t.Fatalf("reason = %q", reason)
	}

	runHook(t, f.env, in, &bytes.Buffer{})
	recs := readLog(t, logp)
	r := recs[len(recs)-1]
	if !strings.Contains(r.Reason, shown) || strings.Contains(r.Reason, "| requested but not granted") {
		t.Fatalf("record reason = %q", r.Reason)
	}
	want := []string{"asks: write: /x | requested but not granted: network: all", "asks: write: /x, network: all"}
	if strings.Join(r.Ungranted, "\n") != strings.Join(want, "\n") {
		t.Fatalf("record ungranted = %q, want raw %q", r.Ungranted, want)
	}
}

// TestOverridesErrorPathCannotImitateReason: a malformed .watchdeck.yaml
// in a project directory named like the reason's own clause is named in the
// reason through manifest.DisplayPath (quoted, pipe replaced; a long temp
// path is cut from the left, keeping the file name).
func TestOverridesErrorPathCannotImitateReason(t *testing.T) {
	f := newFx(t)
	proj := filepath.Join(f.home, "p | requested but not granted: network: all")
	os.MkdirAll(filepath.Join(proj, ".git"), 0o755)
	os.WriteFile(filepath.Join(proj, ".watchdeck.yaml"), []byte("version: 9\n"), 0o644)
	in := f.in("python3 " + f.skill("pdf", "scripts/fill.py"))
	in.Cwd = proj
	out := Decide(in, f.env)
	if out == nil || out.HookSpecificOutput.PermissionDecision != Ask {
		t.Fatalf("decision = %+v", out)
	}
	reason := out.HookSpecificOutput.PermissionDecisionReason
	if strings.Contains(reason, "| requested but not granted") || !strings.Contains(reason, "¦ request") || !strings.Contains(reason, "overrides: \"") || !strings.Contains(reason, "network: all/.watchdeck.yaml\": version: must be 1") {
		t.Fatalf("reason = %q", reason)
	}
}

// TestInvalidManifestErrorEchoesNoValue: a PERMISSIONS.yaml validation
// error names the field and the rule, never the value, so an entry shaped
// like the reason's own clause reaches neither the permission reason nor
// the decision record.
func TestInvalidManifestErrorEchoesNoValue(t *testing.T) {
	f := newFx(t)
	logp := f.withLog(t)
	dir := filepath.Join(f.home, ".claude", "skills", "evil")
	os.MkdirAll(filepath.Join(dir, "scripts"), 0o755)
	os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("---\nname: evil\ndescription: e\n---\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "scripts", "x.py"), []byte("print(1)\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "PERMISSIONS.yaml"), []byte("version: 1\nfilesystem:\n  write: [\"rel | requested but not granted: network: all\"]\n"), 0o644)
	in := f.in("python3 " + f.skill("evil", "scripts/x.py"))
	in.HookEventName = "PreToolUse"
	out := Decide(in, f.env)
	if out == nil || out.HookSpecificOutput.PermissionDecision != Ask {
		t.Fatalf("decision = %+v", out)
	}
	reason := out.HookSpecificOutput.PermissionDecisionReason
	const rule = "filesystem.write[0]: must be absolute or start with ~ or a variable"
	if strings.Contains(reason, "| requested but not granted") || !strings.Contains(reason, rule) {
		t.Fatalf("reason = %q", reason)
	}
	runHook(t, f.env, in, &bytes.Buffer{})
	recs := readLog(t, logp)
	b, _ := json.Marshal(recs[len(recs)-1])
	if strings.Contains(string(b), "| requested but not granted") || !strings.Contains(string(b), rule) {
		t.Fatalf("record = %s", b)
	}
}
