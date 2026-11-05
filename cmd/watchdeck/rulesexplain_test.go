package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
	"github.com/Panda-Taps-LLC/watchdeck/internal/rulebook"
)

// `watchdeck rules explain` (Plan 07 Task 1, 2026-10-20): the dry run.

// explainFixture is rulesEnv plus a project with a canary skill, a user
// rule that denies the literal EXPLAINLIT in Bash, and a Claude Code user
// settings file that denies Bash(curl *). It returns the env and the
// canary's script command.
func explainFixture(t *testing.T) (testEnv, string) {
	t.Helper()
	e := rulesEnv(t)
	if err := os.MkdirAll(filepath.Join(e.proj, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	skill := filepath.Join(e.proj, ".claude", "skills", "canary-basic")
	writeFile(t, filepath.Join(skill, "SKILL.md"), "---\nname: canary-basic\ndescription: Test fixture.\n---\n")
	writeFile(t, filepath.Join(skill, "scripts", "probe.py"), "print('ALLOWED')\n")
	writeFile(t, filepath.Join(e.cfg, paths.BinaryName, "overrides.yaml"), `version: 2
rules:
  - {id: no-explain-lit, tool: Bash, match: {literals: [EXPLAINLIT]}, action: deny, severity: high}
`)
	writeFile(t, filepath.Join(e.claude, "settings.json"), `{"permissions":{"deny":["Bash(curl *)"]}}`)
	// the project's own settings file: read for its Bash rules, never written
	writeFile(t, filepath.Join(e.proj, ".claude", "settings.json"), `{"permissions":{"ask":["Bash(git push:*)"]}}`)
	return e, "python3 " + filepath.Join(skill, "scripts", "probe.py") + " net"
}

func explain(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	return call(t, rulesCmd, append([]string{"explain"}, args...)...)
}

func TestRulesExplainDenyExit1(t *testing.T) {
	explainFixture(t)
	code, out, errs := explain(t, "--command", "echo EXPLAINLIT")
	if code != 1 {
		t.Fatalf("exit %d, want 1\n%s%s", code, out, errs)
	}
	for _, want := range []string{"Bash  echo EXPLAINLIT\n", "verdict: deny\n", "reason:  watchdeck: denied by policy: rule no-explain-lit", "rules:   user:no-explain-lit\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if errs != "" {
		t.Errorf("stderr: %q", errs)
	}
}

func TestRulesExplainAskForSkillScript(t *testing.T) {
	_, script := explainFixture(t)
	code, out, errs := explain(t, "--command", script)
	if code != 2 {
		t.Fatalf("exit %d, want 2\n%s%s", code, out, errs)
	}
	rw := paths.BinaryName + " run --skill canary-basic -c "
	for _, want := range []string{"verdict: ask  (rewritten to run under the sandbox: " + rw, "reason:  watchdeck: canary-basic has no PERMISSIONS.yaml"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "rules:") {
		t.Errorf("a rules line without a rule hit:\n%s", out)
	}
}

func TestRulesExplainNoOpinionExit0(t *testing.T) {
	explainFixture(t)
	code, out, errs := explain(t, "--command", "git status")
	if code != 0 {
		t.Fatalf("exit %d, want 0\n%s%s", code, out, errs)
	}
	if want := "Bash  git status\nverdict: allow  (no watchdeck rule applies; Claude Code decides as usual)\n"; out != want {
		t.Fatalf("output %q, want %q", out, want)
	}
	if errs != "" {
		t.Errorf("stderr: %q", errs)
	}
}

// TestRulesExplainLogOnlyIsNoOpinion: a log-only rule hit is named, and
// the verdict stays no opinion (the hook prints nothing for it).
func TestRulesExplainLogOnlyIsNoOpinion(t *testing.T) {
	e := rulesEnv(t)
	writeFile(t, filepath.Join(e.cfg, paths.BinaryName, "overrides.yaml"), `version: 2
rules:
  - {id: tf-plan, tool: Bash, match: {argv0: [terraform], regex: plan}, action: log}
`)
	code, out, _ := explain(t, "--command", "terraform plan")
	if code != 0 || !strings.Contains(out, "verdict: allow  (only a log rule applies: user:tf-plan; Claude Code decides as usual)") || !strings.Contains(out, "rules:   user:tf-plan\n") {
		t.Fatalf("exit %d\n%s", code, out)
	}
}

func TestRulesExplainNativeDeny(t *testing.T) {
	_, script := explainFixture(t)
	// The hook honours the person's Claude Code Bash rules before a
	// rewrite, so the command must name the skill's script.
	code, out, errs := explain(t, "--command", script+" && curl https://example.invalid")
	if code != 1 {
		t.Fatalf("exit %d, want 1\n%s%s", code, out, errs)
	}
	for _, want := range []string{"verdict: deny\n", "reason:  watchdeck: blocked by your Claude Code deny rule Bash(curl *) (user settings)", "rules:   claude-settings:Bash(curl *)\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	// Without a rewrite the hook leaves the call to Claude Code, whose own
	// rule then applies: no opinion here, and the note names the rule
	// (review of Task 1, check 4).
	code, out, errs = explain(t, "--command", "curl https://example.invalid")
	if code != 0 || errs != "" || !strings.Contains(out, "verdict: allow  (no watchdeck rule applies; Claude Code decides as usual)\n") ||
		!strings.Contains(out, "note:    your Claude Code deny rule Bash(curl *) (user settings) matches this command; Claude Code refuses it itself\n") ||
		strings.Contains(out, "rules:") {
		t.Fatalf("plain curl: exit %d, stderr %q\n%s", code, errs, out)
	}
	code, out, _ = explain(t, "--command", "curl https://example.invalid", "--json")
	var doc struct {
		Verdict    string `json:"verdict"`
		NativeRule *struct {
			Value string `json:"value"`
			Kind  string `json:"kind"`
			Scope string `json:"scope"`
		} `json:"native_rule"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil || code != 0 {
		t.Fatalf("json: %v, exit %d\n%s", err, code, out)
	}
	if doc.Verdict != "none" || doc.NativeRule == nil || doc.NativeRule.Value != "Bash(curl *)" || doc.NativeRule.Kind != "deny" || doc.NativeRule.Scope != "user" {
		t.Fatalf("json doc: %s", out)
	}
	code, _, errs = explain(t, "--command", "curl https://example.invalid", "--expect", "deny")
	if code != 1 || !strings.Contains(errs, "expected deny, got allow (no opinion); your Claude Code deny rule Bash(curl *) matches it") {
		t.Fatalf("expect deny on plain curl: exit %d, stderr %q", code, errs)
	}
	// an ask rule, from the project's settings file
	code, out, _ = explain(t, "--command", "git push origin main")
	if code != 0 || !strings.Contains(out, "note:    your Claude Code ask rule Bash(git push:*) (project settings) matches this command; Claude Code applies it itself\n") {
		t.Fatalf("project ask: exit %d\n%s", code, out)
	}
	// nothing named without a match, and the JSON field is null then
	code, out, _ = explain(t, "--command", "git status", "--json")
	if code != 0 || !strings.Contains(out, "\"native_rule\": null") {
		t.Fatalf("no match: exit %d\n%s", code, out)
	}
}

func TestRulesExplainReadRule(t *testing.T) {
	explainFixture(t)
	// A path a recommended native rule's twin covers: the built-in pack
	// asks (the twin, when installed, is Claude Code's to apply).
	code, out, errs := explain(t, "--read", "~/.ssh/id_ed25519")
	if code != 2 {
		t.Fatalf("exit %d, want 2\n%s%s", code, out, errs)
	}
	for _, want := range []string{"Read  ~/.ssh/id_ed25519\n", "verdict: ask\n", "rules:   pack:secrets-read/read-ssh-private-key\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	// --edit, --path (a Write) and --url name their tools
	for _, c := range []struct{ flag, value, tool string }{
		{"--edit", "a.go", "Edit"}, {"--path", "b.txt", "Write"}, {"--url", "https://go.dev/", "WebFetch"},
		{"--mcp", "mcp__github__list_issues", "mcp__github__list_issues"}, {"--skill", "canary-basic", "Skill"},
	} {
		code, out, _ := explain(t, c.flag, c.value)
		if code != 0 || !strings.HasPrefix(out, c.tool+"  ") {
			t.Errorf("%s %s: exit %d\n%s", c.flag, c.value, code, out)
		}
	}
}

func TestRulesExplainExpect(t *testing.T) {
	explainFixture(t)
	code, _, errs := explain(t, "--command", "echo EXPLAINLIT", "--expect", "deny")
	if code != 0 || errs != "" {
		t.Fatalf("expect deny on a deny: exit %d, stderr %q", code, errs)
	}
	code, out, errs := explain(t, "--command", "git status", "--expect", "deny")
	if code != 1 || !strings.Contains(errs, "expected deny, got allow (no opinion)") || !strings.Contains(out, "verdict: allow") {
		t.Fatalf("expect deny on no opinion: exit %d, stdout %q, stderr %q", code, out, errs)
	}
	// no opinion counts as allow (D3: exit 0 for both)
	if code, _, errs := explain(t, "--command", "git status", "--expect", "allow"); code != 0 || errs != "" {
		t.Fatalf("expect allow on no opinion: exit %d, stderr %q", code, errs)
	}
	if code, _, errs := explain(t, "--command", "echo EXPLAINLIT", "--expect", "bogus"); code != 3 || !strings.Contains(errs, "usage:") {
		t.Fatalf("expect bogus: exit %d, stderr %q", code, errs)
	}
}

func TestRulesExplainJSON(t *testing.T) {
	e, script := explainFixture(t)
	code, out, errs := explain(t, "--command", script, "--json", "--mode", "auto")
	if code != 2 {
		t.Fatalf("exit %d, want 2\n%s%s", code, out, errs)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	var keys []string
	for k := range raw {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if got, want := strings.Join(keys, ","), "confidence,cwd,enforcement,input,mode,native_rule,reason,rewritten,rules,shadow,skills,subject,tool,verdict"; got != want {
		t.Fatalf("keys %s, want %s", got, want)
	}
	var doc struct {
		Tool        string            `json:"tool"`
		Input       map[string]string `json:"input"`
		Verdict     string            `json:"verdict"`
		Reason      string            `json:"reason"`
		Rewritten   string            `json:"rewritten"`
		Rules       []map[string]any  `json:"rules"`
		Subject     map[string]string `json:"subject"`
		Enforcement string            `json:"enforcement"`
		Skills      []string          `json:"skills"`
		Confidence  string            `json:"confidence"`
		Shadow      struct {
			On          bool   `json:"on"`
			Would       string `json:"would"`
			WouldReason string `json:"would_reason"`
		} `json:"shadow"`
		Mode string `json:"mode"`
		Cwd  string `json:"cwd"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Tool != "Bash" || doc.Input["command"] != script || doc.Verdict != "ask" || !strings.HasPrefix(doc.Reason, "watchdeck: canary-basic") ||
		!strings.HasPrefix(doc.Rewritten, paths.BinaryName+" run --skill canary-basic -c ") || len(doc.Rules) != 0 ||
		doc.Subject["kind"] != "skill" || doc.Subject["name"] != "canary-basic" || doc.Enforcement != "sandbox" ||
		len(doc.Skills) != 1 || doc.Skills[0] != "canary-basic" || doc.Confidence != "high" ||
		doc.Shadow.On || doc.Shadow.Would != "" || doc.Mode != "auto" || doc.Cwd != e.proj {
		t.Fatalf("doc: %s", out)
	}
	// rules marshal as RuleHit; the no-opinion verdict is "none"
	code, out, _ = explain(t, "--command", "echo EXPLAINLIT", "--json")
	if code != 1 {
		t.Fatalf("exit %d", code)
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Verdict != "deny" || len(doc.Rules) != 1 || doc.Rules[0]["pack"] != "user" || doc.Rules[0]["id"] != "no-explain-lit" || doc.Rules[0]["action"] != "deny" {
		t.Fatalf("deny doc: %s", out)
	}
	code, out, _ = explain(t, "--command", "git status", "--json")
	if err := json.Unmarshal([]byte(out), &doc); err != nil || code != 0 {
		t.Fatal(err, code)
	}
	if doc.Verdict != "none" || doc.Rules == nil || doc.Skills == nil || doc.Mode != "default" {
		t.Fatalf("none doc: %s", out)
	}
	// shadow mode: the shadowed verdict is reported, and the exit stays 0
	writeFile(t, filepath.Join(e.cfg, paths.BinaryName, "overrides.yaml"), `version: 2
mode: shadow
rules:
  - {id: no-explain-lit, tool: Bash, match: {literals: [EXPLAINLIT]}, action: deny, severity: high}
`)
	code, out, _ = explain(t, "--command", "echo EXPLAINLIT", "--json")
	if err := json.Unmarshal([]byte(out), &doc); err != nil || code != 0 {
		t.Fatal(err, code)
	}
	if doc.Verdict != "none" || !doc.Shadow.On || doc.Shadow.Would != "deny" || !strings.Contains(doc.Shadow.WouldReason, "rule no-explain-lit") {
		t.Fatalf("shadow doc: %s", out)
	}
	code, out, _ = explain(t, "--command", "echo EXPLAINLIT")
	if code != 0 || !strings.Contains(out, "verdict: allow  (shadow mode is on: would deny by user:no-explain-lit; Claude Code decides as usual)") || !strings.Contains(out, "would:   rule no-explain-lit") {
		t.Fatalf("shadow human: exit %d\n%s", code, out)
	}
	// --expect under shadow mode: the exit is D3's, and one stderr line says
	// what enforce mode would do, so a loop reading the exit is not misled
	// (review of Plan 07, M8)
	code, _, errs = explain(t, "--command", "echo EXPLAINLIT", "--expect", "allow")
	if code != 0 || errs != paths.BinaryName+" rules explain: shadow mode is on: enforce mode would deny by user:no-explain-lit\n" {
		t.Fatalf("shadow expect allow: exit %d, stderr %q", code, errs)
	}
	code, _, errs = explain(t, "--command", "echo EXPLAINLIT", "--expect", "deny")
	if code != 1 || !strings.Contains(errs, "shadow mode is on: enforce mode would deny by user:no-explain-lit\n") || !strings.Contains(errs, "expected deny, got allow (no opinion)") {
		t.Fatalf("shadow expect deny: exit %d, stderr %q", code, errs)
	}
	// without shadow fields nothing extra is printed
	if code, _, errs := explain(t, "--command", "git status", "--expect", "allow"); code != 0 || errs != "" {
		t.Fatalf("shadow, no would: exit %d, stderr %q", code, errs)
	}
}

func TestRulesExplainCwdAndMode(t *testing.T) {
	e, script := explainFixture(t)
	// --cwd names the session's directory: the project skill is found from
	// elsewhere, and the native ask keeps or drops the rewrite by mode.
	writeFile(t, filepath.Join(e.claude, "settings.json"), `{"permissions":{"ask":["Bash(git clean:*)"]}}`)
	other := filepath.Join(e.home, "other")
	if err := os.MkdirAll(other, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(other)
	cmd := script + " && git clean -fd"
	code, out, _ := explain(t, "--cwd", e.proj, "--command", cmd)
	if code != 2 || !strings.Contains(out, "rewritten to run under the sandbox") || !strings.Contains(out, "your Claude Code ask rule Bash(git clean:*)") {
		t.Fatalf("default mode: exit %d\n%s", code, out)
	}
	code, out, _ = explain(t, "--cwd", e.proj, "--command", cmd, "--mode", "bypassPermissions")
	if code != 2 || strings.Contains(out, "rewritten to run under the sandbox") || !strings.Contains(out, "not sandboxed: in bypassPermissions mode") {
		t.Fatalf("bypassPermissions: exit %d\n%s", code, out)
	}
	// a relative --cwd resolves against the working directory
	code, out, _ = explain(t, "--cwd", "../proj", "--command", cmd, "--json")
	if code != 2 || !strings.Contains(out, `"cwd": "`+e.proj+`"`) {
		t.Fatalf("relative cwd: exit %d\n%s", code, out)
	}
}

func TestRulesExplainUsage(t *testing.T) {
	explainFixture(t)
	for _, args := range [][]string{
		{},                                   // no WHAT
		{"--command", "x", "--read", "y"},    // two WHATs
		{"--command"},                        // WHAT without a value
		{"--command", ""},                    // empty value
		{"--bogus", "x"},                     // unknown flag
		{"--command", "x", "--mode", "loud"}, // unknown mode
		{"--command", "x", "--mode"},         // mode without a value
		{"--command", "x", "--expect"},       // expect without a value
		{"--command", "x", "extra"},          // a stray word
	} {
		code, out, errs := explain(t, args...)
		if code != 3 || out != "" || !strings.Contains(errs, "usage: "+paths.BinaryName+" rules") || !strings.Contains(errs, "explain") {
			t.Errorf("%v: exit %d, stdout %q, stderr %q", args, code, out, errs)
		}
	}
}

func TestRulesExplainInvalidPolicyExit4(t *testing.T) {
	e, _ := explainFixture(t)
	writeFile(t, filepath.Join(e.cfg, paths.BinaryName, "overrides.yaml"), "version: 9\n")
	code, out, errs := explain(t, "--command", "git status")
	if code != 4 {
		t.Fatalf("exit %d, want 4\n%s%s", code, out, errs)
	}
	// the verdict is still the hook's: it asks until the file is fixed
	if !strings.Contains(out, "verdict: ask\n") || !strings.Contains(out, "your policy file is invalid") {
		t.Errorf("stdout:\n%s", out)
	}
	if !strings.Contains(errs, "could not be loaded") || strings.Contains(errs, "version: 9") {
		t.Errorf("stderr: %q", errs)
	}
	// --expect does not hide it
	if code, _, _ := explain(t, "--command", "git status", "--expect", "ask"); code != 4 {
		t.Errorf("with --expect: exit %d, want 4", code)
	}
	// a project file that cannot be parsed is a warning: the hook drops
	// that layer and decides without it
	writeFile(t, filepath.Join(e.cfg, paths.BinaryName, "overrides.yaml"), "version: 2\n")
	writeFile(t, filepath.Join(e.proj, ".watchdeck.yaml"), "version: 9\n")
	code, out, errs = explain(t, "--command", "git status")
	if code != 0 || !strings.Contains(out, "verdict: allow") || !strings.Contains(errs, "warning:") || !strings.Contains(errs, "project") {
		t.Errorf("project error: exit %d, stdout %q, stderr %q", code, out, errs)
	}
}

// TestRulesExplainWritesNoRecord: after every kind of explain call, the
// activity log, the sessions log and the inbox do not exist, and the
// overrides file and the settings file keep their mtime (Review Focus 1).
func TestRulesExplainWritesNoRecord(t *testing.T) {
	e, script := explainFixture(t)
	overrides := filepath.Join(e.cfg, paths.BinaryName, "overrides.yaml")
	settings := filepath.Join(e.claude, "settings.json")
	projectSettings := filepath.Join(e.proj, ".claude", "settings.json")
	stamp := func(p string) string {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := os.ReadFile(p)
		return fi.ModTime().String() + " " + string(b)
	}
	before := map[string]string{overrides: stamp(overrides), settings: stamp(settings), projectSettings: stamp(projectSettings)}
	for _, args := range [][]string{
		{"--command", "echo EXPLAINLIT"},
		{"--command", script},
		{"--command", "git status"},
		{"--command", script + " && curl https://example.invalid"},
		{"--command", script + " && git push origin main"},
		{"--read", "~/.ssh/id_ed25519"},
		{"--edit", "~/.zshrc"},
		{"--path", "/etc/hosts"},
		{"--url", "https://example.invalid/"},
		{"--mcp", "mcp__github__delete_repo"},
		{"--skill", "canary-basic"},
		{"--command", "echo EXPLAINLIT", "--expect", "allow"},
		{"--command", script, "--json", "--mode", "auto"},
		{"--command", "x", "--mode", "loud"},
	} {
		code, _, _ := explain(t, args...)
		if code < 0 || code > 4 {
			t.Fatalf("%v: exit %d", args, code)
		}
	}
	for _, p := range []string{e.activityPath(), filepath.Join(e.state, paths.BinaryName, "sessions.jsonl"), filepath.Join(e.state, paths.BinaryName, rulebook.InboxFile)} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s exists after explain (err %v)", p, err)
		}
	}
	for p, want := range before {
		if got := stamp(p); got != want {
			t.Errorf("%s changed:\n%s\n%s", p, got, want)
		}
	}
	// The activity log is on in this env (WATCHDECK_ACTIVITY is empty, so
	// the default path applies): the hook would have recorded the first
	// call (TestExplainWritesNothing proves that at the hook level).
	if _, _, err := hostPaths(); err != nil {
		t.Fatal(err)
	} else if hp, _, _ := hostPaths(); hp.Activity != e.activityPath() {
		t.Fatalf("activity path %q, want %q: the fixture proves nothing", hp.Activity, e.activityPath())
	}
}

// explainGolden is `rules explain --json` for a deny, an ask and a no
// opinion call over explainFixture, recorded before the document builder
// moved into internal/hook (Plan 08 Task 4, 2026-10-24). <ROOT> stands for
// the test's temp root. The move must leave every byte as it was.
var explainGolden = []struct {
	name string
	args []string
	want string
}{
	{"deny", []string{"--command", "echo EXPLAINLIT", "--json"}, explainGoldenDeny},
	{"ask", []string{"--command", "<SCRIPT>", "--json", "--mode", "auto"}, explainGoldenAsk},
	{"none", []string{"--command", "curl https://example.invalid", "--json"}, explainGoldenNone},
}

// TestExplainJSONUnchangedByMove pins the --json document byte for byte
// (D12: the CLI and the dashboard's try route print one document).
func TestExplainJSONUnchangedByMove(t *testing.T) {
	e, script := explainFixture(t)
	root := filepath.Dir(e.home)
	for _, g := range explainGolden {
		args := append([]string{}, g.args...)
		for i, a := range args {
			if a == "<SCRIPT>" {
				args[i] = script
			}
		}
		_, out, errs := explain(t, args...)
		if errs != "" {
			t.Errorf("%s: stderr %q", g.name, errs)
		}
		got := strings.ReplaceAll(out, root, "<ROOT>")
		if got != g.want {
			t.Errorf("%s: --json changed:\n got: %s\nwant: %s", g.name, got, g.want)
		}
	}
}

const explainGoldenDeny = `{
  "tool": "Bash",
  "input": {
    "command": "echo EXPLAINLIT"
  },
  "verdict": "deny",
  "reason": "watchdeck: denied by policy: rule no-explain-lit (high, deny): from the user policy file",
  "rewritten": "",
  "rules": [
    {
      "pack": "user",
      "id": "no-explain-lit",
      "severity": "high",
      "action": "deny"
    }
  ],
  "subject": null,
  "enforcement": "gate",
  "skills": [],
  "confidence": "",
  "shadow": {
    "on": false,
    "would": "",
    "would_reason": ""
  },
  "native_rule": null,
  "mode": "default",
  "cwd": "<ROOT>/home/proj"
}
`

const explainGoldenAsk = `{
  "tool": "Bash",
  "input": {
    "command": "python3 <ROOT>/home/proj/.claude/skills/canary-basic/scripts/probe.py net"
  },
  "verdict": "ask",
  "reason": "watchdeck: canary-basic has no PERMISSIONS.yaml; default profile (network=none write=${CWD},${TMP} env=PATH,HOME,LANG,TMPDIR)",
  "rewritten": "watchdeck run --skill canary-basic -c 'python3 <ROOT>/home/proj/.claude/skills/canary-basic/scripts/probe.py net'",
  "rules": [],
  "subject": {
    "kind": "skill",
    "name": "canary-basic"
  },
  "enforcement": "sandbox",
  "skills": [
    "canary-basic"
  ],
  "confidence": "high",
  "shadow": {
    "on": false,
    "would": "",
    "would_reason": ""
  },
  "native_rule": null,
  "mode": "auto",
  "cwd": "<ROOT>/home/proj"
}
`

const explainGoldenNone = `{
  "tool": "Bash",
  "input": {
    "command": "curl https://example.invalid"
  },
  "verdict": "none",
  "reason": "",
  "rewritten": "",
  "rules": [],
  "subject": null,
  "enforcement": "",
  "skills": [],
  "confidence": "",
  "shadow": {
    "on": false,
    "would": "",
    "would_reason": ""
  },
  "native_rule": {
    "value": "Bash(curl *)",
    "kind": "deny",
    "scope": "user"
  },
  "mode": "default",
  "cwd": "<ROOT>/home/proj"
}
`
