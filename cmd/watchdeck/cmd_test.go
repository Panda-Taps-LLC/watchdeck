package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/activity"
)

// testEnv points every location at a fresh temp tree: HOME, the three XDG
// dirs and CLAUDE_CONFIG_DIR are set with t.Setenv, WATCHDECK_ACTIVITY is
// cleared (the default path under XDG_STATE_HOME), and the working
// directory is a temp project. Nothing reads or writes the real home.
type testEnv struct {
	home, cfg, cache, state, claude, proj string
}

func newTestEnv(t *testing.T) testEnv {
	t.Helper()
	root := t.TempDir()
	e := testEnv{
		home:   filepath.Join(root, "home"),
		cfg:    filepath.Join(root, "cfg"),
		cache:  filepath.Join(root, "cache"),
		state:  filepath.Join(root, "state"),
		claude: filepath.Join(root, "claude"),
	}
	e.proj = filepath.Join(e.home, "proj")
	if err := os.MkdirAll(e.proj, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", e.home)
	t.Setenv("XDG_CONFIG_HOME", e.cfg)
	t.Setenv("XDG_CACHE_HOME", e.cache)
	t.Setenv("XDG_STATE_HOME", e.state)
	t.Setenv("CLAUDE_CONFIG_DIR", e.claude)
	t.Setenv("WATCHDECK_ACTIVITY", "")
	t.Setenv("WATCHDECK_LIFECYCLE", "")
	t.Chdir(e.proj)
	return e
}

func (e testEnv) activityPath() string {
	return filepath.Join(e.state, "watchdeck", "activity.jsonl")
}

// call runs one subcommand in process and returns exit, stdout, stderr.
func call(t *testing.T, fn func([]string, *bytes.Buffer, *bytes.Buffer) int, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := fn(args, &out, &errb)
	return code, out.String(), errb.String()
}

func activityCmd(a []string, o, e *bytes.Buffer) int { return cmdActivity(a, o, e) }
func pathsCmd(a []string, o, e *bytes.Buffer) int    { return cmdPaths(a, o, e) }
func versionCmd(a []string, o, e *bytes.Buffer) int  { return cmdVersion(a, o, e) }

// seed writes a decision, the run it caused (ids copied at write time, a
// network hint), a second session's decision, a Skill invocation and an
// auto-mode denial.
func seed(t *testing.T, path, cwd string) time.Time {
	t.Helper()
	at := time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)
	ts := func(d time.Duration) string { return at.Add(d).Format(time.RFC3339Nano) }
	one := 1
	cmd := "python3 /fake/canary-basic/scripts/probe.py net --strict"
	recs := []activity.Record{
		{Kind: activity.KindDecision, TS: ts(0), SessionID: "s1", ToolUseID: "toolu_1", Cwd: cwd,
			Skills: []string{"canary-basic"}, Command: cmd, Decision: "ask", Confidence: "high",
			Rewritten: "watchdeck run --skill canary-basic -c '" + cmd + "'"},
		{Kind: activity.KindRun, TS: ts(time.Second), SessionID: "s1", ToolUseID: "toolu_1", Cwd: cwd,
			Skills: []string{"canary-basic"}, Command: cmd, Exit: &one, Outcome: activity.OutcomeFailed,
			JoinedBy: activity.JoinedByWrite, Backend: "seatbelt",
			Hints: []activity.Hint{{Kind: activity.HintNetwork, Errno: 1, Line: "PermissionError: [Errno 1] Operation not permitted",
				Stream: "stderr", Text: "network access refused by the OS (EPERM)", Heuristic: true}}},
		{Kind: activity.KindDecision, TS: ts(2 * time.Second), SessionID: "s2", ToolUseID: "toolu_2", Cwd: cwd,
			Skills: []string{"canary-request"}, Command: "python3 /fake/canary-request/scripts/probe.py net", Decision: "allow"},
		{Kind: activity.KindSkillInvoked, TS: ts(3 * time.Second), SessionID: "s1", ToolUseID: "toolu_3",
			ToolName: "Skill", Skill: "canary-basic"},
		{Kind: activity.KindDenied, TS: ts(4 * time.Second), SessionID: "s1", ToolUseID: "toolu_4",
			ToolName: "Bash", Skills: []string{"canary-exec"}, Command: "python3 /fake/canary-exec/scripts/probe.py", Reason: "auto mode classifier"},
	}
	for _, r := range recs {
		if err := activity.Append(path, r); err != nil {
			t.Fatal(err)
		}
	}
	return at
}

func TestActivityJSONShape(t *testing.T) {
	e := newTestEnv(t)
	seed(t, e.activityPath(), e.proj)

	code, out, errOut := call(t, activityCmd, "--json")
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errOut)
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
	if got, want := strings.Join(keys, ","), "enabled,next,path,records,reset,skipped"; got != want {
		t.Fatalf("keys %s, want %s", got, want)
	}
	var page activityPage
	if err := json.Unmarshal([]byte(out), &page); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(e.activityPath())
	if err != nil {
		t.Fatal(err)
	}
	if !page.Enabled || page.Path != e.activityPath() || page.Next != fi.Size() || page.Reset || page.Skipped != 0 {
		t.Fatalf("page header %+v (file size %d)", page, fi.Size())
	}
	if len(page.Records) != 5 || page.Records[1].Kind != activity.KindRun || page.Records[1].JoinedBy != activity.JoinedByWrite {
		t.Fatalf("records %+v", page.Records)
	}

	// --session, --kinds and --after: the mod's two calls.
	code, out, _ = call(t, activityCmd, "--json", "--session", "s1", "--kinds", "decision,run,skill_invoked,denied", "--tail", "200")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	page = activityPage{}
	if err := json.Unmarshal([]byte(out), &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Records) != 4 {
		t.Fatalf("session s1: %d records, want 4", len(page.Records))
	}
	for _, r := range page.Records {
		if r.SessionID != "s1" {
			t.Fatalf("record from session %q", r.SessionID)
		}
	}
	next := page.Next
	if err := activity.Append(e.activityPath(), activity.Record{Kind: activity.KindSkillInvoked, SessionID: "s1", Skill: "canary-basic"}); err != nil {
		t.Fatal(err)
	}
	code, out, _ = call(t, activityCmd, "--json", "--session", "s1", "--after", jsonInt(next))
	page = activityPage{}
	if err := json.Unmarshal([]byte(out), &page); err != nil || code != 0 {
		t.Fatalf("exit %d, %v", code, err)
	}
	if len(page.Records) != 1 || page.Records[0].Kind != activity.KindSkillInvoked || page.Next <= next {
		t.Fatalf("poll after %d: %+v next %d", next, page.Records, page.Next)
	}

	// --summary --json counts and names the last denial (the auto-mode one).
	code, out, _ = call(t, activityCmd, "--summary", "--json")
	var s activitySummary
	if err := json.Unmarshal([]byte(out), &s); err != nil || code != 0 {
		t.Fatalf("summary exit %d: %v\n%s", code, err, out)
	}
	if s.Decisions["ask"] != 1 || s.Decisions["allow"] != 1 || s.RunsTotal != 1 || s.Runs["failed"] != 1 ||
		s.Denied != 2 || s.DeniedBy["network"] != 1 || s.DeniedBy["auto_mode"] != 1 ||
		s.LastDenial == nil || s.LastDenial.Kind != activity.KindDenied {
		t.Fatalf("summary %+v", s)
	}

	// Text forms: one line per record, a few summary lines.
	code, out, _ = call(t, activityCmd)
	if code != 0 || strings.Count(out, "\n") != 6 || !strings.Contains(out, "failed exit 1 hints 1") {
		t.Fatalf("text exit %d:\n%s", code, out)
	}
	code, out, _ = call(t, activityCmd, "--summary")
	if code != 0 || !strings.Contains(out, "denials:    2 (auto_mode 1, network 1)") || !strings.Contains(out, "canary-exec") {
		t.Fatalf("summary text exit %d:\n%s", code, out)
	}
}

func jsonInt(n int64) string { b, _ := json.Marshal(n); return string(b) }

func TestActivityAbsentLog(t *testing.T) {
	newTestEnv(t)
	code, out, _ := call(t, activityCmd, "--json")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(out, `"records": []`) || !strings.Contains(out, `"next": 0`) || !strings.Contains(out, `"enabled": true`) {
		t.Fatalf("absent log:\n%s", out)
	}
}

func TestActivityOff(t *testing.T) {
	e := newTestEnv(t)
	seed(t, e.activityPath(), e.proj)
	t.Setenv("WATCHDECK_ACTIVITY", "off")
	code, out, _ := call(t, activityCmd, "--json")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	var page activityPage
	if err := json.Unmarshal([]byte(out), &page); err != nil {
		t.Fatal(err)
	}
	if page.Enabled || page.Path != "" || page.Records == nil || len(page.Records) != 0 {
		t.Fatalf("off: %+v", page)
	}
	if code, out, _ = call(t, activityCmd, "--summary"); code != 0 || !strings.Contains(out, "off") {
		t.Fatalf("summary off exit %d: %q", code, out)
	}
}

func TestActivityUsageErrors(t *testing.T) {
	newTestEnv(t)
	for _, args := range [][]string{
		{"--bogus"},
		{"extra"},
		{"--since", "yesterday"},
		{"--kinds", "decision,nope"},
		{"--tail", "-1"},
	} {
		if code, _, _ := call(t, activityCmd, args...); code != 3 {
			t.Errorf("activity %v: exit %d, want 3", args, code)
		}
	}
	if code := run([]string{"activity", "--bogus"}); code != 3 {
		t.Errorf("run(activity --bogus) = %d, want 3", code)
	}
}

func TestActivityTextEscapesControlCharacters(t *testing.T) {
	e := newTestEnv(t)
	// The log is plain text any local process can append to: every field
	// the text forms print (ts, kind, skills, status, command) is escaped.
	for _, r := range []activity.Record{
		{Kind: activity.KindDecision, Decision: "ask", Skills: []string{"canary-basic"},
			Command: "echo \x1b]0;pwned\x07 done\nrm -rf x"},
		{Kind: "decision\x1b[2J", TS: "2026-10-12T09:00:00Z\x1b[31m", Decision: "ask", Command: "x"},
		{Kind: activity.KindDenied, TS: "2026-10-12T09:00:01Z\x1b]0;t\x07", Skills: []string{"canary-exec"}, Reason: "r"},
	} {
		if err := activity.Append(e.activityPath(), r); err != nil {
			t.Fatal(err)
		}
	}
	_, out, _ := call(t, activityCmd)
	if strings.Count(out, "\n") != 3 || strings.ContainsAny(out, "\x1b\x07") ||
		!strings.Contains(out, `\x1b]0;pwned\x07 done\nrm`) ||
		!strings.Contains(out, `2026-10-12T09:00:00Z\x1b[31m  decision\x1b[2J`) {
		t.Fatalf("control characters reached the terminal: %q", out)
	}
	_, out, _ = call(t, activityCmd, "--summary")
	if strings.ContainsAny(out, "\x1b\x07") || !strings.Contains(out, `last:       2026-10-12T09:00:01Z\x1b]0;t\x07  canary-exec`) {
		t.Fatalf("summary: control characters reached the terminal: %q", out)
	}
}

func TestActivityPagingMatchesAPI(t *testing.T) {
	e := newTestEnv(t)
	// 2001 records written directly (Append per line would be slow).
	var b strings.Builder
	for i := 0; i < 2001; i++ {
		b.WriteString(`{"v":1,"kind":"skill_invoked","ts":"2026-10-12T09:00:00Z","skill":"canary-basic"}` + "\n")
	}
	if err := os.MkdirAll(filepath.Dir(e.activityPath()), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(e.activityPath(), []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		args []string
		want int
	}{
		{[]string{"--json"}, 500},
		{[]string{"--json", "--after", "0"}, 500},
		{[]string{"--json", "--after", "10"}, 500},
		{[]string{"--json", "--limit", "5000"}, 2000},
		{[]string{"--json", "--tail", "5000"}, 2000},
		{[]string{"--json", "--tail", "7"}, 7},
		{[]string{"--json", "--limit", "3"}, 3},
	} {
		code, out, errOut := call(t, activityCmd, c.args...)
		var page activityPage
		if code != 0 || json.Unmarshal([]byte(out), &page) != nil {
			t.Fatalf("%v: exit %d %s", c.args, code, errOut)
		}
		if len(page.Records) != c.want {
			t.Errorf("%v: %d records, want %d", c.args, len(page.Records), c.want)
		}
	}
	if _, out, _ := call(t, activityCmd); strings.Count(out, "\n") != activityTextTail {
		t.Errorf("text default: %d lines, want %d", strings.Count(out, "\n"), activityTextTail)
	}
}

func TestPathsJSON(t *testing.T) {
	e := newTestEnv(t)
	custom := filepath.Join(e.state, "elsewhere.jsonl")
	t.Setenv("WATCHDECK_ACTIVITY", custom)
	if err := os.Mkdir(filepath.Join(e.proj, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := call(t, pathsCmd, "--json")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	var got map[string]string
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	proj, _ := filepath.EvalSymlinks(e.proj)
	if got["projectRoot"] != e.proj && got["projectRoot"] != proj {
		t.Errorf("projectRoot %q, want %q", got["projectRoot"], e.proj)
	}
	delete(got, "projectRoot")
	want := map[string]string{
		"home":           e.home,
		"configDir":      filepath.Join(e.cfg, "watchdeck"),
		"cacheBase":      e.cache,
		"stateDir":       filepath.Join(e.state, "watchdeck"),
		"activity":       custom,
		"claudeDir":      e.claude,
		"overridesFile":  filepath.Join(e.cfg, "watchdeck", "overrides.yaml"),
		"indexFile":      filepath.Join(e.cache, "watchdeck", "index.json"),
		"claudeSettings": filepath.Join(e.claude, "settings.json"),
		"sessions":       filepath.Join(e.state, "watchdeck", "sessions.jsonl"),
		"liveDir":        filepath.Join(e.state, "watchdeck", "live"),
	}
	if len(got) != len(want) {
		t.Errorf("keys %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}

	t.Setenv("WATCHDECK_ACTIVITY", "off")
	_, out, _ = call(t, pathsCmd, "--json")
	if !strings.Contains(out, `"activity": ""`) {
		t.Errorf("activity off should print an empty path:\n%s", out)
	}
	code, out, _ = call(t, pathsCmd)
	if code != 0 || !strings.Contains(out, "configDir: "+filepath.Join(e.cfg, "watchdeck")+"\n") {
		t.Errorf("text form exit %d:\n%s", code, out)
	}
	if code, _, _ := call(t, pathsCmd, "--nope"); code != 3 {
		t.Errorf("unknown flag: exit %d, want 3", code)
	}
}

func TestVersionJSON(t *testing.T) {
	code, out, _ := call(t, versionCmd, "--json")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	var v struct {
		Version     *string `json:"version"`
		Platform    string  `json:"platform"`
		Enforcement *bool   `json:"enforcement"`
	}
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatal(err)
	}
	if v.Version == nil || *v.Version != version || v.Platform != runtime.GOOS || v.Enforcement == nil {
		t.Fatalf("version --json: %s", out)
	}
	if code, out, _ = call(t, versionCmd); code != 0 || out != "watchdeck "+version+"\n" {
		t.Fatalf("plain version: exit %d %q", code, out)
	}
	if code, _, _ = call(t, versionCmd, "--nope"); code != 3 {
		t.Fatalf("unknown flag: exit %d", code)
	}
}

// runCmd runs the top-level dispatcher in process without a terminal.
func runCmd(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := runWith(args, &out, &errb, false)
	return code, out.String(), errb.String()
}

// TestUsageListsSix: the documented usage names the six commands, one line
// each, points at "help advanced" for the rest, and names none of the
// advanced commands as a command line.
func TestUsageListsSix(t *testing.T) {
	var cmds []string
	for _, line := range strings.Split(usage, "\n") {
		if strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "   ") {
			cmds = append(cmds, strings.Fields(line)[0])
		}
	}
	want := []string{"watchdeck", "setup", "status", "rules", "doctor", "uninstall"}
	if strings.Join(cmds, " ") != strings.Join(want, " ") {
		t.Fatalf("command lines %q, want %q\n%s", cmds, want, usage)
	}
	if !strings.HasSuffix(strings.TrimRight(usage, "\n"), "\nMore commands: watchdeck help advanced") {
		t.Fatalf("usage does not end with the advanced line:\n%s", usage)
	}
	code, out, _ := runCmd(t, "help")
	if code != 0 || out != usage {
		t.Fatalf("help: exit %d\n%s", code, out)
	}
	for _, a := range []string{"audit", "init", "validate", "enforce", "index", "sessions", "service", "mcp", "policy", "activity", "paths", "demo", "inbox", "allow", "version"} {
		found := false
		for _, line := range strings.Split(advancedUsage, "\n") {
			if f := strings.Fields(line); len(f) > 0 && strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "   ") && f[0] == a {
				found = true
			}
		}
		if !found {
			t.Errorf("advancedUsage has no line for %s", a)
		}
	}
}

// TestBareNoTTYUsageExit3: no arguments and no terminal prints the usage to
// stderr and exits 3, as before; an unknown command is unchanged too.
func TestBareNoTTYUsageExit3(t *testing.T) {
	newTestEnv(t)
	code, out, errOut := runCmd(t)
	if code != 3 || out != "" || errOut != usage {
		t.Fatalf("bare: exit %d, stdout %q, stderr %q", code, out, errOut)
	}
	code, _, errOut = runCmd(t, "bogus")
	if code != 3 || !strings.HasPrefix(errOut, "watchdeck: unknown command \"bogus\"\n\n") || !strings.HasSuffix(errOut, usage) {
		t.Fatalf("unknown: exit %d, stderr %q", code, errOut)
	}
}

// TestAdvancedDispatch: "advanced <sub>" runs the same command as the bare
// spelling with the same output and exit code; "advanced" alone and an
// unknown advanced command print advancedUsage to stderr and exit 3.
func TestAdvancedDispatch(t *testing.T) {
	newTestEnv(t)
	c1, o1, e1 := runCmd(t, "paths", "--json")
	c2, o2, e2 := runCmd(t, "advanced", "paths", "--json")
	if c1 != 0 || c1 != c2 || o1 != o2 || e1 != e2 || o1 == "" {
		t.Fatalf("paths: %d %q %q; advanced paths: %d %q %q", c1, o1, e1, c2, o2, e2)
	}
	c1, _, _ = runCmd(t, "paths", "--bogus")
	c2, _, _ = runCmd(t, "advanced", "paths", "--bogus")
	if c1 != 3 || c2 != 3 {
		t.Fatalf("usage exit: bare %d, advanced %d", c1, c2)
	}
	if code, out, errOut := runCmd(t, "advanced"); code != 3 || out != "" || errOut != advancedUsage {
		t.Fatalf("advanced alone: exit %d, stdout %q, stderr %q", code, out, errOut)
	}
	if code, _, errOut := runCmd(t, "advanced", "bogus"); code != 3 || !strings.HasPrefix(errOut, "watchdeck advanced: unknown command \"bogus\"\n\n") || !strings.HasSuffix(errOut, advancedUsage) {
		t.Fatalf("advanced bogus: exit %d, stderr %q", code, errOut)
	}
	if code, out, _ := runCmd(t, "advanced", "version", "--json"); code != 0 || !strings.Contains(out, `"version"`) {
		t.Fatalf("advanced version: exit %d %q", code, out)
	}
}

// TestHelpAdvanced: "help advanced" and "advanced help" print advancedUsage
// to stdout and exit 0; it lists ui, allow and inbox, which usage does not,
// and leaves out hook and run (Claude Code runs them; both stay accepted).
// Any other help topic prints the usage and exits 0, as before.
func TestHelpAdvanced(t *testing.T) {
	for _, args := range [][]string{{"help", "advanced"}, {"advanced", "help"}, {"advanced", "--help"}} {
		code, out, errOut := runCmd(t, args...)
		if code != 0 || out != advancedUsage || errOut != "" {
			t.Fatalf("%v: exit %d, stdout %q, stderr %q", args, code, out, errOut)
		}
	}
	for _, w := range []string{"\n  ui ", "\n  allow ", "\n  inbox "} {
		if !strings.Contains(advancedUsage, w) {
			t.Errorf("advancedUsage lacks %q", w)
		}
		if strings.Contains(usage, w) {
			t.Errorf("usage names %q", w)
		}
	}
	for _, w := range []string{"\n  hook ", "\n  run "} {
		if strings.Contains(advancedUsage, w) || strings.Contains(usage, w) {
			t.Errorf("a usage text lists %q", w)
		}
	}
	for _, args := range [][]string{{"help", "bogus"}, {"--help", "x", "y"}} {
		if code, out, errOut := runCmd(t, args...); code != 0 || out != usage || errOut != "" {
			t.Fatalf("%v: exit %d, stdout %q, stderr %q", args, code, out, errOut)
		}
	}
}

// TestHookAndRunStillAccepted: hook and run are unlisted but dispatched,
// bare and under advanced (a usage error exits 3, not "unknown command").
func TestHookAndRunStillAccepted(t *testing.T) {
	newTestEnv(t)
	for _, args := range [][]string{{"run"}, {"advanced", "run"}} {
		// cmdRun writes its usage to os.Stderr; the buffer would only hold
		// the dispatcher's "unknown command"
		if code, _, errOut := runCmd(t, args...); code != 3 || errOut != "" {
			t.Fatalf("%v: exit %d, stderr %q", args, code, errOut)
		}
	}
}
