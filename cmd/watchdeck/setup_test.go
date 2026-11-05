package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/activity"
	"github.com/Panda-Taps-LLC/watchdeck/internal/claudesettings"
	"github.com/Panda-Taps-LLC/watchdeck/internal/demo"
	"github.com/Panda-Taps-LLC/watchdeck/internal/lifecycle"
	"github.com/Panda-Taps-LLC/watchdeck/internal/rulebook"
	"github.com/Panda-Taps-LLC/watchdeck/internal/runner"
	"github.com/Panda-Taps-LLC/watchdeck/internal/sandbox"
	"github.com/Panda-Taps-LLC/watchdeck/internal/settings"
	"github.com/Panda-Taps-LLC/watchdeck/internal/userconfig"
	"github.com/goccy/go-yaml"
)

// passSelfTest stands in for the real sandbox self-test in command tests.
func passSelfTest(t *testing.T) {
	t.Helper()
	old := selfTest
	selfTest = func(context.Context, map[string]string) runner.SelfTest {
		return runner.SelfTest{Backend: "seatbelt", Probe: "shell", WriteAllowed: true, WriteDenied: true}
	}
	t.Cleanup(func() { selfTest = old })
}

// testConsole answers questions from input; tty says whether it may ask.
func testConsole(input string, tty, yes bool) (*console, *bytes.Buffer) {
	var out bytes.Buffer
	return &console{in: bufio.NewReader(strings.NewReader(input)), out: &out, errw: &out, tty: tty, assume: yes}, &out
}

func writeFile(t *testing.T, p, s string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

func backups(t *testing.T, path string) []string {
	t.Helper()
	m, _ := filepath.Glob(path + ".bak-*")
	return m
}

func TestSetupPluginOnlyAddsExclusion(t *testing.T) {
	for _, viaFlag := range []bool{false, true} {
		e := newTestEnv(t)
		passSelfTest(t)
		userSettings := filepath.Join(e.claude, "settings.json")
		writeFile(t, userSettings, "{\n  \"sandbox\": {\n    \"enabled\": true\n  }\n}\n")
		if !viaFlag {
			writeFile(t, filepath.Join(e.claude, "plugins", "installed_plugins.json"),
				`{"version":2,"plugins":{"watchdeck@watchdeck":[{"scope":"user","installPath":"/fake/plugin","version":"0.1.0"}]}}`)
		}
		c, out := testConsole("", false, true)
		if code := runSetup(c, setupOptions{plugin: viaFlag}); code != 0 {
			t.Fatalf("viaFlag=%v: exit %d\n%s", viaFlag, code, out)
		}
		st, err := settings.Inspect(userSettings)
		if err != nil {
			t.Fatal(err)
		}
		if !st.Excluded || st.HookInstalled || st.SkillHook || st.DeniedHook {
			t.Fatalf("viaFlag=%v: want the exclusion only, got %+v\n%s", viaFlag, st, out)
		}
		if !strings.Contains(out.String(), "plugin") || !strings.Contains(out.String(), "only the sandbox exclusion") {
			t.Errorf("output does not say why only the exclusion:\n%s", out)
		}
		// --yes never answers the autostart question: the config holds installed_at only
		assertConfigKeys(t, filepath.Join(e.cfg, "watchdeck", "config.yaml"), "installed_at")
	}
}

func TestSetupExclusionOnlyTouchesNothingElse(t *testing.T) {
	e := newTestEnv(t)
	selfTest = func(context.Context, map[string]string) runner.SelfTest {
		t.Fatal("--exclusion-only ran the self-test")
		return runner.SelfTest{}
	}
	t.Cleanup(func() { selfTest = runner.SandboxSelfTest })
	userSettings := filepath.Join(e.claude, "settings.json")
	c, out := testConsole("", false, true)
	if code := runSetup(c, setupOptions{exclusionOnly: true, plugin: true}); code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	st, _ := settings.Inspect(userSettings)
	if !st.Excluded || st.HookInstalled {
		t.Fatalf("status %+v", st)
	}
	// the Rules step is independent of hooks and still runs (--yes applies it)
	if deny, ask := settingsPerms(t, userSettings); len(deny)+len(ask) != len(rulebook.Recommended()) {
		t.Fatalf("--exclusion-only skipped the recommended rules: deny %v ask %v\n%s", deny, ask, out)
	}
	assertConfigKeys(t, filepath.Join(e.cfg, "watchdeck", "config.yaml"), "installed_at")
}

func TestSetupConfirmsAndBacksUp(t *testing.T) {
	e := newTestEnv(t)
	passSelfTest(t)
	userSettings := filepath.Join(e.claude, "settings.json")
	orig := "{\n  \"model\": \"x\"\n}\n"
	writeFile(t, userSettings, orig)

	// "n" for the rules, "n" for the hooks: settings untouched
	c, out := testConsole("n\nn\n", true, false)
	if code := runSetup(c, setupOptions{}); code != 1 {
		t.Fatalf("declined: exit %d, want 1\n%s", code, out)
	}
	if b, _ := os.ReadFile(userSettings); string(b) != orig {
		t.Fatalf("declined but settings changed:\n%s", b)
	}
	if len(backups(t, userSettings)) != 0 {
		t.Fatal("declined but a backup was written")
	}

	// the rules are not asked again (the No above is remembered;
	// TestSetupInstallsRecommendedByDefault covers them), then Enter: the
	// default, yes
	c, out = testConsole("\n\n", true, false)
	if code := runSetup(c, setupOptions{}); code != 0 {
		t.Fatalf("accepted: exit %d\n%s", code, out)
	}
	st, _ := settings.Inspect(userSettings)
	if !st.Complete {
		t.Fatalf("after yes: %+v\n%s", st, out)
	}
	bk := backups(t, userSettings)
	if len(bk) != 1 {
		t.Fatalf("backups = %v", bk)
	}
	if b, _ := os.ReadFile(bk[0]); string(b) != orig {
		t.Fatalf("backup holds %q, want the original", b)
	}
	if !strings.Contains(out.String(), "Apply? (a .bak-<ts> backup is written first) [Y/n]") || !strings.Contains(out.String(), "Start the dashboard automatically with each Claude Code session? [y/N]") {
		t.Fatalf("questions not asked as expected:\n%s", out)
	}

	// a second run has nothing to change and writes no new backup
	c, out = testConsole("\n", true, false)
	if code := runSetup(c, setupOptions{}); code != 0 {
		t.Fatalf("rerun: exit %d\n%s", code, out)
	}
	if !strings.Contains(out.String(), "already set up") || len(backups(t, userSettings)) != 1 {
		t.Fatalf("rerun changed something:\n%s", out)
	}
}

func TestSetupNonTTYWithoutYes(t *testing.T) {
	e := newTestEnv(t)
	passSelfTest(t)
	userSettings := filepath.Join(e.claude, "settings.json")
	c, out := testConsole("y\ny\n", false, false)
	if code := runSetup(c, setupOptions{}); code == 0 {
		t.Fatalf("non-tty without --yes exited 0\n%s", out)
	}
	if _, err := os.Stat(userSettings); err == nil {
		t.Fatal("settings written without a confirm")
	}
	for _, want := range []string{"+ hooks.PreToolUse", "+ sandbox.excludedCommands: watchdeck run *", "not applied", "--yes"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestSetupStopsWhenSelfTestFails(t *testing.T) {
	e := newTestEnv(t)
	selfTest = func(context.Context, map[string]string) runner.SelfTest {
		return runner.SelfTest{Backend: "seatbelt", Probe: "shell", WriteAllowed: true}
	}
	t.Cleanup(func() { selfTest = runner.SandboxSelfTest })
	c, out := testConsole("", false, true)
	if code := runSetup(c, setupOptions{}); code != 1 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if _, err := os.Stat(filepath.Join(e.claude, "settings.json")); err == nil {
		t.Fatal("settings written after a failed self-test")
	}
}

func doctorCmd(a []string, o, e *bytes.Buffer) int { return cmdDoctor(a, o, e) }

func TestDoctorDuplicateHooks(t *testing.T) {
	e := newTestEnv(t)
	passSelfTest(t)
	userSettings := filepath.Join(e.claude, "settings.json")
	bin := filepath.Join(e.home, "bin", "watchdeck")
	writeFile(t, bin, "#!/bin/sh\n")
	if err := os.Chmod(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := settings.Install(userSettings, bin); err != nil {
		t.Fatal(err)
	}
	// clean install, no log yet: no failure
	code, out, _ := call(t, doctorCmd)
	if code != 0 || !strings.Contains(out, "pass  registration") {
		t.Fatalf("clean: exit %d\n%s", code, out)
	}

	// the same Bash call decided twice: the hook runs two times
	now := time.Now().UTC()
	for i := 0; i < 2; i++ {
		if err := activity.Append(e.activityPath(), activity.Record{Kind: activity.KindDecision, TS: now.Add(time.Duration(i) * time.Millisecond).Format(time.RFC3339Nano),
			SessionID: "s1", ToolUseID: "toolu_dup", Cwd: e.proj, Skills: []string{"canary-basic"}, Command: "python3 x.py", Decision: "ask"}); err != nil {
			t.Fatal(err)
		}
	}
	code, out, _ = call(t, doctorCmd)
	if code != 1 || !strings.Contains(out, "fail  double hook") || !strings.Contains(out, "toolu_dup") {
		t.Fatalf("duplicate decisions: exit %d\n%s", code, out)
	}
	if !strings.Contains(out, "pass  last hook seen") {
		t.Errorf("last hook seen not reported:\n%s", out)
	}
	if code, _, _ := call(t, doctorCmd, "--exit-zero"); code != 0 {
		t.Errorf("--exit-zero exited %d", code)
	}

	// the plugin as well as the settings: a warning naming both
	code, out, _ = call(t, doctorCmd, "--plugin")
	if !strings.Contains(out, "warn  registration") || !strings.Contains(out, "plugin and") {
		t.Fatalf("plugin + settings: exit %d\n%s", code, out)
	}

	// the same hook twice in one file
	obj, _, _ := settings.Load(userSettings)
	hooks := obj.Object("hooks", false)
	pre, _ := hooks.Array("PreToolUse")
	first := pre[0]
	hooks.Set("PreToolUse", append(pre, first))
	if _, err := settings.Save(userSettings, obj, false); err != nil {
		t.Fatal(err)
	}
	_, out, _ = call(t, doctorCmd)
	if !strings.Contains(out, "warn  user settings") || !strings.Contains(out, "PreToolUse Bash: 2 entries") {
		t.Fatalf("duplicated settings entry:\n%s", out)
	}
}

func TestDoctorSandboxOnWithoutExclusionFails(t *testing.T) {
	e := newTestEnv(t)
	passSelfTest(t)
	writeFile(t, filepath.Join(e.claude, "settings.json"), `{"sandbox":{"enabled":true}}`)
	code, out, _ := call(t, doctorCmd, "--plugin")
	if code != 1 || !strings.Contains(out, "fail  sandbox exclusion") {
		t.Fatalf("exit %d\n%s", code, out)
	}
}

func TestDoctorJSONShape(t *testing.T) {
	newTestEnv(t)
	passSelfTest(t)
	code, out, _ := call(t, doctorCmd, "--json")
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	if len(raw) != 2 || raw["ok"] == nil || raw["checks"] == nil {
		t.Fatalf("top-level keys: %s", out)
	}
	var rep struct {
		OK     bool                `json:"ok"`
		Checks []map[string]string `json:"checks"`
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	anyFail := false
	for _, c := range rep.Checks {
		if len(c) != 3 || c["name"] == "" || c["message"] == "" {
			t.Errorf("check shape: %v", c)
		}
		switch c["status"] {
		case "pass", "warn":
		case "fail":
			anyFail = true
		default:
			t.Errorf("status %q", c["status"])
		}
		names[c["name"]] = true
	}
	for _, n := range []string{"plugin", "binary", "user settings", "registration", "sandbox exclusion", "double hook", "last hook seen", "sessions", "sandbox self-test"} {
		if !names[n] {
			t.Errorf("no %q check", n)
		}
	}
	// nothing is installed in the temp env: the registration check fails
	if rep.OK || !anyFail || code != 1 {
		t.Errorf("ok=%v anyFail=%v exit=%d; want a failure", rep.OK, anyFail, code)
	}
}

func demoCmd(a []string, o, e *bytes.Buffer) int { return cmdDemo(a, o, e) }

func TestDemoDeniesNetwork(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin only")
	}
	if !sandbox.Available() {
		t.Skip("no sandbox-exec")
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("no python3")
	}
	e := newTestEnv(t)
	before, _ := filepath.Glob("/var/tmp/watchdeck-demo-*")
	code, out, errb := call(t, demoCmd, "--no-open")
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errb)
	}
	for _, want := range []string{
		"net: DENIED(1)",
		"[watchdeck] exit 1 under profile canary-request/",
		"requested but not granted: canary-request: network: all",
		"watchdeck allow canary-request --network all",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	// the demo's own log, never the user's
	if _, err := os.Stat(e.activityPath()); err == nil {
		t.Error("demo wrote the user's activity log")
	}
	after, _ := filepath.Glob("/var/tmp/watchdeck-demo-*")
	if len(after) > len(before) {
		t.Errorf("demo left its directory behind with --no-open: %v", after)
	}
}

func TestDoctorOldDuplicatesOnlyWarn(t *testing.T) {
	e := newTestEnv(t)
	passSelfTest(t)
	userSettings := filepath.Join(e.claude, "settings.json")
	bin := filepath.Join(e.home, "bin", "watchdeck")
	writeFile(t, bin, "#!/bin/sh\n")
	if err := os.Chmod(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := settings.Install(userSettings, bin); err != nil {
		t.Fatal(err)
	}
	// decided twice three hours before the settings were last written: history
	old := time.Now().Add(-3 * time.Hour).UTC()
	for i := 0; i < 2; i++ {
		if err := activity.Append(e.activityPath(), activity.Record{Kind: activity.KindDecision, TS: old.Add(time.Duration(i) * time.Millisecond).Format(time.RFC3339Nano),
			SessionID: "s1", ToolUseID: "toolu_old", Cwd: e.proj, Skills: []string{"canary-basic"}, Command: "python3 x.py", Decision: "ask"}); err != nil {
			t.Fatal(err)
		}
	}
	code, out, _ := call(t, doctorCmd)
	if code != 0 || !strings.Contains(out, "warn  double hook") || !strings.Contains(out, "none since") {
		t.Fatalf("old duplicates: exit %d\n%s", code, out)
	}
	if !strings.Contains(out, "last hook seen     2h 59m ago") && !strings.Contains(out, "last hook seen     3h 0m ago") {
		t.Errorf("last hook seen not in hours:\n%s", out)
	}
}

func TestDoctorReadsLocalSettingsAndBinaries(t *testing.T) {
	e := newTestEnv(t)
	passSelfTest(t)
	// the sandbox is switched on in the user's settings.local.json only
	writeFile(t, filepath.Join(e.claude, "settings.local.json"), `{"sandbox":{"enabled":true}}`)
	code, out, _ := call(t, doctorCmd, "--plugin")
	if code != 1 || !strings.Contains(out, "fail  sandbox exclusion") {
		t.Fatalf("sandbox on in settings.local.json: exit %d\n%s", code, out)
	}
	// hooks in user and project files naming different binaries
	a, b := filepath.Join(e.home, "a", "watchdeck"), filepath.Join(e.home, "b", "watchdeck")
	for _, p := range []string{a, b} {
		writeFile(t, p, "#!/bin/sh\n")
		os.Chmod(p, 0o755)
	}
	if _, err := settings.Install(filepath.Join(e.claude, "settings.json"), a); err != nil {
		t.Fatal(err)
	}
	if _, err := settings.Install(filepath.Join(e.proj, ".claude", "settings.json"), b); err != nil {
		t.Fatal(err)
	}
	_, out, _ = call(t, doctorCmd)
	if !strings.Contains(out, "warn  hook binaries") || !strings.Contains(out, a) || !strings.Contains(out, b) {
		t.Fatalf("different binaries not reported:\n%s", out)
	}
	if !strings.Contains(out, "warn  registration") {
		t.Fatalf("two files registering the hook not reported:\n%s", out)
	}
}

func TestAgo(t *testing.T) {
	for d, want := range map[time.Duration]string{
		5 * time.Second: "5s", 3 * time.Minute: "3m", 90 * time.Minute: "1h 30m", 50 * time.Hour: "2d",
	} {
		if got := ago(d); got != want {
			t.Errorf("ago(%v) = %q, want %q", d, got, want)
		}
	}
}

func TestIsTerminalRefusesDevNullAndPipes(t *testing.T) {
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if isTerminal(f.Fd()) {
		t.Error("/dev/null counted as a terminal")
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	if isTerminal(r.Fd()) {
		t.Error("a pipe counted as a terminal")
	}
}

// TestDemoUICommandUsesTheDemoTree: the dashboard the demo starts resolves
// every location inside the demo tree and reads no transcripts.
func TestDemoUICommandUsesTheDemoTree(t *testing.T) {
	e := newTestEnv(t)
	d, err := demo.Prepare()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Remove() })
	cmd := demoUICommand("/opt/sp/watchdeck", d, os.Environ())
	if got := strings.Join(cmd.Args, " "); got != "/opt/sp/watchdeck ui --detach --open --no-transcripts" {
		t.Errorf("args = %q", got)
	}
	if cmd.Dir != d.Cwd {
		t.Errorf("dir = %q, want %q", cmd.Dir, d.Cwd)
	}
	env := map[string]string{}
	for _, kv := range cmd.Env {
		k, v, _ := strings.Cut(kv, "=")
		if _, dup := env[k]; dup {
			t.Errorf("%s set twice", k)
		}
		env[k] = v
	}
	for _, k := range []string{"HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME", "CLAUDE_CONFIG_DIR", "WATCHDECK_ACTIVITY"} {
		if !strings.HasPrefix(env[k], d.Base+"/") {
			t.Errorf("%s = %q, not under the demo tree %s", k, env[k], d.Base)
		}
	}
	for _, real := range []string{e.home, e.cfg, e.cache, e.state, e.claude} {
		for k, v := range env {
			if v == real {
				t.Errorf("%s still names the user's %s", k, real)
			}
		}
	}
	if env["WATCHDECK_ACTIVITY"] != d.Activity {
		t.Errorf("activity = %q, want %q", env["WATCHDECK_ACTIVITY"], d.Activity)
	}
}

// TestDoctorLifecycle: a file without the lifecycle hooks is a warning
// naming the missing ones, not a failure (the generic partial-install line;
// the separate M4 line could not fire for a real M4 file, whose Bash|Skill
// PermissionDenied group counts as missing, and was removed 2026-10-19); a full install passes; the
// sessions check counts live and idle sessions; WATCHDECK_LIFECYCLE=off is
// a warning.
func TestDoctorLifecycle(t *testing.T) {
	e := newTestEnv(t)
	passSelfTest(t)
	userSettings := filepath.Join(e.claude, "settings.json")
	bin := filepath.Join(e.home, "bin", "watchdeck")
	writeFile(t, bin, "#!/bin/sh\n")
	if err := os.Chmod(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	// PermissionDenied is "*" here; a pre-2026-10-19 install (Bash|Skill) shows it as missing until Install migrates it (TestDeniedMatcherMigrates).
	m4 := `{"hooks": {"PreToolUse": [` +
		`{"matcher": "Bash", "hooks": [{"type": "command", "command": "` + bin + `", "args": ["hook"], "timeout": 5}]},` +
		`{"matcher": "Skill", "hooks": [{"type": "command", "command": "` + bin + `", "args": ["hook"], "timeout": 5}]}],` +
		`"PermissionDenied": [{"matcher": "*", "hooks": [{"type": "command", "command": "` + bin + `", "args": ["hook"], "timeout": 5}]}]},` +
		`"sandbox": {"excludedCommands": ["watchdeck run *"]}}`
	writeFile(t, userSettings, m4)
	code, out, _ := call(t, doctorCmd)
	if code != 0 || !strings.Contains(out, "warn  user settings") || !strings.Contains(out, "3 of 6 hooks, missing SessionStart, SessionEnd, UserPromptSubmit; watchdeck enforce install adds the rest") || strings.Contains(out, "an M4 install") {
		t.Fatalf("lifecycle hooks missing: exit %d\n%s", code, out)
	}
	// a real M4 file (PermissionDenied matcher Bash|Skill): the same line,
	// with PermissionDenied among the missing until Install migrates it
	writeFile(t, userSettings, strings.Replace(m4, `"matcher": "*"`, `"matcher": "Bash|Skill"`, 1))
	if code, out, _ := call(t, doctorCmd); code != 0 || !strings.Contains(out, "2 of 6 hooks, missing PermissionDenied *, SessionStart, SessionEnd, UserPromptSubmit; watchdeck enforce install adds the rest") {
		t.Fatalf("real M4 file: exit %d\n%s", code, out)
	}
	writeFile(t, userSettings, m4)
	if !strings.Contains(out, "pass  sessions") || !strings.Contains(out, "no session recorded yet") {
		t.Fatalf("empty lifecycle:\n%s", out)
	}

	if _, err := settings.Install(userSettings, bin); err != nil {
		t.Fatal(err)
	}
	st := lifecycle.Store{Log: filepath.Join(e.state, "watchdeck", "sessions.jsonl"), Live: filepath.Join(e.state, "watchdeck", "live")}
	for _, id := range []string{"live-1", "live-2", "idle-1", "ended-1"} {
		if _, err := st.Start(id, "", e.proj, "startup"); err != nil {
			t.Fatal(err)
		}
	}
	old := time.Now().Add(-time.Hour)
	_ = os.Chtimes(filepath.Join(st.Live, "idle-1"), old, old)
	if err := st.End("ended-1", "", e.proj, "other"); err != nil {
		t.Fatal(err)
	}
	code, out, _ = call(t, doctorCmd)
	if code != 0 || !strings.Contains(out, "all 6 hooks") || !strings.Contains(out, "pass  sessions") || !strings.Contains(out, "2 live, 1 idle, 1 ended") {
		t.Fatalf("full install: exit %d\n%s", code, out)
	}

	t.Setenv("WATCHDECK_LIFECYCLE", "off")
	_, out, _ = call(t, doctorCmd)
	if !strings.Contains(out, "warn  sessions") || !strings.Contains(out, "WATCHDECK_LIFECYCLE=off") {
		t.Fatalf("lifecycle off:\n%s", out)
	}
}

// installed_at is written on the first successful settings install only; a
// declined or not-applied run records nothing, and a rerun keeps the date.
func TestSetupRecordsInstalledAtOnce(t *testing.T) {
	e := newTestEnv(t)
	passSelfTest(t)
	userSettings := filepath.Join(e.claude, "settings.json")
	writeFile(t, userSettings, "{}\n")
	cfgFile := filepath.Join(e.cfg, "watchdeck", "config.yaml")

	// the rules, then the hooks declined
	c, out := testConsole("n\nn\n", true, false)
	if code := runSetup(c, setupOptions{}); code != 1 {
		t.Fatalf("declined: exit %d\n%s", code, out)
	}
	if cfg, _ := userconfig.Load(cfgFile); cfg.Installed != "" {
		t.Fatalf("declined run recorded installed_at = %q", cfg.Installed)
	}

	code, doc, _ := call(t, doctorCmd)
	if !strings.Contains(doc, "install date") || !strings.Contains(doc, "not recorded") {
		t.Fatalf("doctor before install (exit %d):\n%s", code, doc)
	}

	c, out = testConsole("\n\n\n", true, false)
	if code := runSetup(c, setupOptions{}); code != 0 {
		t.Fatalf("accepted: exit %d\n%s", code, out)
	}
	cfg, err := userconfig.Load(cfgFile)
	first, ok := cfg.InstalledAt()
	if err != nil || !ok || time.Since(first) > time.Minute {
		t.Fatalf("after install: installed_at = %q (%v, ok %v)", cfg.Installed, err, ok)
	}

	// back-date the record, rerun with a change to apply: the date stays
	old := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	if err := os.WriteFile(cfgFile, []byte("installed_at: \""+old.Format(time.RFC3339)+"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	writeFile(t, userSettings, "{}\n")
	c, out = testConsole("\n\n\n", true, false)
	if code := runSetup(c, setupOptions{}); code != 0 {
		t.Fatalf("reinstall: exit %d\n%s", code, out)
	}
	cfg, _ = userconfig.Load(cfgFile)
	if got, ok := cfg.InstalledAt(); !ok || !got.Equal(old) {
		t.Fatalf("second install changed installed_at to %q", cfg.Installed)
	}

	_, doc, _ = call(t, doctorCmd)
	if !strings.Contains(doc, "install date") || !strings.Contains(doc, "installed since 2026-01-02") {
		t.Fatalf("doctor after install:\n%s", doc)
	}
}

// assertConfigKeys fails unless the config file's top-level keys are exactly
// want, and the ui (autostart) key is absent.
func assertConfigKeys(t *testing.T, path string, want ...string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("config not written: %v", err)
	}
	var raw map[string]any
	if err := yaml.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	if len(raw) != len(want) {
		t.Fatalf("config keys = %v, want %v\n%s", raw, want, b)
	}
	for _, k := range want {
		if _, ok := raw[k]; !ok {
			t.Fatalf("config lacks %q:\n%s", k, b)
		}
	}
}

// The plugin path installs no hooks into settings but still records the date,
// once.
func TestSetupPluginPathRecordsInstalledAt(t *testing.T) {
	e := newTestEnv(t)
	passSelfTest(t)
	cfgFile := filepath.Join(e.cfg, "watchdeck", "config.yaml")
	c, out := testConsole("", false, true)
	if code := runSetup(c, setupOptions{plugin: true}); code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	cfg, _ := userconfig.Load(cfgFile)
	first, ok := cfg.InstalledAt()
	if !ok || time.Since(first) > time.Minute {
		t.Fatalf("installed_at = %q", cfg.Installed)
	}
	old := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	if err := os.WriteFile(cfgFile, []byte("installed_at: \""+old.Format(time.RFC3339)+"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, out = testConsole("", false, true)
	if code := runSetup(c, setupOptions{plugin: true}); code != 0 {
		t.Fatalf("rerun: exit %d\n%s", code, out)
	}
	cfg, _ = userconfig.Load(cfgFile)
	if got, _ := cfg.InstalledAt(); !got.Equal(old) {
		t.Fatalf("rerun changed installed_at to %q", cfg.Installed)
	}
}

// recommendedQuestion is the Rules step's question, verbatim.
const recommendedQuestion = "   Add the recommended rules to your Claude Code settings? (12 Read and Edit rules: secrets stay unread, shell start-up files and login items ask first; Read(~/.ssh/id_*) also blocks the public keys id_*.pub)"

// settingsPerms reads permissions.deny and permissions.ask from a settings file.
func settingsPerms(t *testing.T, path string) (deny, ask []string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Permissions struct {
			Deny []string `json:"deny"`
			Ask  []string `json:"ask"`
		} `json:"permissions"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("%v\n%s", err, b)
	}
	return doc.Permissions.Deny, doc.Permissions.Ask
}

// ledgerOf loads the ownership ledger from the test env's state dir.
func ledgerOf(t *testing.T, e testEnv) *claudesettings.Ledger {
	t.Helper()
	led, err := claudesettings.LoadLedger(filepath.Join(e.state, "watchdeck"))
	if err != nil {
		t.Fatal(err)
	}
	return led
}

func TestSetupInstallsRecommendedByDefault(t *testing.T) {
	e := newTestEnv(t)
	passSelfTest(t)
	userSettings := filepath.Join(e.claude, "settings.json")
	c, out := testConsole("", false, true)
	if code := runSetup(c, setupOptions{}); code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	deny, ask := settingsPerms(t, userSettings)
	led := ledgerOf(t, e)
	rec := rulebook.Recommended()
	for _, r := range rec {
		list := ask
		if r.Source.Key == claudesettings.KeyDeny {
			list = deny
		}
		if !slices.Contains(list, r.Value) {
			t.Errorf("%s %s not in settings", r.Source.Key, r.Value)
		}
		want := rulebook.IntentPrefix + rulebook.IntentID(r.Value)
		if got := led.Owners(userSettings, r.Source.Key, r.Value); !slices.Equal(got, []string{want}) {
			t.Errorf("%s claimed by %v, want [%s]", r.Value, got, want)
		}
	}
	if len(deny)+len(ask) != len(rec) || len(led.Entries) != len(rec) {
		t.Errorf("deny %v ask %v ledger %d entries; want %d strings", deny, ask, len(led.Entries), len(rec))
	}
	if !strings.Contains(out.String(), "added 12 recommended rules") {
		t.Errorf("output does not say what was added:\n%s", out)
	}
	cfg, _ := userconfig.Load(filepath.Join(e.cfg, "watchdeck", "config.yaml"))
	if _, ok := cfg.InstalledAt(); !ok {
		t.Fatalf("installed_at not written\n%s", out)
	}
	// the Rules step runs before Hooks
	if i, j := strings.Index(out.String(), ". Rules"), strings.Index(out.String(), ". Hooks"); i < 0 || j < 0 || i > j {
		t.Errorf("Rules step not before Hooks:\n%s", out)
	}
}

func TestSetupRecommendedDeclined(t *testing.T) {
	e := newTestEnv(t)
	passSelfTest(t)
	userSettings := filepath.Join(e.claude, "settings.json")
	writeFile(t, userSettings, "{\n  \"model\": \"x\"\n}\n")
	// "n" for the rules, Enter for the hooks, Enter for autostart
	c, out := testConsole("n\n\n\n", true, false)
	if code := runSetup(c, setupOptions{}); code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	s := out.String()
	if !strings.Contains(s, recommendedQuestion+" [Y/n]") || !strings.Contains(s, "   Skipped; setup will not offer them again. Later: watchdeck rules recommended --install --all") {
		t.Fatalf("question or skip line missing:\n%s", s)
	}
	if deny, ask := settingsPerms(t, userSettings); len(deny)+len(ask) != 0 {
		t.Fatalf("declined but rules written: deny %v ask %v", deny, ask)
	}
	if st, _ := settings.Inspect(userSettings); !st.Complete {
		t.Fatalf("hooks not applied: %+v\n%s", st, s)
	}
	if led := ledgerOf(t, e); len(led.Entries) != 0 {
		t.Fatalf("ledger claims %v", led.Entries)
	}
}

func TestSetupRecommendedIdempotent(t *testing.T) {
	e := newTestEnv(t)
	passSelfTest(t)
	userSettings := filepath.Join(e.claude, "settings.json")
	writeFile(t, userSettings, "{}\n")
	c, out := testConsole("", false, true)
	if code := runSetup(c, setupOptions{}); code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	before, _ := os.ReadFile(userSettings)
	// one backup for the twelve rules (one write), one for the hooks
	nb := len(backups(t, userSettings))
	if nb != 2 {
		t.Fatalf("first run wrote %d backups, want 2\n%s", nb, out)
	}
	c, out = testConsole("", false, true)
	if code := runSetup(c, setupOptions{}); code != 0 {
		t.Fatalf("rerun exit %d\n%s", code, out)
	}
	if after, _ := os.ReadFile(userSettings); string(after) != string(before) {
		t.Fatalf("rerun changed the settings:\n%s", after)
	}
	if got := len(backups(t, userSettings)); got != nb {
		t.Fatalf("rerun wrote %d new backups", got-nb)
	}
	if !strings.Contains(out.String(), "all 12 recommended rules are in your Claude Code settings") {
		t.Errorf("rerun output:\n%s", out)
	}
	if led := ledgerOf(t, e); len(led.Entries) != 12 {
		t.Errorf("ledger has %d entries after rerun", len(led.Entries))
	}
}

const declinedEarlier = "   Recommended rules: declined earlier (watchdeck rules recommended --undecline all)\n"

// TestSetupNoDeclinesAll: a No in the Rules step puts every offered rule on
// the declined list, and the next setup says so and asks nothing.
func TestSetupNoDeclinesAll(t *testing.T) {
	e := rulesEnv(t)
	passSelfTest(t)
	userSettings := filepath.Join(e.claude, "settings.json")
	writeFile(t, userSettings, "{}\n")
	// "n" for the rules, Enter for the hooks, Enter for autostart
	c, out := testConsole("n\n\n\n", true, false)
	if code := runSetup(c, setupOptions{}); code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	d, err := rulebook.LoadDeclined(filepath.Join(e.state, "watchdeck"))
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rulebook.Recommended() {
		if !d.Has(rulebook.IntentPrefix + rulebook.IntentID(r.Value)) {
			t.Errorf("%s not declined", r.Value)
		}
	}
	// Enter for autostart only: the rules are not asked about
	c, out = testConsole("\n", true, false)
	if code := runSetup(c, setupOptions{}); code != 0 {
		t.Fatalf("rerun exit %d\n%s", code, out)
	}
	s := out.String()
	if !strings.Contains(s, declinedEarlier) || strings.Contains(s, "Add the recommended rules") {
		t.Fatalf("rerun output:\n%s", s)
	}
	if deny, ask := settingsPerms(t, userSettings); len(deny)+len(ask) != 0 {
		t.Fatalf("declined rules written: deny %v ask %v", deny, ask)
	}
}

// TestSetupYesHonoursDeclined: setup --yes installs only the offer, never a
// rule the person declined.
func TestSetupYesHonoursDeclined(t *testing.T) {
	e := rulesEnv(t)
	passSelfTest(t)
	userSettings := filepath.Join(e.claude, "settings.json")
	writeFile(t, userSettings, "{}\n")
	rec := rulebook.Recommended()
	if code, out, errs := call(t, rulesCmd, "recommended", "--decline", rec[0].ID, rec[5].ID); code != 0 {
		t.Fatalf("decline: exit %d\n%s%s", code, out, errs)
	}
	c, out := testConsole("", false, true)
	if code := runSetup(c, setupOptions{}); code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	s := out.String()
	if !strings.Contains(s, "   not offered: 2 recommended rules you declined earlier (watchdeck rules recommended --undecline all)\n") ||
		!strings.Contains(s, "added 10 recommended rules") {
		t.Errorf("output:\n%s", s)
	}
	deny, ask := settingsPerms(t, userSettings)
	all := append(deny, ask...)
	if len(all) != 10 || slices.Contains(all, rec[0].Value) || slices.Contains(all, rec[5].Value) {
		t.Fatalf("settings hold %v", all)
	}
	// a rerun with --yes still leaves them out
	c, out = testConsole("", false, true)
	if code := runSetup(c, setupOptions{}); code != 0 || !strings.Contains(out.String(), declinedEarlier) {
		t.Fatalf("rerun: exit %d\n%s", code, out)
	}
	if deny, ask := settingsPerms(t, userSettings); len(deny)+len(ask) != 10 {
		t.Fatalf("rerun changed the rules: deny %v ask %v", deny, ask)
	}
}

// TestReconcileDeclinesHandRemoved: a recommended rule setup added and the
// person then removed by hand is declined by rules reconcile, so the next
// setup --yes does not put it back.
func TestReconcileDeclinesHandRemoved(t *testing.T) {
	e := rulesEnv(t)
	passSelfTest(t)
	userSettings := filepath.Join(e.claude, "settings.json")
	c, out := testConsole("", false, true)
	if code := runSetup(c, setupOptions{}); code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	dropSetting(t, userSettings, "deny", "Read(~/.ssh/id_*)")
	if code, o, errs := call(t, rulesCmd, "reconcile"); code != 0 || !strings.Contains(o, "forgot Read(~/.ssh/id_*) in ") {
		t.Fatalf("reconcile: exit %d\n%s%s", code, o, errs)
	}
	c, out = testConsole("", false, true)
	if code := runSetup(c, setupOptions{}); code != 0 {
		t.Fatalf("rerun exit %d\n%s", code, out)
	}
	if deny, _ := settingsPerms(t, userSettings); slices.Contains(deny, "Read(~/.ssh/id_*)") {
		t.Fatalf("setup put the hand-removed rule back: %v\n%s", deny, out)
	}
	if !strings.Contains(out.String(), declinedEarlier) {
		t.Errorf("rerun output:\n%s", out)
	}
}

// TestRecommendedInstallReconcilesFirst: a recommended rule the person
// removed by hand is not re-added by `rules recommended --install --yes`
// or `setup --yes`, with no `rules reconcile` in between; the install
// reconciles first, so the intent lands on the declined list (final review
// of Plan 04, finding 2, 2026-10-19).
func TestRecommendedInstallReconcilesFirst(t *testing.T) {
	const removed = "Read(~/.ssh/id_*)"
	intent := rulebook.IntentPrefix + rulebook.IntentID(removed)
	for _, path := range []string{"rules recommended --install", "setup --yes"} {
		t.Run(path, func(t *testing.T) {
			e := rulesEnv(t)
			passSelfTest(t)
			userSettings := filepath.Join(e.claude, "settings.json")
			if code, o, errs := call(t, rulesCmd, "recommended", "--install", "--yes"); code != 0 {
				t.Fatalf("install exit %d\n%s%s", code, o, errs)
			}
			dropSetting(t, userSettings, "deny", removed)
			if path == "setup --yes" {
				c, out := testConsole("", false, true)
				if code := runSetup(c, setupOptions{}); code != 0 {
					t.Fatalf("setup exit %d\n%s", code, out)
				}
			} else if code, o, errs := call(t, rulesCmd, "recommended", "--install", "--yes"); code != 0 {
				t.Fatalf("rerun exit %d\n%s%s", code, o, errs)
			}
			if deny, _ := settingsPerms(t, userSettings); slices.Contains(deny, removed) {
				t.Fatalf("%s put the hand-removed rule back: %v", path, deny)
			}
			d, err := rulebook.LoadDeclined(filepath.Join(e.state, "watchdeck"))
			if err != nil || !d.Has(intent) {
				t.Errorf("declined = %v %v, want %s", d.IntentIDs, err, intent)
			}
		})
	}
}
