package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Panda-Taps-LLC/watchdeck/internal/demo"
	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
	"github.com/Panda-Taps-LLC/watchdeck/internal/prove"
	"github.com/Panda-Taps-LLC/watchdeck/internal/runner"
	"github.com/Panda-Taps-LLC/watchdeck/internal/sandbox"
	"github.com/Panda-Taps-LLC/watchdeck/internal/settings"
)

var proveNames = []string{"prove: registration", "prove: rewrite", "prove: sandbox", "prove: read rule", "prove: shadow"}

// proveReady skips unless the real prove can run here: /var/tmp, python3,
// a sandbox backend, and a real self-test that is not nested.
func proveReady(t *testing.T) {
	t.Helper()
	if fi, err := os.Stat("/var/tmp"); err != nil || !fi.IsDir() {
		t.Skip("no /var/tmp")
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("no python3")
	}
	if !sandbox.Available() {
		t.Skip("no sandbox backend")
	}
	if st := runner.SandboxSelfTest(context.Background(), paths.EnvMap(os.Environ())); st.Nested {
		t.Skip("inside a sandbox: no profile can apply here")
	}
}

// registerStub writes script as an executable named exactly watchdeck
// (hookNamed recognises nothing else, and the rewrite's bare word must
// resolve to it), registers it in the user settings and puts its dir first
// on PATH. It returns the stub's path.
func registerStub(t *testing.T, e testEnv, script string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "bin")
	stub := filepath.Join(dir, "watchdeck")
	writeFile(t, stub, script)
	if err := os.Chmod(stub, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := settings.Install(filepath.Join(e.claude, "settings.json"), stub); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return stub
}

// proveReport is doctor --prove's report, in process.
func proveReport(t *testing.T, forcePlugin bool) doctorReport {
	t.Helper()
	rep := runDoctor(forcePlugin)
	doctorProve(&rep, forcePlugin)
	return rep
}

// wantCheck asserts a check's status and that its message holds every want.
func wantCheck(t *testing.T, rep doctorReport, name, status string, want ...string) {
	t.Helper()
	c := checkNamed(t, rep, name)
	if c.Status != status {
		t.Errorf("%s: status %s, want %s: %s", name, c.Status, status, c.Message)
		return
	}
	for _, w := range want {
		if !strings.Contains(c.Message, w) {
			t.Errorf("%s: message lacks %q: %s", name, w, c.Message)
		}
	}
}

func TestDoctorProveDeniesCanary(t *testing.T) {
	bin := testBinary(t) // before newTestEnv: go build must see the real HOME and module cache
	e := newTestEnv(t)
	proveReady(t)
	fakeServiceRunner(t)
	if _, err := settings.Install(filepath.Join(e.claude, "settings.json"), bin); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", filepath.Dir(bin)+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("CLAUDE_PROJECT_DIR", filepath.Join(t.TempDir(), "elsewhere"))
	before, _ := filepath.Glob("/var/tmp/" + paths.BinaryName + "-demo-*")

	rep := proveReport(t, false)
	for _, n := range proveNames {
		t.Logf("%-20s %s  %s", n, checkNamed(t, rep, n).Status, checkNamed(t, rep, n).Message)
	}
	wantCheck(t, rep, "prove: registration", statusPass, bin)
	wantCheck(t, rep, "prove: rewrite", statusPass, paths.BinaryName+" run --skill "+demo.Skill)
	wantCheck(t, rep, "prove: sandbox", statusPass, "net: DENIED", "joined")
	wantCheck(t, rep, "prove: read rule", statusPass, "denied", prove.RuleID)
	wantCheck(t, rep, "prove: shadow", statusPass)

	if _, err := os.Stat(e.activityPath()); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the real activity log exists after the prove: %v", err)
	}
	after, _ := filepath.Glob("/var/tmp/" + paths.BinaryName + "-demo-*")
	for _, d := range after {
		if !slices.Contains(before, d) {
			t.Errorf("a throwaway tree is left behind: %s", d)
		}
	}

	code, out, errb := call(t, doctorCmd, "--prove", "--json", "--exit-zero")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errb)
	}
	var got doctorReport
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	idx := map[string]int{}
	for i, c := range got.Checks {
		idx[c.Name] = i
	}
	prev, ok := idx["sandbox self-test"]
	if !ok {
		t.Fatal("no sandbox self-test check")
	}
	for _, n := range proveNames {
		i, ok := idx[n]
		if !ok || i <= prev {
			t.Fatalf("%q missing or out of order (index %d after %d): %v", n, i, prev, idx)
		}
		prev = i
	}
}

func TestDoctorProveFailsWhenHookStubbed(t *testing.T) {
	e := newTestEnv(t)
	passSelfTest(t)
	fakeServiceRunner(t)
	registerStub(t, e, "#!/bin/sh\nexit 0\n")

	rep := proveReport(t, false)
	wantCheck(t, rep, "prove: registration", statusPass)
	wantCheck(t, rep, "prove: rewrite", statusFail, "no opinion")
	wantCheck(t, rep, "prove: sandbox", statusFail, "not run (prove: rewrite failed)")
	wantCheck(t, rep, "prove: read rule", statusFail, "no opinion")
	wantCheck(t, rep, "prove: shadow", statusPass)
	if rep.OK {
		t.Error("report OK with a stubbed hook")
	}
	if code, out, _ := call(t, doctorCmd, "--prove"); code != 1 {
		t.Errorf("--prove exit %d, want 1\n%s", code, out)
	}
	code, out, _ := call(t, doctorCmd)
	if strings.Contains(out, "prove: ") {
		t.Errorf("plain doctor printed prove checks:\n%s", out)
	}
	if code != 0 {
		t.Logf("plain doctor exits %d in this env (another check fails); --prove is still what adds the prove checks", code)
	}
}

func TestDoctorProveShadowOn(t *testing.T) {
	e := newTestEnv(t)
	passSelfTest(t)
	fakeServiceRunner(t)
	registerStub(t, e, "#!/bin/sh\nexit 0\n")
	writeFile(t, filepath.Join(e.cfg, paths.BinaryName, "overrides.yaml"), "version: 2\nmode: shadow\n")

	rep := proveReport(t, false)
	wantCheck(t, rep, "prove: shadow", statusFail, "shadow mode is on", paths.BinaryName+" rules shadow off")
	if rep.OK {
		t.Error("report OK with shadow mode on")
	}
}

func TestDoctorProveNoRegistration(t *testing.T) {
	newTestEnv(t)
	passSelfTest(t)
	fakeServiceRunner(t)
	rep := proveReport(t, false)
	wantCheck(t, rep, "prove: registration", statusFail, "no hooks registered", paths.BinaryName+" setup")
	for _, n := range []string{"prove: rewrite", "prove: sandbox", "prove: read rule"} {
		wantCheck(t, rep, n, statusFail, "not run (prove: registration failed)")
	}
	wantCheck(t, rep, "prove: shadow", statusPass)
}

func TestDoctorProveApplyFailure(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("no python3: the sandbox leg would warn before the stub's run branch")
	}
	if !sandbox.Available() {
		t.Skip("no sandbox backend: the sandbox leg would fail before the stub's run branch")
	}
	e := newTestEnv(t)
	passSelfTest(t)
	fakeServiceRunner(t)
	// The stub rewrites the probe command it was given (the rewrite leg
	// compares the -c payload with it), then fails to apply the sandbox.
	registerStub(t, e, strings.ReplaceAll(`#!/bin/sh
case "$1" in
hook) PY -I -c '
import json, shlex, sys
d = json.load(sys.stdin)
if d.get("tool_name") == "Bash":
    c = "watchdeck run --skill canary-request -c " + shlex.quote(d["tool_input"]["command"])
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "ask", "permissionDecisionReason": "stub", "updatedInput": {"command": c}}}))
'; exit 0 ;;
run)  echo "[watchdeck] could not apply the sandbox (nested sandbox)" >&2; exit 126 ;;
esac
`, "PY", py))
	rep := proveReport(t, false)
	wantCheck(t, rep, "prove: rewrite", statusPass)
	wantCheck(t, rep, "prove: sandbox", statusFail, "could not apply the sandbox", "exit 126")
	wantCheck(t, rep, "prove: read rule", statusFail, "no opinion")
}

func TestDoctorProveReadAskIsFail(t *testing.T) {
	e := newTestEnv(t)
	passSelfTest(t)
	fakeServiceRunner(t)
	registerStub(t, e, `#!/bin/sh
in=$(cat)
case "$in" in *'"tool_name":"Read"'*)
  printf '%s\n' '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"stub asks"}}' ;;
esac
exit 0
`)
	rep := proveReport(t, false)
	wantCheck(t, rep, "prove: read rule", statusFail, "asked instead of denying", "stub asks")
}

func TestDoctorUsageMentionsProve(t *testing.T) {
	if !strings.Contains(doctorUsage, "--prove") {
		t.Fatal("doctorUsage does not mention --prove")
	}
}

func TestDoctorProveIgnoresProjectRegistration(t *testing.T) {
	e := newTestEnv(t)
	passSelfTest(t)
	fakeServiceRunner(t)
	marker := filepath.Join(t.TempDir(), "ran")
	dir := filepath.Join(t.TempDir(), "bin")
	stub := filepath.Join(dir, "watchdeck")
	writeFile(t, stub, "#!/bin/sh\ntouch '"+marker+"'\ncat >/dev/null\nexit 0\n")
	if err := os.Chmod(stub, 0o755); err != nil {
		t.Fatal(err)
	}
	projectFile := filepath.Join(e.proj, ".claude", "settings.json")
	if _, err := settings.Install(projectFile, stub); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	rep := proveReport(t, false)
	wantCheck(t, rep, "prove: registration", statusFail, "not run: prove runs user-scope registrations only", displayHome(projectFile, e.home), paths.BinaryName+" setup")
	for _, n := range []string{"prove: rewrite", "prove: sandbox", "prove: read rule"} {
		wantCheck(t, rep, n, statusFail, "not run (prove: registration failed)")
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the project-scope stub ran (marker %v)", err)
	}

	// a user-scope registration wins and the project one is named, not run
	user := registerStub(t, e, "#!/bin/sh\ncat >/dev/null\nexit 0\n")
	rep = proveReport(t, false)
	wantCheck(t, rep, "prove: registration", statusPass, user, "; project-scope entry in "+displayHome(projectFile, e.home)+" not run")
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the project-scope stub ran (marker %v)", err)
	}
}
