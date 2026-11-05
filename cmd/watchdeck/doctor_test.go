package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Panda-Taps-LLC/watchdeck/internal/claudesettings"
	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
)

// TestHookCandidatesMatchHookSh keeps the Go list of install dirs and the
// plugin's shell fallback in step.
func TestHookCandidatesMatchHookSh(t *testing.T) {
	b, err := os.ReadFile("../../plugin/bin/hook.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(b)
	var loop string
	for _, line := range strings.Split(script, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "for candidate in ") {
			loop = line
		}
	}
	if loop == "" {
		t.Fatal("hook.sh has no `for candidate in` line")
	}
	var want []string
	for _, c := range paths.HookCandidates("$HOME") {
		want = append(want, `"`+c+`"`)
	}
	got := strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(loop), "for candidate in "), "; do")
	if got != strings.Join(want, " ") {
		t.Errorf("hook.sh candidates\n got: %s\nwant: %s", got, strings.Join(want, " "))
	}
	if !strings.Contains(script, `exec "$dir/`+paths.BinaryName+`" hook`) {
		t.Errorf(`hook.sh has no exec "$dir/%s" hook`, paths.BinaryName)
	}
}

// nativeRulesCheck runs doctor and returns its "native rules" check.
func nativeRulesCheck(t *testing.T) doctorCheck {
	t.Helper()
	for _, c := range runDoctor(false).Checks {
		if c.Name == "native rules" {
			return c
		}
	}
	t.Fatal("no native rules check")
	return doctorCheck{}
}

func TestDoctorNativeRulesDrift(t *testing.T) {
	e := newTestEnv(t)
	passSelfTest(t)
	path := filepath.Join(e.claude, "settings.json")

	// nothing installed yet
	if c := nativeRulesCheck(t); c.Status != statusWarn || c.Message != "recommended rules not installed (12 of 12): watchdeck rules recommended --install" {
		t.Fatalf("before install: %+v", c)
	}

	if code, o, errOut := call(t, rulesCmd, "recommended", "--install", "--yes"); code != 0 {
		t.Fatalf("rules recommended --install: exit %d\n%s%s", code, o, errOut)
	}
	if c := nativeRulesCheck(t); c.Status != statusPass || c.Message != "12 of 12 recommended rules installed; 12 rules added by watchdeck, none drifted" {
		t.Fatalf("after install: %+v", c)
	}

	// remove two owned strings by hand
	deny, ask := settingsPerms(t, path)
	var keep []string
	for _, v := range deny {
		if v != "Read(~/.netrc)" && v != "Read(~/.aws/credentials)" {
			keep = append(keep, v)
		}
	}
	b, _ := json.Marshal(map[string]any{"permissions": map[string][]string{"deny": keep, "ask": ask}})
	writeFile(t, path, string(b)+"\n")
	c := nativeRulesCheck(t)
	if c.Status != statusWarn || !strings.Contains(c.Message, "2 rules watchdeck added were removed by hand: Read(~/.aws/credentials), Read(~/.netrc)") {
		t.Fatalf("after hand removal: %+v", c)
	}
	// reported, not dropped: the ledger still holds them
	led := ledgerOf(t, e)
	for _, v := range []string{"Read(~/.netrc)", "Read(~/.aws/credentials)"} {
		if led.Owners(path, claudesettings.KeyDeny, v) == nil {
			t.Errorf("doctor dropped %s from the ledger", v)
		}
	}

	// one removed: singular wording
	writeFile(t, path, string(mustJSON(t, map[string]any{"permissions": map[string][]string{"deny": append(keep, "Read(~/.aws/credentials)"), "ask": ask}}))+"\n")
	if c := nativeRulesCheck(t); c.Status != statusWarn || !strings.Contains(c.Message, "1 rule watchdeck added was removed by hand: Read(~/.netrc)") {
		t.Fatalf("one removed: %+v", c)
	}

	// an unparsable user settings file fails
	writeFile(t, path, "{not json")
	if c := nativeRulesCheck(t); c.Status != statusFail {
		t.Fatalf("unparsable settings: %+v", c)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
