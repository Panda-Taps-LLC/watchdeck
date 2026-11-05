package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/activity"
)

func statusCmd(a []string, o, e *bytes.Buffer) int { return cmdStatus(a, o, e) }

// setupYes runs "watchdeck setup --yes" in the test env.
func setupYes(t *testing.T, o setupOptions) {
	t.Helper()
	c, out := testConsole("", false, true)
	if code := runSetup(c, o); code != 0 {
		t.Fatalf("setup --yes: exit %d\n%s", code, out)
	}
}

// statusLines checks the fixed five lines of the text output (every line
// but the indented check lines) and returns the indented ones.
func statusLines(t *testing.T, out string, want ...string) []string {
	t.Helper()
	var top, checks []string
	for _, l := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		if strings.HasPrefix(l, "  ") {
			checks = append(checks, l)
		} else {
			top = append(top, l)
		}
	}
	if len(top) != 5 {
		t.Fatalf("want 5 top lines, got %d:\n%s", len(top), out)
	}
	for i, w := range want {
		if w != "" && top[i] != w {
			t.Errorf("line %d: %q, want %q", i+1, top[i], w)
		}
	}
	return checks
}

// TestStatusText: after setup --yes the status screen says Protected, no
// item needs the person, no session is live and the dashboard is not
// running; the checks line counts the doctor report and lists each warn
// and fail check on its own indented line.
func TestStatusText(t *testing.T) {
	newTestEnv(t)
	passSelfTest(t)
	setupYes(t, setupOptions{})

	code, out, errOut := call(t, statusCmd)
	rep := runDoctor(false)
	wantCode := 0
	if !rep.OK {
		wantCode = 1
	}
	if code != wantCode {
		t.Fatalf("exit %d, want %d; stderr %q\n%s", code, wantCode, errOut, out)
	}
	p, w, f, bad := doctorTally(rep)
	checks := statusLines(t, out,
		"watchdeck dev · Protected",
		"Live sessions: 0 (idle 0)",
		"Needs you: 0  (watchdeck inbox)",
		"Dashboard: not running (run watchdeck)",
		"Checks: "+itoa(p)+" passed, "+itoa(w)+" warnings, "+itoa(f)+" failed  (watchdeck doctor)")
	if len(checks) != len(bad) {
		t.Fatalf("%d check lines, want %d:\n%s", len(checks), len(bad), out)
	}
	for i, c := range bad {
		if want := "  " + c.Status + " " + c.Name + ": " + c.Message; checks[i] != want {
			t.Errorf("check line %q, want %q", checks[i], want)
		}
	}

	// one auto-mode denial after the install date is one item that needs you
	e := newTestEnv(t)
	passSelfTest(t)
	setupYes(t, setupOptions{})
	ts := time.Now().UTC().Format(time.RFC3339Nano)
	if err := activity.Append(e.activityPath(), activity.Record{Kind: activity.KindDenied, TS: ts, SessionID: "s1",
		ToolUseID: "t1", Cwd: e.proj, ToolName: "Bash", Argv0: "curl", Reason: "auto mode blocked a download"}); err != nil {
		t.Fatal(err)
	}
	_, out, _ = call(t, statusCmd, "--exit-zero")
	statusLines(t, out, "", "", "Needs you: 1  (watchdeck inbox)")
}

// TestStatusOffSources: with the lifecycle records and the activity log
// off, the two lines say so instead of a count; with nothing installed the
// first line says Not protected.
func TestStatusOffSources(t *testing.T) {
	newTestEnv(t)
	passSelfTest(t)
	t.Setenv("WATCHDECK_ACTIVITY", "off")
	t.Setenv("WATCHDECK_LIFECYCLE", "off")
	_, out, _ := call(t, statusCmd, "--exit-zero")
	statusLines(t, out, "watchdeck dev · Not protected", "Live sessions: lifecycle off", "Needs you: activity log off")

	code, out, _ := call(t, statusCmd, "--json", "--exit-zero")
	var got statusReport
	if err := json.Unmarshal([]byte(out), &got); code != 0 || err != nil {
		t.Fatalf("exit %d, %v\n%s", code, err, out)
	}
	if got.Protection != "off" || got.NeedsEnabled || got.Needs != 0 {
		t.Fatalf("json: %+v", got)
	}
}

// TestStatusJSON: --json prints exactly the documented keys, with the
// doctor report in the same shape as "doctor --json".
func TestStatusJSON(t *testing.T) {
	newTestEnv(t)
	passSelfTest(t)
	setupYes(t, setupOptions{})
	_, out, errOut := call(t, statusCmd, "--json", "--exit-zero")
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		t.Fatalf("not JSON: %v\n%s%s", err, out, errOut)
	}
	var keys []string
	for k := range raw {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if got, want := strings.Join(keys, ","), "dashboard,doctor,idle,live,needs,needs_enabled,protection,version"; got != want {
		t.Fatalf("keys %s, want %s", got, want)
	}
	var dash map[string]json.RawMessage
	if err := json.Unmarshal(raw["dashboard"], &dash); err != nil || len(dash) != 2 || string(dash["running"]) != "false" || string(dash["port"]) != "0" {
		t.Fatalf("dashboard %s", raw["dashboard"])
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw["doctor"], &doc); err != nil || len(doc) != 2 || doc["ok"] == nil || doc["checks"] == nil {
		t.Fatalf("doctor %s", raw["doctor"])
	}
	var got statusReport
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatal(err)
	}
	if got.Version != "dev" || got.Protection != "protected" || !got.NeedsEnabled || got.Needs != 0 || got.Live != 0 || got.Idle != 0 || len(got.Doctor.Checks) == 0 {
		t.Fatalf("json: %+v", got)
	}
}

// TestStatusExitOnDoctorFail: a failing doctor check (Claude Code's
// sandbox on without the exclusion) exits 1 and is listed; --exit-zero
// exits 0 with the same output. Protection is off: nothing of ours is in
// the settings.
func TestStatusExitOnDoctorFail(t *testing.T) {
	e := newTestEnv(t)
	passSelfTest(t)
	writeFile(t, filepath.Join(e.claude, "settings.json"), `{"sandbox": {"enabled": true}}`+"\n")
	code, out, _ := call(t, statusCmd)
	if code != 1 {
		t.Fatalf("exit %d, want 1\n%s", code, out)
	}
	checks := statusLines(t, out, "watchdeck dev · Not protected")
	found := false
	for _, l := range checks {
		if strings.HasPrefix(l, "  fail sandbox exclusion: ") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no fail line for the sandbox exclusion:\n%s", out)
	}
	code, out2, _ := call(t, statusCmd, "--exit-zero")
	if code != 0 || out2 != out {
		t.Fatalf("--exit-zero: exit %d\n%s", code, out2)
	}
	code, out, _ = call(t, statusCmd, "--json")
	var got statusReport
	if err := json.Unmarshal([]byte(out), &got); code != 1 || err != nil || got.Doctor.OK {
		t.Fatalf("--json: exit %d, %v, %+v", code, err, got.Doctor)
	}
	if code, _, errOut := call(t, statusCmd, "--bogus"); code != 3 || !strings.Contains(errOut, "usage: watchdeck status") {
		t.Fatalf("--bogus: exit %d, %q", code, errOut)
	}
	if code, _, _ := call(t, statusCmd, "extra"); code != 3 {
		t.Fatalf("extra arg: exit %d", code)
	}
}

// TestStatusPluginProtected: a plugin install leaves only the sandbox
// exclusion in the user settings (the plugin carries the rest); with
// --plugin that is Protected, without it Partly protected.
func TestStatusPluginProtected(t *testing.T) {
	newTestEnv(t)
	passSelfTest(t)
	setupYes(t, setupOptions{plugin: true, exclusionOnly: true})
	_, out, _ := call(t, statusCmd, "--plugin", "--exit-zero")
	statusLines(t, out, "watchdeck dev · Protected")
	_, out, _ = call(t, statusCmd, "--exit-zero")
	statusLines(t, out, "watchdeck dev · Partly protected")
}

// TestStatusPluginNoExclusion: with the plugin on and no sandbox exclusion
// in the user settings (no file, an empty one, one without the entry), the
// plugin's checks run but the exclusion is missing: Partly protected,
// "partial" in the JSON. Without the plugin the same files are Not
// protected.
func TestStatusPluginNoExclusion(t *testing.T) {
	for _, tc := range []struct{ name, settings string }{
		{"no file", ""},
		{"empty", "{}\n"},
		{"other keys", `{"permissions": {"deny": ["Read(./secrets/**)"]}}` + "\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newTestEnv(t)
			passSelfTest(t)
			if tc.settings != "" {
				writeFile(t, filepath.Join(e.claude, "settings.json"), tc.settings)
			}
			_, out, _ := call(t, statusCmd, "--plugin", "--exit-zero")
			statusLines(t, out, "watchdeck dev · Partly protected")
			_, out, _ = call(t, statusCmd, "--plugin", "--json", "--exit-zero")
			var got statusReport
			if err := json.Unmarshal([]byte(out), &got); err != nil || got.Protection != "partial" {
				t.Fatalf("json: %v %q", err, got.Protection)
			}
			_, out, _ = call(t, statusCmd, "--exit-zero")
			statusLines(t, out, "watchdeck dev · Not protected")
		})
	}
}

// doctorTally counts a report and returns its warn and fail checks in order.
func doctorTally(rep doctorReport) (pass, warn, fail int, bad []doctorCheck) {
	for _, c := range rep.Checks {
		switch c.Status {
		case statusPass:
			pass++
		case statusWarn:
			warn++
			bad = append(bad, c)
		default:
			fail++
			bad = append(bad, c)
		}
	}
	return
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}
