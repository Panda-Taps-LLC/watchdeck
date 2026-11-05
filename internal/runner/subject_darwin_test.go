//go:build darwin

package runner

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/activity"
)

// TestRunCommandSubjectUnderSandbox: a command subject (M6.3) runs under
// Seatbelt with the default profile widened by its grant; network none is
// denied, a home write is denied, and the run record names the subject and
// joins the hook's decision for it.
func TestRunCommandSubjectUnderSandbox(t *testing.T) {
	f := newFixture(t)
	if err := os.WriteFile(filepath.Join(f.cfg, "overrides.yaml"), []byte(`version: 2
subjects:
  - {kind: command, name: probe, match: {argv0: [/usr/bin/python3]}, grant: {network: none}}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	// the script lives in the project: ~/.claude is a built-in read deny
	src, _ := os.ReadFile(filepath.Join(f.home, ".claude", "skills", "canary-basic", "scripts", "probe.py"))
	script := filepath.Join(f.cwd, "probe.py")
	os.WriteFile(script, src, 0o755)
	for action, want := range map[string]string{"net": "net: DENIED(1)", "write-home": "write-home: DENIED(1)", "write-cwd": "write-cwd: ALLOWED"} {
		cmd := "/usr/bin/python3 " + script + " " + action
		if action == "net" {
			err := activity.Append(f.activity, activity.Record{
				Kind: activity.KindDecision, TS: time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano),
				SessionID: "s1", ToolUseID: "toolu_cmd", Cwd: f.cwd, Command: cmd, Decision: "ask",
				Rewritten: "watchdeck run --subject command:probe -c '" + cmd + "'",
				Subject:   &activity.Subject{Kind: "command", Name: "probe"}, Enforcement: activity.EnforcementSandbox,
			})
			if err != nil {
				t.Fatal(err)
			}
		}
		var out, errb bytes.Buffer
		code := Run(context.Background(), Options{CommandSubject: "probe", Command: cmd, Env: f.env, Environ: f.environ, Stdout: &out, Stderr: &errb, ActivityPath: f.activity})
		if code != 0 || !strings.Contains(out.String(), want) {
			t.Fatalf("%s: code %d stdout %q stderr %q", action, code, out.String(), errb.String())
		}
		if action == "net" {
			r := f.lastRun(t)
			if r.Subject == nil || r.Subject.Kind != "command" || r.Subject.Name != "probe" || len(r.Skills) != 0 ||
				r.ToolUseID != "toolu_cmd" || r.JoinedBy != activity.JoinedByWrite || r.Enforcement != activity.EnforcementSandbox {
				t.Fatalf("run record: %+v", r)
			}
		}
	}
}

// TestRunCommandSubjectClaudeConfigDenied: a command subject's run gets
// the same extra denies as a skill run (runDeny): ~/.claude.json and its
// .backup sibling cannot be read, even with network all.
func TestRunCommandSubjectClaudeConfigDenied(t *testing.T) {
	f := newFixture(t)
	os.WriteFile(filepath.Join(f.cfg, "overrides.yaml"), []byte("version: 2\nsubjects:\n  - {kind: command, name: cat, match: {argv0: [/bin/cat]}, grant: {network: all}}\n"), 0o600)
	cfg := filepath.Join(f.home, ".claude.json")
	os.WriteFile(cfg, []byte(`{"fake":"config"}`), 0o600)
	os.WriteFile(cfg+".backup", []byte(`{"fake":"backup"}`), 0o600)
	for _, p := range []string{cfg, cfg + ".backup"} {
		var out, errb bytes.Buffer
		code := Run(context.Background(), Options{CommandSubject: "cat", Command: "/bin/cat " + p, Env: f.env, Environ: f.environ, Stdout: &out, Stderr: &errb, ActivityPath: f.activity})
		if code == 0 || strings.Contains(out.String(), "fake") || !strings.Contains(errb.String(), "Operation not permitted") {
			t.Fatalf("%s: code %d stdout %q stderr %q", p, code, out.String(), errb.String())
		}
	}
	if r := f.lastRun(t); r.Effective == nil || !slices.Contains(r.Effective.Deny, cfg) {
		t.Fatalf("run record does not name the deny: %+v", r.Effective)
	}
}

// TestRunUnknownCommandSubject: an unknown subject is a policy error (125)
// and nothing runs.
func TestRunUnknownCommandSubject(t *testing.T) {
	f := newFixture(t)
	marker := filepath.Join(f.cwd, "ran")
	var out, errb bytes.Buffer
	code := Run(context.Background(), Options{CommandSubject: "nope", Command: "touch " + marker, Env: f.env, Environ: f.environ, Stdout: &out, Stderr: &errb, ActivityPath: f.activity})
	if code != ExitPolicy || !strings.Contains(errb.String(), "unknown command subject nope") {
		t.Fatalf("code %d stderr %q", code, errb.String())
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the command ran")
	}
	if r := f.lastRun(t); r.Outcome != activity.OutcomePolicyError || r.Subject == nil || r.Subject.Name != "nope" {
		t.Fatalf("record: %+v", r)
	}
	// a project file cannot define one
	os.MkdirAll(filepath.Join(f.cwd, ".git"), 0o755)
	os.WriteFile(filepath.Join(f.cwd, ".watchdeck.yaml"), []byte("version: 2\nsubjects:\n  - {kind: command, name: proj, match: {argv0: [touch]}, grant: {network: all}}\n"), 0o600)
	if code := Run(context.Background(), Options{CommandSubject: "proj", Command: "touch " + marker, Env: f.env, Environ: f.environ, Stdout: &out, Stderr: &errb, ActivityPath: f.activity}); code != ExitPolicy {
		t.Fatalf("project command subject ran: %d", code)
	}
}
