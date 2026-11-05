package hook

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/Panda-Taps-LLC/watchdeck/internal/activity"
)

// deniedRecord records one PermissionDenied Bash event and returns its record.
func deniedRecord(t *testing.T, f *fx, command, reason string) activity.Record {
	t.Helper()
	env := f.env
	env.ActivityPath = filepath.Join(t.TempDir(), "activity.jsonl")
	recordDenied(Input{HookEventName: "PermissionDenied", SessionID: "s", ToolUseID: "toolu_r", Cwd: f.cwd,
		ToolName: "Bash", ToolInput: map[string]any{"command": command}, Reason: reason}, env)
	recs := readLog(t, env.ActivityPath)
	if len(recs) != 1 {
		t.Fatalf("want 1 record, got %d", len(recs))
	}
	return recs[0]
}

func TestRedactReasonAssignmentOnly(t *testing.T) {
	f := newFx(t)
	rec := deniedRecord(t, f, "FOO=sk-FAKE-not-a-secret BAR=1", "Blocked: FOO=sk-FAKE-not-a-secret BAR=1 leaks a key")
	if strings.Contains(rec.Reason, "sk-FAKE") {
		t.Fatalf("secret in reason: %q", rec.Reason)
	}
	if rec.Reason != "Blocked: … leaks a key" || rec.Argv0 != "" || rec.Command != "" {
		t.Fatalf("reason %q argv0 %q command %q", rec.Reason, rec.Argv0, rec.Command)
	}
}

func TestRedactReasonOneWord(t *testing.T) {
	f := newFx(t)
	const want = "Permission to use Bash with command ls … has been denied."
	for _, c := range []string{"ls", "ls "} {
		rec := deniedRecord(t, f, c, "Permission to use Bash with command ls has been denied.")
		if rec.Reason != want || strings.Count(rec.Reason, "…") != 1 {
			t.Errorf("%q: reason %q", c, rec.Reason)
		}
	}
}

func TestRedactReasonTrailingSpace(t *testing.T) {
	f := newFx(t)
	rec := deniedRecord(t, f, "ls ", "Permission to use Bash with command ls has been denied.")
	if rec.Reason != "Permission to use Bash with command ls … has been denied." || strings.Count(rec.Reason, "…") != 1 {
		t.Fatalf("reason %q", rec.Reason)
	}
}

func TestRedactReasonUnchangedForSkillCommand(t *testing.T) {
	f := newFx(t)
	cmd := "python3 " + f.skill("pdf", "scripts/fill.py")
	reason := "Blocked " + cmd + " by the classifier"
	rec := deniedRecord(t, f, cmd, reason)
	if rec.Command != cmd || rec.Reason != reason {
		t.Fatalf("command %q reason %q", rec.Command, rec.Reason)
	}
}
