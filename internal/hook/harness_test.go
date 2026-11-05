package hook

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Panda-Taps-LLC/watchdeck/internal/activity"

	"github.com/Panda-Taps-LLC/watchdeck/internal/lifecycle"
)

// Every record the hook writes names its harness: claude-code by default,
// the --harness value when set.
func TestHarnessOnEveryRecord(t *testing.T) {
	for _, tc := range []struct{ set, want string }{{"", "claude-code"}, {"codex", "codex"}} {
		f := newFx(t)
		logp := f.withLog(t)
		f.writeUser(t, richUser)
		f.env.Harness = tc.set
		f.env.Lifecycle = lifecycle.Store{Log: filepath.Join(t.TempDir(), "sessions.jsonl"), Live: filepath.Join(t.TempDir(), "live")}

		runHook(t, f.env, f.in("python3 ~/.claude/skills/pdf/scripts/fill.py"), &bytes.Buffer{})
		runHook(t, f.env, Input{HookEventName: "PermissionDenied", SessionID: "s", ToolUseID: "toolu_d", Cwd: f.cwd,
			ToolName: "Skill", ToolInput: map[string]any{"skill": "pdf"}}, &bytes.Buffer{})
		runHook(t, f.env, Input{HookEventName: "PreToolUse", SessionID: "s", Cwd: f.cwd,
			ToolName: "Skill", ToolInput: map[string]any{"skill": "pdf"}}, &bytes.Buffer{})
		runHook(t, f.env, Input{HookEventName: EventSessionStart, SessionID: "s", Cwd: f.cwd, TranscriptPath: "/x/t.jsonl", Source: "startup"}, &bytes.Buffer{})

		runHook(t, f.env, f.in("cat .env"), &bytes.Buffer{})
		recs := readLog(t, logp)
		kinds := map[string]bool{}
		for _, r := range recs {
			kinds[r.Kind] = true
		}
		for _, k := range []string{activity.KindDecision, activity.KindDenied, activity.KindSkillInvoked, activity.KindRuleLog} {
			if !kinds[k] {
				t.Fatalf("no %s record among %v", k, kinds)
			}
		}
		// The stored line itself carries the field, not just the read default.
		rawLog, err := os.ReadFile(logp)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(strings.TrimSpace(string(rawLog)), "\n") {
			if !strings.Contains(line, `"harness":"`+tc.want+`"`) {
				t.Fatalf("raw line %d lacks harness %q: %s", i, tc.want, line)
			}
		}
		for _, r := range recs {
			if r.Harness != tc.want {
				t.Fatalf("%s record harness = %q, want %q", r.Kind, r.Harness, tc.want)
			}
		}
		raw, err := os.ReadFile(f.env.Lifecycle.Log)
		if err != nil || !strings.Contains(string(raw), `"harness":"`+tc.want+`"`) {
			t.Fatalf("lifecycle log %v: %s", err, raw)
		}
	}
}
