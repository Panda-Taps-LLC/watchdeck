package hook

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/lifecycle"
	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
)

// capturedLifecycle is the scrubbed stdin of SessionStart, UserPromptSubmit
// and SessionEnd from a real `claude -p` session (Claude Code 2.1.296,
// 2026-10-13); see internal/transcript/testdata/e2e-canary/README.md.
func capturedLifecycle(t *testing.T) [][]byte {
	t.Helper()
	f, err := os.Open(filepath.Join("..", "transcript", "testdata", "e2e-canary", "lifecycle-stdin.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out [][]byte
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if len(bytes.TrimSpace(sc.Bytes())) > 0 {
			out = append(out, append([]byte(nil), sc.Bytes()...))
		}
	}
	if len(out) != 3 {
		t.Fatalf("fixture has %d lines, want 3", len(out))
	}
	return out
}

func lifecycleStore(t *testing.T) (lifecycle.Store, string) {
	t.Helper()
	state := filepath.Join(t.TempDir(), "state", "watchdeck")
	return lifecycle.Store{Log: filepath.Join(state, "sessions.jsonl"), Live: filepath.Join(state, "live")}, state
}

func readSessions(t *testing.T, path string) []lifecycle.Record {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []lifecycle.Record
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var r lifecycle.Record
		if err := json.Unmarshal([]byte(l), &r); err != nil {
			t.Fatalf("%v: %s", err, l)
		}
		out = append(out, r)
	}
	return out
}

// TestLifecycleEventsFromCapture: the three captured payloads produce a start
// and an end record (the prompt, inside a minute of the start, only touches
// the marker), print nothing, never store the prompt text, and
// leave no marker behind; the activity log is never opened.
func TestLifecycleEventsFromCapture(t *testing.T) {
	f := newFx(t)
	st, state := lifecycleStore(t)
	f.env.Lifecycle = st
	f.env.ActivityPath = filepath.Join(t.TempDir(), "activity.jsonl")
	payloads := capturedLifecycle(t)
	var in0 Input
	_ = json.Unmarshal(payloads[0], &in0)
	for i, p := range payloads {
		var out bytes.Buffer
		if code := Run(bytes.NewReader(p), &out, f.env); code != 0 || out.Len() != 0 {
			t.Fatalf("payload %d: exit %d, stdout %q", i, code, out.String())
		}
		if i < 2 {
			if _, err := os.Stat(filepath.Join(st.Live, in0.SessionID)); err != nil {
				t.Fatalf("no marker after payload %d: %v", i, err)
			}
		}
	}
	recs := readSessions(t, st.Log)
	if len(recs) != 2 {
		t.Fatalf("records = %+v", recs)
	}
	want := []struct{ kind, source, reason string }{{"start", "startup", ""}, {"end", "", "other"}}
	for i, w := range want {
		r := recs[i]
		if r.Kind != w.kind || r.Source != w.source || r.Reason != w.reason || r.SessionID != in0.SessionID || r.Cwd != "/Users/you/proj" || r.Transcript != in0.TranscriptPath {
			t.Errorf("record %d = %+v, want %+v", i, r, w)
		}
	}
	raw, _ := os.ReadFile(st.Log)
	if bytes.Contains(raw, []byte("Reply with the single word")) || bytes.Contains(raw, []byte("prompt")) {
		t.Fatalf("prompt text or key in the log:\n%s", raw)
	}
	if _, err := os.Lstat(filepath.Join(st.Live, in0.SessionID)); !os.IsNotExist(err) {
		t.Fatalf("marker left after SessionEnd: %v", err)
	}
	if _, err := os.Stat(f.env.ActivityPath); !os.IsNotExist(err) {
		t.Fatal("lifecycle events wrote the activity log")
	}
	if fi, err := os.Stat(st.Log); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("sessions.jsonl = %v, %v", fi, err)
	}
	_ = state
}

// TestLifecycleOffWritesNothing: with the zero Store (WATCHDECK_LIFECYCLE=off)
// the three events create nothing and print nothing.
func TestLifecycleOffWritesNothing(t *testing.T) {
	f := newFx(t)
	f.env.ActivityPath = ""
	stateRoot := t.TempDir()
	hp := paths.Resolve(f.home, map[string]string{"XDG_STATE_HOME": stateRoot, "WATCHDECK_LIFECYCLE": "off"})
	f.env.Lifecycle = lifecycle.Store{Log: hp.Sessions, Live: hp.LiveDir}
	if !f.env.Lifecycle.Off() {
		t.Fatalf("WATCHDECK_LIFECYCLE=off resolved to %+v", f.env.Lifecycle)
	}
	for _, p := range capturedLifecycle(t) {
		var out bytes.Buffer
		if code := Run(bytes.NewReader(p), &out, f.env); code != 0 || out.Len() != 0 {
			t.Fatalf("exit %d, stdout %q", code, out.String())
		}
	}
	if ents, _ := os.ReadDir(stateRoot); len(ents) != 0 {
		t.Fatalf("created %v", ents)
	}
}

// TestOtherEventsTouchMarker: a PreToolUse for a started session moves the
// marker's mtime, appends no lifecycle record, and decides exactly as it
// does with the lifecycle off.
func TestOtherEventsTouchMarker(t *testing.T) {
	f := newFx(t)
	st, _ := lifecycleStore(t)
	if _, err := st.Start("s", "", f.cwd, "startup"); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(st.Live, "s")
	old := time.Now().Add(-time.Hour)
	_ = os.Chtimes(marker, old, old)

	cmd := "python3 " + f.skill("pdf", "scripts/fill.py") + " in.pdf"
	payload := func(command string) []byte {
		b, _ := json.Marshal(map[string]any{"session_id": "s", "cwd": f.cwd, "hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": map[string]any{"command": command}})
		return b
	}
	var off bytes.Buffer
	Run(bytes.NewReader(payload(cmd)), &off, f.env)

	f.env.Lifecycle = st
	var on bytes.Buffer
	Run(bytes.NewReader(payload(cmd)), &on, f.env)
	if off.String() != on.String() || on.Len() == 0 {
		t.Fatalf("decision changed by the lifecycle:\noff %s\non  %s", off.String(), on.String())
	}
	fi, _ := os.Stat(marker)
	if time.Since(fi.ModTime()) > time.Minute {
		t.Fatalf("marker not touched: %v", fi.ModTime())
	}
	// a no-opinion call touches too, and prints nothing
	_ = os.Chtimes(marker, old, old)
	var none bytes.Buffer
	Run(bytes.NewReader(payload("git status")), &none, f.env)
	fi, _ = os.Stat(marker)
	if none.Len() != 0 || time.Since(fi.ModTime()) > time.Minute {
		t.Fatalf("no-opinion: stdout %q, mtime %v", none.String(), fi.ModTime())
	}
	// PermissionDenied for the session touches as well
	_ = os.Chtimes(marker, old, old)
	Run(strings.NewReader(`{"session_id":"s","hook_event_name":"PermissionDenied","tool_name":"Bash","tool_input":{"command":"ls"}}`), &none, f.env)
	fi, _ = os.Stat(marker)
	if time.Since(fi.ModTime()) > time.Minute {
		t.Fatal("PermissionDenied did not touch the marker")
	}
	if recs := readSessions(t, st.Log); len(recs) != 1 {
		t.Fatalf("other events appended lifecycle records: %+v", recs)
	}
	// a session with no marker: nothing is created
	Run(bytes.NewReader([]byte(`{"session_id":"other","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}`)), &none, f.env)
	if _, err := os.Stat(filepath.Join(st.Live, "other")); !os.IsNotExist(err) {
		t.Fatal("touch created a marker")
	}
}

// TestLifecycleInvalidSessionID: a hostile session id writes nothing and
// still exits 0 silently.
func TestLifecycleInvalidSessionID(t *testing.T) {
	f := newFx(t)
	st, state := lifecycleStore(t)
	f.env.Lifecycle = st
	for _, ev := range []string{EventSessionStart, EventUserPromptSubmit, EventSessionEnd, "PreToolUse"} {
		for _, id := range []string{"../../escape", ".hidden", "a/b"} {
			b, _ := json.Marshal(map[string]any{"session_id": id, "hook_event_name": ev, "tool_name": "Bash", "tool_input": map[string]any{"command": "ls"}})
			var out bytes.Buffer
			if code := Run(bytes.NewReader(b), &out, f.env); code != 0 || out.Len() != 0 {
				t.Fatalf("%s %q: exit %d, out %q", ev, id, code, out.String())
			}
		}
	}
	if _, err := os.Stat(state); !os.IsNotExist(err) {
		t.Fatal("an invalid id created the state dir")
	}
}

// TestOnSessionStartCalledAfterStart: the M5.3 extension point runs after the
// start is recorded, and a panic in it never reaches Claude Code.
func TestOnSessionStartCalledAfterStart(t *testing.T) {
	f := newFx(t)
	st, _ := lifecycleStore(t)
	f.env.Lifecycle = st
	saved := lifecycle.OnSessionStart
	t.Cleanup(func() { lifecycle.OnSessionStart = saved })
	var got lifecycle.Record
	var markerSeen bool
	lifecycle.OnSessionStart = func(s lifecycle.Store, r lifecycle.Record) {
		got = r
		_, err := os.Stat(filepath.Join(s.Live, r.SessionID))
		markerSeen = err == nil
		panic("boom")
	}
	var out bytes.Buffer
	code := Run(strings.NewReader(`{"session_id":"s1","hook_event_name":"SessionStart","source":"resume","cwd":"/p"}`), &out, f.env)
	if code != 0 || out.Len() != 0 {
		t.Fatalf("exit %d, out %q", code, out.String())
	}
	if got.SessionID != "s1" || got.Source != "resume" || !markerSeen {
		t.Fatalf("OnSessionStart saw %+v marker=%v", got, markerSeen)
	}
	// not called when the lifecycle is off
	got = lifecycle.Record{}
	f.env.Lifecycle = lifecycle.Store{}
	Run(strings.NewReader(`{"session_id":"s2","hook_event_name":"SessionStart","source":"startup"}`), &out, f.env)
	if got.SessionID != "" {
		t.Fatal("OnSessionStart called with the lifecycle off")
	}
}
