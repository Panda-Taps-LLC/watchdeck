package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/lifecycle"
)

// --state and --denials filter as GET /api/sessions?state=&denials=1 does
// (both read the session catalog).
func TestSessionsStateAndDenials(t *testing.T) {
	src := fixtureASrc(t)
	actSrc, err := filepath.Abs(filepath.Join("..", "..", "internal", "mapmodel", "testdata", "activity-a.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	e := newTestEnv(t)
	seedFixtureA(t, e, src)
	// Old transcripts: a fresh copy would count as live by its mtime.
	old := time.Now().Add(-48 * time.Hour)
	filepath.Walk(filepath.Join(e.claude, "projects"), func(p string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() {
			os.Chtimes(p, old, old)
		}
		return nil
	})
	const sid = "a9896c55-0b77-4f85-a0e0-9be2948b8aa6"
	b, err := os.ReadFile(actSrc)
	if err != nil {
		t.Fatal(err)
	}
	b = bytes.ReplaceAll(b, []byte("/Users/you/.claude/projects"), []byte(filepath.Join(e.claude, "projects")))
	os.MkdirAll(filepath.Dir(e.activityPath()), 0o700)
	if err := os.WriteFile(e.activityPath(), b, 0o600); err != nil {
		t.Fatal(err)
	}
	rows := func(args ...string) []map[string]any {
		t.Helper()
		code, out, errb := call(t, sessionsCmd, append(args, "--json")...)
		if code != 0 {
			t.Fatalf("%v: exit %d %s", args, code, errb)
		}
		var r []map[string]any
		if err := json.Unmarshal([]byte(out), &r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	// Without --state/--denials the catalog is not built: no state, no counts.
	if all := rows(); len(all) != 1 || all[0]["state"] != nil || all[0]["denials"] != nil {
		t.Fatalf("plain row: %v", all)
	}
	all := rows("--denials")
	if len(all) != 1 || all[0]["state"] != "unknown" || all[0]["denials"] != float64(1) || all[0]["decisions"] != float64(2) {
		t.Fatalf("--denials row: %v", all)
	}
	if r := rows("--state", "live"); len(r) != 0 {
		t.Errorf("--state live: %d rows", len(r))
	}
	st := lifecycle.Store{Log: filepath.Join(e.state, "watchdeck", "sessions.jsonl"), Live: filepath.Join(e.state, "watchdeck", "live")}
	if _, err := st.Start(sid, "", "/Users/you/proj", "startup"); err != nil {
		t.Fatal(err)
	}
	if r := rows("--state", "live", "--denials"); len(r) != 1 || r[0]["state"] != "live" {
		t.Errorf("--state live --denials: %v", r)
	}
	st.End(sid, "", "/Users/you/proj", "other")
	if r := rows("--state", "ended"); len(r) != 1 {
		t.Errorf("--state ended: %d rows", len(r))
	}
	if r := rows("--state", "ended", "--search", "DENIED(1)"); len(r) != 1 || r[0]["hit"] == nil {
		t.Errorf("--state with --search: %v", r)
	}
	code, out, _ := call(t, sessionsCmd, "--state", "ended")
	if code != 0 || !strings.Contains(out, "ended") || !strings.Contains(out, "[1 denied]") {
		t.Errorf("text output: %s", out)
	}
	if code, _, _ := call(t, sessionsCmd, "--state", "zombie"); code != 3 {
		t.Errorf("bad --state: exit %d", code)
	}
}
