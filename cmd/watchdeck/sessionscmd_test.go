package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func sessionsCmd(a []string, o, e *bytes.Buffer) int      { return cmdSessions(a, o, e) }
func indexSessionsCmd(a []string, o, e *bytes.Buffer) int { return cmdIndexSessions(a, o, e) }

// seedFixtureA copies fixture A (scrubbed capture, fake paths) into the temp
// CLAUDE_CONFIG_DIR's projects dir; src must be absolute, made so before
// newTestEnv changes the working directory.
func seedFixtureA(t *testing.T, e testEnv, src string) {
	t.Helper()
	dst := filepath.Join(e.claude, "projects")
	err := filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if info.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o700)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), b, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func fixtureASrc(t *testing.T) string {
	t.Helper()
	src, err := filepath.Abs(filepath.Join("..", "..", "internal", "transcript", "testdata", "e2e-canary", "projects"))
	if err != nil {
		t.Fatal(err)
	}
	return src
}

func TestSessionsCLI(t *testing.T) {
	src := fixtureASrc(t)
	e := newTestEnv(t)
	seedFixtureA(t, e, src)
	code, out, errb := call(t, sessionsCmd, "--json")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errb)
	}
	var rows []map[string]any
	if err := json.Unmarshal([]byte(out), &rows); err != nil || len(rows) != 1 {
		t.Fatalf("rows: %v %s", err, out)
	}
	if rows[0]["cwd"] != "/Users/you/proj" || !strings.HasPrefix(rows[0]["title"].(string), "Do exactly three things") {
		t.Errorf("row: %v", rows[0])
	}
	indexDir := filepath.Join(e.state, "watchdeck", "index")
	if st, err := os.Stat(filepath.Join(indexDir, "meta.json")); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("meta.json: %v", err)
	}

	for args, want := range map[string]int{
		"--project|/Users/you/proj":       1,
		"--project|-Users-you-proj":       1,
		"--project|/Users/you/other":      0,
		"--since|2026-10-12":              1,
		"--since|2026-10-14T00:00:00Z":    0,
		"--search|DENIED(1)":              1,
		"--search|nothing-matches-this-1": 0,
	} {
		code, out, errb := call(t, sessionsCmd, append(strings.Split(args, "|"), "--json")...)
		if code != 0 {
			t.Fatalf("%s: exit %d %s", args, code, errb)
		}
		var rows []map[string]any
		if err := json.Unmarshal([]byte(out), &rows); err != nil || len(rows) != want {
			t.Errorf("%s: %d rows (%v) want %d", args, len(rows), err, want)
		}
	}
	code, out, _ = call(t, sessionsCmd, "--search", "denied(1)")
	if code != 0 || !strings.Contains(out, "match: ") || !strings.Contains(out, "canary-basic") {
		t.Errorf("text search output: %s", out)
	}
	if code, _, _ := call(t, sessionsCmd, "--since", "yesterday"); code != 3 {
		t.Errorf("bad --since: exit %d", code)
	}

	code, out, _ = call(t, indexSessionsCmd, "--json")
	if code != 0 || !strings.Contains(out, `"unchanged": 1`) {
		t.Errorf("index sessions: %d %s", code, out)
	}
	code, out, _ = call(t, indexSessionsCmd, "--rebuild", "--json")
	if code != 0 || !strings.Contains(out, `"rebuilt": 1`) {
		t.Errorf("rebuild: %d %s", code, out)
	}
	if code, _, _ := call(t, indexSessionsCmd, "--rebuild", "--purge"); code != 3 {
		t.Errorf("exclusive flags: exit %d", code)
	}
	if code, _, _ := call(t, indexSessionsCmd, "--purge"); code != 0 {
		t.Errorf("purge: exit %d", code)
	}
	if _, err := os.Stat(indexDir); !os.IsNotExist(err) {
		t.Errorf("index dir after purge: %v", err)
	}
}

func TestSessionsNoTranscriptsWritesNothing(t *testing.T) {
	src := fixtureASrc(t)
	e := newTestEnv(t)
	seedFixtureA(t, e, src)
	code, out, _ := call(t, sessionsCmd, "--no-transcripts", "--json")
	if code != 0 || strings.TrimSpace(out) != "[]" {
		t.Errorf("exit %d out %q", code, out)
	}
	if _, err := os.Stat(filepath.Join(e.state, "watchdeck", "index")); !os.IsNotExist(err) {
		t.Errorf("index dir created: %v", err)
	}
}

func TestParseSince(t *testing.T) {
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	if got, err := parseSince("48h", now); err != nil || !got.Equal(now.Add(-48*time.Hour)) {
		t.Errorf("duration: %v %v", got, err)
	}
	if _, err := parseSince("-1h", now); err == nil {
		t.Error("negative duration accepted")
	}
}
