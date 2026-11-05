package mapapi

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func (g graph) count(id string) int {
	for _, n := range g.Nodes {
		if n.ID == id {
			return n.Count
		}
	}
	return -1
}

// TestSubagentSymlinkOutside: a subagents dir inside the projects dir that
// is a symlink to a dir outside it is never listed for the ETag (lifted
// from the B4 verifier's probe). Writing into the outside dir leaves the
// tag alone.
func TestSubagentSymlinkOutside(t *testing.T) {
	e := newEnv(t)
	sub := filepath.Dir(e.subagentA())
	outside := filepath.Join(e.root, "outside-sub")
	if err := os.Rename(sub, outside); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, sub); err != nil {
		t.Fatal(err)
	}
	_, tag := e.mapOK(t, sidA, "topology", false)
	if err := os.WriteFile(filepath.Join(outside, "agent-zzz.jsonl"), []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	appendFile(t, filepath.Join(outside, "agent-"+agentA+".jsonl"), `{"type":"future-kind"}`)
	resp, _ := e.get(t, mapPath(sidA, "topology", false), map[string]string{"If-None-Match": tag})
	if resp.StatusCode != http.StatusNotModified {
		t.Fatalf("a write outside the projects dir changed the tag: %d", resp.StatusCode)
	}
}

// TestHandTypedRunOnlyInDirect: a `watchdeck run` typed by hand in the
// session's cwd, during the session, claimed by no decision, shows only in
// the cwd's direct pseudo-session; the session's sandbox count is unchanged.
func TestHandTypedRunOnlyInDirect(t *testing.T) {
	e := newEnv(t)
	before, _ := e.mapOK(t, sidA, "topology", false)
	n := before.count("sandbox")
	if n < 1 {
		t.Fatalf("sandbox count before = %d", n)
	}
	// 02:18:50 falls between fixture A's first record and its last row.
	appendFile(t, e.paths.Activity, `{"v":1,"kind":"run","ts":"2026-10-13T02:18:50Z","cwd":"`+cwdA+`","skills":["canary-basic"],"command":"python3 hand-typed.py","exit":0,"outcome":"ok","backend":"seatbelt"}`)

	after, _ := e.mapOK(t, sidA, "topology", false)
	if got := after.count("sandbox"); got != n {
		t.Errorf("session sandbox count %d, want %d (unchanged)", got, n)
	}
	tl, _ := e.mapOK(t, sidA, "timeline", false)
	if tl.has("ev:run:0") {
		t.Error("the hand-typed run shows as an orphan event in the session's timeline")
	}

	id := directID(cwdA)
	if r := findRow(e.sessions(t), id); r == nil || r.Source != "activity" || r.Cwd != cwdA {
		t.Fatalf("direct row = %+v", r)
	}
	d, _ := e.mapOK(t, id, "topology", false)
	if d.count("sandbox") != 1 || !d.has("skill:canary-basic") || d.has("skill:canary-request") || d.has("you") {
		t.Errorf("direct graph nodes: %+v", d.Nodes)
	}
}
