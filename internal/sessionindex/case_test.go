package sessionindex

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestIDsDifferingInCase: "AAAA" and "aaaa" are two sessions. Their text
// files are named by sha256 of the id, so on a case-insensitive filesystem
// (the macOS default) they do not share one file.
func TestIDsDifferingInCase(t *testing.T) {
	e := newEnv(t)
	writeSession(t, e.projects, "-a", "AAAA", session("/a", "upperword"))
	writeSession(t, e.projects, "-b", "aaaa", session("/b", "lowerword"))
	ix, st := e.update(t)
	if st.Sessions != 2 || st.Duplicates != 0 {
		t.Fatalf("stats: %+v", st)
	}
	up, low := readText(t, e, "AAAA"), readText(t, e, "aaaa")
	if !strings.Contains(up, "upperword") || strings.Contains(up, "lowerword") ||
		!strings.Contains(low, "lowerword") || strings.Contains(low, "upperword") {
		t.Errorf("texts mixed:\nAAAA: %q\naaaa: %q", up, low)
	}
	for q, want := range map[string]string{"upperword": "AAAA", "lowerword": "aaaa"} {
		hits, err := ix.Search(q, 5)
		if err != nil || len(hits) != 1 || hits[0].SessionID != want {
			t.Errorf("%s: %v %+v", q, err, hits)
		}
	}
	ents, _ := os.ReadDir(filepath.Join(e.dir, "text"))
	if len(ents) != 2 {
		t.Errorf("text files: %d", len(ents))
	}
	if _, st = e.update(t); st.Unchanged != 2 {
		t.Errorf("second update: %+v", st)
	}
}

// TestOldVersionMetaRebuilds: a version-1 index (text/<id>.txt) is dropped
// and rebuilt, and its old text files are removed.
func TestOldVersionMetaRebuilds(t *testing.T) {
	e := newEnv(t)
	writeSession(t, e.projects, "-p", sid(1), session("/p", "alpha"))
	if err := os.MkdirAll(filepath.Join(e.dir, "text"), 0o700); err != nil {
		t.Fatal(err)
	}
	old := filepath.Join(e.dir, "text", sid(1)+".txt")
	if err := os.WriteFile(old, []byte("stale\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.dir, "meta.json"), []byte(`{"version":1,"sessions":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, st := e.update(t); st.Rebuilt != 1 {
		t.Errorf("stats: %+v", st)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Errorf("old text file left: %v", err)
	}
}

// A version-2 index (entries without a harness) is rebuilt, not defaulted.
func TestOldIndexVersionRebuildsWithHarness(t *testing.T) {
	e := newEnv(t)
	writeSession(t, e.projects, "-p", sid(1), session("/p", "alpha"))
	if err := os.MkdirAll(e.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.dir, "meta.json"), []byte(`{"version":2,"sessions":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	ix, st := e.update(t)
	if st.Rebuilt != 1 {
		t.Fatalf("stats: %+v", st)
	}
	if en, ok := ix.Get(sid(1)); !ok || en.Harness != "claude-code" {
		t.Fatalf("entry: %+v %v", en, ok)
	}
}
