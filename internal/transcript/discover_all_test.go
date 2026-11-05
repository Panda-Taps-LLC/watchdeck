package transcript

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDiscoverAllFixtures(t *testing.T) {
	projects := filepath.Join(t.TempDir(), "projects")
	copyTree(t, fixtureProjects(t, "e2e-canary"), projects)
	copyTree(t, fixtureProjects(t, "synthetic-subagents"), projects)
	got, err := DiscoverAll(projects)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("sessions: %+v", got)
	}
	byID := map[string]SessionFiles{}
	for _, s := range got {
		byID[s.ID] = s
	}
	a, b := byID[sessionA], byID[sessionB]
	if a.Subagents != 1 || len(a.SubagentFiles) != 1 || a.SubagentFiles[0].Name != "agent-"+subagentA+".jsonl" || a.Source != "all" {
		t.Errorf("A: %+v", a)
	}
	if b.Subagents != 2 || b.CwdGuess != "/Users/you/proj/b" {
		t.Errorf("B: %+v", b)
	}
	if a.Main.Size == 0 || a.Main.Resolved == "" || a.Main.Path != mainPath(projects, "-Users-you-proj", sessionA) {
		t.Errorf("A main: %+v", a.Main)
	}
}

func TestDiscoverAllRefusesOutsideAndDedupes(t *testing.T) {
	root := t.TempDir()
	projects := filepath.Join(root, "projects")
	outside := filepath.Join(root, "outside")
	for _, d := range []string{filepath.Join(projects, "-real"), outside} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	write := func(p string) {
		if err := os.WriteFile(p, []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(outside, "out-1.jsonl"))
	write(filepath.Join(projects, "-real", "s-1.jsonl"))
	// a project dir symlinked outside, a session file symlinked outside, a
	// second name for an inside session, an invalid id, a non-jsonl file
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.Symlink(outside, filepath.Join(projects, "-linked")))
	must(os.Symlink(filepath.Join(outside, "out-1.jsonl"), filepath.Join(projects, "-real", "s-2.jsonl")))
	must(os.Symlink(filepath.Join(projects, "-real", "s-1.jsonl"), filepath.Join(projects, "-real", "s-3.jsonl")))
	write(filepath.Join(projects, "-real", "bad id.jsonl"))
	write(filepath.Join(projects, "-real", "notes.txt"))
	got, err := DiscoverAll(projects)
	if err != nil {
		t.Fatal(err)
	}
	// s-3 is a second name for s-1: one session, with s-1's id.
	if len(got) != 1 {
		t.Fatalf("got %d: %+v", len(got), got)
	}
	if got[0].Main.Resolved == "" || filepath.Base(got[0].Main.Resolved) != "s-1.jsonl" || got[0].ID != "s-1" {
		t.Errorf("survivor: %+v", got[0].Main)
	}
	if s, err := DiscoverAll(filepath.Join(root, "missing")); err != nil || s != nil {
		t.Errorf("missing dir: %v %v", s, err)
	}
	if _, err := DiscoverAll(""); err != ErrNoProjectsDir {
		t.Errorf("empty: %v", err)
	}
}
