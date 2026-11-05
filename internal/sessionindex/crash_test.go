package sessionindex

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// crashAfterRename makes the next rebuild of id panic right after its text
// file is renamed into place, before meta.json is saved: what a kill at that
// moment leaves on disk (the flock is released, as on process exit).
func crashAfterRename(t *testing.T, id string, f func()) {
	t.Helper()
	afterTextRename = func(got string) {
		if got == id {
			panic("simulated crash")
		}
	}
	defer func() { afterTextRename = nil }()
	defer func() {
		if r := recover(); r != "simulated crash" {
			t.Fatalf("no crash: %v", r)
		}
	}()
	f()
}

// TestCrashBetweenRenameAndMetaSave: a tail_read session with an entry is
// rebuilt (its text file was found short), the transcript having grown
// meanwhile, and the process dies between the rename and the meta save.
// The next update must give exactly the text a fresh index gives: nothing
// duplicated, nothing missing.
func TestCrashBetweenRenameAndMetaSave(t *testing.T) {
	e := newEnv(t)
	p := writeSession(t, e.projects, "-tmp-big", sid(7), userPrompt(0, "/tmp/big", "the head prompt"))
	if err := os.Truncate(p, 33<<20); err != nil {
		t.Fatal(err)
	}
	appendFile(t, p, "\n"+session("/tmp/big", "firstword"))
	ix, _ := e.update(t)
	if en, _ := ix.Get(sid(7)); !en.TailRead {
		t.Fatalf("not a tail read: %+v", en)
	}
	// the transcript grows, and the text file is found short: a rebuild
	appendFile(t, p, session("/tmp/big", "secondword")+session("/tmp/big", "thirdword"))
	bumpMtime(t, p, time.Second)
	if err := os.Truncate(filepath.Join(e.dir, "text", textName(sid(7))), 1); err != nil {
		t.Fatal(err)
	}
	crashAfterRename(t, sid(7), func() { e.open(t).Update() })

	ix, st := e.update(t)
	if st.Rebuilt != 1 {
		t.Errorf("after the crash: %+v", st)
	}
	got := readText(t, e, sid(7))
	en, _ := ix.Get(sid(7))

	fresh := env{root: e.root, projects: e.projects, dir: filepath.Join(e.root, "fresh", "index")}
	fix, _ := fresh.update(t)
	want := readText(t, fresh, sid(7))
	wen, _ := fix.Get(sid(7))
	if got != want {
		t.Errorf("text differs from a fresh index:\n got %q\nwant %q", got, want)
	}
	if en.TextBytes != wen.TextBytes || en.Offset != wen.Offset || en.Turns != wen.Turns || en.ToolCalls != wen.ToolCalls {
		t.Errorf("entry differs: %+v vs %+v", en, wen)
	}
	for _, w := range []string{"firstword", "secondword", "thirdword"} {
		if c := strings.Count(got, "please look for "+w); c != 1 {
			t.Errorf("%s: %d times", w, c)
		}
	}
}

// TestCrashDuringFullRebuild: Rebuild saves an empty meta.json first, so a
// crash after one session's text is renamed leaves no stale entry behind.
func TestCrashDuringFullRebuild(t *testing.T) {
	e := newEnv(t)
	p := writeSession(t, e.projects, "-p", sid(1), session("/p", "alpha"))
	e.update(t)
	if err := os.WriteFile(p, []byte(session("/p", "bravo")+session("/p", "charlie")), 0o600); err != nil {
		t.Fatal(err)
	}
	bumpMtime(t, p, time.Second)
	crashAfterRename(t, sid(1), func() { e.open(t).Rebuild() })
	if _, ok := e.open(t).Get(sid(1)); ok {
		t.Fatal("stale entry survived the crash")
	}
	ix, _ := e.update(t)
	text := readText(t, e, sid(1))
	if en, _ := ix.Get(sid(1)); int64(len(text)) != en.TextBytes || strings.Contains(text, "alpha") || strings.Count(text, "please look for charlie") != 1 {
		t.Errorf("text after recovery: %q", text)
	}
}
