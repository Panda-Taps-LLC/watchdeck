package activity

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLastOfKind(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "activity.jsonl")

	if _, ok, err := LastOfKind(p, KindDecision); ok || err != nil {
		t.Fatalf("absent file: ok=%v err=%v", ok, err)
	}
	if _, ok, err := LastOfKind("", KindDecision); ok || err != nil {
		t.Fatalf("empty path: ok=%v err=%v", ok, err)
	}

	lines := []string{
		`{"v":1,"kind":"decision","ts":"2026-10-13T01:00:00Z","decision":"allow"}`,
		`{"v":1,"kind":"decision","ts":"2026-10-13T02:00:00Z","decision":"ask"}`,
		`{"v":1,"kind":"run","ts":"2026-10-13T02:00:05Z","outcome":"ok"}`,
		`{"v":1,"kind":"skill_invoked","ts":"2026-10-13T02:00:06Z","reason":"\"decision\""}`,
		`not json "decision"`,
		`{"v":1,"kind":"decision","ts":"2026-10-13T03:00:00Z"`, // torn: no newline
	}
	if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	r, ok, err := LastOfKind(p, KindDecision)
	if err != nil || !ok || r.TS != "2026-10-13T02:00:00Z" || r.Decision != "ask" {
		t.Fatalf("got %+v ok=%v err=%v; want the 02:00 ask (a later run, a skill_invoked naming it, junk and a torn line do not count)", r, ok, err)
	}

	// A window that starts mid-line skips the partial line; a decision older
	// than the window is reported absent rather than read for.
	old := TailWindow
	t.Cleanup(func() { TailWindow = old })
	tail := strings.Join(lines[2:], "\n")
	TailWindow = int64(len(tail) + 10)
	if r, ok, err := LastOfKind(p, KindDecision); ok || err != nil {
		t.Fatalf("decision outside the window: got %+v ok=%v err=%v", r, ok, err)
	}
	if r, ok, _ := LastOfKind(p, KindRun); !ok || r.Outcome != "ok" {
		t.Fatalf("run inside the window: got %+v ok=%v", r, ok)
	}
	// The current file is larger than the window, so its newer decision may
	// lie beyond it: an older one in <path>.1 must not stand in for it.
	if err := os.WriteFile(p+".1", []byte(`{"v":1,"kind":"decision","ts":"2026-10-12T00:00:00Z"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if r, ok, err := LastOfKind(p, KindDecision); ok || err != nil {
		t.Fatalf("large current file without a decision in the window read .1: got %+v ok=%v err=%v", r, ok, err)
	}
	if err := os.Remove(p + ".1"); err != nil {
		t.Fatal(err)
	}
	TailWindow = old

	// Just rotated: the current file has no decision, <path>.1 has.
	if err := os.Rename(p, p+".1"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(lines[2]+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r, ok, err = LastOfKind(p, KindDecision)
	if err != nil || !ok || r.TS != "2026-10-13T02:00:00Z" {
		t.Fatalf("rotated: got %+v ok=%v err=%v", r, ok, err)
	}
}
