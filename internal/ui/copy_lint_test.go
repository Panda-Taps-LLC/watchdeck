package ui

import (
	"io/fs"
	"path"
	"testing"

	"github.com/Panda-Taps-LLC/watchdeck/internal/copylint"
)

// TestCopyLint keeps internal vocabulary off the screen: no banned word
// (copylint.Banned) in a string literal of static/*.js or in the text and
// labels of static/index.html. Every file is scanned; there is no exemption
// list (the last one was emptied on 2026-10-19).
func TestCopyLint(t *testing.T) {
	names, err := fs.Glob(StaticFS, "static/*.js")
	if err != nil {
		t.Fatal(err)
	}
	names = append(names, "static/index.html")
	scanned := 0
	for _, name := range names {
		b, err := fs.ReadFile(StaticFS, name)
		if err != nil {
			t.Fatal(err)
		}
		scanned++
		for _, h := range copylint.Scan(path.Base(name), b) {
			t.Errorf("%s:%d: %s: %s", name, h.Line, h.Word, h.Text)
		}
	}
	if scanned < 3 {
		t.Fatalf("scanned %d files; the glob found %q", scanned, names)
	}
}
