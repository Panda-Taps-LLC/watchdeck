package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Panda-Taps-LLC/watchdeck/internal/copylint"
)

// TestUsageCopyLint: the documented usage and every plugin SKILL.md use none
// of the banned internal words. advancedUsage is exempt: it must name the
// hook and run commands.
func TestUsageCopyLint(t *testing.T) {
	hits := copylint.Scan("usage.txt", []byte(usage))
	files, err := filepath.Glob(filepath.Join("..", "..", "plugin", "skills", "*", "SKILL.md"))
	if err != nil || len(files) < 3 {
		t.Fatalf("plugin skills: %v, %d files", err, len(files))
	}
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		hits = append(hits, copylint.Scan(f, src)...)
	}
	for _, h := range hits {
		t.Errorf("%s:%d: %q in %q", h.File, h.Line, h.Word, h.Text)
	}
}
