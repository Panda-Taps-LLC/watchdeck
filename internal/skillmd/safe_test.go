//go:build unix

package skillmd

import (
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestParseNeverBlocksOrStalls: a FIFO SKILL.md is an error at once;
// deeply nested or oversized frontmatter falls back to the line-by-line
// recovery without going through go-yaml, and a large block of duplicate
// keys does not take the quadratic permissive retry.
func TestParseNeverBlocksOrStalls(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "SKILL.md")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	done := make(chan error, 1)
	go func() { _, err := Parse(fifo); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Error("fifo: no error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Parse blocked on a FIFO")
	}
	for name, fm := range map[string]string{
		"nested": "name: x\ndescription: d\nx: " + strings.Repeat("[", 10000) + "\n",
		"big":    "name: x\ndescription: d\n#" + strings.Repeat("y", 70<<10) + "\n",
		"dups":   "name: x\ndescription: d\n" + strings.Repeat("k: v\n", 12000),
	} {
		start := time.Now()
		got, err := ParseBytes([]byte("---\n"+fm+"---\n"), "x")
		// 100 ms; the race detector slows the parser several times over
		// (104 ms seen under -race on darwin arm64, 2026-10-14)
		limit := 100 * time.Millisecond
		if raceEnabled {
			limit = 500 * time.Millisecond
		}
		if el := time.Since(start); el > limit {
			t.Errorf("%s: took %v", name, el)
		}
		if err != nil || got.Name != "x" || len(got.Problems) == 0 {
			t.Errorf("%s: %+v %v", name, got, err)
		}
	}
}
