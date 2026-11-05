package runner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The run record stores its harness on disk; the read default must not be
// what makes it appear.
func TestRunRecordStoresHarness(t *testing.T) {
	p := filepath.Join(t.TempDir(), "activity.jsonl")
	rl := newRunLog(Options{Skills: []string{"pdf"}, Command: "true", ActivityPath: p})
	rl.done(0, "ok", "", nil, nil)
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"harness":"claude-code"`) {
		t.Fatalf("raw run line lacks harness: %s", raw)
	}
}
