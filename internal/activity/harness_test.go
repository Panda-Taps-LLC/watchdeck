package activity

import (
	"os"
	"path/filepath"
	"testing"
)

// A v1 line written before the harness field existed reads back as claude-code.
func TestHarnessDefaultOnRead(t *testing.T) {
	p := filepath.Join(t.TempDir(), "activity.jsonl")
	old := `{"v":1,"kind":"decision","ts":"2026-10-01T00:00:00Z","session_id":"s","decision":"ask"}` + "\n"
	if err := os.WriteFile(p, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Append(p, Record{Kind: KindRun, Harness: "codex"}); err != nil {
		t.Fatal(err)
	}
	res, err := Read(p, ReadOptions{})
	if err != nil || len(res.Records) != 2 {
		t.Fatalf("read: %v %d", err, len(res.Records))
	}
	if got := res.Records[0].Harness; got != HarnessClaudeCode {
		t.Fatalf("old line harness = %q", got)
	}
	if got := res.Records[1].Harness; got != "codex" {
		t.Fatalf("stored harness = %q", got)
	}
}
