package activity

import (
	"os"
	"path/filepath"
	"testing"
)

// TestAppendRefusesSymlink: a symlink planted at the log path is refused
// (O_NOFOLLOW), and the file it points at is left untouched.
func TestAppendRefusesSymlink(t *testing.T) {
	p := logPath(t)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(target, []byte("original\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, p); err != nil {
		t.Fatal(err)
	}
	if err := Append(p, Record{Kind: KindDecision, Command: "x"}); err == nil {
		t.Fatal("append through a symlink succeeded")
	}
	if b, _ := os.ReadFile(target); string(b) != "original\n" {
		t.Fatalf("target written: %q", b)
	}
}
