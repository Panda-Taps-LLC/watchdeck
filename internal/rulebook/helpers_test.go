package rulebook

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Panda-Taps-LLC/watchdeck/internal/claudesettings"
	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
)

// testEnv returns Paths under a fresh temp HOME and points the managed
// settings directory at an empty temp dir, so nothing reads ~/.claude,
// /Library or /etc.
func testEnv(t *testing.T) paths.Paths {
	t.Helper()
	home := t.TempDir()
	managed := t.TempDir()
	prev := claudesettings.ManagedDirOverride
	claudesettings.ManagedDirOverride = func() string { return managed }
	t.Cleanup(func() { claudesettings.ManagedDirOverride = prev })
	return paths.Paths{
		Home:      home,
		ConfigDir: filepath.Join(home, ".config", "watchdeck"),
		StateDir:  filepath.Join(home, ".local", "state", "watchdeck"),
		ClaudeDir: filepath.Join(home, ".claude"),
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readBytes(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// findRow returns the row with id across every group.
func findRow(b Book, id string) (Rule, string, bool) {
	for _, g := range b.Groups {
		for _, r := range g.Rows {
			if r.ID == id {
				return r, g.ID, true
			}
		}
	}
	return Rule{}, "", false
}
