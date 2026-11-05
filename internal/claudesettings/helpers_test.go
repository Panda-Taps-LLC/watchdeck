package claudesettings

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
)

// tempPaths returns a Paths rooted in a fresh temp HOME; nothing here
// touches the real ~/.claude or state dir.
func tempPaths(t *testing.T) paths.Paths {
	t.Helper()
	home := t.TempDir()
	return paths.Paths{
		Home:      home,
		ConfigDir: filepath.Join(home, ".config", "watchdeck"),
		StateDir:  filepath.Join(home, ".local", "state", "watchdeck"),
		ClaudeDir: filepath.Join(home, ".claude"),
	}
}

// writeFile writes content at path, creating parent directories.
func writeFile(t *testing.T, path, content string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// copyFixture copies a realistic settings file from internal/settings/testdata.
func copyFixture(t *testing.T, name, dst string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "settings", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return writeFile(t, dst, string(b))
}

func readString(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func values(es []Entry) []string {
	out := make([]string, len(es))
	for i, e := range es {
		out[i] = e.Value
	}
	return out
}

func userLoc(p paths.Paths) Location {
	return Location{Scope: ScopeUser, Path: filepath.Join(p.ClaudeDir, "settings.json")}
}
