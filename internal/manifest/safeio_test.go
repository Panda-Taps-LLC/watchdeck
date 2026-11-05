//go:build unix

package manifest

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestParseRefusesFIFOAndHostileYAML: PERMISSIONS.yaml is read without
// blocking and capped at 64 KiB; deeply nested YAML is refused before
// go-yaml decodes it (value-free errors).
func TestParseRefusesFIFOAndHostileYAML(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "PERMISSIONS.yaml")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	done := make(chan error, 1)
	go func() { _, err := Parse(fifo); done <- err }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Errorf("fifo: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Parse blocked on a FIFO")
	}

	big := filepath.Join(dir, "big.yaml")
	os.WriteFile(big, []byte("version: 1\n#"+strings.Repeat("x", 64<<10)+"\n"), 0o644)
	if _, err := Parse(big); err == nil || !strings.Contains(err.Error(), "larger than 64 KiB") {
		t.Errorf("big: %v", err)
	}
	for _, src := range []string{
		"version: 1\nenv: " + strings.Repeat("[", 5000) + "\n",
		"version: 1\nfilesystem: " + strings.Repeat("{a: ", 100) + "\n",
	} {
		if _, err := ParseBytes([]byte(src)); err == nil || err.Error() != "malformed YAML (too deeply nested)" {
			t.Errorf("nested: %v", err)
		}
		if _, err := ParseOverrides([]byte(src)); err == nil || err.Error() != "malformed YAML (too deeply nested)" {
			t.Errorf("nested overrides: %v", err)
		}
	}
	// A %YAML directive does not count as a second document.
	if _, err := ParseOverrides([]byte("%YAML 1.2\n---\nversion: 1\n")); err != nil {
		t.Errorf("directive: %v", err)
	}
	if _, err := ParseOverrides([]byte("%YAML 1.2\n---\nversion: 2\n")); err != nil {
		t.Errorf("directive v2: %v", err)
	}
	// The project file is capped at 64 KiB, the user file at 1 MiB.
	proj := filepath.Join(dir, "proj")
	os.MkdirAll(proj, 0o755)
	pad := "version: 1\n#" + strings.Repeat("x", 100<<10) + "\n"
	os.WriteFile(filepath.Join(proj, ProjectOverridesFile), []byte(pad), 0o644)
	if _, _, err := LoadOverrides("", proj); err == nil || !strings.Contains(err.Error(), "larger than 64 KiB") {
		t.Errorf("project cap: %v", err)
	}
	os.WriteFile(filepath.Join(dir, UserOverridesFile), []byte(pad), 0o644)
	if _, _, err := LoadOverrides(dir, ""); err != nil {
		t.Errorf("user 100 KiB: %v", err)
	}
}
