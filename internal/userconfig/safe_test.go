//go:build unix

package userconfig

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestLoadNeverBlocksOrStalls: a FIFO config file is an error at once, and
// deeply nested YAML is refused before go-yaml decodes it.
func TestLoadNeverBlocksOrStalls(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "config.yaml")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	done := make(chan error, 1)
	go func() { _, err := Load(fifo); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Error("fifo: no error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Load blocked on a FIFO")
	}
	if err := SetAutostartUI(fifo, true); err == nil {
		t.Error("SetAutostartUI over a FIFO: no error")
	}
	nested := filepath.Join(dir, "nested.yaml")
	os.WriteFile(nested, []byte("ui: "+strings.Repeat("[", 10000)+"\n"), 0o600)
	if _, err := Load(nested); err == nil || !strings.Contains(err.Error(), "too deeply nested") {
		t.Errorf("nested: %v", err)
	}
}
