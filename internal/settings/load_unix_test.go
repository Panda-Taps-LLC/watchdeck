//go:build unix

package settings

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestLoadFIFONeverBlocks: a project's .claude/settings.json ships with the
// repository, so Load reads it with safeio and a FIFO is an error at once.
func TestLoadFIFONeverBlocks(t *testing.T) {
	p := filepath.Join(t.TempDir(), "settings.json")
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, _, err := Load(p)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Error("Load of a FIFO: want an error")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Load blocked on a FIFO")
	}
}
