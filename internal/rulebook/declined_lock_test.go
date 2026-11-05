//go:build unix

package rulebook

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/Panda-Taps-LLC/watchdeck/internal/claudesettings"
)

// holdLock takes the state-dir lock on its own open file description, so
// this process's next takeLock waits for it as another process's would.
func holdLock(t *testing.T, stateDir string) {
	t.Helper()
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filepath.Join(stateDir, claudesettings.LockFile), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	})
}

func TestDeclineTakesLock(t *testing.T) {
	p := testEnv(t)
	holdLock(t, p.StateDir)
	if err := Decline(p.StateDir, []string{IntentPrefix + "x"}); !errors.Is(err, claudesettings.ErrLockTimeout) {
		t.Fatalf("Decline = %v, want ErrLockTimeout", err)
	}
	if err := Undecline(p.StateDir, []string{IntentPrefix + "x"}); !errors.Is(err, claudesettings.ErrLockTimeout) {
		t.Fatalf("Undecline = %v, want ErrLockTimeout", err)
	}
	if _, err := Undo(Input{Paths: p}, "0123456789abcdef"); !errors.Is(err, claudesettings.ErrLockTimeout) {
		t.Fatalf("Undo = %v, want ErrLockTimeout", err)
	}
	if _, err := os.Lstat(filepath.Join(p.StateDir, DeclinedFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("declined file written without the lock: %v", err)
	}
}
