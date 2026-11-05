//go:build unix

package sessionindex

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLockRefusesSymlink: a symlink planted at index/.lock is refused, not
// followed (O_NOFOLLOW), so Update fails and the target is never created.
func TestLockRefusesSymlink(t *testing.T) {
	e := newEnv(t)
	writeSession(t, e.projects, "-p", sid(1), session("/p", "alpha"))
	if err := os.MkdirAll(e.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(e.root, "victim")
	if err := os.Symlink(victim, filepath.Join(e.dir, ".lock")); err != nil {
		t.Fatal(err)
	}
	if _, err := e.open(t).Update(); err == nil {
		t.Fatal("update through a symlinked lock succeeded")
	}
	if _, err := os.Lstat(victim); !os.IsNotExist(err) {
		t.Errorf("symlink target created: %v", err)
	}
}
