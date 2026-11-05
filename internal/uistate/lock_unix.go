//go:build unix

package uistate

import (
	"errors"
	"os"
	"syscall"

	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
)

const oNoFollow = syscall.O_NOFOLLOW

// Lock is a held ui.lock.
type Lock struct{ f *os.File }

// TryLock takes ui.lock with flock(LOCK_EX|LOCK_NB). ErrLocked means
// another process holds it: a server is running (or starting). The lock is
// released by Release or when the process exits, however it exits.
func TryLock(p paths.Paths) (*Lock, error) {
	if err := EnsureDir(p); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(Path(p, LockFile), os.O_RDWR|os.O_CREATE|oNoFollow, 0o600)
	if err != nil {
		return nil, err
	}
	for {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if !errors.Is(err, syscall.EINTR) {
			break
		}
	}
	if err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, ErrLocked
		}
		return nil, err
	}
	return &Lock{f: f}, nil
}

// Release drops the lock. It is safe on a nil Lock and more than once.
func (l *Lock) Release() {
	if l == nil || l.f == nil {
		return
	}
	syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN)
	l.f.Close()
	l.f = nil
}
