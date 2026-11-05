//go:build unix

package claudesettings

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// lock is a held <stateDir>/claude-settings.lock.
type lock struct{ f *os.File }

// lockRetry is how often takeLock tries again while another process holds
// the lock.
const lockRetry = 50 * time.Millisecond

// takeLock creates stateDir 0700 when needed, opens the lock file 0600
// without following a symlink and takes flock(LOCK_EX|LOCK_NB), trying again
// every 50 ms until deadline has passed, then returns ErrLockTimeout. An
// interrupted flock is retried at once. The kernel releases the lock when
// the process exits, however it exits.
func takeLock(stateDir string, deadline time.Duration) (*lock, error) {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(stateDir, LockFile), os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	end := time.Now().Add(deadline)
	for {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return &lock{f: f}, nil
		}
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			f.Close()
			return nil, err
		}
		if !time.Now().Before(end) {
			f.Close()
			return nil, ErrLockTimeout
		}
		time.Sleep(lockRetry)
	}
}

// release drops the lock. It is safe on a nil lock and more than once.
func (l *lock) release() {
	if l == nil || l.f == nil {
		return
	}
	syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN)
	l.f.Close()
	l.f = nil
}
