//go:build unix

package sessionindex

import (
	"os"
	"syscall"
)

// lock takes an exclusive flock on path (created 0600), blocking until any
// other Update in another process has finished.
func lock(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|oNoFollow, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() {
		syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}

// oNoFollow makes an open refuse a symlink at the final path element.
const oNoFollow = syscall.O_NOFOLLOW
