//go:build !unix

package sessionindex

// lock is a no-op where flock is unavailable; watchdeck ships for macOS
// and Linux only.
func lock(string) (func(), error) { return func() {}, nil }

// oNoFollow is not available here; symlinks are checked with Lstat instead.
const oNoFollow = 0
