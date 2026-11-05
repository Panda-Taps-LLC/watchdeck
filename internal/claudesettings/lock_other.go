//go:build !unix

package claudesettings

import "time"

// lock does nothing here: on Windows there is no cross-process lock, so two
// watchdeck processes writing at once can lose a claim. watchdeck ships for
// macOS and Linux.
type lock struct{}

// takeLock returns a lock that holds nothing.
func takeLock(string, time.Duration) (*lock, error) { return &lock{}, nil }

// release does nothing.
func (l *lock) release() {}
