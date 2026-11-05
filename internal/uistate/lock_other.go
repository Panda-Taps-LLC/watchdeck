//go:build !unix

package uistate

import (
	"errors"

	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
)

const oNoFollow = 0

// Lock is a held ui.lock; watchdeck ships for macOS and Linux only.
type Lock struct{}

// TryLock is unsupported here.
func TryLock(paths.Paths) (*Lock, error) {
	return nil, errors.New("uistate: single-instance lock needs flock (macOS or Linux)")
}

// Release does nothing.
func (l *Lock) Release() {}
