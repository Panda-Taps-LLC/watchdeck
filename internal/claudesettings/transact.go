package claudesettings

import (
	"errors"
	"time"
)

// LockFile is the cross-process lock's name under the state dir.
const LockFile = "claude-settings.lock"

// ErrLockTimeout is Transact's error when another process held the lock for
// the whole deadline.
var ErrLockTimeout = errors.New("claudesettings: another watchdeck is writing your Claude Code settings")

// lockDeadline is how long Transact waits for the lock.
const lockDeadline = 2 * time.Second

// Transact holds <stateDir>/claude-settings.lock (flock, 2 s deadline, then
// ErrLockTimeout) around load, edit and save of the ledger: it loads the
// ledger, calls fn and, when fn returns nil, saves it. fn's error is
// returned as is and nothing is saved. Callers run Manage inside fn so the
// settings write and the ledger write happen under one lock, and two
// watchdeck processes (the dashboard and the CLI) never lose each other's
// claims. On Windows the lock is a no-op.
func Transact(stateDir string, fn func(led *Ledger) error) error {
	l, err := takeLock(stateDir, lockDeadline)
	if err != nil {
		return err
	}
	defer l.release()
	led, err := LoadLedger(stateDir)
	if err != nil {
		return err
	}
	if err := fn(led); err != nil {
		return err
	}
	return led.Save(stateDir)
}

// Locked holds <stateDir>/claude-settings.lock (the same lock and 2 s
// deadline as Transact) around fn, without loading or saving the ledger,
// for other state-dir files that watchdeck processes rewrite (the
// declined list, the inbox's undo). fn must not call Transact or Locked:
// a nested lock from the same process waits out the deadline and fails.
func Locked(stateDir string, fn func() error) error {
	l, err := takeLock(stateDir, lockDeadline)
	if err != nil {
		return err
	}
	defer l.release()
	return fn()
}
