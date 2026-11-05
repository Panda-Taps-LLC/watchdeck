// Package sandbox runs a command under an OS sandbox profile.
//
// On macOS the profile is a Seatbelt (sandbox-exec) profile string. Apply
// failures, which happen when the process is already inside a sandbox, are
// reported as ErrApply so callers can fail closed instead of running the
// command unconfined.
package sandbox

import (
	"context"
	"errors"
	"io"
	"os"
	"time"
)

// StreamWaitDelay bounds how long Run keeps copying the child's output after
// the child has exited. When Stdout or Stderr is not an *os.File (the runner
// passes tail writers), the child writes into a pipe; a grandchild started in
// the background (`sleep 60 & echo done`) inherits that pipe and would keep
// Run waiting until it exits. After the delay the pipes are closed and Run
// returns the child's own exit status. Output the grandchild writes later is
// lost, which is the price of not hanging.
const StreamWaitDelay = 2 * time.Second

// ErrApply means the sandbox could not be applied (typically a nested sandbox).
var ErrApply = errors.New("sandbox: could not apply the profile")

// ErrProfile means sandbox-exec rejected the profile text (a watchdeck bug, never the script's fault).
var ErrProfile = errors.New("sandbox: profile rejected by sandbox-exec")

// ErrUnsupported means this platform has no enforcement backend.
var ErrUnsupported = errors.New("sandbox: enforcement is not supported on this platform")

// Options describes one sandboxed run.
type Options struct {
	Profile string    // compiled profile (Seatbelt text on macOS)
	Argv    []string  // command and arguments; Argv[0] is resolved via PATH by the OS
	Env     []string  // the complete child environment (nothing is inherited)
	Dir     string    // working directory ("" = inherit)
	Stdin   io.Reader // nil = inherit os.Stdin
	Stdout  io.Writer // nil = inherit os.Stdout
	Stderr  io.Writer // nil = inherit os.Stderr; the apply-failure scanner tees this
}

// Result is the child's exit state.
type Result struct {
	ExitCode int  // child's exit code, or 128+signal when Signaled
	Signaled bool // true when the child died from a signal
	Signal   os.Signal
}

func (o *Options) defaults() {
	if o.Stdin == nil {
		o.Stdin = os.Stdin
	}
	if o.Stdout == nil {
		o.Stdout = os.Stdout
	}
	if o.Stderr == nil {
		o.Stderr = os.Stderr
	}
}

// Run executes Argv under Profile and waits for it. It returns ErrApply when
// the sandbox itself failed to apply, ErrUnsupported off macOS/Linux, and the
// child's Result otherwise (a non-zero exit is not an error).
func Run(ctx context.Context, o Options) (Result, error) {
	o.defaults()
	return run(ctx, o)
}
