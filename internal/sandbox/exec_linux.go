//go:build linux

package sandbox

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

// Bwrap is the bubblewrap binary. Designed on 2026-10-12, exercised only by
// CI on ubuntu-24.04 (see .github/workflows/ci.yml); not run on a developer
// machine yet.
const Bwrap = "/usr/bin/bwrap"

// Available reports whether bubblewrap is present.
func Available() bool {
	if _, err := os.Stat(Bwrap); err == nil {
		return true
	}
	_, err := exec.LookPath("bwrap")
	return err == nil
}

// On Linux the "profile" is the bwrap argument vector, one argument per
// line, compiled by internal/profile (BwrapArgs). Run splits it back.
func run(ctx context.Context, o Options) (Result, error) {
	if !Available() {
		return Result{}, ErrUnsupported
	}
	bin := Bwrap
	if _, err := os.Stat(bin); err != nil {
		bin, _ = exec.LookPath("bwrap")
	}
	var args []string
	for _, line := range strings.Split(o.Profile, "\n") {
		if line != "" {
			args = append(args, line)
		}
	}
	// The profile ends with --clearenv; re-add only the variables the runner
	// kept (already scrubbed to the manifest env list). bwrap applies --setenv
	// after --clearenv when it follows it on the command line.
	for _, kv := range o.Env {
		if k, v, ok := strings.Cut(kv, "="); ok {
			args = append(args, "--setenv", k, v)
		}
	}
	args = append(args, "--")
	args = append(args, o.Argv...)
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = o.Env
	cmd.Dir = o.Dir
	cmd.Stdin = o.Stdin
	cmd.Stdout = o.Stdout
	cmd.Stderr = o.Stderr
	cmd.WaitDelay = StreamWaitDelay
	if err := cmd.Start(); err != nil {
		return Result{}, err
	}
	stopSignals := forwardSignals(cmd.Process)
	waitErr := cmd.Wait()
	stopSignals()

	var res Result
	var exitErr *exec.ExitError
	switch {
	// ErrWaitDelay: the child exited 0 but a descendant still held one of
	// its output pipes; Wait closed them after StreamWaitDelay. A normal exit.
	case waitErr == nil, errors.Is(waitErr, exec.ErrWaitDelay), errors.As(waitErr, &exitErr):
		ps := cmd.ProcessState
		if ws, ok := ps.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			res.Signaled = true
			res.Signal = ws.Signal()
			res.ExitCode = 128 + int(ws.Signal())
		} else {
			res.ExitCode = ps.ExitCode()
		}
		// bwrap itself fails (user namespaces disabled, AppArmor) with exit 1
		// and a "bwrap:" diagnostic before the child starts; callers see it as
		// an apply failure only when the child never ran, which we cannot
		// distinguish here without a stderr scanner. Kept simple for CI.
	default:
		return Result{}, waitErr
	}
	return res, nil
}
