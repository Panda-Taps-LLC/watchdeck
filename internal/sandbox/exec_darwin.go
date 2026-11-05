//go:build darwin

package sandbox

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
)

// SandboxExec is the macOS sandbox binary.
const SandboxExec = "/usr/bin/sandbox-exec"

// exit codes sandbox-exec itself uses (sysexits.h)
const (
	exitProfileError = 65 // EX_DATAERR: malformed profile
	exitOSErr        = 71 // EX_OSERR: sandbox_apply failed OR execvp of the target failed
)

// Available reports whether enforcement can run on this machine.
func Available() bool {
	_, err := os.Stat(SandboxExec)
	return err == nil
}

// applyScanner tees the child's stderr to the real writer while watching the
// first few kilobytes for sandbox-exec's own apply failure line.
type applyScanner struct {
	dst     io.Writer
	mu      sync.Mutex
	head    bytes.Buffer
	matched bool
}

const headLimit = 8 << 10

// sawPrefix reports whether sandbox-exec printed any diagnostic of its own.
func (s *applyScanner) sawPrefix() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.Contains(s.head.String(), "sandbox-exec:")
}

func (s *applyScanner) Write(p []byte) (int, error) {
	s.mu.Lock()
	if s.head.Len() < headLimit {
		s.head.Write(p[:min(len(p), headLimit-s.head.Len())])
		if !s.matched && isApplyFailure(s.head.String()) {
			s.matched = true
		}
	}
	s.mu.Unlock()
	return s.dst.Write(p)
}

// isApplyFailure recognises sandbox-exec's own apply diagnostic, which it
// prints before exec'ing the child, so it is always at the head of stderr:
//
//	sandbox-exec: sandbox_apply: Operation not permitted      (exit 71)
//
// Exit 71 alone is not enough: an execvp failure of the target also exits 71
// ("sandbox-exec: execvp() of '/x' failed: ..."), and a malformed profile exits
// 65. Only the sandbox_apply line means the sandbox was not applied.
func isApplyFailure(head string) bool {
	for _, line := range strings.Split(head, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "sandbox-exec:") && strings.Contains(line, "sandbox_apply") {
			return true
		}
	}
	return false
}

func run(ctx context.Context, o Options) (Result, error) {
	if !Available() {
		return Result{}, ErrUnsupported
	}
	args := append([]string{"-p", o.Profile}, o.Argv...)
	cmd := exec.CommandContext(ctx, SandboxExec, args...)
	cmd.Env = o.Env
	cmd.Dir = o.Dir
	cmd.Stdin = o.Stdin
	cmd.Stdout = o.Stdout
	scanner := &applyScanner{dst: o.Stderr}
	cmd.Stderr = scanner
	cmd.WaitDelay = StreamWaitDelay

	if err := cmd.Start(); err != nil {
		return Result{}, err
	}

	// Forward interrupts to the child so Ctrl-C reaches the sandboxed process.
	stopSignals := forwardSignals(cmd.Process)
	waitErr := cmd.Wait()
	stopSignals()

	scanner.mu.Lock()
	applyFailed := scanner.matched
	scanner.mu.Unlock()

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
	default:
		return Result{}, waitErr
	}
	if applyFailed {
		return res, ErrApply
	}
	if res.ExitCode == exitProfileError && scanner.sawPrefix() {
		return res, ErrProfile
	}
	return res, nil
}
