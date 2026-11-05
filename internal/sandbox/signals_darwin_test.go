//go:build darwin

package sandbox

import (
	"bytes"
	"context"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

// selfSignal sends sig to this test process after d, once Run has started
// relaying (forwardSignals is registered right after the child starts).
func selfSignal(d time.Duration, sig syscall.Signal) {
	go func() {
		time.Sleep(d)
		_ = syscall.Kill(os.Getpid(), sig)
	}()
}

// TestSIGHUPForwarded: a SIGHUP to watchdeck reaches the sandboxed child.
func TestSIGHUPForwarded(t *testing.T) {
	skipIfNoSandbox(t)
	selfSignal(500*time.Millisecond, syscall.SIGHUP)
	var errb bytes.Buffer
	res, err := Run(context.Background(), Options{Profile: trivial,
		Argv: []string{"/bin/sh", "-c", `trap "exit 7" HUP; echo ready >&2; sleep 30 & wait`},
		Env:  []string{"PATH=/usr/bin:/bin"}, Stdin: strings.NewReader(""), Stdout: &bytes.Buffer{}, Stderr: &errb})
	if err != nil || res.ExitCode != 7 {
		t.Fatalf("res=%+v err=%v stderr=%q", res, err, errb.String())
	}
}

// TestSIGTERMEscalatesToKill: a child that ignores a forwarded SIGTERM is
// killed KillAfter later.
func TestSIGTERMEscalatesToKill(t *testing.T) {
	skipIfNoSandbox(t)
	old := KillAfter
	KillAfter = 300 * time.Millisecond
	defer func() { KillAfter = old }()
	selfSignal(500*time.Millisecond, syscall.SIGTERM)
	start := time.Now()
	res, err := Run(context.Background(), Options{Profile: trivial,
		Argv: []string{"/bin/sh", "-c", `trap "" TERM; while :; do sleep 1; done`},
		Env:  []string{"PATH=/usr/bin:/bin"}, Stdin: strings.NewReader(""), Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Signaled || res.Signal != syscall.SIGKILL {
		t.Errorf("res = %+v, want killed", res)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Errorf("took %v", d)
	}
}
