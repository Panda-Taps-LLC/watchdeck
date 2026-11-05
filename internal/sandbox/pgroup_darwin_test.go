//go:build darwin

package sandbox

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// waitGone fails unless pid is gone within 3 s (and kills it if not).
func waitGone(t *testing.T, pid int, what string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for syscall.Kill(pid, 0) == nil {
		if time.Now().After(deadline) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
			t.Fatalf("%s %d survived", what, pid)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func readPid(t *testing.T, path string) int {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if b, err := os.ReadFile(path); err == nil {
			if pid, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && pid > 0 {
				return pid
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no pid in %s", path)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestSIGKILLEscalationKillsGrandchild: the SIGKILL that follows an ignored
// SIGTERM reaches a grandchild that also ignores SIGTERM (the process tree
// is walked at escalation).
func TestSIGKILLEscalationKillsGrandchild(t *testing.T) {
	skipIfNoSandbox(t)
	old := KillAfter
	KillAfter = 300 * time.Millisecond
	defer func() { KillAfter = old }()
	pidFile := filepath.Join(t.TempDir(), "grandchild.pid")
	selfSignal(700*time.Millisecond, syscall.SIGTERM)
	res, err := Run(context.Background(), Options{Profile: trivial,
		Argv: []string{"/bin/sh", "-c", `trap "" TERM; /bin/sh -c 'trap "" TERM; while :; do sleep 1; done' & echo $! > "$PIDFILE"; while :; do sleep 1; done`},
		Env:  []string{"PATH=/usr/bin:/bin", "PIDFILE=" + pidFile}, Stdin: strings.NewReader(""), Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Signaled || res.Signal != syscall.SIGKILL {
		t.Fatalf("res = %+v, want killed", res)
	}
	waitGone(t, readPid(t, pidFile), "grandchild")
}

// TestHelperRunsSandboxed is not a test on its own: TestGroupKillTakesChild
// starts this test binary with WATCHDECK_SANDBOX_HELPER set, as Claude
// Code's shell would start `watchdeck run`.
func TestHelperRunsSandboxed(t *testing.T) {
	pidFile := os.Getenv("WATCHDECK_SANDBOX_HELPER")
	if pidFile == "" {
		t.Skip("helper only")
	}
	_, _ = Run(context.Background(), Options{Profile: trivial,
		Argv: []string{"/bin/sh", "-c", `sleep 60 & echo $! > "$PIDFILE"; wait`},
		Env:  []string{"PATH=/usr/bin:/bin", "PIDFILE=" + pidFile}, Stdin: strings.NewReader(""), Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}})
}

// TestGroupKillTakesChild (verifier finding, 2026-10-14): when the caller's
// process group is ended with SIGKILL (as Claude Code may end a Bash
// command), watchdeck cannot forward anything; the sandboxed child and its
// children are in the same group and die with it, never left with ppid 1.
func TestGroupKillTakesChild(t *testing.T) {
	skipIfNoSandbox(t)
	pidFile := filepath.Join(t.TempDir(), "sleep.pid")
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperRunsSandboxed$", "-test.count=1")
	cmd.Env = append(os.Environ(), "WATCHDECK_SANDBOX_HELPER="+pidFile)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} // the "shell's" group
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	sleepPid := readPid(t, pidFile)
	if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	waitGone(t, sleepPid, "sandboxed grandchild after the group SIGKILL")
}

// TestChildStaysInCallerGroup: the child runs in watchdeck's process
// group, and stdin passes through.
func TestChildStaysInCallerGroup(t *testing.T) {
	skipIfNoSandbox(t)
	var out bytes.Buffer
	_, err := Run(context.Background(), Options{Profile: trivial,
		Argv: []string{"/bin/sh", "-c", `read line; echo "$(/usr/bin/perl -e 'print getpgrp()') $line"`},
		Env:  []string{"PATH=/usr/bin:/bin"}, Stdin: strings.NewReader("hello\n"), Stdout: &out, Stderr: &bytes.Buffer{}})
	if err != nil {
		t.Fatal(err)
	}
	f := strings.Fields(out.String())
	if len(f) != 2 || f[0] != strconv.Itoa(syscall.Getpgrp()) || f[1] != "hello" {
		t.Fatalf("output %q, our pgrp %d", out.String(), syscall.Getpgrp())
	}
}

// TestDescendants walks a small tree.
func TestDescendants(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "gc.pid")
	cmd := exec.Command("/bin/sh", "-c", `sh -c 'sleep 30' & echo $! > "$1"; wait`, "sh", pidFile)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { killTree(cmd.Process); _ = cmd.Wait() }()
	child := readPid(t, pidFile)
	ds := descendants(cmd.Process.Pid)
	found := false
	for _, d := range ds {
		found = found || d == child
	}
	if !found {
		t.Fatalf("descendants of %d = %v, want %d among them", cmd.Process.Pid, ds, child)
	}
}
