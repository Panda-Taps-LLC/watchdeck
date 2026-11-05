//go:build darwin

package sandbox

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const trivial = "(version 1)(allow default)"

func skipIfNoSandbox(t *testing.T) {
	t.Helper()
	if !Available() {
		t.Skip("no /usr/bin/sandbox-exec")
	}
}

func TestRunTrue(t *testing.T) {
	skipIfNoSandbox(t)
	var out, errb bytes.Buffer
	res, err := Run(context.Background(), Options{Profile: trivial, Argv: []string{"/usr/bin/true"}, Env: []string{"PATH=/usr/bin:/bin"}, Stdout: &out, Stderr: &errb})
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("res=%+v err=%v stderr=%s", res, err, errb.String())
	}
}

func TestExitCodePassesThrough(t *testing.T) {
	skipIfNoSandbox(t)
	var errb bytes.Buffer
	res, err := Run(context.Background(), Options{Profile: trivial, Argv: []string{"/bin/sh", "-c", "echo oops >&2; exit 7"}, Env: []string{"PATH=/usr/bin:/bin"}, Stdout: &bytes.Buffer{}, Stderr: &errb})
	if err != nil {
		t.Fatalf("unexpected err %v", err)
	}
	if res.ExitCode != 7 || !strings.Contains(errb.String(), "oops") {
		t.Fatalf("res=%+v stderr=%q", res, errb.String())
	}
}

// TestLingeringGrandchildBoundedByWaitDelay: with non-file writers the child
// writes into pipes; a background grandchild holding them must not keep Run
// waiting past StreamWaitDelay, and the child's own exit code (0 via
// exec.ErrWaitDelay, non-zero via ExitError) and output come back intact.
func TestLingeringGrandchildBoundedByWaitDelay(t *testing.T) {
	skipIfNoSandbox(t)
	home := t.TempDir()
	env := []string{"PATH=/usr/bin:/bin", "HOME=" + home}
	for _, c := range []struct {
		script string
		code   int
		out    string
	}{
		{"sleep 10 & echo done", 0, "done\n"},
		{"sleep 10 >&2 & echo partial; exit 7", 7, "partial\n"},
	} {
		var out, errb bytes.Buffer
		start := time.Now()
		res, err := Run(context.Background(), Options{Profile: trivial, Argv: []string{"/bin/sh", "-c", c.script}, Env: env, Dir: home, Stdout: &out, Stderr: &errb})
		took := time.Since(start)
		if err != nil {
			t.Fatalf("%q: err %v", c.script, err)
		}
		if took > StreamWaitDelay+2*time.Second {
			t.Errorf("%q: Run took %v", c.script, took)
		}
		if res.ExitCode != c.code || res.Signaled || out.String() != c.out {
			t.Errorf("%q: res=%+v out=%q err=%q", c.script, res, out.String(), errb.String())
		}
	}
}

func TestEnvIsNotInherited(t *testing.T) {
	skipIfNoSandbox(t)
	t.Setenv("CANARY_SECRET", "not-a-real-secret")
	var out bytes.Buffer
	_, err := Run(context.Background(), Options{Profile: trivial, Argv: []string{"/bin/sh", "-c", "echo ${CANARY_SECRET:-SCRUBBED}"}, Env: []string{"PATH=/usr/bin:/bin"}, Stdout: &out, Stderr: &bytes.Buffer{}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(out.String()) != "SCRUBBED" {
		t.Fatalf("secret leaked into child: %q", out.String())
	}
}

// TestNestedApplyFails re-runs this test binary inside an outer sandbox-exec and
// asserts that Run reports ErrApply instead of executing the command.
//
// Verified 2026-10-11: nesting succeeds only when the outer profile is a bare
// (allow default). Any deny rule in the outer profile (network, file, mach,
// sysctl, exec) makes the inner sandbox_apply fail with exit 71 and
// "sandbox-exec: sandbox_apply: Operation not permitted". Claude Code's Bash
// sandbox always carries denies, so this is the case that matters.
func TestNestedApplyFails(t *testing.T) {
	skipIfNoSandbox(t)
	if os.Getenv("SANDBOX_TEST_HELPER") == "1" {
		_, err := Run(context.Background(), Options{Profile: trivial, Argv: []string{"/usr/bin/true"}, Env: []string{"PATH=/usr/bin:/bin"}, Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}})
		switch {
		case errors.Is(err, ErrApply):
			os.Stdout.WriteString("ERRAPPLY\n")
		case err == nil:
			os.Stdout.WriteString("RAN\n")
		default:
			os.Stdout.WriteString("OTHER: " + err.Error() + "\n")
		}
		os.Exit(0)
	}
	outer := "(version 1)(allow default)(deny network*)"
	cmd := exec.Command(SandboxExec, "-p", outer, os.Args[0], "-test.run=^TestNestedApplyFails$", "-test.v=false")
	cmd.Env = append(os.Environ(), "SANDBOX_TEST_HELPER=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helper failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "ERRAPPLY") {
		t.Fatalf("nested run did not report ErrApply:\n%s", out)
	}
}

// An execvp failure of the target exits 71 like an apply failure but must not be reported as one.
func TestExecvpFailureIsNotApplyFailure(t *testing.T) {
	skipIfNoSandbox(t)
	var errb bytes.Buffer
	res, err := Run(context.Background(), Options{Profile: trivial, Argv: []string{"/nonexistent/binary"}, Env: []string{"PATH=/usr/bin:/bin"}, Stdout: &bytes.Buffer{}, Stderr: &errb})
	if errors.Is(err, ErrApply) {
		t.Fatalf("execvp failure misreported as ErrApply: %s", errb.String())
	}
	if err != nil {
		t.Fatalf("unexpected err %v", err)
	}
	if res.ExitCode != 71 {
		t.Fatalf("exit=%d stderr=%q", res.ExitCode, errb.String())
	}
}

func TestMalformedProfile(t *testing.T) {
	skipIfNoSandbox(t)
	var errb bytes.Buffer
	res, err := Run(context.Background(), Options{Profile: "(version 1)(allow", Argv: []string{"/usr/bin/true"}, Env: []string{"PATH=/usr/bin:/bin"}, Stdout: &bytes.Buffer{}, Stderr: &errb})
	if !errors.Is(err, ErrProfile) {
		t.Fatalf("want ErrProfile, got err=%v exit=%d stderr=%q", err, res.ExitCode, errb.String())
	}
}
