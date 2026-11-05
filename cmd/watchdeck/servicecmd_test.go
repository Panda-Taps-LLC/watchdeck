package main

import (
	"bytes"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/Panda-Taps-LLC/watchdeck/internal/service"
)

func serviceCmd(a []string, o, e *bytes.Buffer) int { return cmdService(a, o, e) }

// refusingRunner is TestMain's default: any call is a test bug.
type refusingRunner struct{}

func (refusingRunner) Run(name string, args ...string) (string, error) {
	panic("a test reached the service runner: " + name + " " + strings.Join(args, " "))
}

type recordingRunner struct{ calls []string }

func (r *recordingRunner) Run(name string, args ...string) (string, error) {
	c := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, c)
	return "", nil
}

func fakeServiceRunner(t *testing.T) *recordingRunner {
	t.Helper()
	r := &recordingRunner{}
	old := serviceRunner
	serviceRunner = r
	t.Cleanup(func() { serviceRunner = old })
	return r
}

func TestServiceInstallViaFakeRunner(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("launchd or systemd only")
	}
	newTestEnv(t)
	r := fakeServiceRunner(t)
	o, err := serviceOptions()
	if err != nil {
		t.Fatal(err)
	}

	// --dry-run: prints the file and commands, runs and writes nothing
	code, out, _ := call(t, serviceCmd, "install", "--dry-run")
	if code != 0 || !strings.Contains(out, "ui") || !strings.Contains(out, "--service") || !strings.Contains(out, "dry run") {
		t.Fatalf("dry run: %d %q", code, out)
	}
	if len(r.calls) != 0 {
		t.Fatalf("dry run ran %v", r.calls)
	}
	if _, err := os.Stat(o.File()); err == nil {
		t.Fatal("dry run wrote the file")
	}

	// no terminal, no --yes: nothing
	c, buf := testConsole("", false, false)
	if code := serviceInstall(c, o, false); code != 1 || len(r.calls) != 0 {
		t.Fatalf("no tty: %d %v\n%s", code, r.calls, buf)
	}
	// declined on a terminal: nothing
	c, buf = testConsole("n\n", true, false)
	if code := serviceInstall(c, o, false); code != 1 || len(r.calls) != 0 {
		t.Fatalf("declined: %d %v\n%s", code, r.calls, buf)
	}
	if _, err := os.Stat(o.File()); err == nil {
		t.Fatal("declined but the file was written")
	}

	// confirmed: file written under the temp home, commands through the fake
	c, buf = testConsole("y\n", true, false)
	if code := serviceInstall(c, o, false); code != 0 {
		t.Fatalf("install: %d\n%s", code, buf)
	}
	b, err := os.ReadFile(o.File())
	if err != nil || string(b) != service.Content(o) {
		t.Fatalf("file: %v", err)
	}
	if !strings.HasPrefix(o.File(), o.Paths.Home) && !strings.HasPrefix(o.File(), os.Getenv("XDG_CONFIG_HOME")) {
		t.Fatalf("service file outside the temp dirs: %s", o.File())
	}
	want := "systemctl --user enable --now watchdeck-ui.service"
	if runtime.GOOS == "darwin" {
		want = "launchctl bootstrap gui/"
	}
	if !strings.Contains(strings.Join(r.calls, "\n"), want) {
		t.Fatalf("calls %v", r.calls)
	}

	code, out, _ = call(t, serviceCmd, "status")
	if code != 0 || !strings.Contains(out, "installed and loaded") || !strings.Contains(out, "dashboard: not running") {
		t.Fatalf("status: %d %q", code, out)
	}

	code, out, _ = call(t, serviceCmd, "uninstall", "--yes")
	if code != 0 || !strings.Contains(out, "removed") {
		t.Fatalf("uninstall: %d %q", code, out)
	}
	if _, err := os.Stat(o.File()); !os.IsNotExist(err) {
		t.Fatal("file still there")
	}
}

func TestServiceUsage(t *testing.T) {
	newTestEnv(t)
	for _, args := range [][]string{{}, {"bogus"}, {"install", "extra"}, {"--yes"}} {
		code, _, _ := call(t, serviceCmd, args...)
		if code != 3 {
			t.Errorf("service %v: %d, want 3", args, code)
		}
	}
}
