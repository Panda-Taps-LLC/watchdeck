package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/Panda-Taps-LLC/watchdeck/internal/demo"
	"github.com/Panda-Taps-LLC/watchdeck/internal/sandbox"
)

const demoUsage = `usage: watchdeck demo [--yes] [--no-open] [--keep]

Runs a test skill, canary-request (built into the binary), in a throwaway
directory under /var/tmp with its own HOME, XDG dirs, Claude Code config dir
and activity log. Its script asks for the network; the default grant does
not give it, so the sandbox refuses the connection and watchdeck prints
the denial and its [watchdeck] trailer. Then it offers to open the
dashboard on the demo tree (the run shows on the Flow page as a "direct"
session). The dashboard runs with the same demo environment, so its Skills,
Grants and Enforce pages see and change only the demo tree. Nothing of your
own skills, grants, settings or activity log is read or changed.

  --yes      open the dashboard without asking
  --no-open  do not offer the dashboard
  --keep     keep the demo directory (it is removed at the end otherwise,
             unless the dashboard was opened on it)

Needs python3: without it, demo explains and exits 0. Exit codes: 0 done,
1 no sandbox backend on this machine (sandbox-exec on macOS, bwrap on
Linux), 2 an error, 3 usage.
`

func cmdDemo(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("demo", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, demoUsage) }
	yes := fs.Bool("yes", false, "")
	noOpen := fs.Bool("no-open", false, "")
	keepFlag := fs.Bool("keep", false, "")
	if err := fs.Parse(args); err != nil {
		return 3
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "watchdeck demo: unexpected argument %q\n", fs.Arg(0))
		return 3
	}
	if !sandbox.Available() {
		fmt.Fprintln(stdout, "watchdeck demo: this machine has no sandbox backend (sandbox-exec on macOS, bwrap on Linux), so there is nothing to show.")
		return 1
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		fmt.Fprintln(stdout, "watchdeck demo: the demo skill's script is Python, and python3 is not on PATH, so it was not run.")
		fmt.Fprintln(stdout, "Install python3 and rerun, or try a skill of your own: watchdeck audit lists them.")
		return 0
	}
	e, err := demo.Prepare()
	if err != nil {
		fmt.Fprintln(stderr, "watchdeck demo:", err)
		return 2
	}
	keep := *keepFlag
	defer func() {
		if !keep {
			e.Remove()
		}
	}()

	fmt.Fprintf(stdout, "Demo skill %s asks for network: all in its PERMISSIONS.yaml; the default grant is network: none.\n", demo.Skill)
	fmt.Fprintf(stdout, "Running under its sandbox:\n  watchdeck run --skill %s -c '%s'\n\n", demo.Skill, e.ProbeCommand(python))
	var seen bytes.Buffer
	// one writer for both streams: run copies stdout and stderr from two
	// goroutines, so the shared writer is serialized
	w := &lockedWriter{w: io.MultiWriter(stdout, &seen)}
	code := e.Run(context.Background(), python, os.Environ(), w, w)
	fmt.Fprintln(stdout)
	switch {
	case strings.Contains(seen.String(), "net: DENIED"):
		fmt.Fprintln(stdout, "The sandbox refused the connection (net: DENIED), and the [watchdeck] lines say why and how to widen the grant.")
		fmt.Fprintf(stdout, "In your own setup that would be: watchdeck allow %s --network all\n", demo.Skill)
	case code == 0:
		fmt.Fprintln(stdout, "The probe was not denied the network; that is unexpected. Run watchdeck doctor.")
	default:
		fmt.Fprintf(stdout, "The probe did not get as far as a network denial (exit %d; see the output above). Run watchdeck doctor.\n", code)
	}

	if *noOpen {
		return demoDone(stdout, e, keep)
	}
	c := newConsole(stdout, stderr, *yes)
	open, ok := c.ask("\nOpen the dashboard on this demo?", true)
	if !ok {
		fmt.Fprintln(stdout, "\nNo terminal to ask on: the dashboard was not opened. Rerun with --yes to open it.")
		return demoDone(stdout, e, keep)
	}
	if !open {
		return demoDone(stdout, e, keep)
	}
	self, err := selfPath()
	if err != nil {
		fmt.Fprintln(stderr, "watchdeck demo:", err)
		return 2
	}
	keep = true // the dashboard reads the tree
	cmd := demoUICommand(self, e, os.Environ())
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintln(stderr, "watchdeck demo: could not start the dashboard:", err)
	} else {
		fmt.Fprintln(stdout, "Open Flow and pick the \"direct\" session: the run and its network denial are there.")
	}
	fmt.Fprintf(stdout, "The demo files stay in %s while the dashboard reads them; delete it when done.\n", e.Base)
	return 0
}

// demoDone reports where a kept tree is; the deferred cleanup removes the rest.
func demoDone(stdout io.Writer, e *demo.Env, keep bool) int {
	if keep {
		fmt.Fprintf(stdout, "The demo files stay in %s (--keep). To look at them in the dashboard:\n  env HOME=%s XDG_CONFIG_HOME=%s XDG_CACHE_HOME=%s XDG_STATE_HOME=%s CLAUDE_CONFIG_DIR=%s WATCHDECK_ACTIVITY=%s watchdeck ui --no-transcripts\n",
			e.Base, e.Home, e.XDGConfig, e.XDGCache, e.XDGState, e.ClaudeDir, e.Activity)
	}
	return 0
}

// demoUICommand is the detached dashboard for the demo: the demo
// environment (every location inside the demo tree), the demo project as
// its working directory, and no transcript reading.
func demoUICommand(self string, e *demo.Env, parent []string) *exec.Cmd {
	cmd := exec.Command(self, "ui", "--detach", "--open", "--no-transcripts")
	cmd.Env = e.Environ(parent)
	cmd.Dir = e.Cwd
	return cmd
}

// lockedWriter serializes writes to w.
type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}
