package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/mapapi"
	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
	"github.com/Panda-Taps-LLC/watchdeck/internal/rulebook"
	"github.com/Panda-Taps-LLC/watchdeck/internal/sessionsapi"
	"github.com/Panda-Taps-LLC/watchdeck/internal/ui"
	"github.com/Panda-Taps-LLC/watchdeck/internal/uistate"
)

const uiUsage = `usage: watchdeck ui [--port N] [--no-open] [--idle MINUTES] [--no-transcripts]
                    [--detach [--open]] [--ensure [--open]] [--service]
                    [--stop] [--rotate-token]

Serves the dashboard on 127.0.0.1 (never another address) and opens it in
the browser. One dashboard runs per state dir: when one is already running
and healthy, 'watchdeck ui' opens that one (its port, token and mode win;
--port, --idle and --no-transcripts are then ignored).

The token is kept in <state dir>/ui.token (0600) and reused across restarts;
the launch URL carries it in its fragment (#t=...). The URL is printed to
stdout only when no browser was opened or opening failed, never to stderr.
A dashboard started from a terminal exits 0 after --idle minutes without an
authenticated API request (default 30, 0 = never), or on Ctrl-C; one started
with --ensure or --service has no idle exit.

  --port N           port to bind (default: the last port used, when free,
                     else any free port)
  --no-open          do not open a browser; print the URL instead
  --idle MINUTES     idle exit (default 30; 0 disables, except with --detach)
  --no-transcripts   never read Claude Code session transcripts
  --detach           start the dashboard in the background and return once it
                     listens; prints the URL, or with --open opens the browser
                     and prints "opened http://127.0.0.1:<port>/" (no token)
  --ensure           make sure a dashboard runs: return at once if one holds
                     the lock, else start one in the background (no idle exit)
                     without waiting for it; with --open, wait for it and
                     open the browser
  --open             with --detach or --ensure: open the browser
  --service          run in the foreground with no idle exit (launchd and
                     systemd use this; see watchdeck service)
  --stop             stop the running dashboard (authenticated, with a nonce)
  --rotate-token     replace the token; open tabs and remembered tokens stop
                     working, a running dashboard switches at once

`

const (
	uiDefaultIdle   = 30              // minutes
	detachWait      = 5 * time.Second // the mod's call times out at 10 s
	ensureOpenWait  = 5 * time.Second
	openerWait      = 5 * time.Second
	stopWait        = 5 * time.Second
	loserWait       = 2 * time.Second  // a second server waits this long for the first to answer
	lockRetry       = time.Second      // a Locked check by another process holds the lock for a moment
	stateReassert   = 15 * time.Second // how often a server checks that ui.json still names it
	detachedFDFlag  = "detached-fd"
	detachedChildFD = 3 // the first of cmd.ExtraFiles
)

func cmdUI(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("ui", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, uiUsage) }
	port := fs.Int("port", 0, "")
	noOpen := fs.Bool("no-open", false, "")
	open := fs.Bool("open", false, "")
	idle := fs.Int("idle", uiDefaultIdle, "")
	noTranscripts := fs.Bool("no-transcripts", false, "")
	detach := fs.Bool("detach", false, "")
	ensure := fs.Bool("ensure", false, "")
	service := fs.Bool("service", false, "")
	stop := fs.Bool("stop", false, "")
	rotate := fs.Bool("rotate-token", false, "")
	// Internal: the mode of a server started by --ensure (auto); --service
	// is mode service; a terminal run is manual.
	mode := fs.String("mode", "", "")
	// Internal: set by --detach on the re-executed child. The child writes
	// its launch URL (or "error: ...") as one line to this inherited pipe
	// fd.
	detachedFD := fs.Int(detachedFDFlag, 0, "")
	if err := fs.Parse(args); err != nil {
		return 3
	}
	portSet := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "port" {
			portSet = true
		}
	})
	actions := 0
	for _, b := range []bool{*detach, *ensure, *service, *stop, *rotate} {
		if b {
			actions++
		}
	}
	switch {
	case fs.NArg() > 0:
		fmt.Fprintf(stderr, "watchdeck ui: unexpected argument %q\n", fs.Arg(0))
		return 3
	case *port < 0 || *port > 65535:
		fmt.Fprintf(stderr, "watchdeck ui: --port %d out of range\n", *port)
		return 3
	case *idle < 0:
		fmt.Fprintln(stderr, "watchdeck ui: --idle must not be negative")
		return 3
	case *open && *noOpen:
		fmt.Fprintln(stderr, "watchdeck ui: --open and --no-open contradict each other")
		return 3
	case actions > 1:
		fmt.Fprintln(stderr, "watchdeck ui: --detach, --ensure, --service, --stop and --rotate-token exclude each other")
		return 3
	case *detach && *detachedFD != 0:
		fmt.Fprintln(stderr, "watchdeck ui: --detach cannot be nested")
		return 3
	case *detachedFD != 0 && *detachedFD < detachedChildFD:
		// 0, 1 and 2 are stdio: the URL with its token must never go there.
		fmt.Fprintf(stderr, "watchdeck ui: --%s must be %d or higher\n", detachedFDFlag, detachedChildFD)
		return 3
	case *mode != "" && !uistate.ValidMode(*mode):
		fmt.Fprintf(stderr, "watchdeck ui: --mode must be manual, auto or service\n")
		return 3
	case *mode != "" && actions > 0:
		fmt.Fprintln(stderr, "watchdeck ui: --mode is internal and takes no other action")
		return 3
	}

	hp, env, err := hostPaths()
	if err != nil {
		fmt.Fprintln(stderr, "watchdeck ui:", err)
		return 2
	}
	ctx := context.Background()
	switch {
	case *stop:
		return uiStop(ctx, hp, stdout, stderr)
	case *rotate:
		return uiRotate(hp, stdout, stderr)
	case *ensure:
		return uiEnsure(ctx, hp, stdout, stderr, *open, *noTranscripts)
	case *detach:
		// A background server started from a terminal always has an idle exit.
		minutes := *idle
		if minutes == 0 {
			minutes = uiDefaultIdle
		}
		if inst, err := uistate.Running(ctx, hp); err == nil {
			return reportInstance(stdout, stderr, inst, *open)
		}
		pass := -1
		if portSet {
			pass = *port
		}
		return uiDetach(stdout, stderr, pass, minutes, *noTranscripts, *open)
	}

	m := *mode
	if *service {
		m = uistate.ModeService
	}
	if m == "" {
		m = uistate.ModeManual
	}
	// A terminal run reuses a healthy dashboard instead of starting a second.
	if m == uistate.ModeManual && *detachedFD == 0 {
		if inst, err := uistate.Running(ctx, hp); err == nil {
			return reportInstance(stdout, stderr, inst, !*noOpen)
		}
	}
	return serveUI(serveOptions{
		paths: hp, env: env, mode: m,
		port: *port, portSet: portSet,
		idle:          *idle,
		noTranscripts: *noTranscripts,
		noOpen:        *noOpen,
		open:          *open,
		detachedFD:    *detachedFD,
	}, stdout, stderr)
}

type serveOptions struct {
	paths         paths.Paths
	env           map[string]string
	mode          string
	port          int
	portSet       bool
	idle          int
	noTranscripts bool
	noOpen, open  bool
	detachedFD    int
}

// serveUI runs the server in this process: take ui.lock (or report the
// instance that holds it and exit 0), load the token, bind the last port
// when free, write ui.json, serve until idle, a signal or POST /api/shutdown.
func serveUI(o serveOptions, stdout, stderr io.Writer) int {
	var report *os.File // the detached child's status pipe
	if o.detachedFD != 0 {
		report = os.NewFile(uintptr(o.detachedFD), "detached-status")
		if report == nil {
			return 3
		}
		defer report.Close()
	}
	fail := func(code int, format string, a ...any) int {
		msg := fmt.Sprintf(format, a...)
		fmt.Fprintln(stderr, "watchdeck ui:", msg)
		if report != nil {
			fmt.Fprintln(report, "error:", msg)
		}
		return code
	}
	hp := o.paths
	ctx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	lock, err := uistate.LockOrWait(hp, lockRetry)
	if errors.Is(err, uistate.ErrLocked) {
		// Another server won: report it and leave (exit 0).
		inst, perr := uistate.WaitRunning(ctx, hp, loserWait)
		if perr != nil {
			return fail(1, "another watchdeck ui holds %s but does not answer", uistate.Path(hp, uistate.LockFile))
		}
		switch {
		case report != nil:
			fmt.Fprintln(report, inst.URL())
			return 0
		case o.mode == uistate.ModeManual:
			return reportInstance(stdout, stderr, inst, !o.noOpen)
		default:
			fmt.Fprintf(stderr, "watchdeck ui: already running (pid %d, %s mode) on 127.0.0.1:%d; exiting\n", inst.State.PID, inst.Status.Mode, inst.State.Port)
			return 0
		}
	}
	if err != nil {
		return fail(2, "%v", err)
	}
	defer lock.Release()
	pid := os.Getpid()
	// First write under the lock: port 0, so no probe reaches the old port
	// (which something else may hold now) before this server listens.
	hint := 0
	if st, ok, _ := uistate.ReadState(hp); ok {
		hint = uistate.HintPort(st)
	}
	if err := uistate.MarkStarting(hp, pid, o.mode); err != nil {
		return fail(2, "state: %v", err)
	}
	if o.mode == uistate.ModeService {
		rotateServiceLog(hp, stderr)
	}

	token, err := uistate.LoadOrCreateToken(hp)
	if err != nil {
		return fail(2, "token: %v", err)
	}
	watcher := uistate.NewTokenWatcher(hp)

	idle := o.idle
	cwd := ""
	if o.mode == uistate.ModeManual {
		cwd, _ = os.Getwd()
	} else {
		idle = 0 // auto and service: no idle exit
	}
	self, _ := selfPath() // "" when the OS cannot say; the Enforce page then reports it
	// The session catalog (M5.5) owns the session index for this server's
	// lifetime: one goroutine refreshes it, the Sessions routes and the
	// event stream read its snapshot, and it lists the projects a
	// ?project= value may name.
	catalog := sessionsapi.New(sessionsapi.Options{Paths: hp, NoTranscripts: o.noTranscripts})
	catalogCtx, stopCatalog := context.WithCancel(ctx)
	defer stopCatalog()
	catalog.Start(catalogCtx)
	roots := catalog.ProjectRoots
	routes := mapapi.Routes(mapapi.Deps{
		Paths:         hp,
		Cwd:           cwd,
		Environ:       o.env,
		NoTranscripts: o.noTranscripts,
		Version:       version,
		ProjectRoots:  roots,
	})
	delete(routes, mapapi.PatternSessions) // the catalog's GET /api/sessions replaces mapapi's
	for k, v := range catalog.Routes() {
		routes[k] = v
	}
	// Leak watch reads the session index, so it is off with transcripts.
	var leaks func(time.Time) []rulebook.Leak
	if !o.noTranscripts {
		leaks = catalog.Leaks
	}
	srv, err := ui.New(ui.Options{
		Paths:         hp,
		Cwd:           cwd,
		Environ:       o.env,
		Version:       version,
		Binary:        self,
		Idle:          time.Duration(idle) * time.Minute,
		NoTranscripts: o.noTranscripts,
		Token:         token,
		TokenSource:   watcher.Token,
		Mode:          o.mode,
		ProjectRoots:  roots,
		Routes:        routes,
		Events:        catalog,
		Leaks:         leaks,
	})
	if err != nil {
		return fail(2, "%v", err)
	}

	// Stable port: the one ui.json last recorded, when it is free.
	want := o.port
	if !o.portSet {
		want = hint
	}
	ln, err := ui.Listen(want)
	if err != nil && !o.portSet && want != 0 {
		ln, err = ui.Listen(0)
		if err == nil {
			// Something else holds the old port. A browser that remembered
			// the token on that origin may hand it to whatever serves there,
			// so the token is replaced: the old one is worth nothing now.
			if _, rerr := uistate.RotateToken(hp); rerr != nil {
				ln.Close()
				return fail(2, "port %d is taken and the token could not be rotated: %v", want, rerr)
			}
			fmt.Fprintf(stderr, "watchdeck ui: port %d is in use by another process; listening on a new port and the token was rotated (open tabs and remembered tokens stop working)\n", want)
		}
	}
	if err != nil {
		return fail(2, "%v", err)
	}
	lport := ln.Addr().(*net.TCPAddr).Port
	mine := uistate.State{
		PID: pid, Port: lport, Started: time.Now().UTC().Format(time.RFC3339),
		Version: version, Binary: self, Mode: o.mode, NoTranscripts: o.noTranscripts,
	}
	if err := uistate.WriteState(hp, mine); err != nil {
		ln.Close()
		return fail(2, "state: %v", err)
	}
	defer uistate.ClearPID(hp, pid)
	// ui.json is what other processes probe; if anything rewrites it while
	// this server holds the lock, put it back.
	reassertDone := make(chan struct{})
	defer close(reassertDone)
	go func() {
		t := time.NewTicker(stateReassert)
		defer t.Stop()
		for {
			select {
			case <-reassertDone:
				return
			case <-t.C:
				uistate.Reassert(hp, mine)
			}
		}
	}()

	url := srv.URL(ln)
	fmt.Fprintf(stderr, "watchdeck ui: listening on %s (%s)\n", ln.Addr(), modeText(o.mode, idle))

	served := make(chan error, 1)
	go func() { served <- srv.Serve(ctx, ln) }()

	switch {
	case report != nil:
		fmt.Fprintln(report, url)
		report.Close()
		report = nil
	case o.mode != uistate.ModeManual:
		if o.open {
			if err := openBrowser(url); err != nil {
				fmt.Fprintf(stderr, "watchdeck ui: could not open a browser (%v)\n", err)
			}
		}
	case o.noOpen:
		fmt.Fprintln(stdout, url)
	default:
		if err := openBrowser(url); err != nil {
			fmt.Fprintf(stderr, "watchdeck ui: could not open a browser (%v); open the URL printed on stdout\n", err)
			fmt.Fprintln(stdout, url)
		} else {
			fmt.Fprintf(stdout, "watchdeck ui: opened %s in your browser\n", baseURL(ln))
		}
	}

	if err := <-served; err != nil {
		fmt.Fprintln(stderr, "watchdeck ui:", err)
		return 1
	}
	switch {
	case srv.Stopped():
		fmt.Fprintln(stderr, "watchdeck ui: stopped (watchdeck ui --stop)")
	case ctx.Err() == nil:
		fmt.Fprintf(stderr, "watchdeck ui: no requests for %d min, exiting\n", idle)
	}
	return 0
}

// reportInstance points the person at a running dashboard: it opens the
// browser at its launch URL, or prints the URL when open is false or the
// opener failed. The token goes to the browser or stdout, never stderr.
func reportInstance(stdout, stderr io.Writer, inst uistate.Instance, open bool) int {
	fmt.Fprintf(stderr, "watchdeck ui: already running (pid %d, %s mode) on 127.0.0.1:%d; using it (--port, --idle and --no-transcripts do not apply)\n",
		inst.State.PID, inst.Status.Mode, inst.State.Port)
	if open {
		if err := openBrowser(inst.URL()); err == nil {
			fmt.Fprintf(stdout, "watchdeck ui: opened %s in your browser\n", uistate.BaseURL(inst.State.Port))
			return 0
		} else {
			fmt.Fprintf(stderr, "watchdeck ui: could not open a browser (%v); open the URL printed on stdout\n", err)
		}
	}
	fmt.Fprintln(stdout, inst.URL())
	return 0
}

// uiEnsure makes sure a dashboard runs. Without --open it never waits: one
// flock attempt and, when the lock was free, one fork/exec (uistate.Ensure).
// With --open it waits for the dashboard to answer and opens the browser.
//
// --ensure never prints the launch URL, on any path: it runs from slash
// commands and the in-session mod, whose output reaches the model and the
// transcript. When the browser cannot be opened it exits 1 and says to run
// watchdeck ui in a terminal.
func uiEnsure(ctx context.Context, hp paths.Paths, stdout, stderr io.Writer, open, noTranscripts bool) int {
	self, err := selfPath()
	if err != nil {
		fmt.Fprintln(stderr, "watchdeck ui: cannot locate the watchdeck binary:", err)
		return 1
	}
	if open {
		if inst, err := uistate.Running(ctx, hp); err == nil {
			return ensureOpen(stdout, stderr, inst)
		}
	}
	spawned, pid, err := uistate.Ensure(hp, self, uistate.SpawnOptions{Mode: uistate.ModeAuto, NoTranscripts: noTranscripts})
	if err != nil {
		fmt.Fprintln(stderr, "watchdeck ui:", err)
		return 1
	}
	if spawned {
		fmt.Fprintf(stderr, "watchdeck ui: started pid %d in the background (auto mode, no idle exit)\n", pid)
	} else if !open {
		fmt.Fprintln(stderr, "watchdeck ui: already running")
	}
	if !open {
		return 0
	}
	inst, err := uistate.WaitRunning(ctx, hp, ensureOpenWait)
	if err != nil {
		fmt.Fprintf(stderr, "watchdeck ui: the dashboard did not answer within %s; run watchdeck ui\n", ensureOpenWait)
		return 1
	}
	return ensureOpen(stdout, stderr, inst)
}

// ensureOpen opens the browser at inst's launch URL. The URL (with its
// token) goes only to the opener, never to stdout or stderr.
func ensureOpen(stdout, stderr io.Writer, inst uistate.Instance) int {
	if err := openBrowser(inst.URL()); err != nil {
		fmt.Fprintf(stderr, "watchdeck ui: could not open a browser (%v); run `watchdeck ui` in a terminal\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "watchdeck ui: opened %s in your browser\n", uistate.BaseURL(inst.State.Port))
	return 0
}

func uiStop(ctx context.Context, hp paths.Paths, stdout, stderr io.Writer) int {
	inst, err := uistate.Stop(ctx, hp, stopWait)
	switch {
	case errors.Is(err, uistate.ErrNotRunning):
		fmt.Fprintln(stdout, "watchdeck ui: not running")
		return 0
	case err != nil:
		fmt.Fprintln(stderr, "watchdeck ui:", err)
		return 1
	}
	fmt.Fprintf(stdout, "watchdeck ui: stopped pid %d (%s mode)\n", inst.State.PID, inst.Status.Mode)
	if inst.Status.Mode == uistate.ModeService {
		fmt.Fprintln(stdout, "watchdeck ui: the service stays installed and starts again at the next login; watchdeck service uninstall removes it")
	}
	return 0
}

func uiRotate(hp paths.Paths, stdout, stderr io.Writer) int {
	if _, err := uistate.RotateToken(hp); err != nil {
		fmt.Fprintln(stderr, "watchdeck ui: rotate token:", err)
		return 2
	}
	fmt.Fprintf(stdout, "watchdeck ui: new token written to %s; open tabs and remembered tokens no longer work. Run watchdeck ui to open the dashboard again.\n",
		displayHome(uistate.Path(hp, uistate.TokenFile), hp.Home))
	return 0
}

// uiDetach re-executes this binary as a background server in its own session
// (stdio on /dev/null, so a caller waiting for EOF on our stdout is never
// held up), waits until it listens, then opens the browser or prints the URL.
// port -1 lets the child pick (the last port, else any).
func uiDetach(stdout, stderr io.Writer, port, idle int, noTranscripts, open bool) int {
	self, err := selfPath()
	if err != nil {
		fmt.Fprintln(stderr, "watchdeck ui: cannot locate the watchdeck binary to detach:", err)
		return 1
	}
	r, w, err := os.Pipe()
	if err != nil {
		fmt.Fprintln(stderr, "watchdeck ui:", err)
		return 1
	}
	defer r.Close()
	args := []string{"ui", "--no-open",
		"--idle", strconv.Itoa(idle),
		"--" + detachedFDFlag, strconv.Itoa(detachedChildFD)}
	if port >= 0 {
		args = append(args, "--port", strconv.Itoa(port))
	}
	if noTranscripts {
		args = append(args, "--no-transcripts")
	}
	cmd := exec.Command(self, args...)
	cmd.ExtraFiles = []*os.File{w} // fd 3 in the child
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	// Stdin, Stdout and Stderr stay nil: the child gets /dev/null.
	if err := cmd.Start(); err != nil {
		w.Close()
		fmt.Fprintln(stderr, "watchdeck ui: start:", err)
		return 1
	}
	w.Close()
	pid := cmd.Process.Pid

	_ = r.SetReadDeadline(time.Now().Add(detachWait))
	line, rerr := bufio.NewReader(r).ReadString('\n')
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "http://127.0.0.1:") {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		switch {
		case strings.HasPrefix(line, "error:"):
			fmt.Fprintln(stderr, "watchdeck ui:", strings.TrimSpace(strings.TrimPrefix(line, "error:")))
		case errors.Is(rerr, os.ErrDeadlineExceeded):
			fmt.Fprintf(stderr, "watchdeck ui: the background server did not start within %s\n", detachWait)
		default:
			fmt.Fprintln(stderr, "watchdeck ui: the background server exited before it listened")
		}
		return 1
	}
	_ = cmd.Process.Release()
	base, _, _ := strings.Cut(line, "#")
	hostport := strings.TrimSuffix(strings.TrimPrefix(base, "http://"), "/")
	fmt.Fprintf(stderr, "watchdeck ui: started pid %d, listening on %s (%s)\n", pid, hostport, idleText(idle))
	if open {
		err := openBrowser(line)
		if err == nil {
			fmt.Fprintf(stdout, "watchdeck ui: opened %s in your browser\n", base)
			return 0
		}
		fmt.Fprintf(stderr, "watchdeck ui: could not open a browser (%v); open the URL printed on stdout\n", err)
	}
	fmt.Fprintln(stdout, line)
	return 0
}

// openBrowser opens url with $BROWSER when set, else `open` (macOS) or
// `xdg-open` (Linux). The opener's own output is discarded. An opener that
// has not returned within openerWait counts as a failure (the caller then
// prints the URL); it is left running, never killed, since it may be the
// browser itself.
func openBrowser(url string) error {
	name := os.Getenv("BROWSER")
	if name == "" {
		switch runtime.GOOS {
		case "darwin":
			name = "open"
		case "linux":
			name = "xdg-open"
		default:
			return fmt.Errorf("no opener on %s", runtime.GOOS)
		}
	}
	cmd := exec.Command(name, url)
	if err := cmd.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return err
	case <-time.After(openerWait):
		return fmt.Errorf("%s did not return within %s", filepath.Base(name), openerWait)
	}
}

// baseURL is the launch URL without the token: http://127.0.0.1:<port>/.
func baseURL(ln net.Listener) string {
	return "http://" + ln.Addr().String() + "/"
}

func idleText(minutes int) string {
	if minutes == 0 {
		return "no idle exit"
	}
	return fmt.Sprintf("idle exit after %d min", minutes)
}

func modeText(mode string, idle int) string {
	if mode == uistate.ModeManual {
		return idleText(idle)
	}
	return mode + " mode, no idle exit"
}
