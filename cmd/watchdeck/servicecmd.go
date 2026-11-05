package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/service"
	"github.com/Panda-Taps-LLC/watchdeck/internal/uistate"
)

const serviceUsage = `usage: watchdeck service install|uninstall|status [--dry-run] [--yes]

Runs the dashboard as a per-user service that starts at login and has no
idle exit ('watchdeck ui --service'):

  macOS  ~/Library/LaunchAgents/com.pandataps.watchdeck.plist,
         launchctl bootstrap gui/<uid> (bootout to remove)
  Linux  ~/.config/systemd/user/watchdeck-ui.service,
         systemctl --user enable --now (disable --now to remove)

It is restarted only after a failure; 'watchdeck ui --stop' stops it until
the next login. Output goes to <state dir>/ui.log (0600). The location
variables set now (XDG_*_HOME, CLAUDE_CONFIG_DIR, WATCHDECK_ACTIVITY) are
written into the service, which does not inherit your shell.

  --dry-run   print the file and the commands; change nothing
  --yes       install or uninstall without asking

Exit codes: 0 done, 1 declined or a command failed, 2 an error, 3 usage.
`

// serviceRunner runs launchctl and systemctl. Tests replace it (TestMain
// installs one that refuses), so no test reaches the real service managers.
var serviceRunner service.Runner = execRunner{}

type execRunner struct{}

func (execRunner) Run(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(out), err
}

// serviceOptions builds service.Options for this host.
func serviceOptions() (service.Options, error) {
	hp, env, err := hostPaths()
	if err != nil {
		return service.Options{}, err
	}
	self, err := selfPath()
	if err != nil {
		return service.Options{}, err
	}
	return service.Options{OS: runtime.GOOS, Paths: hp, Binary: service.StableBinary(self), UID: os.Getuid(), Environ: env, Runner: serviceRunner}, nil
}

func cmdService(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		if len(args) > 0 && (args[0] == "-h" || args[0] == "--help") {
			fmt.Fprint(stdout, serviceUsage)
			return 0
		}
		fmt.Fprint(stderr, serviceUsage)
		return 3
	}
	sub := args[0]
	fs := flag.NewFlagSet("service", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, serviceUsage) }
	dry := fs.Bool("dry-run", false, "")
	yes := fs.Bool("yes", false, "")
	if err := fs.Parse(args[1:]); err != nil {
		return 3
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "watchdeck service: unexpected argument %q\n", fs.Arg(0))
		return 3
	}
	o, err := serviceOptions()
	if err != nil {
		fmt.Fprintln(stderr, "watchdeck service:", err)
		return 2
	}
	c := newConsole(stdout, stderr, *yes)
	switch sub {
	case "install":
		return serviceInstall(c, o, *dry)
	case "uninstall":
		return serviceUninstall(c, o, *dry)
	case "status":
		return serviceStatus(stdout, stderr, o)
	default:
		fmt.Fprintf(stderr, "watchdeck service: unknown subcommand %q\n\n%s", sub, serviceUsage)
		return 3
	}
}

func printPlan(w io.Writer, p service.Plan, home string, content bool) {
	if content {
		fmt.Fprintf(w, "   write %s:\n", displayHome(p.File, home))
		for _, l := range strings.Split(strings.TrimRight(p.Content, "\n"), "\n") {
			fmt.Fprintf(w, "     | %s\n", l)
		}
		fmt.Fprintf(w, "   create %s (0600)\n", displayHome(p.Log, home))
	} else {
		fmt.Fprintf(w, "   remove %s\n", displayHome(p.File, home))
	}
	for _, cmd := range p.Commands {
		fmt.Fprintf(w, "   run    %s\n", strings.Join(cmd, " "))
	}
}

func serviceInstall(c *console, o service.Options, dry bool) int {
	p, err := service.InstallPlan(o)
	if err != nil {
		fmt.Fprintln(c.errw, "watchdeck service:", err)
		return 2
	}
	fmt.Fprintln(c.out, "watchdeck service install:")
	printPlan(c.out, p, o.Paths.Home, true)
	if dry {
		fmt.Fprintln(c.out, "(dry run: nothing changed)")
		return 0
	}
	yes, ok := c.ask("Install and start the dashboard service?", true)
	switch {
	case !ok:
		fmt.Fprintln(c.errw, "watchdeck service: no terminal to confirm on; nothing was changed. Rerun in a terminal, or with --yes.")
		return 1
	case !yes:
		fmt.Fprintln(c.out, "nothing changed")
		return 1
	}
	// A dashboard started by hand or by --ensure holds the lock, and the
	// service's server would exit 0 beside it (and not be restarted).
	if inst, err := uistate.Running(context.Background(), o.Paths); err == nil && inst.Status.Mode != uistate.ModeService {
		if _, err := uistate.Stop(context.Background(), o.Paths, stopWait); err == nil {
			fmt.Fprintf(c.out, "stopped the running dashboard (pid %d, %s mode) so the service can take over\n", inst.State.PID, inst.Status.Mode)
		} else {
			fmt.Fprintf(c.out, "warning: could not stop the running dashboard (pid %d): %v; the service starts once it exits\n", inst.State.PID, err)
		}
	}
	if _, err := service.Install(o); err != nil {
		fmt.Fprintln(c.errw, "watchdeck service:", err)
		return 1
	}
	fmt.Fprintln(c.out, "installed; the dashboard now starts at login. Open it with: watchdeck ui")
	return 0
}

func serviceUninstall(c *console, o service.Options, dry bool) int {
	p, err := service.UninstallPlan(o)
	if err != nil {
		fmt.Fprintln(c.errw, "watchdeck service:", err)
		return 2
	}
	fmt.Fprintln(c.out, "watchdeck service uninstall:")
	printPlan(c.out, p, o.Paths.Home, false)
	if dry {
		fmt.Fprintln(c.out, "(dry run: nothing changed)")
		return 0
	}
	yes, ok := c.ask("Stop and remove the dashboard service?", true)
	switch {
	case !ok:
		fmt.Fprintln(c.errw, "watchdeck service: no terminal to confirm on; nothing was changed. Rerun in a terminal, or with --yes.")
		return 1
	case !yes:
		fmt.Fprintln(c.out, "nothing changed")
		return 1
	}
	if _, err := service.Uninstall(o); err != nil {
		fmt.Fprintln(c.errw, "watchdeck service:", err)
		return 1
	}
	fmt.Fprintf(c.out, "removed; the log %s is kept (delete it by hand if you like)\n", displayHome(o.Log(), o.Paths.Home))
	return 0
}

func serviceStatus(stdout, stderr io.Writer, o service.Options) int {
	st, err := service.Status(o)
	if err != nil && !errors.Is(err, service.ErrNoRunner) {
		fmt.Fprintln(stderr, "watchdeck service:", err)
		return 2
	}
	switch {
	case !st.Installed:
		fmt.Fprintf(stdout, "not installed (%s absent)\n", displayHome(st.File, o.Paths.Home))
	case st.Loaded:
		fmt.Fprintf(stdout, "installed and loaded (%s)%s\n", displayHome(st.File, o.Paths.Home), detail(st.Detail))
	default:
		fmt.Fprintf(stdout, "installed but not loaded (%s)%s\n", displayHome(st.File, o.Paths.Home), detail(st.Detail))
	}
	if inst, err := uistate.Running(context.Background(), o.Paths); err == nil {
		fmt.Fprintf(stdout, "dashboard: running, pid %d, %s mode, %s\n", inst.State.PID, inst.Status.Mode, uistate.BaseURL(inst.State.Port))
	} else {
		fmt.Fprintln(stdout, "dashboard: not running")
	}
	return 0
}

func detail(s string) string {
	if s == "" {
		return ""
	}
	return ": " + s
}
