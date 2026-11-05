// Command watchdeck: every Claude Code session as a live map; turn a denial into a rule in one click.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
)

// version is set at build time via -ldflags "-X main.version=...".
var version = "dev"

// usage documents the six commands a person needs; advancedUsage
// (advanced.go) lists the rest, which are still accepted bare.
const usage = `usage: watchdeck [command] [args]

  watchdeck  open the dashboard in your browser (127.0.0.1 only), starting
             it in the background when it is not running; without a
             terminal it prints this help
  setup      first run: sandbox self-test, skill summary, recommended rules,
             the Claude Code settings watchdeck needs, dashboard autostart;
             asks before each write
  status     one screen: protection, live sessions, what needs you, the
             dashboard and the install checks (--json; exits 1 when a
             check fails)
  rules      list | explain | add | remove | set | shadow | recommended |
             reconcile | grant: every rule on this machine, strongest
             first, one place to add one (writes your Claude Code settings
             or the overrides file, with a backup), and a dry run of one
             call (explain)
  doctor     check the install, one line per check with the fix for each
             problem (--json; exits 1 when a check fails)
  uninstall  remove watchdeck in one confirmed step, with what it wrote to
             your Claude Code settings (--purge also deletes its config,
             state and cache; --dry-run)

More commands: watchdeck help advanced
`

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	// only bare "watchdeck" needs the terminal check; the hook skips the ioctl
	tty := len(args) == 0 && isTerminal(os.Stdout.Fd())
	return runWith(args, os.Stdout, os.Stderr, tty)
}

// runWith dispatches one command line. tty says whether stdout is a
// terminal: bare "watchdeck" opens the dashboard there and prints the usage
// (exit 3) anywhere else. Commands that write to os.Stdout and os.Stderr
// themselves ignore stdout and stderr.
func runWith(args []string, stdout, stderr io.Writer, tty bool) int {
	if len(args) == 0 {
		if tty {
			return cmdUI([]string{"--ensure", "--open"}, stdout, stderr)
		}
		fmt.Fprint(stderr, usage)
		return 3
	}
	switch args[0] {
	case "help", "-h", "--help":
		// "help advanced" lists the rest; any other topic prints the usage
		// and exits 0, as before the advanced split
		if len(args) == 2 && args[1] == "advanced" {
			fmt.Fprint(stdout, advancedUsage)
		} else {
			fmt.Fprint(stdout, usage)
		}
		return 0
	case "advanced":
		return cmdAdvanced(args[1:], stdout, stderr)
	}
	if code, ok := dispatch(args[0], args[1:], stdout, stderr); ok {
		return code
	}
	fmt.Fprintf(stderr, "%s: unknown command %q\n\n%s", paths.BinaryName, args[0], usage)
	return 3
}

// dispatch runs the command named name, documented or advanced; ok is false
// when no command has that name. Keep it a switch: the binary is the hook
// and must stay init-free (no lookup map).
func dispatch(name string, args []string, stdout, stderr io.Writer) (code int, ok bool) {
	switch name {
	case "version":
		return cmdVersion(args, stdout, stderr), true
	case "--version", "-v":
		fmt.Fprintln(stdout, paths.BinaryName, version)
		return 0, true
	case "status":
		return cmdStatus(args, stdout, stderr), true
	case "enforce":
		return cmdEnforce(args), true
	case "audit":
		return cmdAudit(args), true
	case "init":
		return cmdInit(args), true
	case "validate":
		return cmdValidate(args), true
	case "run":
		return cmdRun(args), true
	case "hook":
		return cmdHook(args), true
	case "index":
		return cmdIndex(args), true
	case "sessions":
		return cmdSessions(args, stdout, stderr), true
	case "allow":
		return cmdAllow(args), true
	case "rules":
		return cmdRules(args, stdout, stderr), true
	case "inbox":
		return cmdInbox(args, stdout, stderr), true
	case "activity":
		return cmdActivity(args, stdout, stderr), true
	case "paths":
		return cmdPaths(args, stdout, stderr), true
	case "setup":
		return cmdSetup(args, stdout, stderr), true
	case "uninstall":
		return cmdUninstall(args, stdout, stderr), true
	case "doctor":
		return cmdDoctor(args, stdout, stderr), true
	case "demo":
		return cmdDemo(args, stdout, stderr), true
	case "ui":
		return cmdUI(args, stdout, stderr), true
	case "service":
		return cmdService(args, stdout, stderr), true
	case "policy":
		return cmdPolicy(args, stdout, stderr), true
	case "mcp":
		return cmdMCP(args, stdout, stderr), true
	}
	return 0, false
}
