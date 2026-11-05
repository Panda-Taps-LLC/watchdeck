package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/lifecycle"
	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
	"github.com/Panda-Taps-LLC/watchdeck/internal/policy"
	"github.com/Panda-Taps-LLC/watchdeck/internal/rulebook"
	"github.com/Panda-Taps-LLC/watchdeck/internal/settings"
	"github.com/Panda-Taps-LLC/watchdeck/internal/skills"
	"github.com/Panda-Taps-LLC/watchdeck/internal/uistate"
)

const statusUsage = `usage: watchdeck status [--json] [--plugin] [--exit-zero]

One screen: whether this machine is protected, how many Claude Code
sessions are live, how many items need you, whether the dashboard is
running, and the install checks (the same checks "watchdeck doctor" runs),
with one line per warning or failure.

Protected means the user settings carry everything watchdeck needs (with
the plugin: the sandbox exclusion; the plugin carries the rest). Partly
protected means some of it is there (with the plugin on: the plugin's checks
run but the sandbox exclusion is missing).

  --json       {"version","protection":"protected|partial|off","live","idle",
               "needs","needs_enabled","dashboard":{"running","port"},
               "doctor":{"ok","checks":[...]}}
  --plugin     treat the plugin as active (/watchdeck:status passes it)
  --exit-zero  exit 0 even when a check fails (for slash commands)

Exit codes: 0 no failed check, 1 at least one check failed, 3 usage.
`

// statusDashboardTimeout bounds the dashboard health check.
const statusDashboardTimeout = 2 * time.Second

type statusDashboard struct {
	Running bool `json:"running"`
	Port    int  `json:"port"`
}

// statusReport is "status --json".
type statusReport struct {
	Version      string          `json:"version"`
	Protection   string          `json:"protection"` // protected | partial | off
	Live         int             `json:"live"`
	Idle         int             `json:"idle"`
	Needs        int             `json:"needs"`
	NeedsEnabled bool            `json:"needs_enabled"`
	Dashboard    statusDashboard `json:"dashboard"`
	Doctor       doctorReport    `json:"doctor"`

	liveText, needsText string // the text lines' values
	shadow              bool   // shadow mode is on (text only: the JSON carries it in doctor.checks)
}

func cmdStatus(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, statusUsage) }
	asJSON := fs.Bool("json", false, "")
	plugin := fs.Bool("plugin", false, "")
	exitZero := fs.Bool("exit-zero", false, "")
	if err := fs.Parse(args); err != nil {
		return 3
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "%s status: unexpected argument %q\n", paths.BinaryName, fs.Arg(0))
		return 3
	}
	hp, _, err := hostPaths()
	if err != nil {
		fmt.Fprintf(stderr, "%s status: %v\n", paths.BinaryName, err)
		return 2
	}
	rep := buildStatus(hp, *plugin)
	if *asJSON {
		if code := writeJSON(stdout, stderr, rep); code != 0 {
			return code
		}
	} else {
		printStatus(stdout, rep)
	}
	if !rep.Doctor.OK && !*exitZero {
		return 1
	}
	return 0
}

func buildStatus(hp paths.Paths, forcePlugin bool) statusReport {
	rep := statusReport{Version: version}
	cwd, _ := os.Getwd()
	root := paths.ProjectRoot(cwd, hp.Home)

	// protection: the user settings file only
	pluginOn := forcePlugin
	if !pluginOn {
		proot := root
		if proot == "" {
			proot = cwd
		}
		if _, on, err := skills.PluginActive(hp.ClaudeDir, proot, paths.BinaryName); err == nil && on {
			pluginOn = true
		}
	}
	rep.Protection = "off"
	if st, err := settings.Inspect(hp.ClaudeSettings()); err == nil {
		switch {
		case st.Complete, pluginOn && st.Excluded:
			rep.Protection = "protected"
		case pluginOn || st.Count() > 0 || st.Excluded:
			// with the plugin on, its checks run even when the user
			// settings lack the sandbox exclusion
			rep.Protection = "partial"
		}
	} else if pluginOn {
		rep.Protection = "partial"
	}

	// live sessions
	ls := lifecycle.Store{Log: hp.Sessions, Live: hp.LiveDir}
	if ls.Off() {
		rep.liveText = "lifecycle off"
	} else if ss, err := ls.List(); err != nil {
		rep.liveText = fmt.Sprintf("unknown (%v)", err)
	} else {
		rep.Live, rep.Idle, _, _ = lifecycle.Counts(ss)
		rep.liveText = fmt.Sprintf("%d (idle %d)", rep.Live, rep.Idle)
	}

	// what needs you: the inbox's open items
	if hp.Activity == "" {
		rep.needsText = "activity log off"
	} else {
		rep.NeedsEnabled = true
		book, err := rulebook.List(rulebook.Input{Paths: hp, ProjectRoot: root})
		var items []rulebook.Item
		if err == nil {
			items, err = rulebook.Open(rulebook.InboxInput{Paths: hp, Book: &book})
		}
		if err != nil {
			rep.needsText = fmt.Sprintf("unknown (%v)", err)
		} else {
			rep.Needs = len(items)
			rep.needsText = fmt.Sprintf("%d  (%s inbox)", rep.Needs, paths.BinaryName)
		}
	}

	// dashboard: running means the lock is held and it answered a health check
	ctx, cancel := context.WithTimeout(context.Background(), statusDashboardTimeout)
	defer cancel()
	if inst, err := uistate.Running(ctx, hp); err == nil {
		rep.Dashboard = statusDashboard{Running: true, Port: inst.State.Port}
	}

	rep.shadow, _ = policy.ShadowOn(hp.OverridesFile()) // an error reads as off; doctor warns
	rep.Doctor = runDoctor(forcePlugin)
	return rep
}

func printStatus(w io.Writer, rep statusReport) {
	prot := "Not protected"
	switch rep.Protection {
	case "protected":
		prot = "Protected"
	case "partial":
		prot = "Partly protected"
	}
	if rep.shadow && rep.Protection == "protected" {
		prot += " · Observing only"
	}
	fmt.Fprintf(w, "%s %s · %s\n", paths.BinaryName, rep.Version, prot)
	fmt.Fprintf(w, "Live sessions: %s\n", rep.liveText)
	fmt.Fprintf(w, "Needs you: %s\n", rep.needsText)
	if rep.Dashboard.Running {
		fmt.Fprintf(w, "Dashboard: running at http://127.0.0.1:%d\n", rep.Dashboard.Port)
	} else {
		fmt.Fprintf(w, "Dashboard: not running (run %s)\n", paths.BinaryName)
	}
	var pass, warn, fail int
	for _, c := range rep.Doctor.Checks {
		switch c.Status {
		case statusPass:
			pass++
		case statusWarn:
			warn++
		default:
			fail++
		}
	}
	fmt.Fprintf(w, "Checks: %d passed, %d warnings, %d failed  (%s doctor)\n", pass, warn, fail, paths.BinaryName)
	for _, c := range rep.Doctor.Checks {
		if c.Status != statusPass {
			fmt.Fprintf(w, "  %s %s: %s\n", c.Status, c.Name, c.Message)
		}
	}
}
