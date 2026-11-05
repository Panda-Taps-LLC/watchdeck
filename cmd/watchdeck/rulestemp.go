package main

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
	"github.com/Panda-Taps-LLC/watchdeck/internal/rulebook"
)

// Temporary allows on the command line (Plan 08): rules pause, rules
// resume and allow --for. Each writes the user policy file through
// rulebook after a confirm (--yes without a terminal), backup first.

// rulesPause is rules pause <row-id>... --for 1h|8h|session=<id> [--yes],
// or rules pause --list (read-only: the temporaries in force).
func rulesPause(args []string, stdout, stderr io.Writer) int {
	var ids []string
	forSpec, list, yes, haveFor := "", false, false, false
	for i := 0; i < len(args); i++ {
		switch a := args[i]; {
		case a == "--list":
			list = true
		case a == "--yes":
			yes = true
		case a == "--for":
			if i+1 >= len(args) {
				return rulesUsageErr(stderr, "pause: --for takes %s", rulebook.ForSpecs)
			}
			forSpec, haveFor = args[i+1], true
			i++
		case strings.HasPrefix(a, "--for="):
			forSpec, haveFor = strings.TrimPrefix(a, "--for="), true
		case strings.HasPrefix(a, "-"):
			return rulesUsageErr(stderr, "unknown flag %q", a)
		default:
			ids = append(ids, a)
		}
	}
	in, err := rulesInput()
	if err != nil {
		return rulesErr(stderr, err)
	}
	if list {
		if len(args) != 1 {
			return rulesUsageErr(stderr, "pause --list takes nothing else")
		}
		views := rulebook.ListTemporaries(in)
		if len(views) == 0 {
			fmt.Fprintln(stdout, "no temporaries: no rule is paused and no grant is widened for a while")
			return 0
		}
		for _, v := range views {
			line := v.ID + "  " + v.Sentence + "  until " + localTime(v.Until)
			if v.Session != "" {
				line += "  session " + v.Session
			}
			fmt.Fprintln(stdout, line)
		}
		return 0
	}
	if len(ids) == 0 || !haveFor {
		return rulesUsageErr(stderr, "pause takes one or more rule ids and --for %s", rulebook.ForSpecs)
	}
	switch {
	case forSpec == "1h", forSpec == "8h", strings.HasPrefix(forSpec, "session="):
	default:
		return rulesUsageErr(stderr, "pause: --for takes %s", rulebook.ForSpecs)
	}
	for _, id := range ids {
		fmt.Fprintf(stdout, "Pause %s for %s: it records what it matches and blocks or asks nothing until then.\n", id, forWords(forSpec))
	}
	c := newConsole(stdout, stderr, yes)
	ok, answered := c.ask("Apply? (a .bak-<ts> backup is written first)", true)
	if !answered {
		fmt.Fprintln(stdout, "Not applied: no terminal to confirm; rerun with --yes.")
		return 1
	}
	if !ok {
		fmt.Fprintln(stdout, "Not applied.")
		return 1
	}
	temps, err := rulebook.Pause(in, ids, forSpec)
	if err != nil {
		return rulesErr(stderr, err)
	}
	for _, t := range temps {
		row, _ := rulebook.PauseRowID(t.Rule)
		fmt.Fprintf(stdout, "paused %s until %s (%s; end it early with: %s rules resume %s)\n", row, localTime(t.Until.Format(time.RFC3339)), t.ID, paths.BinaryName, t.ID)
	}
	return 0
}

// forWords is a --for spelling as words.
func forWords(spec string) string {
	switch spec {
	case "1h":
		return "an hour"
	case "8h":
		return "eight hours"
	}
	return "session " + strings.TrimPrefix(spec, "session=") + " (eight hours at most)"
}

// localTime shows an RFC 3339 time in the local zone, to the minute.
func localTime(s string) string {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return s
	}
	return t.Local().Format("2006-01-02 15:04")
}

// rulesResume is rules resume <id|all> [--yes]: the temporary ends now.
func rulesResume(args []string, stdout, stderr io.Writer) int {
	set, pos, bad := rulesFlags(args, "--yes")
	if bad != "" {
		return rulesUsageErr(stderr, "unknown flag %q", bad)
	}
	if len(pos) != 1 {
		return rulesUsageErr(stderr, "resume takes one temporary id (see %s rules pause --list) or all", paths.BinaryName)
	}
	id := pos[0]
	in, err := rulesInput()
	if err != nil {
		return rulesErr(stderr, err)
	}
	if id == "all" {
		fmt.Fprintln(stdout, "End every temporary now: paused rules block and ask again, timed grants end.")
	} else {
		fmt.Fprintf(stdout, "End %s now.\n", id)
	}
	c := newConsole(stdout, stderr, set["--yes"])
	ok, answered := c.ask("Apply? (a .bak-<ts> backup is written first)", true)
	if !answered {
		fmt.Fprintln(stdout, "Not applied: no terminal to confirm; rerun with --yes.")
		return 1
	}
	if !ok {
		fmt.Fprintln(stdout, "Not applied.")
		return 1
	}
	if err := rulebook.End(in, id); err != nil {
		if errors.Is(err, rulebook.ErrNoTemporary) {
			return rulesErr(stderr, fmt.Errorf("no temporary %q (see %s rules pause --list)", id, paths.BinaryName))
		}
		return rulesErr(stderr, err)
	}
	fmt.Fprintf(stdout, "resumed %s\n", id)
	return 0
}
