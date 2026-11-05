package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Panda-Taps-LLC/watchdeck/internal/claudesettings"
	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
	"github.com/Panda-Taps-LLC/watchdeck/internal/policy"
	"github.com/Panda-Taps-LLC/watchdeck/internal/rulebook"
)

const rulesUsage = `usage: ` + paths.BinaryName + ` rules <list | explain | add | remove | set | shadow | pause | resume | recommended | reconcile | grant> [args]

  list [--json] [--project]
      every rule on this machine, strongest first: sandbox, blocked, auto
      mode, ` + paths.BinaryName + ` rules, ask first or allowed. One line per rule:
      <state>  <id>  <sentence>  (<enforced by>, <owner>, <scope>).
      --project shows the project's rules only; --json prints the whole list.
  explain WHAT [--cwd DIR] [--mode MODE] [--expect allow|ask|deny] [--json]
      a dry run: what the hook would answer for one call, and by which
      rule, recording nothing. WHAT is one of --command CMD, --read PATH,
      --edit PATH, --path PATH (a write), --url URL, --mcp TOOL (as
      Claude Code names it, mcp__server__tool) or --skill NAME. --cwd is
      the session's working directory (default: here), --mode its
      permission mode (default, acceptEdits, auto, bypassPermissions,
      dontAsk, plan). Exit 0 allow or no opinion, 1 deny, 2 ask, 3 usage,
      4 a policy file could not be loaded; with --expect, 0 when the
      verdict matches and 1 when it does not.
  add (--block | --ask) WHAT [--project] [--twin] [--everywhere] [--yes]
      WHAT is one of --read PATH, --edit PATH, --path PATH (read and edit),
      --domain HOST, --mcp TOOL, --command PREFIX, --regex RE, --text TEXT.
      Prints the plan, asks, then writes your Claude Code settings (user
      scope; --project for the project's .claude/settings.json) or the
      overrides file, with a .bak-<ts> backup first. --twin also adds the
      hook rule a command block suggests. --everywhere covers every route
      to a path, domain or command as one rule: a path also for the search
      tools and for shell commands that name it (an absolute or ~/ path,
      or --project for a relative one); a domain also in the sandbox's
      denied domains, for web fetches and for network programs that name
      it; a command also as its hook twin. Skill scripts are not covered.
      Without a terminal and without --yes it prints the plan and exits 1.
  remove <id> [--yes]
      remove one rule ` + paths.BinaryName + ` added (a native string it does not own is
      refused, exit 2), turn a built-in pack rule off, or delete a policy rule.
      A rule added with --everywhere is removed on its own; the rest stay.
  remove --intent <intent id> [--yes]
      remove every rule added together with --everywhere (the plan prints
      the intent id; rules list --json shows it on each rule).
  set <id> on|off [--yes]
      switch a built-in ` + paths.BinaryName + ` rule (pack:<pack>/<id>) on or off in
      the overrides file, keeping its action; any other rule is refused.
  shadow [on|off] [--yes]
      shadow mode: ` + paths.BinaryName + `'s own rules (built-in packs, your rules,
      path, domain, MCP and agent rules) are recorded with what they
      would have done (would: deny or ask) but never block or ask.
      Claude Code's own rules and the sandbox are unaffected. Alone it
      prints "shadow mode: on|off"; on and off write the overrides file
      after a confirm, with a .bak-<ts> backup first.
  pause <id>... --for 1h|8h|session=<id> [--yes]
      pause built-in ` + paths.BinaryName + ` rules (pack:<pack>/<id>) or your own
      rules (user:<id>) for an hour, eight hours, or one session (eight
      hours at most): a paused rule records what it matches and blocks or
      asks nothing. Claude Code's own rules cannot be paused. Writes the
      overrides file after a confirm; the pause ends by itself.
  pause --list
      the pauses and timed grants in force, with their ids.
  resume <id|all> [--yes]
      end a pause or a timed grant now.
  recommended [--install [--all]] [--decline ID...] [--undecline ID...] [--yes]
      the twelve recommended native rules: installed, missing or declined.
      --install adds the missing ones not declined in one step (--all adds
      the declined ones too). --decline stops offering rules (setup and
      --install skip them); --undecline offers them again. Each takes row
      ids as the listing prints them, or the word all.
  reconcile
      forget the rules ` + paths.BinaryName + ` added that you have since removed from
      your settings by hand; a recommended one is also declined, so it is
      not offered again. Prints what it forgot.
  grant <skill> [allow flags]
      widen or revoke a skill's sandbox grant (the same as ` + paths.BinaryName + ` allow;
      --for 1h widens it for a while only).

Exit 0 ok, 1 declined or not confirmed, 2 error, 3 usage.
`

// cmdRules is `watchdeck rules`.
func cmdRules(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, rulesUsage)
		return 3
	}
	switch args[0] {
	case "-h", "--help", "help":
		fmt.Fprint(stdout, rulesUsage)
		return 0
	case "list":
		return rulesList(args[1:], stdout, stderr)
	case "explain":
		return cmdRulesExplain(args[1:], stdout, stderr)
	case "add":
		return rulesAdd(args[1:], stdout, stderr)
	case "remove":
		return rulesRemove(args[1:], stdout, stderr)
	case "set":
		return rulesSet(args[1:], stdout, stderr)
	case "shadow":
		return rulesShadow(args[1:], stdout, stderr)
	case "pause":
		return rulesPause(args[1:], stdout, stderr)
	case "resume":
		return rulesResume(args[1:], stdout, stderr)
	case "recommended":
		return rulesRecommended(args[1:], stdout, stderr)
	case "reconcile":
		return rulesReconcile(args[1:], stdout, stderr)
	case "grant":
		return cmdAllow(args[1:])
	}
	fmt.Fprintf(stderr, "%s rules: unknown subcommand %q\n\n%s", paths.BinaryName, args[0], rulesUsage)
	return 3
}

// rulesInput is the rulebook input for this machine and the git root of
// the working directory ("" when there is none).
func rulesInput() (rulebook.Input, error) {
	hp, _, err := hostPaths()
	if err != nil {
		return rulebook.Input{}, err
	}
	cwd, _ := os.Getwd()
	return rulebook.Input{Paths: hp, ProjectRoot: paths.ProjectRoot(cwd, hp.Home)}, nil
}

// rulesFlags parses boolean flags by hand: each arg must be one of names.
// It returns the set flags and the positional args, or ok false naming the
// first unknown flag.
func rulesFlags(args []string, names ...string) (set map[string]bool, pos []string, bad string) {
	set = map[string]bool{}
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			known := false
			for _, n := range names {
				if a == n {
					known = true
				}
			}
			if !known {
				return nil, nil, a
			}
			set[a] = true
			continue
		}
		pos = append(pos, a)
	}
	return set, pos, ""
}

func rulesUsageErr(stderr io.Writer, format string, a ...any) int {
	fmt.Fprintf(stderr, paths.BinaryName+" rules: "+format+"\n\n%s", append(a, rulesUsage)...)
	return 3
}

func rulesErr(stderr io.Writer, err error) int {
	fmt.Fprintf(stderr, "%s rules: %v\n", paths.BinaryName, err)
	return 2
}

func rulesList(args []string, stdout, stderr io.Writer) int {
	set, pos, bad := rulesFlags(args, "--json", "--project")
	if bad != "" {
		return rulesUsageErr(stderr, "unknown flag %q", bad)
	}
	if len(pos) > 0 {
		return rulesUsageErr(stderr, "list takes no arguments")
	}
	in, err := rulesInput()
	if err != nil {
		return rulesErr(stderr, err)
	}
	if set["--project"] && in.ProjectRoot == "" {
		return rulesErr(stderr, errors.New("--project: no project here (no .git above the working directory)"))
	}
	book, err := rulebook.List(in)
	if err != nil {
		return rulesErr(stderr, err)
	}
	if set["--project"] {
		for i := range book.Groups {
			var rows []rulebook.Rule
			for _, r := range book.Groups[i].Rows {
				if r.Scope == claudesettings.ScopeProject || r.Owner == rulebook.OwnerProject {
					rows = append(rows, r)
				}
			}
			book.Groups[i].Rows = append([]rulebook.Rule{}, rows...)
		}
	}
	if set["--json"] {
		return writeJSON(stdout, stderr, book)
	}
	home := in.Paths.Home
	for _, w := range book.Warnings {
		fmt.Fprintln(stdout, "warning:", w)
	}
	for _, g := range book.Groups {
		fmt.Fprintf(stdout, "%s (%d)\n", g.Title, len(g.Rows))
		for _, r := range g.Rows {
			fmt.Fprintf(stdout, "  %-7s  %s  %s  (%s, %s, %s)\n", r.State, r.ID, r.Sentence, r.Enforcement, r.Owner, orDash(string(r.Scope)))
		}
	}
	if n := len(book.Recommended); n > 0 {
		fmt.Fprintf(stdout, "Recommended, not installed: %d (%s rules recommended --install)\n", n, paths.BinaryName)
	}
	for _, d := range book.Drift {
		fmt.Fprintf(stdout, "drift: %s in %s %s: %s\n", d.Entry.Value, displayHome(d.Entry.Path, home), d.Entry.Key, d.Reason)
	}
	return 0
}

// addWhat maps a rules add flag to the request it fills.
func addWhat(flag string) (rulebook.What, string, bool) {
	switch flag {
	case "--read":
		return rulebook.WhatPath, rulebook.PathRead, true
	case "--edit":
		return rulebook.WhatPath, rulebook.PathEdit, true
	case "--path":
		return rulebook.WhatPath, rulebook.PathBoth, true
	case "--domain":
		return rulebook.WhatHost, "", true
	case "--mcp":
		return rulebook.WhatMCP, "", true
	case "--command":
		return rulebook.WhatCommand, "", true
	case "--regex":
		return rulebook.WhatRegex, "", true
	case "--text":
		return rulebook.WhatText, "", true
	}
	return "", "", false
}

// addFlag is the rules add spelling of a request (the inverse of addWhat).
func addFlag(r rulebook.AddRequest) string {
	switch r.What {
	case rulebook.WhatPath:
		switch r.Tool {
		case rulebook.PathRead:
			return "--read"
		case rulebook.PathEdit:
			return "--edit"
		}
		return "--path"
	case rulebook.WhatHost:
		return "--domain"
	case rulebook.WhatMCP:
		return "--mcp"
	case rulebook.WhatCommand:
		return "--command"
	case rulebook.WhatRegex:
		return "--regex"
	case rulebook.WhatText:
		return "--text"
	}
	return ""
}

// addLine is the rules add command line for a request, or "" when it has
// no spelling.
func addLine(r rulebook.AddRequest) string {
	f := addFlag(r)
	if f == "" {
		return ""
	}
	act := "--block"
	if r.Action == "ask" {
		act = "--ask"
	}
	line := paths.BinaryName + " rules add " + act + " " + f + " " + shellQuote(r.Value)
	if r.Scope == claudesettings.ScopeProject {
		line += " --project"
	}
	return line
}

// shellQuote quotes s for a POSIX shell when it needs it (a leading ~
// is quoted too, so the shell does not expand it).
func shellQuote(s string) string {
	safe := s != ""
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-_./:@%+=,", c)) {
			safe = false
			break
		}
	}
	if safe {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func rulesAdd(args []string, stdout, stderr io.Writer) int {
	var req rulebook.AddRequest
	var yes, twin, project bool
	whats := 0
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch a {
		case "--block", "--ask":
			if req.Action != "" {
				return rulesUsageErr(stderr, "add takes one of --block or --ask")
			}
			req.Action = "deny"
			if a == "--ask" {
				req.Action = "ask"
			}
			continue
		case "--yes":
			yes = true
			continue
		case "--twin":
			twin = true
			continue
		case "--everywhere":
			req.Everywhere = true
			continue
		case "--project":
			project = true
			continue
		}
		what, tool, ok := addWhat(a)
		if !ok {
			return rulesUsageErr(stderr, "add: unknown argument %q", a)
		}
		if i+1 >= len(args) {
			return rulesUsageErr(stderr, "add: %s needs a value", a)
		}
		whats++
		i++
		req.What, req.Tool, req.Value = what, tool, args[i]
	}
	if req.Action == "" {
		return rulesUsageErr(stderr, "add needs --block or --ask")
	}
	if whats != 1 {
		return rulesUsageErr(stderr, "add needs exactly one of --read, --edit, --path, --domain, --mcp, --command, --regex, --text")
	}
	if req.What == rulebook.WhatRegex || req.What == rulebook.WhatText {
		req.Tool = "Bash"
	}
	req.Twin = twin
	in, err := rulesInput()
	if err != nil {
		return rulesErr(stderr, err)
	}
	if project {
		req.Scope = claudesettings.ScopeProject
	}
	plan, err := rulebook.Propose(in, req)
	if err != nil {
		return rulesErr(stderr, err)
	}
	return applyPlan(in, plan, yes, stdout, stderr, "rules", nil)
}

// printRulePlan prints a plan's steps and its suggested twin.
func printRulePlan(w io.Writer, home string, plan rulebook.Plan) {
	fmt.Fprintln(w, "Plan:")
	for _, s := range plan.Steps {
		fmt.Fprintf(w, "  %-7s  %s  %s  %s\n", s.Mechanism, displayHome(s.File, home), s.Key, s.Value)
		fmt.Fprintf(w, "           %s\n", s.Sentence)
	}
	if plan.Suggested != nil {
		fmt.Fprintf(w, "Suggested: --twin also adds the hook rule for the %s %q (user policy file).\n", plan.Suggested.What, plan.Suggested.Value)
	}
	if len(plan.Steps) > 0 && strings.HasPrefix(plan.Steps[0].IntentID, "intent:") {
		id := plan.Steps[0].IntentID
		fmt.Fprintf(w, "These rules are one intent, %s; remove them together with %s rules remove --intent %s\n", id, paths.BinaryName, id)
	}
}

// printResult prints the files written, their backups and the row ids.
// "nothing changed" is said only when applyErr is nil: a failed apply that
// wrote nothing did not find every rule already there.
func printResult(w io.Writer, home string, res rulebook.Result, applyErr error) {
	for _, f := range res.Written {
		fmt.Fprintln(w, "wrote", displayHome(f, home))
	}
	for _, b := range res.Backups {
		fmt.Fprintln(w, "backup", displayHome(b, home))
	}
	if len(res.Written) == 0 && applyErr == nil {
		fmt.Fprintln(w, "nothing changed: every rule was already there")
	}
	if len(res.RowIDs) > 0 {
		fmt.Fprintln(w, "rule ids:", strings.Join(res.RowIDs, " "))
	}
}

// applyPlan prints plan, asks, applies it and prints the result. after,
// when set, runs once the plan is written (its exit code is returned).
func applyPlan(in rulebook.Input, plan rulebook.Plan, yes bool, stdout, stderr io.Writer, cmd string, after func(rulebook.Result) int) int {
	home := in.Paths.Home
	printRulePlan(stdout, home, plan)
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
	res, err := rulebook.Apply(in, plan)
	printResult(stdout, home, res, err)
	if err != nil {
		fmt.Fprintf(stderr, "%s %s: %v\n", paths.BinaryName, cmd, err)
		return 2
	}
	if w := rulebook.SearchWatchWarning(in, plan); w != "" {
		fmt.Fprintln(stdout, "Note:", w)
	}
	if after != nil {
		return after(res)
	}
	return 0
}

// findRule returns the row with id in book.
func findRule(book rulebook.Book, id string) (rulebook.Rule, bool) {
	for _, g := range book.Groups {
		for _, r := range g.Rows {
			if r.ID == id {
				return r, true
			}
		}
	}
	return rulebook.Rule{}, false
}

func rulesRemove(args []string, stdout, stderr io.Writer) int {
	for i, a := range args {
		if a != "--intent" {
			continue
		}
		if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
			return rulesUsageErr(stderr, "remove --intent needs an intent id")
		}
		rest := append(append([]string{}, args[:i]...), args[i+2:]...)
		set, pos, bad := rulesFlags(rest, "--yes")
		if bad != "" {
			return rulesUsageErr(stderr, "unknown flag %q", bad)
		}
		if len(pos) != 0 {
			return rulesUsageErr(stderr, "remove --intent takes no rule id")
		}
		return rulesRemoveIntent(args[i+1], set["--yes"], stdout, stderr)
	}
	set, pos, bad := rulesFlags(args, "--yes")
	if bad != "" {
		return rulesUsageErr(stderr, "unknown flag %q", bad)
	}
	if len(pos) != 1 {
		return rulesUsageErr(stderr, "remove takes one rule id")
	}
	id := pos[0]
	in, err := rulesInput()
	if err != nil {
		return rulesErr(stderr, err)
	}
	book, err := rulebook.List(in)
	if err != nil {
		return rulesErr(stderr, err)
	}
	r, found := findRule(book, id)
	if !found {
		return rulesErr(stderr, fmt.Errorf("no rule %q (see %s rules list)", id, paths.BinaryName))
	}
	native := r.Kind == rulebook.KindNativeDeny || r.Kind == rulebook.KindNativeAsk || r.Kind == rulebook.KindNativeAllow
	if native && r.Owner != rulebook.OwnerUs {
		return rulesErr(stderr, fmt.Errorf("%w: %s is %s's; edit %s by hand", rulebook.ErrNotOwned, r.Value, r.Owner, displayHome(r.Source.File, in.Paths.Home)))
	}
	fmt.Fprintf(stdout, "Remove: %s  %s  (%s, %s, %s)\n", r.ID, r.Sentence, r.Enforcement, r.Owner, orDash(string(r.Scope)))
	c := newConsole(stdout, stderr, set["--yes"])
	ok, answered := c.ask("Remove? (a .bak-<ts> backup is written first)", true)
	if !answered {
		fmt.Fprintln(stdout, "Not removed: no terminal to confirm; rerun with --yes.")
		return 1
	}
	if !ok {
		fmt.Fprintln(stdout, "Not removed.")
		return 1
	}
	// A built-in pack rule cannot be deleted, only switched off: rules
	// remove keeps doing that (rulebook.Remove on a pack row clears its
	// override instead).
	remove := rulebook.Remove
	if r.Kind == rulebook.KindPack {
		remove = func(in rulebook.Input, id string) (rulebook.Result, error) { return rulebook.SetEnabled(in, id, false) }
	}
	res, err := remove(in, id)
	for _, f := range res.Written {
		fmt.Fprintln(stdout, "wrote", displayHome(f, in.Paths.Home))
	}
	for _, b := range res.Backups {
		fmt.Fprintln(stdout, "backup", displayHome(b, in.Paths.Home))
	}
	if err != nil {
		return rulesErr(stderr, err)
	}
	if r.Kind == rulebook.KindPack {
		fmt.Fprintln(stdout, "switched off", id)
	} else {
		fmt.Fprintln(stdout, "removed", id)
	}
	return 0
}

// rulesRemoveIntent is rules remove --intent: it lists every rule of the
// intent, asks, and removes them together.
func rulesRemoveIntent(id string, yes bool, stdout, stderr io.Writer) int {
	in, err := rulesInput()
	if err != nil {
		return rulesErr(stderr, err)
	}
	book, err := rulebook.List(in)
	if err != nil {
		return rulesErr(stderr, err)
	}
	var rows []rulebook.Rule
	for _, g := range book.Groups {
		for _, r := range g.Rows {
			if r.Intent != nil && r.Intent.ID == id {
				rows = append(rows, r)
			}
		}
	}
	if len(rows) == 0 {
		return rulesErr(stderr, fmt.Errorf("no rule belongs to %q (see %s rules list --json)", id, paths.BinaryName))
	}
	fmt.Fprintf(stdout, "Remove every rule of: %s\n", rows[0].Intent.Sentence)
	for _, r := range rows {
		fmt.Fprintf(stdout, "  %s  %s  (%s, %s)\n", r.ID, r.Sentence, r.Enforcement, orDash(string(r.Scope)))
	}
	c := newConsole(stdout, stderr, yes)
	ok, answered := c.ask(fmt.Sprintf("Remove all %d? (a .bak-<ts> backup is written first)", len(rows)), true)
	if !answered {
		fmt.Fprintln(stdout, "Not removed: no terminal to confirm; rerun with --yes.")
		return 1
	}
	if !ok {
		fmt.Fprintln(stdout, "Not removed.")
		return 1
	}
	res, err := rulebook.RemoveIntent(in, id)
	for _, f := range res.Written {
		fmt.Fprintln(stdout, "wrote", displayHome(f, in.Paths.Home))
	}
	for _, b := range res.Backups {
		fmt.Fprintln(stdout, "backup", displayHome(b, in.Paths.Home))
	}
	for _, r := range res.RowIDs {
		fmt.Fprintln(stdout, "removed", r)
	}
	if err != nil {
		return rulesErr(stderr, err)
	}
	return 0
}

func rulesRecommended(args []string, stdout, stderr io.Writer) int {
	var install, all, yes bool
	var ids []string
	mode := "" // the last of --decline or --undecline: the ids after it are its
	for _, a := range args {
		switch a {
		case "--install":
			install = true
		case "--all":
			all = true
		case "--yes":
			yes = true
		case "--decline", "--undecline":
			if mode != "" && mode != a {
				return rulesUsageErr(stderr, "recommended takes one of --decline or --undecline")
			}
			mode = a
		default:
			if strings.HasPrefix(a, "-") {
				return rulesUsageErr(stderr, "unknown flag %q", a)
			}
			if mode == "" {
				return rulesUsageErr(stderr, "recommended: %q: ids follow --decline or --undecline", a)
			}
			ids = append(ids, a)
		}
	}
	switch {
	case mode != "" && len(ids) == 0:
		return rulesUsageErr(stderr, "%s needs a row id (as the listing prints it) or all", mode)
	case mode != "" && install:
		return rulesUsageErr(stderr, "%s does not go with --install", mode)
	case all && !install:
		return rulesUsageErr(stderr, "--all goes with --install")
	}
	in, err := rulesInput()
	if err != nil {
		return rulesErr(stderr, err)
	}
	if install && mode == "" {
		reconcileBeforeInstall(stderr, "", in)
	}
	book, err := rulebook.List(in)
	if err != nil {
		return rulesErr(stderr, err)
	}
	missing := map[string]rulebook.Rule{}
	for _, r := range book.Recommended {
		missing[r.ID] = r
	}
	if mode != "" {
		return rulesDecline(in, missing, ids, mode == "--decline", stdout, stderr)
	}
	if !install {
		nMissing, nDeclined := 0, 0
		for _, r := range rulebook.Recommended() {
			state := "installed"
			if m, ok := missing[r.ID]; ok {
				state = "missing"
				nMissing++
				if m.Declined {
					state = "declined"
					nMissing--
					nDeclined++
				}
			}
			fmt.Fprintf(stdout, "  %-9s  %s  %s  (%s)\n", state, r.ID, r.Sentence, r.Value)
		}
		if nMissing > 0 {
			fmt.Fprintf(stdout, "%d not installed: %s rules recommended --install adds them.\n", nMissing, paths.BinaryName)
		}
		if nDeclined > 0 {
			fmt.Fprintf(stdout, "%d declined: %s rules recommended --install --all adds them anyway; --undecline all offers them again.\n", nDeclined, paths.BinaryName)
		}
		return 0
	}
	if len(book.Recommended) == 0 {
		fmt.Fprintln(stdout, "nothing to do: every recommended rule is installed")
		return 0
	}
	warnDeclined(stderr, "", in.Paths.StateDir, all)
	offer := rulebook.RecommendedOffer(in, book.Recommended, all)
	if len(offer) == 0 {
		fmt.Fprintf(stdout, "nothing to do: every missing recommended rule was declined (%s rules recommended --install --all adds them anyway)\n", paths.BinaryName)
		return 0
	}
	if n := len(book.Recommended) - len(offer); n > 0 {
		fmt.Fprintf(stdout, "skipping %d declined recommended rule%s (--all adds them too)\n", n, plural(n))
	}
	plan, err := recommendedPlan(in, offer)
	if err != nil {
		return rulesErr(stderr, err)
	}
	return applyPlan(in, plan, yes, stdout, stderr, "rules recommended", nil)
}

// recommendedRow finds a recommended rule by the row id the listing prints
// (or by its ledger intent id).
func recommendedRow(rec []rulebook.Rule, id string) (rulebook.Rule, bool) {
	for _, r := range rec {
		if r.ID == id || recommendedIntent(r) == id {
			return r, true
		}
	}
	return rulebook.Rule{}, false
}

// recommendedIntent is a recommended rule's ledger intent id, the id the
// declined list holds.
func recommendedIntent(r rulebook.Rule) string {
	return rulebook.IntentPrefix + rulebook.IntentID(r.Value)
}

// recommendedRowID is the row id for a declined intent id, or the intent
// id itself when no recommended rule has it.
func recommendedRowID(intent string) string {
	if r, ok := recommendedRow(rulebook.Recommended(), intent); ok {
		return r.ID
	}
	return intent
}

// rulesDecline is rules recommended --decline / --undecline: ids are row
// ids or "all" (for --decline every recommended rule not installed, for
// --undecline every declined one). It prints one line per rule whose state
// changed, or "nothing to change". Declining only edits watchdeck's own
// declined list (no settings file), so it asks nothing.
func rulesDecline(in rulebook.Input, missing map[string]rulebook.Rule, ids []string, decline bool, stdout, stderr io.Writer) int {
	rec := rulebook.Recommended()
	var targets []rulebook.Rule
	add := func(r rulebook.Rule) {
		for _, t := range targets {
			if t.ID == r.ID {
				return
			}
		}
		targets = append(targets, r)
	}
	for _, id := range ids {
		if id == "all" {
			for _, r := range rec {
				if _, notInstalled := missing[r.ID]; decline && !notInstalled {
					continue
				}
				add(r)
			}
			continue
		}
		r, ok := recommendedRow(rec, id)
		if !ok {
			return rulesErr(stderr, fmt.Errorf("no recommended rule %q (see %s rules recommended)", id, paths.BinaryName))
		}
		add(r)
	}
	d, derr := rulebook.LoadDeclined(in.Paths.StateDir)
	if derr != nil {
		// Declining replaces a file that cannot be read (the person's
		// explicit decline wins); undeclining leaves it as it is.
		fmt.Fprintln(stderr, "warning:", derr)
	}
	var changed []rulebook.Rule
	var intents []string
	for _, r := range targets {
		if d.Has(recommendedIntent(r)) != decline {
			changed = append(changed, r)
			intents = append(intents, recommendedIntent(r))
		}
	}
	if len(changed) == 0 {
		fmt.Fprintln(stdout, "nothing to change")
		return 0
	}
	edit, verb := rulebook.Undecline, "undeclined"
	if decline {
		edit, verb = rulebook.Decline, "declined"
	}
	if err := edit(in.Paths.StateDir, intents); err != nil {
		return rulesErr(stderr, err)
	}
	if derr != nil && decline {
		fmt.Fprintln(stdout, "replaced the unreadable declined list")
	}
	for _, r := range changed {
		fmt.Fprintf(stdout, "%s %s\n", verb, r.ID)
	}
	return 0
}

// rulesSet is rules set <id> on|off: a built-in pack rule switched on or
// off (rulebook.SetEnabled); any other row is refused before the question,
// and nothing is written.
func rulesSet(args []string, stdout, stderr io.Writer) int {
	set, pos, bad := rulesFlags(args, "--yes")
	if bad != "" {
		return rulesUsageErr(stderr, "unknown flag %q", bad)
	}
	if len(pos) != 2 {
		return rulesUsageErr(stderr, "set takes a rule id and on or off")
	}
	id, state := pos[0], pos[1]
	if state != "on" && state != "off" {
		return rulesUsageErr(stderr, "set: %q is not on or off", state)
	}
	on := state == "on"
	in, err := rulesInput()
	if err != nil {
		return rulesErr(stderr, err)
	}
	book, err := rulebook.List(in)
	if err != nil {
		return rulesErr(stderr, err)
	}
	r, found := findRule(book, id)
	if !found {
		return rulesErr(stderr, fmt.Errorf("no rule %q (see %s rules list)", id, paths.BinaryName))
	}
	if r.Kind != rulebook.KindPack || !strings.HasPrefix(id, "pack:") {
		// refused before any question; the writer is never called for it
		return rulesErr(stderr, fmt.Errorf("%s is not a built-in %s rule; remove the rule instead", id, paths.BinaryName))
	}
	fmt.Fprintf(stdout, "Switch %s: %s  %s  (%s, %s, %s)\n", state, r.ID, r.Sentence, r.Enforcement, r.Owner, orDash(string(r.Scope)))
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
	res, err := rulebook.SetEnabled(in, id, on)
	for _, f := range res.Written {
		fmt.Fprintln(stdout, "wrote", displayHome(f, in.Paths.Home))
	}
	for _, b := range res.Backups {
		fmt.Fprintln(stdout, "backup", displayHome(b, in.Paths.Home))
	}
	if err != nil {
		return rulesErr(stderr, err)
	}
	if len(res.Written) == 0 {
		fmt.Fprintf(stdout, "nothing changed: %s is already %s\n", id, state)
		return 0
	}
	fmt.Fprintf(stdout, "switched %s %s\n", state, id)
	return 0
}

// rulesShadow is rules shadow [on|off] [--yes] (Phase 6): alone it prints
// the mode; on and off switch it in the overrides file after a confirm,
// through rulebook.SetShadow (backup first).
func rulesShadow(args []string, stdout, stderr io.Writer) int {
	set, pos, bad := rulesFlags(args, "--yes")
	if bad != "" {
		return rulesUsageErr(stderr, "unknown flag %q", bad)
	}
	if len(pos) > 1 || (len(pos) == 1 && pos[0] != "on" && pos[0] != "off") {
		return rulesUsageErr(stderr, "shadow takes on, off or nothing")
	}
	in, err := rulesInput()
	if err != nil {
		return rulesErr(stderr, err)
	}
	cur, err := policy.ShadowOn(in.Paths.OverridesFile())
	if err != nil {
		return rulesErr(stderr, err)
	}
	word := func(on bool) string {
		if on {
			return "on"
		}
		return "off"
	}
	if len(pos) == 0 {
		fmt.Fprintf(stdout, "shadow mode: %s\n", word(cur))
		return 0
	}
	on := pos[0] == "on"
	if on == cur {
		fmt.Fprintf(stdout, "nothing changed: shadow mode is already %s\n", word(on))
		return 0
	}
	if on {
		fmt.Fprintf(stdout, "Switch shadow mode on: %s's own rules are recorded with what they would have done, but never block or ask. Claude Code's own rules and the sandbox are unaffected.\n", paths.BinaryName)
	} else {
		fmt.Fprintf(stdout, "Switch shadow mode off: %s's own rules block and ask again.\n", paths.BinaryName)
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
	res, err := rulebook.SetShadow(in, on)
	for _, f := range res.Written {
		fmt.Fprintln(stdout, "wrote", displayHome(f, in.Paths.Home))
	}
	for _, b := range res.Backups {
		fmt.Fprintln(stdout, "backup", displayHome(b, in.Paths.Home))
	}
	if err != nil {
		return rulesErr(stderr, err)
	}
	fmt.Fprintf(stdout, "shadow mode %s\n", word(on))
	if on && in.Paths.Activity == "" {
		fmt.Fprintln(stdout, "note: the activity log is off (WATCHDECK_ACTIVITY=off), so shadow mode records nothing until it is on")
	}
	return 0
}

// rulesReconcile is rules reconcile: rulebook.Reconcile for this machine
// and the working directory's project. Each string the person removed by
// hand is forgotten from the ledger; each recommended one is declined.
func rulesReconcile(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		return rulesUsageErr(stderr, "reconcile takes no arguments")
	}
	in, err := rulesInput()
	if err != nil {
		return rulesErr(stderr, err)
	}
	dropped, declined, err := rulebook.Reconcile(in)
	if err != nil {
		return rulesErr(stderr, err)
	}
	printReconcile(stdout, in.Paths.Home, dropped, declined)
	return 0
}

// printReconcile prints what Reconcile forgot and declined, or "nothing to
// reconcile".
func printReconcile(w io.Writer, home string, dropped []claudesettings.Drift, declined []string) {
	if len(dropped) == 0 && len(declined) == 0 {
		fmt.Fprintln(w, "nothing to reconcile")
		return
	}
	for _, d := range dropped {
		fmt.Fprintf(w, "forgot %s in %s %s (removed by you)\n", d.Entry.Value, displayHome(d.Entry.Path, home), d.Entry.Key)
	}
	for _, id := range declined {
		fmt.Fprintf(w, "declined %s\n", recommendedRowID(id))
	}
}

// recommendedPlan is rulebook.RecommendedPlan: rules recommended --install
// and setup's Rules step both apply it with rulebook.Apply (one write and
// one backup per file).
func recommendedPlan(in rulebook.Input, missing []rulebook.Rule) (rulebook.Plan, error) {
	return rulebook.RecommendedPlan(in, missing)
}

// warnDeclined prints "warning: <err>" (after indent) when the declined
// list cannot be read: RecommendedOffer then declines nothing, so rules the
// person declined are offered (and, with --yes, installed). Nothing is
// printed with all, which offers every rule anyway.
// reconcileBeforeInstall runs rulebook.Reconcile before a recommended
// install computes its offer, so a recommended rule the person removed by
// hand is declined and not put back (final review of Plan 04, finding 2).
// A failure is printed as a warning and never blocks the install.
func reconcileBeforeInstall(w io.Writer, indent string, in rulebook.Input) {
	if _, _, err := rulebook.Reconcile(in); err != nil {
		fmt.Fprintf(w, "%swarning: could not check for rules removed by hand (%v)\n", indent, err)
	}
}

func warnDeclined(w io.Writer, indent, stateDir string, all bool) {
	if all {
		return
	}
	if _, err := rulebook.LoadDeclined(stateDir); err != nil {
		fmt.Fprintf(w, "%swarning: %v; every missing recommended rule is offered\n", indent, err)
	}
}
