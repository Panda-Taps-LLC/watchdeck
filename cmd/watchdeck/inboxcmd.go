package main

import (
	"fmt"
	"io"
	"strings"

	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
	"github.com/Panda-Taps-LLC/watchdeck/internal/rulebook"
)

const inboxUsage = `usage: ` + paths.BinaryName + ` inbox [--json]
       ` + paths.BinaryName + ` inbox resolve <id> (add | ack | dismiss | undo) [--yes]

What needs you since install (else the last seven days), newest first:
auto-mode denials, the hook's gate denies and asks, sandbox refusals and
skills asking past their grant. One line per item:
<id>  <kind>  <when>  <what>  <why>, then the suggested fix as a
"` + paths.BinaryName + ` rules add" line. A Bash program gets an ask, never a
block, with the path rule to use instead when a file was the target.
With the activity log off only transcript rejections can be listed.

  resolve <id> add       add the suggested fix (prints the rule and the
                         plan and asks; --yes skips the question, not the
                         printing) and close the item
  resolve <id> ack       close the item; the answer after a grant (a
                         skill asking past its grant or a sandbox refusal
                         has no rule to add: widen the grant with
                         "` + paths.BinaryName + ` rules grant <skill> …", then ack)
  resolve <id> dismiss   close it and every item like it
  resolve <id> undo      reopen an item you resolved: after an add, the
                         rules it wrote are removed first (asks; --yes
                         skips the question); prints each rule removed
                         and "reopened <id>"

Exit 0 ok, 1 declined or not confirmed, 2 error, 3 usage.
`

// cmdInbox is `watchdeck inbox`.
func cmdInbox(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		switch args[0] {
		case "-h", "--help", "help":
			fmt.Fprint(stdout, inboxUsage)
			return 0
		case "resolve":
			return inboxResolve(args[1:], stdout, stderr)
		}
	}
	set, pos, bad := rulesFlags(args, "--json")
	if bad != "" || len(pos) > 0 {
		return inboxUsageErr(stderr, "unknown argument %q", firstOf(bad, pos))
	}
	in, items, code := inboxOpen(stderr)
	if code != 0 {
		return code
	}
	if set["--json"] {
		if items == nil {
			items = []rulebook.Item{}
		}
		return writeJSON(stdout, stderr, items)
	}
	if len(items) == 0 {
		if in.Paths.Activity == "" {
			fmt.Fprintln(stdout, "the activity log is off (WATCHDECK_ACTIVITY=off): only transcript rejections can be listed")
			return 0
		}
		fmt.Fprintln(stdout, "nothing needs you")
		return 0
	}
	for _, it := range items {
		fmt.Fprintf(stdout, "%s  %s  %s  %s  %s\n", it.ID, it.Kind, it.TS.Local().Format("2006-01-02 15:04"), it.What, it.Why)
		fmt.Fprintf(stdout, "    fix: %s\n", fixLine(it))
	}
	return 0
}

// fixLine is an item's suggested fix: a rules add line (for a Bash
// program, the ask and on a second line the path rule to use instead when
// a file was the target), or for an item with no rule to add (a skill
// asking past its grant, a sandbox refusal) what to do instead and the ack
// that closes it.
func fixLine(it rulebook.Item) string {
	if len(it.Fix) > 0 && it.Fix[0].What == rulebook.WhatPackRule {
		// No rules add flag spells a pack rule's action: resolve add
		// applies it. The next fix, when it has a spelling, is the other way.
		line := packRuleFix(it.Fix[0]) + ": " + paths.BinaryName + " inbox resolve " + it.ID + " add"
		if len(it.Fix) > 1 {
			if alt := addLine(it.Fix[1]); alt != "" {
				line += "\n       or: " + alt
			}
		}
		return line
	}
	if len(it.Fix) > 0 {
		if line := addLine(it.Fix[0]); line != "" {
			if it.Fix[0].What == rulebook.WhatCommand {
				line += "\n       or a path rule if a file was the target: " + paths.BinaryName + " rules add --block --read <path>"
			}
			return line
		}
	}
	ack := paths.BinaryName + " inbox resolve " + it.ID + " ack"
	if it.Kind == rulebook.ItemSkillRequest {
		skill := "<skill>"
		if _, target, ok := strings.Cut(it.What, " · "); ok && target != "" {
			skill, _, _ = strings.Cut(target, ", ")
		}
		return paths.BinaryName + " rules grant " + shellQuote(skill) + " … then " + ack
	}
	return "none; " + ack
}

// packRuleFix names a pack-rule fix: the rule and the action it is set to.
func packRuleFix(r rulebook.AddRequest) string {
	act := r.Action
	switch act {
	case "deny":
		act = "block"
	case "ask":
		act = "ask first"
	}
	return "set the " + paths.BinaryName + " rule " + r.Value + " to " + act
}

func firstOf(bad string, pos []string) string {
	if bad != "" {
		return bad
	}
	return pos[0]
}

func inboxUsageErr(stderr io.Writer, format string, a ...any) int {
	fmt.Fprintf(stderr, paths.BinaryName+" inbox: "+format+"\n\n%s", append(a, inboxUsage)...)
	return 3
}

// inboxOpen lists the inbox against this machine's rules.
func inboxOpen(stderr io.Writer) (rulebook.Input, []rulebook.Item, int) {
	in, err := rulesInput()
	if err != nil {
		fmt.Fprintf(stderr, "%s inbox: %v\n", paths.BinaryName, err)
		return in, nil, 2
	}
	book, err := rulebook.List(in)
	if err != nil {
		fmt.Fprintf(stderr, "%s inbox: %v\n", paths.BinaryName, err)
		return in, nil, 2
	}
	items, err := rulebook.Open(rulebook.InboxInput{Paths: in.Paths, Book: &book})
	if err != nil {
		fmt.Fprintf(stderr, "%s inbox: %v\n", paths.BinaryName, err)
		return in, nil, 2
	}
	return in, items, 0
}

func inboxResolve(args []string, stdout, stderr io.Writer) int {
	set, pos, bad := rulesFlags(args, "--yes")
	if bad != "" {
		return inboxUsageErr(stderr, "unknown flag %q", bad)
	}
	if len(pos) != 2 {
		return inboxUsageErr(stderr, "resolve takes an item id and add, ack, dismiss or undo")
	}
	id, verb := pos[0], pos[1]
	switch verb {
	case "add", "ack", "dismiss":
	case "undo":
		return inboxUndo(id, set["--yes"], stdout, stderr)
	default:
		return inboxUsageErr(stderr, "resolve: %q is not add, ack, dismiss or undo", verb)
	}
	in, items, code := inboxOpen(stderr)
	if code != 0 {
		return code
	}
	var item *rulebook.Item
	for i := range items {
		if items[i].ID == id {
			item = &items[i]
		}
	}
	if item == nil {
		fmt.Fprintf(stderr, "%s inbox: no open item %q (see %s inbox)\n", paths.BinaryName, id, paths.BinaryName)
		return 2
	}
	stateDir := in.Paths.StateDir
	resolved := func(r rulebook.Resolution) int {
		if err := rulebook.Resolve(stateDir, r); err != nil {
			fmt.Fprintf(stderr, "%s inbox: %v\n", paths.BinaryName, err)
			return 2
		}
		fmt.Fprintf(stdout, "resolved %s (%s)\n", id, r.Action)
		return 0
	}
	switch verb {
	case "ack":
		return resolved(rulebook.Resolution{ID: id, Action: rulebook.ResolveAcknowledge})
	case "dismiss":
		return resolved(rulebook.Resolution{ID: id, Action: rulebook.ResolveDismiss, Signature: rulebook.Signature(*item)})
	}
	if len(item.Fix) == 0 {
		fmt.Fprintln(stdout, "this item has no rule to add; use ack or dismiss")
		if item.Kind == rulebook.ItemSkillRequest {
			fmt.Fprintf(stdout, "(widen the skill's grant with %s, then ack)\n", fixLine(*item))
		}
		return 1
	}
	plan, err := rulebook.Propose(in, item.Fix[0])
	if err != nil {
		fmt.Fprintf(stderr, "%s inbox: %v\n", paths.BinaryName, err)
		return 2
	}
	// The exact rule, before the plan and the confirm, in every mode.
	if item.Fix[0].What == rulebook.WhatPackRule {
		fmt.Fprintf(stdout, "rule: %s\n", packRuleFix(item.Fix[0]))
	} else if line := addLine(item.Fix[0]); line != "" {
		fmt.Fprintf(stdout, "rule: %s\n", line)
	}
	return applyPlan(in, plan, set["--yes"], stdout, stderr, "inbox", func(res rulebook.Result) int {
		r := rulebook.Resolution{ID: id, Action: rulebook.ResolveAddRule}
		if len(res.RowIDs) > 0 {
			r.RuleID, r.RuleIDs = res.RowIDs[0], res.RowIDs // every row, so an undo removes them all
		}
		return resolved(r)
	})
}

// inboxUndo is inbox resolve <id> undo: the item is resolved, so it is not
// looked up in the open list; rulebook.Undo cancels its latest resolution
// (removing every rule an add wrote) and the item reopens. It asks first:
// an undo of an add removes rules from the settings.
func inboxUndo(id string, yes bool, stdout, stderr io.Writer) int {
	in, err := rulesInput()
	if err != nil {
		fmt.Fprintf(stderr, "%s inbox: %v\n", paths.BinaryName, err)
		return 2
	}
	fmt.Fprintf(stdout, "Undo: reopen %s; the rules its add wrote, if any, are removed\n", id)
	c := newConsole(stdout, stderr, yes)
	ok, answered := c.ask("Undo? (a .bak-<ts> backup is written first)", true)
	if !answered {
		fmt.Fprintln(stdout, "Not undone: no terminal to confirm; rerun with --yes.")
		return 1
	}
	if !ok {
		fmt.Fprintln(stdout, "Not undone.")
		return 1
	}
	res, err := rulebook.Undo(in, id)
	for _, f := range res.Written {
		fmt.Fprintln(stdout, "wrote", displayHome(f, in.Paths.Home))
	}
	for _, b := range res.Backups {
		fmt.Fprintln(stdout, "backup", displayHome(b, in.Paths.Home))
	}
	for _, row := range res.RowIDs {
		fmt.Fprintln(stdout, "removed", row)
	}
	if err != nil {
		fmt.Fprintf(stderr, "%s inbox: %v\n", paths.BinaryName, err)
		return 2
	}
	fmt.Fprintln(stdout, "reopened", id)
	return 0
}
