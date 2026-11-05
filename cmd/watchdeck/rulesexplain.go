package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/Panda-Taps-LLC/watchdeck/internal/activity"
	"github.com/Panda-Taps-LLC/watchdeck/internal/claudesettings"
	"github.com/Panda-Taps-LLC/watchdeck/internal/hook"
	"github.com/Panda-Taps-LLC/watchdeck/internal/lifecycle"
	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
	"github.com/Panda-Taps-LLC/watchdeck/internal/policy"
)

// `watchdeck rules explain` (Plan 07 Task 1, 2026-10-20): a dry run. It
// builds one synthetic PreToolUse call from the flags, runs it through
// hook.Explain (the hook's pipeline with no watchdog, no lifecycle touch
// and no activity line) and prints the verdict and what decided it.
//
// Exit codes (D3): 0 allow or no opinion, 1 deny, 2 ask, 3 usage, 4 the
// policy could not be loaded; with --expect, 0 when the verdict matches
// and 1 when it does not (3 and 4 as before).

// explainWhats names the WHAT flags in the order the usage lists them.
const explainWhats = "--command, --read, --edit, --path, --url, --mcp, --skill"

// explainWhat maps a WHAT flag to the tool it stands for and the
// tool_input key that carries its value. The vocabulary is rules add's
// where one flag names one call (D2): --path is a Write here (rules add's
// --path covers Read and Edit), --url a WebFetch (rules add's --domain is
// a host, not a call), and --skill a Skill call. An MCP tool is named as
// Claude Code names it, mcp__<server>__<tool>, with an empty input; tool
// is "" for it, the value being the tool name.
func explainWhat(flag string) (tool, key string, ok bool) {
	switch flag {
	case "--command":
		return "Bash", "command", true
	case "--read":
		return "Read", "file_path", true
	case "--edit":
		return "Edit", "file_path", true
	case "--path":
		return "Write", "file_path", true
	case "--url":
		return "WebFetch", "url", true
	case "--mcp":
		return "", "", true
	case "--skill":
		return "Skill", "skill", true
	}
	return "", "", false
}

// permissionModes are the values --mode accepts: Claude Code's
// permission_mode as the hook receives it.
const permissionModes = "default, acceptEdits, auto, bypassPermissions, dontAsk, plan"

func validPermissionMode(m string) bool {
	switch m {
	case "default", "acceptEdits", "auto", "bypassPermissions", "dontAsk", "plan":
		return true
	}
	return false
}

// explainRequest is one parsed rules explain command line.
type explainRequest struct {
	tool   string // the ToolName
	key    string // the tool_input key; "" for an MCP tool
	value  string // the WHAT value as typed
	cwd    string // --cwd as typed; "" = the working directory
	mode   string // --mode; default "default"
	expect string // --expect; "" = none
	json   bool
}

// parseExplainArgs reads the flags by hand like the other rules
// subcommands. It returns the usage error, "" when the line is good.
func parseExplainArgs(args []string) (explainRequest, string) {
	req := explainRequest{mode: "default"}
	whats := 0
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch a {
		case "--json":
			req.json = true
			continue
		case "--cwd", "--mode", "--expect":
			if i+1 >= len(args) {
				return req, fmt.Sprintf("explain: %s needs a value", a)
			}
			i++
			switch a {
			case "--cwd":
				req.cwd = args[i]
			case "--mode":
				req.mode = args[i]
			case "--expect":
				req.expect = args[i]
			}
			continue
		}
		tool, key, ok := explainWhat(a)
		if !ok {
			return req, fmt.Sprintf("explain: unknown argument %q", a)
		}
		if i+1 >= len(args) || args[i+1] == "" {
			return req, fmt.Sprintf("explain: %s needs a value", a)
		}
		i++
		whats++
		req.tool, req.key, req.value = tool, key, args[i]
	}
	if whats != 1 {
		return req, "explain needs exactly one of " + explainWhats
	}
	if req.tool == "" {
		req.tool = req.value // --mcp: the tool name is the value
	}
	if !validPermissionMode(req.mode) {
		return req, fmt.Sprintf("explain: --mode %q is not one of %s", req.mode, permissionModes)
	}
	switch req.expect {
	case "", hook.Allow, hook.Ask, hook.Deny:
	default:
		return req, fmt.Sprintf("explain: --expect %q is not allow, ask or deny", req.expect)
	}
	return req, ""
}

// cmdRulesExplain is `watchdeck rules explain`.
func cmdRulesExplain(args []string, stdout, stderr io.Writer) int {
	req, msg := parseExplainArgs(args)
	if msg != "" {
		return rulesUsageErr(stderr, "%s", msg)
	}
	hp, environ, err := hostPaths()
	if err != nil {
		fmt.Fprintf(stderr, "%s rules explain: %v\n", paths.BinaryName, err)
		return 4
	}
	cwd := req.cwd
	if cwd == "" {
		cwd, _ = os.Getwd()
	} else {
		if cwd, err = filepath.Abs(cwd); err != nil {
			fmt.Fprintf(stderr, "%s rules explain: --cwd: %v\n", paths.BinaryName, err)
			return 4
		}
		// The call is asked about for that directory's session, so the
		// project Claude Code would name is its git root, not this one's.
		delete(environ, "CLAUDE_PROJECT_DIR")
	}

	// The policy, loaded as the hook loads it (D3: exit 4 when a file
	// cannot be loaded). The hook fails closed on the user file (every
	// gated call asks) and drops the project layer on the project file;
	// the verdict below is that answer, and the exit says why.
	userPath, projectPath, _ := policyFilesAt(hp, cwd)
	lp := policy.LoadCached(filepath.Join(hp.StateDir, policy.CacheFile), userPath, projectPath)
	policyErr := ""
	if lp.UserErr != nil {
		policyErr = fmt.Sprintf("your policy file %s could not be loaded (%s); the hook asks about every gated call until it is fixed (%s doctor)",
			displayHome(userPath, hp.Home), firstLineOf(lp.UserErr.Error()), paths.BinaryName)
	}
	if lp.ProjectErr != nil {
		fmt.Fprintf(stderr, "warning: the project policy file %s could not be loaded (%s); the hook decides without it\n",
			displayHome(projectPath, hp.Home), firstLineOf(lp.ProjectErr.Error()))
	}

	in := hook.Input{
		HookEventName:  "PreToolUse",
		SessionID:      "explain",
		ToolUseID:      "toolu_explain",
		Cwd:            cwd,
		PermissionMode: req.mode,
		ToolName:       req.tool,
		ToolInput:      map[string]any{},
	}
	if req.key != "" {
		in.ToolInput[req.key] = req.value
	}
	env := hook.Env{
		Home: hp.Home, CacheDir: hp.CacheBase, UserCfgDir: hp.ConfigDir,
		ActivityPath: "", Environ: environ, StateDir: hp.StateDir,
		Lifecycle: lifecycle.Store{},
	}
	out, ex := hook.Explain(in, env)

	if req.json {
		doc := hook.BuildDoc(in, out, ex)
		if code := writeJSON(stdout, stderr, doc); code != 0 {
			return 4
		}
	} else {
		printExplanation(stdout, in, req, ex)
	}

	if policyErr != "" {
		fmt.Fprintf(stderr, "%s rules explain: %s\n", paths.BinaryName, policyErr)
		return 4
	}
	if req.expect != "" {
		if ex.Shadow && ex.Would != "" {
			// Under shadow mode the verdict is the observed one, so an
			// --expect that reads only the exit would miss what enforce
			// mode would do (review of Plan 07, M8). The exit stays D3's.
			by := explainWouldBy(ex)
			if by != "" {
				by = " by " + by
			}
			fmt.Fprintf(stderr, "%s rules explain: shadow mode is on: enforce mode would %s%s\n", paths.BinaryName, ex.Would, by)
		}
		if explainMatches(req.expect, ex.Verdict) {
			return 0
		}
		got := ex.Verdict
		if got == "none" {
			got = "allow (no opinion)"
		}
		if n := ex.NativeRule; n != nil {
			got += "; your Claude Code " + n.Kind + " rule " + oneLine(n.Value) + " matches it"
		}
		fmt.Fprintf(stderr, "%s rules explain: expected %s, got %s\n", paths.BinaryName, req.expect, got)
		return 1
	}
	switch ex.Verdict {
	case hook.Deny:
		return 1
	case hook.Ask:
		return 2
	}
	return 0
}

// explainMatches reports whether an --expect value matches a verdict: no
// opinion counts as allow (D3 gives both exit 0).
func explainMatches(expect, verdict string) bool {
	return expect == verdict || (expect == hook.Allow && verdict == "none")
}

// printExplanation is the human form: the call, the verdict with what
// qualifies it in parentheses, the hook's reason, the rule ids.
func printExplanation(w io.Writer, in hook.Input, req explainRequest, ex hook.Explanation) {
	if req.key == "" {
		fmt.Fprintf(w, "%s  (no input)\n", oneLine(in.ToolName))
	} else {
		fmt.Fprintf(w, "%s  %s\n", in.ToolName, oneLine(req.value))
	}
	ids := explainRuleIDs(ex.Rules)
	word := ex.Verdict
	var notes []string
	if ex.Rewritten != "" {
		notes = append(notes, "rewritten to run under the sandbox: "+oneLine(ex.Rewritten))
	}
	if ex.Shadow {
		by := explainWouldBy(ex)
		if by != "" {
			by = " by " + by
		}
		notes = append(notes, "shadow mode is on: would "+ex.Would+by)
	}
	if ex.Verdict == "none" {
		word = hook.Allow
		switch {
		case ex.Shadow:
			notes = append(notes, "Claude Code decides as usual")
		case len(ids) > 0:
			notes = append(notes, "only a log rule applies: "+strings.Join(ids, ", ")+"; Claude Code decides as usual")
		default:
			notes = append(notes, "no watchdeck rule applies; Claude Code decides as usual")
		}
	}
	line := "verdict: " + word
	if len(notes) > 0 {
		line += "  (" + strings.Join(notes, "; ") + ")"
	}
	fmt.Fprintln(w, line)
	if ex.Reason != "" {
		fmt.Fprintf(w, "reason:  %s\n", oneLine(ex.Reason))
	}
	if ex.Shadow && ex.WouldReason != "" {
		fmt.Fprintf(w, "would:   %s\n", oneLine(ex.WouldReason))
	}
	if len(ids) > 0 {
		fmt.Fprintf(w, "rules:   %s\n", strings.Join(ids, ", "))
	}
	if n := ex.NativeRule; n != nil {
		// The hook did not check this rule (it does so only before a
		// rewrite); Claude Code applies it itself. A deny refuses in every
		// permission mode; what an ask does depends on the mode (a prompt
		// by default, none under dontAsk or bypassPermissions, as Claude
		// Code documents it; not run here), so the ask note names no
		// outcome.
		does := "refuses it itself"
		if n.Kind == claudesettings.KindAsk {
			does = "applies it itself"
		}
		fmt.Fprintf(w, "note:    your Claude Code %s rule %s (%s settings) matches this command; Claude Code %s\n", n.Kind, oneLine(n.Value), oneLine(n.Scope), does)
	}
}

func explainRuleIDs(hits []activity.RuleHit) []string {
	var out []string
	for _, h := range hits {
		if h.Pack == "" || h.ID == "" {
			continue
		}
		id := oneLine(hook.RuleID(h))
		dup := false
		for _, x := range out {
			if x == id {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, id)
		}
	}
	return out
}

// explainWouldBy names what a shadowed verdict came from: the rule hits
// at that action, else the gate's subject.
func explainWouldBy(ex hook.Explanation) string {
	var hits []activity.RuleHit
	for _, h := range ex.Rules {
		if h.Action == ex.Would {
			hits = append(hits, h)
		}
	}
	if ids := explainRuleIDs(hits); len(ids) > 0 {
		return strings.Join(ids, ", ")
	}
	if ex.Subject != nil {
		return oneLine(ex.Subject.Kind + " gate " + ex.Subject.Name)
	}
	return ""
}

// oneLine keeps a line a line: every control character, other
// non-printable rune and invalid byte becomes '?'. Spaces, '|' and the
// text's length stay: the value is the person's own typed input or the
// hook's reason, printed back to them, never a policy value.
func oneLine(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r == utf8.RuneError || (r != ' ' && !unicode.IsPrint(r)) {
			b.WriteByte('?')
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// firstLineOf is the first line of an error's text.
func firstLineOf(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
