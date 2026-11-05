package hook

import (
	"path/filepath"
	"sort"
	"strings"

	"github.com/Panda-Taps-LLC/watchdeck/internal/manifest"
	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
	"github.com/Panda-Taps-LLC/watchdeck/internal/shellparse"
)

// Model-typed `watchdeck run` (M6.3, M6.7 verifier findings). The hook's
// own rewrite is the legitimate producer of `watchdeck run`; Claude Code
// runs the rewritten command without calling the hook again. A model that
// types one itself must not borrow a grant the hook would not have given
// (a skill's network or auto_allow for an arbitrary payload, a command
// subject's grant, an MCP server's launch grant). So a lone run the model
// typed gets the hook's normal answer only when its subjects are exactly
// the ones the hook itself would produce for its -c payload:
//
//   - `--subject mcp:<name>` (or any kind but skill and command): ask. An
//     MCP server's launch grant is for the configured server command only,
//     and Claude Code never starts MCP servers through Bash.
//   - `--skill` / `--subject skill:` / `--subject command:`: the payload is
//     run through the sandbox stage as if the model had typed it plainly.
//     When that rewrites it to the same skill set (high confidence) or the
//     same command subject, the answer is the rewrite's decision (ask, or
//     allow when auto-allowed), without a new rewrite. Otherwise, or in the
//     `--` argv form, ask.
//
// A leading assignment or a redirection makes the command not a lone run
// (shellparse.IsSingleWatchdeckRun), so it is asked about as a compound.

// mentionsRun reports whether command may invoke `watchdeck run`: the
// text "watchdeck run", or a word ending in watchdeck (quotes trimmed)
// followed by the word run, whatever the spacing.
func mentionsRun(command string) bool { return mentionsSub(command, "run") }

// mutatingSub reports the first watchdeck subcommand in command that may
// change watchdeck's or Claude Code's settings (Plan 04 Task 16,
// 2026-10-19). A model-typed one always asks, as `watchdeck allow` has
// since 2026-10-14: a --yes must never weaken watchdeck's own rules
// without the person seeing it. The spelling tolerance is mentionsSub's
// (quotes, $' and $" openers and backslashes stripped, ASCII case folded
// since macOS finds the binary under any case, any word ending in
// watchdeck, any spacing, inside a compound), and every mention is
// checked, so a read-only one first does not hide a later one.
// `advanced` is skipped: `watchdeck advanced enforce install` reports
// enforce. A word after the name that starts a new command (&&, ||, |, ;)
// is not a subcommand; any other word is. sub is "" when the subcommand
// cannot be read: the name glued to a redirection, an expansion or a list
// (watchdeck>x, watchdeck${IFS}rules, {watchdeck,rules}, a script's
// ["watchdeck", "rules"]), any command that also holds xargs or
// parallel, a word that is not a plain name, or any $ or backtick
// (in the folded text) or backslash (in the original) anywhere in a
// command that names the binary. `run` is handled before
// this, except a run reached through a variable, which lands here.
func mutatingSub(command string) (string, bool) {
	plain, found := foldedMention(command)
	if !found {
		return "", false
	}
	// xargs and parallel append words from stdin to whatever follows
	// them. A word walk around them was evaded twice (separators glued to
	// xargs, gxargs), so any command that also holds either text asks,
	// whatever the word boundaries (ruled 2026-10-19; the accepted false
	// positive is a read-only command such as `watchdeck status | xargs
	// echo`).
	if strings.Contains(plain, "xargs") || strings.Contains(plain, "parallel") {
		return "", true
	}
	for k := strings.Index(plain, paths.BinaryName); k >= 0; {
		e := k + len(paths.BinaryName)
		if e < len(plain) && (strings.IndexByte("<>{},[]$", plain[e]) >= 0 || strings.HasPrefix(plain[e:], "&>")) {
			return "", true
		}
		n := strings.Index(plain[e:], paths.BinaryName)
		if n < 0 {
			break
		}
		k = e + n
	}
	f := strings.Fields(plain)
	for i := 0; i < len(f); i++ {
		// $(which watchdeck) rules … and `which watchdeck` rules …
		if !strings.HasSuffix(strings.TrimRight(f[i], ")`"), paths.BinaryName) {
			continue
		}
		j := i + 1
		for j < len(f) && f[j] == "advanced" {
			j++
		}
		if j >= len(f) || startsCommand(f[j]) {
			continue
		}
		sub, ended := shellWord(f[j])
		if !plainSub(sub) {
			// A redirection, an expansion or a parenthesis where the
			// subcommand goes.
			return "", true
		}
		var rest []string
		if !ended {
			rest = f[j+1:]
		}
		if !readOnlySub(sub, rest) {
			return sub, true
		}
	}
	// The name held in a shell variable (a=watchdeck; $a rules reconcile,
	// read w <<< watchdeck; $w setup, IFS splits, ${a//:/ }) is never a
	// word that ends in the name, so the walk above finds nothing. Ruled
	// fail-closed (final review of Plan 04, 2026-10-19): a command that
	// names the binary and holds any expansion or backtick asks. The walk
	// runs first, so `$(which watchdeck) rules …` still reports rules. The
	// accepted false positives are read-only commands with an expansion,
	// such as `watchdeck rules list > "$HOME/x"`.
	//
	// A backslash in the original text asks too (re-review of the fix
	// wave, 2026-10-19): plain has every backslash stripped, so
	// `printf 'watchdeck\tuninstall --yes' | sh` reads as watchdecktuninstall,
	// and printf, echo -e or %b turn the escape into a separator at run
	// time. The accepted false positive is a read-only command with an
	// escape, such as `grep 'watchdeck\b' notes`.
	if strings.ContainsAny(plain, "$`") || strings.IndexByte(command, '\\') >= 0 {
		return "", true
	}
	return "", false
}

// foldedMention is the cheap pre-check shared by both guards: whether
// command may name the binary once single, double, $'…' and $"…" quotes,
// backslashes and ASCII case are set aside. plain is that text, lower-cased; it is
// only built when the name may be there.
func foldedMention(command string) (plain string, found bool) {
	// U+212A KELVIN SIGN: the case-insensitive APFS volume folds it to
	// k, so watchdec\u212a runs the binary. The re-review of 2026-10-19
	// checked that no other Unicode character folds to a letter of the
	// name; ASCII case is folded below.
	plain = command
	if strings.ContainsAny(command, "'\"\\\u212a") {
		plain = strings.NewReplacer("$'", "", `$"`, "", "'", "", `"`, "", `\`, "", "\u212a", "k").Replace(command)
	}
	if !containsFoldASCII(plain, paths.BinaryName) {
		return "", false
	}
	return strings.ToLower(plain), true
}

// containsFoldASCII reports whether s contains sub (lower-case ASCII)
// with ASCII letters of s compared case-insensitively. No allocation.
func containsFoldASCII(s, sub string) bool {
	if sub == "" {
		return true
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i]|0x20 != sub[0] {
			continue
		}
		j := 1
		for ; j < len(sub); j++ {
			c := s[i+j]
			if 'A' <= c && c <= 'Z' {
				c += 'a' - 'A'
			}
			if c != sub[j] {
				break
			}
		}
		if j == len(sub) {
			return true
		}
	}
	return false
}

// plainSub reports whether sub reads as a subcommand or flag name.
func plainSub(sub string) bool {
	if sub == "" {
		return false
	}
	for i := 0; i < len(sub); i++ {
		c := sub[i]
		if !('a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// startsCommand reports whether word begins a new shell command.
func startsCommand(word string) bool {
	return word != "" && strings.IndexByte(";&|", word[0]) >= 0 && !strings.HasPrefix(word, "&>")
}

// shellWord cuts word at its first shell operator character; ended
// reports that the cut started a new command (;, &, |), so nothing
// after it belongs to this one.
func shellWord(word string) (w string, ended bool) {
	k := strings.IndexAny(word, ";&|<>()")
	if k < 0 {
		return word, false
	}
	return word[:k], strings.IndexByte(";&|", word[k]) >= 0 && !strings.HasPrefix(word[k:], "&>")
}

// readOnlySub reports whether `watchdeck <sub> <rest...>` only reads.
// A switch, not a map: internal/hook is init-free.
func readOnlySub(sub string, rest []string) bool {
	next := ""
	if len(rest) > 0 && !startsCommand(rest[0]) {
		next, _ = shellWord(rest[0])
	}
	switch sub {
	case "version", "paths", "status", "doctor", "audit", "validate",
		"sessions", "activity", "help", "index", "demo",
		"--help", "-h", "--version", "-v":
		return true
	case "rules":
		// list and explain (a dry run, Plan 07) only read, whatever
		// follows; an inner command with $ or a backtick still asks
		// through the expansion rule below.
		if next == "list" || next == "explain" {
			return true
		}
		// `rules shadow` alone reads the mode. Any word after it may switch
		// it (on, off, or a flag before on: --yes on), so only the end of the
		// command or a new command keeps it read-only.
		if next == "pause" {
			// `rules pause --list` reads the temporaries (Plan 08); any
			// other word, before or after --list, may pause a rule.
			if len(rest) < 2 || startsCommand(rest[1]) {
				return false
			}
			w, ended := shellWord(rest[1])
			return w == "--list" && (ended || len(rest) < 3 || startsCommand(rest[2]))
		}
		return next == "shadow" && (len(rest) < 2 || startsCommand(rest[1]))
	case "mcp":
		return next == "status"
	case "policy":
		return next == "check"
	case "inbox":
		// Read-only unless resolve follows anywhere later in the
		// command: a spurious ask is harmless, a missed resolve is not.
		// The CLI resolves only when resolve is the first argument, and
		// any spelling of it ($'resolve', res$()olve, {resolve,}) is a
		// word that does not start with "-": read-only only with no
		// argument or a flag first.
		for _, w := range rest {
			if w, _ := shellWord(w); w == "resolve" {
				return false
			}
		}
		return next == "" || strings.HasPrefix(next, "-")
	}
	return false
}

// mentionsSub reports whether command may invoke `watchdeck <sub>`.
// Quotes and backslashes can split the words (watch'd'eck, r\un) and
// macOS runs WATCHDECK as watchdeck: look at the folded text.
func mentionsSub(command, sub string) bool {
	if strings.Contains(command, paths.BinaryName+" "+sub) {
		return true
	}
	plain, found := foldedMention(command)
	if !found {
		return false
	}
	f := strings.Fields(plain)
	for i := 0; i+1 < len(f); i++ {
		w := strings.Trim(f[i], `'"\`)
		if strings.HasSuffix(w, paths.BinaryName) && strings.Trim(f[i+1], `'"\`) == sub {
			return true
		}
	}
	return false
}

// loneRunReason is the ask reason for a `watchdeck run` that is not a
// lone run: environment overrides get their own wording.
func loneRunReason(command, cwd string, environ map[string]string) string {
	if prog, err := shellparse.Parse(command, cwd, environ); err == nil && prog != nil && len(prog.Calls) == 1 {
		c := prog.Calls[0]
		if len(c.Assigns) > 0 && len(c.Argv) >= 2 && filepath.Base(c.Argv[0]) == paths.BinaryName && c.Argv[1] == "run" {
			return "watchdeck: watchdeck run with environment overrides is not allowed through the hook; run it without the VAR=value prefix"
		}
	}
	return "watchdeck: compound command around `watchdeck run`; run it alone"
}

// runArgs is what a `watchdeck run` names.
type runArgs struct {
	argv0          string   // the parsed first word, quotes removed
	skills         []string // sorted, deduped
	commandSubject string
	otherKind      string // first subject kind other than skill and command
	payload        string
	hasPayload     bool
	argvForm       bool
	commandCount   int
}

// parseRunArgs reads the flags of `watchdeck run` from argv (argv[0] is
// watchdeck, argv[1] run), as the CLI's flag package would.
func parseRunArgs(argv []string) runArgs {
	var r runArgs
	if len(argv) > 0 {
		r.argv0 = argv[0]
	}
	for i := 2; i < len(argv); i++ {
		a := strings.TrimPrefix(argv[i], "-") // -x and --x are one flag
		name, val, hasVal := strings.Cut(a, "=")
		switch {
		case argv[i] == "--":
			r.argvForm = true
			i = len(argv)
			continue
		case !strings.HasPrefix(argv[i], "-"):
			continue
		}
		name = strings.TrimPrefix(name, "-")
		if !hasVal && (name == "c" || name == "skill" || name == "subject") && i+1 < len(argv) {
			val = argv[i+1]
			i++
		}
		switch name {
		case "c":
			r.payload, r.hasPayload = val, true
		case "skill":
			r.skills = append(r.skills, val)
		case "subject":
			kind, n, _ := strings.Cut(val, ":")
			switch kind {
			case "skill":
				r.skills = append(r.skills, n)
			case "command":
				r.commandSubject = n
				r.commandCount++
			default:
				if r.otherKind == "" {
					r.otherKind = kind
				}
			}
		}
	}
	r.skills = sortedSkills(r.skills)
	return r
}

func runArgsOf(command, cwd string, environ map[string]string) (runArgs, bool) {
	prog, err := shellparse.Parse(command, cwd, environ)
	if err != nil || prog == nil || len(prog.Calls) != 1 {
		return runArgs{}, false
	}
	return parseRunArgs(prog.Calls[0].Argv), true
}

// modelTypedRun decides a lone `watchdeck run` the model typed.
// The meta carries only the native Claude Code rule hits of the payload
// (Plan 02 Task 7), so the record names the rule.
func modelTypedRun(in Input, command, cwd string, env Env, lp loadedPolicy) (*Output, meta) {
	got, ok := runArgsOf(command, cwd, env.Environ)
	if !ok {
		return ask("watchdeck: could not read this watchdeck run command; run the plain command and let the hook rewrite it", nil, ""), meta{}
	}
	switch {
	case got.argv0 != paths.BinaryName:
		// ./watchdeck, /tmp/x/watchdeck, ../x/watchdeck: a repository
		// can ship its own "watchdeck"; only the bare name (found through
		// PATH, as the hook's own rewrite writes it) gets the normal answer.
		return ask("watchdeck: this runs a watchdeck binary by path ("+manifest.DisplayPath(got.argv0)+"), not the installed one; run the plain command and let the hook rewrite it", nil, ""), meta{}
	case got.otherKind == "mcp":
		return ask("watchdeck: MCP launch subjects are only for configured MCP servers; Claude Code never starts one through Bash", nil, ""), meta{}
	case got.otherKind != "":
		return ask("watchdeck: watchdeck run with subject kind "+manifest.DisplayPath(got.otherKind)+" is not something the hook produces", nil, ""), meta{}
	case len(got.skills) == 0 && got.commandSubject == "":
		return nil, meta{} // names nothing: run itself refuses (usage, exit 3)
	case got.argvForm || !got.hasPayload:
		return ask("watchdeck: a model-typed watchdeck run must carry its command in -c, so the hook can check it", nil, ""), meta{}
	}
	// The person's own Claude Code deny rules see only `watchdeck run …`
	// here, so match them against the payload first, whether or not the
	// payload would be rewritten (Plan 02 Task 7).
	no, nm, hit := nativeCheck(env, cwd, got.payload)
	if hit && no.HookSpecificOutput.PermissionDecision == Deny {
		return no, meta{Rules: nm.Rules, Enforcement: nm.Enforcement}
	}
	// What would the hook have done with the payload typed plainly?
	inner := in
	inner.ToolInput = map[string]any{"command": got.payload}
	// The comparison asks what the hook does with the plain payload; the
	// typed run carries no rewrite to drop, so the mode does not apply
	// (nativeAsk would otherwise leave out the rewrite compared below).
	inner.PermissionMode = ""
	out, m := sandboxStage(inner, env, cwd, lp)
	if out != nil && out.HookSpecificOutput.PermissionDecision == Deny {
		return out, meta{Rules: m.Rules, Enforcement: m.Enforcement} // the person's own Claude Code deny rule matched the payload
	}
	if out != nil && out.HookSpecificOutput.UpdatedInput != nil {
		rw, _ := out.HookSpecificOutput.UpdatedInput["command"].(string)
		want, ok := runArgsOf(rw, cwd, env.Environ)
		same := ok && want.commandSubject == got.commandSubject && got.commandCount <= 1 && equalStrings(want.skills, got.skills)
		if same && (len(want.skills) == 0 || m.Confidence == "high") {
			s := out.HookSpecificOutput
			return &Output{HookSpecificOutput: Specific{
				HookEventName: "PreToolUse", PermissionDecision: s.PermissionDecision,
				PermissionDecisionReason: s.PermissionDecisionReason, AdditionalContext: s.AdditionalContext,
			}}, meta{Rules: m.Rules}
		}
	}
	what := strings.Join(got.skills, ", ")
	if got.commandSubject != "" {
		if what != "" {
			what += ", "
		}
		what += "command:" + got.commandSubject
	}
	reason := "watchdeck: this watchdeck run names " + manifest.DisplayPath(what) + ", which is not what the hook would choose for its command; run the plain command and let the hook rewrite it"
	if hit { // a native ask on the payload: name it
		return ask(no.HookSpecificOutput.PermissionDecisionReason+" | "+strings.TrimPrefix(reason, "watchdeck: "), nil, ""), meta{Rules: nm.Rules}
	}
	return ask(reason, nil, ""), meta{}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	a, b = append([]string(nil), a...), append([]string(nil), b...)
	sort.Strings(a)
	sort.Strings(b)
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
