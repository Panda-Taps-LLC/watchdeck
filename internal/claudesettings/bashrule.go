package claudesettings

import (
	"strings"

	"github.com/Panda-Taps-LLC/watchdeck/internal/shellparse"
)

// Native Bash rules (Plan 02 Task 7). Claude Code evaluates its own
// permissions.deny and ask rules against the command the PreToolUse hook
// hands back, so once the hook rewrites `curl …` to `watchdeck run -c
// 'curl …'` a rule such as Bash(curl *) no longer sees the curl. The hook
// therefore matches the person's Bash deny and ask rules against the
// original command before it rewrites, with the semantics documented at
// code.claude.com/docs/en/permissions (read 2026-10-19):
//
//   - a rule matches the whole text of a subcommand; `*` matches any text,
//     spaces included; a rule without `*` matches one exact command;
//   - subcommands are split on &&, ||, ;, |, |&, & and newlines, and a deny
//     or ask rule applies when any subcommand matches, at any depth
//     (subshell, command substitution, control-flow body);
//   - the wrappers timeout, time, nice, nohup, stdbuf, command, builtin,
//     noglob and bare xargs are stripped, and deny and ask rules match past
//     any leading VAR=value assignments; a wrapper's options are read as
//     GNU getopt_long reads them (bundled short flags, unique long-option
//     prefixes), and a backslash-newline outside single quotes is removed
//     as bash removes it (shellparse.Subcommands);
//   - a trailing " *" also matches the bare command when it is the rule's
//     only wildcard; the space is significant; a ":*" suffix is the same as
//     " *", a colon elsewhere is literal;
//   - Bash and Bash(*) match every command.
//
// Where the documentation leaves a case open the matcher reads it so that
// a rule matches more, never less: a rule is also matched against the
// whole command text (so a rule written with an operator in it can match),
// a `*` is a wildcard even inside quotes, whitespace runs in the command
// also match as single spaces, and Bash() matches everything. A command
// the parser rejects is decided only by a match-all rule (Bash, Bash(*),
// an unreadable settings file); otherwise it is Uncertain, and the hook
// asks.

// Rule kinds.
const (
	KindDeny = "deny"
	KindAsk  = "ask"
)

// BashRule is one Bash deny or ask rule from Claude Code's settings.
type BashRule struct {
	Pattern string // the specifier, ":*" suffix normalised to " *"; "*" for bare Bash
	Kind    string // "deny" | "ask"
	Scope   Scope
	Value   string // the rule as written, e.g. "Bash(git clean:*)"; "" when Unreadable
	// Unreadable marks a settings file that exists but could not be read or
	// parsed: its rules are unknown, so it stands for an ask that matches
	// every command. Path names the file.
	Unreadable bool   `json:",omitempty"`
	Path       string `json:",omitempty"`
}

// BashMatch is MatchBash's answer. Rule is nil when nothing matched.
type BashMatch struct {
	Rule       *BashRule
	Subcommand string // the subcommand text the rule matched
	Uncertain  bool   // the command could not be parsed and no match-all rule applies
}

// BashRules returns the Bash rules of eff: Deny entries first, then Ask,
// each in file order. Entries for other tools are skipped.
func BashRules(eff Effective) []BashRule {
	var out []BashRule
	add := func(es []Entry, kind string) {
		for _, e := range es {
			if p, ok := bashPattern(e.Value); ok {
				out = append(out, BashRule{Pattern: p, Kind: kind, Scope: e.Scope, Value: e.Value})
			}
		}
	}
	add(eff.Deny, KindDeny)
	add(eff.Ask, KindAsk)
	return out
}

// bashPattern returns the normalised pattern of a Bash rule value.
func bashPattern(v string) (string, bool) {
	if v == "Bash" {
		return "*", true
	}
	if !strings.HasPrefix(v, "Bash(") || !strings.HasSuffix(v, ")") {
		return "", false
	}
	p := v[len("Bash(") : len(v)-1]
	if p == "" {
		return "*", true // undocumented; read as matching everything
	}
	if strings.HasSuffix(p, ":*") {
		p = p[:len(p)-2] + " *"
	}
	return p, true
}

// MatchBash matches command against rules: every deny rule first, then
// every ask rule. With no rules it parses nothing and matches nothing.
func MatchBash(rules []BashRule, command string) BashMatch {
	if len(rules) == 0 {
		return BashMatch{}
	}
	whole := strings.TrimSpace(command)
	subs, err := shellparse.Subcommands(command)
	for _, kind := range []string{KindDeny, KindAsk} {
		for i := range rules {
			r := &rules[i]
			if r.Kind != kind {
				continue
			}
			if r.Unreadable || r.Pattern == "*" {
				return BashMatch{Rule: r, Subcommand: whole}
			}
			if err != nil {
				continue // only a match-all rule decides an unparseable command
			}
			if matchRule(r.Pattern, whole) || matchRule(r.Pattern, strings.Join(strings.Fields(whole), " ")) {
				return BashMatch{Rule: r, Subcommand: whole}
			}
			for _, s := range subs {
				for _, f := range s.Forms {
					if matchRule(r.Pattern, f) {
						return BashMatch{Rule: r, Subcommand: s.Text}
					}
				}
			}
		}
	}
	if err != nil {
		return BashMatch{Uncertain: true}
	}
	return BashMatch{}
}

// matchRule matches one normalised pattern against one command text.
func matchRule(pattern, text string) bool {
	if globStar(pattern, text) {
		return true
	}
	// a trailing " *" that is the only wildcard also matches the bare command
	if strings.HasSuffix(pattern, " *") && strings.Count(pattern, "*") == 1 {
		return text == pattern[:len(pattern)-2]
	}
	return false
}

// globStar reports whether text matches pattern, where `*` matches any
// run of characters (spaces and slashes included) and every other
// character matches itself. Iterative with one backtrack point: linear in
// practice, never exponential.
func globStar(pattern, text string) bool {
	p, t := 0, 0
	star, mark := -1, 0
	for t < len(text) {
		switch {
		case p < len(pattern) && pattern[p] == '*':
			star, mark = p, t
			p++
		case p < len(pattern) && pattern[p] == text[t]:
			p++
			t++
		case star >= 0:
			p = star + 1
			mark++
			t = mark
		default:
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}
