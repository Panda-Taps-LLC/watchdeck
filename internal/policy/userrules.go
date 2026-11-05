package policy

import (
	"github.com/Panda-Taps-LLC/watchdeck/internal/rules"
)

// UserPack is the pack name user and project rules report under.
const UserPack = "user"

// UserRuleField is the rules.Input field a user rule reads for tool: the
// command for Bash, the file path for the file tools, the URL for WebFetch,
// and Text for everything else (the caller puts WebSearch's query, or the
// JSON of another tool's input, there).
func UserRuleField(tool string) string {
	switch tool {
	case "Bash":
		return rules.FieldCommand
	case "WebFetch":
		return rules.FieldURL
	}
	for _, t := range FileTools {
		if t == tool {
			return rules.FieldFilePath
		}
	}
	return rules.FieldText
}

// EvalRules runs the user's and the project's own rules for a call of tool
// and returns the hits, in file order (user first), under pack "user". A
// rule whose regex does not compile (a hand edit; Save refuses one) fails
// closed: a deny or ask rule reports a hit with its action, a log rule is
// skipped. A hit never carries the matched text.
func (p *Policy) EvalRules(tool string, in rules.Input) []rules.Hit {
	if p == nil || len(p.rules) == 0 {
		return nil
	}
	field := UserRuleField(tool)
	var hits []rules.Hit
	for _, r := range p.rules {
		if tier(r.Tool, tool) < 0 {
			continue
		}
		if len(r.Match.Argv0) > 0 && field != rules.FieldCommand {
			continue // argv0 names a program: it applies to Bash only
		}
		m, err := rules.NewMatcher(field, rules.Match{Regex: r.Match.Regex, Literals: r.Match.Literals, Argv0: r.Match.Argv0})
		desc := "from the " + r.Source.String() + " policy file"
		if err != nil {
			if r.Action == "log" {
				continue
			}
			desc = "could not be compiled (" + r.Source.String() + " policy file); failing closed"
		} else if !m.Match(in) {
			continue
		}
		sev := rules.Severity(r.Severity)
		if sev == "" {
			sev = rules.Medium
		}
		hits = append(hits, rules.Hit{
			Pack: UserPack, Version: 0, Rule: r.ID, Field: field,
			Severity: sev, Action: rules.Action(r.Action), Description: desc,
		})
	}
	return hits
}
