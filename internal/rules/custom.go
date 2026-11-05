package rules

import (
	"fmt"
	"regexp"
)

// Matcher is a compiled matcher for one policy-file rule (M6.3): the user's
// own `rules:` entries, which internal/policy validates and the hook
// evaluates next to the built-in packs. It uses the same matching as a pack
// rule (literal pre-filter, argv0 command position, field caps), but the
// caller picks the field and decides which tools the rule applies to, so a
// rule may name any tool pattern (mcp__github__*), not only the tools the
// packs know.
type Matcher struct {
	c *compiled
}

// NewMatcher compiles m for field (command, file_path, content, url or
// text). The regex is compiled here, so an invalid one is an error now and
// never a panic later.
func NewMatcher(field string, m Match) (*Matcher, error) {
	m.Field = field
	c, err := newCompiled(&Rule{Tool: "*", Match: m})
	if err != nil {
		return nil, err
	}
	if c.re.Expr != "" {
		if _, err := regexp.Compile(c.re.Expr); err != nil {
			return nil, fmt.Errorf("match.regex: does not compile")
		}
	}
	return &Matcher{c: c}, nil
}

// Match reports whether in matches. A nil Matcher never matches.
func (m *Matcher) Match(in Input) bool {
	if m == nil || m.c == nil {
		return false
	}
	var f fieldCache
	return m.c.match(&f, in)
}

// Field is the input field the matcher reads.
func (m *Matcher) Field() string {
	if m == nil || m.c == nil {
		return ""
	}
	return m.c.field
}
