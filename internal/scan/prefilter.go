package scan

import (
	"bytes"
	"regexp/syntax"
	"unicode"
)

// requiredLiterals derives, from a regex, a set of byte strings such that any
// line matching the regex must contain at least one of them. It is used as a
// cheap pre-filter (bytes.Contains runs far faster than regexp). The result is
// nil when nothing safe can be derived, in which case the regex always runs.
//
// Rules: a concatenation requires every literal run inside it (we keep the
// longest); an alternation requires one of its branches' literals (all
// branches must yield one); optional or starred nodes contribute nothing;
// case-folded literals are skipped unless they contain no letters.
func requiredLiterals(expr string) [][]byte {
	re, err := syntax.Parse(expr, syntax.Perl)
	if err != nil {
		return nil
	}
	lits := required(re.Simplify())
	if len(lits) == 0 {
		return nil
	}
	// All or nothing: the set is a disjunction, so dropping one entry would
	// reject lines that only match through it. A short entry (the parser
	// factors "chmod|chown|crontab" into "c(h(mod|own)|rontab)") makes the
	// whole filter useless, so the regex runs unfiltered instead.
	out := make([][]byte, 0, len(lits))
	for _, l := range lits {
		if len(l) < minLiteral {
			return nil
		}
		out = append(out, []byte(l))
	}
	return out
}

// minLiteral is the shortest literal worth filtering on.
const minLiteral = 3

// required returns an "any-of" set: the line must contain at least one entry.
// An empty set means "no constraint".
func required(re *syntax.Regexp) []string {
	switch re.Op {
	case syntax.OpLiteral:
		if re.Flags&syntax.FoldCase != 0 {
			for _, r := range re.Rune {
				if unicode.IsLetter(r) {
					return nil
				}
			}
		}
		return []string{string(re.Rune)}
	case syntax.OpCapture:
		return required(re.Sub[0])
	case syntax.OpPlus:
		return required(re.Sub[0])
	case syntax.OpRepeat:
		if re.Min >= 1 {
			return required(re.Sub[0])
		}
		return nil
	case syntax.OpConcat:
		// Join adjacent literals into longer runs, then keep the longest
		// single-literal constraint; an any-of set from a child is kept only
		// if no single literal exists.
		var best []string
		var run []rune
		flush := func() {
			if len(run) > 0 {
				s := string(run)
				if len(best) != 1 || len(s) > len(best[0]) {
					if len(best) <= 1 {
						best = []string{s}
					} else if len(s) >= 3 {
						best = []string{s}
					}
				}
				run = nil
			}
		}
		for _, sub := range re.Sub {
			if sub.Op == syntax.OpLiteral && sub.Flags&syntax.FoldCase == 0 {
				run = append(run, sub.Rune...)
				continue
			}
			flush()
			if got := required(sub); len(got) > 0 {
				if len(got) == 1 {
					if len(best) != 1 || len(got[0]) > len(best[0]) {
						best = got
					}
				} else if len(best) == 0 {
					best = got
				}
			}
		}
		flush()
		return best
	case syntax.OpAlternate:
		var set []string
		for _, sub := range re.Sub {
			got := required(sub)
			if len(got) == 0 {
				return nil
			}
			set = append(set, got...)
		}
		return set
	}
	return nil
}

func anyContains(line []byte, lits [][]byte) bool {
	for _, l := range lits {
		if bytes.Contains(line, l) {
			return true
		}
	}
	return false
}
