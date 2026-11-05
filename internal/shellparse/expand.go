package shellparse

import (
	"strconv"
	"strings"
	"unicode/utf8"

	"mvdan.cc/sh/v3/syntax"
)

// evalWord expands a word as far as the hook can know statically. It
// returns the expanded text and whether any part stayed unresolved (an
// unknown variable, a substitution, an arithmetic expansion, ~user). For
// unresolved parts the raw source text is kept in place.
func (w *walker) evalWord(word *syntax.Word, sc scope) (string, bool) {
	if word == nil {
		return "", false
	}
	var b strings.Builder
	unresolved := false
	for i, part := range word.Parts {
		s, u := w.evalPart(part, sc, i == 0, false)
		b.WriteString(s)
		unresolved = unresolved || u
	}
	return b.String(), unresolved
}

func (w *walker) evalPart(part syntax.WordPart, sc scope, first, inDouble bool) (string, bool) {
	switch x := part.(type) {
	case *syntax.Lit:
		v := x.Value
		if first && !inDouble && strings.HasPrefix(v, "~") {
			home := w.env["HOME"]
			switch {
			case v == "~" && home != "":
				return home, false
			case strings.HasPrefix(v, "~/") && home != "":
				return home + unescapeLit(v[1:], false), false
			default:
				return v, true // ~user, or no HOME to expand with
			}
		}
		return unescapeLit(v, inDouble), false
	case *syntax.SglQuoted:
		if x.Dollar {
			return ansiC(x.Value), false
		}
		return x.Value, false
	case *syntax.DblQuoted:
		var b strings.Builder
		unresolved := false
		for _, p := range x.Parts {
			s, u := w.evalPart(p, sc, false, true)
			b.WriteString(s)
			unresolved = unresolved || u
		}
		return b.String(), unresolved
	case *syntax.ParamExp:
		if v, ok := w.param(x, sc); ok {
			return v, false
		}
		return w.rawText(x), true
	case *syntax.CmdSubst:
		w.stmts(x.Stmts, sc.clone(), false)
		return w.rawText(x), true
	case *syntax.ProcSubst:
		w.stmts(x.Stmts, sc.clone(), false)
		return w.rawText(x), true
	case *syntax.ExtGlob:
		return w.rawText(x), false
	default:
		return w.rawText(x), true
	}
}

// param resolves the few parameters the hook can know.
func (w *walker) param(x *syntax.ParamExp, sc scope) (string, bool) {
	if x.Param == nil || x.Exp != nil || x.Index != nil || x.Slice != nil ||
		x.Repl != nil || x.Length || x.Excl || x.Width || x.IsSet ||
		x.Names != 0 || x.NestedParam != nil || len(x.Modifiers) > 0 {
		return "", false
	}
	name := x.Param.Value
	switch name {
	case "PWD":
		return sc.cwd, sc.cwd != ""
	case "HOME", "CLAUDE_SKILL_DIR":
		v, ok := w.env[name]
		return v, ok && v != ""
	}
	v, ok := sc.vars[name]
	return v, ok
}

// rawText returns the source text of a node.
func (w *walker) rawText(n syntax.Node) string {
	start, end := n.Pos().Offset(), n.End().Offset()
	if start > end || end > uint(len(w.src)) {
		return ""
	}
	return w.src[start:end]
}

// wordText returns a here-doc body as text: literal parts verbatim,
// expansions as their source text.
func (w *walker) wordText(word *syntax.Word) string {
	var b strings.Builder
	for _, p := range word.Parts {
		if l, ok := p.(*syntax.Lit); ok {
			b.WriteString(l.Value)
		} else {
			b.WriteString(w.rawText(p))
		}
	}
	return b.String()
}

// unescapeLit removes the backslash escapes Bash would remove from a literal.
// Outside double quotes every backslash-X becomes X; inside, only dollar,
// backtick, double quote, backslash and newline may be escaped.
func unescapeLit(v string, inDouble bool) string {
	if !strings.Contains(v, `\`) {
		return v
	}
	var b strings.Builder
	b.Grow(len(v))
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c != '\\' || i+1 >= len(v) {
			b.WriteByte(c)
			continue
		}
		n := v[i+1]
		if inDouble {
			switch n {
			case '$', '`', '"', '\\':
				b.WriteByte(n)
				i++
			case '\n':
				i++
			default:
				b.WriteByte(c)
			}
			continue
		}
		if n != '\n' {
			b.WriteByte(n)
		}
		i++
	}
	return b.String()
}

// ansiC decodes the body of a $'...' string.
func ansiC(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' || i+1 >= len(s) {
			b.WriteByte(c)
			continue
		}
		i++
		switch n := s[i]; n {
		case 'a':
			b.WriteByte('\a')
		case 'b':
			b.WriteByte('\b')
		case 'e', 'E':
			b.WriteByte(0x1b)
		case 'f':
			b.WriteByte('\f')
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		case 'v':
			b.WriteByte('\v')
		case '\\', '\'', '"', '?':
			b.WriteByte(n)
		case 'x':
			j := i + 1
			for j < len(s) && j < i+3 && isHexDigit(s[j]) {
				j++
			}
			if j == i+1 {
				b.WriteString(`\x`)
				continue
			}
			v, _ := strconv.ParseUint(s[i+1:j], 16, 8)
			b.WriteByte(byte(v))
			i = j - 1
		case 'u', 'U':
			width := 4
			if n == 'U' {
				width = 8
			}
			j := i + 1
			for j < len(s) && j < i+1+width && isHexDigit(s[j]) {
				j++
			}
			if j == i+1 {
				b.WriteByte('\\')
				b.WriteByte(n)
				continue
			}
			v, _ := strconv.ParseUint(s[i+1:j], 16, 32)
			if v > utf8.MaxRune {
				v = utf8.RuneError
			}
			b.WriteRune(rune(v))
			i = j - 1
		case '0', '1', '2', '3', '4', '5', '6', '7':
			j := i
			for j < len(s) && j < i+3 && s[j] >= '0' && s[j] <= '7' {
				j++
			}
			v, _ := strconv.ParseUint(s[i:j], 8, 16)
			b.WriteByte(byte(v))
			i = j - 1
		default:
			b.WriteByte('\\')
			b.WriteByte(n)
		}
	}
	return b.String()
}

func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}
