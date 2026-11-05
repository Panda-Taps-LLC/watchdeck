// Package copylint finds banned words in the text a person reads: the
// dashboard's string literals, the shell's text and labels, the CLI usage
// text and the plugin's SKILL.md files. The words are internal vocabulary
// ("hook", "matcher", "nonce", ...) that the product never puts on screen.
//
// Scan understands just enough of each format to look only at what is
// shown: in JavaScript the string and template literals (not identifiers,
// comments or regular expressions); in HTML the text nodes and the title,
// aria-label and placeholder attributes (not other attributes, scripts or
// styles); in Markdown and plain text everything outside fenced code
// blocks.
//
// The package is init-free like every package near the hook binary:
// constants, plain functions and one lazyre.Regexp.
package copylint

import (
	"path/filepath"
	"strings"

	"github.com/Panda-Taps-LLC/watchdeck/internal/lazyre"
)

// bannedRe matches a banned word, whole word, case-insensitive.
var bannedRe = lazyre.Regexp{Expr: `(?i)\b(hooks?|no\s+opinion|ungranted|subject|gate|matcher|profile\s+hash|pretooluse|classifier|nonce)\b`}

// Banned returns the banned words in a fixed order. "hook" also covers
// "hooks". Each call returns a new slice.
func Banned() []string {
	return []string{"no opinion", "ungranted", "subject", "gate", "matcher", "profile hash", "hook", "PreToolUse", "classifier", "nonce"}
}

// Hit is one banned word found in a file.
type Hit struct {
	File string // the name passed to Scan
	Line int    // 1-based line of the word
	Word string // the word as written in the source
	Text string // the literal, text node or line that holds it (trimmed, at most 120 bytes)
}

// Scan returns the banned words in src, read according to name's extension:
// .js, .mjs, .html, .htm, .md, .markdown, .txt. Any other extension yields
// nothing.
func Scan(name string, src []byte) []Hit {
	s := &scanner{name: name, src: src}
	switch strings.ToLower(filepath.Ext(name)) {
	case ".js", ".mjs":
		s.js()
	case ".html", ".htm":
		s.html()
	case ".md", ".markdown", ".txt":
		s.text()
	}
	return s.hits
}

type scanner struct {
	name string
	src  []byte
	hits []Hit
}

// check reports every banned word in src[start:end]. Backslash escapes are
// blanked first (same length, so offsets keep their lines): "\nhook" is
// read as "  hook".
func (s *scanner) check(start, end int) {
	if start >= end {
		return
	}
	body := []byte(string(s.src[start:end]))
	if s.escapes() {
		for i := 0; i < len(body); i++ {
			if body[i] == '\\' && i+1 < len(body) {
				body[i], body[i+1] = ' ', ' '
				i++
			}
		}
	}
	text := strings.TrimSpace(string(s.src[start:end]))
	if len(text) > 120 {
		text = text[:120]
	}
	for _, m := range bannedRe.Get().FindAllIndex(body, -1) {
		s.hits = append(s.hits, Hit{
			File: s.name,
			Line: s.lineAt(start + m[0]),
			Word: string(s.src[start+m[0] : start+m[1]]),
			Text: text,
		})
	}
}

func (s *scanner) escapes() bool {
	ext := strings.ToLower(filepath.Ext(s.name))
	return ext == ".js" || ext == ".mjs"
}

func (s *scanner) lineAt(off int) int {
	n := 1
	for _, c := range s.src[:off] {
		if c == '\n' {
			n++
		}
	}
	return n
}

// ---------------------------------------------------------------- JavaScript

// prevKind is the class of the previous significant token, which decides
// whether a "/" starts a regular expression or divides.
type prevKind int

const (
	prevStart    prevKind = iota // start of input: a regex may follow
	prevOperator                 // a punctuator or keyword after which a regex may follow
	prevValue                    // an identifier, number, literal, ")" or "]": "/" divides
)

func (s *scanner) js() {
	s.code(0, false)
}

// code scans JavaScript from i. With inTemplate set it stops after the "}"
// that closes a template literal's "${" and returns the index after it;
// otherwise it runs to the end of input.
func (s *scanner) code(i int, inTemplate bool) int {
	src := s.src
	prev := prevStart
	depth := 0
	for i < len(src) {
		c := src[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '/' && i+1 < len(src) && src[i+1] == '/':
			for i < len(src) && src[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < len(src) && src[i+1] == '*':
			end := strings.Index(string(src[i+2:]), "*/")
			if end < 0 {
				return len(src)
			}
			i += 2 + end + 2
		case c == '"' || c == '\'':
			i = s.quoted(i, c)
			prev = prevValue
		case c == '`':
			i = s.template(i)
			prev = prevValue
		case c == '/':
			if prev == prevValue {
				i++
				prev = prevOperator
			} else {
				i = skipRegex(src, i)
				prev = prevValue
			}
		case c == '{':
			depth++
			i++
			prev = prevOperator
		case c == '}':
			if inTemplate && depth == 0 {
				return i + 1
			}
			depth--
			i++
			prev = prevOperator
		case c == ')' || c == ']':
			i++
			prev = prevValue
		case isIdentStart(c) || isDigit(c):
			j := i
			for j < len(src) && (isIdentPart(src[j]) || src[j] == '.' && isDigit(src[i])) {
				j++
			}
			if regexKeyword(string(src[i:j])) {
				prev = prevOperator
			} else {
				prev = prevValue
			}
			i = j
		case c == '.':
			// Member access: the next token is a property name, a value.
			i++
			prev = prevOperator
		default:
			// ( , = : [ ! & | ? ; + - * % < > ~ ^ and anything else.
			i++
			prev = prevOperator
		}
	}
	return i
}

// quoted scans a '...' or "..." literal starting at i and checks its body.
func (s *scanner) quoted(i int, q byte) int {
	src := s.src
	start := i + 1
	j := start
	for j < len(src) && src[j] != q && src[j] != '\n' {
		if src[j] == '\\' {
			j++
		}
		j++
	}
	if j > len(src) {
		j = len(src)
	}
	s.check(start, j)
	if j < len(src) {
		j++
	}
	return j
}

// template scans a `...` literal starting at i: the text between
// substitutions is checked, each ${...} is scanned as code.
func (s *scanner) template(i int) int {
	src := s.src
	j := i + 1
	chunk := j
	for j < len(src) {
		switch {
		case src[j] == '\\':
			j += 2
		case src[j] == '`':
			s.check(chunk, j)
			return j + 1
		case src[j] == '$' && j+1 < len(src) && src[j+1] == '{':
			s.check(chunk, j)
			j = s.code(j+2, true)
			chunk = j
		default:
			j++
		}
	}
	if j > len(src) {
		j = len(src)
	}
	s.check(chunk, j)
	return j
}

// skipRegex skips a regular expression literal starting at i (the "/"),
// including a character class that may hold "/", and its flags.
func skipRegex(src []byte, i int) int {
	j := i + 1
	class := false
	for j < len(src) && src[j] != '\n' {
		c := src[j]
		if c == '\\' {
			j += 2
			continue
		}
		if c == '[' {
			class = true
		} else if c == ']' {
			class = false
		} else if c == '/' && !class {
			j++
			for j < len(src) && isIdentPart(src[j]) {
				j++
			}
			return j
		}
		j++
	}
	return j
}

// regexKeyword reports the keywords after which a "/" starts a regex.
func regexKeyword(w string) bool {
	switch w {
	case "return", "typeof", "case", "do", "else", "in", "instanceof", "new", "void", "delete", "throw":
		return true
	}
	return false
}

func isIdentStart(c byte) bool {
	return c == '_' || c == '$' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= 0x80
}

func isIdentPart(c byte) bool { return isIdentStart(c) || isDigit(c) }

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// ---------------------------------------------------------------- HTML

// html checks text nodes and the title, aria-label and placeholder
// attributes. Comments, <script> and <style> bodies, and every other
// attribute are skipped.
func (s *scanner) html() {
	src := s.src
	low := strings.ToLower(string(src))
	i := 0
	for i < len(src) {
		if src[i] != '<' {
			j := strings.IndexByte(low[i:], '<')
			if j < 0 {
				j = len(src) - i
			}
			s.check(i, i+j)
			i += j
			continue
		}
		if strings.HasPrefix(low[i:], "<!--") {
			end := strings.Index(low[i+4:], "-->")
			if end < 0 {
				return
			}
			i += 4 + end + 3
			continue
		}
		end := s.tag(i)
		opening := !strings.HasPrefix(low[i+1:end], "/")
		name := tagName(low[i+1 : end])
		i = end
		if opening && (name == "script" || name == "style") {
			close := strings.Index(low[i:], "</"+name)
			if close < 0 {
				return
			}
			i += close
		}
	}
}

// tag scans the tag starting at i ("<"), checks the shown attributes and
// returns the index after its ">".
func (s *scanner) tag(i int) int {
	src := s.src
	j := i + 1
	for j < len(src) && src[j] != '>' {
		c := src[j]
		if !isAttrNameByte(c) {
			j++
			continue
		}
		k := j
		for k < len(src) && isAttrNameByte(src[k]) {
			k++
		}
		attr := strings.ToLower(string(src[j:k]))
		j = k
		for j < len(src) && (src[j] == ' ' || src[j] == '\t' || src[j] == '\n') {
			j++
		}
		if j >= len(src) || src[j] != '=' {
			continue
		}
		j++
		for j < len(src) && (src[j] == ' ' || src[j] == '\t' || src[j] == '\n') {
			j++
		}
		if j >= len(src) {
			break
		}
		var vs, ve int
		if q := src[j]; q == '"' || q == '\'' {
			vs = j + 1
			ve = vs
			for ve < len(src) && src[ve] != q {
				ve++
			}
			j = ve + 1
		} else {
			vs = j
			ve = j
			for ve < len(src) && src[ve] != ' ' && src[ve] != '>' && src[ve] != '\n' {
				ve++
			}
			j = ve
		}
		switch attr {
		case "title", "aria-label", "placeholder":
			s.check(vs, min(ve, len(src)))
		}
	}
	if j < len(src) {
		j++
	}
	return j
}

func tagName(t string) string {
	t = strings.TrimPrefix(t, "/")
	k := 0
	for k < len(t) && (t[k] >= 'a' && t[k] <= 'z' || isDigit(t[k]) || t[k] == '-') {
		k++
	}
	return t[:k]
}

func isAttrNameByte(c byte) bool {
	return c == '-' || c == '_' || c == ':' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || isDigit(c)
}

// ---------------------------------------------------------------- Markdown, text

// text checks every line outside fenced code blocks (``` or ~~~ fences).
func (s *scanner) text() {
	src := s.src
	fence := ""
	for i := 0; i < len(src); {
		j := i
		for j < len(src) && src[j] != '\n' {
			j++
		}
		line := strings.TrimLeft(string(src[i:j]), " ")
		switch {
		case fence != "":
			if strings.HasPrefix(line, fence) {
				fence = ""
			}
		case strings.HasPrefix(line, "```"):
			fence = "```"
		case strings.HasPrefix(line, "~~~"):
			fence = "~~~"
		default:
			s.check(i, j)
		}
		i = j + 1
	}
}
