package shellparse

import (
	"sort"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// Subcommands for Claude Code permission rules (Plan 02 Task 7).
//
// Claude Code matches a Bash deny or ask rule against each subcommand of a
// command (split on &&, ||, ;, |, |&, & and newlines, including commands
// inside a subshell, a command substitution or a control-flow body), after
// stripping a fixed list of wrappers and, for deny and ask rules, any
// leading VAR=value assignments (code.claude.com/docs/en/permissions,
// read 2026-10-19). Subcommands gives every simple command of the parsed
// text with the spellings such a rule may be matched against. It never
// looks inside a string handed to `sh -c`: the documentation says a rule
// does not match there.

// Subcommand is one simple command (or declaration such as `export X=1`).
type Subcommand struct {
	// Text is the command's source as written, assignments included,
	// redirections that follow its last word excluded.
	Text string
	// Forms are the spellings to match, most literal first: Text, Text
	// without its leading assignments, then the text behind each stripped
	// wrapper; each also with its words joined by single spaces. Duplicates
	// are removed.
	Forms []string
}

// Subcommands parses cmd as Bash and lists every simple command in it,
// at any depth of the syntax tree. A parse error returns it and no list.
func Subcommands(cmd string) ([]Subcommand, error) {
	f, err := newParser().Parse(strings.NewReader(cmd), "")
	if err != nil {
		return nil, err
	}
	cl := newCleaner(cmd, f)
	var out []Subcommand
	var timed []*syntax.CallExpr // calls behind the `time` keyword (a TimeClause, not a word)
	syntax.Walk(f, func(n syntax.Node) bool {
		switch x := n.(type) {
		case *syntax.TimeClause:
			if x.Stmt != nil {
				if c, ok := x.Stmt.Cmd.(*syntax.CallExpr); ok {
					timed = append(timed, c)
				}
			}
		case *syntax.CallExpr:
			afterTime := false
			for _, c := range timed {
				afterTime = afterTime || c == x
			}
			if sc, ok := callSubcommand(cl, x, afterTime); ok {
				out = append(out, sc)
			}
		case *syntax.DeclClause:
			text := span(cmd, x.Pos(), x.End())
			joined := cl.span(x.Pos(), x.End())
			out = append(out, Subcommand{Text: text, Forms: dedupe([]string{text, joined, joinFields(joined)})})
		}
		return true
	})
	return out, nil
}

func span(src string, from, to syntax.Pos) string {
	a, b := int(from.Offset()), int(to.Offset())
	if a < 0 || b > len(src) || a > b {
		return ""
	}
	return src[a:b]
}

// cleaner gives source spans with every line continuation (backslash-
// newline) removed, as bash removes it before splitting words, except
// inside single quotes (plain or $'...'), where bash keeps it. A text
// without a backslash-newline is returned as a plain slice.
type cleaner struct {
	src string
	sq  [][2]int // byte ranges of the single-quoted parts, in source order
	any bool     // src holds a backslash-newline
}

func newCleaner(src string, f *syntax.File) *cleaner {
	c := &cleaner{src: src, any: strings.Contains(src, "\\\n")}
	if !c.any {
		return c
	}
	syntax.Walk(f, func(n syntax.Node) bool {
		if q, ok := n.(*syntax.SglQuoted); ok {
			c.sq = append(c.sq, [2]int{int(q.Pos().Offset()), int(q.End().Offset())})
		}
		return true
	})
	sort.Slice(c.sq, func(i, j int) bool { return c.sq[i][0] < c.sq[j][0] })
	return c
}

func (c *cleaner) span(from, to syntax.Pos) string {
	raw := span(c.src, from, to)
	if !c.any || !strings.Contains(raw, "\\\n") {
		return raw
	}
	a := int(from.Offset())
	var b strings.Builder
	b.Grow(len(raw))
	q := sort.Search(len(c.sq), func(i int) bool { return c.sq[i][1] > a })
	for i := 0; i < len(raw); i++ {
		p := a + i
		for q < len(c.sq) && c.sq[q][1] <= p {
			q++
		}
		if q < len(c.sq) && c.sq[q][0] <= p {
			b.WriteByte(raw[i]) // inside single quotes: literal
			continue
		}
		if raw[i] == '\\' && i+1 < len(raw) {
			if raw[i+1] != '\n' {
				b.WriteByte(raw[i]) // an escape pair (\\ included) is kept whole
				b.WriteByte(raw[i+1])
			}
			i++
			continue
		}
		b.WriteByte(raw[i])
	}
	return b.String()
}

// callSubcommand builds one call's forms. afterWrapper is true when the
// call follows the `time` keyword, which the parser keeps outside it.
func callSubcommand(cl *cleaner, c *syntax.CallExpr, afterWrapper bool) (Subcommand, bool) {
	if len(c.Args) == 0 && len(c.Assigns) == 0 {
		return Subcommand{}, false
	}
	end := c.End()
	text := span(cl.src, c.Pos(), end)
	joined := cl.span(c.Pos(), end)
	forms := []string{text, joined}
	if len(c.Args) == 0 {
		return Subcommand{Text: text, Forms: dedupe(append(forms, joinFields(joined)))}, true
	}
	words := make([]string, len(c.Args))
	lits := make([]string, len(c.Args))
	isLit := make([]bool, len(c.Args))
	lead := make([]string, len(c.Args))
	for i, w := range c.Args {
		words[i] = cl.span(w.Pos(), w.End())
		lits[i], isLit[i] = literalWord(w)
		lead[i] = leadingLiteral(w)
	}
	// spaced is the words joined by single spaces; off[i] is where word i
	// starts in it, so the words from i on are a slice, not a new string.
	spaced := strings.Join(words, " ")
	off := make([]int, len(words))
	for i := 1; i < len(words); i++ {
		off[i] = off[i-1] + len(words[i-1]) + 1
	}
	// addFrom records the text from word at on, as written (line
	// continuations removed) and with single spaces, once per word.
	added := make(map[int]bool)
	addFrom := func(at int) {
		if added[at] {
			return
		}
		added[at] = true
		forms = append(forms, cl.span(c.Args[at].Pos(), end), spaced[off[at]:])
	}
	forms = append(forms, spaced)
	if len(c.Assigns) > 0 {
		forms = append(forms, cl.span(c.Args[0].Pos(), end))
	}
	// strip walks the wrappers from word at. A wrapper may have several
	// readings (stripWrapper), each a candidate for where its command
	// starts; every candidate is a form and is walked in turn. Each
	// stripped wrapper (the `time` keyword counts as one) may be followed
	// by one expanded word (`nice "$N" rm`): that word is tried as the
	// command, and so is the word after it, where stripping resumes, so
	// stacked wrappers chain (`nohup "$X" timeout 5 rm` reaches rm). One
	// skip per wrapper, never two: `nice "$N" "$M" rm` stops at "$M".
	// seen keeps the walk linear when readings converge: a start already
	// walked records no form and is not walked again.
	seen := make(map[int]bool)
	var strip func(at int, skip bool)
	strip = func(at int, skip bool) {
		key := at * 2
		if skip {
			key++
		}
		if seen[key] {
			return
		}
		seen[key] = true
		if at > 0 {
			addFrom(at)
		}
		if !isLit[at] {
			if skip && at+1 < len(c.Args) {
				strip(at+1, false)
			}
			return
		}
		for _, n := range stripWrapper(lits[at:], isLit[at:], lead[at:]) {
			if n > 0 && at+n < len(c.Args) {
				strip(at+n, true)
			}
		}
	}
	strip(0, afterWrapper)
	forms = append(forms, joinFields(joined))
	return Subcommand{Text: text, Forms: dedupe(forms)}, true
}

// stripWrapper returns, for the wrapper at argv[0], each number of words
// it may take (options and operands included) before the command it
// runs, in ascending order, every one of them; nil when argv[0]
// is not a wrapper Claude Code strips, or when no reading of its options
// is possible (an unknown option). lead holds each word's leading literal
// text with quotes removed (leadingLiteral).
//
// Options are read as GNU getopt_long reads them: short options may be
// bundled (`-vs KILL`, `-vsKILL`), a short option's value is the rest of
// its word or else the next word, and a long option may be written as any
// unique prefix of its name (`--sig=KILL`, `--fore`); an ambiguous prefix,
// an unknown option, a value given to an option that takes none
// (`--foreground=x`) or --help/--version runs nothing, so it gives no
// reading. nice's old adjustment spelling (-10) may come first, and the
// options are read on after it (`nice -10 -n 5 rm`).
//
// A word that is not literal (it holds an expansion such as "$T") in a
// value or operand position is consumed like any value, so `timeout "$T"
// curl …` still exposes the curl: an option's separate value is skipped
// unread, an expansion where an option or operand may stand is the
// operand (timeout's duration) unless its leading literal starts with
// "-", and then its option name is read from that literal (`-o"$M"`,
// `"-o$M"`, `--signal="$S"`, `"--signal=$S"`), so quoting cannot hide it.
// A leading literal that names no value-taking option yet may still be
// completed by the expansion (`-"$S"`, `-$N`, `-v"$S"`, `--"$X"`,
// `--sig"$X"`) is one complete option word whose name is expanded; it is
// read both ways, alone (the next word is the operand or the command)
// and with the next word as its value, and each reading is a candidate
// (`timeout -"$S" KILL 5 rm` reaches rm through the value reading, which
// still takes the duration after it). At most one value word per
// expanded option; later words are never tried as the command
// (`timeout 5 echo rm` is echo, not rm).
func stripWrapper(argv []string, lit []bool, lead []string) []int {
	if len(argv) < 2 || !lit[0] {
		return nil
	}
	switch argv[0] {
	case "nohup", "builtin", "noglob":
		if argv[1] == "--" {
			return []int{2}
		}
		return []int{1}
	case "time":
		return optSpec{plain: "p"}.scan(argv, lit, lead, 1)
	case "command":
		if argv[1] == "-v" || argv[1] == "-V" {
			return nil // the query form looks a command up, it does not run it
		}
		return optSpec{plain: "p"}.scan(argv, lit, lead, 1)
	case "xargs":
		if strings.HasPrefix(argv[1], "-") {
			return nil
		}
		return []int{1}
	case "nice":
		// -N (a bare adjustment such as -10) is an old spelling, taken
		// first; the options are read on after it. An expanded one, -$N or
		// -"$N", is an expanded option word for scan.
		i := 1
		for i < len(argv) && lit[i] && len(argv[i]) > 1 && argv[i][0] == '-' && isDigits(argv[i][1:]) {
			i++
		}
		return optSpec{withArg: "n", long: []string{"--adjustment"}}.scan(argv, lit, lead, i)
	case "stdbuf":
		return optSpec{withArg: "ioe", long: []string{"--input", "--output", "--error"}}.scan(argv, lit, lead, 1)
	case "timeout":
		// -f and -p are read as plain flags, so a timeout that spells
		// --foreground and --preserve-status that way is seen through;
		// where timeout rejects them this only matches more.
		var out []int
		for _, n := range (optSpec{withArg: "sk", plain: "vfp",
			long:      []string{"--signal", "--kill-after"},
			plainLong: []string{"--foreground", "--preserve-status", "--verbose"}}).scan(argv, lit, lead, 1) {
			out = append(out, n+1) // the duration
		}
		return out
	}
	return nil
}

// optSpec is one wrapper's options: withArg the short options taking a
// value, plain the short ones without; long the long options taking a
// value (--name=value or --name value), plainLong the long ones without.
// --help and --version are known to every wrapper and run nothing.
type optSpec struct {
	withArg, plain  string
	long, plainLong []string
}

const (
	longNone  = iota // unknown, ambiguous, or one that runs nothing
	longValue        // takes a value
	longPlain        // takes none
)

// resolveLong reads a long option name as getopt_long does: an exact name
// wins, else a prefix of exactly one name.
func (o optSpec) resolveLong(name string) int {
	kind, hits := longNone, 0
	for _, set := range []struct {
		names []string
		kind  int
	}{{o.long, longValue}, {o.plainLong, longPlain}, {[]string{"--help", "--version"}, longNone}} {
		for _, n := range set.names {
			if n == name {
				return set.kind
			}
			if strings.HasPrefix(n, name) {
				kind, hits = set.kind, hits+1
			}
		}
	}
	if hits != 1 {
		return longNone
	}
	return kind
}

// longPrefix reports whether name (a leading literal cut short by an
// expansion) could still become a value-taking long option.
func (o optSpec) longPrefix(name string) bool {
	for _, n := range o.long {
		if strings.HasPrefix(n, name) {
			return true
		}
	}
	return false
}

const (
	shortBad   = iota // an unknown short option
	shortPlain        // only options without a value
	shortValue        // a value-taking option; attached reports its value is in the word
)

// short reads a cluster of short options (the word without its "-").
func (o optSpec) short(cluster string) (kind int, attached bool) {
	for j := 0; j < len(cluster); j++ {
		switch {
		case strings.IndexByte(o.plain, cluster[j]) >= 0:
		case strings.IndexByte(o.withArg, cluster[j]) >= 0:
			return shortValue, j+1 < len(cluster)
		default:
			return shortBad, false
		}
	}
	return shortPlain, false
}

// scan reads the options from argv[from] and returns the index of the
// first word after them, one per reading, ascending. Every reading is
// returned: dropping one could drop the one a deny rule matches. The work
// stays linear because each word is scanned once (seen).
func (o optSpec) scan(argv []string, lit []bool, lead []string, from int) []int {
	ends := make(map[int]bool)
	seen := make(map[int]bool)
	var walk func(i int)
	walk = func(i int) {
		for i < len(argv) {
			if seen[i] {
				return
			}
			seen[i] = true
			a := argv[i]
			if !lit[i] {
				l := lead[i]
				if !strings.HasPrefix(l, "-") {
					ends[i] = true // an expansion as the operand
					return
				}
				if strings.HasPrefix(l, "--") {
					name, _, hasVal := strings.Cut(l, "=")
					switch {
					case hasVal && o.resolveLong(name) == longValue:
						i++ // --signal="$S": the value is in the word
						continue
					case !hasVal && (l == "--" || o.longPrefix(name)):
						walk(i + 2) // --"$X", --sig"$X": alone or with a value
						i++
						continue
					}
					return
				}
				switch k, attached := o.short(l[1:]); k {
				case shortValue:
					// -o"$M", -vs"$S": the value is in the word, or, when
					// the expansion is empty, the next word.
					if !attached {
						walk(i + 2)
					}
					i++
					continue
				case shortPlain:
					walk(i + 2) // -"$S", -v"$S": alone or with a value
					i++
					continue
				}
				return
			}
			switch {
			case a == "--":
				ends[i+1] = true
				return
			case !strings.HasPrefix(a, "-") || a == "-":
				ends[i] = true
				return
			case strings.HasPrefix(a, "--"):
				name, _, hasVal := strings.Cut(a, "=")
				switch o.resolveLong(name) {
				case longValue:
					if hasVal {
						i++
					} else {
						i += 2
					}
				case longPlain:
					if hasVal {
						return // --foreground=x: an error, nothing runs
					}
					i++
				default:
					return
				}
			default:
				switch k, attached := o.short(a[1:]); {
				case k == shortPlain:
					i++
				case k == shortValue && attached:
					i++ // -oL, -vsKILL
				case k == shortValue:
					i += 2 // -o L, -vs KILL
				default:
					return
				}
			}
		}
	}
	walk(from)
	var out []int
	for i := range ends {
		if i < len(argv) {
			out = append(out, i)
		}
	}
	sort.Ints(out)
	return out
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func joinFields(s string) string { return strings.Join(strings.Fields(s), " ") }

func dedupe(in []string) []string {
	out := in[:0]
	seen := make(map[string]bool, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// leadingLiteral is the literal text a word starts with, quotes removed,
// up to its first expansion: `"-o$M"` and `-o"$M"` both give "-o".
func leadingLiteral(w *syntax.Word) string {
	var b strings.Builder
	for _, p := range w.Parts {
		switch x := p.(type) {
		case *syntax.Lit:
			b.WriteString(unescapeLit(x.Value, false))
		case *syntax.SglQuoted:
			if x.Dollar {
				b.WriteString(ansiC(x.Value))
			} else {
				b.WriteString(x.Value)
			}
		case *syntax.DblQuoted:
			for _, q := range x.Parts {
				l, ok := q.(*syntax.Lit)
				if !ok {
					return b.String()
				}
				b.WriteString(unescapeLit(l.Value, true))
			}
		default:
			return b.String()
		}
	}
	return b.String()
}
