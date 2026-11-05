// Package shellparse turns a Bash command string into the list of simple
// commands it would run, each with the working directory it would run in.
//
// It is a recogniser, not an interpreter. It expands only what the hook can
// know statically (~, $HOME, $PWD, ${CLAUDE_SKILL_DIR}, and plain VAR=value
// assignments earlier in the same command) and reports Low confidence for
// anything that could hide a path from a textual reading: command and process
// substitution, eval/source/exec, xargs, find -exec, here-docs, loops,
// unresolved variables in a path position and parse errors.
package shellparse

import (
	"path/filepath"
	"strings"

	"mvdan.cc/sh/v3/syntax"

	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
)

// Confidence says how far the caller may trust Program.Calls.
type Confidence int

const (
	// None: nothing of interest (used by callers; Parse never returns it).
	None Confidence = iota
	// Low: the program contains a construct whose effect cannot be read off
	// the text. Program.Reason says which.
	Low
	// High: every command and path in Program.Calls was read directly from
	// the text after the supported expansions.
	High
)

func (c Confidence) String() string {
	switch c {
	case None:
		return "none"
	case Low:
		return "low"
	case High:
		return "high"
	}
	return "confidence(?)"
}

// Call is one simple command: its argument vector after expansion and the
// working directory it runs in (tracked through `cd X && ...`).
//
// Argv keeps every token as written (leading VAR=value assignments are
// stripped; wrapper prefixes such as `env` or `uv run` are kept).
type Call struct {
	Argv    []string
	Cwd     string
	Assigns []string // names of prefix assignments (FOO=1 cmd); the values are not needed
}

// Program is the result of Parse.
type Program struct {
	Calls      []Call
	Confidence Confidence
	// Reason is empty for High; for Low it names the first construct(s)
	// that lowered confidence.
	Reason string
	// StdinInterpreter is true when an interpreter (python, node, bash, sh,
	// zsh, ruby, perl, ...) reads its program from stdin: `-` as its script
	// argument, `-s` for shells, or no script argument while fed by a pipe,
	// a `<` redirect or a here-doc.
	StdinInterpreter bool
	// HereDocs holds the bodies of here-docs (<<, <<-) and here-strings
	// (<<<), plus inline program text given to an interpreter with -c/-e
	// (python3 -c '...', node -e '...'). The caller decides whether a
	// needle inside one of them matters.
	HereDocs []string
}

// maxNestDepth bounds recursion into `bash -c '...'` strings.
const maxNestDepth = 4

func newParser() *syntax.Parser {
	return syntax.NewParser(syntax.Variant(syntax.LangBash))
}

// Parse parses cmd as Bash. cwd is the directory the command starts in; env
// supplies HOME and CLAUDE_SKILL_DIR for expansion (PWD follows the tracked
// cwd). On a parse error the returned Program has Confidence Low and a
// Reason, and the parser error is returned alongside it.
func Parse(cmd, cwd string, env map[string]string) (*Program, error) {
	return parse(cmd, cwd, env, 0)
}

func parse(cmd, cwd string, env map[string]string, depth int) (*Program, error) {
	prog := &Program{Confidence: High}
	f, err := newParser().Parse(strings.NewReader(cmd), "")
	if err != nil {
		prog.Confidence = Low
		prog.Reason = "parse error: " + err.Error()
		return prog, err
	}
	w := &walker{src: cmd, env: env, prog: prog, depth: depth}
	w.scanSubstitutions(f)
	w.stmts(f.Stmts, newScope(cwd), false)
	return prog, nil
}

// Quote returns s quoted so that Bash reads it back as exactly one word
// equal to s. It wraps syntax.Quote for the Bash dialect. A string holding
// NUL bytes cannot be quoted for any shell; those bytes are dropped first
// (Bash itself discards NUL bytes in command text).
func Quote(s string) string {
	q, err := syntax.Quote(s, syntax.LangBash)
	if err == nil {
		return q
	}
	s = strings.ReplaceAll(s, "\x00", "")
	q, err = syntax.Quote(s, syntax.LangBash)
	if err != nil {
		return "''"
	}
	return q
}

// Unquote is Quote's inverse: it parses s as Bash and returns the value of
// its one word when s is exactly one literal word (quoted or not) with no
// expansion, operator, assignment or redirection; ok is false otherwise.
func Unquote(s string) (string, bool) {
	f, err := newParser().Parse(strings.NewReader(s), "")
	if err != nil || len(f.Stmts) != 1 {
		return "", false
	}
	st := f.Stmts[0]
	if st.Background || st.Negated || st.Coprocess || len(st.Redirs) > 0 {
		return "", false
	}
	call, ok := st.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) != 1 || len(call.Assigns) > 0 {
		return "", false
	}
	return literalWord(call.Args[0])
}

// IsSingleWatchdeckRun reports whether cmd is exactly one simple command
// `watchdeck run ...` (any directory prefix on argv[0]) with no pipes,
// lists, background operator, negation, command or process substitution,
// and (since M6.3) no leading assignment and no redirection: `HOME=/x
// watchdeck run …` or `CLAUDE_CONFIG_DIR=/x watchdeck run …` would move
// the sandbox's home-relative denies, so it is not a lone run. A wrapper
// (`env`, `nice`) is not either: argv[0] must be watchdeck. It is the
// hook's recursion guard: only such a command may pass without a fresh
// decision.
func IsSingleWatchdeckRun(cmd string) bool {
	f, err := newParser().Parse(strings.NewReader(cmd), "")
	if err != nil || len(f.Stmts) != 1 {
		return false
	}
	s := f.Stmts[0]
	if s.Background || s.Negated || s.Coprocess || len(s.Redirs) > 0 {
		return false
	}
	call, ok := s.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) < 2 || len(call.Assigns) > 0 {
		return false
	}
	subst := false
	syntax.Walk(f, func(n syntax.Node) bool {
		switch n.(type) {
		case *syntax.CmdSubst, *syntax.ProcSubst:
			subst = true
		}
		return !subst
	})
	if subst {
		return false
	}
	a0, ok0 := literalWord(call.Args[0])
	a1, ok1 := literalWord(call.Args[1])
	return ok0 && ok1 && filepath.Base(a0) == paths.BinaryName && a1 == "run"
}

// literalWord returns the value of a word made only of literal and quoted
// parts (no expansions of any kind).
func literalWord(w *syntax.Word) (string, bool) {
	var b strings.Builder
	for i, p := range w.Parts {
		switch x := p.(type) {
		case *syntax.Lit:
			v := x.Value
			if i == 0 && strings.HasPrefix(v, "~") {
				return "", false
			}
			b.WriteString(unescapeLit(v, false))
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
					return "", false
				}
				b.WriteString(unescapeLit(l.Value, true))
			}
		default:
			return "", false
		}
	}
	return b.String(), true
}
