package shellparse

import (
	"fmt"
	"path/filepath"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// scope is the state that flows from one statement to the next: the tracked
// working directory and the plain VAR=value assignments seen so far.
type scope struct {
	cwd  string
	vars map[string]string
}

func newScope(cwd string) scope {
	return scope{cwd: cwd, vars: map[string]string{}}
}

// clone returns a copy for a subshell: changes inside do not escape.
func (s scope) clone() scope {
	vars := make(map[string]string, len(s.vars))
	for k, v := range s.vars {
		vars[k] = v
	}
	return scope{cwd: s.cwd, vars: vars}
}

type walker struct {
	src   string
	env   map[string]string
	prog  *Program
	depth int
}

func (w *walker) low(reason string) {
	w.prog.Confidence = Low
	switch {
	case w.prog.Reason == "":
		w.prog.Reason = reason
	case strings.Contains(w.prog.Reason, reason):
	default:
		w.prog.Reason += "; " + reason
	}
}

// scanSubstitutions lowers confidence for command and process substitution
// anywhere in the tree: argument words, redirect targets, assignment values,
// unquoted here-doc bodies.
func (w *walker) scanSubstitutions(f *syntax.File) {
	syntax.Walk(f, func(n syntax.Node) bool {
		switch x := n.(type) {
		case *syntax.CmdSubst:
			if x.Backquotes {
				w.low("backtick command substitution")
			} else {
				w.low("command substitution $(...)")
			}
		case *syntax.ProcSubst:
			w.low("process substitution")
		}
		return true
	})
}

func (w *walker) stmts(list []*syntax.Stmt, sc scope, piped bool) scope {
	for _, s := range list {
		sc = w.stmt(s, sc, piped)
	}
	return sc
}

// stmt walks one statement. piped is true when the statement's stdin is the
// output of a pipe. It returns the scope the next statement starts in.
func (w *walker) stmt(s *syntax.Stmt, sc scope, piped bool) scope {
	if s == nil {
		return sc
	}
	fed := piped
	for _, r := range s.Redirs {
		switch r.Op {
		case syntax.Hdoc, syntax.DashHdoc:
			if r.N == nil || r.N.Value == "0" {
				fed = true
			}
			if r.Hdoc != nil {
				body := w.wordText(r.Hdoc)
				if r.Op == syntax.DashHdoc {
					body = stripLeadingTabs(body)
				}
				w.prog.HereDocs = append(w.prog.HereDocs, body)
			}
		case syntax.WordHdoc:
			if r.N == nil || r.N.Value == "0" {
				fed = true
			}
			if r.Word != nil {
				v, _ := w.evalWord(r.Word, sc)
				w.prog.HereDocs = append(w.prog.HereDocs, v)
			}
		case syntax.RdrIn, syntax.RdrInOut:
			if r.N == nil || r.N.Value == "0" {
				fed = true
			}
			if r.Word != nil {
				w.evalWord(r.Word, sc) // walks any nested statements
			}
		default:
			if r.Word != nil {
				w.evalWord(r.Word, sc)
			}
		}
	}
	switch c := s.Cmd.(type) {
	case nil:
		return sc
	case *syntax.CallExpr:
		return w.call(c, sc, fed)
	case *syntax.BinaryCmd:
		if c.Op == syntax.Pipe || c.Op == syntax.PipeAll {
			sc = w.stmt(c.X, sc, piped)
			return w.stmt(c.Y, sc, true)
		}
		sc = w.stmt(c.X, sc, false)
		return w.stmt(c.Y, sc, false)
	case *syntax.Subshell:
		w.stmts(c.Stmts, sc.clone(), fed)
		return sc
	case *syntax.Block:
		return w.stmts(c.Stmts, sc, fed)
	case *syntax.IfClause:
		for ic := c; ic != nil; ic = ic.Else {
			sc = w.stmts(ic.Cond, sc, false)
			sc = w.stmts(ic.Then, sc, false)
		}
		return sc
	case *syntax.WhileClause:
		w.low("shell loop (while/until)")
		sc = w.stmts(c.Cond, sc, false)
		return w.stmts(c.Do, sc, false)
	case *syntax.ForClause:
		w.low("shell loop (for)")
		if wi, ok := c.Loop.(*syntax.WordIter); ok {
			for _, item := range wi.Items {
				w.evalWord(item, sc)
			}
		}
		return w.stmts(c.Do, sc, false)
	case *syntax.CaseClause:
		if c.Word != nil {
			w.evalWord(c.Word, sc)
		}
		for _, item := range c.Items {
			for _, p := range item.Patterns {
				w.evalWord(p, sc)
			}
			sc = w.stmts(item.Stmts, sc, false)
		}
		return sc
	case *syntax.FuncDecl:
		w.stmt(c.Body, sc.clone(), false)
		return sc
	case *syntax.DeclClause:
		for _, a := range c.Args {
			w.assign(a, sc, true)
		}
		return sc
	case *syntax.TimeClause:
		return w.stmt(c.Stmt, sc, fed)
	case *syntax.CoprocClause:
		w.stmt(c.Stmt, sc.clone(), fed)
		return sc
	case *syntax.ArithmCmd, *syntax.LetClause, *syntax.TestClause:
		// Substitutions inside were caught by scanSubstitutions.
		return sc
	default:
		return sc
	}
}

// assign records a plain `NAME=value` in the scope when the value is fully
// resolved. record is false for assignments that prefix a command
// (`FOO=1 cmd`), which only affect that command's environment.
func (w *walker) assign(a *syntax.Assign, sc scope, record bool) {
	if a == nil {
		return
	}
	if a.Array != nil {
		for _, e := range a.Array.Elems {
			if e.Value != nil {
				w.evalWord(e.Value, sc)
			}
		}
		return
	}
	if a.Value == nil {
		return
	}
	v, unresolved := w.evalWord(a.Value, sc)
	if record && a.Name != nil && !a.Append && a.Index == nil && !a.Naked {
		if unresolved {
			delete(sc.vars, a.Name.Value)
		} else {
			sc.vars[a.Name.Value] = v
		}
	}
}

func (w *walker) call(c *syntax.CallExpr, sc scope, fed bool) scope {
	for _, a := range c.Assigns {
		w.assign(a, sc, len(c.Args) == 0)
	}
	if len(c.Args) == 0 {
		return sc
	}
	argv := make([]string, len(c.Args))
	unresolved := make([]bool, len(c.Args))
	for i, word := range c.Args {
		argv[i], unresolved[i] = w.evalWord(word, sc)
	}
	for i := range argv {
		if unresolved[i] && (i == 0 || strings.Contains(argv[i], "/")) {
			w.low(fmt.Sprintf("unresolved expansion in path position: %s", argv[i]))
		}
	}
	var assigns []string
	for _, a := range c.Assigns {
		if a.Name != nil {
			assigns = append(assigns, a.Name.Value)
		}
	}
	// Everything below looks at the command behind wrapper prefixes.
	cmd, cmdUnresolved, chdir, chdirUnresolved := stripWrappers(argv, unresolved)

	// `env -C DIR cmd` runs cmd in DIR; the shell's own cwd is unchanged.
	callSc := sc
	switch {
	case chdirUnresolved:
		w.low("env -C to an unresolved path: " + chdir)
	case chdir != "":
		if !filepath.IsAbs(chdir) {
			chdir = filepath.Join(sc.cwd, chdir)
		}
		callSc.cwd = filepath.Clean(chdir)
	}
	w.prog.Calls = append(w.prog.Calls, Call{Argv: argv, Cwd: callSc.cwd, Assigns: assigns})
	if len(cmd) == 0 {
		return sc
	}
	base := baseName(cmd[0])
	switch base {
	case "cd", "pushd":
		return w.cd(cmd, cmdUnresolved, sc, assigns)
	case "popd":
		w.low("popd (previous directory unknown)")
	case "eval":
		w.low("eval")
	case "source", ".":
		w.low("source")
	case "exec":
		w.low("exec builtin")
	case "xargs":
		w.low("xargs")
	case "find":
		for _, a := range cmd[1:] {
			switch a {
			case "-exec", "-execdir", "-ok", "-okdir":
				w.low("find -exec")
			}
		}
	}
	if isInterpreter(base) {
		w.interpreter(base, cmd, cmdUnresolved, callSc, fed)
	}
	return sc
}

// cd tracks the new working directory. assigns are the call's prefix
// assignment names (`CDPATH=x cd y` searches x).
func (w *walker) cd(cmd []string, unresolved []bool, sc scope, assigns []string) scope {
	idx := -1
	for i := 1; i < len(cmd); i++ {
		if cmd[i] == "--" {
			if i+1 < len(cmd) {
				idx = i + 1
			}
			break
		}
		if strings.HasPrefix(cmd[i], "-") && cmd[i] != "-" {
			continue // -P, -L, -e, -@
		}
		idx = i
		break
	}
	if idx < 0 {
		home := w.env["HOME"]
		if home == "" {
			w.low("cd with no argument and no HOME")
			return sc
		}
		sc.cwd = filepath.Clean(home)
		return sc
	}
	target := cmd[idx]
	switch {
	case unresolved[idx]:
		w.low("cd to an unresolved path: " + target)
		return sc
	case target == "-":
		w.low("cd - (previous directory unknown)")
		return sc
	case target == "":
		return sc
	case w.cdpathSet(sc, assigns) && !filepath.IsAbs(target) && !dotRelative(target):
		// bash searches CDPATH before the cwd for such a target.
		w.low("cd with CDPATH set (target directory unknown)")
		return sc
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(sc.cwd, target)
	}
	sc.cwd = filepath.Clean(target)
	return sc
}

// cdpathSet reports whether the command sets CDPATH for this call: a prefix
// assignment or an earlier assignment in the program. The hook's own
// environment is not the Bash tool's shell, and a CDPATH exported in the
// person's dotfiles would otherwise downgrade every `cd x && <abs script>`.
func (w *walker) cdpathSet(sc scope, assigns []string) bool {
	for _, a := range assigns {
		if a == "CDPATH" {
			return true
		}
	}
	return sc.vars["CDPATH"] != ""
}

// dotRelative reports whether a cd target starts with `.` or `..`, which
// bash resolves without consulting CDPATH.
func dotRelative(t string) bool {
	return t == "." || t == ".." || strings.HasPrefix(t, "./") || strings.HasPrefix(t, "../")
}

// stripWrappers drops prefixes that do not change which program runs:
// `env [VAR=v...]`, `command`, `builtin`, `nohup`, `time`, `uv run`,
// `poetry run`, `pipenv run`. chdir is the directory of the last
// `env -C DIR` / `env --chdir=DIR` seen ("" for none), and chdirUnresolved
// whether that word held an unresolved expansion.
func stripWrappers(argv []string, unresolved []bool) (cmd []string, cmdUnresolved []bool, chdir string, chdirUnresolved bool) {
	for len(argv) > 0 {
		switch baseName(argv[0]) {
		case "env":
			i := 1
			for i < len(argv) {
				a := argv[i]
				switch {
				case a == "-i" || a == "-" || a == "--ignore-environment":
					i++
				case a == "-C" || a == "--chdir":
					if i+1 < len(argv) {
						chdir, chdirUnresolved = argv[i+1], unresolved[i+1]
					}
					i += 2
				case strings.HasPrefix(a, "--chdir="):
					chdir, chdirUnresolved = strings.TrimPrefix(a, "--chdir="), unresolved[i]
					i++
				case strings.HasPrefix(a, "-C"):
					chdir, chdirUnresolved = strings.TrimPrefix(a, "-C"), unresolved[i]
					i++
				case a == "-u" || a == "--unset":
					i += 2
				case !strings.HasPrefix(a, "-") && strings.Contains(a, "="):
					i++
				default:
					goto done
				}
			}
		done:
			if i > len(argv) {
				i = len(argv)
			}
			argv, unresolved = argv[i:], unresolved[i:]
		case "command", "builtin", "nohup", "time":
			argv, unresolved = argv[1:], unresolved[1:]
		case "uv", "poetry", "pipenv":
			if len(argv) >= 2 && argv[1] == "run" {
				argv, unresolved = argv[2:], unresolved[2:]
			} else {
				return argv, unresolved, chdir, chdirUnresolved
			}
		default:
			return argv, unresolved, chdir, chdirUnresolved
		}
	}
	return argv, unresolved, chdir, chdirUnresolved
}

// stripLeadingTabs applies the `<<-` rule: leading tabs are removed from
// every line of the body (mvdan keeps them in the AST).
func stripLeadingTabs(body string) string {
	lines := strings.Split(body, "\n")
	for i, l := range lines {
		lines[i] = strings.TrimLeft(l, "\t")
	}
	return strings.Join(lines, "\n")
}

func baseName(s string) string {
	if !strings.Contains(s, "/") {
		return s
	}
	return filepath.Base(s)
}

// Interpreter handling.

func isShell(base string) bool {
	switch base {
	case "bash", "sh", "zsh", "dash", "ksh":
		return true
	}
	return false
}

func isInterpreter(base string) bool {
	if isShell(base) {
		return true
	}
	switch {
	case strings.HasPrefix(base, "python"):
		return true
	case base == "node", base == "nodejs", base == "ruby", base == "perl":
		return true
	}
	return false
}

type operandKind int

const (
	opNone   operandKind = iota // no program given (interactive, or stdin when fed)
	opStdin                     // explicit `-` or shell `-s`
	opInline                    // -c/-e code string
	opScript                    // a script path or a module
)

// interpreterOperand finds what program the interpreter would run.
func interpreterOperand(base string, cmd []string) (kind operandKind, operand string, idx int) {
	takesValue := func(a string) bool {
		switch {
		case isShell(base):
			return a == "-o" || a == "--rcfile" || a == "--init-file"
		case strings.HasPrefix(base, "python"):
			return a == "-W" || a == "-X" || a == "-Q"
		case base == "node" || base == "nodejs":
			switch a {
			case "-r", "--require", "--import", "--loader", "--experimental-loader",
				"--input-type", "-C", "--conditions", "--title", "--stack-size":
				return true
			}
		case base == "ruby":
			return a == "-r" || a == "-I" || a == "-C" || a == "-E" || a == "-F"
		case base == "perl":
			return a == "-I" || a == "-M" || a == "-m"
		}
		return false
	}
	for i := 1; i < len(cmd); i++ {
		a := cmd[i]
		switch {
		case a == "-":
			return opStdin, "", i
		case a == "--":
			if i+1 < len(cmd) {
				return opScript, cmd[i+1], i + 1
			}
			return opNone, "", -1
		case !strings.HasPrefix(a, "-"):
			return opScript, a, i
		}
		short := !strings.HasPrefix(a, "--")
		flags := a[1:]
		switch {
		case isShell(base):
			if short && strings.ContainsRune(flags, 's') {
				return opStdin, "", i
			}
			if short && strings.ContainsRune(flags, 'c') {
				if i+1 < len(cmd) {
					return opInline, cmd[i+1], i + 1
				}
				return opNone, "", -1
			}
		case strings.HasPrefix(base, "python"):
			if short && strings.ContainsRune(flags, 'c') {
				if i+1 < len(cmd) {
					return opInline, cmd[i+1], i + 1
				}
				return opNone, "", -1
			}
			if short && strings.ContainsRune(flags, 'm') {
				if i+1 < len(cmd) {
					return opScript, cmd[i+1], i + 1
				}
				return opNone, "", -1
			}
		case base == "node" || base == "nodejs":
			if a == "-e" || a == "--eval" || a == "-p" || a == "--print" {
				if i+1 < len(cmd) {
					return opInline, cmd[i+1], i + 1
				}
				return opNone, "", -1
			}
			if v, ok := strings.CutPrefix(a, "--eval="); ok {
				return opInline, v, i
			}
			if v, ok := strings.CutPrefix(a, "--print="); ok {
				return opInline, v, i
			}
		case base == "ruby" || base == "perl":
			if a == "-e" || (base == "perl" && a == "-E") {
				if i+1 < len(cmd) {
					return opInline, cmd[i+1], i + 1
				}
				return opNone, "", -1
			}
			if short && len(a) > 2 && (a[1] == 'e' || (base == "perl" && a[1] == 'E')) {
				return opInline, a[2:], i
			}
		}
		if takesValue(a) {
			i++
		}
	}
	return opNone, "", -1
}

func (w *walker) interpreter(base string, cmd []string, unresolved []bool, sc scope, fed bool) {
	kind, operand, idx := interpreterOperand(base, cmd)
	switch kind {
	case opStdin:
		w.prog.StdinInterpreter = true
	case opNone:
		if fed {
			w.prog.StdinInterpreter = true
		}
	case opInline:
		if !isShell(base) {
			w.prog.HereDocs = append(w.prog.HereDocs, operand)
			return
		}
		if idx < 0 || unresolved[idx] {
			w.low(base + " -c with a non-literal script")
			return
		}
		if w.depth >= maxNestDepth {
			w.low(base + " -c nested too deeply")
			return
		}
		inner, err := parse(operand, sc.cwd, w.env, w.depth+1)
		if err != nil {
			w.low("nested " + base + " -c: " + inner.Reason)
			return
		}
		w.prog.Calls = append(w.prog.Calls, inner.Calls...)
		w.prog.HereDocs = append(w.prog.HereDocs, inner.HereDocs...)
		if inner.StdinInterpreter {
			w.prog.StdinInterpreter = true
		}
		if inner.Confidence == Low {
			w.low("nested " + base + " -c: " + inner.Reason)
		}
	case opScript:
		// A named script or module: nothing to flag here.
	}
}
