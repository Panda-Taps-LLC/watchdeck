// Package match decides which indexed skills a Bash command would run
// scripts from.
//
// FastReject is the hook's cheap first gate: no parsing, no syscalls. Resolve
// is the slow path: parse with shellparse, resolve every argv token against
// the skills' script globs, and grade the answer.
package match

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/bmatcuk/doublestar/v4"

	"github.com/Panda-Taps-LLC/watchdeck/internal/lazyre"
	"github.com/Panda-Taps-LLC/watchdeck/internal/shellparse"
)

// IndexedSkill is what the index knows about one skill.
type IndexedSkill struct {
	Name string
	// Dir is the skill's real root directory (after EvalSymlinks).
	Dir string
	// Aliases are other paths that lead to the same directory, such as a
	// symlink under ~/.claude/skills pointing at ~/.agents/skills/<name>.
	Aliases []string
	// Scripts are doublestar globs relative to the root that name the files
	// the hook treats as scripts. Empty means ["scripts/**"].
	Scripts []string
}

// DefaultScripts is the glob set used when IndexedSkill.Scripts is empty.
var DefaultScripts = []string{"scripts/**"}

// Index supplies the skills and the needles FastReject scans for.
type Index interface {
	Skills() []IndexedSkill
	// Needles are substrings whose presence in a command means it may touch
	// a skill: absolute skill roots and aliases, their ~ and $HOME spellings,
	// and the generic markers in GenericNeedles.
	Needles() []string
}

// GenericNeedles are needles every index should include: they catch
// relative and variable-based spellings of skill paths.
var GenericNeedles = []string{".claude/skills", "scripts/", "${CLAUDE_SKILL_DIR}", "$CLAUDE_SKILL_DIR"}

// Result is Resolve's answer.
type Result struct {
	// Skills whose scripts the command references, in first-seen order.
	Skills []string
	// Confidence: High when the program read cleanly and at least one skill
	// matched; Low when a needle is present but the boundary could not be
	// determined (see Reason); None when nothing resolved to a script.
	Confidence shellparse.Confidence
	Reason     string
	// HasNeedle is true when any needle occurs in the raw command text.
	HasNeedle bool
}

// FastReject reports whether the hook can ignore cmd without parsing it:
// the text contains no needle and no interpreter-reads-stdin pattern, and
// cwd is not inside a skill directory. It does no I/O.
func FastReject(cmd, cwd string, idx Index) bool {
	if mentionsNeedle(cmd, idx.Needles()) {
		return false
	}
	if hasStdinPattern(cmd) {
		return false
	}
	// `~/.cl*/sk*/...` defeats every substring needle; Resolve matches
	// path patterns against the skill roots.
	if strings.Contains(cmd, "/") && strings.ContainsAny(cmd, "*?[{") {
		for _, w := range strings.Fields(cmd) {
			if strings.Contains(w, "/") && hasGlob(w) {
				return false
			}
		}
	}
	if cwd != "" {
		c := filepath.Clean(cwd)
		for _, s := range idx.Skills() {
			if underDir(c, s.Dir) {
				return false
			}
			for _, a := range s.Aliases {
				if underDir(c, a) {
					return false
				}
			}
		}
	}
	return true
}

// Resolve parses cmd and names the skills whose scripts it references.
func Resolve(cmd, cwd string, env map[string]string, idx Index) Result {
	needles := idx.Needles()
	res := Result{HasNeedle: mentionsNeedle(cmd, needles)}
	prog, _ := shellparse.Parse(cmd, cwd, env)

	skills := idx.Skills()
	var roots [][]root // canonical roots per skill, built on first use
	seen := map[string]bool{}
	globReach := false
	for _, call := range prog.Calls {
		for i, tok := range call.Argv {
			abs, real, ok := resolveToken(tok, i, call.Cwd)
			if !ok {
				continue
			}
			if roots == nil {
				roots = make([][]root, len(skills))
				for si, s := range skills {
					roots[si] = skillRoots(s)
				}
			}
			hit := false
			for si, s := range skills {
				if matchSkill(roots[si], s.Scripts, abs, real) {
					hit = true
					if !seen[s.Name] {
						seen[s.Name] = true
						res.Skills = append(res.Skills, s.Name)
					}
				}
			}
			// shellparse keeps glob and brace text literally; bash expands
			// it. A pattern that can reach a skill's scripts but matched no
			// skill as written leaves the boundary unknown.
			if !hit && !globReach && hasGlob(tok) {
				for si, s := range skills {
					if globReachesScripts(roots[si], s.Scripts, abs) {
						globReach = true
						break
					}
				}
			}
		}
	}

	hereNeedle := false
	for _, h := range prog.HereDocs {
		if containsAny(h, needles) {
			hereNeedle = true
			break
		}
	}
	switch {
	case prog.StdinInterpreter && (res.HasNeedle || len(res.Skills) > 0):
		res.Confidence = shellparse.Low
		res.Reason = "interpreter reads script from stdin"
	case prog.Confidence == shellparse.Low && (res.HasNeedle || len(res.Skills) > 0):
		res.Confidence = shellparse.Low
		res.Reason = prog.Reason
	case hereNeedle:
		res.Confidence = shellparse.Low
		res.Reason = "here-doc or inline code references a skill path"
	case globReach:
		// HasNeedle is set too: the hook asks only when a needle is present,
		// and `~/.cl*/sk*/...` holds none.
		res.Confidence = shellparse.Low
		res.Reason = "glob or brace in a path that can reach a skill script"
		res.HasNeedle = true
	case prog.Confidence == shellparse.High && len(res.Skills) > 0:
		res.Confidence = shellparse.High
	default:
		res.Confidence = shellparse.None
	}
	return res
}

type root struct{ clean, real string }

func skillRoots(s IndexedSkill) []root {
	out := make([]root, 0, 1+len(s.Aliases))
	for _, p := range append([]string{s.Dir}, s.Aliases...) {
		if p == "" {
			continue
		}
		r := root{clean: filepath.Clean(p)}
		r.real = r.clean
		if rp, err := filepath.EvalSymlinks(r.clean); err == nil {
			r.real = rp
		}
		out = append(out, r)
	}
	return out
}

// resolveToken turns an argv token into an absolute path to test. argv[0]
// without a slash is a PATH lookup, not a file; option tokens are skipped;
// a relative token must exist under the call's cwd unless it is a glob.
func resolveToken(tok string, i int, cwd string) (abs, real string, ok bool) {
	if tok == "" || strings.HasPrefix(tok, "-") {
		return "", "", false
	}
	if i == 0 && !strings.Contains(tok, "/") {
		return "", "", false
	}
	abs = tok
	if !filepath.IsAbs(abs) {
		if cwd == "" {
			return "", "", false
		}
		abs = filepath.Join(cwd, abs)
		if !exists(abs) && !strings.ContainsAny(tok, "*?[") {
			return "", "", false
		}
	}
	abs = filepath.Clean(abs)
	real = abs
	if rp, err := filepath.EvalSymlinks(abs); err == nil {
		real = rp
	}
	return abs, real, true
}

func matchSkill(roots []root, globs []string, abs, real string) bool {
	if len(globs) == 0 {
		globs = DefaultScripts
	}
	for _, r := range roots {
		for _, p := range [2]string{abs, real} {
			for _, rt := range [2]string{r.clean, r.real} {
				rel, err := filepath.Rel(rt, p)
				if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, "../") {
					continue
				}
				rel = filepath.ToSlash(rel)
				for _, g := range globs {
					if ok, _ := doublestar.Match(g, rel); ok {
						return true
					}
				}
			}
		}
	}
	return false
}

// hasGlob reports whether tok holds pattern characters bash would expand:
// `*`, `?`, `[`, an extglob group, or a brace list or range. The parser has
// already removed quoting, so a quoted `*` is a (harmless) false positive.
func hasGlob(tok string) bool {
	if strings.ContainsAny(tok, "*?[") {
		return true
	}
	for _, g := range [...]string{"@(", "+(", "!("} {
		if strings.Contains(tok, g) {
			return true
		}
	}
	if o := strings.IndexByte(tok, '{'); o >= 0 {
		if c := strings.IndexByte(tok[o:], '}'); c > 0 {
			in := tok[o : o+c]
			return strings.Contains(in, ",") || strings.Contains(in, "..")
		}
	}
	return false
}

// globReachesScripts reports, without I/O, whether the absolute pattern abs
// could name a path below one of roots whose next component matches the
// leading directory of a script glob. Pattern components are compared with
// the root's one by one (doublestar also takes `{a,b}`). A brace holding a
// `/` cannot be split by component, so it counts as reaching.
func globReachesScripts(roots []root, globs []string, abs string) bool {
	if len(globs) == 0 {
		globs = DefaultScripts
	}
	if o := strings.IndexByte(abs, '{'); o >= 0 {
		if c := strings.IndexByte(abs[o:], '}'); c > 0 && strings.Contains(abs[o:o+c], "/") {
			return true
		}
	}
	pc := strings.Split(filepath.ToSlash(abs), "/")
	for _, r := range roots {
		for _, rt := range [2]string{r.clean, r.real} {
			rc := strings.Split(filepath.ToSlash(rt), "/")
			if len(pc) <= len(rc) {
				continue
			}
			if ok, _ := doublestar.Match(strings.Join(pc[:len(rc)], "/"), strings.Join(rc, "/")); !ok {
				continue
			}
			next := pc[len(rc)]
			for _, g := range globs {
				lead, _, nested := strings.Cut(g, "/")
				if !nested || hasGlob(lead) {
					return true // the script glob matches at the root's top level
				}
				if ok, _ := doublestar.Match(next, lead); ok {
					return true
				}
			}
		}
	}
	return false
}

func exists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

// underDir reports whether clean path p equals dir or lies below it. It
// allocates nothing when dir is already clean.
func underDir(p, dir string) bool {
	if dir == "" {
		return false
	}
	dir = filepath.Clean(dir)
	if !strings.HasPrefix(p, dir) {
		return false
	}
	return len(p) == len(dir) || p[len(dir)] == filepath.Separator || dir == string(filepath.Separator)
}

// quoteStrip drops the quoting characters that bash removes from a word:
// sk""ills and scr\ipts are skills and scripts to the shell. The
// replacer is built on use (the package stays init-free).
func quoteStrip(s string) string {
	return strings.NewReplacer("'", "", `"`, "", `\`, "").Replace(s)
}

// mentionsNeedle checks the raw text and, when it holds quotes or
// backslashes, a quote-stripped copy, so quoting inside a path does not hide
// it from the needles (the parser would unquote it).
func mentionsNeedle(cmd string, needles []string) bool {
	if containsAny(cmd, needles) {
		return true
	}
	if !strings.ContainsAny(cmd, `'"\`) {
		return false
	}
	return containsAny(quoteStrip(cmd), needles)
}

func containsAny(s string, needles []string) bool {
	for _, n := range needles {
		if n != "" && strings.Contains(s, n) {
			return true
		}
	}
	return false
}

// Stdin-interpreter textual patterns. interp must start a word and be
// followed by a lone `-` (or `-s`) token, or follow a pipe.
const interp = `(?:python[0-9.]*|nodejs|node|bash|dash|zsh|ksh|sh|ruby|perl)`

var (
	stdinDashRe  = lazyre.Regexp{Expr: `(?:^|[\s|;&(/])` + interp + `(?:\s+-\S+)*\s+-s?(?:$|[\s<|;&)])`}
	pipeInterpRe = lazyre.Regexp{Expr: `\|&?\s*` + interp + `(?:$|[\s<|;&)])`}
)

func hasStdinPattern(cmd string) bool {
	if strings.Contains(cmd, "<<") {
		return true
	}
	if !strings.Contains(cmd, "python") && !strings.Contains(cmd, "node") &&
		!strings.Contains(cmd, "sh") && !strings.Contains(cmd, "ruby") &&
		!strings.Contains(cmd, "perl") {
		return false
	}
	return stdinDashRe.MatchString(cmd) || pipeInterpRe.MatchString(cmd)
}
