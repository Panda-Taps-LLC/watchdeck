package rules

import (
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/Panda-Taps-LLC/watchdeck/internal/lazyre"
	"github.com/goccy/go-yaml"
)

// cmdPos anchors a command name at command position: start of input, after
// a pipe (also `|&`), `;`, `&`, `(`, `{`, `$(`, a backtick or a newline, or
// after a control keyword; optionally negated with `!`. Based on
// internal/scan's. YAML regexes reach it as {{CMD}}.
const cmdPos = "(?:^|[|;&({`\\n]|\\$\\(|\\b(?:if|then|else|elif|do|while|until|time|nohup)\\s)\\s*(?:!\\s*)?"

// wrappers skips leading assignments and wrapper commands with their flags,
// including flags that take a value (`sudo -u root`, `nice -n 10`,
// `timeout -s KILL 5`, `env -u X A=b`, `xargs -I{} `). YAML regexes reach it
// as {{WRAP}}, so the argv0 prefix and the pipe-to-shell targets share it.
const wrappers = `(?:(?:[A-Za-z_][A-Za-z0-9_]*=\S*` +
	`|(?:sudo|doas)(?:\s+(?:-[ugCDhnpRrTU]\s*\S+|-\S+))*` +
	`|nice(?:\s+(?:-n\s*\S+|-\S+))*` +
	`|timeout(?:\s+(?:-[sk]\s*\S+|-\S+))*\s+[0-9.]+[smhd]?` +
	`|env(?:\s+(?:-[uSCP]\s*\S+|-\S+|[A-Za-z_][A-Za-z0-9_]*=\S*))*` +
	`|command(?:\s+-[pvV]+)*` +
	`|exec(?:\s+(?:-a\s*\S+|-\S+))*` +
	`|xargs(?:\s+(?:-[IEdLnPsa]\s*\S+|-\S+))*` +
	`|stdbuf(?:\s+-\S+)*` +
	`|time(?:\s+-p)?|nohup|builtin` +
	`)\s+)*`

// gapTok is one piece of a simple command's text: a whole quoted string, a
// backslash escape, a redirect that contains `&` (`2>&1`, `&>`), or any
// character that does not end the simple command. Quoted pieces let a gap
// cross a `;`, `&` or `|` inside quotes. Because the plain class also takes
// quote characters, an unbalanced quote never stops a match (only adds
// ways to match). YAML regexes reach it as {{TOK}}.
const gapTok = `"[^"]*"|'[^']*'|\\[\s\S]|[<>]&|&>|[^|;&\n]`

// rest is what may sit between a command name and the rule's regex: the
// remainder of the same simple command.
const rest = `(?:[\s<>](?:` + gapTok + `)*?)?`

// expandPlaceholders replaces the placeholders a YAML regex may use.
func expandPlaceholders(expr string) string {
	if !strings.Contains(expr, "{{") {
		return expr
	}
	return strings.NewReplacer("{{CMD}}", cmdPos, "{{WRAP}}", wrappers, "{{TOK}}", gapTok).Replace(expr)
}

var knownTools = [...]string{"Bash", "Read", "Write", "Edit", "MultiEdit", "NotebookEdit", "WebFetch", "WebSearch", "Glob", "Grep", "*"}

type loaded struct {
	packs []Pack
	err   error
}

var (
	loadOnce sync.Once
	loadRes  loaded
)

func load() *loaded {
	loadOnce.Do(func() { loadRes = fromTables(genPacks) })
	return &loadRes
}

// fromTables checks the generated packs' shape and prepares each rule's
// matcher, leaving genPacks untouched. No parsing happens here; regexes
// compile later, per rule, on first need.
func fromTables(src []Pack) loaded {
	if len(src) == 0 {
		return loaded{err: fmt.Errorf("no rule packs")}
	}
	packs := make([]Pack, len(src))
	for i, p := range src {
		p.Rules = append([]Rule(nil), p.Rules...)
		if err := checkShape(&p); err != nil {
			return loaded{err: err}
		}
		packs[i] = p
	}
	return loaded{packs: packs}
}

// LoadFS parses packs/*.yaml from fsys and checks every pack fully,
// regexes included. The generator (./gen) and tests use it; the hook never
// parses YAML.
func LoadFS(fsys fs.FS) ([]Pack, error) {
	names, err := fs.Glob(fsys, "packs/*.yaml")
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	var packs []Pack
	for _, name := range names {
		b, err := fs.ReadFile(fsys, name)
		if err != nil {
			return nil, err
		}
		var p Pack
		if err := yaml.UnmarshalWithOptions(b, &p, yaml.Strict()); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		if want := strings.TrimSuffix(path.Base(name), ".yaml"); p.Name != want {
			return nil, fmt.Errorf("%s: pack %q does not match the file name", name, p.Name)
		}
		if err := Validate(p); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		packs = append(packs, p)
	}
	if len(packs) == 0 {
		return nil, fmt.Errorf("no rule packs under packs/")
	}
	return packs, nil
}

func checkShape(p *Pack) error {
	if !isID(p.Name) {
		return fmt.Errorf("pack name %q: want lower-case letters, digits and dashes", p.Name)
	}
	if p.Version < 1 {
		return fmt.Errorf("pack %s: version must be >= 1", p.Name)
	}
	if p.Description == "" {
		return fmt.Errorf("pack %s: description is empty", p.Name)
	}
	if len(p.Rules) == 0 {
		return fmt.Errorf("pack %s: no rules", p.Name)
	}
	for i := range p.Rules {
		r := &p.Rules[i]
		where := p.Name + "/" + r.ID
		if !isID(r.ID) {
			return fmt.Errorf("pack %s: rule id %q: want lower-case letters, digits and dashes", p.Name, r.ID)
		}
		for j := 0; j < i; j++ {
			if p.Rules[j].ID == r.ID {
				return fmt.Errorf("%s: duplicate rule id", where)
			}
		}
		if !r.Severity.valid() {
			return fmt.Errorf("%s: severity %q: want low, medium, high or critical", where, r.Severity)
		}
		if !r.Action.valid() {
			return fmt.Errorf("%s: action %q: want deny, ask or log", where, r.Action)
		}
		if r.Description == "" || r.FPNote == "" {
			return fmt.Errorf("%s: description and fp_note are required", where)
		}
		c, err := newCompiled(r)
		if err != nil {
			return fmt.Errorf("%s: %w", where, err)
		}
		r.c = c
	}
	return nil
}

func isID(s string) bool {
	if s == "" {
		return false
	}
	for _, ch := range s {
		if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
			return false
		}
	}
	return true
}

// Validate checks a pack fully, including that every regex compiles. The
// runtime load skips the compile (lazyre compiles on first use and panics
// on a bad expression), so the generator and tests run Validate over every
// pack and an invalid regex never reaches packs_gen.go.
func Validate(p Pack) error {
	p.Rules = append([]Rule(nil), p.Rules...) // checkShape sets matchers; leave the caller's rules alone
	if err := checkShape(&p); err != nil {
		return err
	}
	for _, r := range p.Rules {
		if r.c.re.Expr == "" {
			continue
		}
		if _, err := regexp.Compile(r.c.re.Expr); err != nil {
			return fmt.Errorf("%s/%s: %w", p.Name, r.ID, err)
		}
	}
	return nil
}

// compiled is a rule's prepared matcher; the regex compiles on first use.
type compiled struct {
	anyTool bool
	tools   []string
	field   string
	lits    []string
	fold    bool // literals compare against the lower-cased field
	re      lazyre.Regexp
}

func newCompiled(r *Rule) (*compiled, error) {
	c := &compiled{}
	for _, t := range strings.Split(r.Tool, "|") {
		t = strings.TrimSpace(t)
		ok := false
		for _, k := range knownTools {
			ok = ok || t == k
		}
		if !ok {
			return nil, fmt.Errorf("tool %q: want one of %s, or several joined by |", t, strings.Join(knownTools[:], ", "))
		}
		if t == "*" {
			c.anyTool = true
		}
		c.tools = append(c.tools, t)
	}
	m := r.Match
	c.field = m.Field
	if c.field == "" {
		c.field = defaultField(c.tools)
		if c.field == "" {
			return nil, fmt.Errorf("match.field is required for tool %q", r.Tool)
		}
	}
	switch c.field {
	case FieldCommand, FieldFilePath, FieldContent, FieldURL, FieldText:
	default:
		return nil, fmt.Errorf("match.field %q: want command, file_path, content, url or text", c.field)
	}
	if m.Regex == "" && len(m.Literals) == 0 && len(m.Argv0) == 0 {
		return nil, fmt.Errorf("match needs regex, literals or argv0")
	}
	if m.Anchored && (len(m.Argv0) == 0 || m.Regex == "") {
		return nil, fmt.Errorf("match.anchored needs argv0 and regex")
	}
	c.fold = strings.HasPrefix(m.Regex, "(?i)") || (m.Regex == "" && len(m.Argv0) == 0)
	lits := m.Literals
	if len(lits) == 0 {
		lits = m.Argv0
	}
	for _, l := range lits {
		if l == "" {
			return nil, fmt.Errorf("match.literals: empty literal")
		}
		if c.fold {
			l = strings.ToLower(l)
		}
		c.lits = append(c.lits, l)
	}
	expr := expandPlaceholders(m.Regex)
	if len(m.Argv0) > 0 {
		if c.field != FieldCommand {
			return nil, fmt.Errorf("match.argv0 needs field command")
		}
		names := make([]string, len(m.Argv0))
		for i, n := range m.Argv0 {
			if n == "" || strings.ContainsAny(n, " /\t") {
				return nil, fmt.Errorf("match.argv0 %q: want a bare command name", n)
			}
			names[i] = regexp.QuoteMeta(n)
		}
		head := cmdPos + wrappers + `["']?\\?(?:[^\s;&|]*/)?(?:` + strings.Join(names, "|") + `)["']?`
		gap := rest
		if m.Anchored {
			gap = ""
		}
		if expr == "" {
			expr = head + `(?:[\s<>;&|)]|$)`
		} else {
			flags := ""
			if strings.HasPrefix(expr, "(?i)") {
				flags, expr = "(?i)", expr[4:]
			}
			expr = flags + head + gap + "(?:" + expr + ")"
		}
	}
	c.re.Expr = expr
	return c, nil
}

func defaultField(tools []string) string {
	field := ""
	for _, t := range tools {
		var f string
		switch t {
		case "Bash":
			f = FieldCommand
		case "Read", "Write", "Edit", "MultiEdit", "NotebookEdit", "Glob", "Grep":
			f = FieldFilePath
		case "WebFetch":
			f = FieldURL
		default:
			return ""
		}
		if field != "" && field != f {
			return ""
		}
		field = f
	}
	return field
}

func (c *compiled) appliesTo(tool string) bool {
	if c == nil {
		return false
	}
	if c.anyTool {
		return true
	}
	for _, t := range c.tools {
		if t == tool {
			return true
		}
	}
	return false
}

func (c *compiled) match(f *fieldCache, in Input) bool {
	s := f.get(in, c.field)
	if s == "" {
		return false
	}
	if len(c.lits) > 0 {
		hay := s
		if c.fold {
			hay = f.getLower(in, c.field)
		}
		found := false
		for _, l := range c.lits {
			if strings.Contains(hay, l) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return c.re.Expr == "" || c.re.MatchString(s)
}
