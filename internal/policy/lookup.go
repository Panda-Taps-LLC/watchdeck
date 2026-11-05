package policy

import (
	"net/url"
	"path"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
	"mvdan.cc/sh/v3/syntax"

	"github.com/Panda-Taps-LLC/watchdeck/internal/manifest"
)

// Decision is a gate lookup result: the strongest action that matched, the
// subject that said so and the pattern (tool glob, path, domain, tool name)
// that matched. Action is ActionNone, ActionAsk or ActionDeny; Subject is
// nil with ActionNone.
//
// Precedence: deny > ask (every matching subject of both files counts; a
// gate only adds restrictions). Among matches with the same action the
// reported one is the most specific: exact name > glob > "*" for the
// subject's name or match, then for the inner pattern, then the user file
// before the project file, then file order.
type Decision struct {
	Action  Action
	Subject *Subject
	Pattern string
}

// tier ranks how specifically pattern names value: 2 exact, 1 glob, 0 "*".
// -1 means no match.
func tier(pattern, value string) int {
	switch {
	case pattern == "*":
		return 0
	case !strings.ContainsAny(pattern, "*?"):
		if pattern == value {
			return 2
		}
		return -1
	case wildMatch(pattern, value):
		return 1
	}
	return -1
}

// wildMatch matches s against a pattern where '*' is any run of bytes
// (spaces and '/' included) and '?' is one byte. No escapes, no classes.
func wildMatch(pattern, s string) bool {
	p, i := 0, 0
	star, mark := -1, 0
	for i < len(s) {
		switch {
		case p < len(pattern) && (pattern[p] == '?' || pattern[p] == s[i]):
			p++
			i++
		case p < len(pattern) && pattern[p] == '*':
			star, mark = p, i
			p++
		case star >= 0:
			p = star + 1
			mark++
			i = mark
		default:
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}

type cand struct {
	d          Decision
	outer, in  int
	sourceRank int // 1 user, 0 project
}

func better(a, b cand) bool { // a strictly better than b
	if a.d.Action != b.d.Action {
		return a.d.Action > b.d.Action
	}
	if a.outer != b.outer {
		return a.outer > b.outer
	}
	if a.in != b.in {
		return a.in > b.in
	}
	return a.sourceRank > b.sourceRank
}

func srcRank(s manifest.Source) int {
	if s == manifest.SourceUser {
		return 1
	}
	return 0
}

type picker struct {
	best cand
	ok   bool
}

func (pk *picker) offer(c cand) {
	if !pk.ok || better(c, pk.best) {
		pk.best, pk.ok = c, true
	}
}

func (pk *picker) decision() Decision {
	if !pk.ok {
		return Decision{}
	}
	return pk.best.d
}

// MCPToolAction is the gate for MCP tool `tool` of server `server` (the
// parts of mcp__<server>__<tool>). Subjects of kind mcp match the server by
// name (exact, glob or "*"); their tools map matches the tool name.
func (p *Policy) MCPToolAction(server, tool string) Decision {
	var pk picker
	for _, s := range p.subjects {
		if s.Kind != KindMCP {
			continue
		}
		outer := tier(s.Name, server)
		if outer < 0 {
			continue
		}
		for _, pat := range sortedKeys(s.MCPTools) {
			in := tier(pat, tool)
			if in < 0 {
				continue
			}
			pk.offer(cand{d: Decision{Action: actionOf(s.MCPTools[pat]), Subject: s, Pattern: pat}, outer: outer, in: in, sourceRank: srcRank(s.Source)})
		}
	}
	return pk.decision()
}

// bestTier is the best tier of value over patterns, -1 for none.
func bestTier(patterns []string, value string) int {
	best := -1
	for _, pat := range patterns {
		if t := tier(pat, value); t > best {
			best = t
		}
	}
	return best
}

// ToolGate is the gate for a tool call on a target. A target starting with
// '/' or '~' is a path and is checked against the paths of every tool
// subject whose match.tools names the tool; anything else is a URL or host
// name and is checked against domains. Paths are compared case-folded,
// cleaned, with ~ and ${HOME} expanded against p.Home; a relative target is
// never matched (the caller makes it absolute). A plain path entry matches
// itself and everything below it; a glob entry goes through doublestar, and
// **/name matches that name in any directory. A domain entry matches the
// host exactly, "*.example.com" any subdomain (not example.com itself), and
// "*" any host.
func (p *Policy) ToolGate(tool, target string) Decision {
	isPath := strings.HasPrefix(target, "/") || strings.HasPrefix(target, "~")
	if isPath {
		return p.gate(tool, true, "", p.normTarget(target))
	}
	host := hostOf(target)
	if host == "" {
		return Decision{}
	}
	return p.gate(tool, false, host, "")
}

// GateHost is ToolGate for a host the caller already normalised
// (NormalizeHost): no URL parsing, so an IPv6 literal stays whole.
func (p *Policy) GateHost(tool, host string) Decision {
	if host == "" {
		return Decision{}
	}
	return p.gate(tool, false, strings.ToLower(host), "")
}

// HasGates reports whether some tool subject has path (paths true) or
// domain (paths false) entries for tool.
func (p *Policy) HasGates(tool string, paths bool) bool {
	for _, s := range p.subjects {
		if s.Kind != KindTool || bestTier(s.Match.Tools, tool) < 0 {
			continue
		}
		g := s.Domains
		if paths {
			g = s.Paths
		}
		if !g.IsEmpty() {
			return true
		}
	}
	return false
}

func (p *Policy) gate(tool string, isPath bool, host, tpath string) Decision {
	var pk picker
	for _, s := range p.subjects {
		if s.Kind != KindTool {
			continue
		}
		outer := bestTier(s.Match.Tools, tool)
		if outer < 0 {
			continue
		}
		var g *manifest.GateLists
		if isPath {
			g = s.Paths
		} else {
			g = s.Domains
		}
		if g == nil {
			continue
		}
		for _, l := range []struct {
			act  Action
			list []string
		}{{ActionDeny, g.Deny}, {ActionAsk, g.Ask}} {
			for _, e := range l.list {
				var in int
				if isPath {
					in = p.pathTier(e, tpath)
				} else {
					in = domainTier(e, host)
				}
				if in < 0 {
					continue
				}
				pk.offer(cand{d: Decision{Action: l.act, Subject: s, Pattern: e}, outer: outer, in: in, sourceRank: srcRank(s.Source)})
			}
		}
	}
	return pk.decision()
}

func (p *Policy) expandHome(s string) string {
	if p.Home == "" {
		return s
	}
	switch {
	case s == "~" || strings.HasPrefix(s, "~/"):
		return p.Home + s[1:]
	case s == "${HOME}" || strings.HasPrefix(s, "${HOME}/"):
		return p.Home + strings.TrimPrefix(s, "${HOME}")
	}
	return s
}

func (p *Policy) normTarget(t string) string {
	t = p.expandHome(t)
	return strings.ToLower(path.Clean(t))
}

// GateSearch is the path gate for a search tool (Grep, Glob) whose path
// names a directory to search: a path at or under an entry gets that
// entry's action, as for ToolGate; a path that is an ancestor of an entry
// (searching it can reach the entry) gets ask, never deny; a "**/name"
// entry can match under any directory, so it asks too. target is an
// absolute, normalised path.
func (p *Policy) GateSearch(tool, target string) Decision {
	tpath := p.normTarget(target)
	var pk picker
	for _, s := range p.subjects {
		if s.Kind != KindTool || s.Paths == nil {
			continue
		}
		outer := bestTier(s.Match.Tools, tool)
		if outer < 0 {
			continue
		}
		for _, l := range []struct {
			act  Action
			list []string
		}{{ActionDeny, s.Paths.Deny}, {ActionAsk, s.Paths.Ask}} {
			for _, e := range l.list {
				if in := p.pathTier(e, tpath); in >= 0 {
					pk.offer(cand{d: Decision{Action: l.act, Subject: s, Pattern: e}, outer: outer, in: in, sourceRank: srcRank(s.Source)})
					continue
				}
				if p.searchReaches(e, tpath) {
					pk.offer(cand{d: Decision{Action: ActionAsk, Subject: s, Pattern: e}, outer: outer, in: 0, sourceRank: srcRank(s.Source)})
				}
			}
		}
	}
	return pk.decision()
}

// searchReaches reports whether a search rooted at dir could reach a path
// the entry names: dir is an ancestor of the entry (or of its fixed prefix
// before the first glob character), or the entry is "**/…".
func (p *Policy) searchReaches(entry, dir string) bool {
	e := strings.ToLower(p.expandHome(entry))
	if strings.HasPrefix(e, "**/") {
		return true
	}
	if i := strings.IndexAny(e, "*?["); i >= 0 {
		e = e[:i]
		if j := strings.LastIndexByte(e, '/'); j >= 0 {
			e = e[:j]
		}
	}
	e = path.Clean(e)
	if dir == "/" || strings.HasPrefix(e, dir+"/") || e == dir {
		return true
	}
	if p.ResolveEntries && strings.HasPrefix(e, "/") {
		if r := strings.ToLower(CanonicalPath(p.expandHome(entry))); strings.HasPrefix(r, dir+"/") {
			return true
		}
	}
	return false
}

// pathTier: 2 plain path (equal or under), 1 glob, -1 no match.
func (p *Policy) pathTier(entry, target string) int {
	e := strings.ToLower(p.expandHome(entry))
	if strings.ContainsAny(e, "*?[") {
		var ok bool
		if strings.HasPrefix(e, "**/") {
			ok, _ = doublestar.Match(e, strings.TrimPrefix(target, "/"))
		} else {
			ok, _ = doublestar.Match(e, target)
		}
		if ok {
			return 1
		}
		return -1
	}
	e = path.Clean(e)
	if target == e || strings.HasPrefix(target, e+"/") || e == "/" {
		return 2
	}
	// The entry's own real spelling (/tmp is /private/tmp on macOS; a
	// symlinked home): the target is checked in its real spelling by the
	// hook, so the entry is too. Folded like the rest.
	if p.ResolveEntries && strings.HasPrefix(e, "/") {
		if r := strings.ToLower(CanonicalPath(p.expandHome(entry))); r != e && (target == r || strings.HasPrefix(target, r+"/")) {
			return 2
		}
	}
	return -1
}

// hostOf returns the lower-case host of a URL or a bare host name.
func hostOf(t string) string {
	t = strings.TrimSpace(t)
	if strings.Contains(t, "://") {
		u, err := url.Parse(t)
		if err != nil {
			return ""
		}
		t = u.Hostname()
	} else if i := strings.IndexAny(t, "/:"); i >= 0 {
		t = t[:i]
	}
	return strings.TrimSuffix(strings.ToLower(t), ".")
}

// domainTier: 2 exact, 1 "*.x" subdomain, 0 "*", -1 no match.
func domainTier(entry, host string) int {
	e := strings.ToLower(entry)
	switch {
	case e == "*":
		return 0
	case strings.HasPrefix(e, "*."):
		if strings.HasSuffix(host, e[1:]) {
			return 1
		}
	case e == host:
		return 2
	}
	return -1
}

// MaxCommandLen caps the command CommandSubject looks at; a longer one has
// no subject.
const MaxCommandLen = 16 << 10

// CommandSubject returns the command subject for a command line. A subject
// applies only to a single simple command of inert words (see
// simpleCommand: one plain call, every word an unquoted [A-Za-z0-9_./:@%+,=-]
// literal or a plain single- or double-quoted string); anything else, a
// parse error, or a command over MaxCommandLen bytes has no subject, so a
// glob never spans a command separator and no word can expand into code in
// bash or zsh. M6.3 applies command subjects under these rules.
//
// A subject matches when every matcher it has matches: argv0 and glob.
// argv0 is the first word (a plain literal; a quoted or expanded first word
// matches only "*"): a bare entry (npm) matches only a first word
// without '/' (which the shell resolves through PATH; M6.3 resolves it the
// same way), an absolute entry (/usr/bin/make) only that exact first word,
// and "*" any. glob is one of the patterns over the whole trimmed command,
// where '*' spans anything (spaces and '/') and '?' is one byte.
//
// One subject is returned, the most specific: a non-"*" glob and argv0 both
// matched > a non-"*" glob > a non-"*" argv0 > only "*" matchers; then the
// glob with more literal bytes; then the lexically smaller name. Command
// subjects come from the user file only (New drops the project's).
func (p *Policy) CommandSubject(command string) (*Subject, bool) {
	cmd := strings.TrimSpace(command)
	if cmd == "" || len(cmd) > MaxCommandLen {
		return nil, false
	}
	argv0, simple := simpleCommand(cmd)
	if !simple {
		return nil, false
	}
	type score struct{ spec, lit, src int }
	var best *Subject
	var bs score
	for _, s := range p.subjects {
		if s.Kind != KindCommand {
			continue
		}
		var sc score
		sc.src = srcRank(s.Source)
		if len(s.Match.Argv0) > 0 {
			hit, nonStar := false, false
			for _, a := range s.Match.Argv0 {
				switch {
				case a == "*":
					hit = true
				case argv0 == "":
					// quoted or expanded first word: only "*" matches
				case strings.Contains(a, "/"):
					if a == argv0 {
						hit, nonStar = true, true
					}
				case a == argv0: // a bare entry never matches a path
					hit, nonStar = true, true
				}
			}
			if !hit {
				continue
			}
			if nonStar {
				sc.spec |= 1
			}
		}
		if len(s.Match.Glob) > 0 {
			hit := false
			for _, g := range s.Match.Glob {
				if !wildMatch(g, cmd) {
					continue
				}
				hit = true
				if g != "*" {
					sc.spec |= 2
					if l := literalLen(g); l > sc.lit {
						sc.lit = l
					}
				}
			}
			if !hit {
				continue
			}
		}
		if best == nil || sc.spec > bs.spec ||
			(sc.spec == bs.spec && (sc.lit > bs.lit ||
				(sc.lit == bs.lit && (sc.src > bs.src ||
					(sc.src == bs.src && s.Name < best.Name))))) {
			best, bs = s, sc
		}
	}
	return best, best != nil
}

func literalLen(g string) int {
	n := 0
	for i := 0; i < len(g); i++ {
		if g[i] != '*' && g[i] != '?' {
			n++
		}
	}
	return n
}

// AgentRules returns the agent subjects whose agent_type matches, most
// specific first (exact > glob > "*", then user before project, then file
// order).
func (p *Policy) AgentRules(agentType string) []*Subject {
	var out []*Subject
	var tiers []int
	for _, s := range p.subjects {
		if s.Kind != KindAgent {
			continue
		}
		t := tier(s.Match.AgentType, agentType)
		if t < 0 {
			continue
		}
		// stable insertion by tier, keeping user-before-project order
		i := len(out)
		for i > 0 && tiers[i-1] < t {
			i--
		}
		out = append(out, nil)
		tiers = append(tiers, 0)
		copy(out[i+1:], out[i:])
		copy(tiers[i+1:], tiers[i:])
		out[i], tiers[i] = s, t
	}
	return out
}

// AgentToolAction is the gate for a subagent of type agentType calling tool:
// the strongest of every matching agent subject's tools.deny / tools.ask.
func (p *Policy) AgentToolAction(agentType, tool string) Decision {
	var pk picker
	for _, s := range p.subjects {
		if s.Kind != KindAgent || s.AgentTools == nil {
			continue
		}
		outer := tier(s.Match.AgentType, agentType)
		if outer < 0 {
			continue
		}
		for _, l := range []struct {
			act  Action
			list []string
		}{{ActionDeny, s.AgentTools.Deny}, {ActionAsk, s.AgentTools.Ask}} {
			for _, pat := range l.list {
				if in := tier(pat, tool); in >= 0 {
					pk.offer(cand{d: Decision{Action: l.act, Subject: s, Pattern: pat}, outer: outer, in: in, sourceRank: srcRank(s.Source)})
				}
			}
		}
	}
	return pk.decision()
}

// AgentSkillAction is the gate for a subagent of type agentType invoking a
// skill: deny when some matching agent subject has a skills.allow list that
// does not name the skill (or "*"), so several lists intersect. A skills
// list only narrows; it never allows.
func (p *Policy) AgentSkillAction(agentType, skill string) Decision {
	var pk picker
	for _, s := range p.subjects {
		if s.Kind != KindAgent || s.AgentSkills == nil {
			continue
		}
		outer := tier(s.Match.AgentType, agentType)
		if outer < 0 {
			continue
		}
		listed := false
		for _, n := range s.AgentSkills {
			if n == "*" || n == skill {
				listed = true
				break
			}
		}
		if !listed {
			pk.offer(cand{d: Decision{Action: ActionDeny, Subject: s, Pattern: "skills.allow"}, outer: outer, sourceRank: srcRank(s.Source)})
		}
	}
	return pk.decision()
}

// simpleCommand reports whether cmd is one simple command made only of
// inert words, and returns its first word when that is a plain literal.
// Claude Code runs a Bash-tool command in the user's shell, often zsh,
// where unquoted text can run code (glob qualifiers *(e:...:), =(cmd),
// ${(...)}, extglob, arithmetic), so this is an allow-list, not a
// deny-list. After parsing as bash (mvdan.cc/sh; a parse error is no
// match) there must be exactly one statement: a plain call, not in the
// background, not negated, no trailing ';', no redirection, no VAR=
// prefix, no comment, no newline; and every part of every word must be
//
//   - an unquoted literal of [A-Za-z0-9_./:@%+,=-] only, with no "==" and
//     not starting the word with '=', even after empty quotes (”=cmd is
//     zsh's EQUALS expansion),
//   - a single-quoted literal ('...', not $'...'), or
//   - a double-quoted literal with no $, backquote or backslash.
//
// Anything else (parameter, arithmetic or command expansion, process
// substitution, brace expansion, extglob, unquoted * ? [ ] ( ) { } ! ~ ^ #
// or a backslash) is not simple: the check fails closed. Callers cap the
// input first (MaxCommandLen).
func simpleCommand(cmd string) (argv0 string, ok bool) {
	if strings.ContainsAny(cmd, "\n\r") {
		return "", false
	}
	f, err := syntax.NewParser(syntax.Variant(syntax.LangBash), syntax.KeepComments(true)).Parse(strings.NewReader(cmd), "")
	if err != nil || f == nil || len(f.Stmts) != 1 || len(f.Last) > 0 {
		return "", false
	}
	st := f.Stmts[0]
	if st.Background || st.Coprocess || st.Semicolon.IsValid() || st.Negated || len(st.Redirs) > 0 || len(st.Comments) > 0 {
		return "", false
	}
	call, isCall := st.Cmd.(*syntax.CallExpr)
	if !isCall || len(call.Args) == 0 || len(call.Assigns) > 0 {
		return "", false
	}
	for _, w := range call.Args {
		if !inertWord(w) {
			return "", false
		}
	}
	return call.Args[0].Lit(), true
}

// inertWord reports whether every part of w is an allowed literal (see
// simpleCommand).
func inertWord(w *syntax.Word) bool {
	if w == nil || len(w.Parts) == 0 {
		return false
	}
	// leading is true while every part so far was an empty quoted string:
	// zsh's EQUALS expansion (=cmd) also fires on ''=cmd.
	leading := true
	for _, part := range w.Parts {
		switch x := part.(type) {
		case *syntax.Lit:
			if !inertLit(x.Value) || strings.Contains(x.Value, "==") || (leading && strings.HasPrefix(x.Value, "=")) {
				return false
			}
			leading = false
		case *syntax.SglQuoted:
			if x.Dollar {
				return false
			}
			if x.Value != "" {
				leading = false
			}
		case *syntax.DblQuoted:
			if x.Dollar {
				return false
			}
			if len(x.Parts) > 0 {
				leading = false
			}
			for _, dp := range x.Parts {
				l, ok := dp.(*syntax.Lit)
				if !ok || strings.ContainsAny(l.Value, "$`\\") {
					return false
				}
			}
		default:
			return false
		}
	}
	return true
}

// inertLit reports whether an unquoted literal has only
// [A-Za-z0-9_./:@%+,=-].
func inertLit(v string) bool {
	if v == "" {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("_./:@%+,=-", c) >= 0:
		default:
			return false
		}
	}
	return true
}
