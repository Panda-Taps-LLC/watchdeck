package hook

import (
	"encoding/json"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Panda-Taps-LLC/watchdeck/internal/activity"
	"github.com/Panda-Taps-LLC/watchdeck/internal/claudesettings"
	"github.com/Panda-Taps-LLC/watchdeck/internal/index"
	"github.com/Panda-Taps-LLC/watchdeck/internal/manifest"
	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
	"github.com/Panda-Taps-LLC/watchdeck/internal/policy"
	"github.com/Panda-Taps-LLC/watchdeck/internal/rules"
)

// The decision pipeline (M6.3). One PreToolUse call goes through:
//
//  1. the policy, from the cache (policy.LoadCached: two stats when no
//     policy file exists, else one small cache read);
//  2. the tool fast filter: a tool other than Bash with no enabled pack
//     rule, gate or user rule for it gets no opinion here;
//  3. the gate stage: the built-in rule packs (rules.Eval with the policy's
//     config), the user's own rules, and the gates (agent rules by
//     agent_type, MCP tool rules, file path gates, domain gates). Each
//     answers none, log, ask or deny, never allow;
//  4. for Bash, the sandbox stage: a skill script or a user command subject
//     is rewritten to `watchdeck run` (ask, or allow when auto-allowed and
//     the command is solely the invocation). Before a rewrite is returned,
//     the person's Claude Code Bash deny and ask rules are matched against
//     the original command (nativeCheck): a deny hit denies without the
//     rewrite; an ask hit or an unparseable command asks with it, except
//     in bypassPermissions and dontAsk, where it asks without it.
//
// The answer is the strongest across stages, deny > ask > allow: a gate's
// deny replaces a rewrite, a gate's ask turns an allow into an ask (the
// rewrite is kept, so the command still runs sandboxed). Only stage 4 can
// produce allow, and only when stage 3 said at most log. Only user-defined
// subjects rewrite; packs never do.
//
// Shadow mode (Phase 6, mode: shadow in the user file) is the one
// downgrade, applied in combine after stage 3 and before the answer
// leaves: a stage 3 ask or deny is recorded with what it would have done
// (would, would_reason) and not printed. Stage 4's answer, including the
// native-rule mirror and the hook's own safety asks, goes out unchanged;
// with none the hook prints nothing and Claude Code's own permission flow
// decides. Shadow mode never produces allow. An invalid user file is
// never in shadow mode.

// gateAction orders a gate stage result. Larger is stronger.
type gateAction int

const (
	gNone gateAction = iota
	gLog
	gAsk
	gDeny
)

func gateOf(a string) gateAction {
	switch a {
	case "deny":
		return gDeny
	case "ask":
		return gAsk
	case "log":
		return gLog
	}
	return gNone
}

func gateOfPolicy(a policy.Action) gateAction {
	switch a {
	case policy.ActionDeny:
		return gDeny
	case policy.ActionAsk:
		return gAsk
	case policy.ActionLog:
		return gLog
	}
	return gNone
}

// gateResult is the gate stage's answer.
type gateResult struct {
	action  gateAction
	reasons []string // one per hit or gate, value-free
	hits    []activity.RuleHit
	subject *activity.Subject // the strongest gate's subject, if a gate fired
	target  string            // normalised target for the record (~ for home)
	// temps are the ids of the temporaries that paused a hit (Plan 08): the
	// hit is in hits with action log and raised nothing.
	temps []string
}

// pause records a paused hit: kept with action log (what it did), never
// raised.
func (g *gateResult) pause(hit activity.RuleHit, tempID string) {
	hit.Action = "log"
	g.hits = append(g.hits, hit)
	g.temps = appendTemp(g.temps, tempID)
}

// appendTemp adds id to ids once.
func appendTemp(ids []string, id string) []string {
	for _, x := range ids {
		if x == id {
			return ids
		}
	}
	return append(ids, id)
}

// joinTemps is the record's temporary field: the ids sorted, comma-joined.
func joinTemps(ids []string) string {
	out := append([]string(nil), ids...)
	sort.Strings(out)
	return strings.Join(out, ",")
}

func (g *gateResult) raise(a gateAction, reason string) {
	if a > g.action {
		g.action = a
	}
	if reason != "" {
		g.reasons = append(g.reasons, reason)
	}
}

// loadedPolicy is the policy for one call.
type loadedPolicy struct {
	policy.Loaded
	cfg rules.Config
}

// UserPolicyPath and ProjectPolicyPath are the two policy files for a cwd.
func policyPaths(env Env, cwd string) (user, project string) {
	if env.UserCfgDir != "" {
		user = filepath.Join(env.UserCfgDir, "overrides.yaml")
	}
	if root := index.ProjectRoot(cwd, env.Home); root != "" {
		project = filepath.Join(root, manifest.ProjectOverridesFile)
	}
	return user, project
}

func loadPolicy(env Env, cwd string) loadedPolicy {
	cache := ""
	if env.StateDir != "" {
		cache = filepath.Join(env.StateDir, policy.CacheFile)
	}
	up, pp := policyPaths(env, cwd)
	l := policy.LoadCached(cache, up, pp)
	l.Policy.Home = env.Home
	l.Policy.ResolveEntries = true
	return loadedPolicy{Loaded: l, cfg: l.Policy.RulesConfig()}
}

// shadow reports whether the gate stage is in shadow mode (Phase 6). An
// invalid user file is never shadow: its mode cannot be read, and the
// "policy file is invalid" ask stays enforced.
func (lp loadedPolicy) shadow() bool {
	return lp.UserErr == nil && lp.Policy != nil && lp.Policy.Shadow()
}

// relevant is the tool fast filter: could stage 3 have an opinion?
func (lp loadedPolicy) relevant(tool string) bool {
	if lp.UserErr != nil {
		return true // fail closed: the user's gates are unknown
	}
	return lp.Policy.Relevant(lp.cfg, tool)
}

// toolInputs returns the rules input for a call: the pack input (without
// Text before the tool ran) and the text user rules read for tools whose
// input is not a command, path or URL.
func toolInputs(in Input, env Env, target policy.Target) (rules.Input, string) {
	ti := in.ToolInput
	str := func(k string) string { s, _ := ti[k].(string); return s }
	var ri rules.Input
	text := ""
	switch {
	case in.ToolName == "Bash":
		ri.Command = str("command")
	case isFileTool(in.ToolName):
		ri.FilePath = rawPath(in)
		if target.OK {
			ri.FilePath = tildeHome(target.Lexical, env.Home)
		}
		switch in.ToolName {
		case "Write":
			ri.Content = str("content")
		case "Edit":
			ri.Content = str("new_string")
		case "NotebookEdit":
			ri.Content = str("new_source")
		case "MultiEdit":
			if edits, ok := ti["edits"].([]any); ok {
				var parts []string
				for _, e := range edits {
					if m, ok := e.(map[string]any); ok {
						if s, ok := m["new_string"].(string); ok {
							parts = append(parts, s)
						}
					}
				}
				ri.Content = strings.Join(parts, "\n")
			}
		}
	case in.ToolName == "WebFetch":
		ri.URL = str("url")
	case in.ToolName == "WebSearch":
		text = str("query")
	default:
		if b, err := json.Marshal(ti); err == nil {
			if len(b) > rules.MaxInput {
				b = b[:rules.MaxInput]
			}
			text = string(b)
		}
	}
	return ri, text
}

func isFileTool(t string) bool {
	for _, f := range policy.FileTools {
		if t == f {
			return true
		}
	}
	return false
}

// rawPath is the file path a file tool's input names.
func rawPath(in Input) string {
	key := "file_path"
	if in.ToolName == "NotebookEdit" {
		key = "notebook_path"
	}
	s, _ := in.ToolInput[key].(string)
	return s
}

// gateStage runs packs, user rules and gates for one PreToolUse call.
func gateStage(in Input, env Env, cwd string, lp loadedPolicy) gateResult {
	var g gateResult
	tool := in.ToolName
	p := lp.Policy
	if lp.UserErr != nil {
		g.raise(gAsk, "your policy file is invalid ("+firstLine(lp.UserErr.Error())+"); gates and rules cannot be applied until it is fixed (watchdeck doctor)")
	}

	var target policy.Target
	switch {
	case isFileTool(tool):
		target = policy.NormalizePath(rawPath(in), cwd, env.Home)
		if target.OK {
			g.target = tildeHome(target.Lexical, env.Home)
		}
	case tool == "WebFetch":
		u, _ := in.ToolInput["url"].(string)
		target = policy.NormalizeHost(u)
		if target.OK {
			g.target = target.Lexical
		}
	}

	// packs
	ri, text := toolInputs(in, env, target)
	hits := rules.Eval(lp.cfg, tool, ri)
	if target.Real != "" {
		r2 := ri
		r2.FilePath = tildeHome(target.Real, env.Home)
		hits = mergeHits(hits, rules.Eval(lp.cfg, tool, r2))
	}
	// user rules read Text for tools without a command, path or URL
	ur := ri
	ur.Text = text
	hits = append(hits, p.EvalRules(tool, ur)...)
	if target.Real != "" && policy.UserRuleField(tool) == rules.FieldFilePath {
		r2 := ur
		r2.FilePath = tildeHome(target.Real, env.Home)
		hits = mergeHits(hits, p.EvalRules(tool, r2))
	}
	for _, h := range hits {
		hit := activity.RuleHit{Pack: h.Pack, ID: h.Rule, Version: h.Version, Severity: string(h.Severity), Action: string(h.Action)}
		// A paused rule (a temporary in force, Plan 08) has no opinion,
		// exactly like a rule switched off; its hit is only logged.
		if tid, ok := p.Paused(h.Pack, h.Rule, in.SessionID); ok {
			g.pause(hit, tid)
			continue
		}
		g.hits = append(g.hits, hit)
		id := h.Pack + "/" + h.Rule
		if h.Pack == policy.UserPack {
			id = "rule " + h.Rule
		}
		g.raise(gateOf(string(h.Action)), id+" ("+string(h.Severity)+", "+string(h.Action)+"): "+h.Description)
	}

	offer := func(d policy.Decision, what string) {
		a := gateOfPolicy(d.Action)
		if a == gNone || d.Subject == nil {
			return
		}
		if a > g.action || g.subject == nil {
			g.subject = &activity.Subject{Kind: d.Subject.Kind, Name: d.Subject.Name}
		}
		g.raise(a, d.Subject.Kind+" gate "+manifest.DisplayPath(d.Subject.Name)+" ("+d.Subject.Source.String()+" file): "+
			d.Action.String()+" "+what+" (entry "+manifest.DisplayPath(d.Pattern)+")")
	}

	// agent rules (subagents only: agent_type is on the hook input there)
	if in.AgentType != "" {
		offer(p.AgentToolAction(in.AgentType, tool), tool+" for agent type "+manifest.DisplayPath(in.AgentType))
		if tool == "Skill" {
			if sk := skillName(in.ToolInput); sk != "" {
				offer(p.AgentSkillAction(in.AgentType, sk), "skill "+manifest.DisplayPath(sk)+" for agent type "+manifest.DisplayPath(in.AgentType))
			}
		}
	}
	// MCP tools: every reading of mcp__<server>__<tool>; the strongest wins
	if splits, ok := policy.SplitMCPTool(tool); ok {
		var best policy.Decision
		for _, sp := range splits {
			if d := p.MCPToolAction(sp[0], sp[1]); d.Action > best.Action {
				best = d
			}
		}
		if best.Action != policy.ActionNone {
			if g.target == "" {
				g.target = tool
			}
			offer(best, "MCP tool "+manifest.DisplayPath(tool))
		}
	}
	// file path gates
	// A path that cannot be normalised (~user, relative without a cwd, a
	// macOS alias root such as /.vol or /.nofollow) asks whenever a path
	// gate or a pack rule watches the tool: neither can decide on it.
	if isFileTool(tool) && !target.OK && rawPath(in) != "" && (p.HasGates(tool, true) || rules.HasPreRules(lp.cfg, tool)) {
		g.raise(gAsk, "the "+tool+" path could not be normalised (relative without a cwd, ~user, or a macOS alias such as /.vol, /.resolve, /.nofollow); path gates and rules cannot decide")
	} else if isFileTool(tool) && p.HasGates(tool, true) {
		if !target.OK {
			g.raise(gAsk, "the "+tool+" path could not be normalised; path gates cannot decide")
		} else {
			d := p.ToolGate(tool, target.Lexical)
			if target.Real != "" {
				if d2 := p.ToolGate(tool, target.Real); d2.Action > d.Action {
					d = d2
				}
			}
			offer(d, tool+" on "+manifest.DisplayPath(g.target))
		}
	}
	// search tools: Grep and Glob search a directory (path, default the
	// cwd); a path under an entry gets the entry's action, an ancestor of an
	// entry asks (the search can reach it)
	if (tool == "Grep" || tool == "Glob") && p.HasGates(tool, true) {
		raw, _ := in.ToolInput["path"].(string)
		if raw == "" {
			raw = cwd
		}
		st := policy.NormalizePath(raw, cwd, env.Home)
		if !st.OK {
			g.raise(gAsk, "the "+tool+" path could not be normalised; path gates cannot decide")
		} else {
			if g.target == "" {
				g.target = tildeHome(st.Lexical, env.Home)
			}
			d := p.GateSearch(tool, st.Lexical)
			if st.Real != "" {
				if d2 := p.GateSearch(tool, st.Real); d2.Action > d.Action {
					d = d2
				}
			}
			offer(d, tool+" in "+manifest.DisplayPath(tildeHome(st.Lexical, env.Home)))
		}
	}
	// domain gates (WebFetch; WebSearch carries a query, not a URL)
	if tool == "WebFetch" && p.HasGates(tool, false) {
		if !target.OK {
			g.raise(gAsk, "the WebFetch host could not be normalised (empty, escaped or non-ASCII); domain gates cannot decide")
		} else {
			offer(p.GateHost(tool, target.Lexical), "WebFetch of host "+manifest.DisplayPath(target.Lexical))
		}
	}
	return g
}

// mergeHits appends the hits of b that a does not already have.
func mergeHits(a, b []rules.Hit) []rules.Hit {
	for _, h := range b {
		dup := false
		for _, x := range a {
			if x.Pack == h.Pack && x.Rule == h.Rule {
				dup = true
				break
			}
		}
		if !dup {
			a = append(a, h)
		}
	}
	return a
}

// tildeHome shows a path under home as ~/…, so a record never carries the
// home directory.
func tildeHome(p, home string) string {
	if home == "" {
		return p
	}
	for _, h := range []string{home, policy.CanonicalPath(home)} {
		h = strings.TrimRight(h, "/")
		if h == "" {
			continue
		}
		// case-folded: the canonical spelling of a target may differ in
		// case from $HOME on a case-insensitive volume
		switch {
		case strings.EqualFold(p, h):
			return "~"
		case len(p) > len(h) && p[len(h)] == '/' && strings.EqualFold(p[:len(h)], h):
			return "~" + p[len(h):]
		}
	}
	return p
}

// testNativeLoad, when set (tests only), runs each time the native rules
// are loaded.
var testNativeLoad func()

// loadNativeRules returns the Bash deny and ask rules of the person's
// Claude Code settings (managed, user, project, local), through the cache
// in the state dir. The project is CLAUDE_PROJECT_DIR when Claude Code set
// it, else the git root of cwd, else cwd.
func loadNativeRules(env Env, cwd string) []claudesettings.BashRule {
	if testNativeLoad != nil {
		testNativeLoad()
	}
	p := paths.Paths{Home: env.Home, ClaudeDir: env.Environ["CLAUDE_CONFIG_DIR"]}
	root := env.Environ["CLAUDE_PROJECT_DIR"]
	if root == "" {
		root = index.ProjectRoot(cwd, env.Home)
	}
	if root == "" {
		root = cwd
	}
	cache := ""
	if env.StateDir != "" {
		cache = filepath.Join(env.StateDir, claudesettings.RulesCacheFile)
	}
	if env.claudeManaged != nil {
		return claudesettings.LoadCachedRulesAt(cache, *env.claudeManaged, p, root)
	}
	return claudesettings.LoadCachedRulesFor(cache, p, root)
}

// nativeCheck matches command against the native Bash rules. hit is false
// when no rule matched and the command parsed; otherwise the answer is a
// deny (a deny rule) or an ask (an ask rule, an unreadable settings file,
// or a command that could not be parsed), without a rewrite; sandboxStage
// keeps its rewrite for an ask outside bypassPermissions and dontAsk.
func nativeCheck(env Env, cwd, command string) (*Output, meta, bool) {
	rules := loadNativeRules(env, cwd)
	bm := claudesettings.MatchBash(rules, command)
	m := meta{Enforcement: activity.EnforcementGate}
	switch {
	case bm.Rule != nil && bm.Rule.Unreadable:
		m.Rules = []activity.RuleHit{{Pack: activity.PackClaudeSettings, ID: "unreadable " + string(bm.Rule.Scope) + " settings", Action: Ask}}
		return ask("watchdeck: could not read your Claude Code "+string(bm.Rule.Scope)+" settings file, so its Bash deny and ask rules cannot be checked against this command", nil, ""), m, true
	case bm.Rule != nil && bm.Rule.Kind == claudesettings.KindDeny:
		m.Rules = []activity.RuleHit{{Pack: activity.PackClaudeSettings, ID: bm.Rule.Value, Action: Deny}}
		return &Output{HookSpecificOutput: Specific{
			HookEventName: "PreToolUse", PermissionDecision: Deny,
			PermissionDecisionReason: "watchdeck: blocked by your Claude Code deny rule " + bm.Rule.Value + " (" + string(bm.Rule.Scope) + " settings)",
			AdditionalContext: "The user's own Claude Code deny rule " + bm.Rule.Value + " matches part of this command. " +
				"Do not retry it another way; report the denial to the user.",
		}}, m, true
	case bm.Rule != nil:
		m.Rules = []activity.RuleHit{{Pack: activity.PackClaudeSettings, ID: bm.Rule.Value, Action: Ask}}
		return ask("watchdeck: your Claude Code ask rule "+bm.Rule.Value+" ("+string(bm.Rule.Scope)+" settings) matches part of this command", nil, ""), m, true
	case bm.Uncertain:
		return ask("watchdeck: could not parse this command against your Claude Code rules", nil, ""), m, true
	}
	return nil, meta{}, false
}

// combine merges the gate stage into the sandbox stage's answer. A deny
// from the sandbox stage (a native Claude Code rule) stays a deny. In
// shadow mode a gate ask or deny is recorded on m and not printed.
func combine(g gateResult, out *Output, m meta, shadow bool) (*Output, meta) {
	m.Rules = append(g.hits, m.Rules...)
	if g.target != "" {
		m.Target = g.target
	}
	if len(g.temps) > 0 {
		m.Temporary = joinTemps(g.temps)
	}
	if shadow && g.action >= gAsk {
		// Shadow mode (Phase 6): the gate stage's verdict is recorded, never
		// printed. The sandbox stage's answer goes out unchanged (a rewrite is
		// never shadowed); with none the hook stays silent and Claude Code's
		// own permission flow decides. Nothing here can say allow.
		m.Shadow = true
		m.Would = Ask
		if g.action == gDeny {
			m.Would = Deny
		}
		m.WouldReason = strings.Join(g.reasons, " | ")
		if out == nil {
			m.Enforcement = activity.EnforcementGate
			m.Subject = g.subject
		}
		return out, m
	}
	switch {
	case g.action == gDeny:
		m.Enforcement = activity.EnforcementGate
		if g.subject != nil {
			m.Subject = g.subject
		}
		reasons := g.reasons
		if out != nil {
			reasons = append(reasons, strings.TrimPrefix(out.HookSpecificOutput.PermissionDecisionReason, "watchdeck: "))
		}
		return &Output{HookSpecificOutput: Specific{
			HookEventName: "PreToolUse", PermissionDecision: Deny,
			PermissionDecisionReason: "watchdeck: denied by policy: " + strings.Join(reasons, " | "),
			AdditionalContext: "watchdeck denied this tool call by policy (a gate, not the OS sandbox). Do not retry it another way; " +
				"report the denial to the user, who can change the policy in watchdeck's overrides.yaml.",
		}}, m
	case g.action == gAsk:
		if out == nil {
			m.Enforcement = activity.EnforcementGate
			m.Subject = g.subject
			return ask("watchdeck: "+strings.Join(g.reasons, " | "), nil, ""), m
		}
		s := out.HookSpecificOutput
		if s.PermissionDecision != Deny {
			s.PermissionDecision = Ask // a gate's ask beats a sandbox allow, never a deny
		}
		s.PermissionDecisionReason = "watchdeck: " + strings.Join(g.reasons, " | ") + " | " + strings.TrimPrefix(s.PermissionDecisionReason, "watchdeck: ")
		return &Output{HookSpecificOutput: s}, m
	}
	// A paused hit alone is recorded like a log hit (Plan 08), shadow mode
	// or not: it decided nothing.
	if out == nil && (g.action == gLog || (g.action == gNone && len(g.temps) > 0)) {
		m.LogOnly = true
		m.Subject = g.subject
		m.Enforcement = activity.EnforcementGate
	}
	return out, m
}

// hostOnly is the normalised host of a URL, "" when it has none.
func hostOnly(u string) string {
	if t := policy.NormalizeHost(u); t.OK {
		return t.Lexical
	}
	return ""
}
