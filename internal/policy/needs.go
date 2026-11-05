package policy

import (
	"sort"
	"strings"

	"github.com/Panda-Taps-LLC/watchdeck/internal/rules"
)

// FileTools are the tools whose input names a file path.
var FileTools = [...]string{"Read", "Write", "Edit", "MultiEdit", "NotebookEdit"}

// WebTools are the tools whose input names a URL or a search query.
var WebTools = [...]string{"WebFetch", "WebSearch"}

// GatesFor reports whether a gate or a user rule of this policy could have
// an opinion on a call of tool: a tool subject with path or domain entries
// whose match.tools names it, an mcp subject whose name matches the server
// of an mcp__ tool, an agent subject whose tools lists name it (or, for the
// Skill tool, any skills.allow list), or a user rule for it. The built-in
// packs are separate (rules.HasPreRules).
func (p *Policy) GatesFor(tool string) bool {
	if p == nil {
		return false
	}
	splits, isMCP := SplitMCPTool(tool)
	for _, s := range p.subjects {
		switch s.Kind {
		case KindTool:
			if bestTier(s.Match.Tools, tool) >= 0 && (!s.Paths.IsEmpty() || !s.Domains.IsEmpty()) {
				return true
			}
		case KindMCP:
			if !isMCP || len(s.MCPTools) == 0 {
				continue
			}
			for _, sp := range splits {
				if tier(s.Name, sp[0]) >= 0 {
					return true
				}
			}
		case KindAgent:
			if s.AgentTools != nil && (bestTier(s.AgentTools.Deny, tool) >= 0 || bestTier(s.AgentTools.Ask, tool) >= 0) {
				return true
			}
			if tool == "Skill" && s.AgentSkills != nil {
				return true
			}
		}
	}
	for _, r := range p.rules {
		if tier(r.Tool, tool) >= 0 {
			return true
		}
	}
	return false
}

// HasKind reports whether some subject has kind k.
func (p *Policy) HasKind(k Kind) bool {
	if p == nil {
		return false
	}
	for _, s := range p.subjects {
		if s.Kind == k {
			return true
		}
	}
	return false
}

// Relevant reports whether the hook could have an opinion on a PreToolUse
// call of tool beyond the skill and command-subject path: a gate, a user
// rule, or an enabled pack rule under cfg.
func (p *Policy) Relevant(cfg rules.Config, tool string) bool {
	return rules.HasPreRules(cfg, tool) || p.GatesFor(tool)
}

// FilesNeed lists the file tools (in FileTools order) that need the hook
// for a rule only the hook enforces, and names the reason for the first:
// a path gate (a tool subject with path entries) or an agent gate naming the
// tool, the person's own rule for it, or an enabled built-in pack rule for it
// at ask or deny on any field a PreToolUse call carries, unless that rule's
// native twin is installed (its id in covered, rulebook.CoveredTwins) and it
// is at its default action. A rule raised above its default never counts as
// covered: its twin's strings were chosen for the default and can be
// narrower than the rule (read-other-credentials names ~/.netrc only). Log
// rules never count; the gap they leave is documented in DESIGN §8.
func (p *Policy) FilesNeed(cfg rules.Config, covered []string) (tools []string, why string) {
	for _, t := range FileTools {
		if r := p.FileNeed(cfg, covered, t); r != "" {
			if why == "" {
				why = r
			}
			tools = append(tools, t)
		}
	}
	return tools, why
}

// FileNeed is FilesNeed for one tool: the reason it needs the hook, or "".
func (p *Policy) FileNeed(cfg rules.Config, covered []string, tool string) string {
	if p != nil {
		for _, r := range p.rules {
			if tier(r.Tool, tool) >= 0 {
				return "your rule " + r.ID
			}
		}
		for _, s := range p.subjects {
			switch s.Kind {
			case KindTool:
				if bestTier(s.Match.Tools, tool) >= 0 && (!s.Paths.IsEmpty() || !s.Domains.IsEmpty()) {
					return "a path rule for " + tool
				}
			case KindAgent:
				if s.AgentTools != nil && (bestTier(s.AgentTools.Deny, tool) >= 0 || bestTier(s.AgentTools.Ask, tool) >= 0) {
					return "an agent rule for " + tool
				}
			}
		}
	}
	for _, r := range rules.RulesFor(cfg, tool) {
		if r.Action != rules.Deny && r.Action != rules.Ask {
			continue
		}
		if r.Action == r.Default && hasID(covered, r.ID) {
			continue
		}
		switch {
		case r.Action == rules.Deny:
			return r.ID + " set to deny"
		case r.Field == rules.FieldContent:
			return r.ID + " asks before a write"
		case tool == "Read":
			return r.ID + " asks before a read"
		default:
			return r.ID + " asks before an edit"
		}
	}
	return ""
}

func hasID(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// Matchers are the hook registrations a policy needs beyond the base six
// (Bash, Skill, PermissionDenied and the three lifecycle events).
type Matchers struct {
	Files        bool     // PreToolUse Read|Write|Edit|MultiEdit|NotebookEdit
	FileTools    []string // when set, PreToolUse for exactly these file tools instead (settings.NeededExtra)
	Web          bool     // PreToolUse WebFetch|WebSearch
	MCP          bool     // PreToolUse mcp__.*
	Other        []string // PreToolUse for other tools named by a gate or rule, sorted
	All          bool     // a gate or rule names tools by a wildcard: PreToolUse for every tool
	PostWebFetch bool     // PostToolUse WebFetch|WebSearch (the prompt-injection pack)
}

// ExtraMatchers reports which registrations the policy needs: a tool group
// is registered only when some enabled pack rule, gate or user rule could
// have an opinion on one of its tools.
func (p *Policy) ExtraMatchers(cfg rules.Config) Matchers {
	var m Matchers
	for _, t := range FileTools {
		m.Files = m.Files || p.Relevant(cfg, t)
	}
	for _, t := range WebTools {
		m.Web = m.Web || p.Relevant(cfg, t)
		m.PostWebFetch = m.PostWebFetch || rules.HasPostRules(cfg, t)
	}
	other := map[string]bool{}
	note := func(pat string) {
		switch {
		case pat == "" || pat == "Bash" || pat == "Skill":
		case strings.HasPrefix(pat, "mcp__"):
			m.MCP = true
		case strings.ContainsAny(pat, "*?"):
			lit := pat[:strings.IndexAny(pat, "*?")]
			if strings.HasPrefix("mcp__", lit) || strings.HasPrefix(lit, "mcp__") {
				m.MCP = true
			}
			if !strings.HasPrefix(lit, "mcp__") {
				m.All = true // a wildcard that may name any tool
			}
		default:
			for _, t := range FileTools {
				if pat == t {
					m.Files = true
					return
				}
			}
			for _, t := range WebTools {
				if pat == t {
					m.Web = true
					return
				}
			}
			other[pat] = true
		}
	}
	if p != nil {
		for _, s := range p.subjects {
			switch s.Kind {
			case KindMCP:
				if len(s.MCPTools) > 0 {
					m.MCP = true
				}
			case KindTool:
				if !s.Paths.IsEmpty() || !s.Domains.IsEmpty() {
					for _, t := range s.Match.Tools {
						note(t)
					}
				}
			case KindAgent:
				if s.AgentTools != nil {
					for _, t := range s.AgentTools.Deny {
						note(t)
					}
					for _, t := range s.AgentTools.Ask {
						note(t)
					}
				}
			}
		}
		for _, r := range p.rules {
			note(r.Tool)
		}
	}
	for t := range other {
		m.Other = append(m.Other, t)
	}
	sort.Strings(m.Other)
	return m
}
