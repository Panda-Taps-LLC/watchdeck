package mapmodel

import (
	"sort"
	"strings"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/activity"
	"github.com/Panda-Taps-LLC/watchdeck/internal/transcript"
)

// Detail shapes for non-skill nodes.

// AgentDetail is an agent's card.
type AgentDetail struct {
	Model     string      `json:"model"` // "model:<id>", "model:unknown" without a transcript
	Calls     int         `json:"calls"`
	Tools     []NameCount `json:"tools"`
	Spawned   []string    `json:"spawned"`
	SkillRuns int         `json:"skill_runs"`
}

// ToolDetail is a tool's or an MCP server's card.
type ToolDetail struct {
	Tools   []NameCount  `json:"tools,omitempty"` // MCP: per-tool counts
	ByAgent []AgentCount `json:"by_agent"`
	Policy  Ring         `json:"policy"`
	Rules   []NameCount  `json:"rules,omitempty"` // M6.4: "pack/id: action" hits, most first
}

// SandboxDetail is the sandbox's card.
type SandboxDetail struct {
	Runs     int    `json:"runs"`
	Denials  int    `json:"denials"`
	Backend  string `json:"backend,omitempty"`
	LastExit *int   `json:"last_exit,omitempty"`
	// Subjects counts the runs of non-skill subjects ("mcp github",
	// "command npm-scripts"), M6.4.
	Subjects []NameCount `json:"subjects,omitempty"`
}

// EventDetail is a timeline event's card (non-skill events).
type EventDetail struct {
	Command  string `json:"command,omitempty"`
	Decision string `json:"decision,omitempty"`
	Skill    string `json:"skill,omitempty"`
	Path     string `json:"path,omitempty"`
	Pattern  string `json:"pattern,omitempty"`
	Host     string `json:"host,omitempty"`
	Calls    int    `json:"calls,omitempty"`
	// M6.4: the rules that matched ("pack/id: action"), the deciding
	// subject ("tool files (gate)") and the normalised target.
	Rules    []string `json:"rules,omitempty"`
	Subject  string   `json:"subject,omitempty"`
	Target   string   `json:"target,omitempty"`
	Inferred bool     `json:"inferred,omitempty"` // approved, read from the Bash result (no run record)
	// ToolUseIDs lists every call a merged event stands for ("Grep ×5").
	ToolUseIDs []string `json:"tool_use_ids,omitempty"`
}

// NameCount is a tool name and its call count.
type NameCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// AgentCount is an agent node id and a call count.
type AgentCount struct {
	Agent string `json:"agent"`
	Count int    `json:"count"`
}

const maxList = 12 // caps on detail lists (§4)

func sortCounts(m map[string]int) []NameCount {
	out := make([]NameCount, 0, len(m))
	for k, v := range m {
		out = append(out, NameCount{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Name < out[j].Name
	})
	if len(out) > maxList {
		out = out[:maxList]
	}
	return out
}

func (m *model) agentLabel(id string) string {
	if id == transcript.MainAgentID {
		return "Main agent"
	}
	if a := m.byAgent[id]; a != nil && a.typ != "" {
		return a.typ
	}
	return "subagent"
}

func agentNode(id string) string { return "agent:" + id }

// isSpawn reports an Agent/Task call, drawn as a spawn, not a tool.
func (c *call) isSpawn() bool {
	if c.ev != nil && c.ev.Kind == "spawn" {
		return true
	}
	return c.tool == "Agent" || c.tool == "Task"
}

// toolNodeID is the topology node a call is drawn on.
func (c *call) toolNodeID() string {
	if c.server != "" {
		return "mcp:" + c.server
	}
	return "tool:" + c.tool
}

// toolLabel is a tool's name as nodes and lists show it.
func (c *call) toolLabel() string {
	if c.server != "" {
		return "MCP " + c.server
	}
	return c.tool
}

func glyphFor(tool string) string {
	switch tool {
	case "Bash":
		return "bash"
	case "Read":
		return "read"
	case "Grep":
		return "grep"
	case "Glob":
		return "glob"
	case "Edit", "MultiEdit", "NotebookEdit":
		return "edit"
	case "Write":
		return "write"
	case "WebFetch":
		return "webfetch"
	case "WebSearch":
		return "websearch"
	case "Agent", "Task":
		return "agent-tool"
	case "Skill":
		return "skill-tool"
	}
	return "generic"
}

// modelLabel shortens a model id: "claude-opus-5-5" → "opus-5.5",
// "claude-sonnet-4-5-20250929" → "sonnet-4.5".
func modelLabel(id string) string {
	s := strings.TrimPrefix(id, "claude-")
	parts := strings.Split(s, "-")
	if n := len(parts); n > 1 && len(parts[n-1]) == 8 && digits(parts[n-1]) {
		parts = parts[:n-1]
	}
	if n := len(parts); n > 2 && len(parts[n-1]) <= 2 && len(parts[n-2]) <= 2 && digits(parts[n-1]) && digits(parts[n-2]) {
		parts = append(parts[:n-2], parts[n-2]+"."+parts[n-1])
	}
	return strings.Join(parts, "-")
}

func digits(s string) bool {
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

func backendName(b string) string {
	switch b {
	case "seatbelt":
		return "Seatbelt"
	case "bwrap":
		return "bubblewrap"
	}
	return b
}

// sessionInfo is the header block and liveness.
func (m *model) sessionInfo(o Options) SessionInfo {
	si := SessionInfo{ID: m.sid, Harness: activity.HarnessClaudeCode, Cwd: o.Cwd, NoTranscripts: o.NoTranscripts || (m.s == nil && !o.TranscriptMissing)}
	if m.s == nil && o.TranscriptMissing && !o.NoTranscripts {
		si.TranscriptMissing, si.TranscriptPath = true, o.TranscriptPath
	}
	var first, last time.Time
	if m.s != nil {
		si.Truncated = m.s.Truncated
		first, last = m.s.Started, m.s.LastEvent
	}
	for _, t := range m.recTimes {
		if first.IsZero() || t.Before(first) {
			first = t
		}
		if t.After(last) {
			last = t
		}
	}
	si.Started, si.Last = fmtTS(first), fmtTS(last)
	si.Live = !o.Now.IsZero() && !last.IsZero() && o.Now.Sub(last) < LiveWindow
	return si
}

// ticks is one entry per call, in order; never filtered. A call in dropped
// (Options.Authorities) names no node: in topology its tool node may still
// be drawn for the calls that were kept.
func (m *model) ticks(g *Graph, dropped map[string]bool) []Tick {
	have := map[string]bool{}
	if g.View == ViewTopology {
		for _, n := range g.Nodes {
			have[n.ID] = true
		}
	}
	out := make([]Tick, 0, len(m.calls))
	for _, c := range m.calls {
		t := Tick{ID: c.id, TS: fmtTS(c.ts), Tool: c.tool, Policy: c.v.policy, Authority: c.v.authority}
		if len(c.skills) > 0 {
			t.Skill = c.skills[0]
		} else if c.invoked != "" {
			t.Skill = c.invoked
		}
		if g.View == ViewTopology {
			id := c.toolNodeID()
			if c.isSpawn() {
				id = ""
				if c.spawned != "" {
					id = agentNode(c.spawned)
				}
			}
			if have[id] && !dropped[c.id] {
				t.Node = id
			}
			if a := agentNode(c.agent); have[a] {
				t.Agent = a
			}
			t.Ran = c.v.ran
		} else {
			// The event that shows the call, also when it was merged into
			// an earlier event ("Grep ×5").
			t.Node = m.tlNode[c.id]
		}
		out = append(out, t)
	}
	return out
}

// totals counts over the whole session (HideNone and Authorities do not
// change them).
func (m *model) totals() Totals {
	var t Totals
	t.Agents = len(m.agents)
	models := map[string]bool{}
	for _, a := range m.agents {
		if a.model != "" && a.model != "unknown" {
			models[a.model] = true
		}
	}
	t.Models = len(models)
	tools, servers := map[string]bool{}, map[string]bool{}
	for _, c := range m.calls {
		if t.ByAuthority == nil {
			t.ByAuthority = map[string]int{}
		}
		t.ByAuthority[c.v.authority]++
		switch {
		case c.v.authority == AuthorityDenyRule, c.v.authority == AuthorityClassifier:
			t.BlockedCalls++
		case c.v.authority == AuthorityHook && c.v.policy == PolicyDeny:
			t.BlockedCalls++
		case (c.v.authority == AuthorityUser || c.v.authority == AuthorityBlocked) && c.v.authRejected:
			// A person's "No" and a rejection this reader does not
			// recognise: refused before running, as the You and Blocked
			// chips count them.
			t.BlockedCalls++
		}
		switch c.v.policy {
		case PolicyAllow:
			t.Allow++
		case PolicyAsk:
			t.Ask++
		case PolicyDeny:
			t.Deny++
		default:
			t.None++
		}
		if c.isSpawn() {
			continue
		}
		if c.server != "" {
			servers[c.server] = true
		} else {
			tools[c.tool] = true
		}
	}
	t.Tools, t.MCP = len(tools), len(servers)
	t.Skills = len(m.skillOrder)
	t.Denials = t.Deny
	for _, v := range m.orphanV {
		if v.sandboxDeny {
			t.Denials++
		}
	}
	return t
}

// approvals counts asks the user approved: the ask has a joined run (so
// it certainly went ahead) and was not answered by auto mode.
func (m *model) approvals() int {
	n := 0
	for _, c := range m.calls {
		if c.v.approved && c.run != nil && !c.autoMode() {
			n++
		}
	}
	return n
}

// autoMode reports a call decided under permission_mode auto, where an
// ask is answered by Claude Code's classifier, not by the user.
func (c *call) autoMode() bool {
	for _, r := range []*activity.Record{c.dec, c.run} {
		if r != nil && r.PermMode != "" {
			return r.PermMode == "auto"
		}
	}
	return false
}
