package mapmodel

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/activity"
	"github.com/Panda-Taps-LLC/watchdeck/internal/transcript"

	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
)

// fallbackWindow is how far apart a transcript Bash call and an id-less
// decision with the same command may be (§3.6 step 3).
const fallbackWindow = 60 * time.Second

// call is one tool call: a transcript tool_use, or (with no transcript, or
// when the transcript lacks it) a decision, denial or Skill invocation from
// the activity log.
type call struct {
	id      string
	ts      time.Time
	seq     int
	agent   string // agent id ("main" or the bare subagent id)
	tool    string // Bash, Read, Agent, Skill, mcp__server__tool, ...
	server  string // MCP server, "" otherwise
	mcpTool string
	command string // Bash command as the agent wrote it
	path    string // display path (relative to the session cwd)
	pattern string
	host    string
	spawned string // for an Agent call: the subagent id when linked

	ev  *transcript.Event // nil for activity-only calls
	res *resultView       // the tool_result, nil when absent

	authority transcript.Authority // the verdict on the tool_result row (zero when none)
	errText   string               // the first 160 bytes, on a rune boundary, of an is_error result, every tool

	hookDecision, hookRewrite, hookReason string // the transcript's hook_success attachment

	dec     *activity.Record // the decision for this call
	run     *activity.Record // the run joined to the decision
	denied  *activity.Record // an auto-mode denial
	invoked string           // skill named by a Skill tool call (transcript or skill_invoked record)
	ruleLog *activity.Record // a rule_log record for this call (M6.4): log-only rule hits

	joinedBy string // "id" | "command" (transcript↔decision), with the run's own joined_by kept on run

	skills []string // skills the call's command ran (sorted, deduped)
	v      verdict
}

// resultView is the part of a tool_result the policy reads.
type resultView struct {
	text    string // the first 240 characters of a Bash result
	isError bool
	ts      time.Time
	seq     int
}

// agentInfo is one agent of the session.
type agentInfo struct {
	id        string
	typ       string
	name      string
	model     string
	parent    string // agent id that spawned it, "" for main and for unlinked agents
	spawnCall string // the parent's Agent tool_use id, when linked
	spawnTS   time.Time
	endTS     time.Time
	returnTS  time.Time // the parent's tool_result for the spawn
	returnSeq int
	returned  bool
}

// model is the intermediate state shared by both layouts.
type model struct {
	s        *transcript.Session
	sid      string
	cwd      string // the session's real cwd, for relative paths and run matching (never serialized)
	agents   []*agentInfo
	byAgent  map[string]*agentInfo
	calls    []*call
	orphans  []*activity.Record // runs no call claims ("run, caller unknown")
	orphanV  []verdict          // their sandbox-stage verdicts, same index
	recTimes []time.Time        // timestamps of the kept records
	declared map[string]Declared
	live     bool

	skillOrder []string
	skillAgg   map[string]*skillAgg
	execs      int // executions that reached the sandbox (runs plus transcript-inferred)

	tlNode map[string]string // timeline: tool_use id → the event node that shows it (merged events included)
}

// sortedRecords returns a copy of recs in a total order: timestamp (records
// without a parseable one last), then the record's own JSON bytes. Join walks
// slice order, so this is what makes shuffled input give the same graph.
func sortedRecords(recs []activity.Record) []activity.Record {
	type keyed struct {
		r  activity.Record
		t  time.Time
		ok bool
		b  []byte
	}
	ks := make([]keyed, len(recs))
	for i, r := range recs {
		t, err := time.Parse(time.RFC3339Nano, r.TS)
		b, _ := json.Marshal(r)
		ks[i] = keyed{r: r, t: t, ok: err == nil, b: b}
	}
	sort.SliceStable(ks, func(i, j int) bool {
		a, b := ks[i], ks[j]
		if a.ok != b.ok {
			return a.ok
		}
		if !a.t.Equal(b.t) {
			return a.t.Before(b.t)
		}
		return bytes.Compare(a.b, b.b) < 0
	})
	out := make([]activity.Record, len(ks))
	for i := range ks {
		out[i] = ks[i].r
	}
	return out
}

func recTime(r *activity.Record) time.Time {
	t, err := time.Parse(time.RFC3339Nano, r.TS)
	if err != nil {
		return time.Time{}
	}
	return t
}

// assemble joins the transcript and the records into calls (§3.6).
func assemble(s *transcript.Session, recs []activity.Record, o Options) *model {
	m := &model{s: s, byAgent: map[string]*agentInfo{}}
	if s != nil {
		m.sid, m.cwd = s.ID, s.Cwd
	} else {
		m.sid, m.cwd = o.SessionID, o.Cwd
	}
	direct := strings.HasPrefix(m.sid, "direct:")

	// 1. Order, give id-less decisions a synthetic id (so Join carries it to
	// their run), join run↔decision over everything.
	all := sortedRecords(recs)
	synthetic := map[string]bool{}
	for i := range all {
		if all[i].Kind == activity.KindDecision && all[i].ToolUseID == "" {
			id := "rec-" + strconv.Itoa(i)
			all[i].ToolUseID = id
			synthetic[id] = true
		}
	}
	all = activity.Join(all)

	// 2. Keep this session's records. A record with no session id after
	// the join (a hand-typed `watchdeck run`, or a run no decision
	// claims) belongs only to its cwd's direct pseudo-session: the caller
	// passes those, filtered to one cwd, with a "direct:" SessionID. A real
	// session never takes one in, even from its own cwd and window: two
	// sessions sharing a cwd could otherwise both claim it, and a run typed
	// by hand during a session is not that session's.
	var keptIdx []int
	for i := range all {
		r := &all[i]
		switch {
		case direct && r.SessionID == "":
			keptIdx = append(keptIdx, i)
		case !direct && r.SessionID != "" && r.SessionID == m.sid:
			keptIdx = append(keptIdx, i)
		}
	}
	sort.Ints(keptIdx)
	kept := make([]*activity.Record, len(keptIdx))
	for k, i := range keptIdx {
		kept[k] = &all[i]
	}
	for _, r := range kept {
		if t := recTime(r); !t.IsZero() {
			m.recTimes = append(m.recTimes, t)
		}
	}

	// 3. Agents.
	m.agentsFrom(s, kept)

	// 4. Index records by tool_use id.
	decByID := map[string]*activity.Record{}
	runByID := map[string]*activity.Record{}
	deniedByID := map[string]*activity.Record{}
	invokedByID := map[string]*activity.Record{}
	ruleLogByID := map[string]*activity.Record{}
	var runs []*activity.Record
	for _, r := range kept {
		switch r.Kind {
		case activity.KindDecision:
			decByID[r.ToolUseID] = r // the latest wins
		case activity.KindRun:
			runs = append(runs, r)
			if r.ToolUseID != "" {
				if _, dup := runByID[r.ToolUseID]; !dup {
					runByID[r.ToolUseID] = r
				}
			}
		case activity.KindDenied:
			if r.ToolUseID != "" {
				deniedByID[r.ToolUseID] = r
			}
		case activity.KindSkillInvoked:
			if r.ToolUseID != "" {
				invokedByID[r.ToolUseID] = r
			}
		case activity.KindRuleLog:
			if r.ToolUseID != "" {
				ruleLogByID[r.ToolUseID] = r
			}
		}
	}
	usedRuleLog := map[*activity.Record]bool{}
	usedDec := map[string]bool{}
	usedDenied := map[*activity.Record]bool{}
	usedInvoked := map[*activity.Record]bool{}

	// 5. Transcript calls, joined by id.
	if s != nil {
		for i := range s.Events {
			e := &s.Events[i]
			if !e.IsCall() || e.ToolCall == nil {
				continue
			}
			c := m.callFromEvent(s, e)
			if d := decByID[c.id]; d != nil && !synthetic[c.id] {
				c.dec, c.joinedBy = d, "id"
				usedDec[c.id] = true
			}
			if d := deniedByID[c.id]; d != nil {
				c.denied = d
				usedDenied[d] = true
			}
			if r := invokedByID[c.id]; r != nil {
				usedInvoked[r] = true
				if c.invoked == "" {
					c.invoked = r.Skill
				}
			}
			if r := ruleLogByID[c.id]; r != nil {
				c.ruleLog = r
				usedRuleLog[r] = true
			}
			m.calls = append(m.calls, c)
		}
		// 6. Decisions without ids: same command, nearest within 60 s.
		for _, r := range kept {
			if r.Kind != activity.KindDecision || !synthetic[r.ToolUseID] {
				continue
			}
			dt := recTime(r)
			var best *call
			var bestD time.Duration
			for _, c := range m.calls {
				if c.dec != nil || c.tool != "Bash" || c.command != r.Command || c.ts.IsZero() || dt.IsZero() {
					continue
				}
				d := c.ts.Sub(dt)
				if d < 0 {
					d = -d
				}
				if d > fallbackWindow {
					continue
				}
				if best == nil || d < bestD {
					best, bestD = c, d
				}
			}
			if best != nil {
				best.dec, best.joinedBy = r, "command"
				usedDec[r.ToolUseID] = true
			}
		}
	}

	// 7. Activity-only calls.
	seq := 1 << 20
	for _, r := range kept {
		seq++
		switch r.Kind {
		case activity.KindDecision:
			if usedDec[r.ToolUseID] || decByID[r.ToolUseID] != r {
				continue
			}
			tool := r.ToolName // M6.4: gates decide other tools too
			if tool == "" {
				tool = "Bash"
			}
			c := m.callFromRecord(r, tool, seq)
			c.dec = r
			if rl := ruleLogByID[r.ToolUseID]; rl != nil && !synthetic[r.ToolUseID] {
				c.ruleLog = rl
				usedRuleLog[rl] = true
			}
			// a gated Skill call has both a skill_invoked and a decision record
			if inv := invokedByID[r.ToolUseID]; inv != nil && !synthetic[r.ToolUseID] {
				usedInvoked[inv] = true
				c.invoked = inv.Skill
			}
			if d := deniedByID[r.ToolUseID]; d != nil && !synthetic[r.ToolUseID] {
				c.denied = d
				usedDenied[d] = true
			}
			m.calls = append(m.calls, c)
		}
	}
	seq = 1 << 21
	for _, r := range kept {
		seq++
		switch r.Kind {
		case activity.KindDenied:
			if usedDenied[r] {
				continue
			}
			tool := r.ToolName
			if tool == "" {
				tool = "Bash"
			}
			c := m.callFromRecord(r, tool, seq)
			c.denied = r
			if tool == "Skill" {
				c.invoked = r.Skill
			}
			usedDenied[r] = true
			m.calls = append(m.calls, c)
		case activity.KindRuleLog:
			if usedRuleLog[r] {
				continue
			}
			tool := r.ToolName
			if tool == "" {
				tool = "Bash"
			}
			c := m.callFromRecord(r, tool, seq)
			c.ruleLog = r
			usedRuleLog[r] = true
			m.calls = append(m.calls, c)
		case activity.KindSkillInvoked:
			if usedInvoked[r] || r.Skill == "" {
				continue
			}
			c := m.callFromRecord(r, "Skill", seq)
			c.invoked = r.Skill
			usedInvoked[r] = true
			m.calls = append(m.calls, c)
		}
	}

	// 8. Runs onto calls by the decision's id (write-time or Join's), the rest are orphans.
	byID := map[string]*call{}
	for _, c := range m.calls {
		if c.dec != nil {
			byID[c.dec.ToolUseID] = c
		}
	}
	for _, r := range runs {
		if r.ToolUseID != "" {
			if c := byID[r.ToolUseID]; c != nil && c.run == nil && runByID[r.ToolUseID] == r {
				c.run = r
				continue
			}
		}
		m.orphans = append(m.orphans, r)
	}

	// 9. Skills per call, then order calls.
	for _, c := range m.calls {
		var sk []string
		for _, r := range []*activity.Record{c.dec, c.run, c.denied} {
			if r != nil && r.Kind != activity.KindSkillInvoked {
				sk = append(sk, r.Skills...)
			}
		}
		if c.denied != nil && c.denied.ToolName == "Skill" && c.denied.Skill != "" {
			sk = append(sk, c.denied.Skill)
		}
		if c.dec == nil && c.denied == nil {
			// Only the transcript's hook attachment: the skills are in its rewrite.
			sk = append(sk, rewriteSkills(c.hookRewrite)...)
		}
		c.skills = uniqSorted(sk)
	}
	sort.SliceStable(m.calls, func(i, j int) bool { return callLess(m.calls[i], m.calls[j]) })
	return m
}

func callLess(a, b *call) bool {
	if tsLess(a.ts, b.ts) != tsLess(b.ts, a.ts) {
		return tsLess(a.ts, b.ts)
	}
	if a.seq != b.seq {
		return a.seq < b.seq
	}
	return a.id < b.id
}

// tsLess orders timestamps with zero (missing) after every real one.
func tsLess(a, b time.Time) bool {
	if a.IsZero() != b.IsZero() {
		return !a.IsZero()
	}
	return a.Before(b)
}

func uniqSorted(xs []string) []string {
	if len(xs) == 0 {
		return nil
	}
	out := append([]string(nil), xs...)
	sort.Strings(out)
	w := 0
	for i, x := range out {
		if x == "" || (i > 0 && x == out[i-1]) {
			continue
		}
		out[w] = x
		w++
	}
	return out[:w]
}

func (m *model) callFromEvent(s *transcript.Session, e *transcript.Event) *call {
	tc := e.ToolCall
	c := &call{
		id:           tc.ID,
		ts:           e.TS,
		seq:          e.Seq,
		agent:        e.Agent,
		tool:         tc.Name,
		server:       tc.MCPServer,
		mcpTool:      tc.MCPTool,
		command:      tc.Command,
		path:         m.rel(tc.Path),
		pattern:      tc.Pattern,
		host:         tc.URL,
		invoked:      tc.Skill,
		ev:           e,
		hookDecision: tc.HookDecision,
		hookRewrite:  tc.HookRewrite,
		hookReason:   tc.HookReason,
	}
	if c.id == "" {
		c.id = "seq-" + strconv.Itoa(e.Seq)
	}
	if tc.Spawn != nil {
		c.spawned = tc.Spawn.AgentID
	}
	if c.server == "" {
		c.server, c.mcpTool = splitMCP(c.tool)
	}
	if r := s.Result(tc.ID); r != nil {
		c.res = &resultView{text: r.Snippet, isError: r.IsError, ts: r.TS, seq: r.Seq}
		c.authority, c.errText = r.Authority, r.ErrorText
	}
	if _, ok := m.byAgent[c.agent]; !ok {
		c.agent = transcript.MainAgentID
	}
	return c
}

func (m *model) callFromRecord(r *activity.Record, tool string, seq int) *call {
	c := &call{id: r.ToolUseID, ts: recTime(r), seq: seq, tool: tool, command: r.Command, agent: transcript.MainAgentID}
	if c.command == "" && r.Argv0 != "" {
		c.command = r.Argv0 + " … (command not recorded)" // a gate-only record (M6.4)
	}
	if c.id == "" {
		c.id = "rec-" + strconv.Itoa(seq)
	}
	if strings.HasPrefix(tool, "mcp__") {
		c.server, c.mcpTool = splitMCP(tool)
	}
	if r.AgentID != "" {
		if _, ok := m.byAgent[r.AgentID]; ok {
			c.agent = r.AgentID
		}
	}
	return c
}

// agentsFrom builds the agent list: the transcript's agents, then any agent
// only the records name (no transcript, or a tail read that missed it).
func (m *model) agentsFrom(s *transcript.Session, kept []*activity.Record) {
	add := func(a *agentInfo) {
		m.agents = append(m.agents, a)
		m.byAgent[a.id] = a
	}
	if s != nil {
		spawnBy := map[string]*transcript.Event{}
		for i := range s.Events {
			e := &s.Events[i]
			if e.Kind == "spawn" && e.ToolCall != nil && e.ToolCall.Spawn != nil && e.ToolCall.Spawn.AgentID != "" {
				if _, ok := spawnBy[e.ToolCall.Spawn.AgentID]; !ok {
					spawnBy[e.ToolCall.Spawn.AgentID] = e
				}
			}
		}
		for _, a := range s.Agents {
			ai := &agentInfo{id: a.ID, typ: a.Type, name: a.Name, model: a.Model, spawnTS: a.SpawnTS, endTS: a.EndTS}
			if a.ID != transcript.MainAgentID {
				if sp := spawnBy[a.ID]; sp != nil {
					ai.parent, ai.spawnCall = sp.Agent, sp.ToolCall.ID
					if ai.typ == "" {
						ai.typ = sp.ToolCall.Spawn.SubagentType
					}
					if ai.spawnTS.IsZero() || (!sp.TS.IsZero() && sp.TS.Before(ai.spawnTS)) {
						ai.spawnTS = sp.TS
					}
					if r := s.Result(sp.ToolCall.ID); r != nil {
						ai.returned, ai.returnTS, ai.returnSeq = true, r.TS, r.Seq
					}
				}
			}
			add(ai)
		}
	}
	if _, ok := m.byAgent[transcript.MainAgentID]; !ok {
		main := &agentInfo{id: transcript.MainAgentID, model: "unknown"}
		m.agents = append([]*agentInfo{main}, m.agents...)
		m.byAgent[main.id] = main
	}
	for _, r := range kept {
		if r.AgentID == "" || !transcript.ValidID(r.AgentID) {
			continue
		}
		if a, ok := m.byAgent[r.AgentID]; ok {
			if a.typ == "" {
				a.typ = r.AgentType
			}
			continue
		}
		t := recTime(r)
		add(&agentInfo{id: r.AgentID, typ: r.AgentType, model: "unknown", spawnTS: t, endTS: t})
	}
	for _, r := range kept {
		if a, ok := m.byAgent[r.AgentID]; ok && a.id != transcript.MainAgentID && (m.s == nil || m.s.AgentByID(a.id) == nil) {
			if t := recTime(r); !t.IsZero() && t.After(a.endTS) {
				a.endTS = t
			}
		}
	}
}

// rel shows a tool's file path relative to the session cwd, or by base name
// when it lies elsewhere, so no absolute path reaches the page.
func (m *model) rel(p string) string {
	if p == "" {
		return ""
	}
	if m.cwd != "" {
		cwd := filepath.Clean(m.cwd)
		cp := filepath.Clean(p)
		if cp == cwd {
			return "."
		}
		if strings.HasPrefix(cp, cwd+string(filepath.Separator)) {
			return cp[len(cwd)+1:]
		}
	}
	if filepath.IsAbs(p) {
		return filepath.Base(p)
	}
	return p
}

// rewriteSkills reads the skill names from the hook's rewrite, whose
// grammar is fixed: watchdeck run --skill <n> [--skill <n>] -c '<original>'.
// Anything else gives nil.
func rewriteSkills(rewrite string) []string {
	f := strings.Fields(rewrite)
	if len(f) < 4 || filepath.Base(f[0]) != paths.BinaryName || f[1] != "run" {
		return nil
	}
	var out []string
	for i := 2; i < len(f); i++ {
		switch {
		case f[i] == "-c":
			return out
		case f[i] == "--skill" && i+1 < len(f):
			out = append(out, f[i+1])
			i++
		case strings.HasPrefix(f[i], "--skill="):
			out = append(out, strings.TrimPrefix(f[i], "--skill="))
		default:
			return nil
		}
	}
	return nil
}

// splitMCP splits mcp__<server>__<tool> at the first "__" after the prefix
// (§3.5); the server part may itself hold single underscores.
func splitMCP(name string) (server, tool string) {
	rest, ok := strings.CutPrefix(name, "mcp__")
	if !ok {
		return "", ""
	}
	i := strings.Index(rest, "__")
	if i <= 0 || i+2 >= len(rest) {
		return "", ""
	}
	return rest[:i], rest[i+2:]
}
