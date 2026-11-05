package mapmodel

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/transcript"
)

// Topology columns (§3.9): node centre x and header x.
const (
	colModels  = 60
	colAgents  = 170
	colTools   = 430
	colSkills  = 700
	colSandbox = 884
)

func topoColumns() []Column {
	return []Column{{"Models", 30}, {"Agents", 120}, {"Tools", 402}, {"Skill scripts", 662}, {"Enforcement", 836}}
}

// Node sizes.
const (
	sizeYou     = 44
	sizeMain    = 104
	sizeSub     = 60
	sizeModel   = 44
	sizeTool    = 54
	sizeMCP     = 60
	sizeSkill   = 88
	sizeSandbox = 92
)

// toolAgg is one tool or MCP node's calls.
type toolAgg struct {
	id, label, glyph, server string
	first                    *call
	count                    int
	ring                     Ring
	byAgent                  map[string]int
	mcpTools                 map[string]int
	skillCalls               int
	rules                    map[string]int  // "pack/id: action" → hits (M6.4)
	subjects                 map[string]bool // subject labels (M6.4)
	authority                string          // the calls' one authority word; "" once two differ
	mixed                    bool
}

// addAuthority keeps the node's authority while every call shares it.
func (t *toolAgg) addAuthority(w string) {
	switch {
	case t.mixed:
	case t.count == 1:
		t.authority = w
	case t.authority != w:
		t.authority, t.mixed = "", true
	}
}

// topology lays the session out in fixed columns (§3.9).
func (m *model) topology(g *Graph, o Options) {
	g.Columns = topoColumns()
	nodes := map[string]*Node{}
	var order []*Node
	put := func(n Node) *Node {
		p := &n
		nodes[n.ID] = p
		order = append(order, p)
		return p
	}

	// Per-agent and per-tool aggregates.
	agentCalls := map[string][]*call{}
	tools := map[string]*toolAgg{}
	var toolOrder []string
	for _, c := range m.calls {
		agentCalls[c.agent] = append(agentCalls[c.agent], c)
		if c.isSpawn() {
			continue
		}
		id := c.toolNodeID()
		t := tools[id]
		if t == nil {
			t = &toolAgg{id: id, label: c.toolLabel(), server: c.server, first: c, byAgent: map[string]int{}, mcpTools: map[string]int{}, rules: map[string]int{}, subjects: map[string]bool{}}
			if c.server == "" {
				t.glyph = glyphFor(c.tool)
			}
			tools[id] = t
			toolOrder = append(toolOrder, id)
		}
		t.count++
		t.addAuthority(c.v.authority)
		t.ring.add(c.v.policy)
		t.byAgent[c.agent]++
		if c.server != "" {
			t.mcpTools[c.mcpTool]++
		}
		if len(c.skills) > 0 {
			t.skillCalls++
		}
		for _, h := range c.ruleHits() {
			t.rules[ruleLabel(h)]++
		}
		if s := c.subjectLabel(); s != "" {
			t.subjects[s] = true
		}
	}
	hidden := func(t *toolAgg) bool {
		return o.HideNone && t.id != "tool:Bash" && t.ring.None == t.count
	}

	// You and the main agent.
	main := m.byAgent[transcript.MainAgentID]
	var you *Node
	if m.s != nil {
		np := len(m.s.Prompts)
		you = put(Node{ID: "you", Kind: "you", Label: "You", Sub: plural(np, "prompt", "prompts") + " · " + plural(m.approvals(), "approval", "approvals"),
			X: colAgents, Y: 236, W: sizeYou, H: sizeYou, Count: np, Tone: "none"})
	}
	mainNode := put(m.agentNode(main, agentCalls[main.id], colAgents, 370, sizeMain, g.Session.Live))

	// Models: main's at its row, the others above it, then below.
	var models []string
	modelUsers := map[string][]*agentInfo{}
	for _, a := range m.agents {
		if a.model == "" || a.model == "unknown" {
			continue
		}
		if _, ok := modelUsers[a.model]; !ok {
			models = append(models, a.model)
		}
		modelUsers[a.model] = append(modelUsers[a.model], a)
	}
	upper := []float64{155, 65}
	other := 0
	for _, id := range models {
		y := 0.0
		if id == main.model {
			y = 370
		} else {
			if other < len(upper) {
				y = upper[other]
			} else {
				y = 460 + float64(other-len(upper))*90
			}
			other++
		}
		sub := "model"
		if id != main.model {
			sub = "model · subagents"
		}
		put(Node{ID: "model:" + id, Kind: "model", Label: modelLabel(id), Sub: sub, X: colModels, Y: y, W: sizeModel, H: sizeModel})
	}

	// Tools column: subagents, then tools (Bash first), then MCP servers.
	y := 110.0
	last := 0.0
	for _, a := range m.agents[1:] {
		live := g.Session.Live && m.s != nil && !a.returned
		put(m.agentNode(a, agentCalls[a.id], colTools, y, sizeSub, live))
		last = y
		y += 90
	}
	var plain, mcp []*toolAgg
	for _, id := range toolOrder {
		t := tools[id]
		if hidden(t) {
			continue
		}
		if t.server != "" {
			mcp = append(mcp, t)
		} else {
			plain = append(plain, t)
		}
	}
	sort.SliceStable(plain, func(i, j int) bool { return plain[i].id == "tool:Bash" && plain[j].id != "tool:Bash" })
	if len(plain) > 0 {
		y = 290
		if last > 0 {
			y = math.Max(290, last+90)
		}
		for _, t := range plain {
			put(m.toolNode(t, colTools, y))
			last = y
			y += 70
		}
	}
	if len(mcp) > 0 {
		y = 290
		if last > 0 {
			y = math.Max(290, last+80)
		}
		for _, t := range mcp {
			put(m.toolNode(t, colTools, y))
			y += 80
		}
	}

	// Skills and the sandbox.
	var skillYs []float64
	for i, name := range m.skillOrder {
		a := m.skillAgg[name]
		sy := 270 + float64(i)*130
		if len(m.skillOrder) == 1 {
			sy = 340
		}
		skillYs = append(skillYs, sy)
		d := a.detail
		put(Node{ID: "skill:" + name, Kind: "skill", Label: name, Sub: a.sub, X: colSkills, Y: sy, W: sizeSkill, H: sizeSkill,
			Count: a.count(), Tone: a.tone, Requested: a.hasD && a.d.HasManifest, Detail: &d})
	}
	if m.execs > 0 {
		sy := 340.0
		if len(skillYs) > 0 {
			sum := 0.0
			for _, v := range skillYs {
				sum += v
			}
			sy = math.Min(424, math.Max(296, r1(sum/float64(len(skillYs)))))
		}
		put(m.sandboxNode(colSandbox, sy, sizeSandbox))
	}

	// Edges.
	var edges []Edge
	if you != nil {
		edges = append(edges, Edge{ID: "e:prompt:you~agent:main", Kind: "prompt", From: "you", To: mainNode.ID,
			D: "M" + num(you.X) + " " + num(you.Y+you.H/2+4) + " V" + num(mainNode.Y-mainNode.H/2-4), Width: 2, Count: you.Count, Tone: "light"})
	}
	labelled := false
	for _, id := range models {
		mn := nodes["model:"+id]
		for _, a := range modelUsers[id] {
			an := nodes[agentNode(a.id)]
			if an == nil {
				continue
			}
			label := ""
			if !labelled {
				label, labelled = "runs on", true
			}
			e := link("e:runs_on:"+mn.ID+"~"+an.ID, "runs_on", mn, an, label, false)
			e.Width, e.Tone, e.Dash = 1.8, "blue", "2 4"
			if a.id != transcript.MainAgentID {
				e.Width = 1.5
			}
			edges = append(edges, e)
		}
	}
	labelled = false
	for _, a := range m.agents[1:] {
		parent := a.parent
		if nodes[agentNode(parent)] == nil {
			parent = transcript.MainAgentID
		}
		label := ""
		if !labelled {
			label, labelled = "spawned", true
		}
		e := link("e:spawn:"+agentNode(parent)+"~"+agentNode(a.id), "spawn", nodes[agentNode(parent)], nodes[agentNode(a.id)], label, false)
		e.Width, e.Tone, e.Dash = 1.8, "teal", "6 6"
		edges = append(edges, e)
	}
	for _, a := range m.agents {
		counts := map[string]int{}
		var ids []string
		for _, c := range agentCalls[a.id] {
			if c.isSpawn() {
				continue
			}
			id := c.toolNodeID()
			if counts[id] == 0 {
				ids = append(ids, id)
			}
			counts[id]++
		}
		for _, id := range ids {
			tn := nodes[id]
			if tn == nil {
				continue
			}
			e := link("e:call:"+agentNode(a.id)+"~"+id, "call", nodes[agentNode(a.id)], tn, "", false)
			e.Count, e.Width, e.Tone = counts[id], width(counts[id]), "grey"
			if tn.Kind == "mcp" {
				e.Tone, e.Dash = "violet", "6 6"
			}
			edges = append(edges, e)
		}
	}
	edges = append(edges, m.skillEdges(nodes)...)
	edges = append(edges, m.sandboxEdges(nodes)...)

	// Canvas grows instead of overlapping.
	h := o.Canvas.H
	for _, n := range order {
		h = math.Max(h, math.Ceil(n.Y+n.H/2+40))
	}
	g.Canvas = Size{W: o.Canvas.W, H: h}
	for _, n := range order {
		g.Nodes = append(g.Nodes, *n)
	}
	g.Edges = append(g.Edges, edges...)
}

func (a *skillAgg) count() int {
	if a.execs > 0 {
		return a.execs
	}
	return len(a.calls) + len(a.invokes)
}

// agentNode builds an agent's node at (x, y).
func (m *model) agentNode(a *agentInfo, calls []*call, x, y, size float64, live bool) Node {
	var ring Ring
	tools := map[string]int{}
	skillRuns := 0
	var spawned []string
	for _, c := range calls {
		ring.add(c.v.policy)
		tools[c.toolLabel()]++
		if c.v.ran {
			skillRuns++
		}
	}
	for _, b := range m.agents {
		parent := b.parent
		if parent == "" && b.id != transcript.MainAgentID {
			parent = transcript.MainAgentID
		}
		if parent == a.id && len(spawned) < maxList {
			spawned = append(spawned, agentNode(b.id))
		}
	}
	model := "model:" + a.model
	if a.model == "" {
		model = "model:unknown"
	}
	d := &AgentDetail{Model: model, Calls: len(calls), Tools: sortCounts(tools), Spawned: nonNilStrings(spawned), SkillRuns: skillRuns}
	n := Node{ID: agentNode(a.id), Kind: "agent", X: x, Y: y, W: size, H: size, Count: len(calls), Live: live, Ring: &ring, Detail: d}
	if a.id == transcript.MainAgentID {
		n.Label = "Main agent"
		n.Sub = fmt.Sprintf("%d spawned · %s", len(spawned), plural(skillRuns, "skill run", "skill runs"))
		return n
	}
	n.Role, n.Tone, n.Label = "subagent", "teal", m.agentLabel(a.id)
	parts := []string{"subagent"}
	if top := d.Tools; len(top) > 0 {
		var t []string
		for i, nc := range top {
			if i == 2 {
				break
			}
			t = append(t, fmt.Sprintf("%s ×%d", nc.Name, nc.Count))
		}
		parts = append(parts, strings.Join(t, " "))
	}
	if !a.spawnTS.IsZero() && !a.endTS.IsZero() && a.endTS.After(a.spawnTS) {
		parts = append(parts, fmt.Sprintf("%d s", int(math.Round(a.endTS.Sub(a.spawnTS).Seconds()))))
	}
	n.Sub = strings.Join(parts, " · ")
	return n
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// toolNode builds a tool or MCP node.
func (m *model) toolNode(t *toolAgg, x, y float64) Node {
	by := map[string]int{}
	for a, n := range t.byAgent {
		by[agentNode(a)] = n
	}
	var byAgent []AgentCount
	for _, nc := range sortCounts(by) {
		byAgent = append(byAgent, AgentCount{Agent: nc.Name, Count: nc.Count})
	}
	d := &ToolDetail{ByAgent: byAgent, Policy: t.ring}
	hits := 0
	if len(t.rules) > 0 {
		d.Rules = sortCounts(t.rules)
		for _, n := range t.rules {
			hits += n
		}
	}
	subjects := sortedNames(t.subjects)
	if t.server != "" {
		d.Tools = sortCounts(t.mcpTools)
		var names []string
		for i, nc := range d.Tools {
			if i == 2 {
				break
			}
			names = append(names, nc.Name)
		}
		return Node{ID: t.id, Kind: "mcp", Label: t.label, Sub: strings.Join(names, " · "), X: x, Y: y, W: sizeMCP, H: sizeMCP, Count: t.count, Tone: "violet", Authority: t.authority, RuleHits: hits, Subjects: subjects, Detail: d}
	}
	n := Node{ID: t.id, Kind: "tool", Label: t.label, Glyph: t.glyph, X: x, Y: y, W: sizeTool, H: sizeTool, Count: t.count, Tone: "light", Authority: t.authority, RuleHits: hits, Subjects: subjects, Detail: d}
	switch {
	case t.skillCalls > 0:
		n.Sub = fmt.Sprintf("%d of %d ran skill scripts", t.skillCalls, t.count)
	case t.ring.None == t.count:
		n.Tone, n.Sub = "none", "no check"
		if len(t.byAgent) == 1 {
			for a := range t.byAgent {
				if a != transcript.MainAgentID {
					n.Sub = "by " + m.agentLabel(a)
				}
			}
		}
	default:
		n.Sub = policyWords(t.ring)
	}
	return n
}

func policyWords(r Ring) string {
	var p []string
	for _, x := range []struct {
		w string
		n int
	}{{"allow", r.Allow}, {"ask", r.Ask}, {"denied", r.Deny}} {
		if x.n > 0 {
			p = append(p, fmt.Sprintf("%s %d", x.w, x.n))
		}
	}
	return strings.Join(p, " · ")
}

// sandboxNode builds the OS sandbox node from every run of the session.
func (m *model) sandboxNode(x, y, size float64) Node {
	d := &SandboxDetail{}
	var last *verdict
	var lastRunDur int64
	tone := "ok"
	visit := func(v verdict, backend string, dur int64) {
		d.Runs++
		if v.sandboxDeny {
			d.Denials++
			tone = "deny"
		}
		if backend != "" {
			d.Backend = backendName(backend)
		}
		vv := v
		last, lastRunDur = &vv, dur
	}
	// In time order: calls (sorted) and orphans interleaved by timestamp.
	type ex struct {
		v       verdict
		backend string
		dur     int64
		ts      time.Time
	}
	var xs []ex
	for _, c := range m.calls {
		if !c.v.ran {
			continue
		}
		e := ex{v: c.v, ts: c.ts}
		if c.run != nil {
			e.backend, e.dur, e.ts = c.run.Backend, c.run.DurationMS, recTime(c.run)
		}
		xs = append(xs, e)
	}
	for i, r := range m.orphans {
		xs = append(xs, ex{v: m.orphanV[i], backend: r.Backend, dur: r.DurationMS, ts: recTime(r)})
	}
	sort.SliceStable(xs, func(i, j int) bool { return tsLess(xs[i].ts, xs[j].ts) })
	for _, e := range xs {
		visit(e.v, e.backend, e.dur)
	}
	// M6.4: the non-skill subjects that ran here (command subjects, MCP
	// servers launched through run), by name and run count.
	subj := map[string]int{}
	for _, c := range m.calls {
		if c.run != nil && c.run.Subject != nil && c.run.Subject.Kind != "skill" {
			subj[c.run.Subject.Kind+" "+c.run.Subject.Name]++
		}
	}
	for _, r := range m.orphans {
		if r.Subject != nil && r.Subject.Kind != "skill" {
			subj[r.Subject.Kind+" "+r.Subject.Name]++
		}
	}
	var subjects []string
	if len(subj) > 0 {
		d.Subjects = sortCounts(subj)
		for _, nc := range d.Subjects {
			subjects = append(subjects, nc.Name+" (sandbox)")
		}
	}
	n := Node{ID: "sandbox", Kind: "sandbox", Label: "OS sandbox", X: x, Y: y, W: size, H: size, Count: d.Runs, Tone: tone, Subjects: subjects, Detail: d}
	be := d.Backend
	if be == "" {
		be = "OS sandbox"
	}
	n.Sub = be + " · " + plural(d.Runs, "run", "runs")
	if last != nil {
		d.LastExit = last.exit
		// The last run's exit and duration only: a denial is the node's tone
		// and the edge's label, never sub2 (the page colours sub2 green).
		n.Sub2 = "ran"
		if last.exit != nil {
			n.Sub2 = "exit " + strconv.Itoa(*last.exit)
		}
		if lastRunDur > 0 {
			n.Sub2 += fmt.Sprintf(" · %.1f s", float64(lastRunDur)/1000)
		}
	}
	return n
}

// gateRank orders gate badges by how much the user needs to see them.
func gateRank(v verdict) int {
	switch {
	case v.blocked:
		return 6
	case v.rejected:
		return 5
	case v.pending:
		return 4
	case v.unsandboxed:
		return 3
	case v.approved:
		return 2
	case v.gatePolicy == PolicyAsk:
		return 1
	}
	return 0
}

// skillEdges are tool→skill edges (gate) and Skill-tool invocations.
func (m *model) skillEdges(nodes map[string]*Node) []Edge {
	type agg struct {
		from, to string
		calls    []*call
		invoke   bool
	}
	var list []*agg
	idx := map[string]*agg{}
	for _, c := range m.calls {
		targets := c.skills
		invoke := false
		if len(targets) == 0 && c.invoked != "" {
			targets, invoke = []string{c.invoked}, true
		}
		for _, s := range targets {
			k := c.toolNodeID() + ">" + s
			a := idx[k]
			if a == nil {
				a = &agg{from: c.toolNodeID(), to: "skill:" + s, invoke: invoke}
				idx[k] = a
				list = append(list, a)
			}
			a.calls = append(a.calls, c)
		}
	}
	var out []Edge
	for _, a := range list {
		from, to := nodes[a.from], nodes[a.to]
		if from == nil || to == nil {
			continue
		}
		n := len(a.calls)
		if a.invoke {
			e := link("e:invoke:"+a.from+"~"+a.to, "invoke", from, to, "invoked", false)
			e.Count, e.Width, e.Tone, e.Dash = n, width(n), "light", "2 4"
			rep := a.calls[n-1]
			if rep.v.policy == PolicyDeny {
				e.Tone, e.Policy, e.Label = "deny", PolicyDeny, rep.v.gate
			}
			out = append(out, e)
			continue
		}
		rep := a.calls[0]
		for _, c := range a.calls[1:] {
			if gateRank(c.v) >= gateRank(rep.v) {
				rep = c
			}
		}
		label := rep.v.gate
		if n > 1 {
			label += fmt.Sprintf(" ×%d", n)
		}
		e := link("e:skill_run:"+a.from+"~"+a.to, "skill_run", from, to, label, false)
		e.Count, e.Width = n, width(n)
		if e.Width < 3 {
			e.Width = 3
		}
		e.Policy, e.Tone, e.Glow = rep.v.gatePolicy, rep.v.gateTone, true
		if e.Tone == "" {
			e.Tone, e.Glow = "grey", false
		}
		e.Unsandboxed, e.Dotted, e.Pending, e.Inferred = rep.v.unsandboxed, rep.v.rejected, rep.v.pending, rep.v.approvalInferred
		if e.Unsandboxed {
			e.Dash = "5 4"
		}
		out = append(out, e)
	}
	return out
}

// sandboxEdges are skill→sandbox edges, one per skill with executions.
func (m *model) sandboxEdges(nodes map[string]*Node) []Edge {
	sb := nodes["sandbox"]
	if sb == nil {
		return nil
	}
	var out []Edge
	for _, name := range m.skillOrder {
		a := m.skillAgg[name]
		sn := nodes["skill:"+name]
		if sn == nil || a.execs == 0 {
			continue
		}
		var vs []verdict
		for _, c := range a.calls {
			if c.v.ran {
				vs = append(vs, c.v)
			}
		}
		vs = append(vs, a.orphanV...)
		var rep verdict
		deny := false
		for _, v := range vs {
			if v.sandboxDeny || !deny {
				rep = v
			}
			deny = deny || v.sandboxDeny
		}
		label := rep.out
		if len(vs) > 1 {
			label += fmt.Sprintf(" ×%d", len(vs))
		}
		e := link("e:sandbox:skill:"+name+"~sandbox", "sandbox", sn, sb, label, deny)
		e.Count, e.Width = len(vs), width(len(vs))
		switch {
		case deny:
			e.Policy, e.Tone, e.Flow = PolicyDeny, "deny", true
			if e.Width < 4 {
				e.Width = 4
			}
		case rep.outTone == "ok":
			e.Policy, e.Tone, e.Glow = PolicyAllow, "ok", true
			if e.Width < 3 {
				e.Width = 3
			}
		default:
			e.Tone = "grey"
		}
		out = append(out, e)
	}
	return out
}
