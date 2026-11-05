package mapmodel

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/activity"
	"github.com/Panda-Taps-LLC/watchdeck/internal/transcript"
)

// Timeline geometry (§3.10).
const (
	laneMain    = 150
	laneSub0    = 400
	laneStep    = 250
	maxSubLanes = 3
	rowY0       = 80
	rowStep     = 50
	rowGap      = 20
	gapAfter    = 30 * time.Second
)

// item is one timeline row.
type item struct {
	kind     string // prompt | spawn | call | return | run | orphan
	ts       time.Time
	seq      int
	ord      int
	id       string
	c        *call
	a        *agentInfo
	prompt   int
	orphan   int
	merged   int
	absorbed []string // a merged event: the tool_use ids of every call it stands for
	y        float64
}

func ordOf(kind string) int {
	switch kind {
	case "prompt":
		return 0
	case "spawn":
		return 1
	case "call":
		return 2
	case "return":
		return 3
	}
	return 4
}

// timeline lays the session out as rows in time order and one lane per
// agent, plus the skill-scripts and sandbox lanes (§3.10).
func (m *model) timeline(g *Graph, o Options) {
	items := m.timelineItems(o)
	m.tlNode = map[string]string{}

	// Rows.
	y := float64(rowY0)
	var ticks []TimeTick
	var prev *item
	for _, it := range items {
		gap := false
		if prev != nil {
			y += rowStep
			if !it.ts.IsZero() && !prev.ts.IsZero() && it.ts.Sub(prev.ts) > gapAfter {
				y += rowGap
				gap = true
			}
		}
		it.y = y
		mark := prev == nil || gap || it.kind == "spawn" || it.kind == "return" || (it.kind == "call" && len(it.c.skills) > 0)
		if mark && !it.ts.IsZero() {
			ticks = append(ticks, TimeTick{Y: y, Label: it.ts.In(o.Loc).Format("15:04:05")})
		}
		prev = it
	}
	lastY := y
	endY := lastY
	if g.Session.Live {
		endY = lastY + 60
		ticks = append(ticks, TimeTick{Y: endY, Label: "now", Tone: "ok"})
	}

	// Lanes.
	subs := m.agents[1:]
	nSub := len(subs)
	if nSub > maxSubLanes {
		nSub = maxSubLanes + 1
	}
	// Skills sit one step right of the last subagent lane, and at 650 when
	// there is at most one subagent lane, so columns stay where they are.
	skillsX := float64(laneSub0 + laneStep*max(1, nSub))
	sandboxX := skillsX + 240
	laneX := map[string]float64{transcript.MainAgentID: laneMain}
	laneID := map[string]string{transcript.MainAgentID: agentNode(transcript.MainAgentID)}
	for i, a := range subs {
		k := i
		if i >= maxSubLanes {
			k = maxSubLanes
			laneID[a.id] = "agent:other"
		} else {
			laneID[a.id] = agentNode(a.id)
		}
		laneX[a.id] = float64(laneSub0 + laneStep*k)
	}
	main := m.byAgent[transcript.MainAgentID]
	lanes := []Lane{{ID: agentNode(main.id), Kind: "agent", Label: "Main agent", X: laneMain, Y0: 48, Y1: endY, Spine: "light"}}
	if main.model != "" && main.model != "unknown" {
		lanes[0].Model = modelLabel(main.model)
	}
	type span struct{ y0, y1 float64 }
	spans := map[string]*span{}
	extend := func(lid string, y float64) {
		s := spans[lid]
		if s == nil {
			spans[lid] = &span{y, y}
			return
		}
		s.y0, s.y1 = math.Min(s.y0, y), math.Max(s.y1, y)
	}
	for _, it := range items {
		switch it.kind {
		case "spawn", "return":
			extend(laneID[it.a.id], it.y)
		case "call":
			if it.c.agent != transcript.MainAgentID {
				extend(laneID[it.c.agent], it.y)
			}
		}
	}
	other := 0
	for i, a := range subs {
		if i >= maxSubLanes {
			other++
			continue
		}
		l := Lane{ID: agentNode(a.id), Kind: "agent", Label: m.agentLabel(a.id) + " · subagent", X: laneX[a.id], Spine: "teal"}
		if a.model != "" && a.model != "unknown" {
			l.Model = modelLabel(a.model)
		}
		if s := spans[l.ID]; s != nil {
			l.Y0, l.Y1 = s.y0, s.y1
			if g.Session.Live && m.s != nil && !a.returned {
				l.Y1 = endY
			}
		}
		lanes = append(lanes, l)
	}
	if other > 0 {
		l := Lane{ID: "agent:other", Kind: "agent", Label: fmt.Sprintf("other subagents (%d)", other), X: laneSub0 + laneStep*maxSubLanes, Spine: "teal"}
		if s := spans[l.ID]; s != nil {
			l.Y0, l.Y1 = s.y0, s.y1
		}
		lanes = append(lanes, l)
	}
	lanes = append(lanes, Lane{ID: "skills", Kind: "skills", Label: "Skill scripts", X: skillsX}, Lane{ID: "sandbox", Kind: "sandbox", Label: "Sandbox", X: sandboxX})

	// Events and edges.
	var nodes []Node
	var edges []Edge
	byCall := map[string]map[string]*Node{} // call id → skill name → skill event (for the run's edges)
	for _, it := range items {
		switch it.kind {
		case "prompt":
			sum := ""
			if m.s != nil && it.prompt < len(m.s.Prompts) {
				sum = clip(m.s.Prompts[it.prompt].Summary, 60)
			}
			nodes = append(nodes, Node{ID: "ev:prompt:" + strconv.Itoa(it.prompt), Kind: "you", Label: "You", Sub: sum, X: laneMain, Y: it.y, W: 28, H: 28, Tone: "none", Event: true, TS: fmtTS(it.ts)})
		case "spawn":
			a := it.a
			var calls []*call
			for _, c := range m.calls {
				if c.agent == a.id {
					calls = append(calls, c)
				}
			}
			an := m.agentNode(a, calls, laneX[a.id], it.y, 44, false)
			sub := plural(len(calls), "call", "calls")
			if d, ok := an.Detail.(*AgentDetail); ok && d.SkillRuns > 0 {
				sub += " · " + plural(d.SkillRuns, "skill run", "skill runs")
			} else {
				sub += " · touched no skill"
			}
			n := Node{ID: "ev:spawn:" + a.id, Kind: "agent", Role: "subagent", Label: m.agentLabel(a.id) + " spawned", Sub: sub, X: an.X, Y: it.y, W: 44, H: 44,
				Tone: "teal", Event: true, ToolUseID: it.c.id, TS: fmtTS(it.ts), Authority: it.c.v.authority, Detail: an.Detail}
			nodes = append(nodes, n)
			m.tlNode[it.c.id] = n.ID
			px := laneX[it.c.agent]
			x1, x2 := px+6, n.X-n.W/2-4
			edges = append(edges, Edge{ID: "t:spawn:" + a.id, Kind: "spawn", From: agentNode(it.c.agent), To: n.ID, D: "M" + num(x1) + " " + num(it.y) + " H" + num(x2),
				Width: 1.8, Tone: "teal", Dash: "6 6", Label: "spawned", LX: r1((x1 + x2) / 2), LY: r1(it.y - 14)})
		case "return":
			a := it.a
			parent := a.parent
			if _, ok := laneX[parent]; !ok {
				parent = transcript.MainAgentID
			}
			sx, px, ry := laneX[a.id], laneX[parent], it.y
			d := "M" + num(sx) + " " + num(ry) + " C" + num(sx) + " " + num(ry+30) + " " + num(px+30) + " " + num(ry+20) + " " + num(px+10) + " " + num(ry+20)
			edges = append(edges, Edge{ID: "t:return:" + a.id, Kind: "return", From: agentNode(a.id), To: agentNode(parent), D: d, Width: 1.5, Tone: "teal", Dash: "4 6"})
		case "call":
			c := it.c
			n := m.callEvent(c, it, laneX[c.agent])
			nodes = append(nodes, n)
			m.tlNode[c.id] = n.ID
			for _, id := range it.absorbed {
				m.tlNode[id] = n.ID
			}
			if len(c.skills) == 0 {
				continue
			}
			tn := n
			byCall[c.id] = map[string]*Node{}
			for _, s := range c.skills {
				a := m.skillAgg[s]
				d := m.eventSkillDetail(a, c)
				sn := Node{ID: "ev:" + c.id + ":skill:" + s, Kind: "skill", Label: s, Sub: a.sub, X: skillsX, Y: it.y, W: 60, H: 60, Tone: a.tone,
					Requested: a.hasD && a.d.HasManifest, Event: true, ToolUseID: c.id, TS: fmtTS(c.ts), Authority: c.v.authority, Detail: d}
				nodes = append(nodes, sn)
				snc := sn
				byCall[c.id][s] = &snc
				e := link("t:skill_run:"+c.id+":"+s, "skill_run", &tn, &snc, c.v.gate, false)
				e.Count, e.Width, e.Policy, e.Tone, e.Glow = 1, 3, c.v.gatePolicy, c.v.gateTone, true
				if e.Tone == "" {
					e.Tone, e.Glow = "grey", false
				}
				e.Unsandboxed, e.Dotted, e.Pending, e.Inferred = c.v.unsandboxed, c.v.rejected, c.v.pending, c.v.approvalInferred
				if e.Unsandboxed {
					e.Dash = "5 4"
				}
				edges = append(edges, e)
			}
		case "run":
			c := it.c
			v := c.v
			var dur int64
			if c.run != nil {
				dur = c.run.DurationMS
			}
			var d *SkillDetail
			if len(c.skills) > 0 {
				d = m.eventSkillDetail(m.skillAgg[c.skills[0]], c)
			}
			rn := Node{ID: "ev:" + c.id + ":run", Kind: "sandbox", Label: "OS sandbox", Sub: runWords(v, dur), X: sandboxX, Y: it.y, W: 56, H: 56,
				Tone: nodeTone(v.outTone), Event: true, ToolUseID: c.id, TS: fmtTS(it.ts), Authority: v.authority}
			if d != nil {
				rn.Detail = d
			}
			nodes = append(nodes, rn)
			for _, s := range c.skills {
				sn := byCall[c.id][s]
				if sn == nil {
					continue
				}
				label := v.out
				if v.sandboxDeny && v.exit != nil && !strings.Contains(label, "exit") {
					label += " · exit " + strconv.Itoa(*v.exit)
				}
				e := link("t:sandbox:"+c.id+":"+s, "sandbox", sn, &rn, label, v.sandboxDeny)
				e.Count, e.Width = 1, 3
				switch {
				case v.sandboxDeny:
					e.Policy, e.Tone, e.Flow, e.Width = PolicyDeny, "deny", true, 4
				case v.outTone == "ok":
					e.Policy, e.Tone, e.Glow = PolicyAllow, "ok", true
				default:
					e.Tone = "grey"
				}
				edges = append(edges, e)
			}
		case "orphan":
			r := m.orphans[it.orphan]
			v := m.orphanV[it.orphan]
			rn := Node{ID: "ev:run:" + strconv.Itoa(it.orphan), Kind: "sandbox", Label: "OS sandbox", Sub: "run, caller unknown · " + runWords(v, r.DurationMS),
				X: sandboxX, Y: it.y, W: 56, H: 56, Tone: nodeTone(v.outTone), Event: true, TS: r.TS}
			if sk := uniqSorted(r.Skills); len(sk) > 0 {
				a := m.skillAgg[sk[0]]
				d := a.detail
				d.Command = r.Command
				d.Outcome = &Outcome{Tone: outTone(v), Label: v.out, Exit: v.exit, Evidence: v.evidence, TS: r.TS}
				d.CalledBy = "caller unknown (no decision matched the run)"
				rn.Detail = &d
			}
			nodes = append(nodes, rn)
		}
	}

	h := math.Max(o.Canvas.H, lastY+60)
	if g.Session.Live {
		h = math.Max(h, endY+40)
	}
	g.Canvas = Size{W: math.Max(o.Canvas.W, sandboxX+110), H: h}
	placePills(nodes, edges)
	g.Nodes = append(g.Nodes, nodes...)
	g.Edges = append(g.Edges, edges...)
	g.Lanes = lanes
	g.TicksY = ticks
}

func nodeTone(outTone string) string {
	switch outTone {
	case "deny", "ok":
		return outTone
	}
	return "none"
}

func runWords(v verdict, durMS int64) string {
	if v.sandboxDeny || durMS <= 0 {
		return v.out
	}
	return fmt.Sprintf("%s · %.1f s", v.out, float64(durMS)/1000)
}

// timelineItems gathers the rows in (TS, Seq) order and merges runs of
// identical no-opinion calls ("Grep ×5").
func (m *model) timelineItems(o Options) []*item {
	var items []*item
	if m.s != nil {
		k := 0
		for i := range m.s.Events {
			e := &m.s.Events[i]
			if e.Kind != "prompt" {
				continue
			}
			items = append(items, &item{kind: "prompt", ts: e.TS, seq: e.Seq, prompt: k, id: "p" + strconv.Itoa(k)})
			k++
		}
	}
	for i, c := range m.calls {
		if c.isSpawn() {
			if a := m.byAgent[c.spawned]; a != nil && c.spawned != "" {
				items = append(items, &item{kind: "spawn", ts: c.ts, seq: c.seq, c: c, a: a, id: c.id})
				continue
			}
		}
		if o.HideNone && c.v.policy == PolicyNone {
			continue
		}
		items = append(items, &item{kind: "call", ts: c.ts, seq: c.seq, c: c, id: c.id})
		if c.v.ran {
			it := &item{kind: "run", ts: c.ts, seq: 1<<23 + i, c: c, id: c.id}
			switch {
			case c.run != nil:
				if t := recTime(c.run); !t.IsZero() {
					it.ts = t
				}
			case c.res != nil:
				it.ts, it.seq = c.res.ts, c.res.seq
			}
			if tsLess(it.ts, c.ts) {
				it.ts = c.ts
			}
			items = append(items, it)
		}
	}
	for _, a := range m.agents[1:] {
		if a.returned && m.byAgent[a.id] != nil && a.spawnCall != "" {
			items = append(items, &item{kind: "return", ts: a.returnTS, seq: a.returnSeq, a: a, id: a.id})
		}
	}
	for i, r := range m.orphans {
		items = append(items, &item{kind: "orphan", ts: recTime(r), seq: 1<<24 + i, orphan: i, id: "o" + strconv.Itoa(i)})
	}
	for _, it := range items {
		it.ord = ordOf(it.kind)
	}
	sort.SliceStable(items, func(i, j int) bool {
		a, b := items[i], items[j]
		if tsLess(a.ts, b.ts) != tsLess(b.ts, a.ts) {
			return tsLess(a.ts, b.ts)
		}
		if a.seq != b.seq {
			return a.seq < b.seq
		}
		if a.ord != b.ord {
			return a.ord < b.ord
		}
		return a.id < b.id
	})
	// A spawn whose subagent was never seen returning keeps its lane open;
	// a return without its spawn row is dropped (tail read).
	spawned := map[string]bool{}
	var out []*item
	for _, it := range items {
		switch it.kind {
		case "spawn":
			spawned[it.a.id] = true
		case "return":
			if !spawned[it.a.id] {
				continue
			}
		case "call":
			if p := last(out); p != nil && p.kind == "call" && mergeable(p.c, it.c) {
				if p.merged == 0 {
					p.merged, p.absorbed = 1, []string{p.c.id}
				}
				p.merged++
				p.absorbed = append(p.absorbed, it.c.id)
				continue
			}
		}
		out = append(out, it)
	}
	return out
}

func last(xs []*item) *item {
	if len(xs) == 0 {
		return nil
	}
	return xs[len(xs)-1]
}

func mergeable(a, b *call) bool {
	return a.agent == b.agent && a.toolNodeID() == b.toolNodeID() &&
		a.v.policy == PolicyNone && b.v.policy == PolicyNone && a.v.authority == b.v.authority &&
		len(a.skills)+len(b.skills) == 0 && a.invoked == "" && b.invoked == "" && !a.isSpawn() && !b.isSpawn()
}

// callEvent is a call's event in its agent's lane.
func (m *model) callEvent(c *call, it *item, x float64) Node {
	size := 40.0
	if c.agent == transcript.MainAgentID {
		size = 52
	}
	n := Node{ID: "ev:" + c.id, Kind: "tool", Label: c.toolLabel(), X: x, Y: it.y, W: size, H: size, Tone: toneOf(c.v.policy),
		Event: true, ToolUseID: c.id, TS: fmtTS(c.ts), Authority: c.v.authority}
	if c.server != "" {
		n.Kind, n.Label = "mcp", c.mcpTool
	} else {
		n.Glyph = glyphFor(c.tool)
	}
	if len(c.skills) > 0 {
		n.ID += ":tool"
	}
	d := &EventDetail{Command: c.command}
	for _, h := range c.ruleHits() {
		d.Rules = append(d.Rules, ruleLabel(h))
	}
	n.RuleHits = len(d.Rules)
	if s := c.subjectLabel(); s != "" {
		d.Subject = s
		n.Subjects = []string{s}
	}
	for _, r := range []*activity.Record{c.dec, c.ruleLog} {
		if r != nil && r.Target != "" {
			d.Target = r.Target
			break
		}
	}
	what := ""
	switch {
	case c.command != "":
		what = clip(c.command, 48)
	case c.pattern != "":
		what, d.Pattern, d.Path = c.pattern, c.pattern, c.path
	case c.path != "":
		what, d.Path = c.path, c.path
	case c.host != "":
		what, d.Host = c.host, c.host
	case c.invoked != "":
		what, d.Skill = c.invoked, c.invoked
	}
	if it.merged > 1 {
		what = fmt.Sprintf("%s ×%d", c.toolLabel(), it.merged)
		d.Calls = it.merged
		d.ToolUseIDs = it.absorbed
		d.Command, d.Path, d.Pattern, d.Host = "", "", "", ""
	}
	if c.v.policy == PolicyNone {
		// watchdeck did not check the call. Who decided travels in
		// Node.Authority, which the dashboard prints as a word; Sub never
		// carries the raw authority word. Only a call with no authority at
		// all says "no check" here.
		if c.v.authority == "" {
			if what != "" {
				what += " · "
			}
			what += "no check"
		}
		// Shadow mode's label is the only gate text a call without a
		// policy can carry ("observed: would deny|ask"); the sub-line shows
		// it on the canvas, the card's decision line in the card.
		if c.v.observed != "" {
			if what != "" {
				what += " · "
			}
			what += c.v.observed
		}
		d.Decision = c.v.gate
	} else {
		d.Decision = decisionWords(c)
		d.Inferred = c.v.approvalInferred
		if len(c.skills) > 0 {
			d.Skill = strings.Join(c.skills, ", ")
		}
	}
	n.Sub = what
	n.Detail = d
	return n
}

// decisionWords is the decision line of a call's card. Shadow mode's
// observation goes last, after what happened to the call itself.
func decisionWords(c *call) string {
	v := c.v
	w := v.gate
	if v.observed != "" && w != v.observed {
		w = strings.TrimSuffix(w, " · "+v.observed)
	}
	switch {
	case v.blocked:
	case v.approved && v.gatePolicy == PolicyAsk:
		if c.autoMode() {
			w += " · approved in auto mode"
		} else {
			w += " · approved by you"
		}
		if v.approvalInferred {
			w += " (read from the result; no run record)"
		}
		if c.run != nil && !c.ts.IsZero() {
			if end := recTime(c.run); !end.IsZero() {
				start := end.Add(-time.Duration(c.run.DurationMS) * time.Millisecond)
				if s := int(math.Round(start.Sub(c.ts).Seconds())); s >= 1 {
					w += " after " + strconv.Itoa(s) + " s"
				}
			}
		}
	case v.rejected:
		w += " · declined by you"
	case v.pending:
		w += " · waiting for you"
	case v.gatePolicy == PolicyAllow:
		w += " · no prompt"
	}
	if v.decisionSrc == EvidenceHook {
		w += " (from the transcript's hook record)"
	}
	if v.observed != "" && w != v.observed {
		w += " · " + v.observed
	}
	return w
}

// eventSkillDetail is the skill's card narrowed to one call.
func (m *model) eventSkillDetail(a *skillAgg, c *call) *SkillDetail {
	d := a.detail
	d.Command = c.command
	d.Decision = decisionWords(c)
	d.Outcome = callOutcome(c)
	if c.run != nil && c.run.Effective != nil {
		d.RanUnder = viewItems(c.run.Effective)
	} else if !c.v.ran {
		d.RanUnder = nil
	}
	d.CalledBy = m.agentLabel(c.agent) + " via " + c.tool
	d.Joined = joinedWords(c)
	d.Inferred = c.v.approvalInferred
	return &d
}

func joinedWords(c *call) string {
	var p []string
	switch c.joinedBy {
	case "id":
		p = append(p, "decision joined by tool_use_id")
	case "command":
		p = append(p, "decision joined by command match")
	}
	if c.run != nil {
		switch c.run.JoinedBy {
		case activity.JoinedByWrite:
			p = append(p, "run joined at write time")
		case activity.JoinedByHeuristic:
			p = append(p, "run joined by command match")
		}
	}
	return strings.Join(p, "; ")
}
