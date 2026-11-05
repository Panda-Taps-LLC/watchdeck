package mapmodel

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/Panda-Taps-LLC/watchdeck/internal/activity"
	"github.com/Panda-Taps-LLC/watchdeck/internal/manifest"
	"github.com/Panda-Taps-LLC/watchdeck/internal/transcript"
)

func TestHideNone(t *testing.T) {
	s := loadA(t)
	all := Build(s, recsA(t), declaredA(t), optsA(s, ViewTopology, false))
	hid := Build(s, recsA(t), declaredA(t), optsA(s, ViewTopology, true))
	for _, id := range []string{"tool:Read", "tool:Grep", "tool:SubagentHandback"} {
		if node(all, id) == nil || node(hid, id) != nil {
			t.Errorf("%s: want present without hide-none, absent with it", id)
		}
		for _, e := range hid.Edges {
			if e.To == id || e.From == id {
				t.Errorf("edge %s still touches hidden %s", e.ID, id)
			}
		}
	}
	for _, id := range []string{"you", "agent:main", "agent:a3033ade8c1d9c1a5", "model:claude-opus-5-5", "tool:Bash", "skill:canary-basic", "skill:canary-request", "sandbox"} {
		if node(hid, id) == nil {
			t.Errorf("hide-none removed %s", id)
		}
	}
	if b := node(hid, "tool:Bash"); b.Count != 2 || b.Sub != "2 of 2 ran skill scripts" {
		t.Errorf("Bash %d %q", b.Count, b.Sub)
	}
	// Ticks are the whole session, for Read too, but no tick names a hidden node.
	if len(hid.Ticks) != len(all.Ticks) || !reflect.DeepEqual(hid.Totals, all.Totals) || hid.Totals.None != 4 {
		t.Errorf("ticks or totals changed: %d/%d %+v %+v", len(hid.Ticks), len(all.Ticks), hid.Totals, all.Totals)
	}
	for _, tk := range hid.Ticks {
		if tk.Tool == "Read" && tk.Node != "" {
			t.Errorf("tick names hidden node %s", tk.Node)
		}
	}
	// Timeline: the Read event goes, the spawn and the skill events stay.
	tl := Build(s, recsA(t), declaredA(t), optsA(s, ViewTimeline, true))
	if node(tl, "ev:toolu_01PEzFa65hdCYERmSZVb9Yej") != nil {
		t.Error("timeline kept a no-opinion event under hide-none")
	}
	if node(tl, "ev:spawn:a3033ade8c1d9c1a5") == nil || node(tl, "ev:"+idMainProbe+":run") == nil {
		t.Error("timeline dropped a spawn or a run under hide-none")
	}
}

func TestDeclaredVsDid(t *testing.T) {
	s := loadA(t)
	g := Build(s, recsA(t), declaredA(t), optsA(s, ViewTopology, false))
	if v := skillDetail(t, g, "skill:canary-request").DeclaredVsDid; v.Verdict != VerdictAsDeclared || v.Did != "1 connect, refused" || !v.Floor {
		t.Errorf("canary-request %+v", v)
	}
	if v := skillDetail(t, g, "skill:canary-basic").DeclaredVsDid; v.Verdict != VerdictUndeclared || v.Declared != "no manifest" {
		t.Errorf("canary-basic %+v", v)
	}

	b := newSess().
		call(1, "main", "toolu_c", "Bash", probeNet).result(2, "main", "toolu_c", "done", false).
		call(5, "main", "toolu_u", "Bash", "python3 .claude/skills/canary-basic/scripts/probe.py net")
	recs := []activity.Record{
		dec("toolu_c", 1, "allow", "canary-request", probeNet), run("toolu_c", 1.8, activity.OutcomeOK, 0, "canary-request", probeNet),
		dec("toolu_u", 5, "ask", "canary-basic", "python3 .claude/skills/canary-basic/scripts/probe.py net"),
	}
	g = Build(b.s, recs, declaredA(t), Options{Now: at(3600)})
	if v := skillDetail(t, g, "skill:canary-request").DeclaredVsDid; v.Verdict != VerdictClean {
		t.Errorf("clean run: %+v", v)
	}
	if v := skillDetail(t, g, "skill:canary-basic").DeclaredVsDid; v.Verdict != VerdictUnknown || v.Did != "not run" {
		t.Errorf("decision without a run: %+v", v)
	}
	// A reached capability the manifest does not declare is undeclared.
	b = newSess().call(1, "main", "toolu_x", "Bash", "python3 .claude/skills/canary-basic/scripts/probe.py net").result(2, "main", "toolu_x", "net: ALLOWED", false)
	recs = []activity.Record{dec("toolu_x", 1, "allow", "canary-basic", "x"), run("toolu_x", 1.5, activity.OutcomeOK, 0, "canary-basic", "x")}
	recs[0].Command, recs[1].Command = b.s.Events[0].ToolCall.Command, b.s.Events[0].ToolCall.Command
	g = Build(b.s, recs, declaredA(t), Options{Now: at(3600)})
	if v := skillDetail(t, g, "skill:canary-basic").DeclaredVsDid; v.Verdict != VerdictUndeclared || v.Did != "network reached" {
		t.Errorf("reached network without a manifest: %+v", v)
	}
}

// TestGrantReflected: the same session and records, Declared before and
// after `watchdeck allow canary-request --network all`. The card's
// granted list, sub and fix follow the grant passed in; after the grant
// only env: CANARY_SECRET stays ungranted, which has no CLI form, so the
// fix and the grant button go away.
func TestGrantReflected(t *testing.T) {
	s := loadA(t)
	before := declaredWith(t, manifest.Default())
	widened := manifest.Default()
	widened.Network = manifest.NetAll
	after := declaredWith(t, widened)
	if got := after["canary-request"].Ungranted; !reflect.DeepEqual(got, []string{"env: CANARY_SECRET"}) {
		t.Fatalf("Clip after the grant: %v", got)
	}
	for _, view := range []string{ViewTopology, ViewTimeline} {
		id := "skill:canary-request"
		if view == ViewTimeline {
			id = "ev:" + idSubGrep + ":skill:canary-request"
		}
		gb := Build(s, recsA(t), before, optsA(s, view, false))
		ga := Build(s, recsA(t), after, optsA(s, view, false))
		db, da := skillDetail(t, gb, id), skillDetail(t, ga, id)
		if db.Fix != "watchdeck allow canary-request --network all" || db.Grant == nil || db.Grant.Network != "all" {
			t.Errorf("%s before: fix %q grant %+v", view, db.Fix, db.Grant)
		}
		if da.Fix != "" || da.Grant != nil {
			t.Errorf("%s after: fix %q grant %+v, want none", view, da.Fix, da.Grant)
		}
		if db.Granted[0] != "net none" || da.Granted[0] != "net all" {
			t.Errorf("%s granted %v → %v", view, db.Granted, da.Granted)
		}
		nb, na := node(gb, id), node(ga, id)
		if nb.Sub != "asked net all · granted none" || na.Sub != "asked net all · granted all" {
			t.Errorf("%s sub %q → %q", view, nb.Sub, na.Sub)
		}
	}
	// A manifest whose only extra is the network: after the grant nothing is
	// ungranted, the shield turns green.
	req := canaryRequest(t)
	req.Env = nil
	_, ung := manifest.Clip(req, widened)
	d := map[string]Declared{"canary-request": {Skill: "canary-request", HasManifest: true, Request: req, Granted: widened, Ungranted: ung}}
	g := Build(s, recsA(t), d, optsA(s, ViewTopology, false))
	if n := node(g, "skill:canary-request"); n.Tone != "ok" || n.Sub != "asked net all · granted all" {
		t.Errorf("fully granted: tone %q sub %q", n.Tone, n.Sub)
	}
	// Records' "<skill>: item" form is accepted too.
	d["canary-request"] = Declared{Skill: "canary-request", HasManifest: true, Request: req, Granted: manifest.Default(), Ungranted: []string{"canary-request: network: all", "other: network: all"}}
	g = Build(s, recsA(t), d, optsA(s, ViewTopology, false))
	if f := skillDetail(t, g, "skill:canary-request").Fix; f != "watchdeck allow canary-request --network all" {
		t.Errorf("record-form ungranted: fix %q", f)
	}
}

func TestMCPGrouping(t *testing.T) {
	b := newSess()
	for i := 0; i < 4; i++ {
		b.call(float64(i), "main", fmt.Sprintf("toolu_n%d", i), "mcp__playwright__browser_navigate", "")
	}
	for i := 0; i < 2; i++ {
		b.call(float64(10+i), "main", fmt.Sprintf("toolu_s%d", i), "mcp__playwright__browser_take_screenshot", "")
	}
	b.call(20, "main", "toolu_d", "mcp__claude_ai_Claude_Docs__read", "")
	g := Build(b.s, nil, nil, Options{Now: at(3600)})
	n := node(g, "mcp:playwright")
	if n == nil || n.Count != 6 || n.Label != "MCP playwright" || n.Sub != "browser_navigate · browser_take_screenshot" {
		t.Fatalf("playwright node %+v", n)
	}
	want := []NameCount{{"browser_navigate", 4}, {"browser_take_screenshot", 2}}
	if got := n.Detail.(*ToolDetail).Tools; !reflect.DeepEqual(got, want) {
		t.Errorf("tools %v", got)
	}
	if node(g, "mcp:claude_ai_Claude_Docs") == nil {
		t.Error("server with single underscores not split at the first __")
	}
	if e := edge(g, "e:call:agent:main~mcp:playwright"); e == nil || e.Tone != "violet" || e.Dash != "6 6" || e.Count != 6 {
		t.Errorf("mcp edge %+v", e)
	}
	if g.Totals.MCP != 2 || g.Totals.Tools != 0 {
		t.Errorf("totals %+v", g.Totals)
	}
	if srv, tool := splitMCP("mcp__claude_ai_Claude_Docs__read"); srv != "claude_ai_Claude_Docs" || tool != "read" {
		t.Errorf("split %q %q", srv, tool)
	}
	for _, bad := range []string{"mcp__", "mcp__x", "mcp____y", "Bash"} {
		if srv, _ := splitMCP(bad); srv != "" {
			t.Errorf("%q split to %q", bad, srv)
		}
	}
}

// TestFixtureB: three subagents (meta-linked, order-linked, legacy
// sidechain), an MCP call, a Skill invocation and a hook-attachment ask.
func TestFixtureB(t *testing.T) {
	s := loadB(t)
	g := Build(s, nil, nil, Options{Cwd: "/Users/you/proj-b", Now: s.LastEvent.Add(3600e9)})
	for id, label := range map[string]string{
		"agent:b000000000000001":                     "Explore",
		"agent:b000000000000002":                     "general-purpose",
		"agent:b1000000-0000-4000-8000-0000000000c1": "subagent",
	} {
		if n := node(g, id); n == nil || n.Label != label || n.Role != "subagent" || n.X != colTools {
			t.Errorf("%s: %+v", id, n)
		}
	}
	if n := node(g, "mcp:playwright"); n == nil || n.Count != 1 {
		t.Errorf("mcp %+v", n)
	}
	if e := edge(g, "e:invoke:tool:Skill~skill:canary-prose"); e == nil || e.Kind != "invoke" {
		t.Errorf("skill invocation edge %+v", e)
	}
	var b01 *Tick
	for i := range g.Ticks {
		if g.Ticks[i].ID == "toolu_B01" {
			b01 = &g.Ticks[i]
		}
	}
	if b01 == nil || b01.Policy != PolicyDeny || b01.Skill != "canary-request" {
		t.Errorf("toolu_B01 (hook ask, net: DENIED(1)) tick %+v", b01)
	}
	// Transcript only: the shield comes from the hook's rewrite, the cut from the result text.
	if e := edge(g, "e:sandbox:skill:canary-request~sandbox"); e == nil || e.Cut == nil || e.Label != "DENIED network" {
		t.Errorf("fixture B sandbox edge %+v", e)
	}
	// Subagents at 110, 200, 290; tools start at 380.
	if b := node(g, "tool:Bash"); b == nil || b.Y != 380 {
		t.Errorf("Bash %+v", b)
	}
	tl := Build(s, nil, nil, Options{View: ViewTimeline, Now: s.LastEvent.Add(3600e9)})
	if len(tl.Lanes) != 6 || tl.Lanes[4].ID != "skills" || tl.Lanes[4].X != 1150 || tl.Lanes[5].X != 1390 || tl.Canvas.W != 1500 {
		t.Errorf("lanes %+v canvas %+v", tl.Lanes, tl.Canvas)
	}
}

func TestNoTranscripts(t *testing.T) {
	g := Build(nil, recsA(t), declaredA(t), Options{SessionID: sidA, Cwd: "/Users/you/proj", NoTranscripts: true, Now: at(3600)})
	if !g.Session.NoTranscripts || g.Session.TranscriptMissing {
		t.Errorf("session %+v", g.Session)
	}
	for _, n := range g.Nodes {
		if n.Kind == "you" || n.Kind == "model" || (n.Kind == "tool" && n.ID != "tool:Bash") {
			t.Errorf("unexpected node %s without transcripts", n.ID)
		}
	}
	if node(g, "tool:Bash") == nil || node(g, "sandbox") == nil {
		t.Error("Bash or the sandbox missing")
	}
	// Without the transcript the result text is gone: canary-basic's quiet
	// run is ok, canary-request's hint still denies.
	if d := skillDetail(t, g, "skill:canary-basic"); d.Outcome.Label != "exit 0" {
		t.Errorf("canary-basic outcome %+v", d.Outcome)
	}
	if d := skillDetail(t, g, "skill:canary-request"); d.Outcome.Evidence != EvidenceHint {
		t.Errorf("canary-request outcome %+v", d.Outcome)
	}
	m := Build(nil, recsA(t), declaredA(t), Options{SessionID: sidA, TranscriptMissing: true, TranscriptPath: "~/.claude/projects/-Users-you-proj/" + sidA + ".jsonl"})
	if m.Session.NoTranscripts || !m.Session.TranscriptMissing || m.Session.TranscriptPath == "" {
		t.Errorf("missing transcript session %+v", m.Session)
	}
	// direct: pseudo-session — records without a session id.
	r := run("", 5, activity.OutcomeOK, 0, "canary-request", probeNet)
	d := Build(nil, []activity.Record{r}, declaredA(t), Options{SessionID: "direct:0123456789ab", Cwd: "/Users/you/proj", NoTranscripts: true})
	if n := node(d, "sandbox"); n == nil || n.Count != 1 {
		t.Errorf("direct session %+v", d.Nodes)
	}
}

// TestLayoutGrowsInsteadOfOverlapping: many tools and subagents, fixed
// steps, canvas taller than 720, no two nodes in a column overlap.
func TestLayoutGrowsInsteadOfOverlapping(t *testing.T) {
	b := newSess()
	for i := 0; i < 5; i++ {
		b.sub(fmt.Sprintf("s%02d", i), "Explore", float64(10+i), float64(20+i), fmt.Sprintf("toolu_sp%d", i))
	}
	for i := 0; i < 14; i++ {
		b.call(float64(30+i), "main", fmt.Sprintf("toolu_t%d", i), fmt.Sprintf("Tool%02d", i), "")
	}
	g := Build(b.s, nil, nil, Options{Now: at(3600)})
	if g.Canvas.H <= 720 {
		t.Errorf("canvas did not grow: %+v", g.Canvas)
	}
	cols := map[float64][]Node{}
	for _, n := range g.Nodes {
		cols[n.X] = append(cols[n.X], n)
		if n.Y+n.H/2 > g.Canvas.H {
			t.Errorf("%s below the canvas", n.ID)
		}
	}
	for x, ns := range cols {
		sort.Slice(ns, func(i, j int) bool { return ns[i].Y < ns[j].Y })
		for i := 1; i < len(ns); i++ {
			if ns[i].Y-ns[i-1].Y < (ns[i].H+ns[i-1].H)/2 {
				t.Errorf("column %v: %s and %s overlap", x, ns[i-1].ID, ns[i].ID)
			}
		}
	}
	// Timeline: three subagent lanes, the rest folded.
	tl := Build(b.s, nil, nil, Options{View: ViewTimeline, Now: at(3600)})
	var ids []string
	for _, l := range tl.Lanes {
		ids = append(ids, l.ID+"@"+fmt.Sprint(l.X))
	}
	want := "agent:main@150 agent:s00@400 agent:s01@650 agent:s02@900 agent:other@1150 skills@1400 sandbox@1640"
	if strings.Join(ids, " ") != want {
		t.Errorf("lanes %s", strings.Join(ids, " "))
	}
	if tl.Lanes[4].Label != "other subagents (2)" || tl.Canvas.W != 1750 {
		t.Errorf("fold %+v canvas %+v", tl.Lanes[4], tl.Canvas)
	}
	// Rows never share a y.
	ys := map[float64]string{}
	for _, n := range tl.Nodes {
		if n.Kind == "skill" {
			continue // a skill event shares its call's row by design
		}
		if prev, ok := ys[n.Y]; ok && prev != n.ID {
			t.Errorf("%s and %s on one row", prev, n.ID)
		}
		ys[n.Y] = n.ID
	}
}

func TestMissingTimestampsSortLast(t *testing.T) {
	recs := []activity.Record{{Kind: "decision", TS: "", Command: "b"}, {Kind: "decision", TS: "2026-10-12T14:31:09Z", Command: "a"}, {Kind: "decision", TS: "bad", Command: "c"}}
	got := sortedRecords(recs)
	if got[0].Command != "a" {
		t.Errorf("timed record not first: %+v", got)
	}
	b := newSess().push(transcript.Event{Agent: "main", Kind: "tool_use", ToolCall: &transcript.ToolCall{ID: "toolu_nots", Name: "Read"}}).
		call(5, "main", "toolu_timed", "Read", "")
	g := Build(b.s, nil, nil, Options{})
	if g.Ticks[0].ID != "toolu_timed" || g.Ticks[1].ID != "toolu_nots" {
		t.Errorf("ticks %+v", g.Ticks)
	}
}

func TestModelLabel(t *testing.T) {
	for in, want := range map[string]string{
		"claude-opus-5-5":            "opus-5.5",
		"claude-fable-5-1":           "fable-5.1",
		"claude-sonnet-4-5-20250929": "sonnet-4.5",
		"claude-3-5-sonnet-20241022": "3-5-sonnet",
		"gpt-x":                      "gpt-x",
	} {
		if got := modelLabel(in); got != want {
			t.Errorf("%s → %s, want %s", in, got, want)
		}
	}
}

// TestDeterminism: repeated builds, shuffled records and reversed records
// give byte-identical JSON, for both fixtures and both views.
func TestDeterminism(t *testing.T) {
	sa, sb := loadA(t), loadB(t)
	recsB := []activity.Record{
		{V: 1, Kind: "decision", TS: "2026-10-12T10:00:01.2Z", SessionID: sidB, ToolUseID: "toolu_B01", Cwd: "/Users/you/proj-b", Skills: []string{"canary-request"}, Command: "python3 .claude/skills/canary-request/scripts/probe.py net", Decision: "ask", Rewritten: "watchdeck run --skill canary-request -c 'x'", Confidence: "high"},
		{V: 1, Kind: "run", TS: "2026-10-12T10:00:02.9Z", Cwd: "/Users/you/proj-b", Skills: []string{"canary-request"}, Command: "python3 .claude/skills/canary-request/scripts/probe.py net", Exit: intp(0), Outcome: "ok"},
		{V: 1, Kind: "skill_invoked", TS: "2026-10-12T10:00:09.5Z", SessionID: sidB, ToolUseID: "toolu_B07", ToolName: "Skill", Skill: "canary-prose"},
		{V: 1, Kind: "run", TS: "2026-10-12T10:00:05Z", Cwd: "/Users/you/proj-b", Skills: []string{"canary-basic"}, Command: "x", Exit: intp(1), Outcome: "failed"},
	}
	for _, tc := range []struct {
		name string
		s    *transcript.Session
		recs []activity.Record
	}{{"A", sa, recsA(t)}, {"B", sb, recsB}} {
		for _, view := range []string{ViewTopology, ViewTimeline} {
			o := Options{View: view, Cwd: tc.s.Cwd, Now: tc.s.LastEvent.Add(3600e9)}
			want := mustJSON(t, Build(tc.s, tc.recs, declaredA(t), o))
			rng := rand.New(rand.NewSource(7))
			for i := 0; i < 20; i++ {
				recs := append([]activity.Record(nil), tc.recs...)
				switch i {
				case 0: // as is
				case 1:
					for l, r := 0, len(recs)-1; l < r; l, r = l+1, r-1 {
						recs[l], recs[r] = recs[r], recs[l]
					}
				default:
					rng.Shuffle(len(recs), func(a, b int) { recs[a], recs[b] = recs[b], recs[a] })
				}
				if got := mustJSON(t, Build(tc.s, recs, declaredA(t), o)); !bytes.Equal(got, want) {
					t.Fatalf("%s %s: build %d differs", tc.name, view, i)
				}
			}
		}
	}
}

// TestNoRealPaths: the Graph carries no string that starts with the
// directory the transcript was loaded from or with /Users/, except the two
// display values the caller passed. Fixture A is copied into a temp dir so
// Session.Path and Agent.File are temp paths.
func TestNoRealPaths(t *testing.T) {
	tmp := t.TempDir()
	src, _ := filepath.Abs(filepath.Join("..", "transcript", "testdata", "e2e-canary", "projects"))
	dst := filepath.Join(tmp, "projects")
	err := filepath.Walk(src, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if fi.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	s, err := transcript.Load(filepath.Join(dst, "-Users-you-proj", sidA+".jsonl"), transcript.Options{ProjectsDir: dst})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(s.Path, tmp) && !strings.HasPrefix(s.Path, "/private"+tmp) {
		t.Fatalf("session path %q not under the temp dir", s.Path)
	}
	const cwd = "/Users/you/proj"
	const tpath = "/Users/you/.claude/projects/-Users-you-proj/x.jsonl"
	allowed := map[string]bool{cwd: true, tpath: true}
	prefixes := []string{tmp, "/private" + tmp, "/Users/", filepath.Dir(s.Path)}
	check := func(name string, g Graph) {
		b, _ := json.Marshal(g)
		var v any
		_ = json.Unmarshal(b, &v)
		walkStrings(v, func(str string) {
			if allowed[str] {
				return
			}
			for _, p := range prefixes {
				if strings.HasPrefix(str, p) {
					t.Errorf("%s: %q starts with %q", name, str, p)
				}
			}
		})
	}
	for _, view := range []string{ViewTopology, ViewTimeline} {
		for _, hide := range []bool{false, true} {
			check(view, Build(s, recsA(t), declaredA(t), Options{View: view, HideNone: hide, Cwd: cwd, Now: s.LastEvent}))
		}
		check(view+" missing", Build(nil, recsA(t), declaredA(t), Options{View: view, SessionID: sidA, Cwd: cwd, TranscriptMissing: true, TranscriptPath: tpath}))
		check(view+" off", Build(nil, recsA(t), declaredA(t), Options{View: view, SessionID: sidA, Cwd: cwd, NoTranscripts: true}))
	}
}

func walkStrings(v any, f func(string)) {
	switch x := v.(type) {
	case string:
		f(x)
	case []any:
		for _, e := range x {
			walkStrings(e, f)
		}
	case map[string]any:
		for k, e := range x {
			f(k)
			walkStrings(e, f)
		}
	}
}
