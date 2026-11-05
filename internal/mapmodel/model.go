// Package mapmodel turns one Claude Code session (a transcript.Session, or
// nothing under --no-transcripts) and watchdeck's activity records into
// the agent map's Graph: nodes, edges, lanes and ticks with server-side,
// deterministic coordinates for the Flow page's topology and timeline views
// (Spec B §3).
//
// Build is a pure function. It reads no file and no clock (o.Now is the
// only time source), and the same inputs give byte-identical JSON whatever
// order the activity records arrive in. The one exception to "no I/O" is
// inherited from activity.Join: when a decision's and a run's cwd differ
// after filepath.Clean it compares them through filepath.EvalSymlinks.
//
// Privacy: the Graph never carries a transcript's file path (Session.Path,
// Agent.File) or a record's transcript_path or cwd. session.cwd and
// session.transcript_path are display values the caller passes in Options.
// Tool file paths are shown relative to the session's cwd (or by base name
// when outside it). Shell commands are shown as the agent wrote them.
//
// The package does no work at init (no regexp, no tables built at start).
package mapmodel

import (
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/activity"
	"github.com/Panda-Taps-LLC/watchdeck/internal/manifest"
	"github.com/Panda-Taps-LLC/watchdeck/internal/transcript"
)

// Views.
const (
	ViewTopology = "topology"
	ViewTimeline = "timeline"
)

// Default canvas and liveness.
const (
	DefaultWidth  = 1000
	DefaultHeight = 720
	// LiveWindow: a session whose newest event (transcript row or activity
	// record) is younger than this at Options.Now is live.
	LiveWindow = 30 * time.Second
)

// Options control one Build.
type Options struct {
	View     string // ViewTopology (default) | ViewTimeline
	HideNone bool   // drop tools and timeline events that carry no policy (§3.7)
	// Authorities keeps only the calls decided by these parties (Authority*
	// words); empty keeps every call. A dropped call leaves the graph
	// (nodes, counts, edges) but keeps its tick, with no node. Spawns are
	// structure and always stay, as under HideNone. It is independent of
	// HideNone, which filters on policy, not authority: both apply.
	Authorities []string
	Now         time.Time // zero: nothing is live, no pending asks
	Canvas      Size      // zero: DefaultWidth × DefaultHeight (a minimum; the canvas grows)
	// Loc is the zone for timeline tick labels (HH:MM:SS); nil means UTC.
	Loc *time.Location

	// SessionID names the session when s == nil. A "direct:" id selects the
	// records that carry no session id (hand-typed `watchdeck run`); the
	// caller filters those to one cwd first.
	SessionID string
	// Cwd is the display value for session.cwd and the base for relative
	// tool paths when s == nil.
	Cwd string
	// NoTranscripts: transcripts are off (--no-transcripts). s must be nil.
	NoTranscripts bool
	// TranscriptMissing: transcripts are on but this session's file was not
	// found; TranscriptPath is the display value shown in the banner.
	TranscriptMissing bool
	TranscriptPath    string
}

// Declared is what the API layer knows about one skill at request time: its
// request as written and the grant it gets now (Default() widened by the
// current overrides). Ungranted is clip(Request, Granted)'s refusal list, in
// manifest.Clip's form ("network: all") or the records' form
// ("<skill>: network: all"); both are accepted.
type Declared struct {
	Skill       string
	HasManifest bool
	Request     manifest.Manifest
	Granted     manifest.Effective
	Ungranted   []string
}

// Size is a canvas size in CSS pixels.
type Size struct {
	W float64 `json:"w"`
	H float64 `json:"h"`
}

// Graph is the Flow page's input (Spec B §3.1).
type Graph struct {
	Session SessionInfo `json:"session"`
	View    string      `json:"view"`
	Canvas  Size        `json:"canvas"`
	Columns []Column    `json:"columns,omitempty"` // topology column headers
	Nodes   []Node      `json:"nodes"`
	Edges   []Edge      `json:"edges"`
	Lanes   []Lane      `json:"lanes"`
	TicksY  []TimeTick  `json:"ticks_y,omitempty"` // timeline time axis
	Ticks   []Tick      `json:"ticks"`             // every tool call in order, never filtered
	Totals  Totals      `json:"totals"`
	// Shown counts the calls the graph draws after HideNone and
	// Authorities (spawns always count); Totals and Ticks are the session's.
	Shown int    `json:"shown"`
	ETag  string `json:"etag,omitempty"` // set by the API layer, never by Build
}

// SessionInfo is the header block.
type SessionInfo struct {
	ID                string `json:"id"`
	Harness           string `json:"harness"` // stub: always claude-code until a harness is read from the records
	Cwd               string `json:"cwd"`
	Live              bool   `json:"live"`
	Truncated         bool   `json:"truncated"`
	NoTranscripts     bool   `json:"no_transcripts"`
	TranscriptMissing bool   `json:"transcript_missing,omitempty"`
	TranscriptPath    string `json:"transcript_path,omitempty"`
	Started           string `json:"started,omitempty"`
	Last              string `json:"last,omitempty"`
}

// Column is a topology column header.
type Column struct {
	Label string  `json:"label"`
	X     float64 `json:"x"`
}

// Node is one shape on the canvas (topology) or one event (timeline).
type Node struct {
	ID        string  `json:"id"`
	Kind      string  `json:"kind"` // you | agent | model | tool | mcp | skill | sandbox
	Role      string  `json:"role,omitempty"`
	Label     string  `json:"label"`
	Glyph     string  `json:"glyph,omitempty"`
	Sub       string  `json:"sub,omitempty"`
	Sub2      string  `json:"sub2,omitempty"`
	X         float64 `json:"x"`
	Y         float64 `json:"y"`
	W         float64 `json:"w"`
	H         float64 `json:"h"`
	Count     int     `json:"count,omitempty"`
	Tone      string  `json:"tone,omitempty"`
	Live      bool    `json:"live,omitempty"`
	Requested bool    `json:"requested,omitempty"`
	Ring      *Ring   `json:"ring,omitempty"`
	Event     bool    `json:"event,omitempty"`
	ToolUseID string  `json:"tool_use_id,omitempty"`
	TS        string  `json:"ts,omitempty"`
	// Authority is who decided the call (Authority*): on every timeline
	// event built from a call, the word its Tick carries; on a topology
	// tool node only when every call drawn on it has the same word.
	Authority string `json:"authority,omitempty"`
	// RuleHits counts the pack and user rule hits on this node's calls
	// (M6.4): the badge. Subjects names the policy subjects that decided
	// them ("tool files (gate)", "command npm-scripts (sandbox)").
	RuleHits int      `json:"rule_hits,omitempty"`
	Subjects []string `json:"subjects,omitempty"`
	Detail   any      `json:"detail,omitempty"`
}

// Ring is a call count by policy.
type Ring struct {
	Allow int `json:"allow"`
	Ask   int `json:"ask"`
	Deny  int `json:"deny"`
	None  int `json:"none"`
}

func (r *Ring) add(policy string) {
	switch policy {
	case PolicyAllow:
		r.Allow++
	case PolicyAsk:
		r.Ask++
	case PolicyDeny:
		r.Deny++
	default:
		r.None++
	}
}

// Edge is one path. D is SVG path data in canvas coordinates.
type Edge struct {
	ID          string  `json:"id"`
	Kind        string  `json:"kind"` // prompt | runs_on | spawn | return | call | skill_run | invoke | sandbox
	From        string  `json:"from"`
	To          string  `json:"to"`
	D           string  `json:"d"`
	Width       float64 `json:"width"`
	Count       int     `json:"count,omitempty"`
	Policy      string  `json:"policy,omitempty"`
	Tone        string  `json:"tone"`
	Dash        string  `json:"dash,omitempty"`
	Label       string  `json:"label,omitempty"`
	LX          float64 `json:"lx,omitempty"`
	LY          float64 `json:"ly,omitempty"`
	Glow        bool    `json:"glow,omitempty"`
	Flow        bool    `json:"flow,omitempty"`
	Cut         *Point  `json:"cut,omitempty"`
	Unsandboxed bool    `json:"unsandboxed,omitempty"`
	Dotted      bool    `json:"dotted,omitempty"`
	Pending     bool    `json:"pending,omitempty"`
	Inferred    bool    `json:"inferred,omitempty"` // the approval is read from the Bash result; no run record
}

// Point is a canvas coordinate.
type Point struct {
	X float64 `json:"x"`
	Y float64 `json:"y"`
}

// Lane is one timeline column.
type Lane struct {
	ID    string  `json:"id"`
	Kind  string  `json:"kind"` // agent | skills | sandbox
	Label string  `json:"label"`
	Model string  `json:"model,omitempty"`
	X     float64 `json:"x"`
	Y0    float64 `json:"y0,omitempty"`
	Y1    float64 `json:"y1,omitempty"`
	Spine string  `json:"spine,omitempty"`
}

// TimeTick is a label on the timeline's time axis.
type TimeTick struct {
	Y     float64 `json:"y"`
	Label string  `json:"label"`
	Tone  string  `json:"tone,omitempty"`
}

// Tick is one tool call in the strip under the canvas.
type Tick struct {
	ID     string `json:"id"`
	TS     string `json:"ts,omitempty"`
	Tool   string `json:"tool"`
	Policy string `json:"policy"`
	// Authority is who decided the call (Authority*); Policy stays what
	// watchdeck's own evidence says.
	Authority string `json:"authority"`
	Node      string `json:"node,omitempty"`  // topology node to select
	Skill     string `json:"skill,omitempty"` // first skill the call ran
	// Topology only, for the replay control and edge cards: the agent node
	// that made the call, and whether a skill script ran in the sandbox.
	Agent string `json:"agent,omitempty"`
	Ran   bool   `json:"ran,omitempty"`
}

// Totals feed the header tags. Counts of calls by policy are over the whole
// session; HideNone and Authorities never change them.
type Totals struct {
	Agents  int `json:"agents"`
	Models  int `json:"models"`
	Tools   int `json:"tools"`
	MCP     int `json:"mcp"`
	Skills  int `json:"skills"`
	Denials int `json:"denials"`
	Allow   int `json:"allow"`
	Ask     int `json:"ask"`
	Deny    int `json:"deny"`
	None    int `json:"none"`
	// ByAuthority counts calls by who decided them (Authority*); omitted
	// when the session has no calls.
	ByAuthority map[string]int `json:"by_authority,omitempty"`
	// BlockedCalls counts calls refused before they ran, from three
	// sources: a native permissions.deny rule (authority deny_rule), the
	// auto-mode check (classifier, from the transcript or a
	// PermissionDenied record), and watchdeck's hook (authority hook with
	// policy deny). A sandbox refusal at run time is not one. Unlike Deny
	// it also counts refusals read only from the transcript (Plan 05
	// Task 6).
	BlockedCalls int `json:"blocked_calls,omitempty"`
}

// Build assembles the Graph for one session. s is nil under
// --no-transcripts or when the transcript was not found. recs may hold
// records of other sessions: they are joined together (so the run↔decision
// rule sees every candidate) and then only this session's are kept. A
// record left without a session id after the join (a hand-typed run, or a
// run no decision claims) is kept only by a "direct:" session, never by a
// real one. declared is keyed by skill name.
func Build(s *transcript.Session, recs []activity.Record, declared map[string]Declared, o Options) Graph {
	if o.View != ViewTimeline {
		o.View = ViewTopology
	}
	if o.Canvas.W <= 0 {
		o.Canvas.W = DefaultWidth
	}
	if o.Canvas.H <= 0 {
		o.Canvas.H = DefaultHeight
	}
	if o.Loc == nil {
		o.Loc = time.UTC
	}
	m := assemble(s, recs, o)
	m.declared = declared

	g := Graph{
		Session: m.sessionInfo(o),
		View:    o.View,
		Nodes:   []Node{},
		Edges:   []Edge{},
		Lanes:   []Lane{},
	}
	m.live = g.Session.Live
	m.judgeAll()
	m.skillInfo()
	g.Totals = m.totals()
	all := m.calls
	if len(o.Authorities) > 0 {
		// Lay out the kept calls only; ticks and totals see them all.
		m.calls = keepAuthorities(all, o.Authorities)
		m.skillOrder, m.skillAgg, m.orphanV, m.execs = nil, nil, nil, 0
		m.skillInfo()
	}
	if o.View == ViewTimeline {
		m.timeline(&g, o)
	} else {
		m.topology(&g, o)
	}
	var dropped map[string]bool
	if len(m.calls) != len(all) {
		dropped = map[string]bool{}
		for _, c := range all {
			dropped[c.id] = true
		}
		for _, c := range m.calls {
			delete(dropped, c.id)
		}
	}
	m.calls = all
	g.Ticks = m.ticks(&g, dropped)
	g.Shown = shown(all, o)
	return g
}

// IsAuthority reports whether w is one of the nine Authority* words.
func IsAuthority(w string) bool {
	switch w {
	case AuthorityDenyRule, AuthorityClassifier, AuthorityAuto, AuthorityAllowRule, AuthorityUser,
		AuthorityHook, AuthoritySandbox, AuthorityBlocked, AuthorityNone:
		return true
	}
	return false
}

// keepAuthorities is the calls whose authority is in words, and every spawn.
func keepAuthorities(calls []*call, words []string) []*call {
	out := make([]*call, 0, len(calls))
	for _, c := range calls {
		if c.isSpawn() || containsWord(words, c.v.authority) {
			out = append(out, c)
		}
	}
	return out
}

func containsWord(words []string, w string) bool {
	for _, x := range words {
		if x == w {
			return true
		}
	}
	return false
}

// shown counts the calls a view draws: kept by Authorities and, under
// HideNone, carrying a policy. Spawns always count. (Topology keeps a Bash
// node whose calls all have no policy; those calls are drawn but not
// counted here, so shown means the same in every view.)
func shown(calls []*call, o Options) int {
	n := 0
	for _, c := range calls {
		if c.isSpawn() {
			n++
			continue
		}
		if len(o.Authorities) > 0 && !containsWord(o.Authorities, c.v.authority) {
			continue
		}
		if o.HideNone && c.v.policy == PolicyNone {
			continue
		}
		n++
	}
	return n
}
