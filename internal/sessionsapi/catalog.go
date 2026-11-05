// Package sessionsapi is the dashboard's session catalog (M5.5): every Claude
// Code session the machine knows, merged from three sources, plus the routes
// that serve it and the event source behind GET /api/events.
//
//   - the session index (internal/sessionindex): metadata of every
//     transcript under the projects dir, and the search text;
//   - the lifecycle store (internal/lifecycle): live, idle or ended;
//   - the activity log (internal/activity): decisions, asks, denials and
//     skills, read by offset so a refresh reads only what was appended.
//
// One Catalog owns the sessionindex.Index, which is not safe for concurrent
// use: Update runs under the write half of an RWMutex, reads (Entries, Get,
// Search) under the read half. A single goroutine (Start) refreshes every
// 15 s and as soon as a cheap Stat sees sessions.jsonl, the live dir or the
// activity log change. Handlers read an immutable snapshot swapped in by
// each refresh, so a request never waits for a transcript read.
//
// With NoTranscripts (watchdeck ui --no-transcripts) the index is never
// opened or written and no transcript is read: sessions come from
// transcript.DiscoverAll (directory listings and Stat only), the lifecycle
// records and the activity log, with no title, model or search text. Stat
// is not reading: a transcript's size and mtime still list it and still
// make it live (the lifecycle's 30 s rule), as they did before M5.5.
//
// Privacy: no response carries the home dir, the projects dir or a
// transcript path. A project is shown in projectscope.Display form ("~/x"
// under home), which projectscope.Resolve accepts back as ?project=.
//
// The package does no work at init: cmd/watchdeck links it and is also the
// hook binary.
package sessionsapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/activity"
	"github.com/Panda-Taps-LLC/watchdeck/internal/lifecycle"
	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
	"github.com/Panda-Taps-LLC/watchdeck/internal/projectscope"
	"github.com/Panda-Taps-LLC/watchdeck/internal/rulebook"
	"github.com/Panda-Taps-LLC/watchdeck/internal/sessionindex"
	"github.com/Panda-Taps-LLC/watchdeck/internal/transcript"
	"github.com/Panda-Taps-LLC/watchdeck/internal/ui"
)

// States a row can be in. Unknown: no lifecycle record and no marker (a
// session from before the lifecycle hooks, or one they never saw).
const (
	StateLive    = lifecycle.Live
	StateIdle    = lifecycle.Idle
	StateEnded   = lifecycle.Ended
	StateUnknown = lifecycle.Unknown
)

// Defaults.
const (
	DefaultRefresh = 15 * time.Second
	DefaultWatch   = time.Second
	runningWindow  = 10 * time.Minute // a decision this recent with no run yet: its skill is "running"
	subBuffer      = 32
	directPrefix   = "direct:"
)

// Options configures a Catalog.
type Options struct {
	Paths         paths.Paths
	NoTranscripts bool
	Now           func() time.Time // nil: time.Now
	Refresh       time.Duration    // full refresh period (0: 15 s)
	Watch         time.Duration    // Stat period for early refreshes (0: 1 s)
}

// Denial is the newest denial of a session, as the activity log shows it.
type Denial struct {
	TS    string `json:"ts"`
	Skill string `json:"skill,omitempty"`
	Label string `json:"label"`
}

// Row is one session in GET /api/sessions and `watchdeck sessions --json`
// style listings.
type Row struct {
	ID          string   `json:"id"`
	Project     string   `json:"project"`      // the session's cwd in Display form; usable as ?project=
	ProjectName string   `json:"project_name"` // its last path element
	Title       string   `json:"title,omitempty"`
	Branch      string   `json:"branch,omitempty"`
	Models      []string `json:"models"`
	CCVersion   string   `json:"cc_version,omitempty"`
	Entrypoint  string   `json:"entrypoint,omitempty"`
	State       string   `json:"state"` // live | idle | ended | unknown
	FirstTS     string   `json:"first_ts,omitempty"`
	LastTS      string   `json:"last_ts,omitempty"`
	Turns       int      `json:"turns"`
	ToolCalls   int      `json:"tool_calls"`
	Subagents   int      `json:"subagents"`
	Skills      []string `json:"skills"`
	Decisions   int      `json:"decisions"`
	Denials     int      `json:"denials"`
	Asks        int      `json:"asks"`
	Leaks       int      `json:"leaks"` // leak watch findings in the session index
	// RunningSkill is the skill of the newest decision that rewrote a
	// command to `watchdeck run` and has no run record yet (within 10
	// minutes), on a live session.
	RunningSkill string  `json:"running_skill,omitempty"`
	LastDenial   *Denial `json:"last_denial,omitempty"`
	Truncated    bool    `json:"truncated,omitempty"`
	Direct       bool    `json:"direct,omitempty"` // runs typed by hand in one cwd, no Claude Code session
	// Sources names where the row came from: index, transcript (Stat only),
	// lifecycle, activity.
	Sources []string `json:"sources"`
	Snippet string   `json:"snippet,omitempty"` // with ?q=: the first match

	last time.Time // sort key
	cwd  string    // absolute cwd (never serialized)
}

// RuleHit counts one rule's hits in a session (decision and rule_log
// records, M6.4). Severity and action are those of the newest hit.
type RuleHit struct {
	Pack     string `json:"pack"`
	Rule     string `json:"rule"`
	Severity string `json:"severity"`
	Action   string `json:"action"`
	Count    int    `json:"count"`
}

// Risk is a session's risk summary.
type Risk struct {
	Denials       int       `json:"denials"`
	Asks          int       `json:"asks"`
	UngrantedAsks int       `json:"ungranted_asks"` // asks whose skill requested more than the grant
	Ungranted     []string  `json:"ungranted"`      // distinct "<skill>: <what>" lines, home shown as ~
	RuleHits      []RuleHit `json:"rule_hits"`      // pack and user rule hits, most frequent first
	// Leaks are the session's leak watch findings, in file order, targets
	// in display form; none under --no-transcripts.
	Leaks []sessionindex.Finding `json:"leaks,omitempty"`
}

// Detail is GET /api/sessions/{id}.
type Detail struct {
	Row
	Runs        int      `json:"runs"`
	Agents      []string `json:"agent_types"` // subagent types the activity log names
	TailRead    bool     `json:"tail_read,omitempty"`
	TextCapped  bool     `json:"text_capped,omitempty"`
	Risk        Risk     `json:"risk"`
	Transcripts bool     `json:"transcripts"` // false under --no-transcripts
}

// Project is one row of GET /api/projects.
type Project struct {
	Project  string `json:"project"` // Display form; pass back as ?project=
	Name     string `json:"name"`
	Sessions int    `json:"sessions"`
	Live     int    `json:"live"`
	Denials  int    `json:"denials"`
	LastTS   string `json:"last_ts,omitempty"`
}

// snapshot is what one refresh built; never modified after it is swapped in.
type snapshot struct {
	rows     []Row // sorted newest first, then id
	byID     map[string]int
	details  map[string]*Detail
	projects []Project
	roots    []string // absolute project roots for projectscope
	states   map[string]string
	leaks    []rulebook.Leak // every session's findings, in row order
	at       time.Time
}

// Catalog merges the three sources. Build it with New; call Start to keep
// it fresh, Close (or cancel Start's ctx) to stop.
type Catalog struct {
	o     Options
	store lifecycle.Store

	ixMu sync.RWMutex
	ix   *sessionindex.Index // nil under NoTranscripts or when it could not be opened

	refreshMu sync.Mutex // one refresh at a time
	act       *actAgg    // owned by refresh (under refreshMu)
	idxSig    string     // the session count after the last index refresh

	mu   sync.RWMutex
	snap *snapshot

	subMu sync.Mutex
	subs  map[chan ui.Event]struct{}

	searchSem chan struct{}
	stopOnce  sync.Once
	stopCh    chan struct{}
	done      chan struct{}
}

// New builds a Catalog. It opens the session index (creating nothing; an
// unreadable index is rebuilt by the first refresh) unless NoTranscripts.
func New(o Options) *Catalog {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Refresh <= 0 {
		o.Refresh = DefaultRefresh
	}
	if o.Watch <= 0 {
		o.Watch = DefaultWatch
	}
	c := &Catalog{
		o:         o,
		store:     lifecycle.Store{Log: o.Paths.Sessions, Live: o.Paths.LiveDir, Now: o.Now},
		act:       newActAgg(),
		subs:      map[chan ui.Event]struct{}{},
		searchSem: make(chan struct{}, 2),
		stopCh:    make(chan struct{}),
		done:      make(chan struct{}),
	}
	if !o.NoTranscripts && o.Paths.StateDir != "" {
		if ix, err := sessionindex.Open(sessionindex.Options{Dir: o.Paths.SessionIndexDir(), ProjectsDir: o.Paths.ClaudeProjectsDir()}); err == nil {
			c.ix = ix
		}
	}
	return c
}

// Start refreshes once, then keeps refreshing in one goroutine until ctx is
// done or Close is called. It returns at once.
func (c *Catalog) Start(ctx context.Context) {
	go c.loop(ctx)
}

// Close stops the refresh goroutine; Done is closed once it has returned.
func (c *Catalog) Close() {
	c.stopOnce.Do(func() { close(c.stopCh) })
}

// Done is closed when the refresh goroutine has returned.
func (c *Catalog) Done() <-chan struct{} { return c.done }

func (c *Catalog) loop(ctx context.Context) {
	defer close(c.done)
	c.Refresh(true)
	full := time.NewTicker(c.o.Refresh)
	defer full.Stop()
	watch := time.NewTicker(c.o.Watch)
	defer watch.Stop()
	lifeSig, actSig := c.lifeSig(), c.actSig()
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopCh:
			return
		case <-full.C:
			c.Refresh(true)
			lifeSig, actSig = c.lifeSig(), c.actSig()
		case <-watch.C:
			l, a := c.lifeSig(), c.actSig()
			switch {
			case l != lifeSig:
				c.Refresh(true) // a session started or ended: index it now
			case a != actSig:
				c.Refresh(false)
			}
			lifeSig, actSig = l, a
		}
	}
}

// statSig is a cheap change signature: size and mtime of each path.
func statSig(ps ...string) string {
	var b strings.Builder
	for _, p := range ps {
		if p == "" {
			b.WriteString("-|")
			continue
		}
		if fi, err := os.Stat(p); err == nil {
			b.WriteString(fi.ModTime().Format(time.RFC3339Nano))
			b.WriteByte('/')
			b.WriteString(itoa(fi.Size()))
		}
		b.WriteByte('|')
	}
	return b.String()
}

// lifeSig changes when a lifecycle record is appended or a marker is
// created or removed (the live dir's mtime). Marker touches do not change
// it; live → idle is caught by the periodic refresh.
func (c *Catalog) lifeSig() string { return statSig(c.o.Paths.Sessions, c.o.Paths.LiveDir) }

func (c *Catalog) actSig() string { return statSig(c.o.Paths.Activity) }

// Refresh rebuilds the snapshot now. full also brings the session index up
// to date (or, under NoTranscripts, re-lists the projects dir); otherwise
// only the lifecycle states and the activity log are re-read. It publishes
// a "session" event per state change, an "activity" event when records
// were appended and an "index" event when the index changed.
func (c *Catalog) Refresh(full bool) {
	c.refreshMu.Lock()
	defer c.refreshMu.Unlock()
	c.refreshLocked(full)
}

// refreshLocked is Refresh with refreshMu held.
func (c *Catalog) refreshLocked(full bool) {
	prev := c.current()
	indexChanged := false
	if full || prev == nil {
		indexChanged = c.updateIndex()
	}
	life, _ := c.store.List()
	newRecs := c.act.update(c.o.Paths.Activity)
	var refs []transcript.SessionFiles
	if c.o.NoTranscripts && c.o.Paths.ClaudeDir != "" {
		refs, _ = transcript.DiscoverAll(c.o.Paths.ClaudeProjectsDir())
	}
	var entries []sessionindex.Entry
	if c.ix != nil {
		c.ixMu.RLock()
		entries = c.ix.Entries()
		c.ixMu.RUnlock()
	}
	s := c.build(entries, refs, life)
	c.mu.Lock()
	c.snap = s
	c.mu.Unlock()

	if prev == nil {
		return // the first snapshot: nothing to compare against
	}
	for _, r := range s.rows {
		if was, ok := prev.states[r.ID]; !ok || was != r.State {
			c.publish("session", map[string]string{"id": r.ID, "state": r.State, "prev": was})
		}
	}
	if len(newRecs) > 0 {
		ids := map[string]bool{}
		var list []string
		for _, id := range newRecs {
			if !ids[id] {
				ids[id] = true
				list = append(list, id)
			}
		}
		sort.Strings(list)
		c.publish("activity", map[string]any{"sessions": list, "records": len(newRecs)})
	}
	if indexChanged {
		c.publish("index", map[string]any{"sessions": len(s.rows)})
	}
}

// updateIndex runs Index.Update under the write lock and reports whether
// the index changed.
func (c *Catalog) updateIndex() bool {
	if c.ix == nil {
		return false
	}
	c.ixMu.Lock()
	st, err := c.ix.Update()
	c.ixMu.Unlock()
	if err != nil {
		return false
	}
	sig := itoa(int64(st.Sessions)) // meta.json is re-saved on every Update, so its time is no signal
	changed := st.Rebuilt+st.Appended+st.Pruned > 0 || sig != c.idxSig
	c.idxSig = sig
	return changed
}

func (c *Catalog) current() *snapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.snap
}

// snapshotNow returns the current snapshot, refreshing first when there is
// none yet (a request that beat Start's first refresh, and tests).
func (c *Catalog) snapshotNow() *snapshot {
	if s := c.current(); s != nil {
		return s
	}
	// Cold start: requests that arrive together wait for one refresh; the
	// re-check under the lock keeps each of them from running another.
	c.refreshMu.Lock()
	defer c.refreshMu.Unlock()
	if s := c.current(); s != nil {
		return s
	}
	c.refreshLocked(true)
	return c.current()
}

// Leaks lists the leak watch findings of every session at or after since
// (zero: all), for the inbox (ui.Options.Leaks). Under NoTranscripts there
// are none.
func (c *Catalog) Leaks(since time.Time) []rulebook.Leak {
	s := c.snapshotNow()
	if s == nil {
		return nil
	}
	var out []rulebook.Leak
	for _, l := range s.leaks {
		if !l.TS.Before(since) {
			out = append(out, l)
		}
	}
	return out
}

// ProjectRoots lists every absolute project root the catalog knows (the
// cwd of every session and record, each with its git root), for
// projectscope. It is ui.Options.ProjectRoots and mapapi.Deps.ProjectRoots.
func (c *Catalog) ProjectRoots() []string {
	s := c.snapshotNow()
	if s == nil {
		return nil
	}
	return s.roots
}

// ---------------------------------------------------------------- events

// Subscribe implements ui.EventSource.
func (c *Catalog) Subscribe() (<-chan ui.Event, func()) {
	ch := make(chan ui.Event, subBuffer)
	c.subMu.Lock()
	c.subs[ch] = struct{}{}
	c.subMu.Unlock()
	var once sync.Once
	return ch, func() {
		once.Do(func() {
			c.subMu.Lock()
			delete(c.subs, ch)
			c.subMu.Unlock()
		})
	}
}

// Subscribers is the number of open subscriptions (tests).
func (c *Catalog) Subscribers() int {
	c.subMu.Lock()
	defer c.subMu.Unlock()
	return len(c.subs)
}

// publish sends a nudge to every subscriber without blocking: a full
// buffer drops the event (the page also polls slowly while streaming).
func (c *Catalog) publish(name string, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	ev := ui.Event{Name: name, Data: b}
	c.subMu.Lock()
	defer c.subMu.Unlock()
	for ch := range c.subs {
		select {
		case ch <- ev:
		default:
		}
	}
}

// ---------------------------------------------------------------- merge

func (c *Catalog) display(p string) string { return projectscope.Display(p, c.o.Paths.Home) }

// tildeAll replaces the home dir inside free text (ungranted lines,
// reasons) with "~".
func (c *Catalog) tildeAll(s string) string {
	home := filepath.Clean(c.o.Paths.Home)
	if home == "" || home == "." || home == "/" {
		return s
	}
	return tildeAt(s, home)
}

// tildeAt replaces home with "~" only where it ends at a path boundary
// (followed by "/" or the end of the text), so /Users/a never rewrites
// /Users/ab.
func tildeAt(s, home string) string {
	var b strings.Builder
	for {
		i := strings.Index(s, home)
		if i < 0 {
			b.WriteString(s)
			return b.String()
		}
		end := i + len(home)
		b.WriteString(s[:i])
		if end < len(s) && pathNameByte(s[end]) {
			b.WriteString(home) // a sibling such as /Users/ab or /Users/a.bak
		} else {
			b.WriteByte('~')
		}
		s = s[end:]
	}
}

// pathNameByte reports whether c can continue a path component, so home
// followed by it names a sibling directory rather than home itself.
func pathNameByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-'
}

func baseName(p string) string {
	p = strings.TrimRight(p, "/")
	if p == "" {
		return ""
	}
	if p == "~" {
		return "~"
	}
	return p[strings.LastIndexByte(p, '/')+1:]
}

func ts(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// directID matches internal/mapapi's: "direct:" and the first 12 hex
// characters of sha256(clean cwd), so a row links to the same map.
func directID(cwd string) string {
	sum := sha256.Sum256([]byte(filepath.Clean(cwd)))
	return directPrefix + hex.EncodeToString(sum[:])[:12]
}

func (c *Catalog) build(entries []sessionindex.Entry, refs []transcript.SessionFiles, life []lifecycle.Session) *snapshot {
	now := c.o.Now()
	type acc struct {
		row    Row
		detail Detail
		mtime  time.Time
		hasLC  bool
	}
	byID := map[string]*acc{}
	get := func(id string) *acc {
		a := byID[id]
		if a == nil {
			a = &acc{row: Row{ID: id, State: StateUnknown}}
			byID[id] = a
		}
		return a
	}
	addSource := func(a *acc, s string) {
		for _, x := range a.row.Sources {
			if x == s {
				return
			}
		}
		a.row.Sources = append(a.row.Sources, s)
	}
	later := func(a *acc, t time.Time) {
		if t.After(a.row.last) {
			a.row.last = t
		}
	}
	for i := range entries {
		e := &entries[i]
		a := get(e.ID)
		addSource(a, "index")
		a.row.cwd = e.Cwd
		a.row.Title = c.tildeAll(e.Title)
		a.row.Branch = e.GitBranch
		a.row.Models = append([]string(nil), e.Models...)
		a.row.CCVersion = e.CCVersion
		a.row.Entrypoint = e.Entrypoint
		a.row.FirstTS = ts(e.FirstTS)
		a.row.Turns, a.row.ToolCalls, a.row.Subagents = e.Turns, e.ToolCalls, e.Subagents
		a.row.Skills = append([]string(nil), e.Skills...)
		a.row.Truncated = e.Truncated
		a.detail.TailRead, a.detail.TextCapped = e.TailRead, e.TextCapped
		a.row.Leaks = len(e.Findings)
		for _, f := range e.Findings {
			f.Target = c.tildeAll(f.Target)
			a.detail.Risk.Leaks = append(a.detail.Risk.Leaks, f)
		}
		a.mtime = e.Mtime
		later(a, e.LastTS)
		later(a, e.Mtime)
	}
	for i := range refs {
		r := &refs[i]
		a := get(r.ID)
		addSource(a, "transcript")
		if a.row.cwd == "" {
			a.row.cwd = r.CwdGuess
		}
		a.row.Subagents = max(a.row.Subagents, r.Subagents)
		a.mtime = r.ModTime
		later(a, r.ModTime)
	}
	for _, l := range life {
		a := get(l.SessionID)
		addSource(a, "lifecycle")
		a.hasLC = true
		a.row.State = l.State
		if l.Cwd != "" && (a.row.cwd == "" || !containsStr(a.row.Sources, "index")) {
			a.row.cwd = l.Cwd
		}
		if a.row.FirstTS == "" {
			a.row.FirstTS = l.Started
		}
		later(a, l.LastSeen)
	}
	for id, s := range c.act.sessions {
		a := get(id)
		addSource(a, "activity")
		if strings.HasPrefix(id, directPrefix) {
			a.row.Direct = true
			a.row.Title = paths.BinaryName + " run typed by hand (no Claude Code session)"
		}
		if a.row.cwd == "" {
			a.row.cwd = s.cwd
		}
		if a.row.FirstTS == "" && !s.first.IsZero() {
			a.row.FirstTS = ts(s.first)
		}
		later(a, s.last)
		a.row.Decisions, a.row.Denials, a.row.Asks = s.decisions, s.denials, s.asks
		for k := range s.skills {
			if !containsStr(a.row.Skills, k) {
				a.row.Skills = append(a.row.Skills, k)
			}
		}
		a.row.Subagents = max(a.row.Subagents, len(s.agents))
		if s.lastDenial != nil {
			d := *s.lastDenial
			d.Label = c.tildeAll(d.Label)
			a.row.LastDenial = &d
		}
		a.detail.Runs = s.runs
		a.detail.Risk.Denials, a.detail.Risk.Asks, a.detail.Risk.UngrantedAsks = s.denials, s.asks, s.ungrantedAsks
		for _, h := range s.ruleHits {
			a.detail.Risk.RuleHits = append(a.detail.Risk.RuleHits, *h)
		}
		for u := range s.ungranted {
			a.detail.Risk.Ungranted = append(a.detail.Risk.Ungranted, c.tildeAll(u))
		}
		for t := range s.agentTypes {
			a.detail.Agents = append(a.detail.Agents, t)
		}
		if p := s.running(now); p != "" {
			a.row.RunningSkill = p
		}
	}

	out := &snapshot{byID: map[string]int{}, details: map[string]*Detail{}, states: map[string]string{}, at: now}
	projects := map[string]*Project{}
	var cwds []string
	for _, a := range byID {
		r := &a.row
		if !a.hasLC && !r.Direct && !a.mtime.IsZero() {
			if age := now.Sub(a.mtime); age < lifecycle.TranscriptWindow && age > -time.Minute {
				r.State = StateLive // no lifecycle hooks, but the transcript is being written
			}
		}
		if r.State != StateLive {
			r.RunningSkill = ""
		}
		r.Project = c.display(r.cwd)
		r.ProjectName = baseName(r.Project)
		r.LastTS = ts(r.last)
		if r.Models == nil {
			r.Models = []string{}
		}
		if r.Skills == nil {
			r.Skills = []string{}
		}
		sort.Strings(r.Skills)
		sort.Strings(r.Sources)
		d := a.detail
		sort.Strings(d.Risk.Ungranted)
		sort.Strings(d.Agents)
		if d.Risk.Ungranted == nil {
			d.Risk.Ungranted = []string{}
		}
		if d.Agents == nil {
			d.Agents = []string{}
		}
		if d.Risk.RuleHits == nil {
			d.Risk.RuleHits = []RuleHit{}
		}
		sort.Slice(d.Risk.RuleHits, func(i, j int) bool {
			x, y := d.Risk.RuleHits[i], d.Risk.RuleHits[j]
			if x.Count != y.Count {
				return x.Count > y.Count
			}
			return x.Pack+"/"+x.Rule < y.Pack+"/"+y.Rule
		})
		d.Transcripts = !c.o.NoTranscripts
		out.rows = append(out.rows, *r)
		dd := d
		out.details[r.ID] = &dd
		out.states[r.ID] = r.State
		if r.cwd != "" {
			cwds = append(cwds, r.cwd)
			p := projects[r.Project]
			if p == nil {
				p = &Project{Project: r.Project, Name: r.ProjectName}
				projects[r.Project] = p
			}
			p.Sessions++
			p.Denials += r.Denials
			if r.State == StateLive {
				p.Live++
			}
			if r.LastTS > p.LastTS {
				p.LastTS = r.LastTS
			}
		}
	}
	sort.Slice(out.rows, func(i, j int) bool { return rowBefore(&out.rows[i], &out.rows[j]) })
	for i := range out.rows {
		out.byID[out.rows[i].ID] = i
		d := out.details[out.rows[i].ID]
		d.Row = out.rows[i]
		for _, f := range d.Risk.Leaks {
			out.leaks = append(out.leaks, rulebook.Leak{SessionID: d.ID, Ref: f.Ref, Tool: f.Tool, Target: f.Target, TargetCut: f.TargetCut, Where: f.Where,
				Pattern: f.Pattern, Label: f.Label, Agent: f.Agent, Project: d.Project, TS: f.TS})
		}
	}
	for _, p := range projects {
		out.projects = append(out.projects, *p)
	}
	sort.Slice(out.projects, func(i, j int) bool {
		if out.projects[i].LastTS != out.projects[j].LastTS {
			return out.projects[i].LastTS > out.projects[j].LastTS
		}
		return out.projects[i].Project < out.projects[j].Project
	})
	out.roots = projectscope.Roots(cwds, c.o.Paths.Home)
	return out
}

func rowBefore(a, b *Row) bool {
	if !a.last.Equal(b.last) {
		return a.last.After(b.last)
	}
	return a.ID < b.ID
}

func containsStr(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// ---------------------------------------------------------------- activity

// actAgg keeps per-session counts over the activity log, read by offset.
type actAgg struct {
	next     int64
	sessions map[string]*actSess
}

type pendingRun struct {
	skill string
	at    time.Time
}

type actSess struct {
	cwd                                           string
	first, last                                   time.Time
	decisions, denials, asks, ungrantedAsks, runs int
	skills, ungranted, agents, agentTypes         map[string]bool
	lastDenial                                    *Denial
	lastDenialAt                                  time.Time
	pending                                       map[string]pendingRun // tool_use_id → a rewritten decision with no run yet
	ruleHits                                      map[string]*RuleHit   // "<pack>/<rule>" → count (M6.4)
}

func newActAgg() *actAgg { return &actAgg{sessions: map[string]*actSess{}} }

// update reads what was appended since the last call (all of it on a reset)
// and returns the session id of each new record.
func (g *actAgg) update(path string) []string {
	if path == "" {
		return nil
	}
	res, err := activity.ReadFrom(path, g.next)
	if err != nil {
		return nil
	}
	if res.Reset {
		g.sessions = map[string]*actSess{}
	}
	g.next = res.Next
	var ids []string
	for i := range res.Records {
		if id := g.add(&res.Records[i]); id != "" {
			ids = append(ids, id)
		}
	}
	return ids
}

func (g *actAgg) add(r *activity.Record) string {
	id := r.SessionID
	if id == "" {
		if r.Cwd == "" {
			return ""
		}
		id = directID(r.Cwd)
	} else if !transcript.ValidID(id) {
		return ""
	}
	s := g.sessions[id]
	if s == nil {
		s = &actSess{skills: map[string]bool{}, ungranted: map[string]bool{}, agents: map[string]bool{}, agentTypes: map[string]bool{}, pending: map[string]pendingRun{}}
		g.sessions[id] = s
	}
	if s.cwd == "" && !strings.HasPrefix(r.Cwd, "~") { // a gate-only record shows cwd as ~ (M6.4)
		s.cwd = r.Cwd
	}
	t, _ := time.Parse(time.RFC3339Nano, r.TS)
	if !t.IsZero() {
		if s.first.IsZero() || t.Before(s.first) {
			s.first = t
		}
		if t.After(s.last) {
			s.last = t
		}
	}
	denial := func(label, skill string) {
		s.denials++
		if s.lastDenial == nil || !t.Before(s.lastDenialAt) {
			s.lastDenial = &Denial{TS: r.TS, Skill: skill, Label: label}
			s.lastDenialAt = t
		}
	}
	first := func(xs []string) string {
		if len(xs) > 0 {
			return xs[0]
		}
		return ""
	}
	for _, h := range r.Rules {
		if s.ruleHits == nil {
			s.ruleHits = map[string]*RuleHit{}
		}
		k := h.Pack + "/" + h.ID
		rh := s.ruleHits[k]
		if rh == nil {
			rh = &RuleHit{Pack: h.Pack, Rule: h.ID}
			s.ruleHits[k] = rh
		}
		rh.Count++
		rh.Severity, rh.Action = h.Severity, h.Action
	}
	switch r.Kind {
	case activity.KindDecision:
		s.decisions++
		if r.Decision == "deny" {
			who := ""
			if r.Subject != nil {
				who = r.Subject.Kind + " " + r.Subject.Name
			}
			denial("denied by a watchdeck gate", who)
		}
		if r.Decision == "ask" {
			s.asks++
			if len(r.Ungranted) > 0 {
				s.ungrantedAsks++
			}
		}
		for _, u := range r.Ungranted {
			s.ungranted[u] = true
		}
		if r.Rewritten != "" && r.ToolUseID != "" && len(r.Skills) > 0 {
			s.pending[r.ToolUseID] = pendingRun{skill: strings.Join(r.Skills, ", "), at: t}
		}
	case activity.KindDenied:
		denial("blocked by Claude Code (auto mode)", first(r.Skills))
	case activity.KindRun:
		s.runs++
		if r.ToolUseID != "" {
			delete(s.pending, r.ToolUseID)
		}
		switch {
		case len(r.Hints) > 0:
			k := r.Hints[0].Label
			if k == "" {
				k = r.Hints[0].Kind
			}
			denial("sandbox denied "+k, first(r.Skills))
		case r.Outcome == "policy_error":
			denial("policy error (exit 125)", first(r.Skills))
		case r.Outcome == "no_sandbox":
			denial("not sandboxed (exit 126)", first(r.Skills))
		case r.Outcome == "usage":
			denial("usage error", first(r.Skills))
		}
	}
	for _, k := range r.Skills {
		s.skills[k] = true
	}
	if r.Skill != "" {
		s.skills[r.Skill] = true
	}
	if r.AgentID != "" {
		s.agents[r.AgentID] = true
	}
	if r.AgentType != "" {
		s.agentTypes[r.AgentType] = true
	}
	return id
}

// running is the skill of the newest pending decision within runningWindow.
func (s *actSess) running(now time.Time) string {
	var best pendingRun
	for _, p := range s.pending {
		if now.Sub(p.at) < runningWindow && p.at.After(best.at) {
			best = p
		}
	}
	return best.skill
}
