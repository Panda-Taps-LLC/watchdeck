package mapapi

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/activity"
	"github.com/Panda-Taps-LLC/watchdeck/internal/manifest"
	"github.com/Panda-Taps-LLC/watchdeck/internal/mapmodel"
	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
	"github.com/Panda-Taps-LLC/watchdeck/internal/skills"
	"github.com/Panda-Taps-LLC/watchdeck/internal/transcript"
)

// Session is one row of GET /api/sessions. It is built from the activity
// log and Stat calls; no transcript is opened to make it.
type Session struct {
	ID           string `json:"id"`
	Cwd          string `json:"cwd"` // as recorded (display value); for a transcript-only session Discover's guess
	Live         bool   `json:"live"`
	Started      string `json:"started,omitempty"`       // earliest activity record; absent for a transcript-only session
	LastActivity string `json:"last_activity,omitempty"` // newest of the transcript's mtime and the newest record
	// Decisions counts the hook's decision records. Denials counts what the
	// activity log alone shows: denied records and runs with a denial hint
	// or an outcome of policy_error, no_sandbox or usage. A denial that only
	// the transcript's tool result reports appears on the map, not here.
	Decisions int      `json:"decisions"`
	Denials   int      `json:"denials"`
	Skills    []string `json:"skills"`
	Source    string   `json:"source"` // activity | transcript | both
	Subagents int      `json:"subagents"`
}

// directPrefix marks the pseudo-session of records that carry no session id
// (a `watchdeck run` typed by hand): one per cwd, Spec B §1c.
const directPrefix = "direct:"

// directID is "direct:" and the first 12 hex characters of sha256(cwd).
func directID(cwd string) string {
	sum := sha256.Sum256([]byte(filepath.Clean(cwd)))
	return directPrefix + hex.EncodeToString(sum[:])[:12]
}

// validSessionID accepts a transcript id (transcript.ValidID) or the direct
// form "direct:" + 12 lowercase hex characters.
func validSessionID(id string) bool {
	if rest, ok := strings.CutPrefix(id, directPrefix); ok {
		if len(rest) != 12 {
			return false
		}
		for i := 0; i < len(rest); i++ {
			if c := rest[i]; !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				return false
			}
		}
		return true
	}
	return transcript.ValidID(id)
}

// group is what the activity log says about one session.
type group struct {
	id          string
	cwd         string
	first, last time.Time
	decisions   int
	denials     int
	skills      map[string]bool
	agents      map[string]bool
	transcripts []string // distinct transcript_path values whose file stem is this session id
}

func (g *group) add(r *activity.Record) {
	if g.cwd == "" {
		g.cwd = r.Cwd
	}
	if t, err := time.Parse(time.RFC3339Nano, r.TS); err == nil {
		if g.first.IsZero() || t.Before(g.first) {
			g.first = t
		}
		if t.After(g.last) {
			g.last = t
		}
	}
	switch r.Kind {
	case activity.KindDecision:
		g.decisions++
	case activity.KindDenied:
		g.denials++
	case activity.KindRun:
		if len(r.Hints) > 0 || r.Outcome == "policy_error" || r.Outcome == "no_sandbox" || r.Outcome == "usage" {
			g.denials++
		}
	}
	for _, s := range r.Skills {
		g.skills[s] = true
	}
	if r.Skill != "" {
		g.skills[r.Skill] = true
	}
	if r.AgentID != "" {
		g.agents[r.AgentID] = true
	}
	// Only a transcript named after this very session is taken: a record
	// cannot point Discover at another session's file.
	if p := r.Transcript; p != "" && g.id == r.SessionID && strings.TrimSuffix(filepath.Base(p), ".jsonl") == g.id {
		for _, q := range g.transcripts {
			if q == p {
				return
			}
		}
		g.transcripts = append(g.transcripts, p)
	}
}

// groupRecords groups records by session id; records without one go to
// their cwd's direct pseudo-session (records with neither are dropped).
func groupRecords(recs []activity.Record) map[string]*group {
	out := map[string]*group{}
	for i := range recs {
		r := &recs[i]
		id := r.SessionID
		if id == "" {
			if r.Cwd == "" {
				continue
			}
			id = directID(r.Cwd)
		} else if !transcript.ValidID(id) {
			continue // the page could never ask for it
		}
		g := out[id]
		if g == nil {
			g = &group{id: id, skills: map[string]bool{}, agents: map[string]bool{}}
			out[id] = g
		}
		g.add(r)
	}
	return out
}

// readActivity reads the whole log (rotated file first), joined.
func (a *api) readActivity() ([]activity.Record, error) {
	res, err := activity.Read(a.d.Paths.Activity, activity.ReadOptions{})
	return res.Records, err
}

func (a *api) discover(cwd string, transcripts []string) []transcript.SessionRef {
	if a.d.NoTranscripts {
		return nil
	}
	refs, err := transcript.Discover(transcript.PathsDeps{
		ClaudeProjectsDir: a.d.Paths.ClaudeProjectsDir(),
		Cwd:               cwd,
		TranscriptPaths:   transcripts,
	})
	if err != nil {
		return nil // an unreadable projects dir lists nothing, as a missing one does
	}
	return refs
}

// handleSessions is GET /api/sessions: newest first, metadata only.
func (a *api) handleSessions(w http.ResponseWriter, r *http.Request) {
	cwd, err := a.cwdFor(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	recs, err := a.readActivity()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "the activity log could not be read")
		return
	}
	groups := groupRecords(recs)
	var named []string
	for _, g := range groups {
		named = append(named, g.transcripts...)
	}
	sort.Strings(named)
	refs := a.discover(cwd, named)

	now := a.d.Now()
	byID := map[string]*Session{}
	last := map[string]time.Time{}
	for _, g := range groups {
		s := &Session{ID: g.id, Cwd: g.cwd, Decisions: g.decisions, Denials: g.denials, Source: "activity", Skills: sortedKeys(g.skills), Subagents: len(g.agents)}
		if !g.first.IsZero() {
			s.Started = g.first.UTC().Format(time.RFC3339Nano)
		}
		byID[g.id], last[g.id] = s, g.last
	}
	for _, ref := range refs {
		s := byID[ref.ID]
		if s == nil {
			s = &Session{ID: ref.ID, Cwd: ref.CwdGuess, Source: "transcript", Skills: []string{}}
			byID[ref.ID] = s
		} else if s.Source != "activity" {
			continue // the same id under two project dirs: the newest ref (Discover's order) wins
		} else {
			s.Source = "both"
		}
		s.Subagents = max(s.Subagents, ref.Subagents)
		if ref.ModTime.After(last[ref.ID]) {
			last[ref.ID] = ref.ModTime
		}
	}
	out := make([]Session, 0, len(byID))
	for id, s := range byID {
		if t := last[id]; !t.IsZero() {
			s.LastActivity = t.UTC().Format(time.RFC3339Nano)
			s.Live = now.Sub(t) < mapmodel.LiveWindow
		}
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool {
		ti, tj := last[out[i].ID], last[out[j].ID]
		if !ti.Equal(tj) {
			return ti.After(tj)
		}
		return out[i].ID < out[j].ID
	})
	writeJSON(w, http.StatusOK, out)
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// viewTicks is the ticks-only map view: {session, ticks, totals, updated}.
const viewTicks = "ticks"

// ticksView is the body of ?view=ticks. Updated is the session's newest
// event or record (Session.Last), so a poller can tell a quiet session.
type ticksView struct {
	Session mapmodel.SessionInfo `json:"session"`
	Ticks   []mapmodel.Tick      `json:"ticks"`
	Totals  mapmodel.Totals      `json:"totals"`
	Shown   int                  `json:"shown"`
	Updated string               `json:"updated"`
}

// authorityMsg is the 400 for a bad ?authority= value.
const authorityMsg = "authority must be a comma list of deny_rule, classifier, auto, allow_rule, user, hook, sandbox, blocked, none"

// parseAuthorities reads ?authority=a,b: each comma-separated word, spaces
// trimmed, must be one of the nine authority words. The result is sorted
// and without repeats; an empty value is no filter (nil). ok is false on an
// unknown or empty word.
func parseAuthorities(v string) (words []string, ok bool) {
	if strings.TrimSpace(v) == "" {
		return nil, true
	}
	seen := map[string]bool{}
	for _, w := range strings.Split(v, ",") {
		w = strings.TrimSpace(w)
		if !mapmodel.IsAuthority(w) {
			return nil, false
		}
		seen[w] = true
	}
	return sortedKeys(seen), true
}

// handleMap is GET /api/sessions/{id}/map?view=topology|timeline|ticks&hide_none=0|1&authority=a,b.
func (a *api) handleMap(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !validSessionID(id) {
		writeError(w, http.StatusBadRequest, "invalid session id")
		return
	}
	q := r.URL.Query()
	view := q.Get("view")
	switch view {
	case "":
		view = mapmodel.ViewTopology
	case mapmodel.ViewTopology, mapmodel.ViewTimeline, viewTicks:
	default:
		writeError(w, http.StatusBadRequest, "view must be topology, timeline or ticks")
		return
	}
	var hide bool
	switch q.Get("hide_none") {
	case "", "0":
	case "1":
		hide = true
	default:
		writeError(w, http.StatusBadRequest, "hide_none must be 0 or 1")
		return
	}
	auths, ok := parseAuthorities(q.Get("authority"))
	if !ok {
		writeError(w, http.StatusBadRequest, authorityMsg)
		return
	}
	authKey := "all"
	if auths != nil {
		authKey = strings.Join(auths, ",")
	}
	cwd, err := a.cwdFor(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	inm := r.Header.Get("If-None-Match")
	hideKey := "0"
	if hide {
		hideKey = "1"
	}
	key := id + "|" + view + "|" + hideKey + "|" + authKey + "|" + cwd

	// Fast path: the inputs of this session's last build, Stat only.
	if in := a.cached(key); in != nil && inm != "" {
		if tag := a.etag(in); notModified(inm, tag) {
			w.Header().Set("ETag", quoted(tag))
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}

	recs, err := a.readActivity()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "the activity log could not be read")
		return
	}
	res, ok := a.resolve(id, recs, cwd)
	if !ok {
		writeError(w, http.StatusNotFound, "unknown session")
		return
	}
	in := &inputs{view: view, hideNone: hide, authorities: authKey, noTranscripts: a.d.NoTranscripts, activity: a.d.Paths.Activity}
	var s *transcript.Session
	if res.ref != nil {
		if real, err := filepath.EvalSymlinks(res.ref.Path); err == nil {
			in.transcript = real
			if root, err := projectsRoot(a.d.Paths.ClaudeProjectsDir()); err == nil {
				in.root = root
				in.subagents = filepath.Join(filepath.Dir(real), id, "subagents")
			}
		}
		// Load enforces the path safety again (EvalSymlinks, under
		// ProjectsDir, ValidID); a refusal or an unreadable file is a
		// missing transcript, never an error page.
		if ss, err := a.load(res.ref.Path, transcript.Options{ProjectsDir: a.d.Paths.ClaudeProjectsDir()}); err == nil {
			s = ss
		}
	} else {
		in.candidates = res.named
	}

	buildView := view
	if view == viewTicks {
		buildView = mapmodel.ViewTopology // ticks carry their topology node and agent
	}
	o := mapmodel.Options{
		View:          buildView,
		HideNone:      hide,
		Authorities:   auths,
		Now:           a.d.Now(),
		Loc:           time.Local,
		SessionID:     id,
		Cwd:           res.cwd,
		NoTranscripts: a.d.NoTranscripts,
	}
	if s == nil && !a.d.NoTranscripts && !res.direct {
		o.TranscriptMissing = true
		o.TranscriptPath = a.displayPath(res.shownPath)
	}
	if s != nil && o.Cwd == "" {
		o.Cwd = s.Cwd
	}

	// Pass one finds the skills the Graph will show; Declared is then built
	// for every one of them from the current manifests and overrides, so a
	// grant changes the card (without it mapmodel falls back to the
	// records' ungranted lists, which never change).
	first := o
	first.View, first.HideNone, first.Authorities = mapmodel.ViewTopology, false, nil
	g0 := mapmodel.Build(s, res.recs, nil, first)
	var names []string
	for _, n := range g0.Nodes {
		if n.Kind == "skill" {
			names = append(names, strings.TrimPrefix(n.ID, "skill:"))
		}
	}
	declared, overrideFiles, manifestFiles := a.declared(names, res.cwd, cwd)
	in.overrides, in.manifests = overrideFiles, manifestFiles

	tag := a.etag(in)
	a.remember(key, in)
	w.Header().Set("ETag", quoted(tag))
	if notModified(inm, tag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	g := mapmodel.Build(s, res.recs, declared, o)
	if view == viewTicks {
		writeJSON(w, http.StatusOK, ticksView{Session: g.Session, Ticks: g.Ticks, Totals: g.Totals, Shown: g.Shown, Updated: g.Session.Last})
		return
	}
	g.ETag = tag
	writeJSON(w, http.StatusOK, g)
}

// resolution is how one session id maps to records and a transcript.
type resolution struct {
	direct    bool
	cwd       string                 // the recorded cwd (display value and run-matching cwd)
	recs      []activity.Record      // what Build gets
	ref       *transcript.SessionRef // the transcript Discover found, nil when none
	named     []string               // transcript paths the session's records name (Stat-only ETag candidates when ref is nil)
	shownPath string                 // the path the "not found" banner names
}

// resolve finds a session by id. The transcript comes only from Discover
// (the current project's dir, the session's recorded cwd, and the paths the
// session's own records name), never from the request.
func (a *api) resolve(id string, recs []activity.Record, base string) (resolution, bool) {
	var res resolution
	if strings.HasPrefix(id, directPrefix) {
		res.direct = true
		for i := range recs {
			r := recs[i]
			if r.SessionID == "" && r.Cwd != "" && directID(r.Cwd) == id {
				if res.cwd == "" {
					res.cwd = r.Cwd
				}
				res.recs = append(res.recs, r)
			}
		}
		return res, len(res.recs) > 0
	}

	g := groupRecords(recs)[id]
	if g != nil {
		res.cwd, res.named = g.cwd, g.transcripts
		// activity.Read has already joined runs to decisions over the whole
		// log, so a run another session's decision claims carries that
		// session's id. Build gets only this session's records: a run left
		// without a session id (typed by hand, or claimed by no decision)
		// belongs to its cwd's direct pseudo-session alone, never to a real
		// session sharing the cwd (the cross-session guard of Spec B §3.6).
		for _, r := range recs {
			if r.SessionID == id {
				res.recs = append(res.recs, r)
			}
		}
		if len(g.transcripts) > 0 {
			res.shownPath = g.transcripts[0]
		}
	}
	pick := func(refs []transcript.SessionRef) *transcript.SessionRef {
		for i := range refs {
			if refs[i].ID == id {
				return &refs[i]
			}
		}
		return nil
	}
	res.ref = pick(a.discover(base, res.named))
	if res.ref == nil && !a.d.NoTranscripts && res.cwd != "" && filepath.Clean(res.cwd) != filepath.Clean(base) {
		res.ref = pick(a.discover(res.cwd, nil))
	}
	if res.ref != nil {
		res.shownPath = res.ref.Path
		if res.cwd == "" {
			res.cwd = res.ref.CwdGuess
		}
	}
	return res, g != nil || res.ref != nil
}

// declared builds mapmodel.Declared for each named skill found on disk, from
// its PERMISSIONS.yaml and the overrides as they are now. Skills are found
// as /api/skills finds them (home, the cwd, CLAUDE_SKILL_DIR), from the
// session's recorded cwd when that directory exists, else the dashboard's.
// A skill not found is left out (the card then shows what the records say).
// A malformed overrides file counts as empty here; the Skills page reports
// it. It also returns the overrides and manifest paths for the ETag.
func (a *api) declared(names []string, cwd, base string) (map[string]mapmodel.Declared, []string, []string) {
	root := base
	if cwd != "" {
		if fi, err := os.Stat(cwd); err == nil && fi.IsDir() {
			root = cwd
		}
	}
	userFile := a.d.Paths.OverridesFile()
	overrideFiles := []string{userFile}
	var projectFile string
	if pr := paths.ProjectRoot(root, a.d.Paths.Home); pr != "" {
		projectFile = filepath.Join(pr, manifest.ProjectOverridesFile)
		overrideFiles = append(overrideFiles, projectFile)
	}
	if len(names) == 0 {
		return nil, overrideFiles, nil
	}
	roots := skills.Roots{Home: a.d.Paths.Home, Cwd: root}
	if v := a.d.Environ["CLAUDE_SKILL_DIR"]; v != "" {
		roots.Env = map[string]string{"CLAUDE_SKILL_DIR": v}
	}
	found, err := skills.Scan(roots)
	if err != nil {
		return nil, overrideFiles, nil
	}
	user, _, err := manifest.LoadOverridesFile(userFile)
	if err != nil {
		user = manifest.Overrides{}
	}
	var project manifest.Overrides
	if projectFile != "" {
		if p, _, err := manifest.LoadProjectOverridesFile(projectFile); err == nil {
			project = p
		}
	}
	out := map[string]mapmodel.Declared{}
	var manifests []string
	for _, name := range names {
		var sk *skills.Skill
		for i := range found {
			if found[i].Name == name {
				sk = &found[i]
				break
			}
		}
		if sk == nil {
			continue
		}
		mp := filepath.Join(sk.RealRoot, "PERMISSIONS.yaml")
		manifests = append(manifests, mp)
		d := mapmodel.Declared{Skill: name}
		d.Granted, _ = manifest.Grant(name, user, project)
		if req, err := manifest.Parse(mp); err == nil {
			d.HasManifest, d.Request = true, req
			_, d.Ungranted = manifest.Clip(req, d.Granted)
		}
		out[name] = d
	}
	return out, overrideFiles, manifests
}

// projectsRoot is the projects dir made absolute with its symlinks
// resolved: the prefix every path read under it must keep.
func projectsRoot(dir string) (string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(abs)
}

// displayPath shows a transcript path without revealing an absolute path:
// "~/<rel>" under the home dir, ".../<dir>/<file>" anywhere else.
func (a *api) displayPath(p string) string {
	if p == "" {
		return ""
	}
	p = filepath.Clean(p)
	if home := a.d.Paths.Home; home != "" {
		if rel, err := filepath.Rel(filepath.Clean(home), p); err == nil && rel != "." && !strings.HasPrefix(rel, "..") {
			return "~/" + filepath.ToSlash(rel)
		}
	}
	return ".../" + filepath.Base(filepath.Dir(p)) + "/" + filepath.Base(p)
}
