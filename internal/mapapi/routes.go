// Package mapapi serves the agent map's two API routes on the dashboard
// server (Spec B §4), mounted through ui.Options.Routes and therefore behind
// the dashboard's guard (loopback Host, bearer token, security headers):
//
//	GET /api/sessions                 sessions newest first, metadata only
//	GET /api/sessions/{id}/map        one session's Graph (mapmodel.Build)
//
// Since M5.5 the dashboard (cmd/watchdeck/ui.go) drops this package's
// GET /api/sessions and mounts internal/sessionsapi's in its place (every
// project, lifecycle states, filters, pages); the handler here remains for
// its tests and for callers that mount Routes alone. The map route is the
// one the page uses, and it is unchanged.
//
// Transcripts are found only through transcript.Discover (the current
// project's escaped dir plus the transcript_path values the activity log
// names), opened only through transcript.Load with ProjectsDir set (which
// enforces the path safety), and never under NoTranscripts. The session list
// opens no transcript at all: Discover is ReadDir and Stat.
//
// The map carries an ETag over the Stat of every input (see etag.go); a
// request whose If-None-Match equals it gets 304 after Stat calls only, from
// a small in-memory record of which files the session's last build read.
// Nothing derived is written to disk.
//
// Privacy: no response carries an absolute transcript path. A session's cwd
// is shown as recorded (a display value the user already sees in Claude
// Code); a transcript path, when the map must name one in its "not found"
// banner, is shown "~/"-abbreviated under the home dir and as
// ".../<dir>/<file>" anywhere else.
//
// The package does no work at init (no regexp, no package-level maps): the
// binary that links it is also the PreToolUse hook.
package mapapi

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
	"github.com/Panda-Taps-LLC/watchdeck/internal/projectscope"
	"github.com/Panda-Taps-LLC/watchdeck/internal/transcript"
)

// Deps is the host state the routes need; tests point every path at temp
// dirs. Nothing in this package reads the environment or the home dir.
type Deps struct {
	Paths paths.Paths
	// Cwd is the dashboard's cwd: the project whose sessions Discover lists.
	// It is optional (M5.3): a server in auto or service mode has none, and
	// then a request may name a project with ?project=<abs root>, which must
	// be one of ProjectRoots (projectscope.Resolve; anything else is 400).
	Cwd          string
	ProjectRoots func() []string
	Environ      map[string]string // CLAUDE_SKILL_DIR is honoured when finding skills, as /api/skills does
	// NoTranscripts (watchdeck ui --no-transcripts): Discover and Load are
	// never called; sessions and graphs come from the activity log alone.
	NoTranscripts bool
	Version       string           // the binary's version, part of the ETag
	Now           func() time.Time // nil: time.Now
}

// Route patterns (Go 1.22 mux syntax, as ui.Options.Routes wants them).
const (
	PatternSessions = "GET /api/sessions"
	PatternMap      = "GET /api/sessions/{id}/map"
)

// Routes returns the two handlers keyed by their mux patterns, for
// ui.Options.Routes.
func Routes(d Deps) map[string]http.Handler { return newAPI(d).routes() }

func (a *api) routes() map[string]http.Handler {
	return map[string]http.Handler{
		PatternSessions: http.HandlerFunc(a.handleSessions),
		PatternMap:      http.HandlerFunc(a.handleMap),
	}
}

// api holds the dependencies, the test seam for transcript.Load and the
// per-session record of ETag inputs.
type api struct {
	d    Deps
	load func(path string, o transcript.Options) (*transcript.Session, error)

	mu    sync.Mutex
	cache map[string]*inputs // key: session id + "|" + view + "|" + hide_none
	order []string           // insertion order, for eviction
}

// maxCache bounds the ETag-input records (one per session and view seen).
const maxCache = 64

func newAPI(d Deps) *api {
	if d.Now == nil {
		d.Now = time.Now
	}
	return &api{d: d, load: transcript.Load, cache: map[string]*inputs{}}
}

func (a *api) cached(key string) *inputs {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.cache[key]
}

func (a *api) remember(key string, in *inputs) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.cache[key]; !ok {
		a.order = append(a.order, key)
		for len(a.order) > maxCache {
			delete(a.cache, a.order[0])
			a.order = a.order[1:]
		}
	}
	a.cache[key] = in
}

// writeJSON matches internal/ui's encoding: compact JSON, a trailing newline,
// application/json; charset=utf-8. The guard has already set the security
// headers (Cache-Control: no-store among them).
func writeJSON(w http.ResponseWriter, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		status, b = http.StatusInternalServerError, []byte(`{"error":"encoding the response failed"}`)
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	w.Write(append(b, '\n'))
}

// writeError writes {"error": msg}, the dashboard's error body.
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// cwdFor is the working directory a request uses: Deps.Cwd, or a
// ?project= value naming a known project (projectscope.Resolve).
func (a *api) cwdFor(r *http.Request) (string, error) {
	return projectscope.Resolve(r.URL.Query().Get(projectscope.Param), a.d.Cwd, a.d.Paths.Home, a.d.ProjectRoots)
}
