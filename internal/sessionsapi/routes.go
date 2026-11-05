package sessionsapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/projectscope"
	"github.com/Panda-Taps-LLC/watchdeck/internal/sessionindex"
	"github.com/Panda-Taps-LLC/watchdeck/internal/transcript"
)

// Route patterns (Go 1.22 mux syntax, for ui.Options.Routes). PatternSessions
// replaces internal/mapapi's GET /api/sessions; the map route
// (GET /api/sessions/{id}/map) stays mapapi's and is unchanged.
const (
	PatternSessions = "GET /api/sessions"
	PatternSession  = "GET /api/sessions/{id}"
	PatternProjects = "GET /api/projects"
	PatternSearch   = "GET /api/search"
)

// Bounds.
const (
	PageSize        = 100
	MaxSearchHits   = sessionindex.DefaultSearchLimit // 50
	maxQuery        = 256                             // bytes
	searchTimeout   = 10 * time.Second
	listSearchCap   = 5000 // sessions a ?q= on the list can match
	errBusySearch   = "a search is already running; try again"
	errNoTranscript = "transcripts are off (watchdeck ui --no-transcripts): no search text is indexed"
)

// Routes returns the handlers keyed by their mux patterns.
func (c *Catalog) Routes() map[string]http.Handler {
	return map[string]http.Handler{
		PatternSessions: http.HandlerFunc(c.handleSessions),
		PatternSession:  http.HandlerFunc(c.handleSession),
		PatternProjects: http.HandlerFunc(c.handleProjects),
		PatternSearch:   http.HandlerFunc(c.handleSearch),
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		status, b = http.StatusInternalServerError, []byte(`{"error":"encoding the response failed"}`)
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	w.Write(append(b, '\n'))
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// Filter selects rows. Zero value: every row.
type Filter struct {
	Project string // absolute cwd (already validated)
	State   string // live | idle | ended | unknown
	Denials bool   // only rows with at least one denial
	Since   time.Time
	Until   time.Time // exclusive
}

func (f Filter) keep(r *Row) bool {
	if f.Project != "" && filepath.Clean(r.cwd) != f.Project {
		return false
	}
	if f.State != "" && r.State != f.State {
		return false
	}
	if f.Denials && r.Denials == 0 {
		return false
	}
	if !f.Since.IsZero() && r.last.Before(f.Since) {
		return false
	}
	if !f.Until.IsZero() && !r.last.Before(f.Until) {
		return false
	}
	return true
}

// List returns the rows a filter keeps, newest first (the snapshot's order).
// The CLI uses it so `watchdeck sessions --state/--denials` and the API
// cannot drift.
func (c *Catalog) List(f Filter) []Row {
	s := c.snapshotNow()
	if s == nil {
		return nil
	}
	var out []Row
	for i := range s.rows {
		if f.keep(&s.rows[i]) {
			out = append(out, s.rows[i])
		}
	}
	return out
}

// Detail returns one session's detail.
func (c *Catalog) Detail(id string) (Detail, bool) {
	s := c.snapshotNow()
	if s == nil {
		return Detail{}, false
	}
	d, ok := s.details[id]
	if !ok {
		return Detail{}, false
	}
	return *d, true
}

// Projects lists every project with a session, newest first.
func (c *Catalog) Projects() []Project {
	s := c.snapshotNow()
	if s == nil {
		return []Project{}
	}
	return append([]Project{}, s.projects...)
}

// apiErr is a constant error (no errors.New at package level: the package
// must stay init-free).
type apiErr string

func (e apiErr) Error() string { return string(e) }

const (
	errSearchOff apiErr = errNoTranscript
	errBusy      apiErr = errBusySearch
)

// Search runs a full-text search under the index's read lock, cancelled
// with ctx. At most two searches run at once; a third gets errBusy.
func (c *Catalog) Search(ctx context.Context, q string, limit int) ([]sessionindex.Hit, error) {
	if c.ix == nil {
		return nil, errSearchOff
	}
	c.snapshotNow() // a search before the first refresh would find an empty index
	select {
	case c.searchSem <- struct{}{}:
	default:
		return nil, errBusy
	}
	defer func() { <-c.searchSem }()
	c.ixMu.RLock()
	defer c.ixMu.RUnlock()
	return c.ix.SearchContext(ctx, q, limit)
}

// parseTime accepts RFC3339 or a date (UTC midnight; for until, the next
// midnight, so a date is inclusive).
func parseTime(v string, end bool) (time.Time, bool) {
	if v == "" {
		return time.Time{}, true
	}
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t, true
	}
	if t, err := time.Parse("2006-01-02", v); err == nil {
		if end {
			t = t.Add(24 * time.Hour)
		}
		return t, true
	}
	return time.Time{}, false
}

// project validates ?project=: "~/…" or absolute, clean, and a cwd the
// catalog knows (any session's cwd or git root). The error never echoes the
// value.
func (c *Catalog) project(v string, s *snapshot) (string, error) {
	if v == "" {
		return "", nil
	}
	return projectscope.Resolve(v, "", c.o.Paths.Home, func() []string { return s.roots })
}

// cursor is base64url("<unix nanos of last>|<id>") of the last row of a page.
func encodeCursor(r *Row) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(r.last.UnixNano(), 10) + "|" + r.ID))
}

func decodeCursor(v string) (time.Time, string, bool) {
	b, err := base64.RawURLEncoding.DecodeString(v)
	if err != nil || len(b) > 256 {
		return time.Time{}, "", false
	}
	ns, id, ok := strings.Cut(string(b), "|")
	if !ok || !(transcript.ValidID(id) || validDirect(id)) {
		return time.Time{}, "", false
	}
	n, err := strconv.ParseInt(ns, 10, 64)
	if err != nil {
		return time.Time{}, "", false
	}
	return time.Unix(0, n), id, true
}

func validDirect(id string) bool {
	rest, ok := strings.CutPrefix(id, directPrefix)
	if !ok || len(rest) != 12 {
		return false
	}
	for i := 0; i < len(rest); i++ {
		if c := rest[i]; !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// sessionsJSON is GET /api/sessions.
type sessionsJSON struct {
	Sessions       []Row  `json:"sessions"`        // never null
	NextCursor     string `json:"next_cursor"`     // "" on the last page
	Total          int    `json:"total"`           // rows the filters keep (all pages)
	Transcripts    bool   `json:"transcripts"`     // false under --no-transcripts
	SearchDisabled bool   `json:"search_disabled"` // a ?q= under --no-transcripts: no text to search
	Updated        string `json:"updated"`         // when the snapshot was built
}

// handleSessions is GET /api/sessions?project&state&denials=1&since&until&q&cursor&limit.
// Rows are newest first by last activity, then id; a page holds at most 100
// (limit may lower it). The cursor names the last row of the previous page
// by its sort key, so a session that arrives between two page requests
// lands on page one and never shifts or repeats a later page.
func (c *Catalog) handleSessions(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	s := c.snapshotNow()
	if s == nil {
		writeError(w, http.StatusInternalServerError, "the session catalog could not be built")
		return
	}
	var f Filter
	var err error
	if f.Project, err = c.project(q.Get("project"), s); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	switch v := q.Get("state"); v {
	case "", StateLive, StateIdle, StateEnded, StateUnknown:
		f.State = v
	default:
		writeError(w, http.StatusBadRequest, "state must be live, idle, ended or unknown")
		return
	}
	switch q.Get("denials") {
	case "", "0":
	case "1":
		f.Denials = true
	default:
		writeError(w, http.StatusBadRequest, "denials must be 0 or 1")
		return
	}
	var ok bool
	if f.Since, ok = parseTime(q.Get("since"), false); !ok {
		writeError(w, http.StatusBadRequest, "since must be RFC3339 or 2006-01-02")
		return
	}
	if f.Until, ok = parseTime(q.Get("until"), true); !ok {
		writeError(w, http.StatusBadRequest, "until must be RFC3339 or 2006-01-02")
		return
	}
	limit := PageSize
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			writeError(w, http.StatusBadRequest, "limit must be a positive integer")
			return
		}
		limit = min(n, PageSize)
	}
	var after struct {
		set  bool
		last time.Time
		id   string
	}
	if v := q.Get("cursor"); v != "" {
		t, id, ok := decodeCursor(v)
		if !ok {
			writeError(w, http.StatusBadRequest, "invalid cursor")
			return
		}
		after.set, after.last, after.id = true, t, id
	}
	text := strings.TrimSpace(q.Get("q"))
	if len(text) > maxQuery {
		writeError(w, http.StatusBadRequest, "q is longer than 256 bytes")
		return
	}
	out := sessionsJSON{Sessions: []Row{}, Transcripts: !c.o.NoTranscripts, Updated: ts(s.at)}
	var snippets map[string]string
	if text != "" {
		if c.ix == nil {
			out.SearchDisabled = true
			writeJSON(w, http.StatusOK, out)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), searchTimeout)
		defer cancel()
		hits, err := c.Search(ctx, text, listSearchCap)
		if err != nil {
			searchError(w, err)
			return
		}
		snippets = make(map[string]string, len(hits))
		for _, h := range hits {
			snippets[h.SessionID] = c.tildeAll(h.Snippet)
		}
	}
	for i := range s.rows {
		row := &s.rows[i]
		if !f.keep(row) {
			continue
		}
		if snippets != nil {
			sn, hit := snippets[row.ID]
			if !hit {
				continue
			}
			rc := *row
			rc.Snippet = sn
			row = &rc
		}
		out.Total++
		if after.set {
			pivot := Row{ID: after.id, last: after.last}
			if !rowBefore(&pivot, row) {
				continue // at or before the cursor
			}
		}
		if len(out.Sessions) < limit {
			out.Sessions = append(out.Sessions, *row)
		} else if out.NextCursor == "" {
			out.NextCursor = encodeCursor(&out.Sessions[len(out.Sessions)-1])
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func searchError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errBusy):
		w.Header().Set("Retry-After", "1")
		writeError(w, http.StatusTooManyRequests, errBusySearch)
	case errors.Is(err, errSearchOff):
		writeError(w, http.StatusConflict, errNoTranscript)
	case errors.Is(err, context.Canceled):
		writeError(w, 499, "search cancelled") // the client is gone; nobody reads this
	case errors.Is(err, context.DeadlineExceeded):
		writeError(w, http.StatusServiceUnavailable, "search took too long; try a longer query")
	default:
		writeError(w, http.StatusInternalServerError, "search failed")
	}
}

// handleSession is GET /api/sessions/{id}.
func (c *Catalog) handleSession(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !transcript.ValidID(id) && !validDirect(id) {
		writeError(w, http.StatusBadRequest, "invalid session id")
		return
	}
	d, ok := c.Detail(id)
	if !ok {
		writeError(w, http.StatusNotFound, "unknown session")
		return
	}
	writeJSON(w, http.StatusOK, d)
}

// handleProjects is GET /api/projects.
func (c *Catalog) handleProjects(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"projects": c.Projects()})
}

// hitJSON is one GET /api/search hit.
type hitJSON struct {
	SessionID   string `json:"session_id"`
	Snippet     string `json:"snippet"` // at most 240 bytes, newlines as spaces
	Title       string `json:"title,omitempty"`
	Project     string `json:"project,omitempty"`
	ProjectName string `json:"project_name,omitempty"`
	State       string `json:"state,omitempty"`
	LastTS      string `json:"last_ts,omitempty"`
}

// handleSearch is GET /api/search?q=&limit=: at most 50 hits, one per
// session, newest first, each with a snippet of at most 240 bytes. Two
// searches run at once at most (429 beyond); a search stops when the
// client goes away or after 10 s.
func (c *Catalog) handleSearch(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	text := strings.TrimSpace(q.Get("q"))
	if len(text) > maxQuery {
		writeError(w, http.StatusBadRequest, "q is longer than 256 bytes")
		return
	}
	limit := MaxSearchHits
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			writeError(w, http.StatusBadRequest, "limit must be a positive integer")
			return
		}
		limit = min(n, MaxSearchHits)
	}
	out := map[string]any{"hits": []hitJSON{}, "disabled": c.ix == nil}
	if text == "" || c.ix == nil {
		writeJSON(w, http.StatusOK, out)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), searchTimeout)
	defer cancel()
	hits, err := c.Search(ctx, text, limit)
	if err != nil {
		searchError(w, err)
		return
	}
	s := c.snapshotNow()
	list := make([]hitJSON, 0, len(hits))
	for _, h := range hits {
		hj := hitJSON{SessionID: h.SessionID, Snippet: c.tildeAll(h.Snippet)}
		if s != nil {
			if i, ok := s.byID[h.SessionID]; ok {
				row := &s.rows[i]
				hj.Title, hj.Project, hj.ProjectName, hj.State, hj.LastTS = row.Title, row.Project, row.ProjectName, row.State, row.LastTS
			}
		}
		list = append(list, hj)
	}
	out["hits"] = list
	writeJSON(w, http.StatusOK, out)
}
