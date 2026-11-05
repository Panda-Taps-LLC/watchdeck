package ui

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/Panda-Taps-LLC/watchdeck/internal/activity"
)

const (
	activityDefaultLimit = 500
	activityMaxLimit     = 2000 // also the cap on tail
)

// activityJSON is GET /api/activity, and what `watchdeck activity --json`
// prints.
type activityJSON struct {
	Records []activity.Record `json:"records"` // never null
	Next    int64             `json:"next"`    // pass back as ?after=
	Reset   bool              `json:"reset"`   // the file shrank (rotated or truncated): drop what you hold; records are then the newest ones
	Skipped int               `json:"skipped"` // unparseable lines passed over
	Path    string            `json:"path"`
	Enabled bool              `json:"enabled"` // false when WATCHDECK_ACTIVITY=off
}

func (s *Server) activityRoutes() []route {
	return []route{{"GET /api/activity", http.HandlerFunc(s.handleActivity)}}
}

// handleActivity answers GET /api/activity?after=N&limit=M&tail=T&kinds=a,b&session=S.
// The page asks for ?after=0&tail=200 first, then polls ?after=<next>.
// activity.Read joins runs to their decisions itself, so there is no second
// Join here. tail is honoured only with after=0; limit defaults to 500 and
// both are capped at 2000. When after is past the end of the file (it was
// rotated or truncated) the answer is reset true with the newest limit
// records and next at the current file's end, so the page drops what it holds
// and polls on from there instead of starting over. A value that is not a non-negative integer is a
// 400. With the log off the answer is 200, enabled false, no records.
func (s *Server) handleActivity(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	after, ok := queryInt(w, q.Get("after"), "after")
	if !ok {
		return
	}
	limit, ok := queryInt(w, q.Get("limit"), "limit")
	if !ok {
		return
	}
	tail, ok := queryInt(w, q.Get("tail"), "tail")
	if !ok {
		return
	}
	if limit == 0 {
		limit = activityDefaultLimit
	}
	limit = min(limit, activityMaxLimit)
	tail = min(tail, activityMaxLimit)
	if after > 0 {
		tail = 0
	}
	var kinds []string // nil = all; an empty non-nil slice would match nothing
	for _, k := range strings.Split(q.Get("kinds"), ",") {
		if k = strings.TrimSpace(k); k != "" {
			kinds = append(kinds, k)
		}
	}

	path := s.opts.Paths.Activity
	out := activityJSON{Records: []activity.Record{}, Path: path, Enabled: path != ""}
	if path == "" {
		writeJSON(w, http.StatusOK, out)
		return
	}
	res, err := activity.Read(path, activity.ReadOptions{
		After:     after,
		Limit:     int(limit),
		Tail:      int(tail),
		Kinds:     kinds,
		SessionID: q.Get("session"),
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "reading the activity log: "+err.Error())
		return
	}
	if res.Records != nil {
		out.Records = res.Records
	}
	out.Next, out.Reset, out.Skipped = res.Next, res.Reset, res.Skipped
	writeJSON(w, http.StatusOK, out)
}

// queryInt parses an optional non-negative integer query value ("" is 0).
// On failure it writes a 400 naming the parameter and returns false.
func queryInt(w http.ResponseWriter, v, name string) (int64, bool) {
	if v == "" {
		return 0, true
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 0 {
		writeError(w, http.StatusBadRequest, name+" must be a non-negative integer")
		return 0, false
	}
	return n, true
}
