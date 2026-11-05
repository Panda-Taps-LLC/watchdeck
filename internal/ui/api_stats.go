package ui

import (
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/activity"
	"github.com/Panda-Taps-LLC/watchdeck/internal/policy"
)

// GET /api/rules/stats (Plan 08 Task 4, D11): how often each rule fired,
// folded from the activity log. The Rules page joins the counts to its
// rows: pack rules by "<pack>/<id>", the person's own rules by id, and
// Claude Code Bash deny and ask rules by the rule as written (those hits
// exist only when the hook checked the rule before a rewrite). Other rows
// get no count.
//
// The fold reads by offset (activity.ReadFrom), the way the session
// catalog does, and never keys a cache on the log's size or mtime: the
// mtime moves on every hook call, so such a cache would miss on every
// page load during a live session. The log is global, so ?project= only
// checks the project as other project-scoped routes do; counts are never
// filtered by directory.

// ruleStat is one rule's counts. A record counts once per rule id however
// often the id appears in it. A shadow-mode record adds to Shadow as well
// as Fired. LastAction is the hit's action in the newest record ("log"
// for a rule_log record).
type ruleStat struct {
	Fired      int    `json:"fired"`
	LastTS     string `json:"last_ts"`
	LastAction string `json:"last_action"`
	Shadow     int    `json:"shadow"`

	lastAt time.Time
}

// statsWindow says what the counts cover: the oldest and newest record
// time in the log ("" when there is none), how many records were read,
// and whether the log has rotated (<log>.1 exists, so anything older than
// Since is gone).
type statsWindow struct {
	Since   string `json:"since"`
	Until   string `json:"until"`
	Records int    `json:"records"`
	Rotated bool   `json:"rotated"`
}

type statsJSON struct {
	ActivityEnabled bool                `json:"activity_enabled"`
	Window          statsWindow         `json:"window"`
	Pack            map[string]ruleStat `json:"pack"`
	User            map[string]ruleStat `json:"user"`
	Native          map[string]ruleStat `json:"native"`
}

// statsFold is the Server's running fold. Its zero value is empty and
// ready (the maps are made on the first clear).
type statsFold struct {
	mu   sync.Mutex
	next int64       // offset in the current file after the last complete line read
	file os.FileInfo // the current file as it was before the last read; nil = absent or never read

	records              int
	since, until         time.Time
	sinceTS, untilTS     string
	pack, user, native   map[string]*ruleStat
	initialised, rotated bool
}

func (s *Server) statsRoutes() []route {
	return []route{{"GET /api/rules/stats", http.HandlerFunc(s.handleRuleStats)}}
}

// handleRuleStats answers GET /api/rules/stats[?project=]. A ?project=
// the server does not know is a 400; with the log off the answer is 200,
// activity_enabled false and empty maps. An unreadable log answers what
// the fold holds.
func (s *Server) handleRuleStats(w http.ResponseWriter, r *http.Request) {
	if _, err := s.cwdFor(r); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	path := s.opts.Paths.Activity
	f := &s.stats
	f.mu.Lock()
	defer f.mu.Unlock()
	if path == "" {
		f.clear()
	} else {
		f.update(path)
	}
	writeJSON(w, http.StatusOK, f.view(path != ""))
}

// update folds what was appended to path since the last call. It starts
// over from offset 0, which reads <path>.1 and then path, when the file
// at path is no longer the one the fold was reading (the hook renamed it
// to <path>.1 and began another; checked by identity, so a new file
// already longer than the old offset is not mistaken for the old one),
// and when activity.ReadFrom reports Reset (the file shrank in place).
// Either way every record in the two files counts once.
func (f *statsFold) update(path string) {
	cur, err := os.Stat(path)
	if err != nil {
		cur = nil
	}
	if f.file != nil && (cur == nil || !os.SameFile(f.file, cur)) {
		f.next = 0
	}
	if f.next == 0 {
		f.clear() // offset 0 reads <path>.1 again
	}
	res, err := activity.ReadFrom(path, f.next)
	if err != nil {
		return
	}
	if res.Reset {
		f.clear()
	}
	for i := range res.Records {
		f.add(&res.Records[i])
	}
	f.next, f.file = res.Next, cur
	_, err = os.Stat(path + ".1")
	f.rotated = err == nil
}

func (f *statsFold) clear() {
	f.records = 0
	f.since, f.until = time.Time{}, time.Time{}
	f.sinceTS, f.untilTS = "", ""
	f.pack = map[string]*ruleStat{}
	f.user = map[string]*ruleStat{}
	f.native = map[string]*ruleStat{}
	f.rotated = false
	f.initialised = true
}

// add folds one record.
func (f *statsFold) add(r *activity.Record) {
	if !f.initialised {
		f.clear()
	}
	f.records++
	t, err := time.Parse(time.RFC3339Nano, r.TS)
	if err != nil {
		t = time.Time{}
	}
	if !t.IsZero() {
		if f.since.IsZero() || t.Before(f.since) {
			f.since, f.sinceTS = t, r.TS
		}
		if f.until.IsZero() || t.After(f.until) {
			f.until, f.untilTS = t, r.TS
		}
	}
	for i, h := range r.Rules {
		if h.Pack == "" || h.ID == "" || seenBefore(r.Rules[:i], h) {
			continue
		}
		var m map[string]*ruleStat
		key := h.ID
		switch h.Pack {
		case policy.UserPack:
			m = f.user
		case activity.PackClaudeSettings:
			m = f.native
		default:
			m, key = f.pack, h.Pack+"/"+h.ID
		}
		st := m[key]
		if st == nil {
			st = &ruleStat{}
			m[key] = st
		}
		st.Fired++
		if r.Shadow {
			st.Shadow++
		}
		// The newest record names the last action; an undated record
		// does so only while nothing dated has.
		if st.LastTS == "" || (!t.IsZero() && !t.Before(st.lastAt)) {
			st.lastAt, st.LastTS, st.LastAction = t, r.TS, h.Action
			if r.Kind == activity.KindRuleLog {
				st.LastAction = "log"
			}
		}
	}
}

// seenBefore reports whether hits already holds h's pack and id.
func seenBefore(hits []activity.RuleHit, h activity.RuleHit) bool {
	for _, x := range hits {
		if x.Pack == h.Pack && x.ID == h.ID {
			return true
		}
	}
	return false
}

// view is the response; the maps are never null.
func (f *statsFold) view(enabled bool) statsJSON {
	out := statsJSON{
		ActivityEnabled: enabled,
		Window:          statsWindow{Since: f.sinceTS, Until: f.untilTS, Records: f.records, Rotated: f.rotated},
		Pack:            make(map[string]ruleStat, len(f.pack)),
		User:            make(map[string]ruleStat, len(f.user)),
		Native:          make(map[string]ruleStat, len(f.native)),
	}
	for k, v := range f.pack {
		out.Pack[k] = *v
	}
	for k, v := range f.user {
		out.User[k] = *v
	}
	for k, v := range f.native {
		out.Native[k] = *v
	}
	return out
}
