package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
	"github.com/Panda-Taps-LLC/watchdeck/internal/sessionindex"
	"github.com/Panda-Taps-LLC/watchdeck/internal/sessionsapi"
	"github.com/Panda-Taps-LLC/watchdeck/internal/transcript"
)

const sessionsUsage = `usage: watchdeck sessions [--project P] [--since D] [--state S] [--denials]
                          [--search Q] [--limit N] [--json]

Lists Claude Code sessions of every project from the session index
(<stateDir>/index), refreshing it first: new and grown transcripts are read,
vanished ones pruned. --project matches the project dir name, the session's
cwd, or a path (escaped the way Claude Code names project dirs). --since takes
RFC3339, a date (2006-01-02) or a duration (48h). --search is a
case-insensitive substring search over the full session text (prompts,
replies, tool inputs and results); one hit per session, newest first.
--state live|idle|ended|unknown keeps sessions in that lifecycle state
(SessionStart/SessionEnd records and live markers; unknown: neither) and
--denials keeps sessions whose activity log shows a denial, as the
dashboard's GET /api/sessions?state=...&denials=1 does.
--json prints each index entry whole, its leak watch findings included
(where a secret-shaped string was seen; never the string).
--no-transcripts lists nothing and writes nothing.
Exit 0 on success, 2 when the index cannot be read or written, 3 usage.

`

const indexSessionsUsage = `usage: watchdeck index sessions [--rebuild | --purge] [--json]

Refreshes the session index under <stateDir>/index and prints what changed.
--rebuild reads every transcript again; --purge deletes the index.

`

// sessionRow is one line of `sessions --json`.
type sessionRow struct {
	sessionindex.Entry
	State     string            `json:"state,omitempty"` // live | idle | ended | unknown (lifecycle); only with --state or --denials
	Decisions int               `json:"decisions,omitempty"`
	Denials   int               `json:"denials,omitempty"`
	Asks      int               `json:"asks,omitempty"`
	Hit       *sessionindex.Hit `json:"hit,omitempty"`
}

func sessionIndexOptions(hp paths.Paths, noTranscripts bool) sessionindex.Options {
	return sessionindex.Options{Dir: hp.SessionIndexDir(), ProjectsDir: hp.ClaudeProjectsDir(), NoTranscripts: noTranscripts}
}

func cmdSessions(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("sessions", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, sessionsUsage)
		fs.PrintDefaults()
	}
	project := fs.String("project", "", "only sessions of this project (dir name, cwd or path)")
	since := fs.String("since", "", "only sessions active since (RFC3339, 2006-01-02 or a duration)")
	search := fs.String("search", "", "full-text search, case-insensitive")
	limit := fs.Int("limit", 0, "at most N sessions (default all; 50 with --search)")
	state := fs.String("state", "", "only sessions in this state: live, idle, ended or unknown")
	denials := fs.Bool("denials", false, "only sessions with a denial in the activity log")
	asJSON := fs.Bool("json", false, "machine-readable output")
	noTranscripts := fs.Bool("no-transcripts", false, "do not read transcripts or touch the index")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		return 3
	}
	switch *state {
	case "", sessionsapi.StateLive, sessionsapi.StateIdle, sessionsapi.StateEnded, sessionsapi.StateUnknown:
	default:
		fmt.Fprintln(stderr, "watchdeck sessions: --state must be live, idle, ended or unknown")
		return 3
	}
	var cutoff time.Time
	if *since != "" {
		t, err := parseSince(*since, time.Now())
		if err != nil {
			fmt.Fprintln(stderr, "watchdeck sessions:", err)
			return 3
		}
		cutoff = t
	}
	hp, _, err := hostPaths()
	if err != nil {
		fmt.Fprintln(stderr, "watchdeck sessions:", err)
		return 2
	}
	if *noTranscripts {
		if *asJSON {
			fmt.Fprintln(stdout, "[]")
		} else {
			fmt.Fprintln(stdout, "transcripts are off (--no-transcripts): nothing listed")
		}
		return 0
	}
	ix, err := sessionindex.Open(sessionIndexOptions(hp, false))
	if err == nil {
		_, err = ix.Update()
	}
	if err != nil {
		fmt.Fprintln(stderr, "watchdeck sessions:", err)
		return 2
	}
	// With --state or --denials, lifecycle state and activity counts come
	// from the dashboard's session catalog, so the CLI and GET /api/sessions
	// agree. Without them the catalog (a second index pass, the lifecycle
	// log and the whole activity log) is not built, and rows carry neither.
	var merged map[string]sessionsapi.Row
	if *state != "" || *denials {
		cat := sessionsapi.New(sessionsapi.Options{Paths: hp})
		cat.Refresh(false)
		merged = map[string]sessionsapi.Row{}
		for _, r := range cat.List(sessionsapi.Filter{}) {
			merged[r.ID] = r
		}
	}
	row := func(e sessionindex.Entry) sessionRow {
		if merged == nil {
			return sessionRow{Entry: e}
		}
		m, ok := merged[e.ID]
		if !ok {
			m.State = sessionsapi.StateUnknown
		}
		return sessionRow{Entry: e, State: m.State, Decisions: m.Decisions, Denials: m.Denials, Asks: m.Asks}
	}
	match := projectMatcher(*project)
	keep := func(e sessionindex.Entry) bool {
		if !match(e) {
			return false
		}
		if *state != "" || *denials {
			r := row(e)
			if *state != "" && r.State != *state {
				return false
			}
			if *denials && r.Denials == 0 {
				return false
			}
		}
		if !cutoff.IsZero() {
			last := e.LastTS
			if last.IsZero() {
				last = e.Mtime
			}
			if last.Before(cutoff) {
				return false
			}
		}
		return true
	}
	var rows []sessionRow
	if *search != "" {
		n := *limit
		if n <= 0 {
			n = sessionindex.DefaultSearchLimit
		}
		// search everything, then filter: the filters are cheap and the
		// search stops early only when no filter is set
		searchLimit := n
		if *project != "" || !cutoff.IsZero() || *state != "" || *denials {
			searchLimit = len(ix.Entries()) + 1
		}
		hits, err := ix.Search(*search, searchLimit)
		if err != nil {
			fmt.Fprintln(stderr, "watchdeck sessions:", err)
			return 2
		}
		for i := range hits {
			e, ok := ix.Get(hits[i].SessionID)
			if !ok || !keep(e) {
				continue
			}
			sr := row(e)
			sr.Hit = &hits[i]
			rows = append(rows, sr)
			if len(rows) == n {
				break
			}
		}
	} else {
		for _, e := range ix.Entries() {
			if keep(e) {
				rows = append(rows, row(e))
				if *limit > 0 && len(rows) == *limit {
					break
				}
			}
		}
	}
	if *asJSON {
		if rows == nil {
			rows = []sessionRow{}
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		enc.Encode(rows)
		return 0
	}
	if len(rows) == 0 {
		fmt.Fprintln(stdout, "no sessions")
		return 0
	}
	for _, r := range rows {
		last := r.LastTS
		if last.IsZero() {
			last = r.Mtime
		}
		flags := ""
		if r.Truncated {
			flags = "  [truncated]"
		}
		if r.Denials > 0 {
			flags += fmt.Sprintf("  [%d denied]", r.Denials)
		}
		state := ""
		if r.State != "" {
			state = fmt.Sprintf("%-7s  ", r.State)
		}
		fmt.Fprintf(stdout, "%s  %s%s  %s%s\n", last.Local().Format("2006-01-02 15:04"), state, r.ID, orDash(r.Cwd), flags)
		fmt.Fprintf(stdout, "    %s\n", orDash(r.Title))
		fmt.Fprintf(stdout, "    branch %s  models %s  turns %d  tools %d  subagents %d  skills %s\n",
			orDash(r.GitBranch), orDash(strings.Join(r.Models, ",")), r.Turns, r.ToolCalls, r.Subagents, orDash(strings.Join(r.Skills, ",")))
		if r.Hit != nil {
			fmt.Fprintf(stdout, "    match: %s\n", r.Hit.Snippet)
		}
	}
	return 0
}

// projectMatcher matches --project against the project dir name, the cwd,
// or a path escaped the way Claude Code names project dirs.
func projectMatcher(p string) func(sessionindex.Entry) bool {
	if p == "" {
		return func(sessionindex.Entry) bool { return true }
	}
	clean := p
	if abs, err := filepath.Abs(p); err == nil && (strings.HasPrefix(p, "/") || strings.HasPrefix(p, ".")) {
		clean = abs
	}
	esc := transcript.EscapeProjectDir(clean)
	return func(e sessionindex.Entry) bool {
		return e.ProjectDir == p || e.ProjectDir == esc || e.Cwd == clean ||
			(len(esc) > transcript.ProjectDirMaxLen && strings.HasPrefix(e.ProjectDir, esc[:transcript.ProjectDirMaxLen]+"-"))
	}
}

// parseSince accepts RFC3339, a date (local midnight) or a Go duration
// counted back from now.
func parseSince(s string, now time.Time) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	if t, err := time.ParseInLocation("2006-01-02", s, time.Local); err == nil {
		return t, nil
	}
	if d, err := time.ParseDuration(s); err == nil && d > 0 {
		return now.Add(-d), nil
	}
	return time.Time{}, fmt.Errorf("--since %q: want RFC3339, 2006-01-02 or a duration like 48h", s)
}

// cmdIndexSessions is `watchdeck index sessions`.
func cmdIndexSessions(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("index sessions", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, indexSessionsUsage)
		fs.PrintDefaults()
	}
	rebuild := fs.Bool("rebuild", false, "read every transcript again")
	purge := fs.Bool("purge", false, "delete the session index")
	asJSON := fs.Bool("json", false, "print the update stats as JSON")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		return 3
	}
	if *rebuild && *purge {
		fmt.Fprintln(stderr, "watchdeck index sessions: --rebuild and --purge are exclusive")
		return 3
	}
	hp, _, err := hostPaths()
	if err != nil {
		fmt.Fprintln(stderr, "watchdeck index sessions:", err)
		return 2
	}
	o := sessionIndexOptions(hp, false)
	if *purge {
		if err := sessionindex.Purge(o); err != nil {
			fmt.Fprintln(stderr, "watchdeck index sessions:", err)
			return 2
		}
		fmt.Fprintf(stdout, "removed %s\n", o.Dir)
		return 0
	}
	ix, err := sessionindex.Open(o)
	var st sessionindex.Stats
	if err == nil {
		if *rebuild {
			st, err = ix.Rebuild()
		} else {
			st, err = ix.Update()
		}
	}
	if err != nil {
		fmt.Fprintln(stderr, "watchdeck index sessions:", err)
		return 2
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		enc.Encode(st)
		return 0
	}
	fmt.Fprintf(stdout, "%s\n", o.Dir)
	fmt.Fprintf(stdout, "  sessions:   %d\n", st.Sessions)
	fmt.Fprintf(stdout, "  read:       %d new or rebuilt, %d grown, %d unchanged\n", st.Rebuilt, st.Appended, st.Unchanged)
	fmt.Fprintf(stdout, "  pruned:     %d\n", st.Pruned)
	if st.Duplicates > 0 || st.Errors > 0 {
		fmt.Fprintf(stdout, "  skipped:    %d duplicate ids, %d unreadable\n", st.Duplicates, st.Errors)
	}
	return 0
}
