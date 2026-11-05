package ui

import (
	"net/http"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Panda-Taps-LLC/watchdeck/internal/activity"
	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
	"github.com/Panda-Taps-LLC/watchdeck/internal/projectscope"
)

const (
	recentDefaultLimit = 12
	recentMaxLimit     = 50
	recentTail         = 400 // records read from the end of the log
)

// recentJSON is GET /api/recent: the latest calls something stopped,
// asked about or rewrote, newest first.
type recentJSON struct {
	Items []recentItem `json:"items"`
}

// recentItem is one such call. It never carries a command, a reason, a
// tool input or prompt text: What is the record's target, else its
// program name (argv0), else the skill, else the tool.
type recentItem struct {
	TS        string `json:"ts"`
	SessionID string `json:"session_id"`
	ToolUseID string `json:"tool_use_id"`
	AgentType string `json:"agent_type"`
	Tool      string `json:"tool"`
	What      string `json:"what"`
	Outcome   string `json:"outcome"`   // ask | deny | rewrite | refused | shadow
	Authority string `json:"authority"` // hook | classifier | blocked | sandbox
	Skill     string `json:"skill"`
	Project   string `json:"project"` // the record's cwd, home as ~
	// Shadow and Would come from a decision record shadow mode wrote: the
	// verdict a rule would have given (deny | ask) and did not enforce.
	Shadow bool   `json:"shadow,omitempty"`
	Would  string `json:"would,omitempty"`
}

func (s *Server) recentRoutes() []route {
	return []route{{"GET /api/recent", http.HandlerFunc(s.handleRecent)}}
}

// handleRecent answers GET /api/recent?limit=N[&project=P]. limit is
// 1..50 (default 12); anything else is a 400. It reads the last 400
// decision, denied and run records and keeps decisions that asked, denied
// or rewrote, decisions shadow mode observed (outcome shadow; shadow and
// would on every decision item), every denial and runs with sandbox hints. With ?project=
// only records whose cwd is inside that project are kept; without it,
// every project. The log off answers an empty list.
func (s *Server) handleRecent(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := recentDefaultLimit
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > recentMaxLimit {
			writeError(w, http.StatusBadRequest, "limit must be an integer from 1 to 50")
			return
		}
		limit = n
	}
	cwd, err := s.cwdFor(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	scope := ""
	if q.Get(projectscope.Param) != "" && cwd != "" {
		scope = paths.ProjectRoot(cwd, s.opts.Paths.Home)
		if scope == "" {
			scope = cwd
		}
	}
	out := recentJSON{Items: []recentItem{}}
	path := s.opts.Paths.Activity
	if path == "" {
		writeJSON(w, http.StatusOK, out)
		return
	}
	res, err := activity.Read(path, activity.ReadOptions{
		Tail:  recentTail,
		Kinds: []string{activity.KindDecision, activity.KindDenied, activity.KindRun},
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	home := s.opts.Paths.Home
	for i := len(res.Records) - 1; i >= 0 && len(out.Items) < limit; i-- {
		rec := res.Records[i]
		// The hook writes a Bash record that touches no skill with the
		// home as ~ in cwd (redactUntouched), so expand before comparing.
		if scope != "" && !within(projectscope.Expand(rec.Cwd, home), scope) {
			continue
		}
		if it, ok := recentOf(rec, home); ok {
			out.Items = append(out.Items, it)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// recentOf maps one record to an item, or reports false for a record the
// list does not show.
func recentOf(rec activity.Record, home string) (recentItem, bool) {
	it := recentItem{
		TS: rec.TS, SessionID: rec.SessionID, ToolUseID: rec.ToolUseID, AgentType: rec.AgentType,
		Tool: rec.ToolName, Skill: rec.Skill, Project: projectscope.Display(rec.Cwd, home),
	}
	if it.Skill == "" {
		it.Skill = strings.Join(rec.Skills, ", ")
	}
	switch rec.Kind {
	case activity.KindDecision:
		it.Shadow, it.Would = rec.Shadow, rec.Would
		switch {
		case rec.Decision == activity.DecisionShadow:
			// Observed only: nothing was printed, nothing was stopped.
			it.Outcome = "shadow"
		case rec.Decision == "ask" || rec.Decision == "deny":
			it.Outcome = rec.Decision
		case rec.Decision == "allow" && rec.Rewritten != "":
			it.Outcome = "rewrite"
		default:
			return it, false
		}
		it.Authority = "hook"
	case activity.KindDenied:
		it.Outcome = "deny"
		it.Authority = "blocked"
		if strings.Contains(rec.Reason, "auto mode classifier") {
			it.Authority = "classifier"
		}
	case activity.KindRun:
		if len(rec.Hints) == 0 {
			return it, false
		}
		it.Outcome, it.Authority = "refused", "sandbox"
	default:
		return it, false
	}
	if it.Tool == "" {
		// Decisions and runs without a tool name are Bash: skill scripts.
		it.Tool = "Bash"
	}
	switch {
	case rec.Target != "":
		it.What = rec.Target
	case rec.Argv0 != "":
		it.What = rec.Argv0
	case it.Skill != "":
		it.What = it.Skill
	default:
		it.What = it.Tool
	}
	return it, true
}

// within reports whether p is root or below it.
func within(p, root string) bool {
	if p == "" {
		return false
	}
	p, root = filepath.Clean(p), filepath.Clean(root)
	return p == root || strings.HasPrefix(p, root+string(filepath.Separator))
}
