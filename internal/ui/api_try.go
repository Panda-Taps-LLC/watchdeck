package ui

import (
	"net/http"
	"strings"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/hook"
	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
)

// POST /api/rules/try (Plan 08 Task 4, D12): what the hook would answer
// for one call the person types on the Rules page, by the saved rules
// (there is no draft rule here). It runs hook.Explain, the hook's own
// pipeline with no activity line and no lifecycle touch, and answers the
// document `watchdeck rules explain --json` prints (hook.BuildDoc) plus
// project_scope. It writes nothing of its own, so it takes no nonce; the
// guard (Origin, Sec-Fetch-Site, JSON, body cap, bearer) still applies.
// Explain does refresh the policy cache, the skill index and the Claude
// Code rules cache, as a hook call would.
//
// One mutex around Explain (its cold skill-index build is synchronous and
// two in one process at once is untested) and one 3 s deadline covering
// the wait for it and the run (R15): a request that is not answered in
// time gets 503 with the hook's own slow reason. An Explain still running
// after its request timed out keeps the mutex until it returns.

// tryDeadline is the try route's budget, the hook's own (hook.DecideTimeout).
const tryDeadline = 3 * time.Second

type tryRequest struct {
	What  string `json:"what"`  // command | read | edit | write | url | mcp | skill
	Value string `json:"value"` // the command, path, URL, MCP tool name or skill name
	Mode  string `json:"mode"`  // Claude Code's permission_mode; "" = default
}

// tryJSON is the answer: one flat object.
type tryJSON struct {
	hook.Doc
	ProjectScope bool `json:"project_scope"` // the call was explained in the ?project= project (its policy file and settings count)
}

type tryResult struct {
	out    *hook.Output
	ex     hook.Explanation
	failed bool // the run panicked
}

func (s *Server) tryRoutes() []route {
	return []route{{"POST /api/rules/try", http.HandlerFunc(s.handleTry)}}
}

// tryWhat maps a what to the tool it stands for and the tool_input key
// that carries its value: the rules explain vocabulary, spelled as the
// call it names (the CLI's --path is write here, --url a WebFetch). An
// MCP tool is named as Claude Code names it, mcp__<server>__<tool>, with
// an empty input; tool is "" for it.
func tryWhat(what string) (tool, key string, ok bool) {
	switch what {
	case "command":
		return "Bash", "command", true
	case "read":
		return "Read", "file_path", true
	case "edit":
		return "Edit", "file_path", true
	case "write":
		return "Write", "file_path", true
	case "url":
		return "WebFetch", "url", true
	case "mcp":
		return "", "", true
	case "skill":
		return "Skill", "skill", true
	}
	return "", "", false
}

// tryMode reports whether m is a permission_mode Claude Code sends (the
// list rules explain --mode accepts).
func tryMode(m string) bool {
	switch m {
	case "default", "acceptEdits", "auto", "bypassPermissions", "dontAsk", "plan":
		return true
	}
	return false
}

// handleTry answers POST /api/rules/try[?project=]. 400 for a body that
// is not one {what, value, mode?}, an unknown what or mode, an empty
// value or a ?project= the server does not know; 503 when Explain does
// not answer in time; 500 only when the run panicked. A policy file that cannot be loaded is the hook's
// answer (ask, with the reason), a 200.
func (s *Server) handleTry(w http.ResponseWriter, r *http.Request) {
	timer := time.NewTimer(tryDeadline)
	defer timer.Stop()
	var body tryRequest
	if !readJSON(w, r, &body) {
		return
	}
	tool, key, ok := tryWhat(body.What)
	if !ok {
		writeError(w, http.StatusBadRequest, "what must be one of command, read, edit, write, url, mcp, skill")
		return
	}
	if body.Value == "" {
		writeError(w, http.StatusBadRequest, "value is required")
		return
	}
	if body.Mode == "" {
		body.Mode = "default"
	}
	if !tryMode(body.Mode) {
		writeError(w, http.StatusBadRequest, "mode must be one of default, acceptEdits, auto, bypassPermissions, dontAsk, plan")
		return
	}
	cwd := ""
	if r.URL.Query().Get("project") != "" {
		c, err := s.cwdFor(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		cwd = paths.ProjectRoot(c, s.opts.Paths.Home)
		if cwd == "" {
			cwd = c
		}
	}
	if tool == "" {
		tool = body.Value // mcp: the tool name is the value
		if !mcpToolName(tool) {
			writeError(w, http.StatusBadRequest, "an MCP tool is named mcp__<server>__<tool>")
			return
		}
	}
	in := hook.Input{
		HookEventName:  "PreToolUse",
		SessionID:      "try",
		ToolUseID:      "toolu_try",
		Cwd:            cwd,
		PermissionMode: body.Mode,
		ToolName:       tool,
		ToolInput:      map[string]any{},
	}
	if key != "" {
		in.ToolInput[key] = body.Value
	}
	res, ok := s.runTry(in, s.tryEnv(), timer.C)
	if !ok {
		writeError(w, http.StatusServiceUnavailable, hook.SlowReason)
		return
	}
	if res.failed {
		writeError(w, http.StatusInternalServerError, "the call could not be explained")
		return
	}
	writeJSON(w, http.StatusOK, tryJSON{Doc: hook.BuildDoc(in, res.out, res.ex), ProjectScope: cwd != ""})
}

// tryEnv is the hook Env for a try: the server's paths, no activity log,
// no lifecycle store (Explain clears both itself too). CLAUDE_PROJECT_DIR
// is dropped: the project is the one the page names, not the one the
// dashboard happened to be started from.
func (s *Server) tryEnv() hook.Env {
	environ := make(map[string]string, len(s.opts.Environ))
	for k, v := range s.opts.Environ {
		if k != "CLAUDE_PROJECT_DIR" {
			environ[k] = v
		}
	}
	p := s.opts.Paths
	return hook.Env{Home: p.Home, CacheDir: p.CacheBase, UserCfgDir: p.ConfigDir, StateDir: p.StateDir, Environ: environ}
}

// runTry runs s.explain under the try mutex. ok is false when deadline
// fired first, waiting for the mutex or for the run; the run then goes on
// in its goroutine and frees the mutex when it returns.
func (s *Server) runTry(in hook.Input, env hook.Env, deadline <-chan time.Time) (tryResult, bool) {
	select {
	case s.tryGate <- struct{}{}:
	case <-deadline:
		return tryResult{}, false
	}
	done := make(chan tryResult, 1)
	go func() {
		defer func() { <-s.tryGate }()
		defer func() {
			if recover() != nil {
				done <- tryResult{failed: true}
			}
		}()
		out, ex := s.explain(in, env)
		done <- tryResult{out: out, ex: ex}
	}()
	select {
	case res := <-done:
		return res, true
	case <-deadline:
		return tryResult{}, false
	}
}

// mcpToolName reports whether v is spelled as Claude Code names an MCP
// tool: mcp__<server>__<tool>, both parts non-empty.
func mcpToolName(v string) bool {
	rest, ok := strings.CutPrefix(v, "mcp__")
	if !ok {
		return false
	}
	server, tool, ok := strings.Cut(rest, "__")
	return ok && server != "" && tool != ""
}
