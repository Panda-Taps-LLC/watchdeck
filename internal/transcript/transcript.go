// Package transcript reads Claude Code session transcripts read-only and
// returns a compact, policy-oriented view of one session: which agents ran,
// which tools they called, what the PreToolUse hook decided, and nothing
// else. It is the transcript half of the agent map; the activity log is the
// other half and is joined by tool_use id outside this package.
//
// On-disk layout (verified 2026-10-12 against Claude Code 2.1.296, see
// testdata/e2e-canary/README.md):
//
//	<projects>/<escaped cwd>/<session id>.jsonl                      the main agent
//	<projects>/<escaped cwd>/<session id>/subagents/agent-<id>.jsonl  one file per subagent
//	<projects>/<escaped cwd>/<session id>/subagents/agent-<id>.meta.json  optional
//
// where <escaped cwd> is the cwd with every character other than an ASCII
// letter or digit replaced by "-" (EscapeProjectDir; names over 200 characters
// are cut and given a hash suffix, see ProjectDirMaxLen) and <projects> is
// ~/.claude/projects or $CLAUDE_CONFIG_DIR/projects.
//
// Every path this package opens is resolved through filepath.EvalSymlinks and
// must sit directly under the configured projects dir; session and agent ids
// must satisfy ValidID before the filesystem is touched. Nothing is written,
// nothing is cached on disk, and the returned Session holds no assistant
// text, no thinking, no file contents and no tool results beyond a 240-char
// snippet of Bash output.
//
// Discover lists one project's sessions plus those the activity log names.
// DiscoverAll (M5.4, 2026-10-13) lists every project's sessions for the
// session index; both use Stat and directory listings only and apply the
// same symlink and id checks. LineReader is the shared line streamer.
//
// The package does no init-time work (no regexp compilation, no globals with
// side effects): the binary that links it is also the hook that runs on every
// Bash call.
package transcript

import (
	"errors"
	"strings"
	"time"
	"unicode/utf8"
)

// MainAgentID is the Agent.ID of the session's main agent.
const MainAgentID = "main"

var (
	// ErrNoProjectsDir is returned when Options.ProjectsDir or
	// PathsDeps.ClaudeProjectsDir is empty. The check is never skipped.
	ErrNoProjectsDir = errors.New("transcript: projects dir not configured")
	// ErrOutsideProjects is returned when a transcript path does not resolve
	// to <projects>/<escaped cwd>/<id>.jsonl after symlink resolution.
	ErrOutsideProjects = errors.New("transcript: path is not a session file under the projects dir")
	// ErrBadID is returned when a session or agent id fails ValidID.
	ErrBadID = errors.New("transcript: invalid session or agent id")
)

// SessionRef is a session found by Discover. It is built from directory
// listings and Stat only; the file has not been opened.
type SessionRef struct {
	ID         string    // session id, the file stem
	Path       string    // main transcript .jsonl, as the caller's projects dir names it
	CwdGuess   string    // PathsDeps.Cwd when found under its escaped dir, else UnescapeProjectDirGuess of the dir name (lossy)
	ProjectDir string    // <projects>/<escaped cwd>
	Size       int64     // main file size
	ModTime    time.Time // main file mtime
	Subagents  int       // count of subagents/agent-*.jsonl, 0 when the dir is missing
	Source     string    // "cwd" (found under the escaped cwd), "activity" (named by a transcript_path), or "cwd+activity"
}

// Session is the compact view of one transcript. Everything lives in memory
// for the life of one request; nothing is derived on disk.
type Session struct {
	ID           string
	Harness      string    // coding agent: always "claude-code" for this loader
	Path         string    // the path Load was given, cleaned and made absolute
	Cwd          string    // first cwd seen in the main file
	Started      time.Time // first user or assistant row of the main agent (hook rows at startup are earlier and ignored)
	LastEvent    time.Time // latest timestamp seen in any row of any file
	Truncated    bool      // a tail read dropped the earliest rows of at least one file
	SkippedLines int       // lines dropped: not JSON, over Options.MaxLine, or a final line without a newline (blank lines are ignored, not counted)
	SkippedFiles int       // subagent files not read: id failed ValidID, resolved outside the projects dir, or could not be opened
	Agents       []Agent   // Agents[0] is main; subagents follow ordered by first timestamp, then id
	Events       []Event   // all agents merged, ordered by (TS, Seq); rows without a timestamp sort last
	Prompts      []Prompt  // user turns of the main agent, in file order
	Version      string    // Claude Code version from the first row carrying one, "" when absent
}

// Agent is the main agent or one subagent.
type Agent struct {
	// ID is "main" for the main agent. For a subagent it is the bare id that
	// Claude Code uses everywhere else: the file stem without "agent-", the
	// rows' agentId field, the parent's toolUseResult.agentId, and the hook's
	// agent_id (verified 2026-10-12). For a legacy sidechain embedded in the
	// main file it is the uuid of the sidechain's first row.
	ID        string
	Kind      string // "main" | "subagent"
	Type      string // subagent type (Explore, general-purpose, ...): from the meta file, the parent's Agent call, the parent's result, or the rows' attributionAgent; "" for main
	Name      string // the Agent call's description or the meta file's, at most 60 chars; "" for main
	Model     string // last message.model seen on this agent's assistant rows, "unknown" when none
	SpawnedBy string // tool_use id of the parent's Agent call when the link is certain (SpawnLink "meta" or "result"); "" for main and for order-based guesses
	// SpawnLink says how the subagent was tied to a parent Agent call:
	// "meta" (agent-<id>.meta.json toolUseId), "result" (the parent's
	// tool_result row carried toolUseResult.agentId), "order" (k-th Agent
	// call matched the k-th subagent file by first timestamp; a guess, so
	// SpawnedBy stays empty and the call's Spawn.AgentID carries it), or ""
	// (no link: main, or a spawn that was not seen, for example after a tail read).
	SpawnLink string
	Sidechain bool      // true for a legacy isSidechain:true chain inside the main file
	SpawnTS   time.Time // first row timestamp
	EndTS     time.Time // last row timestamp
	Calls     int       // tool_use blocks by this agent (spawn and skill_invoked events included)
	File      string    // the file the agent was read from (the main file for main and sidechains)
}

// Event is one row the map cares about. Kind is one of:
//
//	"prompt"         a user turn of the main agent
//	"tool_use"       a tool_use block (ToolCall set)
//	"spawn"          a tool_use block of the Agent tool (ToolCall and ToolCall.Spawn set)
//	"skill_invoked"  a tool_use block of the Skill tool (ToolCall.Skill set; shape assumed, see testdata/synthetic-subagents)
//	"tool_result"    a tool_result block (ResultFor set)
//	"return"         the tool_result of an Agent call
//
// spawn and skill_invoked are tool_use rows specialised by tool name, and
// return is a tool_result row specialised the same way; count calls with
// IsCall and results with IsResult.
type Event struct {
	Seq       int       // load order, the tie-break when timestamps are equal or missing
	TS        time.Time // zero when the row had no timestamp
	Agent     string    // Agent.ID
	Kind      string
	ToolCall  *ToolCall // for tool_use, spawn, skill_invoked
	ResultFor string    // tool_use id, for tool_result and return
	IsError   bool      // tool_result is_error
	Snippet   string    // first 240 chars of a Bash tool_result's text, "" for every other tool
	// ErrorText is the first 160 bytes, cut on a rune boundary, of an is_error tool_result's text,
	// for every tool; "" when the result is not an error.
	ErrorText string
	// Authority is the permission verdict Claude Code recorded on the result row.
	Authority Authority
}

// Authority is the permission verdict Claude Code writes on the user row that
// holds a tool_result: permissionDecision {decision, source, reasonType} and,
// on denials, toolDenialKind. A Read blocked by a deny rule carries neither.
type Authority struct {
	Decision   string // permissionDecision.decision: accept | reject | ""
	Source     string // permissionDecision.source: config | user | hook | ""
	ReasonType string // permissionDecision.reasonType: classifier | rule | subcommandResults | hook | prompt | ""
	DenialKind string // toolDenialKind: permission-rule | automode-blocked | ""
}

// Known reports whether any field is set.
func (a Authority) Known() bool { return a != Authority{} }

// Rejected reports whether Claude Code recorded a rejection.
func (a Authority) Rejected() bool { return a.Decision == "reject" }

// IsCall reports whether the event is a tool_use block of any kind.
func (e Event) IsCall() bool {
	return e.Kind == "tool_use" || e.Kind == "spawn" || e.Kind == "skill_invoked"
}

// IsResult reports whether the event is a tool_result block of any kind.
func (e Event) IsResult() bool { return e.Kind == "tool_result" || e.Kind == "return" }

// ToolCall is the compact record of one tool_use block.
type ToolCall struct {
	ID      string // tool_use id (toolu_01...), equal to the hook's tool_use_id (verified 2026-10-12)
	Name    string // Bash, Read, Grep, Edit, WebFetch, Agent, Skill, mcp__<server>__<tool>, ...
	Command string // Bash input.command, first 512 chars; the model's original command, never the hook's rewrite
	Path    string // Read/Edit/Write/NotebookEdit input.file_path (notebook_path), Grep/Glob input.path
	Pattern string // Grep/Glob input.pattern
	URL     string // WebFetch input.url reduced to its host
	Skill   string // Skill tool input.skill
	Spawn   *Spawn // set for Agent (and the older Task) calls
	// MCPServer and MCPTool split mcp__<server>__<tool> at the first "__"
	// after the prefix; the server part may itself contain single underscores.
	MCPServer, MCPTool string
	// HookDecision, HookRewrite and HookReason come from the hook_success
	// attachment row of the PreToolUse hook that answered this call:
	// permissionDecision ("allow" | "ask" | "deny"), updatedInput.command
	// (first 512 chars; "" when the hook asked without rewriting) and
	// permissionDecisionReason (first 240 chars). All empty when no hook
	// printed a JSON decision for the call.
	HookDecision, HookRewrite, HookReason string
	// Authority is copied from the call's tool_result row; zero when the call
	// has no result in the loaded window or the row carried no verdict.
	Authority Authority
}

// Spawn describes an Agent tool call.
type Spawn struct {
	SubagentType string
	Description  string // at most 120 chars
	Model        string // input.model when present (absent in the 2026-10-12 capture)
	AgentID      string // the subagent this call started, once linked; see Confidence
	Confidence   string // "meta" | "result" | "order" | "" (same vocabulary as Agent.SpawnLink)
}

// Prompt is a user turn of the main agent.
type Prompt struct {
	TS      time.Time
	Summary string // first 120 chars of the text
}

// AgentByID returns the agent with the given id, accepting both the bare id
// and the "agent-<id>" file stem; nil when absent.
func (s *Session) AgentByID(id string) *Agent {
	id = strings.TrimPrefix(id, "agent-")
	for i := range s.Agents {
		if s.Agents[i].ID == id {
			return &s.Agents[i]
		}
	}
	return nil
}

// Call returns the tool_use event with the given tool_use id, nil when absent.
func (s *Session) Call(toolUseID string) *Event {
	for i := range s.Events {
		if s.Events[i].IsCall() && s.Events[i].ToolCall != nil && s.Events[i].ToolCall.ID == toolUseID {
			return &s.Events[i]
		}
	}
	return nil
}

// Result returns the tool_result event for the given tool_use id, nil when absent.
func (s *Session) Result(toolUseID string) *Event {
	for i := range s.Events {
		if s.Events[i].IsResult() && s.Events[i].ResultFor == toolUseID {
			return &s.Events[i]
		}
	}
	return nil
}

// ProjectDirMaxLen is the longest project directory name Claude Code writes.
// A longer escaped cwd is cut to this many characters and followed by "-"
// and a short hash (6 characters on 2026-10-12) that this package cannot
// compute; Discover finds such a directory by its prefix instead.
const ProjectDirMaxLen = 200

// EscapeProjectDir returns the untruncated name Claude Code gives a project's
// directory under <projects>: ASCII letters and digits are kept and every
// other character becomes "-", one per UTF-16 code unit (so a character
// outside the Basic Multilingual Plane becomes "--"). Observed on Claude
// Code 2.1.296 on 2026-10-12 with zero-cost unauthenticated runs under a
// temporary CLAUDE_CONFIG_DIR: "/", ".", "_", " ", "+", "~" and "é" each gave
// one "-", an emoji gave two, digits and dashes were kept. When the result is
// longer than ProjectDirMaxLen the on-disk name is truncated and hashed.
func EscapeProjectDir(cwd string) string {
	var b strings.Builder
	b.Grow(len(cwd))
	for _, r := range cwd {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r > 0xFFFF:
			b.WriteString("--")
		default:
			b.WriteByte('-')
		}
	}
	return b.String()
}

// UnescapeProjectDirGuess inverts EscapeProjectDir as far as possible: every
// "-" becomes "/". The result is a guess: a "-", ".", "_" or space in the
// original path is indistinguishable from a separator.
func UnescapeProjectDirGuess(name string) string { return strings.ReplaceAll(name, "-", "/") }

// ValidID reports whether id is an acceptable session or agent id:
// 1 to 96 characters from [A-Za-z0-9_.-], and not "." or "..".
func ValidID(id string) bool {
	if id == "" || len(id) > 96 || id == "." || id == ".." {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_', c == '.', c == '-':
		default:
			return false
		}
	}
	return true
}

// truncate cuts s to at most n bytes on a rune boundary.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// hostOf reduces a URL to its host: strip the scheme, cut at the first
// "/", "?" or "#", drop userinfo. Not a full parser, by design.
func hostOf(u string) string {
	if i := strings.Index(u, "://"); i >= 0 {
		u = u[i+3:]
	}
	if i := strings.IndexAny(u, "/?#"); i >= 0 {
		u = u[:i]
	}
	if i := strings.LastIndex(u, "@"); i >= 0 {
		u = u[i+1:]
	}
	return u
}
