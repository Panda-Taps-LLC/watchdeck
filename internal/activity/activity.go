// Package activity is watchdeck's append-only JSONL log: one record per
// hook decision, per sandboxed run, per Skill-tool invocation and per
// auto-mode denial. Schema v1, one JSON object per line, mode 0600 under the
// user's state dir (paths.Paths.Activity).
//
// The package does no work at init (no regexp, no maps, no templates) because
// the PreToolUse hook links it; the hook only opens the file when it has an
// opinion. Append never reads the file; Read and Correlate never write it.
//
// Privacy: the log stores the shell command of every decision, the Claude
// Code ids on the hook input, the Skill tool's input when a skill is invoked
// (name and args, which can contain prompt text), run outcomes, and only the
// stdout/stderr lines that matched a denial pattern (truncated to 200
// characters). Nothing else from the script's output is ever recorded.
package activity

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/manifest"
)

// Version is the schema version written into every record.
const Version = 1

// Record kinds.
const (
	KindDecision     = "decision"      // the hook had an opinion on a Bash command
	KindRun          = "run"           // watchdeck run finished (any outcome)
	KindSkillInvoked = "skill_invoked" // the Skill tool was called (PreToolUse)
	KindDenied       = "denied"        // auto mode denied a skill-related tool call (PermissionDenied)
	KindRuleLog      = "rule_log"      // a pack or user rule with action log matched; the hook printed nothing (M6.4)
)

// DecisionShadow is a decision record's Decision when shadow mode observed
// a verdict and printed nothing (Phase 6).
const DecisionShadow = "shadow" // decision: shadow mode observed a verdict and printed nothing

// Enforcement classes (M6.4): sandbox is OS-enforced through `watchdeck
// run`; gate is the hook's deny or ask only (never allow), not OS-enforced.
const (
	EnforcementSandbox = "sandbox"
	EnforcementGate    = "gate"
)

// Subject names the policy subject a record concerns (M6.4). Kind is skill,
// command, mcp, tool or agent; Name is the subject's name.
type Subject struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

// RuleHit is one rule that matched a tool call (M6.4): a built-in pack rule
// (Pack is the pack's name), a user rule (Pack "user"), or one of the
// person's Claude Code Bash deny or ask rules matched before a rewrite
// (Pack PackClaudeSettings, ID the rule as written, e.g. "Bash(curl *)";
// Plan 02 Task 7). It never carries the matched text.
type RuleHit struct {
	Pack     string `json:"pack"`
	ID       string `json:"id"`
	Version  int    `json:"version,omitempty"`
	Severity string `json:"severity,omitempty"`
	Action   string `json:"action"` // deny | ask | log
}

// PackClaudeSettings is RuleHit.Pack for a Claude Code settings rule.
const PackClaudeSettings = "claude-settings"

// Run outcomes, derived from the exit code only; "denied" is never stored.
const (
	OutcomeOK          = "ok"           // exit 0
	OutcomeFailed      = "failed"       // non-zero exit from the child
	OutcomeSignaled    = "signaled"     // the child died from a signal
	OutcomePolicyError = "policy_error" // exit 125: unknown skill, malformed manifest, nested run, profile bug
	OutcomeNoSandbox   = "no_sandbox"   // exit 126: the sandbox could not be applied
	OutcomeUsage       = "usage"        // exit 3: bad arguments or unsupported platform
)

// JoinedBy values on a run record.
const (
	JoinedByWrite     = "write"     // the runner copied the ids from a decision at append time
	JoinedByHeuristic = "heuristic" // the reader attached the run to a decision (never on disk)
)

// Hint kinds.
const (
	HintNetwork = "network"
	HintWrite   = "write"
	HintRead    = "read"
	HintExec    = "exec"
	HintUnknown = "unknown"
)

// HarnessClaudeCode is the harness a record belongs to when none is stored:
// every line written before the field existed came from Claude Code.
const HarnessClaudeCode = "claude-code"

// DefaultHarness returns h, or HarnessClaudeCode when h is empty.
func DefaultHarness(h string) string {
	if h == "" {
		return HarnessClaudeCode
	}
	return h
}

// Record is one log line. It is flat with omitempty everywhere; Kind decides
// which fields appear.
type Record struct {
	V          int      `json:"v"`                 // Version
	Kind       string   `json:"kind"`              // decision | run | skill_invoked | denied
	TS         string   `json:"ts"`                // RFC3339Nano, UTC
	Harness    string   `json:"harness,omitempty"` // coding agent that produced the record; Read fills claude-code when absent
	SessionID  string   `json:"session_id,omitempty"`
	ToolUseID  string   `json:"tool_use_id,omitempty"`
	Transcript string   `json:"transcript_path,omitempty"`
	AgentID    string   `json:"agent_id,omitempty"`   // subagent only
	AgentType  string   `json:"agent_type,omitempty"` // subagent only
	PermMode   string   `json:"permission_mode,omitempty"`
	Cwd        string   `json:"cwd,omitempty"`
	Skills     []string `json:"skills,omitempty"` // sorted, deduped
	// Command is the original shell text for a decision or a Bash denial
	// (tool_input.command verbatim) and the -c payload for a run, byte for
	// byte; the two are equal for a hook-rewritten run (TestRewritePayloadRoundTrips),
	// which the join depends on.
	Command string `json:"command,omitempty"`
	// Argv0 is the base name of the program of a Bash call recorded only
	// because a rule pack, a policy rule or a gate answered (M6.4); its
	// command is not stored (commands that touch no skill are never
	// recorded in full).
	Argv0 string `json:"argv0,omitempty"`

	// decision
	Decision   string   `json:"decision,omitempty"`   // ask | allow | deny | shadow
	Reason     string   `json:"reason,omitempty"`     // decision: permissionDecisionReason; denied: the hook input's reason
	Rewritten  string   `json:"rewritten,omitempty"`  // updatedInput.command; absent when asked without a rewrite
	Confidence string   `json:"confidence,omitempty"` // high | low (low: ambiguous, runs unsandboxed if approved)
	Ungranted  []string `json:"ungranted,omitempty"`  // "<skill>: network: all"
	Ignored    []string `json:"ignored,omitempty"`    // "<skill>: project override ignored: …"

	// run (the id fields above are filled by write-time correlation when a decision qualified)
	Exit        *int           `json:"exit,omitempty"`
	Outcome     string         `json:"outcome,omitempty"` // ok | failed | signaled | policy_error | no_sandbox | usage
	DurationMS  int64          `json:"duration_ms,omitempty"`
	ProfileHash string         `json:"profile_hash,omitempty"`
	Backend     string         `json:"backend,omitempty"` // seatbelt | bwrap
	Effective   *manifest.View `json:"effective,omitempty"`
	Warnings    []string       `json:"warnings,omitempty"`
	Hints       []Hint         `json:"hints,omitempty"`
	Error       string         `json:"error,omitempty"` // policy_error / no_sandbox / usage message, first line

	// skill_invoked / denied
	ToolName  string          `json:"tool_name,omitempty"`  // the hook input's tool_name (Skill, Bash, Read, mcp__…)
	Skill     string          `json:"skill,omitempty"`      // best effort: tool_input.skill, else tool_input.name
	ToolInput json.RawMessage `json:"tool_input,omitempty"` // Skill tool only, capped at 2 KiB; never for Bash

	// M6.4, additive (the schema stays v1): the subject, the enforcement
	// class, the rules that matched and the normalised target of a gate (a
	// path with the home directory as ~, or a host name; never file contents,
	// never a URL path, query or userinfo). Skill decisions keep Skills (the
	// run join depends on it) and carry Subject only for a single skill.
	Subject     *Subject  `json:"subject,omitempty"`
	Enforcement string    `json:"enforcement,omitempty"` // sandbox | gate
	Rules       []RuleHit `json:"rules,omitempty"`
	Target      string    `json:"target,omitempty"`

	// Shadow mode (Phase 6), additive: the hook observed a gate verdict it
	// did not enforce. Would is that verdict (deny | ask), WouldReason its
	// value-free reasons. Decision is DecisionShadow when nothing was
	// printed; with a sandbox rewrite it stays the printed decision.
	Shadow      bool   `json:"shadow,omitempty"`
	Would       string `json:"would,omitempty"`
	WouldReason string `json:"would_reason,omitempty"`

	// Temporary allows (Plan 08), additive: the ids of the temporaries
	// that paused a rule hit on this call, sorted and comma-joined. A
	// paused hit is in Rules with action log; it decided nothing.
	Temporary string `json:"temporary,omitempty"`

	// join bookkeeping
	JoinedBy string `json:"joined_by,omitempty"` // run only: "write" (on disk) | "heuristic" (set by the reader) | absent

	// Offset is the byte offset of the line in its file. Set by Read, zeroed
	// by Append: it is for API consumers and ordering, never stored.
	Offset int64 `json:"offset,omitempty"`
}

// Hint is one output line that looked like a sandbox denial. Hints are a
// floor, never a ceiling: they say what the sandbox refused and the script
// reported, not everything that happened.
type Hint struct {
	Kind      string `json:"kind"`            // network | write | read | exec | unknown
	Errno     int    `json:"errno,omitempty"` // 1 EPERM, 2 ENOENT, 13 EACCES, 30 EROFS, 51 (darwin) / 101 (linux) ENETUNREACH
	Line      string `json:"line"`            // the line that matched, trimmed, at most 200 bytes
	Stream    string `json:"stream"`          // stdout | stderr
	Label     string `json:"label,omitempty"` // the canary probe's label (net, write-home, …) when the line was its marker
	Text      string `json:"text"`            // one sentence for humans; the in-session mod prints it verbatim
	Heuristic bool   `json:"heuristic"`       // always true in v1
}

// MaxBytes is the size above which Append renames the file to <path>.1 before
// writing (the previous .1 is replaced). A variable so tests can lower it.
var MaxBytes int64 = 8 << 20

// Now is the timestamp format every record uses.
func Now() string { return time.Now().UTC().Format(time.RFC3339Nano) }

// Append writes one record. path == "" means the log is off and is a no-op.
// It creates the directory (0700) and the file (0600), rotates when the file
// has grown past MaxBytes, and writes the line with a single write call so
// concurrent appenders never interleave. V is set to Version, TS to Now()
// when empty, and Offset is dropped.
func Append(path string, r Record) error {
	if path == "" {
		return nil
	}
	r.V = Version
	if r.TS == "" {
		r.TS = Now()
	}
	r.Offset = 0
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if fi, err := os.Stat(path); err == nil && fi.Size() > MaxBytes {
		// A racing appender may have rotated first; then this Rename fails on
		// a missing source and the new file is simply appended to.
		_ = os.Rename(path, path+".1")
	}
	// O_NOFOLLOW: a symlink planted at the log path is refused, not followed.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.Write(b)
	cerr := f.Close()
	if werr != nil {
		return werr
	}
	return cerr
}

// Stat is a cheap change token for the current file (size and mtime). An
// absent file, or path == "", is (0, zero time, nil).
func Stat(path string) (size int64, mtime time.Time, err error) {
	if path == "" {
		return 0, time.Time{}, nil
	}
	fi, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, time.Time{}, nil
	}
	if err != nil {
		return 0, time.Time{}, err
	}
	return fi.Size(), fi.ModTime(), nil
}

// parseTS reads a record timestamp.
func parseTS(s string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}
