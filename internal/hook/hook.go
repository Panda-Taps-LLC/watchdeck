// Package hook implements the Claude Code PreToolUse hook for Bash: it
// recognises commands that run a skill's scripts and rewrites them to
// `watchdeck run`, deciding "ask" or "allow" from the skill's grant. It
// also records Skill-tool invocations and auto-mode denials of skill-related
// calls in the activity log (events.go); neither of those writes output.
package hook

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/activity"
	"github.com/Panda-Taps-LLC/watchdeck/internal/index"
	"github.com/Panda-Taps-LLC/watchdeck/internal/lifecycle"
	"github.com/Panda-Taps-LLC/watchdeck/internal/manifest"
	"github.com/Panda-Taps-LLC/watchdeck/internal/match"
	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
	"github.com/Panda-Taps-LLC/watchdeck/internal/policy"
	"github.com/Panda-Taps-LLC/watchdeck/internal/shellparse"
	"github.com/Panda-Taps-LLC/watchdeck/internal/skills"
)

// Input is the subset of the hook JSON the hook reads (PreToolUse,
// PermissionDenied, SessionStart, SessionEnd, UserPromptSubmit). AgentID and
// AgentType are present only inside a subagent; Reason on PermissionDenied
// and SessionEnd; Source on SessionStart. UserPromptSubmit's "prompt" is
// deliberately not a field: the prompt text is never read into a record.
type Input struct {
	SessionID      string          `json:"session_id"`
	ToolUseID      string          `json:"tool_use_id"`
	TranscriptPath string          `json:"transcript_path"`
	AgentID        string          `json:"agent_id"`
	AgentType      string          `json:"agent_type"`
	Cwd            string          `json:"cwd"`
	PermissionMode string          `json:"permission_mode"`
	HookEventName  string          `json:"hook_event_name"`
	ToolName       string          `json:"tool_name"`
	ToolInput      map[string]any  `json:"tool_input"`
	Reason         string          `json:"reason"`
	Source         string          `json:"source"`
	ToolResponse   json.RawMessage `json:"tool_response"` // PostToolUse only; read for rule text, never stored
	Harness        string          `json:"-"`             // set by Run from Env.Harness
}

// Output is the hook's JSON response.
type Output struct {
	HookSpecificOutput Specific `json:"hookSpecificOutput"`
}

// Specific is the PreToolUse-specific part of the response.
type Specific struct {
	HookEventName            string         `json:"hookEventName"`
	PermissionDecision       string         `json:"permissionDecision,omitempty"`
	PermissionDecisionReason string         `json:"permissionDecisionReason,omitempty"`
	UpdatedInput             map[string]any `json:"updatedInput,omitempty"`
	AdditionalContext        string         `json:"additionalContext,omitempty"`
}

// Env is what Decide needs from the host.
type Env struct {
	Harness      string // coding agent calling the hook; "" = claude-code
	Home         string
	CacheDir     string
	UserCfgDir   string
	ActivityPath string          // activity log file; "" = log off
	Lifecycle    lifecycle.Store // session lifecycle; the zero Store is off
	Environ      map[string]string
	// StateDir holds the policy cache (policy.CacheFile); "" parses the
	// policy files on every call.
	StateDir string

	loading *atomic.Bool // set by Run: this call is loading the skill index (slowindex.go)
	// claudeManaged, when set (tests), is Claude Code's managed settings
	// directory instead of this OS's (/Library/Application Support/ClaudeCode,
	// /etc/claude-code); "" means none.
	claudeManaged *string
}

// meta is what a decision record needs beyond the Output.
type meta struct {
	Skills      []string // as matched, in first-seen order
	Confidence  string   // high | low | "" (recursion guard, index error)
	Ungranted   []string // "<skill>: network: all"
	Ignored     []string // "<skill>: project override ignored: …"
	Subject     *activity.Subject
	Enforcement string // sandbox | gate
	Rules       []activity.RuleHit
	Target      string
	LogOnly     bool // no output, but log hits: a rule_log record
	// Shadow mode (Phase 6): a gate verdict that was recorded, not printed.
	Shadow      bool
	Would       string // deny | ask
	WouldReason string // the gate's value-free reasons, " | "-joined
	// Temporary is the sorted, comma-joined ids of the temporaries that
	// paused a rule hit on this call (Plan 08).
	Temporary string
}

// Decision names, as Claude Code expects them.
const (
	Ask   = "ask"
	Allow = "allow"
	Deny  = "deny"
)

// Decide returns nil when the hook has no opinion (exit 0, no output).
func Decide(in Input, env Env) *Output {
	out, _ := decide(in, env)
	return out
}

// decide is the M6.3 pipeline (pipeline.go): policy, tool fast filter,
// gate stage, then the sandbox stage for Bash.
func decide(in Input, env Env) (*Output, meta) {
	if in.HookEventName == EventPostToolUse {
		return postDecide(in, env)
	}
	tool := in.ToolName
	if tool == "" {
		return nil, meta{}
	}
	cwd := in.Cwd
	if cwd == "" {
		cwd = env.Home
	}
	if tool == "Bash" {
		command, _ := in.ToolInput["command"].(string)
		if strings.TrimSpace(command) == "" {
			return nil, meta{}
		}
	}
	lp := loadPolicy(env, cwd)
	if tool != "Bash" && !lp.relevant(tool) {
		return nil, meta{} // fast filter: no pack rule, gate or user rule for this tool
	}
	g := gateStage(in, env, cwd, lp)
	var out *Output
	var m meta
	if tool == "Bash" {
		out, m = sandboxStage(in, env, cwd, lp)
	}
	return combine(g, out, m, lp.shadow())
}

// sandboxStage is the Bash path: skills (since M2) and command subjects
// (M6.3) are rewritten to `watchdeck run`. A rewrite is first checked
// against the person's own Claude Code Bash deny and ask rules, matched
// against the original command (Plan 02 Task 7): Claude Code would only
// see the rewritten one. A deny hit denies without the rewrite; an ask
// asks with it, so an approved command still runs sandboxed, except in
// bypassPermissions and dontAsk (nativeAsk). Nothing is
// loaded for that unless a rewrite is about to be returned.
func sandboxStage(in Input, env Env, cwd string, lp loadedPolicy) (*Output, meta) {
	out, m := sandboxRewrite(in, env, cwd, lp)
	if out == nil || out.HookSpecificOutput.UpdatedInput == nil {
		return out, m
	}
	command, _ := in.ToolInput["command"].(string)
	no, nm, hit := nativeCheck(env, cwd, command)
	if !hit {
		return out, m
	}
	m.Rules = append(m.Rules, nm.Rules...)
	if no.HookSpecificOutput.PermissionDecision == Deny {
		m.Enforcement = nm.Enforcement // a deny is the hook's gate; nothing runs
		return no, m
	}
	merged, dropped := nativeAsk(out, no, in.PermissionMode)
	if dropped {
		m.Enforcement = nm.Enforcement // nothing runs sandboxed: the ask is the hook's gate
	}
	return merged, m
}

// nativeAsk merges a native ask (an ask rule, an unreadable settings file,
// an unparseable command) into the rewrite: approved, the command runs
// sandboxed. In bypassPermissions and dontAsk Claude Code may settle the
// ask without a person (final review ruling, 2026-10-19), and its own
// deny rules would then see only the rewrite; there the ask goes out
// without updatedInput, so Claude Code checks the original command, as
// the watchdog's ask already does. dropped reports that case.
func nativeAsk(out, no *Output, mode string) (merged *Output, dropped bool) {
	if mode == "bypassPermissions" || mode == "dontAsk" {
		return ask(no.HookSpecificOutput.PermissionDecisionReason+" | not sandboxed: in "+mode+" mode the original command goes to Claude Code unchanged, so its own rules see it", nil, ""), true
	}
	s := out.HookSpecificOutput
	s.PermissionDecision = Ask
	s.PermissionDecisionReason = no.HookSpecificOutput.PermissionDecisionReason + " | " + strings.TrimPrefix(s.PermissionDecisionReason, "watchdeck: ")
	return &Output{HookSpecificOutput: s}, false
}

// sandboxRewrite decides the Bash path before the native-rules check.
func sandboxRewrite(in Input, env Env, cwd string, lp loadedPolicy) (*Output, meta) {
	command, _ := in.ToolInput["command"].(string)

	// Recursion guard: a lone `watchdeck run ...` passes; anything wrapped
	// around one is suspicious (the exclusion in Claude Code's sandbox may be
	// a prefix match, so a trailing command would run unconfined).
	// A lone run the model typed is checked against what the hook would have
	// produced (runguard.go); a leading assignment or a redirection is not a
	// lone run.
	if mentionsRun(command) {
		if shellparse.IsSingleWatchdeckRun(command) {
			return modelTypedRun(in, command, cwd, env, lp)
		}
		return ask(loneRunReason(command, cwd, env.Environ), nil, ""), meta{}
	}
	if sub, ok := mutatingSub(command); ok {
		what := "`watchdeck " + sub + "`"
		if sub == "" {
			what = "a watchdeck command"
		}
		return ask("watchdeck: "+what+" changes watchdeck or Claude Code settings; it always asks, so a change is never made without the person seeing it", nil, ""), meta{}
	}

	roots := skills.Roots{Home: env.Home, Cwd: cwd, Env: map[string]string{}}
	if v := env.Environ["CLAUDE_SKILL_DIR"]; v != "" {
		roots.Env["CLAUDE_SKILL_DIR"] = v
	}
	ix, err := loadIndex(env, roots)
	if err != nil {
		// Without an index we cannot tell; only intervene when the command looks skill-related.
		for _, n := range index.GenericNeedles {
			if strings.Contains(command, n) {
				return ask("watchdeck: cannot load the skill index ("+err.Error()+"); run `watchdeck index --rebuild`", nil, ""), meta{}
			}
		}
		return commandSubject(in, command, lp)
	}
	if match.FastReject(command, cwd, ix) {
		return commandSubject(in, command, lp)
	}
	res := match.Resolve(command, cwd, env.Environ, ix)
	switch {
	case res.Confidence == shellparse.High && len(res.Skills) > 0:
		return rewrite(in, command, res.Skills, ix, env, cwd)
	case res.Confidence == shellparse.Low && res.HasNeedle:
		why := res.Reason
		if why == "" {
			why = "ambiguous command"
		}
		return ask("watchdeck: could not determine the sandbox boundary ("+why+"); run the script directly, e.g. python3 <path>", nil,
				"watchdeck could not tell which skill script this command runs, so it is NOT sandboxed if approved. Prefer running the skill's script directly (python3 <path/to/script> args) instead of piping, eval, substitutions or copying it elsewhere."),
			meta{Skills: res.Skills, Confidence: "low"}
	}
	return commandSubject(in, command, lp)
}

// commandSubject rewrites a single simple command that a user command
// subject matches (policy.CommandSubject: one plain call of inert words) to
// `watchdeck run --subject command:<name> -c '<original>'`. It asks, or
// allows when the subject's grant has auto_allow (the command is already a
// single simple command). Only the user file defines command subjects.
func commandSubject(in Input, command string, lp loadedPolicy) (*Output, meta) {
	if lp.Policy == nil || !lp.Policy.HasKind(policy.KindCommand) {
		return nil, meta{}
	}
	s, ok := lp.Policy.CommandSubject(command)
	if !ok {
		return nil, meta{}
	}
	eff, _ := lp.Policy.CommandGrant(s)
	updated := make(map[string]any, len(in.ToolInput))
	for k, v := range in.ToolInput {
		updated[k] = v
	}
	updated["command"] = paths.BinaryName + " run --subject " + shellparse.Quote("command:"+s.Name) + " -c " + shellparse.Quote(command)
	decision := Ask
	if eff.AutoAllow {
		decision = Allow
	}
	name := manifest.DisplayPath(s.Name)
	return &Output{HookSpecificOutput: Specific{
		HookEventName:            "PreToolUse",
		PermissionDecision:       decision,
		PermissionDecisionReason: "watchdeck: command subject " + name + " under " + eff.Summary(),
		UpdatedInput:             updated,
		AdditionalContext: "This command runs under a watchdeck sandbox for command subject '" + name + "'. " +
			"If it fails with a permission error (Operation not permitted / EPERM), do not retry it another way; report the denial. " +
			"The user can widen the subject's grant in watchdeck's overrides.yaml.",
	}}, meta{
		Subject: &activity.Subject{Kind: policy.KindCommand, Name: s.Name}, Enforcement: activity.EnforcementSandbox,
		Confidence: "high",
	}
}

func ask(reason string, updated map[string]any, context string) *Output {
	return &Output{HookSpecificOutput: Specific{
		HookEventName: "PreToolUse", PermissionDecision: Ask, PermissionDecisionReason: reason,
		UpdatedInput: updated, AdditionalContext: context,
	}}
}

// rewrite builds the updatedInput and the decision for a matched command.
func rewrite(in Input, command string, names []string, ix *index.Index, env Env, cwd string) (*Output, meta) {
	projectRoot := index.ProjectRoot(cwd, env.Home)
	user, project, oerr := manifest.LoadOverrides(env.UserCfgDir, projectRoot)

	m := meta{Skills: names, Confidence: "high", Enforcement: activity.EnforcementSandbox}
	if len(names) == 1 {
		m.Subject = &activity.Subject{Kind: policy.KindSkill, Name: names[0]}
	}
	var reasons []string
	allAuto := oerr == nil
	for _, name := range names {
		entry, _ := ix.Lookup(name)
		grant, ignored := manifest.Grant(name, user, project)
		for _, ig := range ignored {
			m.Ignored = append(m.Ignored, name+": "+ig)
		}
		eff := grant
		var ungranted []string
		mp := entry.Manifest
		if mp == "" {
			mp = filepath.Join(entry.Dir, "PERMISSIONS.yaml")
		}
		hasReq := false
		if _, err := os.Stat(mp); err == nil {
			hasReq = true
			if req, perr := manifest.Parse(mp); perr != nil {
				reasons = append(reasons, fmt.Sprintf("%s: PERMISSIONS.yaml is invalid (%v); run will refuse", name, firstLine(perr.Error())))
				allAuto = false
				continue
			} else {
				eff, ungranted = manifest.Clip(req, grant)
				for _, u := range ungranted {
					m.Ungranted = append(m.Ungranted, name+": "+u)
				}
			}
		}
		if !eff.AutoAllow || entry.SkillMDIrregular {
			allAuto = false
		}
		r := name
		if entry.SkillMDIrregular {
			// Verifier note (M6.1): a FIFO, directory or device in place of
			// SKILL.md is never read; the directory still counts as a skill,
			// so its scripts run sandboxed and are always asked about.
			r += " (SKILL.md is not a regular file; always asked)"
		}
		if hasReq {
			r += " under " + eff.Summary()
		} else {
			r += " has no PERMISSIONS.yaml; default profile (" + eff.Summary() + ")"
		}
		if len(ungranted) > 0 {
			shown := make([]string, len(ungranted))
			for i, u := range ungranted {
				shown[i] = manifest.DisplayUngranted(u) // m.Ungranted keeps the raw item
			}
			r += "; requested but not granted: " + strings.Join(shown, ", ") + " (grant with: watchdeck allow " + name + " ...)"
		}
		if len(ignored) > 0 {
			r += "; " + strings.Join(ignored, "; ")
		}
		reasons = append(reasons, r)
	}
	if oerr != nil {
		reasons = append(reasons, "overrides: "+oerr.Error())
	}

	var b strings.Builder
	b.WriteString(paths.BinaryName + " run")
	for _, n := range names {
		b.WriteString(" --skill ")
		b.WriteString(shellparse.Quote(n))
	}
	b.WriteString(" -c ")
	b.WriteString(shellparse.Quote(command))

	updated := make(map[string]any, len(in.ToolInput))
	for k, v := range in.ToolInput {
		updated[k] = v
	}
	updated["command"] = b.String()

	// "allow" only for a command that is solely the skill invocation (an
	// optional leading cd, then one call that runs a script of the skill).
	// A compound command would otherwise ride on the skill's grant and skip
	// the user's normal permission prompt for its other parts.
	decision := Ask
	if allAuto && len(names) == 1 && soleInvocation(command, cwd, env.Environ, ix, names[0]) {
		decision = Allow
	}
	skillList := strings.Join(names, ", ")
	context := "This command runs under a watchdeck sandbox for skill '" + skillList + "'. " +
		"If it fails with a permission error (Operation not permitted / EPERM), do not copy the script elsewhere, " +
		"pipe it to an interpreter, or retry outside the sandbox. Report the denial; the user can widen the policy with " +
		"`watchdeck allow " + names[0] + " ...`."
	return &Output{HookSpecificOutput: Specific{
		HookEventName:            "PreToolUse",
		PermissionDecision:       decision,
		PermissionDecisionReason: "watchdeck: " + strings.Join(reasons, " | "),
		UpdatedInput:             updated,
		AdditionalContext:        context,
	}}, m
}

// interpreters that may appear as argv[0] in front of a skill script, each
// with the ONLY options allowed before the script operand. Anything else
// starting with "-" (inline code, module runs, preloads, combined short flags
// such as -uc, unknown options) disqualifies auto-allow; the command still
// runs, it just asks. An allowlist is used rather than a denylist because
// short flags combine and new flags appear.
//
// Slices of constants and a switch, not maps: a package-level map literal is
// built at init, and this package runs on every hook call.
var (
	pythonFlags = []string{"-u", "-B", "-E", "-I", "-O", "-OO", "-s", "-S", "-q", "-b", "-bb", "--"}
	nodeFlags   = []string{"--no-warnings", "--no-deprecation", "--trace-warnings", "--enable-source-maps", "--"}
	shellFlags  = []string{"-e", "-u", "-x", "-eu", "-ue", "-ex", "-eux", "-xe", "--"}
	warnFlags   = []string{"-w", "--"}
)

// interpreterFlags returns the options allowed before the script operand for
// interpreter head, and whether head is a known interpreter.
func interpreterFlags(head string) ([]string, bool) {
	switch head {
	case "python", "python3":
		return pythonFlags, true
	case "node":
		return nodeFlags, true
	case "bash", "sh", "zsh":
		return shellFlags, true
	case "ruby", "perl":
		return warnFlags, true
	}
	return nil, false
}

// wrappers take a subcommand before the script. npx and tsx are not listed:
// npx resolves packages, which is not "the skill's script".
// wrapperSub returns the subcommand wrapper head takes before the script, and
// whether head is a known wrapper.
func wrapperSub(head string) (string, bool) {
	switch head {
	case "uv", "deno", "bun":
		return "run", true
	}
	return "", false
}

// soleInvocation reports whether cmd is exactly one call (after an optional
// `cd DIR`) that runs a script inside the skill directory: either the script
// itself as argv[0], or an interpreter/wrapper whose first positional operand
// is such a script and which carries no inline-code flag. Pipes, lists,
// substitutions, stdin tricks, here-docs and prefix assignments disqualify.
func soleInvocation(cmd, cwd string, environ map[string]string, ix *index.Index, skill string) bool {
	prog, err := shellparse.Parse(cmd, cwd, environ)
	if err != nil || prog == nil || prog.Confidence != shellparse.High || prog.StdinInterpreter || len(prog.HereDocs) > 0 {
		return false
	}
	calls := prog.Calls
	if len(calls) == 2 && len(calls[0].Argv) >= 1 && calls[0].Argv[0] == "cd" {
		calls = calls[1:]
	}
	if len(calls) != 1 || len(calls[0].Argv) == 0 {
		return false
	}
	entry, ok := ix.Lookup(skill)
	if !ok {
		return false
	}
	call := calls[0]
	if len(call.Assigns) > 0 {
		// PYTHONSTARTUP=, NODE_OPTIONS=, LD_PRELOAD=, BASH_ENV= and friends change
		// what the interpreter runs before the script; never auto-allow them.
		return false
	}
	argv := call.Argv
	head := filepath.Base(argv[0])
	rest := argv[1:]
	var allowedFlags []string
	if sub, isWrapper := wrapperSub(head); isWrapper {
		if len(rest) == 0 || rest[0] != sub {
			return false
		}
		rest = rest[1:]
		allowedFlags = nil // no options between `run` and the script
	} else if flags, isInterp := interpreterFlags(head); isInterp {
		allowedFlags = flags
	} else {
		// argv[0] must be the skill's own script
		return inSkill(argv[0], call.Cwd, entry.Dir)
	}
	// options before the script must all be allowlisted; the first operand must be a script in the skill
	for _, a := range rest {
		if strings.HasPrefix(a, "-") {
			if !slices.Contains(allowedFlags, a) {
				return false
			}
			continue
		}
		return inSkill(a, call.Cwd, entry.Dir)
	}
	return false
}

func inSkill(p, cwd, dir string) bool {
	if !filepath.IsAbs(p) {
		p = filepath.Join(cwd, p)
	}
	if r, err := filepath.EvalSymlinks(p); err == nil {
		p = r
	} else {
		p = filepath.Clean(p)
	}
	return p == dir || strings.HasPrefix(p, dir+string(filepath.Separator))
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// Run reads the hook JSON from stdin and writes the response. Exit 0 always:
// a hook that errors must not block Bash, but once a skill-related command
// was seen the fallback is "ask", never silence.
//
// Dispatch: SessionStart, SessionEnd and UserPromptSubmit go to the
// lifecycle store (lifecycle.go) and are never answered: their stdout would
// become model context. Every other event first touches its session's live
// marker. A PermissionDenied event and a Skill-tool PreToolUse are only
// recorded (events.go), never answered. Everything else goes through Decide;
// when it has an opinion the JSON goes to stdout FIRST and the decision record
// is appended after, so a slow disk never delays Claude Code. Without an
// opinion the activity file is never opened.
func Run(stdin io.Reader, stdout io.Writer, env Env) int {
	raw, err := io.ReadAll(stdin)
	if err != nil {
		return 0
	}
	var in Input
	if err := json.Unmarshal(raw, &in); err != nil {
		return 0
	}
	// Watchdog (fail closed on time): Claude Code treats a hook that times
	// out as no opinion, so a hook that hangs (a slow disk, a pathological
	// file that slipped past the read and parse caps) would let the command
	// run unsandboxed. If handle has not finished within DecideTimeout, a
	// Bash or Skill PreToolUse gets an ask and every other event gets
	// nothing; Run returns and the process exits, abandoning the work.
	type result struct {
		out *Output
		m   meta
	}
	in.Harness = activity.DefaultHarness(env.Harness)
	env.Lifecycle.Harness = in.Harness
	env.loading = new(atomic.Bool)
	done := make(chan result, 1)
	go func() {
		defer func() { _ = recover() }() // handle recovers its own; belt and braces
		out, m := handle(in, env)
		done <- result{out, m}
	}()
	timer := time.NewTimer(DecideTimeout)
	defer timer.Stop()
	select {
	case r := <-done:
		if r.out == nil {
			// A log-only rule hit is recorded although nothing is printed: a
			// log hit counts as touching watchdeck's business (M6.4). So is a
			// verdict shadow mode observed (Phase 6).
			if env.ActivityPath != "" {
				switch {
				case r.m.Shadow:
					safely(func() { _ = activity.Append(env.ActivityPath, shadowRecord(in, r.m, env.Home)) })
				case r.m.LogOnly:
					safely(func() { _ = activity.Append(env.ActivityPath, ruleLogRecord(in, r.m, env.Home)) })
				}
			}
			return 0
		}
		enc := json.NewEncoder(stdout)
		_ = enc.Encode(r.out)
		if env.ActivityPath != "" {
			if r.out.HookSpecificOutput.HookEventName == EventPostToolUse {
				safely(func() { _ = activity.Append(env.ActivityPath, ruleLogRecord(in, r.m, env.Home)) })
			} else {
				safely(func() { _ = activity.Append(env.ActivityPath, decisionRecord(in, r.out, r.m, env.Home)) })
			}
		}
	case <-timer.C:
		// Every PreToolUse the hook is registered for gets the ask: a
		// registration beyond Bash and Skill exists only because the policy
		// has gates or rules for that tool (M6.3).
		if in.HookEventName == "" || in.HookEventName == "PreToolUse" {
			_ = json.NewEncoder(stdout).Encode(ask(SlowReason, nil, ""))
		}
		if f := onTimeout; f != nil {
			safely(func() { f(in, env) })
		}
	}
	return 0
}

// onTimeout runs when the watchdog fires (set by slowIndex.go: finish a
// slow cold index build in a detached child).
var onTimeout = watchdogFired

// DecideTimeout bounds a hook call (see Run). Claude Code's own hook timeout
// is longer, so the ask always lands first. Tests lower it.
var DecideTimeout = 3 * time.Second

// SlowReason is the ask reason when the watchdog fires.
const SlowReason = "watchdeck could not decide in time; not sandboxed"

// testDelay, when set (tests only), runs at the start of handle.
var testDelay func()

// testDelayEnv, when set (tests only), runs after testDelay with the call's Env.
var testDelayEnv func(Env)

// handle does the work of one hook call: lifecycle and denied/skill records
// return no output; a Bash PreToolUse goes through decide.
func handle(in Input, env Env) (*Output, meta) {
	if testDelay != nil {
		testDelay()
	}
	if testDelayEnv != nil {
		testDelayEnv(env)
	}
	switch in.HookEventName {
	case EventSessionStart, EventSessionEnd, EventUserPromptSubmit:
		safely(func() { recordLifecycle(in, env) })
		return nil, meta{}
	}
	if in.SessionID != "" {
		safely(func() { _ = env.Lifecycle.Touch(in.SessionID) })
	}
	switch {
	case in.HookEventName == "PermissionRequest":
		// reserved: nothing is printed or written for it (2026-10-19)
		return nil, meta{}
	case in.HookEventName == "PermissionDenied":
		safely(func() { recordDenied(in, env) })
		return nil, meta{}
	case in.ToolName == "Skill" && (in.HookEventName == "" || in.HookEventName == "PreToolUse"):
		// Recorded, then gated: an agent rule's skills.allow or tools list
		// may deny or ask (M6.3); nothing else answers a Skill call.
		safely(func() { recordSkillInvoked(in, env) })
	}
	return decideSafely(in, env)
}

// decideSafely is decide behind the hook's recovery, shared by handle and
// Explain: a panic answers ask for a call that is not Bash and for a Bash
// command that looks skill-related, and nothing otherwise.
func decideSafely(in Input, env Env) (out *Output, m meta) {
	defer func() {
		if r := recover(); r != nil {
			cmd, _ := in.ToolInput["command"].(string)
			out, m = nil, meta{}
			if in.ToolName != "Bash" && in.HookEventName != EventPostToolUse {
				out = ask(fmt.Sprintf("watchdeck: internal error (%v)", r), nil, "")
				return
			}
			for _, n := range index.GenericNeedles {
				if strings.Contains(cmd, n) {
					out = ask(fmt.Sprintf("watchdeck: internal error (%v)", r), nil, "")
					return
				}
			}
		}
	}()
	return decide(in, env)
}

// decisionRecord is the activity line for a decision the hook printed.
func decisionRecord(in Input, out *Output, m meta, home string) activity.Record {
	r := baseRecord(in, activity.KindDecision)
	r.Command, _ = in.ToolInput["command"].(string)
	r.Skills = sortedSkills(m.Skills)
	s := out.HookSpecificOutput
	r.Decision = s.PermissionDecision
	r.Reason = s.PermissionDecisionReason
	if s.UpdatedInput != nil {
		r.Rewritten, _ = s.UpdatedInput["command"].(string)
	}
	r.Confidence = m.Confidence
	r.Ungranted = m.Ungranted
	r.Ignored = m.Ignored
	addPolicyFields(&r, in, m)
	redactUntouched(&r, home)
	return r
}

// ruleLogRecord is the activity line for log-only rule hits (and, after a
// tool ran, the prompt-injection warnings): kind rule_log, no decision.
func ruleLogRecord(in Input, m meta, home string) activity.Record {
	r := baseRecord(in, activity.KindRuleLog)
	r.Command, _ = in.ToolInput["command"].(string)
	addPolicyFields(&r, in, m)
	redactUntouched(&r, home)
	return r
}

// shadowRecord is the activity line for a verdict shadow mode observed and
// the hook did not print: kind decision, decision "shadow", would and
// would_reason set, the same redaction as a gate record.
func shadowRecord(in Input, m meta, home string) activity.Record {
	r := baseRecord(in, activity.KindDecision)
	r.Command, _ = in.ToolInput["command"].(string)
	r.Decision = activity.DecisionShadow
	addPolicyFields(&r, in, m)
	redactUntouched(&r, home)
	return r
}

// addPolicyFields fills the M6.4 fields and the shadow mode fields.
func addPolicyFields(r *activity.Record, in Input, m meta) {
	r.ToolName = in.ToolName
	r.Subject = m.Subject
	r.Enforcement = m.Enforcement
	r.Rules = m.Rules
	r.Target = m.Target
	r.Shadow, r.Would, r.WouldReason = m.Shadow, m.Would, m.WouldReason
	r.Temporary = m.Temporary
}

// redactUntouched applies the owner's rule "commands that touch no skill
// are not recorded" to a Bash record the hook wrote only because a rule
// pack, a policy rule or a gate answered: the command (which may hold a
// token or a password) is left out; its program name (argv0, base name),
// the rule ids and the target stay. A skill or command-subject call keeps
// its command (the run join needs it). The cwd of such a record is shown
// with the home directory as ~ (no run joins it).
func redactUntouched(r *activity.Record, home string) {
	if r.ToolName != "Bash" || r.Command == "" || len(r.Skills) > 0 {
		return
	}
	if r.Subject != nil && (r.Subject.Kind == "skill" || r.Subject.Kind == "command") {
		return
	}
	r.Argv0 = argv0Of(r.Command)
	r.Command = ""
	if r.Rewritten == "" {
		r.Cwd = tildeHome(r.Cwd, home)
	}
}

// argv0Of is the base name of a command's first word, best effort: the
// first word, unquoted only by trimming quotes, cut to 64 bytes.
func argv0Of(cmd string) string {
	w := ""
	for _, x := range strings.Fields(cmd) {
		if !strings.Contains(x, "=") { // skip VAR=value prefixes (never stored)
			w = x
			break
		}
	}
	if w == "" {
		return ""
	}
	w = filepath.Base(strings.Trim(w, `'"`))
	if len(w) > 64 {
		w = w[:64]
	}
	return w
}

// baseRecord copies the Claude Code ids every record carries.
func baseRecord(in Input, kind string) activity.Record {
	r := activity.Record{
		Kind: kind, TS: activity.Now(), Harness: activity.DefaultHarness(in.Harness),
		SessionID: in.SessionID, ToolUseID: in.ToolUseID, Transcript: in.TranscriptPath,
		AgentID: in.AgentID, AgentType: in.AgentType, PermMode: in.PermissionMode,
	}
	if in.Cwd != "" {
		r.Cwd = filepath.Clean(in.Cwd)
	}
	return r
}

// sortedSkills returns a sorted, de-duplicated copy (names itself keeps the
// rewrite's --skill order).
func sortedSkills(names []string) []string {
	if len(names) == 0 {
		return nil
	}
	out := append([]string(nil), names...)
	sort.Strings(out)
	j := 0
	for i, n := range out {
		if i == 0 || n != out[j-1] {
			out[j] = n
			j++
		}
	}
	return out[:j]
}

// safely runs f and swallows a panic: logging must never break the hook.
func safely(f func()) {
	defer func() { _ = recover() }()
	f()
}
