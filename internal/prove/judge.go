package prove

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/activity"
	"github.com/Panda-Taps-LLC/watchdeck/internal/hook"
	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
	"github.com/Panda-Taps-LLC/watchdeck/internal/runner"
	"github.com/Panda-Taps-LLC/watchdeck/internal/shellparse"
)

// reply is one hook call: what the process did (Exit, Stdout, Stderr,
// StartErr, TimedOut, filled by callHook) and, after parseReply, what it
// answered (Output, Empty).
type reply struct {
	Output   *hook.Output
	Empty    bool
	Exit     int
	Stdout   string
	Stderr   string
	StartErr error // the process could not be started
	TimedOut bool  // the call deadline passed
}

// parseReply reads a hook's stdout: blank is Empty (no opinion), anything
// else must be one hook.Output.
func parseReply(stdout []byte) (reply, error) {
	if len(bytes.TrimSpace(stdout)) == 0 {
		return reply{Empty: true}, nil
	}
	var o hook.Output
	if err := json.Unmarshal(stdout, &o); err != nil {
		head := stdout
		if len(head) > 120 {
			head = head[:120]
		}
		return reply{}, fmt.Errorf("the hook printed something that is not a hook reply: %q", head)
	}
	return reply{Output: &o}, nil
}

// rewriteOf is updatedInput.command ("" when none).
func rewriteOf(r reply) string {
	if r.Output == nil {
		return ""
	}
	s, _ := r.Output.HookSpecificOutput.UpdatedInput["command"].(string)
	return s
}

// slow reports whether the reply is the hook watchdog's ask.
func slow(r reply) bool {
	p, err := parseReply([]byte(r.Stdout))
	return err == nil && p.Output != nil && p.Output.HookSpecificOutput.PermissionDecisionReason == hook.SlowReason
}

// callRetry calls the hook and, when it answers with the watchdog's ask,
// once more. stillSlow is true when the second answer is the watchdog's too.
func callRetry(call func([]byte) reply, p []byte) (r reply, stillSlow bool) {
	r = call(p)
	if !slow(r) {
		return r, false
	}
	r = call(p)
	return r, slow(r)
}

// processFailure judges what every hook call must satisfy before its answer
// is read: it started, finished in time, exited 0 and printed a parseable
// reply or nothing. ok is false with the failure message; otherwise parsed
// is the reply with Output or Empty set.
func processFailure(r reply, text string) (parsed reply, msg string, ok bool) {
	switch {
	case r.StartErr != nil:
		return reply{}, fmt.Sprintf("could not start the registered hook (%s): %v", text, r.StartErr), false
	case r.TimedOut:
		return reply{}, fmt.Sprintf("the registered hook (%s) did not answer within its deadline; Claude Code treats that as a non-blocking error and runs the command unchanged", text), false
	case r.Exit != 0:
		return reply{}, fmt.Sprintf("the hook exited %d (it must always exit 0); stderr: %s", r.Exit, firstLine(r.Stderr)), false
	}
	p, err := parseReply([]byte(r.Stdout))
	if err != nil {
		return reply{}, err.Error(), false
	}
	return p, "", true
}

// judgeRewrite runs the Bash leg's hook call (with the SlowReason retry)
// and judges the answer. want is the probe command p carries, text the
// hook's command line, skillDir the canary's directory; rewrite and
// decision are set only on a pass.
func judgeRewrite(call func([]byte) reply, p []byte, want, text, skillDir string) (leg Leg, rewrite, decision string) {
	fail := func(format string, a ...any) (Leg, string, string) {
		return Leg{Name: LegRewrite, Status: Fail, Message: fmt.Sprintf(format, a...)}, "", ""
	}
	raw, stillSlow := callRetry(call, p)
	r, msg, ok := processFailure(raw, text)
	if !ok {
		return fail("%s", msg)
	}
	if r.Empty {
		return fail("no opinion on the canary's script: the hook printed nothing. A stubbed or very old hook answers like this; the real one rewrites skill scripts to %s run", paths.BinaryName)
	}
	s := r.Output.HookSpecificOutput
	if s.PermissionDecision == "deny" {
		return fail("the hook denied the canary instead of rewriting it: %s", s.PermissionDecisionReason)
	}
	if stillSlow {
		return fail("the hook could not decide within its watchdog twice (%s); run %s index --rebuild and try again", hook.SlowReason, paths.BinaryName)
	}
	rw := rewriteOf(r)
	if rw == "" {
		m := "the hook asked without a rewrite: " + s.PermissionDecisionReason
		if strings.Contains(s.PermissionDecisionReason, "cannot load the skill index") {
			m += "; the canary lives in " + skillDir
		}
		if strings.Contains(s.PermissionDecisionReason, "policy file is invalid") {
			m += "; the throwaway policy did not parse (PolicyYAML)"
		}
		return fail("%s", m)
	}
	if s.PermissionDecision == "" {
		head := strings.TrimSpace(raw.Stdout)
		if len(head) > 120 {
			head = head[:120]
		}
		return fail("the hook rewrote without a permissionDecision (%s)", head)
	}
	if !strings.HasPrefix(rw, RewritePrefix()) {
		return fail("the rewrite does not start with %s: %s", RewritePrefix(), rw)
	}
	// The hook quotes the original command with shellparse.Quote; reverse
	// it so a different quoting of the same command still passes, and fail
	// before anything runs when the payload is not the probe command.
	payload := strings.TrimPrefix(rw, RewritePrefix())
	if got, ok := shellparse.Unquote(payload); !ok || got != want {
		return fail("the rewrite's -c payload is not the canary's command: %s", payload)
	}
	words := strings.Fields(rw) // the prefix through the skill name: watchdeck run --skill canary-request
	if len(words) > 4 {
		words = words[:4]
	}
	return Leg{Name: LegRewrite, Status: Pass, Message: fmt.Sprintf("the canary's script was rewritten to %s … (%s) by %s", strings.Join(words, " "), s.PermissionDecision, text)}, rw, s.PermissionDecision
}

// readTail is the suffix of every Read leg pass message.
const readTail = "; Claude Code sends Read calls to the hook only while Read is hooked (the file tools check says whether it is)"

// judgeRead runs the Read leg's hook call (with the SlowReason retry) and
// judges the answer: only deny passes. text is the hook's command line.
func judgeRead(call func([]byte) reply, p []byte, text string) Leg {
	fail := func(format string, a ...any) Leg {
		return Leg{Name: LegReadRule, Status: Fail, Message: fmt.Sprintf(format, a...)}
	}
	raw, _ := callRetry(call, p)
	r, msg, ok := processFailure(raw, text)
	if !ok {
		return fail("%s", msg)
	}
	target := "~/" + idFake
	if r.Empty {
		return fail("no opinion on a Read of %s: the registered hook does not evaluate the built-in rule packs (stubbed, or older than the policy pipeline)", target)
	}
	s := r.Output.HookSpecificOutput
	switch s.PermissionDecision {
	case "deny":
		reason, _, _ := strings.Cut(s.PermissionDecisionReason, " | ")
		m := fmt.Sprintf("a Read of %s was denied (%s)", target, reason)
		if !strings.Contains(s.PermissionDecisionReason, RuleID) {
			m += "; denied by something other than " + RuleID
		}
		return Leg{Name: LegReadRule, Status: Pass, Message: m + readTail}
	case "allow":
		return fail("the hook allowed a Read of %s", target)
	case "ask":
		m := fmt.Sprintf("the hook asked instead of denying (%s): the throwaway policy's deny override was not applied", s.PermissionDecisionReason)
		if strings.Contains(s.PermissionDecisionReason, "policy file is invalid") {
			m += "; the throwaway policy did not parse (PolicyYAML)"
		}
		return fail("%s", m)
	default:
		return fail("the hook answered %q to a Read of %s, not deny", s.PermissionDecision, target)
	}
}

// runOutcome is the rewritten command's execution under /bin/bash -c.
type runOutcome struct {
	Exit       int
	Stdout     string
	Stderr     string
	StartErr   error
	TimedOut   bool
	Timeout    time.Duration // the deadline, for the message
	Binary     string        // the registered binary ("" for a shell-form registration)
	PathBinary string        // what PATH resolves the bare word to, symlinks resolved ("" when it does not)
}

// nestedLeg is the sandbox leg inside an outer sandbox (R6).
func nestedLeg() Leg {
	return Leg{Name: LegSandbox, Status: Warn, Message: fmt.Sprintf("not run: already inside a sandbox (run %s doctor --prove from a terminal)", paths.BinaryName)}
}

// judgeRun judges the sandbox leg from the run's exit code, its output and
// the run record picked from the throwaway activity log (nil when none).
func judgeRun(ro runOutcome, rec *activity.Record, nested bool) Leg {
	if nested {
		return nestedLeg()
	}
	fail := func(format string, a ...any) Leg {
		return Leg{Name: LegSandbox, Status: Fail, Message: fmt.Sprintf(format, a...)}
	}
	trailer := firstTrailerLine(ro.Stderr)
	switch {
	case ro.TimedOut:
		d := ro.Timeout
		if d == 0 {
			d = DefaultRunTimeout
		}
		return fail("the rewritten command did not finish within %s; an unsandboxed probe reports ALLOWED after a 2 s connect timeout, so this is a hang, not a missing sandbox", d)
	case ro.StartErr != nil:
		return fail("could not start /bin/bash: %v", ro.StartErr)
	case ro.Exit == 127:
		bin := ro.Binary
		if bin == "" {
			bin = "a shell-form command"
		}
		return fail("exit 127: a program on the rewrite's path was not found (usually %s; the registered hook is %s): put it on PATH as %s, or rerun %s setup from the one on PATH", paths.BinaryName, bin, paths.BinaryName, paths.BinaryName)
	case ro.Exit == runner.ExitNoSandbox:
		return fail("could not apply the sandbox (exit 126): %s. Outside Claude Code's own sandbox this is a real failure; inside it, add %q to sandbox.excludedCommands (the sandbox exclusion check)", trailer, paths.BinaryName+" run *")
	case ro.Exit == runner.ExitPolicy:
		return fail("policy error before the probe ran (exit 125): %s", trailer)
	case ro.Exit == runner.ExitUsage:
		return fail("no sandbox backend, or %s run refused its arguments (exit 3): %s", paths.BinaryName, trailer)
	case ro.Exit == 0:
		return fail("the probe reached the network (exit 0; stdout: %s): the sandbox did not deny it", netLine(ro.Stdout))
	case ro.Exit != 1:
		return fail("exit %d: %s", ro.Exit, firstLine(ro.Stderr))
	}
	if !strings.Contains(ro.Stdout, "net: DENIED") {
		return fail("exit 1 without a network denial: %s", firstLine(ro.Stderr))
	}
	if rec == nil {
		return fail("the probe was denied (net: DENIED) but the throwaway activity log has no run record: the registered binary did not write it")
	}
	var hint *activity.Hint
	var kinds []string
	for i := range rec.Hints {
		kinds = append(kinds, rec.Hints[i].Kind)
		if hint == nil && rec.Hints[i].Kind == "network" {
			hint = &rec.Hints[i]
		}
	}
	if rec.Outcome != activity.OutcomeFailed || hint == nil {
		k := strings.Join(kinds, ", ")
		if k == "" {
			k = "none"
		}
		return fail("run record outcome %s with hints %s, expected failed with a network hint", rec.Outcome, k)
	}
	if rec.ToolUseID != BashToolUseID || rec.JoinedBy != activity.JoinedByWrite {
		jb := rec.JoinedBy
		if jb == "" {
			jb = "absent"
		}
		return fail("the run record is not joined to the hook's decision (joined_by %s): the run and the decision disagree on the command or cwd", jb)
	}
	m := fmt.Sprintf("the network probe was denied under the sandbox (exit 1, net: DENIED, errno %d, backend %s); run record joined to the decision", hint.Errno, rec.Backend)
	if ro.Binary != "" && ro.PathBinary != "" && ro.PathBinary != ro.Binary {
		m += fmt.Sprintf("; note: PATH ran %s, the registration names %s", ro.PathBinary, ro.Binary)
	}
	return Leg{Name: LegSandbox, Status: Pass, Message: m}
}

// shadowLeg is a pure function of what the caller read from the real user
// policy file.
func shadowLeg(s Shadow) Leg {
	switch {
	case s.Err != nil:
		return Leg{Name: LegShadow, Status: Fail, Message: fmt.Sprintf("could not read %s: %v", s.File, s.Err)}
	case s.On:
		return Leg{Name: LegShadow, Status: Fail, Message: fmt.Sprintf("shadow mode is on in %s: the hook records what it would do and enforces nothing; %s rules shadow off", s.File, paths.BinaryName)}
	case s.File == "":
		return Leg{Name: LegShadow, Status: Pass, Message: "enforce mode (no policy file)"}
	default:
		return Leg{Name: LegShadow, Status: Pass, Message: fmt.Sprintf("enforce mode (%s)", s.File)}
	}
}

// firstTrailerLine is the first stderr line the runner wrote (it starts
// with paths.Trailer), else the first line, else "(no output)".
func firstTrailerLine(stderr string) string {
	for _, l := range strings.Split(stderr, "\n") {
		if strings.HasPrefix(l, paths.Trailer) {
			return strings.TrimSpace(l)
		}
	}
	return firstLine(stderr)
}

// firstLine is the first non-blank line of s, trimmed, or "(no output)".
func firstLine(s string) string {
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			return l
		}
	}
	return "(no output)"
}

// netLine is the probe's net: line on stdout, or the first line.
func netLine(stdout string) string {
	for _, l := range strings.Split(stdout, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "net:") {
			return strings.TrimSpace(l)
		}
	}
	return firstLine(stdout)
}
