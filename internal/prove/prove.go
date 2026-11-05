// Package prove backs `watchdeck doctor --prove`: it runs the hook command
// the person's settings register, in a throwaway demo tree under /var/tmp,
// against the embedded canary skill, and reports five legs: the
// registration was found, the hook rewrote the canary's script to
// `watchdeck run`, that rewrite ran under the sandbox and was denied the
// network, a Read of <tmp HOME>/.ssh/id_fake was denied by a pack rule the
// throwaway policy raises to deny, and the real user policy is not in shadow
// mode. HOME, the XDG dirs, CLAUDE_CONFIG_DIR, the activity log and the
// skill dir resolve inside the tree (ChildEnv); TMPDIR and SSH_AUTH_SOCK
// stay the parent's on purpose, because the sandbox's temp allow and its
// profile file resolve through the real TMPDIR (the canary writes nothing
// there). The shadow answer arrives as data (Options.Shadow), so this
// package never reads the person's own policy, settings or activity log.
package prove

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/activity"
	"github.com/Panda-Taps-LLC/watchdeck/internal/demo"
	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
	"github.com/Panda-Taps-LLC/watchdeck/internal/sandbox"
)

// Leg names in report order; doctor prefixes "prove: ".
const (
	LegRegistration = "registration"
	LegRewrite      = "rewrite"
	LegSandbox      = "sandbox"
	LegReadRule     = "read rule"
	LegShadow       = "shadow"
)

// Status of a leg. The values equal doctor's statusPass/Warn/Fail.
type Status string

// The three statuses.
const (
	Pass Status = "pass"
	Warn Status = "warn"
	Fail Status = "fail"
)

// Leg is one line of the proof.
type Leg struct {
	Name    string `json:"name"`
	Status  Status `json:"status"`
	Message string `json:"message"`
}

// Hook is the registered hook command, as settings.Registration found it.
type Hook struct {
	Argv    []string      // exec form: command then args; shell form: /bin/sh, -c, command
	Text    string        // command plus args, for messages
	Binary  string        // exec form: the absolute binary; "" for the shell form
	Timeout time.Duration // the entry's timeout; 0 = DefaultHookTimeout
	File    string        // the settings file it came from, display form (~/…)
}

// Options for Run.
type Options struct {
	Hook        Hook
	HookErr     string        // non-empty: no usable registration; the message of the registration leg
	Env         *demo.Env     // prepared tree; Run writes PolicyYAML into Env.Cfg/overrides.yaml
	PrepareErr  error         // Env is nil: the rewrite, sandbox and read legs are not run
	Python      string        // absolute python3, or "" (the sandbox leg is not run)
	Environ     []string      // the parent environment (os.Environ())
	Nested      bool          // the caller's sandbox self-test could not apply a profile here
	Shadow      Shadow        // the REAL user policy's mode, read by the caller (doctor_prove.go)
	HookTimeout time.Duration // 0 = Hook.Timeout, else DefaultHookTimeout
	RunTimeout  time.Duration // 0 = DefaultRunTimeout
}

// Shadow is what the caller learned about the real user policy file
// (paths.Paths.OverridesFile()): prove never reads it itself.
type Shadow struct {
	On   bool   // mode: shadow
	File string // the file, display form (~/…); "" when absent
	Err  error  // the file could not be read or parsed
}

// Defaults.
const (
	DefaultHookTimeout = 10 * time.Second
	DefaultRunTimeout  = 20 * time.Second
	MaxHookTimeout     = 30 * time.Second                       // a longer registered timeout is capped for the proof
	SessionID          = "7c0a1e52-0000-4000-8000-00000000000a" // lifecycle.ValidID: a UUID shape
	BashToolUseID      = "toolu_prove_bash"
	ReadToolUseID      = "toolu_prove_read"
)

// hookWaitDelay bounds how long a hook call keeps reading its pipes after
// the process exits or is killed (a backgrounded grandchild holding them).
const hookWaitDelay = 2 * time.Second

// maxKeep is how much of each output stream a call keeps.
const maxKeep = 64 << 10

// Result of one proof.
type Result struct {
	Legs     []Leg            // five, in report order
	Rewrite  string           // updatedInput.command the hook returned ("" when none)
	Decision string           // the Bash leg's permissionDecision
	Run      *activity.Record // the run record judged (nil when none was found)
	Read     *activity.Record // the Read decision record (nil when none)
}

// OK is true when no leg failed.
func (r Result) OK() bool {
	for _, l := range r.Legs {
		if l.Status == Fail {
			return false
		}
	}
	return true
}

// Run performs the proof. It never panics on a bad reply, never touches a
// path outside o.Env.Base, and reports the legs in order (the shadow leg
// is a pure function of o.Shadow).
func Run(ctx context.Context, o Options) Result { return run(ctx, o, nil) }

// run is Run with the hook call injectable (nil = callHook on o.Hook), so
// the judges are tested without a process.
func run(ctx context.Context, o Options, call func([]byte) reply) Result {
	var res Result
	notRun := func(msg string) Result {
		for _, n := range []string{LegRewrite, LegSandbox, LegReadRule} {
			res.Legs = append(res.Legs, Leg{Name: n, Status: Fail, Message: msg})
		}
		res.Legs = append(res.Legs, shadowLeg(o.Shadow))
		return res
	}
	if o.HookErr != "" {
		res.Legs = append(res.Legs, Leg{Name: LegRegistration, Status: Fail, Message: o.HookErr})
		return notRun("not run (prove: " + LegRegistration + " failed)")
	}
	res.Legs = append(res.Legs, registrationLeg(o.Hook))
	e := o.Env
	switch {
	case e == nil && o.PrepareErr != nil:
		return notRun("not run: could not prepare the throwaway tree: " + o.PrepareErr.Error())
	case e == nil:
		return notRun("not run: no throwaway tree")
	}
	if err := writePolicy(e.Cfg); err != nil {
		return notRun("not run: could not write the throwaway policy: " + err.Error())
	}
	env := ChildEnv(e, o.Environ)
	if call == nil {
		timeout := o.callTimeout()
		call = func(p []byte) reply { return callHook(ctx, o.Hook, env, e.Cwd, p, timeout) }
	}

	// rewrite
	rw, rewrite, decision := judgeRewrite(call, BashPayload(e, o.Python), probeCommand(e, o.Python), o.Hook.Text, e.SkillDir)
	res.Legs = append(res.Legs, rw)
	res.Rewrite, res.Decision = rewrite, decision

	// sandbox
	var sb Leg
	switch {
	case rw.Status != Pass:
		sb = Leg{Name: LegSandbox, Status: Fail, Message: "not run (prove: " + LegRewrite + " failed)"}
	case o.Nested:
		sb = nestedLeg()
	case o.Python == "":
		sb = Leg{Name: LegSandbox, Status: Warn, Message: "not run: python3 is not on PATH (the canary's script is Python); the rewrite was still proven"}
	case !sandbox.Available():
		sb = Leg{Name: LegSandbox, Status: Fail, Message: "no sandbox backend on this machine (sandbox-exec on macOS, bwrap on Linux)"}
	default:
		timeout := o.runTimeout()
		ro := execRewrite(ctx, rewrite, env, e.Cwd, timeout)
		ro.Binary = o.Hook.Binary
		if ro.Binary != "" {
			if r, err := filepath.EvalSymlinks(ro.Binary); err == nil {
				ro.Binary = r
			}
		}
		ro.PathBinary = lookPath(paths.BinaryName, env)
		res.Run = pickRecord(e.Activity, activity.KindRun, BashToolUseID)
		sb = judgeRun(ro, res.Run, false)
	}
	res.Legs = append(res.Legs, sb)

	// read rule
	res.Legs = append(res.Legs, judgeRead(call, ReadPayload(e), o.Hook.Text))
	res.Read = pickRecord(e.Activity, activity.KindDecision, ReadToolUseID)

	res.Legs = append(res.Legs, shadowLeg(o.Shadow))
	return res
}

// hookTimeout is the registered timeout capped at MaxHookTimeout, else
// DefaultHookTimeout.
func hookTimeout(h Hook) time.Duration {
	if h.Timeout > 0 {
		return min(h.Timeout, MaxHookTimeout)
	}
	return DefaultHookTimeout
}

// callTimeout is one hook call's deadline: HookTimeout when set, else
// hookTimeout(Hook).
func (o Options) callTimeout() time.Duration {
	if o.HookTimeout > 0 {
		return o.HookTimeout
	}
	return hookTimeout(o.Hook)
}

// runTimeout is the rewrite's deadline: RunTimeout when set, else
// DefaultRunTimeout.
func (o Options) runTimeout() time.Duration {
	if o.RunTimeout > 0 {
		return o.RunTimeout
	}
	return DefaultRunTimeout
}

// ProveDeadline bounds a whole prove from its parts: two legs that each
// call the hook up to twice (the watchdog retry), one run, and 5 s for
// starting processes and reading the tree.
func ProveDeadline(hook, run time.Duration) time.Duration {
	return 2*2*hook + run + 5*time.Second
}

// Deadline is ProveDeadline for these options; the caller bounds Run's
// context with it, so a leg's own deadline always passes first.
func (o Options) Deadline() time.Duration {
	return ProveDeadline(o.callTimeout(), o.runTimeout())
}

// secs formats d in seconds for messages.
func secs(d time.Duration) string { return strconv.FormatFloat(d.Seconds(), 'f', -1, 64) }

// registrationLeg is the pass line for a usable registration.
func registrationLeg(h Hook) Leg {
	t := secs(hookTimeout(h)) + " s"
	if h.Timeout > MaxHookTimeout {
		t = secs(h.Timeout) + " s capped at " + t + " for the proof"
	}
	m := fmt.Sprintf("%s: %s (timeout %s)", h.File, h.Text, t)
	if h.Binary == "" {
		m += " (shell form, run with /bin/sh -c)"
	}
	return Leg{Name: LegRegistration, Status: Pass, Message: m}
}

// capBuf keeps the first maxKeep bytes written to it and drops the rest.
type capBuf struct{ b []byte }

func (c *capBuf) Write(p []byte) (int, error) {
	if room := maxKeep - len(c.b); room > 0 {
		c.b = append(c.b, p[:min(room, len(p))]...)
	}
	return len(p), nil
}

func (c *capBuf) String() string { return string(c.b) }

// callHook runs the registered hook once with p on stdin.
func callHook(ctx context.Context, h Hook, env []string, dir string, p []byte, timeout time.Duration) reply {
	if len(h.Argv) == 0 {
		return reply{StartErr: errors.New("empty command")}
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, h.Argv[0], h.Argv[1:]...)
	var so, se capBuf
	cmd.Stdin, cmd.Stdout, cmd.Stderr = bytes.NewReader(p), &so, &se
	cmd.Dir, cmd.Env = dir, env
	cmd.WaitDelay = hookWaitDelay
	err := cmd.Run()
	r := reply{Stdout: so.String(), Stderr: se.String()}
	var ee *exec.ExitError
	switch {
	case cctx.Err() != nil:
		r.TimedOut = true
	case err == nil:
	case errors.As(err, &ee):
		r.Exit = ee.ExitCode()
	default:
		r.StartErr = err
	}
	return r
}

// execRewrite runs the hook's rewrite as Claude Code would: /bin/bash -c
// under the parent PATH, in the tree's project dir, with empty stdin.
func execRewrite(ctx context.Context, rewrite string, env []string, dir string, timeout time.Duration) runOutcome {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, "/bin/bash", "-c", rewrite)
	var so, se capBuf
	cmd.Stdin, cmd.Stdout, cmd.Stderr = strings.NewReader(""), &so, &se
	cmd.Dir, cmd.Env = dir, env
	cmd.WaitDelay = sandbox.StreamWaitDelay
	err := cmd.Run()
	ro := runOutcome{Stdout: so.String(), Stderr: se.String(), Timeout: timeout}
	var ee *exec.ExitError
	switch {
	case cctx.Err() != nil:
		ro.TimedOut = true
	case err == nil:
	case errors.As(err, &ee):
		ro.Exit = ee.ExitCode()
	default:
		ro.StartErr = err
	}
	return ro
}

// lookPath resolves name on env's PATH as bash would (the first executable
// regular file), symlinks resolved; "" when none.
func lookPath(name string, env []string) string {
	pathVar := ""
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, "PATH="); ok {
			pathVar = v
		}
	}
	for _, dir := range filepath.SplitList(pathVar) {
		if dir == "" {
			dir = "."
		}
		p := filepath.Join(dir, name)
		fi, err := os.Stat(p)
		if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm()&0o111 == 0 {
			continue
		}
		if r, err := filepath.EvalSymlinks(p); err == nil {
			return r
		}
		return p
	}
	return ""
}

// pickRecord returns the newest record of kind in the throwaway log whose
// tool_use_id is id; for a run, the newest run record when none has it (the
// judge then reports it unjoined). nil when there is none.
func pickRecord(path, kind, id string) *activity.Record {
	res, err := activity.Read(path, activity.ReadOptions{Kinds: []string{kind}})
	if err != nil || len(res.Records) == 0 {
		return nil
	}
	for i := len(res.Records) - 1; i >= 0; i-- {
		if res.Records[i].ToolUseID == id {
			return &res.Records[i]
		}
	}
	if kind == activity.KindRun {
		return &res.Records[len(res.Records)-1]
	}
	return nil
}
