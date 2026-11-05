package runner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/activity"
	"github.com/Panda-Taps-LLC/watchdeck/internal/manifest"
	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
	"github.com/Panda-Taps-LLC/watchdeck/internal/policy"
	"github.com/Panda-Taps-LLC/watchdeck/internal/profile"
	"github.com/Panda-Taps-LLC/watchdeck/internal/sandbox"
)

// MCP launch sandbox (M6.7, experimental): `watchdeck run --subject
// mcp:<name> -- <cmd> [args…]` runs a stdio MCP server under the launch
// grant of the user policy's `kind: mcp, name: <name>` subject.
//
// Differences from a skill run:
//   - The grant comes from the user overrides file only (a project file's
//     launch block is dropped by policy.New) and from the subject whose name
//     is exactly <name>: a glob or "*" mcp subject never supplies a launch
//     grant, so one wide subject cannot widen every wrapped server. Without
//     an exact subject with launch.sandbox: true the run is refused (125).
//   - The base is the MCP default profile (MCPDefault): network none, writes
//     to the working directory and temp only, env PATH HOME LANG TMPDIR,
//     widened only by launch.grant (network, write, read, env, caches).
//   - Like every run (runDeny), Claude Code's user config (~/.claude.json,
//     $CLAUDE_CONFIG_DIR/.claude.json, a relocated $CLAUDE_CONFIG_DIR) and
//     the state dir are denied besides the built-in deny list.
//   - stdin and stdout are handed to the child as they are: given *os.File
//     values the child inherits the descriptors, so JSON-RPC bytes never pass
//     through this process (no copy, no buffering, no hint scan). Only stderr
//     goes through a tail writer for denial hints.
//   - One run record per server lifetime, written when the server exits. It
//     is never correlated with a hook decision (Claude Code starts MCP
//     servers itself; there is none).

// MCPOptions for RunMCP.
type MCPOptions struct {
	Server string   // the MCP server name (the subject name)
	Argv   []string // the server's command and args
	Env    Env
	// Environ is the parent environment (os.Environ()).
	Environ []string
	// Stdin and Stdout should be *os.File (the CLI passes os.Stdin and
	// os.Stdout): the child then inherits them directly. Any other reader or
	// writer works but is copied through a pipe by os/exec.
	Stdin        io.Reader
	Stdout       io.Writer
	Stderr       io.Writer
	ActivityPath string
	// AllowHomeCwd lets the server start when its working directory is the
	// home directory ($HOME or the account's). Without it such a start is
	// refused (125): the cwd write grant would cover the whole home.
	AllowHomeCwd bool
}

// RecordMCPUsage appends the run record for a usage error found before
// RunMCP (malformed `run --subject mcp:` arguments in the CLI).
func RecordMCPUsage(o MCPOptions, msg string) {
	newMCPRunLog(o).fail(ExitUsage, activity.OutcomeUsage, msg, nil)
}

// ErrNoLaunch means the user policy has no exact `kind: mcp` subject for
// the server with launch.sandbox: true.
type ErrNoLaunch struct{ Name string }

func (e ErrNoLaunch) Error() string {
	return "no launch policy for MCP server " + e.Name + ": the user overrides file needs a subject {kind: mcp, name: " + e.Name + ", launch: {sandbox: true}} (watchdeck mcp wrap " + e.Name + " adds it)"
}

// MCPDefault is the MCP launch base grant: the skill default (built-in deny
// list, writes to ${CWD} and ${TMP}, network none, exec any, env PATH HOME
// LANG TMPDIR) with nothing else.
func MCPDefault() manifest.Effective {
	return manifest.Default()
}

// MCPLaunchSubject returns the user file's exact mcp subject for name, if
// it has launch.sandbox: true.
func MCPLaunchSubject(f policy.File, name string) (*manifest.PolicySubject, bool) {
	for i := range f.Subjects {
		s := &f.Subjects[i]
		if s.Kind == manifest.KindMCP && s.Name == name && s.Launch != nil && s.Launch.Sandbox {
			return s, true
		}
	}
	return nil, false
}

// ResolveMCP computes the launch policy for MCP server name.
func ResolveMCP(name string, env Env) (*Policy, error) {
	if name == "*" || !manifest.ValidSkillName(name) {
		return nil, fmt.Errorf("invalid MCP server name (%s)", manifest.SubjectNameRule)
	}
	if env.Environ == nil {
		env.Environ = map[string]string{}
	}
	userPath := filepath.Join(env.UserCfgDir, manifest.UserOverridesFile)
	f, _, err := policy.LoadFile(userPath)
	if err != nil {
		return nil, fmt.Errorf("overrides: %w", err)
	}
	sub, ok := MCPLaunchSubject(f, name)
	if !ok {
		return nil, ErrNoLaunch{name}
	}
	eff := MCPDefault()
	if sub.Launch.Grant != nil {
		eff, _ = manifest.Widen(eff, *sub.Launch.Grant, manifest.SourceUser)
	}
	eff.AutoAllow = false

	pol := &Policy{}
	realCWD := realPath(env.Cwd)
	realTMP := userTempDir(env.Environ)
	extra, err := runDeny(env)
	if err != nil {
		return nil, err
	}
	res, dropped, droppedWrites, err := toResolved(eff, nil, env.Home, realCWD, realTMP, extra.Paths)
	if err != nil {
		return nil, err
	}
	res.DenyPatterns = append(res.DenyPatterns, extra.Patterns...)
	pol.ExtraDeny = append(append([]string(nil), extra.Paths...), extra.Patterns...)
	for _, w := range droppedWrites {
		eff.Write = removeEntry(eff.Write, w)
	}
	pol.Effective = eff
	pol.Resolved = res
	p, warnings, err := compile(res)
	if err != nil {
		return nil, fmt.Errorf("profile: %w", err)
	}
	pol.Profile = p
	pol.Warnings = append(dropped, warnings...)
	if realCWD == realPath(env.Home) {
		pol.Warnings = append(pol.Warnings, "working directory is your home directory: the server may write anywhere under it except the protected paths")
	}
	pol.Hash = profile.Hash(p)
	pol.cwdIsHome = realCWD == realPath(env.Home)
	if h, err := accountHome(); err == nil && realCWD == realPath(h) {
		pol.cwdIsHome = true
	}
	return pol, nil
}

// RunMCP runs an MCP server under its launch policy and returns the exit
// code. Exit codes as Run: 3 usage or no backend, 125 policy error, 126
// sandbox not applied, else the server's own.
func RunMCP(ctx context.Context, o MCPOptions) int {
	if o.Stderr == nil {
		o.Stderr = os.Stderr
	}
	if o.Stdout == nil {
		o.Stdout = os.Stdout
	}
	if o.Stdin == nil {
		o.Stdin = os.Stdin
	}
	rl := newMCPRunLog(o)
	envMap := paths.EnvMap(o.Environ)
	if o.Env.Environ == nil {
		o.Env.Environ = envMap
	}
	say := func(msg string) { fmt.Fprintln(o.Stderr, paths.Trailer+msg) }
	if envMap[ProfileEnvVar] != "" {
		msg := fmt.Sprintf("already inside a watchdeck sandbox (%s=%s); nested runs are not allowed", ProfileEnvVar, envMap[ProfileEnvVar])
		say(msg)
		return rl.fail(ExitPolicy, activity.OutcomePolicyError, msg, nil)
	}
	if len(o.Argv) == 0 {
		msg := "nothing to run: give -- command [args...]"
		say(msg)
		return rl.fail(ExitUsage, activity.OutcomeUsage, msg, nil)
	}
	if !sandbox.Available() {
		msg := "enforcement is not available on this platform; refusing to start the MCP server unsandboxed"
		say(msg)
		return rl.fail(ExitUsage, activity.OutcomeUsage, msg, nil)
	}
	pol, err := ResolveMCP(o.Server, o.Env)
	if err != nil {
		say(err.Error())
		return rl.fail(ExitPolicy, activity.OutcomePolicyError, err.Error(), nil)
	}
	if pol.cwdIsHome && !o.AllowHomeCwd {
		msg := "the working directory is the home directory, so the server could write anywhere in it; not started. Start Claude Code in a project directory, or rewrap with watchdeck mcp wrap " + o.Server + " --allow-home-cwd"
		say(msg)
		return rl.fail(ExitPolicy, activity.OutcomePolicyError, msg, pol)
	}
	for _, w := range pol.Warnings {
		say("warning: " + w)
	}
	var childEnv []string
	allowed := map[string]bool{}
	for _, n := range pol.Effective.Env {
		allowed[n] = true
	}
	for _, n := range sortedKeys(envMap) {
		if allowed[n] && n != "TMPDIR" && n != ProfileEnvVar {
			childEnv = append(childEnv, n+"="+envMap[n])
		}
	}
	childEnv = append(childEnv, "TMPDIR="+pol.Resolved.Tmp, ProfileEnvVar+"="+pol.Hash)

	errTail := newTailWriter(o.Stderr, tailKeep)
	res, err := sandbox.Run(ctx, sandbox.Options{
		Profile: pol.Profile, Argv: o.Argv, Env: childEnv, Dir: o.Env.Cwd,
		Stdin: o.Stdin, Stdout: o.Stdout, Stderr: errTail,
	})
	switch {
	case errors.Is(err, sandbox.ErrApply):
		say("could not apply the sandbox (nested sandbox); the MCP server was not started")
		return rl.fail(ExitNoSandbox, activity.OutcomeNoSandbox, "could not apply the sandbox (nested sandbox)", pol)
	case errors.Is(err, sandbox.ErrProfile):
		say("the compiled profile was rejected by the OS (watchdeck bug, please report)")
		return rl.fail(ExitPolicy, activity.OutcomePolicyError, "the compiled profile was rejected by the OS", pol)
	case err != nil:
		say(err.Error())
		return rl.fail(ExitPolicy, activity.OutcomePolicyError, err.Error(), pol)
	}
	if res.ExitCode != 0 && !res.Signaled {
		fmt.Fprintf(o.Stderr, paths.Trailer+"MCP server %s exited %d under profile mcp:%s/%s (%s). Widen: edit launch.grant of subject mcp:%s in your overrides file, or rerun watchdeck mcp wrap with --network/--caches.\n",
			o.Server, res.ExitCode, o.Server, pol.Hash, pol.Effective.Summary(), o.Server)
	}
	outcome := activity.OutcomeOK
	switch {
	case res.Signaled:
		outcome = activity.OutcomeSignaled
	case res.ExitCode != 0:
		outcome = activity.OutcomeFailed
	}
	rl.done(res.ExitCode, outcome, "", pol, scanHints(nil, errTail.Tail(), res.ExitCode, pol.Resolved.ExecAny))
	return res.ExitCode
}

// mcpRunLog is runLog without the decision correlation.
type mcpRunLog struct{ runLog }

func newMCPRunLog(o MCPOptions) *mcpRunLog {
	rl := newRunLog(Options{Argv: o.Argv, Env: o.Env, ActivityPath: o.ActivityPath})
	// M6.4: the run names its subject; it has no skills, and its command is
	// the server's argv.
	rl.rec.Skills = nil
	rl.rec.Subject = &activity.Subject{Kind: "mcp", Name: o.Server}
	rl.rec.Enforcement = activity.EnforcementSandbox
	return &mcpRunLog{*rl}
}

func (rl *mcpRunLog) fail(code int, outcome, msg string, pol *Policy) int {
	rl.done(code, outcome, firstLine(msg), pol, nil)
	return code
}

func (rl *mcpRunLog) done(code int, outcome, errMsg string, pol *Policy, hints []activity.Hint) {
	if rl.path == "" {
		return
	}
	r := rl.rec
	r.Exit = &code
	r.Outcome = outcome
	r.Error = errMsg
	r.DurationMS = time.Since(rl.start).Milliseconds()
	r.Hints = hints
	if pol != nil {
		r.ProfileHash = pol.Hash
		v := pol.Effective.View()
		v.Deny = append(v.Deny, pol.ExtraDeny...)
		r.Effective = &v
		r.Warnings = pol.Warnings
	}
	r.TS = activity.Now()
	_ = activity.Append(rl.path, r)
}
