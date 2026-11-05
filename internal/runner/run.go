package runner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/activity"
	"github.com/Panda-Taps-LLC/watchdeck/internal/manifest"
	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
	"github.com/Panda-Taps-LLC/watchdeck/internal/sandbox"
	"github.com/Panda-Taps-LLC/watchdeck/internal/shellparse"
)

// Exit codes owned by watchdeck itself; everything else is the child's.
const (
	ExitUsage     = 3   // bad arguments or unsupported platform
	ExitPolicy    = 125 // unknown skill, malformed manifest, nested run, profile bug
	ExitNoSandbox = 126 // the sandbox could not be applied (fail closed)
)

// ProfileEnvVar marks a process that already runs under a watchdeck profile.
const ProfileEnvVar = "WATCHDECK_PROFILE"

// Options for Run.
type Options struct {
	Skills []string
	// CommandSubject names a user command subject (M6.3: run --subject
	// command:<name>); it replaces Skills.
	CommandSubject string
	Command        string   // -c form: a shell string run with /bin/bash -c
	Argv           []string // -- form
	Env            Env
	Environ        []string // the parent environment (os.Environ())
	Stdin          io.Reader
	Stdout         io.Writer
	Stderr         io.Writer
	// ActivityPath is the activity log; "" = off. Every Run appends exactly
	// one run record there, whatever the outcome.
	ActivityPath string
}

// Run resolves the policy and executes under it. Returns the process exit
// code, and appends one run record (activity.KindRun) for every outcome.
func Run(ctx context.Context, o Options) int {
	if o.Stderr == nil {
		o.Stderr = os.Stderr
	}
	if o.Stdout == nil {
		o.Stdout = os.Stdout
	}
	rl := newRunLog(o)
	envMap := paths.EnvMap(o.Environ)
	if o.Env.Environ == nil {
		o.Env.Environ = envMap
	}
	if envMap[ProfileEnvVar] != "" {
		msg := fmt.Sprintf("already inside a watchdeck sandbox (%s=%s); nested runs are not allowed", ProfileEnvVar, envMap[ProfileEnvVar])
		fmt.Fprintln(o.Stderr, paths.Trailer+msg)
		return rl.fail(ExitPolicy, activity.OutcomePolicyError, msg, nil)
	}
	if o.Command == "" && len(o.Argv) == 0 {
		msg := "nothing to run: give -c 'command' or -- argv..."
		fmt.Fprintln(o.Stderr, paths.Trailer+msg)
		return rl.fail(ExitUsage, activity.OutcomeUsage, msg, nil)
	}
	if !sandbox.Available() {
		msg := "enforcement is not available on this platform; refusing to run unsandboxed"
		fmt.Fprintln(o.Stderr, paths.Trailer+msg)
		return rl.fail(ExitUsage, activity.OutcomeUsage, msg, nil)
	}

	var pol *Policy
	var err error
	if o.CommandSubject != "" {
		pol, err = ResolveCommandSubject(o.CommandSubject, o.Env, o.Command != "")
	} else {
		pol, err = Resolve(o.Skills, o.Env, o.Command != "")
	}
	if err != nil {
		fmt.Fprintf(o.Stderr, paths.Trailer+"%v\n", err)
		return rl.fail(ExitPolicy, activity.OutcomePolicyError, err.Error(), nil)
	}
	for _, w := range pol.Warnings {
		fmt.Fprintf(o.Stderr, paths.Trailer+"warning: %s\n", w)
	}

	// child environment: only the allowed names, plus TMPDIR and the marker
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

	argv := o.Argv
	if o.Command != "" {
		argv = []string{"/bin/bash", "-c", o.Command}
	}
	// Both streams are forwarded verbatim; only their tails are kept, and only
	// lines that read like a denial end up in the record.
	outTail := newTailWriter(o.Stdout, tailKeep)
	errTail := newTailWriter(o.Stderr, tailKeep)
	res, err := sandbox.Run(ctx, sandbox.Options{
		Profile: pol.Profile, Argv: argv, Env: childEnv, Dir: o.Env.Cwd,
		Stdin: o.Stdin, Stdout: outTail, Stderr: errTail,
	})
	switch {
	case errors.Is(err, sandbox.ErrApply):
		fmt.Fprintln(o.Stderr, paths.Trailer+"could not apply the sandbox (nested sandbox). If Claude Code's sandbox is on, add \""+paths.BinaryName+" run *\" to sandbox.excludedCommands in ~/.claude/settings.json, or run: watchdeck enforce install")
		return rl.fail(ExitNoSandbox, activity.OutcomeNoSandbox, "could not apply the sandbox (nested sandbox)", pol)
	case errors.Is(err, sandbox.ErrProfile):
		fmt.Fprintf(o.Stderr, paths.Trailer+"the compiled profile was rejected by the OS (watchdeck bug, please report):\n%s\n", pol.Profile)
		return rl.fail(ExitPolicy, activity.OutcomePolicyError, "the compiled profile was rejected by the OS", pol)
	case err != nil:
		fmt.Fprintf(o.Stderr, paths.Trailer+"%v\n", err)
		return rl.fail(ExitPolicy, activity.OutcomePolicyError, err.Error(), pol)
	}
	if res.ExitCode != 0 {
		writeTrailer(o.Stderr, pol, res.ExitCode)
	}
	outcome := activity.OutcomeOK
	switch {
	case res.Signaled:
		outcome = activity.OutcomeSignaled
	case res.ExitCode != 0:
		outcome = activity.OutcomeFailed
	}
	rl.done(res.ExitCode, outcome, "", pol, scanHints(outTail.Tail(), errTail.Tail(), res.ExitCode, pol.Resolved.ExecAny))
	return res.ExitCode
}

// RecordUsage appends the run record for a usage error found before Run
// (bad flags in the CLI): outcome usage, exit 3, msg as the error.
func RecordUsage(o Options, msg string) {
	newRunLog(o).fail(ExitUsage, activity.OutcomeUsage, msg, nil)
}

// runLog builds and appends the one run record of a Run.
type runLog struct {
	path  string
	start time.Time
	rec   activity.Record
}

func newRunLog(o Options) *runLog {
	rl := &runLog{path: o.ActivityPath, start: time.Now()}
	rl.rec = activity.Record{
		Kind:    activity.KindRun,
		Harness: activity.HarnessClaudeCode,
		Skills:  sortedUnique(o.Skills),
		Command: commandText(o),
		Backend: backend(),
	}
	if o.Env.Cwd != "" {
		rl.rec.Cwd = filepath.Clean(o.Env.Cwd)
	}
	rl.rec.Enforcement = activity.EnforcementSandbox
	if o.CommandSubject != "" {
		rl.rec.Skills = nil
		rl.rec.Subject = &activity.Subject{Kind: "command", Name: o.CommandSubject}
	} else if len(rl.rec.Skills) == 1 {
		rl.rec.Subject = &activity.Subject{Kind: "skill", Name: rl.rec.Skills[0]}
	}
	return rl
}

// fail records an outcome where the command did not run (or the sandbox
// failed around it) and returns code.
func (rl *runLog) fail(code int, outcome, msg string, pol *Policy) int {
	rl.done(code, outcome, firstLine(msg), pol, nil)
	return code
}

// done fills the outcome, correlates the record with the hook decision that
// caused this run (write time, see activity.Correlate) and appends it. Errors
// are ignored: the log never changes the run's result.
func (rl *runLog) done(code int, outcome, errMsg string, pol *Policy, hints []activity.Hint) {
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
	// Correlate against the start time: the decision preceded the run, and a
	// long run must not age its own decision out of the window.
	r.TS = rl.start.UTC().Format(time.RFC3339Nano)
	r = activity.Correlate(rl.path, r)
	r.TS = activity.Now()
	_ = activity.Append(rl.path, r)
}

// commandText is the -c payload exactly as given, or the argv quoted for bash.
func commandText(o Options) string {
	if o.Command != "" {
		return o.Command
	}
	q := make([]string, len(o.Argv))
	for i, a := range o.Argv {
		q[i] = shellparse.Quote(a)
	}
	return strings.Join(q, " ")
}

func backend() string {
	switch runtime.GOOS {
	case "darwin":
		return "seatbelt"
	case "linux":
		return "bwrap"
	}
	return ""
}

func sortedUnique(names []string) []string {
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

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// writeTrailer explains a non-zero exit in terms of the policy.
func writeTrailer(w io.Writer, pol *Policy, code int) {
	fmt.Fprintf(w, paths.Trailer+"exit %d under profile %s/%s (%s).\n", code, pol.label(), pol.Hash, pol.Effective.Summary())
	for _, u := range pol.Ungranted {
		// "<skill>: <kind>: <value>"; the skill name is validated, the value
		// comes from the skill's PERMISSIONS.yaml. The record keeps it raw.
		name, item, _ := strings.Cut(u, ": ")
		fmt.Fprintf(w, paths.Trailer+"  requested but not granted: %s: %s\n", name, manifest.DisplayUngranted(item))
	}
	for _, ig := range pol.Ignored {
		fmt.Fprintf(w, paths.Trailer+"  %s\n", ig)
	}
	if len(pol.Skills) == 0 {
		fmt.Fprintf(w, paths.Trailer+"If this is a permission error, the policy caused it. Widen the %s subject's grant in overrides.yaml (watchdeck paths shows where).\n", pol.label())
		return
	}
	if len(pol.Skills) == 1 {
		fmt.Fprintf(w, paths.Trailer+"If this is a permission error, the policy caused it. Widen: watchdeck allow %s --network all | --write <path> | --caches\n", pol.Skills[0])
	} else {
		// The effective policy is the intersection of every skill's grant,
		// so widening one skill alone changes nothing (review 2026-10-14).
		fmt.Fprintln(w, paths.Trailer+"If this is a permission error, the policy caused it. The run gets only what every skill named is granted; widen each one:")
		for _, n := range pol.Skills {
			fmt.Fprintf(w, paths.Trailer+"  watchdeck allow %s --network all | --write <path> | --caches\n", n)
		}
	}
	if !pol.Effective.ExecAny {
		// Dogfood 2026-10-12: a pyenv shim on PATH is not on the manifest's exec
		// list, the run dies with "bad interpreter", and allow has no exec flag.
		fmt.Fprintln(w, paths.Trailer+"exec is an allow-list here: \"bad interpreter\" or \"Operation not permitted\" on a program means it is not listed. Add it to the skill's PERMISSIONS.yaml exec list (a version-manager shim such as pyenv needs the shim and the real interpreter); watchdeck allow has no exec flag in v0.1.")
	}
}

func sortedKeys(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
