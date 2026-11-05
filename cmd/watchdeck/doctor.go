package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/activity"
	"github.com/Panda-Taps-LLC/watchdeck/internal/claudesettings"
	"github.com/Panda-Taps-LLC/watchdeck/internal/index"
	"github.com/Panda-Taps-LLC/watchdeck/internal/lifecycle"
	"github.com/Panda-Taps-LLC/watchdeck/internal/manifest"
	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
	"github.com/Panda-Taps-LLC/watchdeck/internal/policy"
	"github.com/Panda-Taps-LLC/watchdeck/internal/rulebook"
	"github.com/Panda-Taps-LLC/watchdeck/internal/rules"
	"github.com/Panda-Taps-LLC/watchdeck/internal/service"
	"github.com/Panda-Taps-LLC/watchdeck/internal/settings"
	"github.com/Panda-Taps-LLC/watchdeck/internal/skills"
	"github.com/Panda-Taps-LLC/watchdeck/internal/uistate"
	"github.com/Panda-Taps-LLC/watchdeck/internal/userconfig"
)

const doctorUsage = `usage: watchdeck doctor [--json] [--plugin] [--exit-zero] [--prove]

Checks the install and prints one pass/warn/fail line per check: the binary
(on PATH, and what the plugin's bin/hook.sh would find), the hooks in the
user and project settings and their settings.local.json (missing,
incomplete, duplicated, different binaries), the plugin and settings hooks
both active, two decisions logged for one tool call since the settings last
changed (the hook ran twice; older ones are a warning), the sandbox
exclusion while Claude Code's sandbox is on, when a hook was last seen, how
many sessions the lifecycle hooks show live and idle, and a sandbox
self-test. A settings file missing only the three lifecycle hooks (an M4
install) is a warning.

  --json       {"ok": bool, "checks": [{"name","status","message"}]}
  --plugin     treat the plugin as active ('claude --plugin-dir' leaves no
               trace in installed_plugins.json; /watchdeck:status passes it)
  --exit-zero  exit 0 even when a check fails (for slash commands)
  --prove      also run the hook your user-scope settings register (a
               project's settings are read, never run) against a built-in
               canary in a throwaway HOME (about a second): the rewrite, a
               denied network probe under the sandbox, a denied Read of
               ~/.ssh/id_fake, and that shadow mode is off

Exit codes: 0 no failures, 1 at least one check failed, 3 usage.
`

// Check status values.
const (
	statusPass = "pass"
	statusWarn = "warn"
	statusFail = "fail"
)

// doctorCheck is one line of the report.
type doctorCheck struct {
	Name    string `json:"name"`
	Status  string `json:"status"` // pass | warn | fail
	Message string `json:"message"`
}

type doctorReport struct {
	OK     bool          `json:"ok"`
	Checks []doctorCheck `json:"checks"`
	nested bool          // the sandbox self-test ran inside a sandbox (doctor --prove reads it)
}

// doctorDupWindow is how many recent decision records the duplicate check reads.
const doctorDupWindow = 2000

// hookCandidates are the install dirs plugin/bin/hook.sh tries after PATH, in order.
func hookCandidates(home string) []string { return paths.HookCandidates(home) }

func cmdDoctor(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, doctorUsage) }
	asJSON := fs.Bool("json", false, "")
	plugin := fs.Bool("plugin", false, "")
	exitZero := fs.Bool("exit-zero", false, "")
	proveFlag := fs.Bool("prove", false, "")
	if err := fs.Parse(args); err != nil {
		return 3
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "watchdeck doctor: unexpected argument %q\n", fs.Arg(0))
		return 3
	}
	rep := runDoctor(*plugin)
	if *proveFlag {
		doctorProve(&rep, *plugin)
	}
	if *asJSON {
		if code := writeJSON(stdout, stderr, rep); code != 0 {
			return code
		}
	} else {
		for _, c := range rep.Checks {
			fmt.Fprintf(stdout, "%-4s  %-18s %s\n", c.Status, c.Name, c.Message)
		}
	}
	if !rep.OK && !*exitZero {
		return 1
	}
	return 0
}

func runDoctor(forcePlugin bool) doctorReport {
	var rep doctorReport
	add := func(name, status, format string, a ...any) {
		rep.Checks = append(rep.Checks, doctorCheck{Name: name, Status: status, Message: fmt.Sprintf(format, a...)})
	}
	hp, env, err := hostPaths()
	if err != nil {
		add("home", statusFail, "%v", err)
		rep.OK = false
		return rep
	}
	cwd, _ := os.Getwd()
	root := paths.ProjectRoot(cwd, hp.Home)
	if root == "" {
		root = cwd
	}

	// plugin
	pluginOn, pluginID := forcePlugin, ""
	if id, on, err := skills.PluginActive(hp.ClaudeDir, root, paths.BinaryName); err != nil {
		add("plugin", statusWarn, "could not read the plugin registry: %v", err)
	} else if on {
		pluginOn, pluginID = true, id
	}
	switch {
	case pluginID != "":
		add("plugin", statusPass, "%s is installed and enabled", pluginID)
	case pluginOn:
		add("plugin", statusPass, "active (--plugin)")
	default:
		add("plugin", statusPass, "not installed; hooks come from the settings files")
	}

	// binary
	self, _ := selfPath()
	doctorBinary(add, self, hp.Home, pluginOn)

	// settings files: the same four Claude Code merges (and PluginActive reads)
	type fileState struct {
		label, path string
		local       bool // a settings.local.json: not shown when absent
	}
	userPath := hp.ClaudeSettings()
	files := []fileState{
		{label: "user settings", path: userPath},
		{label: "user local", path: filepath.Join(hp.ClaudeDir, "settings.local.json"), local: true},
	}
	if pp := paths.ProjectSettings(root); pp != userPath {
		files = append(files,
			fileState{label: "project settings", path: pp},
			fileState{label: "project local", path: filepath.Join(root, ".claude", "settings.local.json"), local: true})
	}
	anyHooks, sandboxOn, excluded := false, false, false
	var hookFiles []string
	// the registrations the policy needs, per target scope (reads the Claude
	// Code settings once each for coveredTwins)
	extraFor := map[bool]settings.Extra{false: policyExtra(false), true: policyExtra(true)}
	firstHook, firstProject := "", false // the first file with our hooks: the file-tools check reads it
	hookCmds := map[string]string{}      // hook command -> first file that names it
	var cmdOrder []string
	var changed time.Time // newest mtime of the files that decide registration
	if fi, err := os.Stat(filepath.Join(hp.ClaudeDir, "plugins", "installed_plugins.json")); err == nil {
		changed = fi.ModTime()
	}
	for _, f := range files {
		shown := displayHome(f.path, hp.Home)
		project := strings.HasPrefix(f.label, "project")
		st, err := settings.Inspect(f.path)
		if err != nil {
			add(f.label, statusFail, "%s: %v", shown, err)
			continue
		}
		if fi, err := os.Stat(f.path); err == nil && fi.ModTime().After(changed) {
			changed = fi.ModTime()
		}
		if !st.Exists && f.local {
			continue
		}
		sandboxOn = sandboxOn || st.SandboxEnabled
		excluded = excluded || st.Excluded
		n := st.Count()
		if n > 0 {
			if !anyHooks {
				firstHook, firstProject = f.path, project
			}
			anyHooks = true
			hookFiles = append(hookFiles, shown)
			if _, seen := hookCmds[st.HookCommand]; !seen {
				hookCmds[st.HookCommand] = shown
				cmdOrder = append(cmdOrder, st.HookCommand)
			}
		}
		dups, _ := settings.Duplicates(f.path)
		switch {
		case !st.Exists:
			add(f.label, statusPass, "%s: absent", shown)
		case len(dups) > 0:
			add(f.label, statusWarn, "%s: hook registered more than once (%s); watchdeck enforce uninstall%s removes every copy, then install once", shown, strings.Join(dups, ", "), projectFlag(project))
		case n == settings.HookCount:
			msg := fmt.Sprintf("%s: all %d hooks (%s)", shown, settings.HookCount, st.HookCommand)
			_, missing, _ := settings.ExtraStatus(f.path, extraFor[project])
			if bin := hookBinary(st.HookCommand); bin != "" && !isExecutable(bin) {
				add(f.label, statusFail, "%s; but %s is missing: rerun watchdeck setup", msg, bin)
			} else if len(missing) > 0 {
				// M6.3: the policy has rules or gates for tools no hook sees
				add(f.label, statusWarn, "%s; but the policy has rules for tools with no hook registered (%s): watchdeck enforce install%s adds them", msg, strings.Join(missing, ", "), projectFlag(project))
			} else {
				add(f.label, statusPass, "%s", msg)
			}
		case n > 0:
			add(f.label, statusWarn, "%s: %d of %d hooks, missing %s; watchdeck enforce install%s adds the rest", shown, n, settings.HookCount, strings.Join(st.Missing(), ", "), projectFlag(project))
		default:
			add(f.label, statusPass, "%s: no watchdeck hooks", shown)
		}
	}

	// registration as a whole
	switch {
	case pluginOn && anyHooks:
		add("registration", statusWarn, "the plugin and %s both register the hook, so each Bash call is decided twice; run watchdeck enforce uninstall (with --project for a project file)", strings.Join(hookFiles, " and "))
	case !pluginOn && !anyHooks:
		add("registration", statusFail, "no hooks registered: run watchdeck setup (or install the plugin)")
	case len(hookFiles) > 1:
		add("registration", statusWarn, "hooks come from %s: each Bash call is decided once per file; keep one", strings.Join(hookFiles, " and "))
	case pluginOn:
		add("registration", statusPass, "hooks come from the plugin")
	default:
		add("registration", statusPass, "hooks come from %s", strings.Join(hookFiles, " and "))
	}
	if anyHooks && !pluginOn {
		doctorFileTools(add, hp, firstHook, firstProject, extraFor[firstProject])
	}
	// The plugin's hooks.json is static: a gate on a tool it does not
	// register never fires (review 2026-10-14).
	if pluginOn {
		if miss := settings.PluginUncovered(extraFor[false]); len(miss) > 0 {
			add("plugin gates", statusFail, "the policy gates %s, which the plugin's hooks do not register, so those gates never fire; run watchdeck enforce install instead of the plugin's hooks", strings.Join(miss, ", "))
		} else {
			add("plugin gates", statusPass, "the plugin registers every tool the policy gates")
		}
	}
	if len(cmdOrder) > 1 {
		var parts []string
		for _, c := range cmdOrder {
			parts = append(parts, fmt.Sprintf("%s runs %s", hookCmds[c], c))
		}
		add("hook binaries", statusWarn, "the settings files run different binaries (%s); they may be different versions", strings.Join(parts, "; "))
	}

	// native rules: the recommended rules, and drift of the ones watchdeck added
	doctorNativeRules(add, hp, root)

	// exclusion
	switch {
	case sandboxOn && !excluded:
		add("sandbox exclusion", statusFail, "Claude Code's sandbox is on and %q is not in sandbox.excludedCommands: every sandboxed skill run fails closed (exit 126); run watchdeck setup", settings.ExcludedCommand)
	case sandboxOn:
		add("sandbox exclusion", statusPass, "Claude Code's sandbox is on and %q is excluded", settings.ExcludedCommand)
	default:
		add("sandbox exclusion", statusPass, "Claude Code's sandbox is off in these files; no exclusion needed")
	}

	// policy cache (M6.3): the hook reads the parsed policy from it
	{
		cwd, _ := os.Getwd()
		project := ""
		if root := index.ProjectRoot(cwd, hp.Home); root != "" {
			project = filepath.Join(root, manifest.ProjectOverridesFile)
		}
		cache := filepath.Join(hp.StateDir, policy.CacheFile)
		switch same, ok := policy.CacheMatchesFresh(cache, filepath.Join(hp.ConfigDir, "overrides.yaml"), project); {
		case !ok:
			add("policy cache", statusPass, "no current cache (the next hook call builds it)")
		case same:
			add("policy cache", statusPass, "matches the policy files")
		default:
			add("policy cache", statusWarn, "differs from the policy files; delete %s (the next hook call rebuilds it)", displayHome(cache, hp.Home))
		}
	}

	// shadow mode (Phase 6): watchdeck's own rules observe, nothing is enforced
	switch on, err := policy.ShadowOn(hp.OverridesFile()); {
	case err != nil:
		add("shadow mode", statusWarn, "unknown: %v", err)
	case on:
		add("shadow mode", statusWarn, "on: rules are observed, not enforced; turn enforcement on with: %s rules shadow off", paths.BinaryName)
	default:
		add("shadow mode", statusPass, "off: rules are enforced")
	}

	// activity: duplicates and last hook seen
	if hp.Activity == "" {
		add("activity log", statusWarn, "off (WATCHDECK_ACTIVITY=off): the duplicate and last-seen checks cannot run")
	} else {
		doctorActivity(add, hp.Activity, changed, time.Now())
	}

	// install date (Plan 02 Task 8)
	doctorInstalledAt(add, hp)

	// session lifecycle (M5.2)
	doctorLifecycle(add, lifecycle.Store{Log: hp.Sessions, Live: hp.LiveDir})

	// dashboard and service: information, a warning at most, never a failure
	doctorDashboard(add, hp, env)

	// sandbox self-test
	st := selfTest(context.Background(), env)
	switch {
	case st.Nested:
		rep.nested = true
		add("sandbox self-test", statusWarn, "%s (run doctor from a terminal to test)", selfTestLine(st))
	case st.OK():
		add("sandbox self-test", statusPass, "%s", strings.TrimPrefix(selfTestLine(st), "pass "))
	default:
		add("sandbox self-test", statusFail, "%s", strings.TrimPrefix(selfTestLine(st), "fail "))
	}

	finish(&rep)
	return rep
}

// finish sets rep.OK: true when no check failed.
func finish(rep *doctorReport) {
	rep.OK = true
	for _, c := range rep.Checks {
		if c.Status == statusFail {
			rep.OK = false
		}
	}
}

// doctorNativeRules reports how many recommended rules the Claude Code
// settings for root hold, and the strings watchdeck added that the person
// has since removed by hand. Those are reported, not dropped: the ledger is
// reconciled on a copy and never saved, so the next write transaction is
// what drops them. A user settings file that exists but cannot be parsed
// fails: Claude Code ignores it.
func doctorNativeRules(add func(name, status, format string, a ...any), hp paths.Paths, root string) {
	const name = "native rules"
	total := len(rulebook.Recommended())
	eff, err := readNative(hp, root)
	if err != nil {
		add(name, statusFail, "%s cannot be read (%v): Claude Code ignores its rules; fix or remove it", displayHome(hp.ClaudeSettings(), hp.Home), err)
		return
	}
	var parts []string
	status := statusPass
	owned := 0
	if led, err := claudesettings.LoadLedger(hp.StateDir); err != nil {
		status = statusWarn
		parts = append(parts, fmt.Sprintf("could not read which rules watchdeck added: %v", err))
	} else {
		cp := &claudesettings.Ledger{V: led.V, Entries: append([]claudesettings.LedgerEntry(nil), led.Entries...)}
		var gone []string
		for _, d := range claudesettings.Reconcile(cp, eff) {
			gone = append(gone, d.Entry.Value)
		}
		owned = len(cp.Entries)
		if k := len(gone); k > 0 {
			sort.Strings(gone)
			status = statusWarn
			verb := "were"
			if k == 1 {
				verb = "was"
			}
			parts = append(parts, fmt.Sprintf("%d rule%s watchdeck added %s removed by hand: %s", k, plural(k), verb, strings.Join(gone, ", ")))
		}
	}
	if k := len(rulebook.RecommendedMissing(eff)); k > 0 {
		status = statusWarn
		parts = append(parts, fmt.Sprintf("recommended rules not installed (%d of %d): watchdeck rules recommended --install", k, total))
	}
	if status == statusPass {
		add(name, statusPass, "%d of %d recommended rules installed; %d rule%s added by watchdeck, none drifted", total, total, owned, plural(owned))
		return
	}
	add(name, status, "%s", strings.Join(parts, "; "))
}

// doctorInstalledAt reports the install date setup recorded in config.yaml.
// A missing date is a warning: it only means setup has not completed on this
// machine (enforce install alone does not record it).
func doctorInstalledAt(add func(name, status, format string, a ...any), hp paths.Paths) {
	cfg, err := userconfig.Load(hp.ConfigFile())
	if err != nil {
		add("install date", statusWarn, "%s does not parse: %v", displayHome(hp.ConfigFile(), hp.Home), err)
		return
	}
	if t, ok := cfg.InstalledAt(); ok {
		add("install date", statusPass, "installed since %s", t.UTC().Format("2006-01-02"))
		return
	}
	add("install date", statusWarn, "not recorded (watchdeck setup records it when it completes)")
}

func doctorBinary(add func(name, status, format string, a ...any), self, home string, pluginOn bool) {
	onPath, err := exec.LookPath(paths.BinaryName)
	if err == nil {
		real := onPath
		if r, err := filepath.EvalSymlinks(onPath); err == nil {
			real = r
		}
		if self != "" && real != self {
			add("binary", statusWarn, "PATH finds %s, but this is %s: the hook runs the one on PATH", onPath, self)
			return
		}
		add("binary", statusPass, "on PATH: %s", onPath)
		return
	}
	for _, c := range hookCandidates(home) {
		if isExecutable(c) {
			status := statusWarn
			msg := fmt.Sprintf("not on PATH; the plugin's hook.sh finds %s", displayHome(c, home))
			if pluginOn {
				status = statusPass
			}
			add("binary", status, "%s", msg)
			return
		}
	}
	if pluginOn {
		add("binary", statusFail, "not on PATH nor in ~/.local/share/watchdeck/bin, /opt/homebrew/bin, /usr/local/bin: the plugin's hook does nothing")
		return
	}
	add("binary", statusWarn, "not on PATH (settings hooks use an absolute path, so they still work)")
}

// doctorActivity reports duplicate decisions and when a hook was last seen.
// A tool call decided twice after changed (the newest mtime of the settings
// files and plugin registry doctor inspected) is a failure: the current
// registration runs the hook twice. Duplicates from before that are history,
// fixed or not: a warning at most.
func doctorActivity(add func(name, status, format string, a ...any), path string, changed, now time.Time) {
	res, err := activity.Read(path, activity.ReadOptions{Tail: doctorDupWindow, Kinds: []string{activity.KindDecision}})
	if err != nil {
		add("double hook", statusWarn, "could not read the activity log: %v", err)
	} else {
		count := map[string]int{}
		latest := map[string]time.Time{}
		for _, r := range res.Records {
			if r.ToolUseID == "" {
				continue
			}
			count[r.ToolUseID]++
			if t, err := time.Parse(time.RFC3339Nano, r.TS); err == nil && t.After(latest[r.ToolUseID]) {
				latest[r.ToolUseID] = t
			}
		}
		var recent, old []string
		for id, n := range count {
			if n < 2 {
				continue
			}
			if latest[id].After(changed) {
				recent = append(recent, id)
			} else {
				old = append(old, id)
			}
		}
		sort.Strings(recent)
		sort.Strings(old)
		switch {
		case len(recent) > 0:
			add("double hook", statusFail, "%d tool call%s since the settings last changed got two or more decisions (e.g. %s): the hook is registered twice; see the registration check", len(recent), plural(len(recent)), recent[0])
		case len(old) > 0:
			add("double hook", statusWarn, "%d tool call%s got two decisions before the settings last changed (%s), e.g. %s; none since", len(old), plural(len(old)), changed.Local().Format(time.RFC3339), old[0])
		default:
			add("double hook", statusPass, "no tool call decided twice in the last %d decisions", len(res.Records))
		}
	}
	var newest time.Time
	for _, k := range []string{activity.KindDecision, activity.KindSkillInvoked, activity.KindDenied} {
		r, ok, err := activity.LastOfKind(path, k)
		if err != nil || !ok {
			continue
		}
		if t, err := time.Parse(time.RFC3339Nano, r.TS); err == nil && t.After(newest) {
			newest = t
		}
	}
	if newest.IsZero() {
		add("last hook seen", statusWarn, "never: no hook record in the activity log yet (start a Claude Code session and run a skill)")
		return
	}
	add("last hook seen", statusPass, "%s ago (%s)", ago(now.Sub(newest)), newest.Local().Format("2006-01-02 15:04"))
}

// doctorLifecycle reports how many sessions the lifecycle records show live
// and idle. Off is a warning; nothing recorded yet is a pass that says so.
func doctorLifecycle(add func(name, status, format string, a ...any), st lifecycle.Store) {
	if st.Off() {
		add("sessions", statusWarn, "lifecycle records off (WATCHDECK_LIFECYCLE=off): live sessions cannot be shown")
		return
	}
	ss, err := st.List()
	if err != nil {
		add("sessions", statusWarn, "could not read the lifecycle records: %v", err)
		return
	}
	if len(ss) == 0 {
		add("sessions", statusPass, "no session recorded yet (the lifecycle hooks record the next one that starts)")
		return
	}
	live, idle, ended, _ := lifecycle.Counts(ss)
	add("sessions", statusPass, "%d live, %d idle, %d ended", live, idle, ended)
}

// doctorDashboard reports the running dashboard (uistate: lock held and an
// authenticated /api/status answered), the autostart setting, and the login
// service. None of them fails the report.
func doctorDashboard(add func(name, status, format string, a ...any), hp paths.Paths, env map[string]string) {
	auto := "autostart off"
	if uistate.AutostartOn(hp, env) {
		auto = "autostart on"
	}
	inst, err := uistate.Running(context.Background(), hp)
	switch {
	case err == nil:
		add("dashboard", statusPass, "running: pid %d, %s mode, port %d (%s)", inst.State.PID, inst.Status.Mode, inst.State.Port, auto)
	case errors.Is(err, uistate.ErrNotRunning):
		add("dashboard", statusPass, "not running; watchdeck ui opens it (%s)", auto)
	case errors.Is(err, uistate.ErrUnhealthy):
		add("dashboard", statusWarn, "a process holds %s but did not answer a health check within %s; watchdeck ui --stop, or end that process", displayHome(uistate.Path(hp, uistate.LockFile), hp.Home), uistate.ProbeTimeout)
	default:
		add("dashboard", statusWarn, "could not check: %v", err)
	}

	o, err := serviceOptions()
	if err != nil {
		add("service", statusWarn, "could not check: %v", err)
		return
	}
	st, err := service.Status(o)
	switch {
	case errors.Is(err, service.ErrUnsupported):
		add("service", statusPass, "not available on this platform")
	case err != nil:
		add("service", statusWarn, "could not check: %v", err)
	case !st.Installed:
		add("service", statusPass, "not installed (optional: watchdeck service install)")
	case st.Loaded:
		add("service", statusPass, "installed and loaded (%s)%s", displayHome(st.File, hp.Home), detail(st.Detail))
	default:
		add("service", statusWarn, "%s is installed but not loaded; watchdeck service install loads it again", displayHome(st.File, hp.Home))
	}
}

// ago renders a duration for people: seconds, minutes, hours and minutes, days.
func ago(d time.Duration) string {
	switch {
	case d < 0:
		return "0s"
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d/time.Second))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d/time.Minute))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh %dm", int(d/time.Hour), int(d%time.Hour/time.Minute))
	default:
		return fmt.Sprintf("%dd", int(d/(24*time.Hour)))
	}
}

// hookBinary is the executable of a hook command when it is an absolute
// path (the exec form `enforce install` writes); "" otherwise.
func hookBinary(cmd string) string {
	if strings.HasPrefix(cmd, "/") && !strings.ContainsAny(cmd, " \t") {
		return cmd
	}
	return ""
}

func isExecutable(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0o111 != 0
}

// doctorFileTools adds the "file tools" check for the settings file at path
// (the first that holds our hooks): for each file tool, whether our hook
// watches it there and whether the policy needs it (need, from policyExtra
// for that file's scope), grouped into one line in policy.FileTools order:
// hooked and needed (with the first reason), needed but not hooked (warn),
// hooked though nothing needs it, not hooked because a native twin covers
// its rules, and not hooked with no enabled rule for it.
func doctorFileTools(add func(name, status, format string, a ...any), hp paths.Paths, path string, project bool, need settings.Extra) {
	hookedList, err := settings.HookedFileTools(path)
	if err != nil {
		return // the per-file check already reported it
	}
	hooked := map[string]bool{}
	for _, t := range hookedList {
		hooked[t] = true
	}
	needed, wild := map[string]bool{}, false
	for _, m := range need.Pre {
		switch {
		case m == settings.MatcherAnyTool || m == settings.MatcherAll:
			wild = true
			for _, t := range policy.FileTools {
				needed[t] = true
			}
		case settings.IsFileMatcher(m):
			for _, t := range strings.Split(m, "|") {
				needed[t] = true
			}
		}
	}
	_, _, root := policyFiles(hp)
	covered, nativeAll := nativeState(hp, nativeRoot(project, root))
	user, projectPolicy, _ := policyFiles(hp)
	pol, _, perr := policy.Load(user, projectPolicy)
	var cfg rules.Config
	if perr == nil {
		cfg = pol.RulesConfig()
	}
	reason := func(tools []string) string {
		switch {
		case wild:
			return "a rule that names every tool"
		case perr != nil:
			return "a policy file that does not load"
		}
		for _, t := range tools {
			if r := pol.FileNeed(cfg, covered, t); r != "" {
				return r
			}
		}
		return "a rule"
	}
	// nativeCovered: some enabled pack rule for t has its native twin installed
	nativeCovered := func(t string) bool {
		for _, r := range rules.RulesFor(cfg, t) {
			if slices.Contains(covered, r.ID) {
				return true
			}
		}
		return false
	}
	var hn, mn, hx, nc, nw []string
	for _, t := range policy.FileTools {
		switch {
		case needed[t] && hooked[t]:
			hn = append(hn, t)
		case needed[t]:
			mn = append(mn, t)
		case hooked[t]:
			hx = append(hx, t)
		case perr == nil && nativeCovered(t):
			nc = append(nc, t)
		default:
			nw = append(nw, t)
		}
	}
	list := func(ts []string) string { return strings.Join(ts, ", ") }
	pron := func(ts []string) string {
		if len(ts) == 1 {
			return "it"
		}
		return "them"
	}
	install := "watchdeck enforce install" + projectFlag(project)
	var parts []string
	status := statusPass
	if len(hn) > 0 {
		parts = append(parts, fmt.Sprintf("hooked for %s (%s)", list(hn), reason(hn)))
	}
	if len(mn) > 0 {
		status = statusWarn
		note := ""
		if !nativeAll {
			note = " (the recommended Claude Code rules are not all installed)"
		}
		why := reason(mn)
		if !strings.Contains(why, " asks before ") { // "X asks before a read" is already a sentence
			why += " needs it"
		}
		parts = append(parts, fmt.Sprintf("%s not hooked but %s%s: %s", list(mn), why, note, install))
	}
	if len(hx) > 0 {
		parts = append(parts, fmt.Sprintf("%s hooked though nothing needs it (%s drops %s)", list(hx), install, pron(hx)))
	}
	var ncReads, ncEdits []string
	for _, t := range nc {
		if t == "Read" {
			ncReads = append(ncReads, t)
		} else {
			ncEdits = append(ncEdits, t)
		}
	}
	if len(ncReads) > 0 {
		parts = append(parts, fmt.Sprintf("%s not hooked, the recommended Claude Code rules cover reads", list(ncReads)))
	}
	if len(ncEdits) > 0 {
		parts = append(parts, fmt.Sprintf("%s not hooked, the recommended Claude Code rules cover edits", list(ncEdits)))
	}
	if len(nw) > 0 {
		parts = append(parts, fmt.Sprintf("%s not hooked, no enabled rule watches %s", list(nw), pron(nw)))
	}
	add("file tools", status, "%s", strings.Join(parts, "; "))
}
