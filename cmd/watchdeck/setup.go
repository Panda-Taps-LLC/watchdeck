package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/audit"
	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
	"github.com/Panda-Taps-LLC/watchdeck/internal/rulebook"
	"github.com/Panda-Taps-LLC/watchdeck/internal/runner"
	"github.com/Panda-Taps-LLC/watchdeck/internal/settings"
	"github.com/Panda-Taps-LLC/watchdeck/internal/skills"
	"github.com/Panda-Taps-LLC/watchdeck/internal/userconfig"
)

const setupUsage = `usage: watchdeck setup [--yes] [--project] [--file PATH] [--plugin] [--exclusion-only]

Gets watchdeck working in Claude Code, one confirmed step at a time:

  1. sandbox self-test: a temp profile and a tiny canary (python3 when found,
     else /bin/sh; the output says which)
  2. a short audit of the installed skills
  3. rules: the recommended Claude Code rules (12 Read and Edit rules in
     permissions.deny and permissions.ask of the user settings file) that are
     not there yet, default yes, with a .bak-<ts> backup; watchdeck records
     the ones it adds so uninstall removes only those. A No is remembered:
     those rules are not offered again (watchdeck rules recommended
     --undecline all offers them again); --yes adds only the ones offered
  4. hooks: when the watchdeck plugin is active, only the sandbox exclusion
     "` + paths.BinaryName + ` run *" is added to the settings (the plugin brings its own
     hooks); otherwise the six hooks and the exclusion, as
     'watchdeck enforce install' does, with a .bak-<ts> backup
  5. dashboard: whether to start it with each Claude Code session
     (ui.autostart in config.yaml; asked on a terminal only, default no;
     --yes keeps the current answer)

  --yes             apply without asking
  --project         edit <git root>/.claude/settings.json instead of the user file
  --file PATH       edit this settings file instead
  --plugin          treat the plugin as active (for 'claude --plugin-dir', which
                    leaves no trace in installed_plugins.json)
  --exclusion-only  add only the sandbox exclusion in step 4; skip steps 1, 2
                    and 5 (step 3 still runs)

Without a terminal and without --yes, setup prints what it would change and
exits 1. Exit codes: 0 done (or nothing to do), 1 declined, refused or the
self-test failed, 2 an error, 3 usage.
`

// selfTest is the sandbox self-test; tests replace it.
var selfTest = runner.SandboxSelfTest

// console is the terminal side of an interactive command.
type console struct {
	in     *bufio.Reader
	out    io.Writer
	errw   io.Writer
	tty    bool // stdin is a terminal: questions can be asked
	assume bool // --yes
}

func newConsole(stdout, stderr io.Writer, yes bool) *console {
	return &console{in: bufio.NewReader(os.Stdin), out: stdout, errw: stderr, tty: isTerminal(os.Stdin.Fd()), assume: yes}
}

// ask asks a yes/no question; an empty answer takes def. With --yes it
// answers def without asking. ok is false when no answer can be had (no
// terminal, end of input).
func (c *console) ask(question string, def bool) (yes, ok bool) {
	if c.assume {
		return def, true
	}
	if !c.tty {
		return false, false
	}
	hint := "[y/N]"
	if def {
		hint = "[Y/n]"
	}
	fmt.Fprintf(c.out, "%s %s ", question, hint)
	line, err := c.in.ReadString('\n')
	if err != nil && line == "" {
		fmt.Fprintln(c.out)
		return false, false
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "":
		return def, true
	case "y", "yes":
		return true, true
	default:
		return false, true
	}
}

func cmdSetup(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, setupUsage) }
	yes := fs.Bool("yes", false, "")
	project := fs.Bool("project", false, "")
	file := fs.String("file", "", "")
	plugin := fs.Bool("plugin", false, "")
	exclusionOnly := fs.Bool("exclusion-only", false, "")
	if err := fs.Parse(args); err != nil {
		return 3
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "watchdeck setup: unexpected argument %q\n", fs.Arg(0))
		return 3
	}
	return runSetup(newConsole(stdout, stderr, *yes), setupOptions{project: *project, file: *file, plugin: *plugin, exclusionOnly: *exclusionOnly})
}

type setupOptions struct {
	project, plugin, exclusionOnly bool
	file                           string
}

func runSetup(c *console, o setupOptions) int {
	out := c.out
	fail := func(code int, format string, a ...any) int {
		fmt.Fprintf(c.errw, "watchdeck setup: "+format+"\n", a...)
		return code
	}
	hp, env, err := hostPaths()
	if err != nil {
		return fail(2, "%v", err)
	}
	cwd, _ := os.Getwd()
	path, err := settingsPath(o.project, o.file)
	if err != nil {
		return fail(2, "%v", err)
	}
	bin, err := installBinary()
	if err != nil {
		return fail(2, "%v", err)
	}

	step := 0
	next := func(title string) {
		step++
		fmt.Fprintf(out, "%d. %s\n", step, title)
	}

	if !o.exclusionOnly {
		next("Sandbox self-test")
		st := selfTest(context.Background(), env)
		fmt.Fprintf(out, "   %s\n", selfTestLine(st))
		if !st.OK() && !st.Nested {
			fmt.Fprintln(out, "   Enforcement does not work on this machine; nothing was changed.")
			return 1
		}

		next("Skills")
		for _, l := range auditSummary(hp, cwd) {
			fmt.Fprintf(out, "   %s\n", l)
		}
	}

	// Rules before Hooks: the hooks plan (policyExtra) reads the native
	// rules, so a file tool the recommended rules now cover is not hooked.
	next("Rules")
	pending, err := setupRules(c, hp, nativeRoot(o.project, paths.ProjectRoot(cwd, hp.Home)))
	if err != nil {
		return fail(2, "%v", err)
	}

	next("Hooks")
	pluginID, pluginOn := "", o.plugin
	if !pluginOn {
		root := paths.ProjectRoot(cwd, hp.Home)
		if root == "" {
			root = cwd
		}
		id, on, perr := skills.PluginActive(hp.ClaudeDir, root, paths.BinaryName)
		if perr != nil {
			fmt.Fprintf(out, "   could not read the plugin registry (%v); assuming no plugin\n", perr)
		}
		pluginID, pluginOn = id, on
	}
	onlyExclusion := o.exclusionOnly || pluginOn
	switch {
	case o.exclusionOnly:
		fmt.Fprintln(out, "   sandbox exclusion only (--exclusion-only)")
	case pluginOn && pluginID != "":
		fmt.Fprintf(out, "   the watchdeck plugin (%s) is active and registers the hooks; the settings get only the sandbox exclusion\n", pluginID)
	case pluginOn:
		fmt.Fprintln(out, "   the watchdeck plugin is active (--plugin) and registers the hooks; the settings get only the sandbox exclusion")
	default:
		fmt.Fprintln(out, "   no watchdeck plugin found: the hooks go into the settings file")
	}
	if pluginOn && !o.exclusionOnly {
		if st, err := settings.Inspect(path); err == nil && st.Count() > 0 {
			fmt.Fprintf(out, "   warning: %s also registers the hook, so it runs twice; remove it with: watchdeck enforce uninstall%s, then rerun setup\n", displayHome(path, hp.Home), projectFlag(o.project))
		}
	}
	var extra settings.Extra
	if !onlyExclusion {
		extra = policyExtra(o.project) // M6.3: only the tool groups the policy has rules for
	}
	plan, err := settings.PlanWith(path, bin, onlyExclusion, extra)
	if err != nil {
		return fail(2, "%v", err)
	}
	declined := false
	if len(plan) == 0 {
		fmt.Fprintf(out, "   %s: already set up, nothing to change\n", displayHome(path, hp.Home))
	} else {
		fmt.Fprintf(out, "   %s will get:\n", displayHome(path, hp.Home))
		for _, a := range plan {
			fmt.Fprintf(out, "     + %s\n", a)
		}
		yes, ok := c.ask("   Apply? (a .bak-<ts> backup is written first)", true)
		switch {
		case !ok:
			fmt.Fprintln(out, "   (not applied: no terminal to confirm on)")
			pending = true
		case !yes:
			fmt.Fprintln(out, "   settings unchanged")
			declined = true
		default:
			var ch settings.Change
			if onlyExclusion {
				ch, err = settings.InstallExclusion(path)
			} else {
				ch, err = settings.InstallWith(path, bin, extra)
			}
			if err != nil {
				return fail(2, "%v", err)
			}
			fmt.Fprintf(out, "   wrote %s\n", displayHome(path, hp.Home))
			if ch.Backup != "" {
				fmt.Fprintf(out, "   backup: %s\n", displayHome(ch.Backup, hp.Home))
			}
		}
	}
	if pending {
		return notApplied(c)
	}
	if !o.exclusionOnly {
		next("Dashboard")
		setupAutostart(c, hp)
	}
	if !o.exclusionOnly {
		fmt.Fprintln(out)
		fmt.Fprintln(out, "Next: watchdeck demo (see a denial), watchdeck doctor (check the install)")
	}
	if declined {
		return 1
	}
	// Every successful completion records the install date when unset: the
	// first one wins, on the settings, plugin and exclusion-only paths alike.
	// A failed save never fails setup.
	if err := userconfig.SetInstalledAt(hp.ConfigFile(), time.Now()); err != nil {
		fmt.Fprintf(out, "   could not record the install date: %v\n", err)
	}
	return 0
}

// setupRules offers the recommended Claude Code rules root's settings do
// not hold yet and the person has not declined (rulebook.RecommendedOffer)
// and, on yes (the default, and --yes), adds them to the user settings
// file. A No is remembered: every offered rule goes on the declined list,
// so a later setup (or --yes) does not offer it again. When every missing
// rule was declined earlier the step says so and asks nothing. pending is
// true when no answer could be had (no terminal, no --yes). A settings
// file that cannot be read is reported and skipped: the Hooks step names
// it.
func setupRules(c *console, hp paths.Paths, root string) (pending bool, err error) {
	out := c.out
	file := displayHome(hp.ClaudeSettings(), hp.Home)
	missing, err := recommendedMissing(hp, root)
	if err != nil {
		fmt.Fprintf(out, "   could not read %s (%v); recommended rules not added\n", file, err)
		return false, nil
	}
	if len(missing) == 0 {
		fmt.Fprintf(out, "   all %d recommended rules are in your Claude Code settings\n", len(rulebook.Recommended()))
		return false, nil
	}
	in := rulebook.Input{Paths: hp, ProjectRoot: root}
	reconcileBeforeInstall(c.errw, "   ", in)
	warnDeclined(c.errw, "   ", hp.StateDir, false)
	offer := rulebook.RecommendedOffer(in, missing, false)
	if len(offer) == 0 {
		fmt.Fprintf(out, "   Recommended rules: declined earlier (%s rules recommended --undecline all)\n", paths.BinaryName)
		return false, nil
	}
	if n := len(missing) - len(offer); n > 0 {
		fmt.Fprintf(out, "   not offered: %d recommended rule%s you declined earlier (%s rules recommended --undecline all)\n", n, plural(n), paths.BinaryName)
	}
	missing = offer
	fmt.Fprintf(out, "   %s will get:\n", file)
	for _, r := range missing {
		fmt.Fprintf(out, "     + %s: %s\n", r.Source.Key, r.Value)
	}
	q := fmt.Sprintf("   Add the recommended rules to your Claude Code settings? (%d Read and Edit rules: secrets stay unread, shell start-up files and login items ask first; Read(~/.ssh/id_*) also blocks the public keys id_*.pub)", len(missing))
	yes, ok := c.ask(q, true)
	switch {
	case !ok:
		fmt.Fprintln(out, "   (not applied: no terminal to confirm on)")
		return true, nil
	case !yes:
		ids := make([]string, 0, len(missing))
		for _, r := range missing {
			ids = append(ids, recommendedIntent(r))
		}
		if err := rulebook.Decline(hp.StateDir, ids); err != nil {
			fmt.Fprintf(out, "   Skipped (the answer was not remembered: %v). Later: %s rules recommended --install\n", err, paths.BinaryName)
			return false, nil
		}
		fmt.Fprintf(out, "   Skipped; setup will not offer them again. Later: %s rules recommended --install --all\n", paths.BinaryName)
		return false, nil
	}
	// the same plan rules recommended --install applies: user scope, one
	// write and one .bak-<ts>, each string claimed under its recommended: id
	var res rulebook.Result
	plan, err := recommendedPlan(in, missing)
	if err == nil {
		res, err = rulebook.Apply(in, plan)
	}
	if err == nil {
		fmt.Fprintf(out, "   added %d recommended rule%s to %s\n", len(missing), plural(len(missing)), file)
	}
	for _, b := range res.Backups {
		fmt.Fprintf(out, "   backup: %s\n", displayHome(b, hp.Home))
	}
	if err != nil {
		return false, fmt.Errorf("adding the recommended rules to %s: %w", file, err)
	}
	return false, nil
}

// setupAutostart asks whether the dashboard should start with each Claude
// Code session and saves the answer as ui.autostart in config.yaml. Only an
// answer typed on a terminal is saved: with --yes (or no terminal) the
// current setting stays as it is, and a first run stays off.
func setupAutostart(c *console, hp paths.Paths) {
	out := c.out
	path := hp.ConfigFile()
	cfg, err := userconfig.Load(path)
	if err != nil {
		fmt.Fprintf(out, "   %s does not parse (%v); autostart left as is\n", displayHome(path, hp.Home), err)
		return
	}
	cur, set := cfg.AutostartUI()
	if c.assume || !c.tty {
		state := "off (never asked)"
		if set {
			state = onOff(cur)
		}
		fmt.Fprintf(out, "   autostart with each Claude Code session: %s (rerun setup in a terminal to change it)\n", state)
		return
	}
	yes, ok := c.ask("   Start the dashboard automatically with each Claude Code session?", cur)
	if !ok {
		return
	}
	if set && yes == cur {
		fmt.Fprintf(out, "   autostart stays %s\n", onOff(cur))
	} else if err := userconfig.SetAutostartUI(path, yes); err != nil {
		fmt.Fprintf(out, "   could not save the answer: %v\n", err)
		return
	} else {
		fmt.Fprintf(out, "   autostart %s (saved in %s)\n", onOff(yes), displayHome(path, hp.Home))
	}
	if yes {
		fmt.Fprintln(out, "   The session hook starts it when a Claude Code session starts (the lifecycle hooks must be installed: watchdeck enforce install, or the plugin). To have it from login instead: watchdeck service install")
	}
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

// notApplied ends a run that needs an answer it cannot get.
func notApplied(c *console) int {
	fmt.Fprintln(c.errw, "watchdeck setup: no terminal to confirm on; nothing was written. Rerun in a terminal, or with --yes to apply the above.")
	return 1
}

func selfTestLine(st runner.SelfTest) string {
	switch {
	case st.Unsupported:
		return "fail: " + st.Detail
	case st.Nested:
		return "skipped: " + st.Detail
	}
	probe := "shell-only probe (python3 not found; network not tested)"
	if st.Probe == "python3" {
		probe = "python3 probe"
	}
	if st.OK() {
		checks := "write outside the work dir denied"
		if st.NetChecked {
			checks += ", network denied"
		}
		return fmt.Sprintf("pass (%s, %s): %s", st.Backend, probe, checks)
	}
	var bad []string
	if !st.WriteAllowed {
		bad = append(bad, "the canary could not write in its own dir")
	}
	if !st.WriteDenied {
		bad = append(bad, "a write outside the work dir was not denied")
	}
	if st.NetChecked && !st.NetDenied {
		bad = append(bad, "a network connect was not denied")
	}
	if st.Detail != "" {
		bad = append(bad, st.Detail)
	}
	return fmt.Sprintf("fail (%s, %s): %s", st.Backend, probe, strings.Join(bad, "; "))
}

// auditSummary is the short form of `watchdeck audit`: a few lines of totals.
func auditSummary(hp paths.Paths, cwd string) []string {
	rep, err := audit.Build(audit.Options{
		Roots:       skills.Roots{Home: hp.Home, Cwd: cwd},
		UserCfgDir:  hp.ConfigDir,
		ProjectRoot: paths.ProjectRoot(cwd, hp.Home),
	})
	if err != nil {
		return []string{"audit failed: " + err.Error()}
	}
	t := rep.Totals
	lines := []string{fmt.Sprintf("%d skill%s found, %d with scripts, %d with a PERMISSIONS.yaml", t.Skills, plural(t.Skills), t.WithScripts, t.WithManifest)}
	if t.Invalid > 0 {
		lines = append(lines, fmt.Sprintf("%d invalid PERMISSIONS.yaml (see: watchdeck audit --verbose)", t.Invalid))
	}
	if n := len(t.NetSkills); n > 0 {
		names := t.NetSkills
		more := ""
		if n > 5 {
			names, more = names[:5], fmt.Sprintf(" and %d more", n-5)
		}
		lines = append(lines, fmt.Sprintf("network use in scripts: %s%s (denied by default; grant with watchdeck allow <skill> --network all)", strings.Join(names, ", "), more))
	}
	lines = append(lines, "full table: watchdeck audit")
	return lines
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func projectFlag(project bool) string {
	if project {
		return " --project"
	}
	return ""
}

// displayHome shortens a path under home to ~/...
func displayHome(p, home string) string {
	if home != "" && (p == home || strings.HasPrefix(p, home+"/")) {
		return "~" + strings.TrimPrefix(p, home)
	}
	return p
}
