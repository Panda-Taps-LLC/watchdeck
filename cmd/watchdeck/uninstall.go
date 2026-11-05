package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/Panda-Taps-LLC/watchdeck/internal/claudesettings"
	"github.com/Panda-Taps-LLC/watchdeck/internal/mcpconfig"
	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
	"github.com/Panda-Taps-LLC/watchdeck/internal/rulebook"
	"github.com/Panda-Taps-LLC/watchdeck/internal/service"
	"github.com/Panda-Taps-LLC/watchdeck/internal/settings"
	"github.com/Panda-Taps-LLC/watchdeck/internal/skills"
	"github.com/Panda-Taps-LLC/watchdeck/internal/uistate"
	"github.com/Panda-Taps-LLC/watchdeck/internal/userconfig"
)

const uninstallUsage = `usage: watchdeck uninstall [--yes] [--purge] [--keep-binary] [--project] [--dry-run]

Removes watchdeck in one confirmed step. It prints the plan, asks once,
then works in this order:

  1. stops the running dashboard
  2. removes the login service ('watchdeck service install'), if installed
  3. unwraps every MCP server 'watchdeck mcp wrap' wrapped
  4. forgets the rules watchdeck added that you have since removed by hand
     (as 'watchdeck rules reconcile' does; a recommended one is declined,
     so a later setup does not offer it again), then removes the hooks and
     the sandbox exclusion from the user settings
     file (with --project also from <git root>/.claude/settings.json), and
     the rules watchdeck added (recorded in its ledger when they were added)
     from every settings file the ledger names, user and project alike,
     writing a .bak-<ts> backup first; rules you wrote yourself stay
  5. turns ui.autostart off in config.yaml
  6. with --purge: deletes watchdeck's config dir (overrides.yaml,
     config.yaml), state dir (activity log, session index, backups, the
     ledger and recommended-declined.json, the recommended rules you
     declined) and
     cache dir; the state dir is kept when the ledger does not load or a
     rule watchdeck added could not be removed (the file is missing or
     unreadable, or the removal failed), so you can retry
  7. last: deletes the binary when the installer put it in
     ~/.local/share/watchdeck/bin, and a ~/.local/bin/watchdeck link to
     it (not with --keep-binary). A binary from Homebrew, go install or a
     build is never deleted: the plan prints how to remove it.

The hooks name the binary's absolute path, so the binary goes after them.
The Claude Code plugin cannot be removed from here; when it is installed the
plan prints 'claude plugin uninstall watchdeck'.

  --yes          apply without asking
  --purge        also delete watchdeck's config, state and cache dirs
  --keep-binary  leave the binary where it is
  --project      also clean <git root>/.claude/settings.json
  --dry-run      print the plan; change nothing

Without a terminal and without --yes, uninstall prints the plan and exits 1.
Exit codes: 0 done (or nothing to do), 1 declined or no terminal, 2 an
error, 3 usage.
`

// installerBinDir is where scripts/install.sh puts the binary, under home.
const installerBinDir = ".local/share/" + paths.BinaryName + "/bin"

// purgeable refuses to let --purge delete d unless it is an absolute path
// whose last element is this binary's own dir name (paths.BinaryName).
func purgeable(d string) error {
	if filepath.Base(d) != paths.BinaryName || !filepath.IsAbs(d) {
		return fmt.Errorf("refusing to delete %s: not a %s dir", d, paths.BinaryName)
	}
	return nil
}

// uninstallSelf is the running binary's resolved path; tests replace it.
var uninstallSelf = selfPath

type uninstallOptions struct {
	purge, keepBinary, project, dryRun bool
}

// uninstallStep is one change: the plan line, what the summary calls it,
// and the action. A soft step's failure is a warning; any other failure
// stops the run before the next step.
type uninstallStep struct {
	label string
	what  string
	soft  bool
	apply func() (string, error)
}

// stepRefused is an apply error that is a warning whatever the step's soft
// flag: the step chose not to act (the state dir kept because rules could
// not be removed), and the run goes on.
type stepRefused struct{ msg string }

func (e stepRefused) Error() string { return e.msg }

type uninstallPlan struct {
	steps []uninstallStep
	notes []string // printed after the steps
	left  []string // what stays, for the summary
}

func (p *uninstallPlan) add(s uninstallStep) { p.steps = append(p.steps, s) }
func (p *uninstallPlan) note(format string, a ...any) {
	p.notes = append(p.notes, fmt.Sprintf(format, a...))
}
func (p *uninstallPlan) keep(what string) { p.left = append(p.left, what) }

func cmdUninstall(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() { fmt.Fprint(stderr, uninstallUsage) }
	yes := flags.Bool("yes", false, "")
	purge := flags.Bool("purge", false, "")
	keepBinary := flags.Bool("keep-binary", false, "")
	project := flags.Bool("project", false, "")
	dry := flags.Bool("dry-run", false, "")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 3
	}
	if flags.NArg() > 0 {
		fmt.Fprintf(stderr, "watchdeck uninstall: unexpected argument %q\n", flags.Arg(0))
		return 3
	}
	return runUninstall(newConsole(stdout, stderr, *yes), uninstallOptions{purge: *purge, keepBinary: *keepBinary, project: *project, dryRun: *dry})
}

func runUninstall(c *console, o uninstallOptions) int {
	out := c.out
	hp, env, err := hostPaths()
	if err != nil {
		fmt.Fprintf(c.errw, "watchdeck uninstall: %v\n", err)
		return 2
	}
	plan, err := planUninstall(hp, env, o)
	if err != nil {
		fmt.Fprintf(c.errw, "watchdeck uninstall: %v\n", err)
		return 2
	}
	if len(plan.steps) == 0 {
		fmt.Fprintln(out, "watchdeck uninstall: nothing to remove")
	} else {
		fmt.Fprintln(out, "watchdeck uninstall will:")
		for i, s := range plan.steps {
			fmt.Fprintf(out, "%2d. %s\n", i+1, s.label)
		}
	}
	for _, n := range plan.notes {
		fmt.Fprintf(out, "  - %s\n", n)
	}
	if len(plan.steps) == 0 {
		return 0
	}
	if o.dryRun {
		fmt.Fprintln(out, "(dry run: nothing changed)")
		return 0
	}
	yes, ok := confirmWrite(c, "Remove the above?")
	switch {
	case !ok:
		fmt.Fprintln(c.errw, "watchdeck uninstall: no terminal to confirm on; nothing was changed. Rerun in a terminal, or with --yes.")
		return 1
	case !yes:
		fmt.Fprintln(out, "nothing changed")
		return 1
	}
	var removed []string
	left := plan.left
	for i, s := range plan.steps {
		msg, err := s.apply()
		if err != nil {
			var refused stepRefused
			if s.soft || errors.As(err, &refused) {
				fmt.Fprintf(out, "%2d. warning: %v\n", i+1, err)
				left = append(left, s.what)
				continue
			}
			fmt.Fprintf(out, "%2d. failed: %v\n", i+1, err)
			fmt.Fprintf(c.errw, "watchdeck uninstall: stopped at step %d; the steps after it were not run. Fix the error and rerun watchdeck uninstall.\n", i+1)
			return 2
		}
		fmt.Fprintf(out, "%2d. %s\n", i+1, msg)
		removed = append(removed, s.what)
	}
	sum := "Done: removed " + strings.Join(removed, ", ")
	if len(left) > 0 {
		sum += "; left " + strings.Join(left, ", ")
	}
	fmt.Fprintln(out, sum+".")
	return 0
}

// planUninstall looks at the machine and lists the changes, changing nothing.
func planUninstall(hp paths.Paths, env map[string]string, o uninstallOptions) (*uninstallPlan, error) {
	p := &uninstallPlan{}
	home := hp.Home
	ctx := context.Background()

	// a. dashboard
	switch inst, err := uistate.Running(ctx, hp); {
	case err == nil:
		p.add(uninstallStep{
			label: fmt.Sprintf("stop the dashboard (pid %d, %s mode)", inst.State.PID, inst.Status.Mode),
			what:  "the dashboard", soft: true,
			apply: func() (string, error) {
				stopped, err := uistate.Stop(ctx, hp, stopWait)
				if errors.Is(err, uistate.ErrNotRunning) {
					return "dashboard already stopped", nil
				}
				if err != nil {
					return "", fmt.Errorf("could not stop the dashboard (pid %d): %v; stop it by hand", inst.State.PID, err)
				}
				return fmt.Sprintf("stopped the dashboard (pid %d)", stopped.State.PID), nil
			},
		})
	case errors.Is(err, uistate.ErrNotRunning):
	default:
		p.note("dashboard: %v; if one is running, stop it with: watchdeck ui --stop", err)
	}

	// b. login service; stat-gated so a machine without one never runs launchctl or systemctl
	if so, err := serviceOptions(); err == nil {
		if _, err := os.Stat(so.File()); err == nil {
			sp, err := service.UninstallPlan(so)
			if err != nil {
				return nil, err
			}
			var cmds []string
			for _, cmd := range sp.Commands {
				cmds = append(cmds, strings.Join(cmd, " "))
			}
			p.add(uninstallStep{
				label: fmt.Sprintf("remove the login service %s (%s)", displayHome(sp.File, home), strings.Join(cmds, "; ")),
				what:  "the login service",
				apply: func() (string, error) {
					if _, err := service.Uninstall(so); err != nil {
						return "", err
					}
					return "removed the login service " + displayHome(sp.File, home), nil
				},
			})
		}
	}

	// c. MCP servers wrapped by watchdeck (user scope only, as mcp wrap writes)
	if err := planMCPUnwrap(p, hp, env); err != nil {
		return nil, err
	}

	// d. hooks and the sandbox exclusion
	userPath, err := settingsPath(false, "")
	if err != nil {
		return nil, err
	}
	targets := []string{userPath}
	projPath, perr := settingsPath(true, "")
	if o.project {
		if perr != nil {
			return nil, perr
		}
		if projPath != userPath {
			targets = append(targets, projPath)
		}
	}
	// The ledger names the settings strings watchdeck added; they go in this
	// step, before --purge deletes the state dir that holds the ledger. Every
	// file the ledger names is cleaned, not only the targets above: a
	// project's .claude/settings.json gets a rules-only step. A file whose
	// strings cannot be removed (missing, unreadable, not a user or project
	// settings file, or failing at apply time) keeps the state dir from
	// --purge, so the ledger stays for a retry.
	led, lerr := claudesettings.LoadLedger(hp.StateDir)
	if lerr != nil {
		p.note("could not read which rules watchdeck added (%v); they stay in your settings", lerr)
		led = nil
	}
	if led != nil && len(led.Entries) > 0 {
		planReconcile(p, hp, led, o.dryRun)
	}
	stuck := &stuckRules{}
	if led != nil {
		for _, lp := range ledgerPaths(led) {
			if slices.ContainsFunc(targets, func(t string) bool { return filepath.Clean(t) == lp }) {
				continue
			}
			if isProjectSettings(lp) {
				targets = append(targets, lp)
				continue
			}
			if n := ownedCount(led, lp); n > 0 {
				stuck.add(lp, n) // an ownerless legacy path holds nothing to remove
			}
		}
	}
	for _, path := range targets {
		hookTarget := path == userPath || (o.project && path == projPath)
		var lines []string
		if hookTarget {
			var err error
			if lines, err = settings.UninstallPlan(path); err != nil {
				return nil, err
			}
		}
		loc := claudesettings.Location{Scope: claudesettings.ScopeUser, Path: path}
		if path != userPath {
			loc.Scope = claudesettings.ScopeProject
		}
		var owned []claudesettings.LedgerEntry
		if led != nil {
			if n := ownedCount(led, path); n > 0 {
				if _, err := os.Lstat(path); err != nil {
					stuck.add(path, n) // missing (or not even stat-able): nothing to remove from
				} else if owned, err = ownedEntries(led, loc); err != nil {
					stuck.add(path, n)
					owned = nil
				}
			}
		}
		if len(lines) == 0 && len(owned) == 0 {
			continue
		}
		path := path
		shown := displayHome(path, home)
		label := fmt.Sprintf("remove from %s (a .bak-<ts> backup is written first):", shown)
		for _, l := range lines {
			if home != "" {
				l = strings.ReplaceAll(l, home+"/", "~/")
			}
			label += "\n      - " + l
		}
		var whats []string
		if len(lines) > 0 {
			whats = append(whats, "the hooks")
		}
		if n := len(owned); n > 0 {
			label += fmt.Sprintf("\n      - remove the %d rule%s watchdeck added to %s (yours stay)", n, plural(n), shown)
			if o.dryRun {
				for _, e := range owned {
					label += "\n        " + e.Value
				}
			}
			whats = append(whats, fmt.Sprintf("%d rule%s watchdeck added", n, plural(n)))
		}
		hooks, rules := len(lines) > 0, len(owned) > 0
		nOwned := len(owned)
		p.add(uninstallStep{
			label: label,
			what:  strings.Join(whats, " and ") + " in " + shown,
			// a rules-only step (a project file only the ledger names) is
			// soft: its failure keeps the state dir, the run goes on
			soft: !hookTarget,
			apply: func() (string, error) {
				var msgs []string
				if rules { // never takes the lock (or makes the state dir) for nothing
					n, bk, err := removeOwned(hp.StateDir, loc)
					if err != nil {
						stuck.add(path, nOwned)
						return "", err
					}
					if n > 0 || bk != "" {
						msg := fmt.Sprintf("removed %d rule%s watchdeck added from %s", n, plural(n), shown)
						if bk != "" {
							msg += "; backup: " + displayHome(bk, home)
						}
						msgs = append(msgs, msg)
					}
				}
				if hooks {
					ch, err := settings.Uninstall(path)
					if err != nil {
						return "", err
					}
					msg := fmt.Sprintf("removed %d entr%s from %s", len(ch.Removed), pluralY(len(ch.Removed)), shown)
					if ch.Backup != "" {
						msg += "; backup: " + displayHome(ch.Backup, home)
					}
					msgs = append(msgs, msg)
				}
				if len(msgs) == 0 {
					return "nothing left to remove from " + shown, nil
				}
				return strings.Join(msgs, "; "), nil
			},
		})
	}
	if !o.project && perr == nil && projPath != userPath {
		if st, err := settings.Inspect(projPath); err == nil && (st.Count() > 0 || st.Excluded) {
			p.note("%s still has watchdeck hooks; remove them with: watchdeck enforce uninstall --project (or rerun with --project)", displayHome(projPath, home))
			p.keep("the project hooks")
		}
	}

	// e. dashboard autostart
	cfgPath := hp.ConfigFile()
	if cfg, err := userconfig.Load(cfgPath); err != nil {
		p.note("%s does not parse (%v); ui.autostart left as is", displayHome(cfgPath, home), err)
	} else if on, _ := cfg.AutostartUI(); on {
		p.add(uninstallStep{
			label: "turn ui.autostart off in " + displayHome(cfgPath, home),
			what:  "ui.autostart",
			apply: func() (string, error) {
				if err := userconfig.SetAutostartUI(cfgPath, false); err != nil {
					return "", err
				}
				return "ui.autostart off in " + displayHome(cfgPath, home), nil
			},
		})
	}

	// f. watchdeck's own dirs
	dirs := []string{hp.ConfigDir, hp.StateDir, filepath.Dir(hp.IndexFile())}
	if o.purge {
		for _, d := range dirs {
			if err := purgeable(d); err != nil {
				return nil, err
			}
			if _, err := os.Lstat(d); err != nil {
				continue
			}
			d := d
			isState := d == hp.StateDir
			if isState {
				if lerr != nil {
					p.note("NOT deleting the state dir: the rules watchdeck added could not be read from its ledger (%v); the ledger stays so you can retry", lerr)
					p.keep(displayHome(d, home))
					continue
				}
				if msg := stuck.refusal(home); msg != "" {
					p.note("%s", msg)
					p.keep(displayHome(d, home))
					continue
				}
			}
			label := "delete " + displayHome(d, home) + " (--purge)"
			if isState {
				if _, err := os.Lstat(filepath.Join(d, rulebook.DeclinedFile)); err == nil {
					label += "\n      - with " + rulebook.DeclinedFile + " (the recommended rules you declined)"
				}
			}
			p.add(uninstallStep{
				label: label,
				what:  displayHome(d, home),
				apply: func() (string, error) {
					if isState {
						// a rules step that failed above keeps the ledger
						if msg := stuck.refusal(home); msg != "" {
							return "", stepRefused{msg}
						}
					}
					if err := os.RemoveAll(d); err != nil {
						return "", err
					}
					return "deleted " + displayHome(d, home), nil
				},
			})
		}
		if hp.Activity != "" && !under(hp.Activity, hp.StateDir) {
			if _, err := os.Lstat(hp.Activity); err == nil {
				p.note("the activity log %s is outside the state dir (WATCHDECK_ACTIVITY); it stays", displayHome(hp.Activity, home))
				p.keep("the activity log")
			}
		}
	} else {
		if msg := stuck.listing(home); msg != "" {
			p.note("%s", msg)
		}
		var kept []string
		if _, err := os.Lstat(hp.OverridesFile()); err == nil {
			kept = append(kept, "your grants in "+displayHome(hp.OverridesFile(), home))
		}
		if hp.Activity != "" {
			if _, err := os.Lstat(hp.Activity); err == nil {
				kept = append(kept, "the activity log "+displayHome(hp.Activity, home))
			}
		}
		if dec := filepath.Join(hp.StateDir, rulebook.DeclinedFile); hp.StateDir != "" {
			if _, err := os.Lstat(dec); err == nil {
				kept = append(kept, "the recommended rules you declined in "+displayHome(dec, home))
			}
		}
		for _, d := range dirs {
			if _, err := os.Lstat(d); err == nil {
				kept = append(kept, displayHome(d, home))
				break
			}
		}
		if len(kept) > 0 {
			p.note("kept: %s (--purge deletes watchdeck's config, state and cache dirs)", strings.Join(kept, "; "))
			p.keep("watchdeck's config and state")
		}
	}

	// plugin: only Claude Code can remove it
	cwd, _ := os.Getwd()
	root := paths.ProjectRoot(cwd, home)
	if root == "" {
		root = cwd
	}
	if id, on, err := skills.PluginActive(hp.ClaudeDir, root, paths.BinaryName); err == nil && on {
		p.note("the watchdeck plugin (%s) is installed; remove it with: claude plugin uninstall watchdeck", id)
		p.keep("the plugin")
	}

	// g. the binary, last: the hooks above name its absolute path
	bin, err := uninstallSelf()
	if err != nil {
		return nil, err
	}
	instDir := filepath.Join(home, installerBinDir)
	link := filepath.Join(home, ".local", "bin", paths.BinaryName)
	switch {
	case o.keepBinary:
		p.keep("the binary")
	case filepath.Dir(bin) == instDir || (evalDir(instDir) != "" && filepath.Dir(bin) == evalDir(instDir)):
		withLink := false
		if fi, err := os.Lstat(link); err == nil && fi.Mode()&fs.ModeSymlink != 0 {
			if r, err := filepath.EvalSymlinks(link); err == nil && r == bin {
				withLink = true
			}
		}
		label := "delete the binary " + displayHome(bin, home)
		if withLink {
			label += " and the link " + displayHome(link, home)
		}
		p.add(uninstallStep{
			label: label,
			what:  "the binary",
			apply: func() (string, error) {
				if withLink {
					if err := os.Remove(link); err != nil && !errors.Is(err, fs.ErrNotExist) {
						return "", err
					}
				}
				if err := os.Remove(bin); err != nil && !errors.Is(err, fs.ErrNotExist) {
					return "", err
				}
				os.Remove(instDir) // only when empty
				return "deleted " + label[len("delete "):], nil
			},
		})
	default:
		hint := "rm " + bin
		if strings.Contains(bin, "/Cellar/"+paths.BinaryName+"/") {
			hint = "brew uninstall " + paths.BinaryName
		}
		p.note("the binary %s was not installed by install.sh and stays; remove it with: %s", displayHome(bin, home), hint)
		p.keep("the binary")
	}
	return p, nil
}

// planMCPUnwrap adds one step that unwraps every wrapped user-scope server
// in a single write (WriteConfig refuses a file that changed since it was
// read, so the step reads, unwraps and writes in one go).
func planMCPUnwrap(p *uninstallPlan, hp paths.Paths, env map[string]string) error {
	home := hp.Home
	if cd := env["CLAUDE_CONFIG_DIR"]; cd != "" && !filepath.IsAbs(cd) {
		p.note("CLAUDE_CONFIG_DIR is not an absolute path; MCP servers not checked")
		return nil
	}
	cfgPath := mcpconfig.UserConfigPath(home, env)
	statePath := filepath.Join(hp.StateDir, mcpconfig.StateFile)
	backups := filepath.Join(hp.StateDir, "mcp-backups")
	unwrapAll := func() (old, next []byte, real string, names []string, st mcpconfig.State, err error) {
		data, real, exists, err := mcpconfig.ReadConfig(cfgPath)
		if err != nil || !exists {
			return nil, nil, real, nil, st, err
		}
		list, err := mcpconfig.List(data)
		if err != nil {
			return nil, nil, real, nil, st, fmt.Errorf("%s: %v", displayHome(cfgPath, home), err)
		}
		st, err = mcpconfig.LoadState(statePath)
		if err != nil {
			return nil, nil, real, nil, st, err
		}
		next = data
		for _, s := range list {
			if !s.Wrapped() {
				continue
			}
			rec, _ := st.Get(real, s.Name)
			n, _, err := mcpconfig.Unwrap(next, s.Name, []byte(rec.Original), []byte(rec.Wrapped))
			if err != nil {
				return nil, nil, real, nil, st, fmt.Errorf("MCP server %s: %v", s.Name, err)
			}
			next = n
			names = append(names, s.Name)
		}
		return data, next, real, names, st, nil
	}
	_, _, _, names, _, err := unwrapAll()
	if err != nil {
		return err
	}
	if len(names) == 0 {
		p.note("no MCP servers wrapped by watchdeck")
		return nil
	}
	p.add(uninstallStep{
		label: fmt.Sprintf("unwrap the MCP server%s %s in %s (backup in the state dir; quit running Claude Code sessions first)", plural(len(names)), strings.Join(names, ", "), displayHome(cfgPath, home)),
		what:  fmt.Sprintf("%d MCP wrap%s", len(names), plural(len(names))),
		apply: func() (string, error) {
			old, next, real, names, st, err := unwrapAll()
			if err != nil {
				return "", err
			}
			if len(names) == 0 {
				return "no MCP servers left to unwrap", nil
			}
			backup, err := mcpconfig.WriteConfig(real, old, next, backups)
			if err != nil {
				return "", err
			}
			for _, n := range names {
				st.Delete(real, n)
			}
			msg := fmt.Sprintf("unwrapped %s; backup: %s", strings.Join(names, ", "), displayHome(backup, home))
			if err := mcpconfig.SaveState(statePath, st); err != nil {
				msg += fmt.Sprintf(" (the wrap records were not updated: %v)", err)
			}
			return msg, nil
		},
	})
	return nil
}

// under reports whether p is dir or inside it.
func under(p, dir string) bool {
	return p == dir || strings.HasPrefix(p, dir+string(filepath.Separator))
}

// evalDir resolves dir through symlinks; "" when it does not exist.
func evalDir(dir string) string {
	r, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return ""
	}
	return r
}

func pluralY(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

// stuckRules is the settings files whose watchdeck strings could not be
// removed, with how many each holds; any entry keeps --purge from deleting
// the state dir (and the ledger in it).
type stuckRules struct {
	paths []string
	n     int
}

func (s *stuckRules) add(path string, n int) {
	if !slices.Contains(s.paths, path) {
		s.paths = append(s.paths, path)
	}
	s.n += n
}

// summary is "<N> rules watchdeck added could not be removed from
// <paths>", or "" when nothing is stuck.
func (s *stuckRules) summary(home string) string {
	if len(s.paths) == 0 {
		return ""
	}
	shown := make([]string, len(s.paths))
	for i, p := range s.paths {
		shown[i] = displayHome(p, home)
	}
	return fmt.Sprintf("%d rule%s watchdeck added could not be removed from %s", s.n, plural(s.n), strings.Join(shown, ", "))
}

// refusal is the --purge plan line that keeps the state dir, or "" when
// nothing is stuck.
func (s *stuckRules) refusal(home string) string {
	if sum := s.summary(home); sum != "" {
		return "NOT deleting the state dir: " + sum + "; the ledger stays so you can retry"
	}
	return ""
}

// listing is the plan line without --purge, or "" when nothing is stuck.
func (s *stuckRules) listing(home string) string {
	sum := s.summary(home)
	if sum == "" {
		return ""
	}
	if s.n == 1 {
		return sum + "; it stays, and so does the ledger, so you can retry"
	}
	return sum + "; they stay, and so does the ledger, so you can retry"
}

// ledgerPaths is the distinct cleaned settings paths the ledger names, in
// first-seen order.
func ledgerPaths(led *claudesettings.Ledger) []string {
	var out []string
	for _, e := range led.Entries {
		if c := filepath.Clean(e.Path); !slices.Contains(out, c) {
			out = append(out, c)
		}
	}
	return out
}

// ownedCount is how many ledger entries some rule id claims in the file at
// path (an ownerless legacy entry owns nothing).
func ownedCount(led *claudesettings.Ledger, path string) int {
	clean := filepath.Clean(path)
	n := 0
	for _, e := range led.Entries {
		if filepath.Clean(e.Path) == clean && led.Owners(e.Path, e.Key, e.Value) != nil {
			n++
		}
	}
	return n
}

// isProjectSettings reports whether path is a project's shared settings
// file, <root>/.claude/settings.json: the only file besides the user's
// that watchdeck writes (never settings.local.json or managed settings).
func isProjectSettings(path string) bool {
	return filepath.IsAbs(path) && filepath.Base(path) == "settings.json" && filepath.Base(filepath.Dir(path)) == ".claude"
}

// planReconcile adds the step that forgets the strings watchdeck added and
// the person has since removed by hand (rulebook.Reconcile, before any
// string is removed), when there are any. It reconciles led in memory as
// it plans, so the rest of the plan no longer counts those strings. Only a
// root whose ledger-named settings files all exist is reconciled: a
// missing file is unknown, not removed by hand, so its strings stay in the
// ledger and still keep --purge from deleting the state dir. The step is
// soft: an error (a corrupt recommended-declined.json, say) is printed and
// the uninstall goes on.
func planReconcile(p *uninstallPlan, hp paths.Paths, led *claudesettings.Ledger, dryRun bool) {
	home := hp.Home
	missing := map[string]bool{}
	roots := []string{""} // user scope
	for _, lp := range ledgerPaths(led) {
		if _, err := os.Lstat(lp); err != nil {
			missing[lp] = true
		}
		if isProjectSettings(lp) {
			if root := filepath.Dir(filepath.Dir(lp)); !slices.Contains(roots, root) {
				roots = append(roots, root)
			}
		}
	}
	var todo []string
	var forgot []claudesettings.LedgerEntry
	for _, root := range roots {
		locs := claudesettings.Locate(hp, root)
		if slices.ContainsFunc(locs, func(l claudesettings.Location) bool { return missing[filepath.Clean(l.Path)] }) {
			continue
		}
		eff, _ := claudesettings.Read(locs, nil)
		drifts := claudesettings.Reconcile(led, eff) // in memory; the step saves
		if len(drifts) == 0 {
			continue
		}
		todo = append(todo, root)
		for _, d := range drifts {
			forgot = append(forgot, d.Entry)
		}
	}
	if len(forgot) == 0 {
		return
	}
	n := len(forgot)
	label := fmt.Sprintf("forget the %d rule%s watchdeck added that you removed by hand (a recommended one is declined, so it is not offered again)", n, plural(n))
	if dryRun {
		for _, e := range forgot {
			label += fmt.Sprintf("\n        %s in %s %s", e.Value, displayHome(e.Path, home), e.Key)
		}
	}
	p.add(uninstallStep{
		label: label,
		what:  fmt.Sprintf("the ledger's record of %d rule%s you removed by hand", n, plural(n)),
		soft:  true,
		apply: func() (string, error) {
			dropped, declined := 0, 0
			for _, root := range todo {
				d, dec, err := rulebook.Reconcile(rulebook.Input{Paths: hp, ProjectRoot: root})
				dropped += len(d)
				declined += len(dec)
				if err != nil {
					return "", fmt.Errorf("could not forget the rules you removed by hand: %v", err)
				}
			}
			msg := fmt.Sprintf("forgot %d rule%s you had removed by hand", dropped, plural(dropped))
			if declined > 0 {
				msg += fmt.Sprintf("; declined %d recommended rule%s so setup does not offer %s again", declined, plural(declined), themIt(declined))
			}
			return msg, nil
		},
	})
}

func themIt(n int) string {
	if n == 1 {
		return "it"
	}
	return "them"
}
