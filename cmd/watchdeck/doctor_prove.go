package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/Panda-Taps-LLC/watchdeck/internal/demo"
	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
	"github.com/Panda-Taps-LLC/watchdeck/internal/policy"
	"github.com/Panda-Taps-LLC/watchdeck/internal/prove"
	"github.com/Panda-Taps-LLC/watchdeck/internal/settings"
	"github.com/Panda-Taps-LLC/watchdeck/internal/skills"
)

// doctorProve appends the five "prove: …" checks to rep (doctor --prove).
func doctorProve(rep *doctorReport, forcePlugin bool) {
	defer finish(rep)
	add := func(l prove.Leg) {
		rep.Checks = append(rep.Checks, doctorCheck{Name: "prove: " + l.Name, Status: string(l.Status), Message: l.Message})
	}
	hp, _, err := hostPaths()
	if err != nil {
		for _, n := range []string{prove.LegRegistration, prove.LegRewrite, prove.LegSandbox, prove.LegReadRule, prove.LegShadow} {
			add(prove.Leg{Name: n, Status: prove.Fail, Message: "home: " + err.Error()})
		}
		return
	}
	cwd, _ := os.Getwd()
	root := paths.ProjectRoot(cwd, hp.Home)
	if root == "" {
		root = cwd
	}
	pluginOn, pluginID := forcePlugin, ""
	if id, on, err := skills.PluginActive(hp.ClaudeDir, root, paths.BinaryName); err == nil && on {
		pluginOn, pluginID = true, id
	}
	hook, hookErr := resolveRegistration(hp, root, pluginOn, pluginID)
	python, _ := exec.LookPath("python3")

	e, perr := demo.Prepare()
	if e != nil {
		defer e.Remove()
	}
	sh := prove.Shadow{}
	if _, err := os.Stat(hp.OverridesFile()); err == nil {
		sh.File = displayHome(hp.OverridesFile(), hp.Home)
	}
	sh.On, sh.Err = policy.ShadowOn(hp.OverridesFile())

	opts := prove.Options{
		Hook: hook, HookErr: hookErr, Env: e, PrepareErr: perr, Python: python,
		Environ: os.Environ(), Nested: rep.nested, Shadow: sh,
	}
	// The whole prove's deadline derives from the legs' (four hook calls at
	// most and one run), so a leg's own deadline always passes first.
	ctx, cancel := context.WithTimeout(context.Background(), opts.Deadline())
	defer cancel()
	res := prove.Run(ctx, opts)
	for _, l := range res.Legs {
		if l.Name == prove.LegRegistration && l.Status == prove.Pass {
			for _, f := range projectRegistrations(hp, root) {
				l.Message += "; project-scope entry in " + f + " not run"
			}
		}
		add(l)
	}
}

// userScopeFiles are the settings files whose registration the prove may
// run: the user's settings.json and settings.local.json.
func userScopeFiles(hp paths.Paths) []string {
	return []string{hp.ClaudeSettings(), filepath.Join(hp.ClaudeDir, "settings.local.json")}
}

// projectScopeFiles are the project's settings.json and settings.local.json
// (none when the project root is the home directory, whose .claude is the
// user's). The prove reads them and never runs what they register: a
// cloned repository's settings file could name any command, and Claude
// Code runs project hooks only after its own trust prompt.
func projectScopeFiles(hp paths.Paths, root string) []string {
	if pp := paths.ProjectSettings(root); pp != hp.ClaudeSettings() {
		return []string{pp, filepath.Join(root, ".claude", "settings.local.json")}
	}
	return nil
}

// projectRegistrations names, in display form, the project-scope files
// that register our PreToolUse Bash hook.
func projectRegistrations(hp paths.Paths, root string) []string {
	var out []string
	for _, f := range projectScopeFiles(hp, root) {
		if _, found, err := settings.Registration(f); err == nil && found {
			out = append(out, displayHome(f, hp.Home))
		}
	}
	return out
}

// resolveRegistration finds the first user-scope settings file, in doctor's
// order, whose PreToolUse Bash entry is ours; "" HookErr when found. A
// registration only in a project-scope file is reported, never run.
func resolveRegistration(hp paths.Paths, root string, pluginOn bool, pluginID string) (prove.Hook, string) {
	var shown, unreadable []string // shown: every file read, user scope first
	for _, f := range append(userScopeFiles(hp), projectScopeFiles(hp, root)...) {
		shown = append(shown, displayHome(f, hp.Home))
	}
	for _, f := range userScopeFiles(hp) {
		name := displayHome(f, hp.Home)
		r, found, err := settings.Registration(f)
		if err != nil {
			unreadable = append(unreadable, fmt.Sprintf("%s could not be read (%v)", name, err))
			continue
		}
		if !found {
			continue
		}
		h := prove.Hook{Text: r.Text(), Timeout: r.Timeout, File: name}
		if r.Shell {
			h.Argv = []string{"/bin/sh", "-c", r.Text()}
			if strings.Contains(r.Command, "CLAUDE_PLUGIN_ROOT") {
				return h, fmt.Sprintf("%s runs the plugin's hook.sh (%s); prove runs settings-file registrations only", name, h.Text)
			}
			return h, ""
		}
		h.Argv = append([]string{r.Command}, r.Args...)
		h.Binary = r.Command
		if !isExecutable(r.Command) {
			return h, fmt.Sprintf("%s registers %s, which is missing or not executable: rerun %s setup", name, r.Command, paths.BinaryName)
		}
		return h, ""
	}
	if proj := projectRegistrations(hp, root); len(proj) > 0 {
		return prove.Hook{}, fmt.Sprintf("found in %s; not run: prove runs user-scope registrations only (a repository's settings file could name any command); run %s setup", proj[0], paths.BinaryName)
	}
	if pluginOn {
		id := pluginID
		if id == "" {
			id = "--plugin"
		}
		return prove.Hook{}, fmt.Sprintf("hooks come from the plugin (%s); prove covers settings-file registrations only and does not run the plugin's bin/hook.sh (known limit); the binary check shows which binary it would find", id)
	}
	msg := fmt.Sprintf("no hooks registered in %s: run %s setup", strings.Join(shown, ", "), paths.BinaryName)
	if len(unreadable) > 0 {
		msg += "; " + strings.Join(unreadable, "; ")
	}
	return prove.Hook{}, msg
}
