package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Panda-Taps-LLC/watchdeck/internal/index"
	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
	"github.com/Panda-Taps-LLC/watchdeck/internal/service"
	"github.com/Panda-Taps-LLC/watchdeck/internal/settings"
)

const enforceUsage = `usage: watchdeck enforce <install|uninstall|status> [--project] [--file PATH]

  install     register the six hooks (PreToolUse Bash, PreToolUse Skill,
              PermissionDenied on every tool, and SessionStart, SessionEnd,
              UserPromptSubmit for the session lifecycle) and the sandbox
              exclusion
  uninstall   remove exactly what install added
  status      show which of the hooks and the exclusion are present

  install also registers PreToolUse for Read|Write|Edit|MultiEdit|NotebookEdit,
  WebFetch|WebSearch, mcp__.* or other tools, and PostToolUse for
  WebFetch|WebSearch, but only when your policy (overrides.yaml and the
  project .watchdeck.yaml) has rules or gates for them. Each file tool
  is registered only for a path rule, your own rule for it, or a pack rule
  at ask or deny whose recommended Claude Code rule is not installed; with
  the recommended rules in place that is Write|Edit|MultiEdit|NotebookEdit.
  Install moves or removes the group when that changes. Run it again
  after adding a gate for a new tool.

  --project   edit <git root>/.claude/settings.json (the current directory
              when no .git is found) instead of ~/.claude/settings.json
  --file      edit this settings file instead

The user settings file is $CLAUDE_CONFIG_DIR/settings.json when that
variable is set.
`

func cmdEnforce(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, enforceUsage)
		return 3
	}
	sub := args[0]
	fs := flag.NewFlagSet("enforce", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	project := fs.Bool("project", false, "edit the project settings file")
	file := fs.String("file", "", "settings file to edit")
	if err := fs.Parse(args[1:]); err != nil {
		return 3
	}
	path, err := settingsPath(*project, *file)
	if err != nil {
		fmt.Fprintln(os.Stderr, "watchdeck enforce:", err)
		return 2
	}
	switch sub {
	case "install":
		bin, err := installBinary()
		if err != nil {
			fmt.Fprintln(os.Stderr, "watchdeck enforce:", err)
			return 2
		}
		ch, err := settings.InstallWith(path, bin, policyExtra(*project && *file == ""))
		if err != nil {
			fmt.Fprintln(os.Stderr, "watchdeck enforce:", err)
			return 2
		}
		if !ch.Changed() {
			fmt.Printf("%s: already installed, nothing changed\n", path)
			return 0
		}
		fmt.Printf("%s:\n", path)
		for _, a := range ch.Added {
			fmt.Printf("  + %s\n", a)
		}
		for _, u := range ch.Updated { // our hooks that named a binary which is gone
			fmt.Printf("  ~ %s\n", u)
		}
		for _, r := range ch.Removed { // overlapping groups (a wildcard group replaces Bash, Skill and the tool groups)
			fmt.Printf("  - %s\n", r)
		}
		if ch.Backup != "" {
			fmt.Printf("  backup: %s\n", ch.Backup)
		}
		return 0
	case "uninstall":
		ch, err := settings.Uninstall(path)
		if err != nil {
			fmt.Fprintln(os.Stderr, "watchdeck enforce:", err)
			return 2
		}
		if !ch.Changed() {
			fmt.Printf("%s: nothing to remove\n", path)
			return 0
		}
		fmt.Printf("%s:\n", path)
		for _, r := range ch.Removed {
			fmt.Printf("  - %s\n", r)
		}
		if ch.Backup != "" {
			fmt.Printf("  backup: %s\n", ch.Backup)
		}
		return 0
	case "status":
		st, err := settings.Inspect(path)
		if err != nil {
			fmt.Fprintln(os.Stderr, "watchdeck enforce:", err)
			return 2
		}
		fmt.Printf("%s\n", path)
		if !st.Exists {
			fmt.Println("  file does not exist")
			return 0
		}
		line := func(label string, v bool) { fmt.Printf("  %-25s %v\n", label+":", v) }
		if st.HookInstalled {
			fmt.Printf("  %-25s %v  (%s)\n", "hook (Bash):", true, st.HookCommand)
		} else {
			line("hook (Bash)", false)
		}
		line("hook (Skill)", st.SkillHook)
		line("hook (PermissionDenied)", st.DeniedHook)
		line("hook (SessionStart)", st.StartHook)
		line("hook (SessionEnd)", st.EndHook)
		line("hook (UserPromptSubmit)", st.PromptHook)
		line("sandbox exclusion", st.Excluded)
		line("claude sandbox enabled", st.SandboxEnabled)
		if st.Complete {
			line("complete", true)
		} else {
			fmt.Printf("  %-25s %v  (watchdeck enforce install adds what is missing)\n", "complete:", false)
		}
		if st.SandboxEnabled && !st.Excluded {
			fmt.Println("  warning: Claude Code's sandbox is on and \"" + paths.BinaryName + " run *\" is not excluded; watchdeck run will fail closed. Run: watchdeck enforce install")
		}
		// M6.3: registrations the policy's gates and rule packs need
		present, missing, err := settings.ExtraStatus(path, policyExtra(*project && *file == ""))
		if err == nil {
			for _, p := range present {
				fmt.Printf("  %-25s true\n", "hook ("+p+"):")
			}
			for _, m := range missing {
				fmt.Printf("  %-25s false  (the policy has rules for these tools; watchdeck enforce install adds it)\n", "hook ("+m+"):")
			}
		}
		if inst, err := settings.InstalledExtra(path); err == nil && len(inst) > 0 && len(present) == 0 && len(missing) == 0 {
			fmt.Printf("  extra hooks installed:    %s (the policy no longer needs them; harmless)\n", strings.Join(inst, ", "))
		}
		return 0
	default:
		fmt.Fprint(os.Stderr, enforceUsage)
		return 3
	}
}

// settingsPath picks the settings file: --file wins; --project is the git
// root's .claude/settings.json (the current directory when no .git is found
// between here and home or /), so the CLI and the dashboard's Enforce page
// name the same file; otherwise the user file under $CLAUDE_CONFIG_DIR or
// ~/.claude.
func settingsPath(project bool, file string) (string, error) {
	if file != "" {
		return file, nil
	}
	if project {
		cwd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		home, _ := os.UserHomeDir()
		root := index.ProjectRoot(cwd, home)
		if root == "" {
			root = cwd
		}
		return filepath.Join(root, ".claude", "settings.json"), nil
	}
	if dir := os.Getenv("CLAUDE_CONFIG_DIR"); dir != "" {
		return filepath.Join(dir, "settings.json"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".claude", "settings.json"), nil
}

// installBinary is the path the hooks record: selfPath, mapped from a Homebrew
// Cellar path to the opt link (as `service install` does), so the hooks
// survive `brew upgrade` and its cleanup.
func installBinary() (string, error) {
	p, err := selfPath()
	if err != nil {
		return "", err
	}
	return service.StableBinary(p), nil
}

func selfPath() (string, error) {
	p, err := os.Executable()
	if err != nil {
		return "", err
	}
	if r, err := filepath.EvalSymlinks(p); err == nil {
		p = r
	}
	return p, nil
}
