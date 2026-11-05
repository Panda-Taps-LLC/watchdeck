package main

import (
	"os"
	"strings"

	"github.com/Panda-Taps-LLC/watchdeck/internal/activity"
	"github.com/Panda-Taps-LLC/watchdeck/internal/hook"
	"github.com/Panda-Taps-LLC/watchdeck/internal/lifecycle"
	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
	"github.com/Panda-Taps-LLC/watchdeck/internal/uistate"
)

// cmdHook is the Claude Code hook handler (PreToolUse, PermissionDenied,
// SessionStart, SessionEnd, UserPromptSubmit).
// It always exits 0.
func cmdHook(args []string) int {
	harness := parseHarness(args)
	hp, env, err := hostPaths()
	if err != nil {
		return 0
	}
	lifecycle.OnSessionStart = autostartUI(hp)
	return hook.Run(os.Stdin, os.Stdout, hook.Env{
		Harness: harness,
		Home:    hp.Home, CacheDir: hp.CacheBase, UserCfgDir: hp.ConfigDir,
		ActivityPath: hp.Activity, Environ: env, StateDir: hp.StateDir,
		Lifecycle: lifecycle.Store{Log: hp.Sessions, Live: hp.LiveDir},
	})
}

// autostartUI returns the SessionStart extension that starts the dashboard
// in the background (M5.3). uistate.EnsureRunning does nothing unless the
// user said yes to autostart in setup (ui.autostart) and
// WATCHDECK_UI_AUTOSTART is not "off"; it never waits for the server and
// the spawned server's stdio is /dev/null, so the hook's output stays clean.
// Errors are ignored: a session must start whatever the dashboard does.
func autostartUI(hp paths.Paths) func(lifecycle.Store, lifecycle.Record) {
	return func(lifecycle.Store, lifecycle.Record) {
		bin, err := selfPath()
		if err != nil {
			return
		}
		_ = uistate.EnsureRunning(hp, bin)
	}
}

// parseHarness reads --harness NAME or --harness=NAME. The name must be 1 to
// 32 lowercase letters, digits or dashes, not starting with a dash; anything else (an empty value, a
// following flag) falls back to claude-code, silently: the hook always exits
// 0 and writes nothing to stderr.
func parseHarness(args []string) string {
	val, ok := "", false
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--harness" && i+1 < len(args):
			val, ok = args[i+1], true
			i++
		case strings.HasPrefix(args[i], "--harness="):
			val, ok = strings.TrimPrefix(args[i], "--harness="), true
		}
	}
	if !ok || len(val) == 0 || len(val) > 32 || val[0] == '-' {
		return activity.HarnessClaudeCode
	}
	for _, c := range val {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return activity.HarnessClaudeCode
		}
	}
	return val
}
