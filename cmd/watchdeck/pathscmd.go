package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"

	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
	"github.com/Panda-Taps-LLC/watchdeck/internal/sandbox"
)

const pathsUsage = `usage: watchdeck paths [--json]

Prints every location watchdeck reads or writes, resolved from HOME,
XDG_CONFIG_HOME, XDG_CACHE_HOME, XDG_STATE_HOME, CLAUDE_CONFIG_DIR and
WATCHDECK_ACTIVITY ("activity" is empty when the log is off) and
WATCHDECK_LIFECYCLE ("sessions" and "liveDir" are empty when it is off). projectRoot
is the git root above the working directory, empty when there is none below
HOME. Scripts and the Claude Code mod read this instead of re-deriving XDG.

`

// pathsJSON is `paths --json`: paths.Paths plus the derived files.
type pathsJSON struct {
	paths.Paths
	OverridesFile  string `json:"overridesFile"`
	IndexFile      string `json:"indexFile"`
	ClaudeSettings string `json:"claudeSettings"`
	ProjectRoot    string `json:"projectRoot"`
}

func cmdPaths(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("paths", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, pathsUsage)
		fs.PrintDefaults()
	}
	asJSON := fs.Bool("json", false, "machine-readable output")
	if err := fs.Parse(args); err != nil {
		return 3
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "watchdeck paths: unexpected argument %q\n", fs.Arg(0))
		return 3
	}
	hp, _, err := hostPaths()
	if err != nil {
		fmt.Fprintln(stderr, "watchdeck paths:", err)
		return 2
	}
	cwd, _ := os.Getwd()
	out := pathsJSON{
		Paths:          hp,
		OverridesFile:  hp.OverridesFile(),
		IndexFile:      hp.IndexFile(),
		ClaudeSettings: hp.ClaudeSettings(),
		ProjectRoot:    paths.ProjectRoot(cwd, hp.Home),
	}
	if *asJSON {
		return writeJSON(stdout, stderr, out)
	}
	for _, kv := range [][2]string{
		{"home", out.Home},
		{"configDir", out.ConfigDir},
		{"cacheBase", out.CacheBase},
		{"stateDir", out.StateDir},
		{"activity", out.Activity},
		{"claudeDir", out.ClaudeDir},
		{"sessions", out.Sessions},
		{"liveDir", out.LiveDir},
		{"overridesFile", out.OverridesFile},
		{"indexFile", out.IndexFile},
		{"claudeSettings", out.ClaudeSettings},
		{"projectRoot", out.ProjectRoot},
	} {
		fmt.Fprintf(stdout, "%s: %s\n", kv[0], clean(kv[1]))
	}
	return 0
}

// versionJSON is `version --json`, a cheap health probe for the mod.
type versionJSON struct {
	Version     string `json:"version"`
	Platform    string `json:"platform"`    // runtime.GOOS
	Enforcement bool   `json:"enforcement"` // the OS sandbox (sandbox-exec or bwrap) is present
}

func cmdVersion(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	fs.SetOutput(stderr)
	asJSON := fs.Bool("json", false, `print {"version","platform","enforcement"}`)
	if err := fs.Parse(args); err != nil {
		return 3
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "watchdeck version: unexpected argument %q\n", fs.Arg(0))
		return 3
	}
	if *asJSON {
		return writeJSON(stdout, stderr, versionJSON{Version: version, Platform: runtime.GOOS, Enforcement: sandbox.Available()})
	}
	fmt.Fprintln(stdout, paths.BinaryName, version)
	return 0
}
