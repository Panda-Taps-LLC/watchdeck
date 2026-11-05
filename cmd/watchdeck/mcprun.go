package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/Panda-Taps-LLC/watchdeck/internal/mcpconfig"
	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
	"github.com/Panda-Taps-LLC/watchdeck/internal/runner"
)

const runMCPUsage = `usage: watchdeck run --subject mcp:NAME [--allow-home-cwd] -- command [args...]   (experimental)

Starts a stdio MCP server under the launch grant of the user policy subject
{kind: mcp, name: NAME, launch: {sandbox: true}}. argv form only (no shell);
stdin and stdout are passed to the server untouched. watchdeck mcp wrap
writes this command into Claude Code's user config.
`

// mcpSubjectArgs reports whether a run invocation names an mcp subject
// (--subject mcp:<x> or --subject=mcp:<x> before "--"). Such a run is
// handled by cmdRunMCP, whatever else is on the line.
func mcpSubjectArgs(args []string) bool {
	for i, a := range args {
		if a == "--" {
			return false
		}
		if v, ok := strings.CutPrefix(a, "--subject="); ok && strings.HasPrefix(v, "mcp:") {
			return true
		}
		if (a == "--subject" || a == "-subject") && i+1 < len(args) && strings.HasPrefix(args[i+1], "mcp:") {
			return true
		}
	}
	return false
}

// cmdRunMCP accepts exactly: --subject mcp:NAME [--allow-home-cwd] --
// argv... (or --subject=mcp:NAME ...).
func cmdRunMCP(args []string) int {
	var name string
	var argv []string
	allowHome := false
	if len(args) >= 1 && args[0] == "--subject" && len(args) >= 3 && args[2] == mcpconfig.AllowHomeCwdFlag {
		allowHome = true
		args = append([]string{args[0], args[1]}, args[3:]...)
	} else if len(args) >= 2 && strings.HasPrefix(args[0], "--subject=") && args[1] == mcpconfig.AllowHomeCwdFlag {
		allowHome = true
		args = append([]string{args[0]}, args[2:]...)
	}
	switch {
	case len(args) >= 4 && args[0] == "--subject" && args[2] == "--":
		name, argv = strings.TrimPrefix(args[1], "mcp:"), args[3:]
	case len(args) >= 3 && strings.HasPrefix(args[0], "--subject=mcp:") && args[1] == "--":
		name, argv = strings.TrimPrefix(args[0], "--subject=mcp:"), args[2:]
	}
	hp, _, herr := hostPaths()
	cwd, _ := os.Getwd()
	o := runner.MCPOptions{
		Server:       name,
		Argv:         argv,
		Env:          runner.Env{Home: hp.Home, Cwd: cwd, CacheDir: hp.CacheBase, UserCfgDir: hp.ConfigDir},
		Environ:      os.Environ(),
		Stdin:        os.Stdin,
		Stdout:       os.Stdout,
		Stderr:       os.Stderr,
		ActivityPath: hp.Activity,
		AllowHomeCwd: allowHome,
	}
	if name == "" || len(argv) == 0 {
		fmt.Fprint(os.Stderr, runMCPUsage)
		if herr == nil {
			runner.RecordMCPUsage(o, "usage: give --subject mcp:NAME -- command [args...]")
		}
		return runner.ExitUsage
	}
	if herr != nil {
		fmt.Fprint(os.Stderr, paths.Trailer, herr, "\n")
		return runner.ExitPolicy
	}
	return runner.RunMCP(context.Background(), o)
}
