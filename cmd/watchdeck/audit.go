package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/Panda-Taps-LLC/watchdeck/internal/audit"
	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
	"github.com/Panda-Taps-LLC/watchdeck/internal/skills"
)

type multiFlag []string

func (m *multiFlag) String() string     { return fmt.Sprint([]string(*m)) }
func (m *multiFlag) Set(s string) error { *m = append(*m, s); return nil }

const auditUsage = `usage: watchdeck audit [--all] [--deep] [--dir PATH]... [--json] [--verbose] [--strict]

Inventories installed skills: scripts, capabilities from a static scan,
PERMISSIONS.yaml status and the profile each would run under. Exits 0 once
the report is printed, even when a manifest is invalid (the table shows
invalid(...), JSON has totals.invalidManifests); --strict exits 1 in that
case, for scripts and CI. Exit 2 is a discovery error, 3 a usage error.

`

func cmdAudit(args []string) int {
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, auditUsage)
		fs.PrintDefaults()
	}
	all := fs.Bool("all", false, "include skills of disabled plugins")
	deep := fs.Bool("deep", false, "also find .claude/skills nested below the working directory")
	asJSON := fs.Bool("json", false, "machine-readable output")
	verbose := fs.Bool("verbose", false, "show problems, ignored overrides and one scan hit per category")
	strict := fs.Bool("strict", false, "exit 1 when any PERMISSIONS.yaml is invalid")
	var dirs multiFlag
	fs.Var(&dirs, "dir", "extra skill directory (repeatable)")
	if err := fs.Parse(args); err != nil {
		return 3
	}
	hp, env, err := hostPaths()
	if err != nil {
		fmt.Fprintln(os.Stderr, "watchdeck audit:", err)
		return 2
	}
	cwd, _ := os.Getwd()
	roots := skills.Roots{Home: hp.Home, Cwd: cwd, ExtraDirs: dirs, All: *all, Deep: *deep}
	if v := env["CLAUDE_SKILL_DIR"]; v != "" {
		roots.Env = map[string]string{"CLAUDE_SKILL_DIR": v}
	}
	rep, err := audit.Build(audit.Options{
		Roots:       roots,
		UserCfgDir:  hp.ConfigDir,
		ProjectRoot: paths.ProjectRoot(cwd, hp.Home),
		Verbose:     *verbose,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "watchdeck audit:", err)
		return 2
	}
	if *asJSON {
		if err := rep.JSON(os.Stdout); err != nil {
			return 2
		}
	} else {
		rep.Table(os.Stdout, *verbose)
	}
	if *strict && rep.Totals.Invalid > 0 {
		return 1
	}
	return 0
}
