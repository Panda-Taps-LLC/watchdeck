package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
	"github.com/Panda-Taps-LLC/watchdeck/internal/runner"
)

const runUsage = `usage: watchdeck run (--skill NAME [--skill NAME...] | --subject KIND:NAME...) (-c 'shell string' | -- argv...)

Runs the command under the sandbox profile resolved for the named skill(s)
or subject. --subject skill:NAME is the same as --skill NAME;
--subject command:NAME runs under the command subject NAME of your
overrides.yaml (one, not combined with skills).
Exit codes: the command's own; 125 policy/config error (unknown skill or
subject); 126 sandbox could not be applied.
`

func cmdRun(args []string) int {
	if mcpSubjectArgs(args) { // M6.7: run --subject mcp:NAME -- argv (mcprun.go)
		return cmdRunMCP(args)
	}
	var rest []string
	for i, a := range args {
		if a == "--" {
			rest = args[i+1:]
			args = args[:i]
			break
		}
	}
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var skillsFlag, subjectFlag multiFlag
	fs.Var(&skillsFlag, "skill", "skill name (repeatable)")
	fs.Var(&subjectFlag, "subject", "KIND:NAME, kind skill or command (repeatable for skills)")
	cmd := fs.String("c", "", "shell command string to run with /bin/bash -c")
	perr := fs.Parse(args)
	hp, _, herr := hostPaths()
	cwd, _ := os.Getwd()
	opts := runner.Options{
		Skills:       skillsFlag,
		Command:      *cmd,
		Argv:         rest,
		Env:          runner.Env{Home: hp.Home, Cwd: cwd, CacheDir: hp.CacheBase, UserCfgDir: hp.ConfigDir},
		Environ:      os.Environ(),
		Stdin:        os.Stdin,
		Stdout:       os.Stdout,
		Stderr:       os.Stderr,
		ActivityPath: hp.Activity,
	}
	if perr != nil {
		runner.RecordUsage(opts, perr.Error())
		return runner.ExitUsage
	}
	// --subject kind:name (M6.3). A malformed value is a usage error (3); a
	// kind other than skill or command is a policy error (125), as is an
	// unknown name (resolved by the runner).
	for _, s := range subjectFlag {
		kind, name, ok := strings.Cut(s, ":")
		if !ok || kind == "" || name == "" {
			fmt.Fprint(os.Stderr, runUsage)
			runner.RecordUsage(opts, "usage: --subject wants KIND:NAME")
			return runner.ExitUsage
		}
		switch kind {
		case "skill":
			opts.Skills = append(opts.Skills, name)
		case "command":
			if opts.CommandSubject != "" {
				fmt.Fprint(os.Stderr, runUsage)
				runner.RecordUsage(opts, "usage: one command subject per run")
				return runner.ExitUsage
			}
			opts.CommandSubject = name
		default:
			fmt.Fprintf(os.Stderr, paths.Trailer+"unknown subject kind %q (want skill or command)\n", kind)
			return runner.ExitPolicy
		}
	}
	if opts.CommandSubject != "" && len(opts.Skills) > 0 {
		fmt.Fprint(os.Stderr, runUsage)
		runner.RecordUsage(opts, "usage: a command subject is not combined with skills")
		return runner.ExitUsage
	}
	if (len(opts.Skills) == 0 && opts.CommandSubject == "") || (*cmd == "" && len(rest) == 0) || (*cmd != "" && len(rest) > 0) || fs.NArg() > 0 {
		fmt.Fprint(os.Stderr, runUsage)
		runner.RecordUsage(opts, "usage: give --skill NAME or --subject KIND:NAME and exactly one of -c 'command' or -- argv")
		return runner.ExitUsage
	}
	if herr != nil {
		fmt.Fprint(os.Stderr, paths.Trailer, herr, "\n")
		return runner.ExitPolicy
	}
	return runner.Run(context.Background(), opts)
}
