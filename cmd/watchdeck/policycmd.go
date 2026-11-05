package main

import (
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/Panda-Taps-LLC/watchdeck/internal/manifest"
	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
	"github.com/Panda-Taps-LLC/watchdeck/internal/policy"
)

const policyUsage = `usage: watchdeck policy check

Validates your overrides.yaml and the project .watchdeck.yaml (the git
root of the current directory), lists the project entries that are ignored,
and lints the gates:
  - a domain entry "example.com" covers only that host, not its subdomains;
    the check names entries without a "*.example.com" twin;
  - a rule regex that does not compile (the hook then fails closed).
Exit 0 when both files are valid (warnings included), 1 when one is not.
`

// cmdPolicy is `watchdeck policy check` (M6.3).
func cmdPolicy(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 || args[0] != "check" {
		fmt.Fprint(stderr, policyUsage)
		return 3
	}
	hp, _, err := hostPaths()
	if err != nil {
		fmt.Fprintln(stderr, "watchdeck policy:", err)
		return 2
	}
	userPath, projectPath, _ := policyFiles(hp)
	p, warns, err := policy.Load(userPath, projectPath)
	if err != nil {
		fmt.Fprintln(stdout, "invalid:", err)
		return 1
	}
	fmt.Fprintf(stdout, "user file:    %s\n", displayHome(userPath, hp.Home))
	if p.Shadow() {
		fmt.Fprintf(stdout, "mode:         shadow (rules are observed, not enforced; %s rules shadow off)\n", paths.BinaryName)
	}
	if projectPath != "" {
		fmt.Fprintf(stdout, "project file: %s\n", displayHome(projectPath, hp.Home))
	}
	lines := policyLint(p)
	for _, w := range warns {
		lines = append(lines, w.String())
	}
	if len(lines) == 0 {
		fmt.Fprintln(stdout, "ok: no warnings")
		return 0
	}
	for _, l := range lines {
		fmt.Fprintln(stdout, "warning:", l)
	}
	return 0
}

// policyLint returns the lint warnings for a loaded policy.
func policyLint(p *policy.Policy) []string {
	var out []string
	for _, s := range p.Subjects() {
		if s.Kind != policy.KindTool || s.Domains == nil {
			continue
		}
		for _, list := range [][]string{s.Domains.Deny, s.Domains.Ask} {
			have := map[string]bool{}
			for _, e := range list {
				have[strings.ToLower(e)] = true
			}
			for _, e := range list {
				le := strings.ToLower(e)
				if le == "*" || strings.HasPrefix(le, "*.") || have["*."+le] {
					continue
				}
				out = append(out, fmt.Sprintf("subjects.tool:%s.domains: %s covers only that host, not its subdomains; add *.%s if you meant them",
					manifest.DisplayPath(s.Name), manifest.DisplayPath(e), manifest.DisplayPath(e)))
			}
		}
	}
	for _, r := range p.Rules() {
		if r.Match.Regex == "" {
			continue
		}
		if _, err := regexp.Compile(r.Match.Regex); err != nil {
			out = append(out, "rules."+r.ID+": the regex does not compile; the hook treats this rule as matching (fail closed)")
		}
	}
	return out
}
