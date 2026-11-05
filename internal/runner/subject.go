package runner

import (
	"fmt"
	"path/filepath"
	"sort"

	"github.com/Panda-Taps-LLC/watchdeck/internal/manifest"
	"github.com/Panda-Taps-LLC/watchdeck/internal/policy"
	"github.com/Panda-Taps-LLC/watchdeck/internal/profile"
)

// ErrUnknownSubject is returned for a command subject the user policy does
// not define (exit 125).
type ErrUnknownSubject struct{ Kind, Name string }

func (e ErrUnknownSubject) Error() string {
	return "unknown " + e.Kind + " subject " + e.Name + " (not in your overrides.yaml)"
}

// ResolveCommandSubject computes the policy for a command subject (M6.3):
// the default profile widened by the subject's grant block. Command
// subjects come from the user file only, so the project file is not read
// and nothing is clipped. needShell is as for Resolve.
func ResolveCommandSubject(name string, env Env, needShell bool) (*Policy, error) {
	userPath := filepath.Join(env.UserCfgDir, "overrides.yaml")
	pl, _, err := policy.Load(userPath, "")
	if err != nil {
		return nil, fmt.Errorf("overrides: %w", err)
	}
	var subj *policy.Subject
	for _, s := range pl.Subjects() {
		if s.Kind == policy.KindCommand && s.Name == name && s.Source == manifest.SourceUser {
			subj = s
			break
		}
	}
	if subj == nil {
		return nil, ErrUnknownSubject{Kind: policy.KindCommand, Name: name}
	}
	eff, _ := pl.CommandGrant(subj)

	pol := &Policy{Subject: policy.KindCommand + ":" + name}
	realCWD := realPath(env.Cwd)
	realTMP := userTempDir(env.Environ)
	// The same extra denies as a skill run and an MCP launch: the state dir,
	// Claude Code's config (~/.claude.json and its siblings, a relocated
	// CLAUDE_CONFIG_DIR) and the account home's denies (claudedeny.go).
	extra, err := runDeny(env)
	if err != nil {
		return nil, err
	}
	res, dropped, droppedWrites, err := toResolved(eff, nil, env.Home, realCWD, realTMP, extra.Paths)
	if err != nil {
		return nil, err
	}
	res.DenyPatterns = append(res.DenyPatterns, extra.Patterns...)
	pol.ExtraDeny = append(append([]string(nil), extra.Paths...), extra.Patterns...)
	for _, w := range droppedWrites {
		eff.Write = removeEntry(eff.Write, w)
	}
	pol.Effective = eff
	if needShell && !res.ExecAny {
		res.ExecAllow = append(res.ExecAllow, "/bin/bash")
		sort.Strings(res.ExecAllow)
	}
	pol.Resolved = res
	p, warnings, err := compile(res)
	if err != nil {
		return nil, fmt.Errorf("profile: %w", err)
	}
	pol.Profile = p
	pol.Warnings = append(dropped, warnings...)
	if realCWD == realPath(env.Home) {
		pol.Warnings = append(pol.Warnings, "working directory is your home directory: the command may write anywhere under it except the protected paths; run from a project directory for a tighter sandbox")
	}
	pol.Hash = profile.Hash(p)
	return pol, nil
}

// label names what a policy is for: the skills joined by "+", or the
// subject ("command:npm-scripts").
func (p *Policy) label() string {
	if p.Subject != "" {
		return p.Subject
	}
	s := ""
	for i, n := range p.Skills {
		if i > 0 {
			s += "+"
		}
		s += n
	}
	return s
}
