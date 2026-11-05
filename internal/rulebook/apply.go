package rulebook

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/Panda-Taps-LLC/watchdeck/internal/claudesettings"
	"github.com/Panda-Taps-LLC/watchdeck/internal/manifest"
	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
	"github.com/Panda-Taps-LLC/watchdeck/internal/policy"
)

// ErrNotOwned is Remove's error for a native row watchdeck did not add.
// It is a comparable struct value rather than errors.New so the message
// can name paths.BinaryName and the var still needs no init code (the
// init-free source check in cmd/watchdeck allows errors.New with a bare
// literal only).
var ErrNotOwned error = notOwnedError{}

type notOwnedError struct{}

func (notOwnedError) Error() string { return "not added by " + paths.BinaryName }

// Result says what Apply or Remove wrote: the files changed, the backups
// taken of their previous bytes, and the row ids the plan's rules (or the
// removed row) have.
type Result struct {
	Written []string `json:"written"`
	Backups []string `json:"backups"`
	RowIDs  []string `json:"row_ids"`
}

func (r *Result) wrote(file, backup string) {
	if !containsStr(r.Written, file) {
		r.Written = append(r.Written, file)
	}
	if backup != "" {
		r.Backups = append(r.Backups, backup)
	}
}

func hasClaim(cs []claudesettings.Claim, c claudesettings.Claim) bool {
	for _, x := range cs {
		if x == c {
			return true
		}
	}
	return false
}

func containsStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// writableSettings returns the user and project settings locations Apply
// and Remove may write, by cleaned path.
func writableSettings(in Input) []claudesettings.Location {
	var out []claudesettings.Location
	for _, l := range claudesettings.Locate(in.Paths, in.ProjectRoot) {
		if l.ReadOnly || (l.Scope != claudesettings.ScopeUser && l.Scope != claudesettings.ScopeProject) {
			continue
		}
		out = append(out, l)
	}
	return out
}

func locationFor(locs []claudesettings.Location, file string) (claudesettings.Location, bool) {
	clean := filepath.Clean(file)
	for _, l := range locs {
		if filepath.Clean(l.Path) == clean {
			return l, true
		}
	}
	return claudesettings.Location{}, false
}

// nativeWrite is the adds for one settings file, grouped by key in plan
// order; one ManageKeys call (one write, one backup) covers the file.
type nativeWrite struct {
	loc    claudesettings.Location
	groups []nativeGroup
}

type nativeGroup struct {
	key    string
	claims []claudesettings.Claim
}

// Apply writes a Plan. Every step is checked before anything is written: a
// native step must name the user or project settings file of in (never
// local or managed) and a deny or ask list (sandbox.network.deniedDomains
// only for a plain host under a host intent); a hook or subject step must
// name the user policy file, or the project's policy file for a step of an
// everywhere intent; anything else is ErrScope. The policy edits are
// tried on the loaded files before any write, so a refused edit writes
// nothing. Native steps run in one claudesettings.Transact and one
// ManageKeys per settings file (so one write and one .bak-<ts> per file,
// each string claimed under its own intent; a string the person already
// has is left theirs and not claimed); hook and subject steps load each
// policy file once, apply every edit and save it once when something
// changed (policy.Save keeps a .bak-<ts>). Row ids are recomputed from the
// steps, never trusted from them, and so is a hook rule's id
// (user-<fnv32a hex8 of its regex or text>), except that a rule whose id
// is its step's intent rule id (intent-<what>-<hex8>-bash for the step's
// intent:<what>:<hex8>) keeps it; a native string's value is checked for
// ( and ) as Propose checks it.
func Apply(in Input, p Plan) (Result, error) {
	res := Result{Written: []string{}, Backups: []string{}, RowIDs: []string{}}
	locs := writableSettings(in)
	over := in.Paths.OverridesFile()
	projPol := ""
	if in.ProjectRoot != "" {
		projPol = filepath.Join(in.ProjectRoot, manifest.ProjectOverridesFile)
	}

	var writes []*nativeWrite
	var policies []*policyWrite
	for _, s := range p.Steps {
		switch s.Mechanism {
		case MechNative:
			loc, ok := locationFor(locs, s.File)
			if !ok {
				return res, fmt.Errorf("%w: %s is not a user or project settings file here", ErrScope, s.File)
			}
			switch s.Key {
			case claudesettings.KeyDeny, claudesettings.KeyAsk:
			case claudesettings.KeyDeniedDomains:
				// The sandbox's domain list is written only as part of a
				// host intent, and only a plain host.
				if what, _, ok := intentParts(s.IntentID); !ok || what != string(WhatHost) || !plainHost(s.Value) {
					return res, errors.New("rulebook: sandbox.network.deniedDomains is written only for a host name, as part of a rule that covers every route")
				}
			default:
				return res, fmt.Errorf("rulebook: key %q: rules are added to permissions.deny or permissions.ask", s.Key)
			}
			if err := checkValue(s.Value); err != nil {
				return res, err
			}
			if err := checkNativeString(s.Value); err != nil {
				return res, err
			}
			row := RowID(kindForKey(s.Key), loc.Scope, s.Key, s.Value)
			intent := s.IntentID
			if intent == "" {
				intent = row
			}
			var w *nativeWrite
			for _, x := range writes {
				if x.loc.Path == loc.Path {
					w = x
				}
			}
			if w == nil {
				w = &nativeWrite{loc: loc}
				writes = append(writes, w)
			}
			c := claudesettings.Claim{Value: s.Value, RuleID: intent}
			placed := false
			for i := range w.groups {
				if g := &w.groups[i]; g.key == s.Key {
					if !hasClaim(g.claims, c) {
						g.claims = append(g.claims, c)
					}
					placed = true
				}
			}
			if !placed {
				w.groups = append(w.groups, nativeGroup{key: s.Key, claims: []claudesettings.Claim{c}})
			}
			res.RowIDs = append(res.RowIDs, row)
		case MechHook, MechSubject:
			project := false
			switch clean := filepath.Clean(s.File); {
			case clean == filepath.Clean(over):
			case projPol != "" && clean == filepath.Clean(projPol) && intentStep(s):
				project = true
			default:
				return res, fmt.Errorf("%w: %s is not the user policy file", ErrScope, s.File)
			}
			scope := claudesettings.ScopeUser
			if project {
				scope = claudesettings.ScopeProject
			}
			switch {
			case s.Mechanism == MechHook && s.Key == rulesOverridesKey:
				// A pack rule's action: re-read from the value, never
				// trusted from the plan.
				key, _, err := parsePackRuleStep(s.Value)
				if err != nil {
					return res, err
				}
				res.RowIDs = append(res.RowIDs, "pack:"+key)
			case s.Mechanism == MechHook:
				if s.Rule == nil {
					return res, errors.New("rulebook: a hook step carries no rule")
				}
				if err := checkMatch(s.Rule.Match); err != nil {
					return res, err
				}
				// The id is recomputed from the match, never trusted from
				// the plan: a plan cannot put its rule under another id.
				// An intent's rule keeps the one id its intent gives it.
				v := hookRuleValue(s.Rule.Match)
				if v == "" {
					return res, errors.New("rulebook: a hook rule matches nothing")
				}
				r := *s.Rule
				if !intentStep(s) {
					r.ID = hookRuleID(v)
				}
				s.Rule = &r
				res.RowIDs = append(res.RowIDs, RowID(KindHookRegex, scope, "", r.ID))
			case s.Subject != nil:
				if err := checkIntentSubject(s); err != nil {
					return res, err
				}
				res.RowIDs = append(res.RowIDs, RowID(KindSubject, scope, policy.KindTool, s.Value))
			default:
				if !manifest.ValidMCPServerPattern(s.Value) {
					return res, fmt.Errorf("rulebook: invalid MCP server name (%s)", manifest.MCPServerRule)
				}
				res.RowIDs = append(res.RowIDs, RowID(KindSubject, claudesettings.ScopeUser, policy.KindMCP, s.Value))
			}
			var pw *policyWrite
			for _, x := range policies {
				if x.project == project {
					pw = x
				}
			}
			if pw == nil {
				pw = &policyWrite{path: s.File, project: project}
				policies = append(policies, pw)
			}
			pw.steps = append(pw.steps, s)
		default:
			return res, fmt.Errorf("rulebook: unknown mechanism %q", s.Mechanism)
		}
	}

	// Try every policy edit on the loaded files first: a refused edit
	// (the policy file's own check) stops the plan before any write.
	for _, pw := range policies {
		f, _, err := loadPolicy(pw.path, pw.project)
		if err != nil {
			return res, err
		}
		if _, err := pw.apply(&f); err != nil {
			return res, err
		}
	}

	var undeclineErr error
	for _, w := range writes {
		err := claudesettings.Transact(in.Paths.StateDir, func(led *claudesettings.Ledger) error {
			edits := make([]claudesettings.KeyEdit, 0, len(w.groups))
			for _, g := range w.groups {
				edits = append(edits, claudesettings.KeyEdit{Key: g.key, Adds: g.claims})
			}
			chs, err := claudesettings.ManageKeys(w.loc, led, edits)
			if err != nil {
				return err
			}
			for _, ch := range chs {
				if len(ch.Added) > 0 {
					res.wrote(w.loc.Path, ch.Backup)
					break // one write, one backup for the file
				}
			}
			// Every claim of the file is now written or was already
			// there: a recommended rule installed is no longer declined.
			// A failure here still saves the ledger (the settings file is
			// already written) and is returned once the rest is done.
			var intents []string
			for _, g := range w.groups {
				for _, c := range g.claims {
					if strings.HasPrefix(c.RuleID, IntentPrefix) {
						intents = append(intents, c.RuleID)
					}
				}
			}
			if len(intents) > 0 && undeclineErr == nil {
				undeclineErr = undecline(in.Paths.StateDir, intents)
			}
			return nil
		})
		if err != nil {
			return res, err
		}
	}

	for _, pw := range policies {
		if err := editPolicyFile(pw.path, pw.project, &res, pw.apply); err != nil {
			return res, err
		}
	}
	if undeclineErr != nil {
		return res, fmt.Errorf("rulebook: rules written, but the declined list was not updated: %w", undeclineErr)
	}
	return res, nil
}

// policyWrite is the hook and subject steps for one policy file.
type policyWrite struct {
	path    string
	project bool
	steps   []Step
}

// apply runs pw's steps on f; changed is true when any of them changed it.
func (pw *policyWrite) apply(f *policy.File) (bool, error) {
	changed := false
	for _, s := range pw.steps {
		var e policy.Edit
		switch {
		case s.Mechanism == MechHook && s.Key == rulesOverridesKey:
			key, action, err := parsePackRuleStep(s.Value)
			if err != nil {
				return false, err
			}
			t := manifest.Toggle{}
			if cur, ok := f.RuleOverrides[key]; ok {
				t = cur.Clone() // an existing enabled is kept
			}
			t.Action = action
			e = policy.Edit{Rule: key, RuleOverride: &t}
		case s.Mechanism == MechHook:
			e = policy.Edit{PutRule: s.Rule}
		case s.Subject != nil:
			e = policy.Edit{Kind: policy.KindTool, Name: s.Value, Put: s.Subject}
		default:
			sub := manifest.PolicySubject{Kind: policy.KindMCP, Name: s.Value}
			for _, cur := range f.Subjects {
				if cur.Kind == policy.KindMCP && cur.Name == s.Value {
					sub = cur.Clone()
				}
			}
			launch := manifest.MCPLaunch{Sandbox: true}
			if sub.Launch != nil {
				launch.Grant = sub.Launch.Grant
			}
			sub.Launch = &launch
			e = policy.Edit{Kind: policy.KindMCP, Name: s.Value, Put: &sub}
		}
		c, err := policy.Apply(f, e)
		if err != nil {
			return false, err
		}
		changed = changed || c
	}
	return changed, nil
}

// intentStep reports whether a hook or subject step belongs to its own
// everywhere intent: the step's IntentID is intent:<what>:<hex8> and its
// rule id or subject name is the one that intent gives.
func intentStep(s Step) bool {
	what, h, ok := intentParts(s.IntentID)
	if !ok {
		return false
	}
	switch {
	case s.Mechanism == MechHook && s.Key == "rules" && s.Rule != nil:
		return s.Rule.ID == intentRuleID(what, h)
	case s.Mechanism == MechSubject && s.Subject != nil:
		return s.Subject.Name == intentSubjectName(what, h) && s.Value == s.Subject.Name
	}
	return false
}

// checkIntentSubject checks a tool subject step: it belongs to its intent,
// and its tools and lists are the ones that intent's kind writes (Grep and
// Glob paths for a path, WebFetch domains for a host). The policy file's
// own check covers the entries' grammar.
func checkIntentSubject(s Step) error {
	bad := errors.New("rulebook: a tool subject is written only as part of a rule that covers every route")
	what, _, ok := intentParts(s.IntentID)
	sub := s.Subject
	if !ok || !intentStep(s) || sub.Kind != policy.KindTool || sub.Grant != nil || sub.Launch != nil ||
		len(sub.MCPTools) > 0 || sub.AgentTools != nil || sub.AgentSkills != nil ||
		len(sub.Match.Argv0)+len(sub.Match.Glob) > 0 || sub.Match.AgentType != "" {
		return bad
	}
	tools := strings.Join(sub.Match.Tools, "|")
	switch What(what) {
	case WhatPath:
		if tools != "Grep|Glob" || sub.Paths.IsEmpty() || !sub.Domains.IsEmpty() {
			return bad
		}
	case WhatHost:
		if tools != "WebFetch" || sub.Domains.IsEmpty() || !sub.Paths.IsEmpty() {
			return bad
		}
	default:
		return bad
	}
	return nil
}

// checkMatch runs checkValue on a hook rule's regex, literals and argv0, so
// a deserialised Plan cannot slip in a control character.
func checkMatch(m manifest.RuleMatch) error {
	if m.Regex != "" {
		if err := checkValue(m.Regex); err != nil {
			return err
		}
	}
	for _, list := range [][]string{m.Literals, m.Argv0} {
		for _, v := range list {
			if err := checkValue(v); err != nil {
				return err
			}
		}
	}
	return nil
}

// editPolicy loads the user policy file, runs fn and saves the file when fn
// reports a change, recording the write and its backup in res.
func editPolicy(path string, res *Result, fn func(f *policy.File) (bool, error)) error {
	return editPolicyFile(path, false, res, fn)
}

// loadPolicy loads a policy file: a project's file with the project
// checks (it must resolve inside its own directory and be a regular file).
func loadPolicy(path string, project bool) (policy.File, bool, error) {
	if project {
		return policy.LoadProjectFile(path)
	}
	return policy.LoadFile(path)
}

// editPolicyFile is editPolicy for the user policy file or, with project,
// a project's policy file. It is the one place rulebook writes a policy
// file: policy.Apply (in fn) then policy.Save.
func editPolicyFile(path string, project bool, res *Result, fn func(f *policy.File) (bool, error)) error {
	f, _, err := loadPolicy(path, project)
	if err != nil {
		return err
	}
	changed, err := fn(&f)
	if err != nil || !changed {
		return err
	}
	backup, err := policy.Save(path, f)
	if err != nil {
		return err
	}
	res.wrote(path, backup)
	return nil
}

// Remove takes one row out:
//
//	native:<scope>:<key>:<hex8>  every ledger claim on the string goes, and
//	                             so the string (a row watchdeck did not add
//	                             is ErrNotOwned, naming the file to edit)
//	pack:<pack>/<rule>           the rule's override is cleared, so it is
//	                             back at its pack's action and state (the
//	                             pack rule itself stays; SetEnabled turns
//	                             it off); no override is no change
//	user:<id>                    the user policy file's rule is deleted
//	subject:<kind>:<name>[:…]    the whole subject is deleted (a skill's
//	                             grant block is reset; "*", the defaults
//	                             for every skill, is refused)
//
//	domain:<scope>:<key>:<hex8>  as native, for a sandbox domain an
//	                             everywhere intent owns (any other is
//	                             ErrNotOwned)
//
// A rule or subject an everywhere intent named (intent-…) is looked for in
// the user policy file, then in the project's. Other rows (auto mode,
// sandbox exclusions) are the person's to edit and are refused. A row that
// names nothing is an error. Remove takes one row even when it belongs to
// an intent; RemoveIntent takes the whole intent.
func Remove(in Input, rowID string) (Result, error) {
	res := Result{Written: []string{}, Backups: []string{}, RowIDs: []string{rowID}}
	return res, removeRow(in, rowID, nil, &res)
}

// removeRow is Remove recording into res. With a nil led a native row is
// removed in its own claudesettings.Transact; otherwise the caller already
// holds the lock and led, and saves it.
func removeRow(in Input, rowID string, led *claudesettings.Ledger, res *Result) error {
	prefix, rest, _ := strings.Cut(rowID, ":")
	over := in.Paths.OverridesFile()
	switch prefix {
	case "native", "domain":
		// A sandbox domain row is removed only when an intent owns it.
		domain := prefix == "domain"
		if led != nil {
			return removeNative(in, rowID, rest, res, led, domain)
		}
		return claudesettings.Transact(in.Paths.StateDir, func(led *claudesettings.Ledger) error {
			return removeNative(in, rowID, rest, res, led, domain)
		})
	case "pack":
		if _, _, ok := packRule(rest); !ok {
			return fmt.Errorf("rulebook: no rule %q", rowID)
		}
		return editPolicy(over, res, func(f *policy.File) (bool, error) {
			return policy.Apply(f, policy.Edit{Rule: rest, RuleOverride: nil})
		})
	case "user":
		if _, ok := intentOfRule(rest); ok {
			return removeIntentPolicyRow(in, res, policy.Edit{DeleteRule: rest}, rowID)
		}
		return editPolicy(over, res, func(f *policy.File) (bool, error) {
			c, err := policy.Apply(f, policy.Edit{DeleteRule: rest})
			if err == nil && !c {
				err = fmt.Errorf("rulebook: no rule %q in %s (a project rule is removed from its %s by hand)", rest, over, manifest.ProjectOverridesFile)
			}
			return c, err
		})
	case "subject":
		parts := strings.SplitN(rest, ":", 3)
		if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
			return fmt.Errorf("rulebook: no rule %q", rowID)
		}
		e := policy.Edit{Kind: parts[0], Name: parts[1], Delete: true}
		if parts[0] == policy.KindSkill {
			// A skill subject is a grant block: Reset deletes it (policy.Apply
			// routes skills through manifest.Apply, which ignores Delete).
			// "*" is the defaults block for every skill, edited with
			// rules grant, never removed as a row.
			if parts[1] == "*" {
				return fmt.Errorf("rulebook: the skill defaults (\"*\") are changed with %s rules grant, not removed", paths.BinaryName)
			}
			e = policy.Edit{Kind: policy.KindSkill, Name: parts[1], Grant: manifest.Edit{Reset: true}}
		}
		if _, ok := intentOfSubject(parts[1]); ok && parts[0] == policy.KindTool {
			return removeIntentPolicyRow(in, res, e, rowID)
		}
		return editPolicy(over, res, func(f *policy.File) (bool, error) {
			c, err := policy.Apply(f, e)
			if err == nil && !c {
				err = fmt.Errorf("rulebook: no %s subject %q in %s (a project subject is removed from its %s by hand)", parts[0], parts[1], over, manifest.ProjectOverridesFile)
			}
			return c, err
		})
	case "automode", "excluded":
		return fmt.Errorf("rulebook: %s rows are not removed by %s; edit the settings file by hand", prefix, paths.BinaryName)
	}
	return fmt.Errorf("rulebook: no rule %q", rowID)
}

// removeNative removes a native row: it finds the string by its hash among
// led's entries for that scope's file and key and drops every claim on
// it, which removes the string. The caller holds the lock and saves led.
func removeNative(in Input, rowID, rest string, res *Result, led *claudesettings.Ledger, intentOnly bool) error {
	parts := strings.SplitN(rest, ":", 3)
	if len(parts) != 3 {
		return fmt.Errorf("rulebook: no rule %q", rowID)
	}
	scope, key, h := claudesettings.Scope(parts[0]), parts[1], parts[2]
	var locs []claudesettings.Location
	for _, l := range claudesettings.Locate(in.Paths, in.ProjectRoot) {
		if l.Scope == scope {
			locs = append(locs, l)
		}
	}
	for _, l := range locs {
		for _, e := range led.Entries {
			if e.Key != key || hash8(e.Value) != h || filepath.Clean(e.Path) != filepath.Clean(l.Path) {
				continue
			}
			value := e.Value
			owners := led.Owners(l.Path, key, value)
			if len(owners) == 0 || (intentOnly && !anyIntent(owners)) {
				return fmt.Errorf("rulebook: %s: %w; remove it from %s by hand", value, ErrNotOwned, l.Path)
			}
			for _, id := range owners {
				ch, err := claudesettings.Manage(l, led, key, nil, []string{value}, id)
				if err != nil {
					return err
				}
				if len(ch.Removed) > 0 {
					res.wrote(l.Path, ch.Backup)
				}
			}
			return nil
		}
	}
	// Not in the ledger: say whether the string is the person's or nowhere.
	eff, _ := claudesettings.Read(locs, nil)
	for _, e := range listFor(eff, key) {
		if hash8(e.Value) == h {
			return fmt.Errorf("rulebook: %s: %w; remove it from %s by hand", e.Value, ErrNotOwned, e.Path)
		}
	}
	return fmt.Errorf("rulebook: no rule %q", rowID)
}

// anyIntent reports whether one of ids is an everywhere intent.
func anyIntent(ids []string) bool {
	for _, id := range ids {
		if _, _, ok := intentParts(id); ok {
			return true
		}
	}
	return false
}

// removeIntentPolicyRow deletes an intent's rule or subject (e) from the
// user policy file, else from the project's.
func removeIntentPolicyRow(in Input, res *Result, e policy.Edit, rowID string) error {
	files := []struct {
		path    string
		project bool
	}{{in.Paths.OverridesFile(), false}}
	if in.projectPolicyOnly && in.ProjectRoot != "" {
		// An undo of a project-scope add: its rows live in the project file.
		files = files[:0]
	}
	if in.ProjectRoot != "" {
		files = append(files, struct {
			path    string
			project bool
		}{filepath.Join(in.ProjectRoot, manifest.ProjectOverridesFile), true})
	}
	for _, pf := range files {
		done := false
		err := editPolicyFile(pf.path, pf.project, res, func(f *policy.File) (bool, error) {
			c, err := policy.Apply(f, e)
			done = c
			return c, err
		})
		if err != nil || done {
			return err
		}
	}
	return fmt.Errorf("rulebook: no rule %q", rowID)
}
