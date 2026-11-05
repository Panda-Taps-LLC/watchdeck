package rulebook

import (
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/manifest"
	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
	"github.com/Panda-Taps-LLC/watchdeck/internal/policy"
)

// Temporary allows (Plan 08): pausing one of watchdeck's own rules for a
// while or for one session, and widening a skill's grant for a while. Both
// are entries under the user policy file's temporary: list
// (manifest.Temporary), written through policy.Apply and policy.Save.
// Native Claude Code rules and auto mode's rules cannot be paused, and
// nothing here ever allows a call: a paused rule has no opinion, and a
// timed grant never carries auto_allow.

// ErrNotPausable is Pause's error for a row that is not one of
// watchdeck's own rules (pack:… or user:…). Nothing is written. Pause
// returns an error that Is ErrNotPausable and whose text fits the row: a
// skill's grant row names allow --for, another policy-file subject says to
// remove it.
var ErrNotPausable = errors.New("rulebook: Claude Code's own rule; change it in Claude Code (only pack:… and user:… rules can be paused)")

// notPausable is ErrNotPausable with a sentence for one row.
type notPausable struct{ msg string }

func (e notPausable) Error() string        { return e.msg }
func (e notPausable) Is(target error) bool { return target == ErrNotPausable }

// errNotPausable is the refusal for rowID.
func errNotPausable(rowID string) error {
	rest, ok := strings.CutPrefix(rowID, "subject:")
	if !ok {
		return ErrNotPausable
	}
	kind, name, _ := strings.Cut(rest, ":")
	name, _, _ = strings.Cut(name, ":")
	if kind == manifest.KindSkill && manifest.ValidSkillName(name) && name != "*" {
		return notPausable{"rulebook: a skill's sandbox grant; use " + paths.BinaryName + " allow " + name + " --for 1h to widen it for a while (only pack:… and user:… rules can be paused)"}
	}
	return notPausable{"rulebook: a " + paths.BinaryName + " path, domain, MCP or agent rule cannot be paused; remove it instead (only pack:… and user:… rules can be paused)"}
}

// ErrNoTemporary is End's error for an id the user policy file does not
// hold.
var ErrNoTemporary = errors.New("rulebook: no temporary with that id")

// MaxGrantFor is the longest a timed grant may last.
const MaxGrantFor = manifest.SessionBackstop

// ForSpecs are the spellings Pause takes: one hour, eight hours, or this
// session (until it ends, with the eight-hour backstop).
const ForSpecs = "1h, 8h or session=<id>"

// parseFor reads a Pause duration: until and the session ("" for every
// session).
func parseFor(spec string, now time.Time) (until time.Time, session string, err error) {
	switch spec {
	case "1h":
		return now.Add(time.Hour), "", nil
	case "8h":
		return now.Add(8 * time.Hour), "", nil
	}
	if s, ok := strings.CutPrefix(spec, "session="); ok && manifest.ValidSessionID(s) {
		return now.Add(manifest.SessionBackstop), s, nil
	}
	return time.Time{}, "", errors.New("rulebook: pause for " + ForSpecs)
}

// pauseKey is the temporary's rule ("<pack>/<id>") for a row id, or ok
// false for a row that cannot be paused.
func pauseKey(rowID string) (key string, ok bool) {
	if k, found := strings.CutPrefix(rowID, "pack:"); found && manifest.ValidRuleKey(k) {
		return k, true
	}
	if id, found := strings.CutPrefix(rowID, "user:"); found && manifest.ValidRuleID(id) {
		return "user/" + id, true
	}
	return "", false
}

// PauseRowID is the row id Pause takes for an inbox rule id ("<pack>/<id>",
// "user/<id>"), or ok false for one that cannot be paused (a Claude Code
// settings rule, "claude-settings/…").
func PauseRowID(ruleID string) (rowID string, ok bool) {
	pack, id, found := strings.Cut(ruleID, "/")
	switch {
	case !found:
		return "", false
	case pack == policy.UserPack && manifest.ValidRuleID(id):
		return "user:" + id, true
	case pack != "claude-settings" && manifest.ValidRuleKey(ruleID):
		return "pack:" + ruleID, true
	}
	return "", false
}

// userRuleExists reports whether a policy file rule with id is in the user
// or the project file (both report under pack user). The project file is
// read with the untrusted loader (it ships with a cloned repository).
func userRuleExists(in Input, id string) bool {
	has := func(f policy.File, err error) bool {
		if err != nil {
			return false
		}
		for _, r := range f.Rules {
			if r.ID == id {
				return true
			}
		}
		return false
	}
	f, _, err := policy.LoadFile(in.Paths.OverridesFile())
	if has(f, err) {
		return true
	}
	if pf := projectFile(in); pf != "" {
		f, _, err = policy.LoadProjectFile(pf)
		return has(f, err)
	}
	return false
}

// projectFile is the project's policy file, "" without a project.
func projectFile(in Input) string {
	if in.ProjectRoot == "" {
		return ""
	}
	return filepath.Join(in.ProjectRoot, manifest.ProjectOverridesFile)
}

// Pause pauses every row in rowIDs (pack:<pack>/<id> or user:<id>; a
// repeated row counts once) for forSpec (ForSpecs): one temporary per rule,
// all with the same until, in one write of the user policy file (backup
// first). A rule already paused for the same sessions (every session, or
// the same one) is paused again from now: the earlier entry is replaced,
// never doubled. Any other row is ErrNotPausable, an unknown rule an
// error; in both cases nothing is written. It returns the temporaries as
// written.
func Pause(in Input, rowIDs []string, forSpec string) ([]manifest.Temporary, error) {
	now := time.Now().UTC().Truncate(time.Second)
	until, session, err := parseFor(forSpec, now)
	if err != nil {
		return nil, err
	}
	var keys []string
	for _, id := range rowIDs {
		key, ok := pauseKey(id)
		if !ok {
			return nil, errNotPausable(id)
		}
		if !containsStr(keys, key) {
			keys = append(keys, key)
		}
	}
	if len(keys) == 0 {
		return nil, errors.New("rulebook: no rule to pause")
	}
	for _, key := range keys {
		pack, id, _ := strings.Cut(key, "/")
		if pack == policy.UserPack {
			if !userRuleExists(in, id) {
				return nil, fmt.Errorf("rulebook: no rule %q", "user:"+id)
			}
		} else if _, _, found := packRule(key); !found {
			return nil, fmt.Errorf("rulebook: no rule %q", "pack:"+key)
		}
	}
	var out []manifest.Temporary
	res := Result{}
	err = editPolicy(in.Paths.OverridesFile(), &res, func(f *policy.File) (bool, error) {
		anyChanged := false
		for _, key := range keys {
			t := manifest.Temporary{Kind: manifest.TempRule, Rule: key, Session: session, Added: now, Until: until}
			t.ID = manifest.TemporaryID(t)
			for _, cur := range append([]manifest.Temporary(nil), f.Temporary...) {
				// the same id too: a re-pause within one second has it
				if cur.Kind == manifest.TempRule && cur.Rule == key && cur.Session == session {
					if _, err := policy.Apply(f, policy.Edit{EndTemporary: cur.ID}); err != nil {
						return false, err
					}
					anyChanged = true
				}
			}
			changed, err := policy.Apply(f, policy.Edit{AddTemporary: &t})
			if err != nil {
				return false, err
			}
			anyChanged = anyChanged || changed
			out = append(out, t)
		}
		return anyChanged, nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// UngrantedEdit is one thing a skill asked for and was not granted, in a
// form GrantFor takes: Field network | write | read | env | caches, Value
// the request's value ("all", a path as the grant spells it, an env name;
// "true" for caches).
type UngrantedEdit struct {
	Skill string `json:"skill"`
	Field string `json:"field"`
	Value string `json:"value"`
}

// parseUngranted reads a decision record's ungranted item
// ("<skill>: <field>: <value>"); ok false for a field GrantFor cannot
// widen (exec, …) or a malformed item.
func parseUngranted(item string) (UngrantedEdit, bool) {
	skill, rest, ok := strings.Cut(item, ": ")
	if !ok || !manifest.ValidSkillName(skill) || skill == "*" {
		return UngrantedEdit{}, false
	}
	field, value, ok := strings.Cut(rest, ": ")
	if !ok || value == "" {
		return UngrantedEdit{}, false
	}
	switch field {
	case "network", "write", "read", "env", "caches":
		return UngrantedEdit{Skill: skill, Field: field, Value: value}, true
	}
	return UngrantedEdit{}, false
}

// GrantFor widens skill's grant for d (at most MaxGrantFor) with edits,
// each of which must name skill: a kind grant temporary in the user policy
// file, one write, backup first. Paths and values are checked as
// `watchdeck allow` checks them (a built-in deny path, through any
// spelling, is refused); auto_allow is never accepted (a timed grant
// never runs a script without asking). The permanent grant is untouched.
func GrantFor(in Input, skill string, edits []UngrantedEdit, d time.Duration) (manifest.Temporary, error) {
	if skill == "*" || !manifest.ValidSkillName(skill) {
		return manifest.Temporary{}, errors.New("rulebook: a timed grant names one skill (" + manifest.SkillNameRule + ")")
	}
	if d <= 0 || d > MaxGrantFor {
		return manifest.Temporary{}, errors.New("rulebook: a timed grant lasts more than nothing and at most 8 hours")
	}
	if len(edits) == 0 {
		return manifest.Temporary{}, errors.New("rulebook: nothing to grant")
	}
	e := manifest.Edit{Home: in.Paths.Home}
	for _, ed := range edits {
		if ed.Skill != skill {
			return manifest.Temporary{}, errors.New("rulebook: every edit of a timed grant names its skill")
		}
		switch ed.Field {
		case "network":
			n, err := manifest.ParseNetwork(ed.Value)
			if err != nil || n == manifest.NetNone {
				return manifest.Temporary{}, errors.New("rulebook: network: must be localhost or all")
			}
			if e.Network == nil || n > *e.Network {
				e.Network = &n
			}
		case "write":
			e.AddWrite = append(e.AddWrite, ed.Value)
		case "read":
			e.AddRead = append(e.AddRead, ed.Value)
		case "env":
			e.AddEnv = append(e.AddEnv, ed.Value)
		case "caches":
			yes := true
			e.Caches = &yes
		case "auto_allow":
			return manifest.Temporary{}, errors.New("rulebook: auto_allow cannot be granted for a while (a timed grant never runs a script without asking)")
		default:
			return manifest.Temporary{}, errors.New("rulebook: a timed grant widens network, write, read, env or caches")
		}
	}
	// manifest.Apply on an empty file normalises and checks the block the
	// way `watchdeck allow` does; nothing of it is written.
	out, _, err := manifest.Apply(manifest.Overrides{}, skill, e)
	if err != nil {
		return manifest.Temporary{}, err
	}
	g := out.Skills[skill]
	g.AutoAllow = nil
	now := time.Now().UTC().Truncate(time.Second)
	t := manifest.Temporary{Kind: manifest.TempGrant, Skill: skill, Grant: &g, Added: now, Until: now.Add(d)}
	t.ID = manifest.TemporaryID(t)
	res := Result{}
	err = editPolicy(in.Paths.OverridesFile(), &res, func(f *policy.File) (bool, error) {
		// Another grant for this skill written in the same second has the
		// same id; take the next free one (final review minor 7).
		for n := 1; n <= 64 && temporaryIDTaken(f.Temporary, t); n++ {
			t.ID = manifest.TemporaryIDN(t, n)
		}
		return policy.Apply(f, policy.Edit{AddTemporary: &t})
	})
	if err != nil {
		return manifest.Temporary{}, err
	}
	return t, nil
}

// End removes the temporary with id from the user policy file (one write,
// backup first); "all" removes every one (no entry is no write). An id not
// in the file is an error.
func End(in Input, id string) error {
	res := Result{}
	if id == "all" {
		return editPolicy(in.Paths.OverridesFile(), &res, func(f *policy.File) (bool, error) {
			changed := false
			for _, t := range append([]manifest.Temporary(nil), f.Temporary...) {
				c, err := policy.Apply(f, policy.Edit{EndTemporary: t.ID})
				if err != nil {
					return false, err
				}
				changed = changed || c
			}
			return changed, nil
		})
	}
	if !manifest.ValidTemporaryID(id) {
		return fmt.Errorf("%w: %q", ErrNoTemporary, id)
	}
	found := false
	err := editPolicy(in.Paths.OverridesFile(), &res, func(f *policy.File) (bool, error) {
		c, err := policy.Apply(f, policy.Edit{EndTemporary: id})
		found = c
		return c, err
	})
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("%w: %q", ErrNoTemporary, id)
	}
	return nil
}

// TemporaryView is one temporary in force, as the Rules page and
// `rules pause --list` show it. Until is RFC 3339 (UTC); Session is ""
// for a pause on every session and for a grant.
type TemporaryView struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Sentence string `json:"sentence"`
	Until    string `json:"until"`
	Session  string `json:"session"`
}

// ListTemporaries is the user policy file's temporaries in force now, in
// file order. A file that cannot be read lists none (List reports it).
func ListTemporaries(in Input) []TemporaryView {
	out := []TemporaryView{}
	f, _, err := policy.LoadFile(in.Paths.OverridesFile())
	if err != nil {
		return out
	}
	now := time.Now()
	for _, t := range f.Temporary {
		if !t.Active(now) {
			continue
		}
		out = append(out, TemporaryView{ID: t.ID, Kind: t.Kind, Sentence: temporarySentence(t), Until: t.Until.UTC().Format(time.RFC3339), Session: t.Session})
	}
	return out
}

// temporarySentence says what a temporary does, in the Rules page's voice.
func temporarySentence(t manifest.Temporary) string {
	if t.Kind == manifest.TempGrant {
		var parts []string
		g := t.Grant
		if g != nil {
			if g.Network != nil {
				parts = append(parts, "network "+g.Network.String())
			}
			for _, p := range g.Write {
				parts = append(parts, "write "+manifest.DisplayPath(p))
			}
			for _, p := range g.Read {
				parts = append(parts, "read "+manifest.DisplayPath(p))
			}
			for _, e := range g.Env {
				parts = append(parts, "env "+e)
			}
			if g.Caches {
				parts = append(parts, "cache folders")
			}
		}
		return "Skill " + t.Skill + " also gets " + strings.Join(parts, ", ")
	}
	rule := t.Rule
	if pack, id, _ := strings.Cut(t.Rule, "/"); pack == policy.UserPack {
		rule = "your rule " + id
	}
	if t.Session != "" {
		return "Paused " + rule + " for one session"
	}
	return "Paused " + rule + " for every session"
}

// temporaryIDTaken reports whether an entry of ts other than t itself
// has t's id (the same entry again stays a no-op in policy.Apply).
func temporaryIDTaken(ts []manifest.Temporary, t manifest.Temporary) bool {
	for _, cur := range ts {
		if cur.ID == t.ID {
			return !reflect.DeepEqual(cur, t)
		}
	}
	return false
}
