// Package policy is the policy file v2 model (M6.1): the user overrides.yaml
// (trusted) and the project .watchdeck.yaml (untrusted), version 1 or 2,
// resolved into subjects of five kinds and two enforcement classes.
//
//   - sandbox: OS-enforced through `watchdeck run` (skills, command
//     subjects, MCP servers launched through run).
//   - gate: the hook answers deny, ask or nothing; a gate never allows, so
//     Claude Code's own permissions keep the final say (MCP tool names,
//     file and web tool gates, agent rules, rule packs). Not OS-enforced.
//
// The strict decoder lives in internal/manifest (ParsePolicyFile), so that
// manifest.LoadOverrides, which the hook and run use, reads a v2 file too.
// This package adds the semantic layer: Load with project restrictions and
// warnings, SkillGrant (exactly manifest.Grant), the command / MCP / tool /
// agent lookups, Apply and Save.
//
// As of M6.1 nothing enforces a non-skill subject: the hook pipeline that
// uses these lookups is M6.3. Skill grants are what the hook and run already
// enforce, through manifest.Grant on the same files.
//
// Every function here is pure apart from Load, LoadFile and Save, which read
// and write the files they are given.
package policy

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/manifest"
	"github.com/Panda-Taps-LLC/watchdeck/internal/rules"
)

// Kind is a subject kind.
type Kind = string

// Subject kinds (re-exported from manifest).
const (
	KindSkill   Kind = manifest.KindSkill
	KindCommand Kind = manifest.KindCommand
	KindMCP     Kind = manifest.KindMCP
	KindTool    Kind = manifest.KindTool
	KindAgent   Kind = manifest.KindAgent
)

// Class is an enforcement class.
type Class string

const (
	// ClassSandbox is OS-enforced through `watchdeck run`.
	ClassSandbox Class = "sandbox"
	// ClassGate is decided by the hook (deny, ask or no opinion), never
	// allowed by it, and is not OS-enforced.
	ClassGate Class = "gate"
)

// Action is a gate lookup result. Larger is stronger.
type Action int

const (
	ActionNone Action = iota
	ActionLog
	ActionAsk
	ActionDeny
)

// String returns none | log | ask | deny.
func (a Action) String() string {
	switch a {
	case ActionLog:
		return "log"
	case ActionAsk:
		return "ask"
	case ActionDeny:
		return "deny"
	}
	return "none"
}

func actionOf(s string) Action {
	switch s {
	case manifest.ActDeny:
		return ActionDeny
	case manifest.ActAsk:
		return ActionAsk
	case manifest.ActLog:
		return ActionLog
	}
	return ActionNone
}

// File is one parsed overrides file (v1 converts in memory).
type File = manifest.PolicyFile

// Subject is one subject with the file it came from.
type Subject struct {
	manifest.PolicySubject
	Source manifest.Source
}

// Class reports the subject's enforcement class: skill and command are
// sandbox; tool and agent are gate; mcp is sandbox when it has a launch
// block with sandbox: true (user file only), else gate. An mcp subject's
// tools map is a gate either way.
func (s *Subject) Class() Class { return SubjectClass(s.PolicySubject) }

// SubjectClass is Subject.Class for a bare manifest.PolicySubject.
func SubjectClass(s manifest.PolicySubject) Class {
	switch s.Kind {
	case KindSkill, KindCommand:
		return ClassSandbox
	case KindMCP:
		if s.Launch != nil && s.Launch.Sandbox {
			return ClassSandbox
		}
	}
	return ClassGate
}

// Warning is a project-file entry that was ignored. Field is a field path
// (names in it are validated), Reason a fixed phrase: no value from the file
// is echoed.
type Warning struct {
	Source manifest.Source
	Field  string
	Reason string
}

// String renders "project policy ignored: <field> (<reason>)".
func (w Warning) String() string {
	return w.Source.String() + " policy ignored: " + w.Field + " (" + w.Reason + ")"
}

// Layer is one file of a Policy.
type Layer struct {
	Path   string
	Exists bool
	File   File               // as parsed (project restrictions not applied)
	Skills manifest.Overrides // skill projection: what manifest.Grant reads
}

// Policy is the user and project files resolved together.
type Policy struct {
	User, Project Layer

	// Home is the user's home directory, used by ToolGate to expand ~ and
	// ${HOME} in path patterns. "" leaves them unexpanded (they then match
	// only a target spelled with ~).
	Home string

	// ResolveEntries makes ToolGate also compare a plain path entry in its
	// real spelling (symlinks resolved on the longest existing prefix). The
	// hook sets it; pure lookups (tests, the dashboard's preview) leave it
	// off and touch no file.
	ResolveEntries bool

	subjects []*Subject                    // user then project, project restrictions applied
	packs    [2]map[string]manifest.Toggle // [user, project-accepted]
	ruleOv   [2]map[string]manifest.Toggle
	rules    []Rule
	temps    []manifest.Temporary // the user file's temporaries in force at NewAt's now
}

// Rule is a user-written rule with its source.
type Rule struct {
	manifest.PolicyRule
	Source manifest.Source
}

// LoadFile reads and strictly parses one file. exists is false (with no
// error) when the file is absent. Errors name the file through
// manifest.DisplayPath and never echo its contents, matching
// manifest.LoadOverridesFile.
func LoadFile(path string) (f File, exists bool, err error) {
	return loadFile(path, "")
}

// LoadProjectFile is LoadFile for a project's .watchdeck.yaml: the file
// must resolve (through symlinks) inside its own directory, and must be a
// regular file (manifest.ReadProjectPolicyFile).
func LoadProjectFile(path string) (f File, exists bool, err error) {
	return loadFile(path, filepath.Dir(path))
}

func loadFile(path, projectRoot string) (f File, exists bool, err error) {
	var b []byte
	if projectRoot != "" {
		b, err = manifest.ReadProjectPolicyFile(path, projectRoot)
	} else {
		b, err = manifest.ReadPolicyFile(path)
	}
	if errors.Is(err, fs.ErrNotExist) {
		return File{}, false, nil
	}
	if err != nil {
		var pe *fs.PathError
		if errors.As(err, &pe) {
			err = pe.Err
		}
		return File{}, true, fmt.Errorf("%s: %w", manifest.DisplayPath(path), err)
	}
	if projectRoot != "" {
		f, err = manifest.ParseProjectPolicyFile(b)
	} else {
		f, err = manifest.ParsePolicyFile(b)
	}
	if err != nil {
		return File{}, true, fmt.Errorf("%s: %w", manifest.DisplayPath(path), err)
	}
	return f, true, nil
}

// Shadow reports whether the user file puts watchdeck's own rules and
// gates in shadow mode (Phase 6): verdicts are recorded, never printed.
func (p *Policy) Shadow() bool { return p.User.File.Mode == manifest.ModeShadow }

// ShadowOn reads the user policy file and reports its mode. Absent:
// (false, nil); unreadable or invalid: (false, err) with LoadFile's error
// (path through DisplayPath, no value). doctor, status and prove read it.
func ShadowOn(userPath string) (on bool, err error) {
	f, exists, err := LoadFile(userPath)
	if err != nil || !exists {
		return false, err
	}
	return f.Mode == manifest.ModeShadow, nil
}

// Load reads the user file (trusted) and the project file (untrusted). An
// empty path skips that file; a missing file is empty. A malformed file is an
// error naming its path. Warnings list every project entry that was ignored
// because only the user file may set it (see New).
func Load(userPath, projectPath string) (*Policy, []Warning, error) {
	var user, project Layer
	var err error
	if userPath != "" {
		user.Path = userPath
		if user.File, user.Exists, err = LoadFile(userPath); err != nil {
			return nil, nil, err
		}
	}
	if projectPath != "" {
		project.Path = projectPath
		if project.File, project.Exists, err = LoadProjectFile(projectPath); err != nil {
			return nil, nil, err
		}
	}
	p, warns := New(user, project)
	return p, warns, nil
}

// New is NewAt(time.Now(), user, project).
func New(user, project Layer) (*Policy, []Warning) { return NewAt(time.Now(), user, project) }

// NewAt builds a Policy from two parsed layers at now (Skills is filled
// from File). The user file's temporaries in force at now (Until after
// now) apply: its grant temporaries widen Skills (manifest.SkillOverridesAt)
// and its rule temporaries are what Paused reads. An expired entry is
// ignored; a project file's temporaries never apply (the loader refuses
// such a file; here they are dropped with a warning).
//
// The project file may not:
//   - widen a skill grant beyond ${CWD}/${TMP} and localhost, or set env,
//     caches or auto_allow (clipped when the grant is resolved, by
//     manifest.Widen, and reported by SkillGrant);
//   - define a command subject (a command subject wraps a command the user
//     runs in `run`; that choice is the user's): ignored;
//   - launch an MCP server (launch is dropped);
//   - set the mode (shadow mode is the user file's choice): ignored;
//   - disable or weaken a rule pack or a rule: a pack or rule toggle is kept
//     only when it leaves the pack or rule enabled and its action, if set, is
//     at least as strong as the default action of every rule it covers (and,
//     for a rule, as the user file's action for its pack). An unknown pack or
//     rule is ignored.
//
// Gates (mcp tools, tool paths/domains, agent tools) only deny or ask and
// an agent skills.allow list only narrows, so the project file keeps them,
// and its rules (deny | ask | log) only add.
func NewAt(now time.Time, user, project Layer) (*Policy, []Warning) {
	user.Skills = manifest.SkillOverridesAt(now, &user.File)
	project.Skills = project.File.BaseSkillOverrides()
	p := &Policy{User: user, Project: project}
	var warns []Warning
	warn := func(field, reason string) {
		warns = append(warns, Warning{Source: manifest.SourceProject, Field: field, Reason: reason})
	}
	for _, t := range user.File.Temporary {
		if t.Active(now) {
			p.temps = append(p.temps, t.Clone())
		}
	}
	if len(project.File.Temporary) > 0 {
		warn("temporary", "only the user file can pause a rule or widen a grant for a while")
	}

	for _, s := range user.File.Subjects {
		p.subjects = append(p.subjects, &Subject{PolicySubject: s.Clone(), Source: manifest.SourceUser})
	}
	for _, s := range project.File.Subjects {
		c := s.Clone()
		field := "subjects." + c.Kind + ":" + c.Name
		if c.Kind == KindCommand {
			warn(field, "only the user file can define a command subject")
			continue
		}
		if c.Launch != nil {
			warn(field+".launch", "only the user file can launch an MCP server")
			c.Launch = nil
			if len(c.MCPTools) == 0 {
				continue
			}
		}
		p.subjects = append(p.subjects, &Subject{PolicySubject: c, Source: manifest.SourceProject})
	}
	// A cloned repository must not silence the person's rules: Shadow
	// reads the user file only.
	if project.File.Mode != "" {
		warn("mode", "only the user file can set the mode")
	}

	p.packs[0] = cloneToggles(user.File.Packs)
	p.ruleOv[0] = cloneToggles(user.File.RuleOverrides)
	// The built-in packs are loaded only when the project file has toggles:
	// a hook call with nothing configured pays nothing.
	var defaults packDefaults
	if len(project.File.Packs)+len(project.File.RuleOverrides) > 0 {
		defaults = builtinDefaults()
	}
	for _, id := range sortedKeys(project.File.Packs) {
		t := project.File.Packs[id]
		floor, known := defaults.packMax[id]
		switch {
		case !known:
			warn("packs."+id, "unknown pack")
			continue
		case userOff(user.File.Packs, id):
			warn("packs."+id, "the user file turned this pack off")
			continue
		case !strengthens(t, floor):
			warn("packs."+id, "the project file can only turn a pack on or raise its action")
			continue
		}
		if p.packs[1] == nil {
			p.packs[1] = map[string]manifest.Toggle{}
		}
		p.packs[1][id] = t.Clone()
	}
	for _, key := range sortedKeys(project.File.RuleOverrides) {
		t := project.File.RuleOverrides[key]
		floor, known := defaults.rule[key]
		if !known {
			warn("rule_overrides."+key, "unknown rule")
			continue
		}
		pack, _, _ := strings.Cut(key, "/")
		if userOff(user.File.Packs, pack) || userOff(user.File.RuleOverrides, key) {
			warn("rule_overrides."+key, "the user file turned this rule or its pack off")
			continue
		}
		if ut, ok := user.File.Packs[pack]; ok && rank(ut.Action) > floor {
			floor = rank(ut.Action)
		}
		if !strengthens(t, floor) {
			warn("rule_overrides."+key, "the project file can only turn a rule on or raise its action")
			continue
		}
		if p.ruleOv[1] == nil {
			p.ruleOv[1] = map[string]manifest.Toggle{}
		}
		p.ruleOv[1][key] = t.Clone()
	}

	for _, r := range user.File.Rules {
		p.rules = append(p.rules, Rule{PolicyRule: r, Source: manifest.SourceUser})
	}
	for _, r := range project.File.Rules {
		p.rules = append(p.rules, Rule{PolicyRule: r, Source: manifest.SourceProject})
	}
	return p, warns
}

// userOff reports whether the user file sets key to off.
func userOff(m map[string]manifest.Toggle, key string) bool {
	t, ok := m[key]
	return ok && t.Enabled != nil && !*t.Enabled
}

// rank orders actions: "" 0, log 1, ask 2, deny 3.
func rank(a string) int {
	switch a {
	case manifest.ActLog:
		return 1
	case manifest.ActAsk:
		return 2
	case manifest.ActDeny:
		return 3
	}
	return 0
}

// strengthens reports whether a project toggle leaves things enabled and
// sets no action below floor.
func strengthens(t manifest.Toggle, floor int) bool {
	if t.Enabled != nil && !*t.Enabled {
		return false
	}
	return t.Action == "" || rank(t.Action) >= floor
}

type packDefaults struct {
	packMax map[string]int // pack → strongest default action of its rules
	rule    map[string]int // "<pack>/<id>" → default action
}

// builtinDefaults reads the embedded packs (internal/rules). Built per call:
// a package-level table would be init work in the hook binary.
func builtinDefaults() packDefaults {
	d := packDefaults{packMax: map[string]int{}, rule: map[string]int{}}
	for _, pk := range rules.Packs() {
		m := 0
		for _, r := range pk.Rules {
			a := rank(string(r.Action))
			d.rule[pk.Name+"/"+r.ID] = a
			if a > m {
				m = a
			}
		}
		d.packMax[pk.Name] = m
	}
	return d
}

func cloneToggles(m map[string]manifest.Toggle) map[string]manifest.Toggle {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]manifest.Toggle, len(m))
	for k, v := range m {
		out[k] = v.Clone()
	}
	return out
}

// RulesConfig is the internal/rules configuration of this policy: the
// accepted project toggles, then the user file's, which replace a project
// entry with the same key.
func (p *Policy) RulesConfig() rules.Config {
	var cfg rules.Config
	for i := 1; i >= 0; i-- {
		for k, t := range p.packs[i] {
			if cfg.Packs == nil {
				cfg.Packs = map[string]rules.PackConfig{}
			}
			cfg.Packs[k] = rules.PackConfig{Enabled: t.Clone().Enabled, Action: rules.Action(t.Action)}
		}
		for k, t := range p.ruleOv[i] {
			if cfg.Rules == nil {
				cfg.Rules = map[string]rules.RuleConfig{}
			}
			cfg.Rules[k] = rules.RuleConfig{Enabled: t.Clone().Enabled, Action: rules.Action(t.Action)}
		}
	}
	return cfg
}

// FileRulesConfig is the internal/rules configuration one file states, with
// no project restriction applied. Save requires it to pass
// rules.Config.Validate.
func FileRulesConfig(f File) rules.Config {
	p, _ := New(Layer{File: f}, Layer{})
	return p.RulesConfig()
}

// Subjects returns every subject, user file first, project restrictions
// applied (a project mcp launch block is gone). The slice is a copy; the
// subjects are shared.
func (p *Policy) Subjects() []*Subject {
	return append([]*Subject(nil), p.subjects...)
}

// Packs returns the pack toggles of the user file and the accepted ones of
// the project file (RulesConfig merges them).
func (p *Policy) Packs() (user, project map[string]manifest.Toggle) {
	return p.packs[0], p.packs[1]
}

// RuleOverrides returns the rule toggles of the user file and the accepted
// ones of the project file.
func (p *Policy) RuleOverrides() (user, project map[string]manifest.Toggle) {
	return p.ruleOv[0], p.ruleOv[1]
}

// Paused reports whether the rule "<pack>/<id>" (pack "user" for a
// policy-file rule) is paused for session: a rule temporary in force for
// every session, or for this one. tempID is the temporary's id. A paused
// rule has no opinion (the hook drops its hit and logs it).
func (p *Policy) Paused(pack, id, session string) (tempID string, ok bool) {
	if len(p.temps) == 0 {
		return "", false
	}
	key := pack + "/" + id
	for _, t := range p.temps {
		if t.Kind == manifest.TempRule && t.Rule == key && (t.Session == "" || t.Session == session) {
			return t.ID, true
		}
	}
	return "", false
}

// Temporaries returns the user file's temporaries in force (copies).
func (p *Policy) Temporaries() []manifest.Temporary {
	out := make([]manifest.Temporary, 0, len(p.temps))
	for _, t := range p.temps {
		out = append(out, t.Clone())
	}
	return out
}

// Rules returns the user-written rules, user file first.
func (p *Policy) Rules() []Rule { return append([]Rule(nil), p.rules...) }

// SkillGrant is the grant for one skill, exactly manifest.Grant on the two
// files' skill projections: Default → project defaults → project "*" →
// project <name> → user defaults → user "*" → user <name>, the project layer
// clipped (manifest.Widen). ignored lists every clipped project entry, in
// manifest's wording. Pure: the real-path re-check of project-scoped entries
// stays a separate step (manifest.ResolveProjectScoped), as in run.
func (p *Policy) SkillGrant(name string) (manifest.Effective, []string) {
	return manifest.Grant(name, p.User.Skills, p.Project.Skills)
}

// CommandGrant is the grant for a command subject: Default widened by its
// grant block. Command subjects come from the user file only.
func (p *Policy) CommandGrant(s *Subject) (manifest.Effective, []string) {
	eff := manifest.Default()
	if s == nil || s.Grant == nil {
		return eff, nil
	}
	return manifest.Widen(eff, *s.Grant, s.Source)
}

func sortedKeys[V any](m map[string]V) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
