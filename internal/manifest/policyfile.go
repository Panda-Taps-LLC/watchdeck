package manifest

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/goccy/go-yaml"

	"github.com/Panda-Taps-LLC/watchdeck/internal/safeio"
)

// Policy file v2 (M6.1). The overrides files (user overrides.yaml, project
// .watchdeck.yaml) may be version 1 (defaults + skills, see
// ParseOverrides) or version 2, which adds subjects of other kinds, rule
// packs and rules. This file holds the one strict decoder for both versions;
// internal/policy builds the semantic model (classes, lookups, project
// restrictions, Save) on top of it. The decoder lives here, not in
// internal/policy, because ParseOverrides and LoadOverrides (used by the hook,
// run, audit and the map) must read a v2 file too, and policy imports this
// package.
//
// Errors follow ParseOverrides: they name the field path and the rule, never
// a value from the file. Names (subject, pack, rule id) are validated before
// they appear in a field path.

// Subject kinds.
const (
	KindSkill   = "skill"
	KindCommand = "command"
	KindMCP     = "mcp"
	KindTool    = "tool"
	KindAgent   = "agent"
)

// KindOrder is the render order of a subject kind (skill first). Unknown
// kinds sort last.
func KindOrder(kind string) int {
	switch kind {
	case KindSkill:
		return 0
	case KindCommand:
		return 1
	case KindMCP:
		return 2
	case KindTool:
		return 3
	case KindAgent:
		return 4
	}
	return 5
}

// Gate actions as written in the file.
const (
	ActDeny = "deny"
	ActAsk  = "ask"
	ActLog  = "log"
)

// Policy file modes (shadow mode, Phase 6). Enforce is the default and is
// normalised to "" at parse, so a file with mode: enforce and one without
// the line mean, and render, the same.
const (
	ModeEnforce = "enforce"
	ModeShadow  = "shadow"
)

// PolicyFile is one parsed and validated overrides file, version 1 or 2. A
// v1 file converts in memory: defaults stays Defaults and every skills: key
// becomes a skill subject (sorted by name; "*" included), so a v1 file and
// its v2 rendering mean the same thing. Nothing here applies a project
// restriction; internal/policy does.
type PolicyFile struct {
	Version int
	// Mode is "" (enforce, the default) | ModeShadow; user file only;
	// never from a v1 file.
	Mode          string
	Packs         map[string]Toggle // pack name → toggle (internal/rules.Config.Packs)
	RuleOverrides map[string]Toggle // "<pack>/<rule id>" → toggle (internal/rules.Config.Rules)
	Rules         []PolicyRule
	Defaults      Override // the skill "defaults" block (applies to every skill, before skill "*")
	Subjects      []PolicySubject
	// Temporary is the temporary: list (Plan 08, temporary.go); user file
	// only, file order, expired entries included until the next save.
	Temporary []Temporary
}

// Toggle is an entry under packs or rule_overrides, the shape of
// internal/rules' PackConfig and RuleConfig: `on`, `off` (also true/false,
// yes/no) set Enabled; a mapping `{enabled: bool, action: deny|ask|log}` sets
// either or both (an empty mapping is an error). Enabled nil keeps the
// default state, Action "" the default action.
type Toggle struct {
	Enabled *bool
	Action  string
}

// IsScalar reports whether t renders as `on` / `off`.
func (t Toggle) IsScalar() bool { return t.Enabled != nil && t.Action == "" }

// Equal compares two toggles.
func (t Toggle) Equal(u Toggle) bool {
	if t.Action != u.Action || (t.Enabled == nil) != (u.Enabled == nil) {
		return false
	}
	return t.Enabled == nil || *t.Enabled == *u.Enabled
}

// PolicyRule is one user-written rule under rules:. Regex is not compiled
// by the parser (internal/policy compiles it before Save; internal/rules at
// use).
type PolicyRule struct {
	ID       string
	Tool     string
	Match    RuleMatch
	Action   string // deny | ask | log
	Severity string // "" | low | medium | high | critical
}

// RuleMatch says what a rule looks for; at least one field is set.
type RuleMatch struct {
	Regex    string
	Literals []string
	Argv0    []string
}

// PolicySubject is one entry under subjects:. Which fields may be set
// depends on Kind (see ParsePolicyFile).
type PolicySubject struct {
	Kind string
	Name string

	Grant *Override // skill, command: the grant block (nil = none written)

	Match SubjectMatch // command: argv0/glob; tool: tools; agent: agent_type

	MCPTools map[string]string // mcp: tool-name glob → deny | ask
	Launch   *MCPLaunch        // mcp: launch through `run` (user file only)

	Paths   *GateLists // tool: path patterns
	Domains *GateLists // tool: domain patterns

	AgentTools  *GateLists // agent: tool names denied / asked
	AgentSkills []string   // agent: skills.allow; nil = no list (every skill), set = only these
}

// SubjectMatch is a subject's match block.
type SubjectMatch struct {
	Argv0     []string // command: program names (basename) or absolute paths; "*" = any
	Glob      []string // command: patterns over the whole command; '*' spans anything, '?' one byte
	Tools     []string // tool: tool names or globs (Write, Edit, mcp__*)
	AgentType string   // agent: agent type, glob or "*"
}

// MCPLaunch is an mcp subject's launch block.
type MCPLaunch struct {
	Sandbox bool
	Grant   *Override
}

// GateLists holds deny and ask entries of a gate. A gate has no allow.
type GateLists struct {
	Deny, Ask []string
}

// IsEmpty reports whether g has no entries.
func (g *GateLists) IsEmpty() bool { return g == nil || len(g.Deny)+len(g.Ask) == 0 }

// PolicyFromOverrides converts a v1 Overrides into a PolicyFile (Version 1,
// skill subjects sorted by name).
func PolicyFromOverrides(o Overrides) PolicyFile {
	f := PolicyFile{Version: 1, Defaults: o.Defaults.clone()}
	names := make([]string, 0, len(o.Skills))
	for n := range o.Skills {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		g := o.Skills[n].clone()
		f.Subjects = append(f.Subjects, PolicySubject{Kind: KindSkill, Name: n, Grant: &g})
	}
	return f
}

// CloneOverride deep-copies an Override (exported for internal/policy).
func CloneOverride(o Override) Override { return o.clone() }

// EmptyOverride reports whether a grant block has nothing set.
func EmptyOverride(o Override) bool { return emptyOverride(o) }

// Clone deep-copies a PolicyFile.
func (f PolicyFile) Clone() PolicyFile {
	out := PolicyFile{Version: f.Version, Mode: f.Mode, Defaults: f.Defaults.clone()}
	out.Packs = cloneToggles(f.Packs)
	out.RuleOverrides = cloneToggles(f.RuleOverrides)
	for _, r := range f.Rules {
		r.Match.Literals = cloneStrings(r.Match.Literals)
		r.Match.Argv0 = cloneStrings(r.Match.Argv0)
		out.Rules = append(out.Rules, r)
	}
	for _, s := range f.Subjects {
		out.Subjects = append(out.Subjects, s.Clone())
	}
	for _, t := range f.Temporary {
		out.Temporary = append(out.Temporary, t.Clone())
	}
	return out
}

// Clone deep-copies a Toggle.
func (t Toggle) Clone() Toggle {
	if t.Enabled != nil {
		v := *t.Enabled
		t.Enabled = &v
	}
	return t
}

func cloneToggles(m map[string]Toggle) map[string]Toggle {
	if m == nil {
		return nil
	}
	out := make(map[string]Toggle, len(m))
	for k, v := range m {
		out[k] = v.Clone()
	}
	return out
}

// Clone deep-copies a PolicySubject.
func (s PolicySubject) Clone() PolicySubject {
	if s.Grant != nil {
		g := s.Grant.clone()
		s.Grant = &g
	}
	s.Match.Argv0 = cloneStrings(s.Match.Argv0)
	s.Match.Glob = cloneStrings(s.Match.Glob)
	s.Match.Tools = cloneStrings(s.Match.Tools)
	if s.MCPTools != nil {
		m := make(map[string]string, len(s.MCPTools))
		for k, v := range s.MCPTools {
			m[k] = v
		}
		s.MCPTools = m
	}
	if s.Launch != nil {
		l := *s.Launch
		if l.Grant != nil {
			g := l.Grant.clone()
			l.Grant = &g
		}
		s.Launch = &l
	}
	s.Paths = s.Paths.clone()
	s.Domains = s.Domains.clone()
	s.AgentTools = s.AgentTools.clone()
	s.AgentSkills = cloneStrings(s.AgentSkills)
	return s
}

func (g *GateLists) clone() *GateLists {
	if g == nil {
		return nil
	}
	return &GateLists{Deny: cloneStrings(g.Deny), Ask: cloneStrings(g.Ask)}
}

// ---- raw v2 decode ----

type rawPolicyV2 struct {
	Version       *int                 `yaml:"version"`
	Mode          string               `yaml:"mode"`
	Packs         map[string]rawToggle `yaml:"packs"`
	RuleOverrides map[string]rawToggle `yaml:"rule_overrides"`
	Rules         []rawRule            `yaml:"rules"`
	Defaults      *rawOverride         `yaml:"defaults"`
	Subjects      []rawSubject         `yaml:"subjects"`
	Temporary     []rawTemporary       `yaml:"temporary"`
	Scope         map[string]any       `yaml:"scope"`
}

// rawToggle is `on`/`off` (true/false, yes/no) or {enabled, action},
// decoded as a plain value: a custom UnmarshalYAML would make go-yaml
// re-format the node for every entry, which is quadratic in the file.
type rawToggle = any

// toToggle interprets a decoded toggle; bad is the rule it breaks, or "".
func toToggle(v any) (t Toggle, bad string) {
	const shape = "must be on, off or {enabled: true|false, action: deny|ask|log}"
	switch x := v.(type) {
	case bool:
		return Toggle{Enabled: &x}, ""
	case string:
		on, ok := parseOnOff(x)
		if !ok {
			return Toggle{}, shape
		}
		return Toggle{Enabled: &on}, ""
	case map[string]any:
		if len(x) == 0 {
			return Toggle{}, "empty mapping (give enabled and/or action)"
		}
		for k, val := range x {
			switch k {
			case "enabled":
				b, ok := val.(bool)
				if !ok {
					return Toggle{}, shape
				}
				t.Enabled = &b
			case "action":
				a, ok := val.(string)
				if !ok {
					return Toggle{}, shape
				}
				switch a {
				case ActDeny, ActAsk, ActLog:
					t.Action = a
				default:
					return Toggle{}, "action: must be one of deny, ask, log"
				}
			default:
				return Toggle{}, shape
			}
		}
		return t, ""
	}
	return Toggle{}, shape
}

type rawRule struct {
	ID       string        `yaml:"id"`
	Tool     string        `yaml:"tool"`
	Match    *rawRuleMatch `yaml:"match"`
	Action   string        `yaml:"action"`
	Severity string        `yaml:"severity"`
}

type rawRuleMatch struct {
	Regex    string   `yaml:"regex"`
	Literals []string `yaml:"literals"`
	Argv0    []string `yaml:"argv0"`
}

type rawSubject struct {
	Kind    string          `yaml:"kind"`
	Name    string          `yaml:"name"`
	Grant   *rawOverride    `yaml:"grant"`
	Match   *rawMatch       `yaml:"match"`
	Tools   map[string]any  `yaml:"tools"`
	Launch  *rawLaunch      `yaml:"launch"`
	Paths   *rawGate        `yaml:"paths"`
	Domains *rawGate        `yaml:"domains"`
	Skills  *rawAgentSkills `yaml:"skills"`
	Scope   map[string]any  `yaml:"scope"`
}

type rawMatch struct {
	Argv0     []string `yaml:"argv0"`
	Glob      []string `yaml:"glob"`
	Tools     []string `yaml:"tools"`
	AgentType *string  `yaml:"agent_type"`
}

type rawLaunch struct {
	Sandbox *bool        `yaml:"sandbox"`
	Grant   *rawOverride `yaml:"grant"`
}

type rawGate struct {
	Deny []string `yaml:"deny"`
	Ask  []string `yaml:"ask"`
}

type rawAgentSkills struct {
	Allow []string `yaml:"allow"`
}

// safeUnmarshal is yaml.UnmarshalWithOptions with a recover: go-yaml
// v1.19.2 panics on some malformed input (a tagged empty node where a
// sequence is expected, found by FuzzParsePolicyFile), and a file from a
// cloned repository must not crash the hook.
func safeUnmarshal(b []byte, v any, opts ...yaml.DecodeOption) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.New("malformed YAML")
		}
	}()
	return yaml.UnmarshalWithOptions(b, v, opts...)
}

// MaxPolicyFileSize caps an overrides file; a larger one is refused before
// it is parsed.
const MaxPolicyFileSize = 1 << 20

// precheck refuses what the strict decoders would not: a file over
// MaxPolicyFileSize, more than one YAML document (go-yaml decodes only the
// first and would silently ignore the rest), and a version that is present
// but not an integer (2.0, "2"). It returns the integer version, 0 when absent.
func precheck(b []byte) (int, error) {
	if len(b) > MaxPolicyFileSize {
		return 0, errors.New("file larger than 1 MiB")
	}
	// One lexer pass: nesting limits, document count and, for an ordinary
	// file, the top-level version (safeio.ScanYAML).
	info, err := safeio.ScanYAML(b)
	if err != nil {
		return 0, err
	}
	if info.Docs > 1 {
		return 0, errors.New("more than one YAML document (--- separators are not supported)")
	}
	if info.HasVersion {
		if !info.VersionInt {
			return 0, errors.New("version: must be an integer (1 or 2)")
		}
		n, err := strconv.Atoi(info.Version)
		if err != nil || n < 0 {
			return 0, errors.New("version: must be an integer (1 or 2)")
		}
		return n, nil
	}
	// No block-style top-level version key (flow style, or none): decode
	// it, still leniently, and let the strict decoder report the rest.
	var v struct {
		Version any `yaml:"version"`
	}
	if err := safeUnmarshal(b, &v); err != nil || v.Version == nil {
		return 0, nil
	}
	switch n := v.Version.(type) {
	case uint64:
		if n > 1<<31 {
			return 0, errors.New("version: must be 1 or 2")
		}
		return int(n), nil
	case int64:
		return int(n), nil
	case int:
		return n, nil
	}
	return 0, errors.New("version: must be an integer (1 or 2)")
}

// ParsePolicyFile parses an overrides file of version 1 or 2 strictly
// (unknown fields and duplicate keys are errors). A v1 file goes through
// ParseOverrides unchanged and converts (PolicyFromOverrides).
func ParsePolicyFile(b []byte) (PolicyFile, error) {
	v, err := precheck(b)
	if err != nil {
		return PolicyFile{}, err
	}
	if v == 2 {
		return parsePolicyV2(b)
	}
	o, err := parseOverridesV1(b)
	if err != nil {
		return PolicyFile{}, err
	}
	return PolicyFromOverrides(o), nil
}

func parsePolicyV2(b []byte) (PolicyFile, error) {
	var raw rawPolicyV2
	if err := safeUnmarshal(b, &raw, yaml.Strict()); err != nil {
		return PolicyFile{}, fmt.Errorf("invalid overrides: %s", valueFreeYAMLErr(err))
	}
	if raw.Version == nil || *raw.Version != 2 {
		return PolicyFile{}, errors.New("version: must be 2")
	}
	if len(raw.Scope) > 0 {
		return PolicyFile{}, errors.New("scope: not supported yet (reserved for agent_type / user / project scoping; leave it empty)")
	}
	f := PolicyFile{Version: 2}
	switch raw.Mode {
	case "", ModeEnforce:
	case ModeShadow:
		f.Mode = ModeShadow
	default:
		return PolicyFile{}, errors.New("mode: must be enforce or shadow")
	}
	var err error

	// packs
	if len(raw.Packs) > 0 {
		f.Packs = make(map[string]Toggle, len(raw.Packs))
		for _, id := range sortedKeys(raw.Packs) {
			if !ValidPackID(id) {
				return PolicyFile{}, errors.New("packs: invalid pack name (" + PackIDRule + ")")
			}
			t, bad := toToggle(raw.Packs[id])
			if bad != "" {
				return PolicyFile{}, errors.New("packs." + id + ": " + bad)
			}
			f.Packs[id] = t
		}
	}

	// rule_overrides
	if len(raw.RuleOverrides) > 0 {
		f.RuleOverrides = make(map[string]Toggle, len(raw.RuleOverrides))
		for _, id := range sortedKeys(raw.RuleOverrides) {
			if !ValidRuleKey(id) {
				return PolicyFile{}, errors.New("rule_overrides: invalid rule key (" + RuleKeyRule + ")")
			}
			t, bad := toToggle(raw.RuleOverrides[id])
			if bad != "" {
				return PolicyFile{}, errors.New("rule_overrides." + id + ": " + bad)
			}
			f.RuleOverrides[id] = t
		}
	}

	// rules
	seenRule := map[string]bool{}
	for i, r := range raw.Rules {
		field := fmt.Sprintf("rules[%d]", i)
		if !ValidRuleID(r.ID) {
			return PolicyFile{}, errors.New(field + ".id: required, " + RuleIDRule)
		}
		field = "rules." + r.ID
		if seenRule[r.ID] {
			return PolicyFile{}, errors.New(field + ".id: duplicate rule id")
		}
		seenRule[r.ID] = true
		if !ValidToolPattern(r.Tool) {
			return PolicyFile{}, errors.New(field + ".tool: required, " + ToolPatternRule)
		}
		if r.Match == nil || (r.Match.Regex == "" && len(r.Match.Literals) == 0 && len(r.Match.Argv0) == 0) {
			return PolicyFile{}, errors.New(field + ".match: needs regex, literals or argv0")
		}
		if len(r.Match.Regex) > 4096 || strings.ContainsAny(r.Match.Regex, "\x00") {
			return PolicyFile{}, errors.New(field + ".match.regex: at most 4096 bytes, no NUL")
		}
		for j, l := range r.Match.Literals {
			if l == "" || len(l) > 1024 || strings.ContainsAny(l, "\x00") {
				return PolicyFile{}, fmt.Errorf("%s.match.literals[%d]: non-empty, at most 1024 bytes", field, j)
			}
		}
		for j, a := range r.Match.Argv0 {
			if !validArgv0(a) {
				return PolicyFile{}, fmt.Errorf("%s.match.argv0[%d]: %s", field, j, argv0Rule)
			}
		}
		switch r.Action {
		case ActDeny, ActAsk, ActLog:
		default:
			return PolicyFile{}, errors.New(field + ".action: must be one of deny, ask, log")
		}
		switch r.Severity {
		case "", "low", "medium", "high", "critical":
		default:
			return PolicyFile{}, errors.New(field + ".severity: must be one of low, medium, high, critical")
		}
		f.Rules = append(f.Rules, PolicyRule{
			ID: r.ID, Tool: r.Tool, Action: r.Action, Severity: r.Severity,
			Match: RuleMatch{Regex: r.Match.Regex, Literals: r.Match.Literals, Argv0: r.Match.Argv0},
		})
	}

	// defaults
	if f.Defaults, err = convertOverride("defaults", raw.Defaults); err != nil {
		return PolicyFile{}, err
	}

	// subjects
	seen := map[string]bool{}
	for i, rs := range raw.Subjects {
		s, err := convertSubject(i, rs)
		if err != nil {
			return PolicyFile{}, err
		}
		key := s.Kind + ":" + s.Name
		if seen[key] {
			return PolicyFile{}, fmt.Errorf("subjects.%s: duplicate subject (subjects[%d] repeats an earlier kind and name)", key, i)
		}
		seen[key] = true
		f.Subjects = append(f.Subjects, s)
	}

	// temporary
	if f.Temporary, err = convertTemporaries(raw.Temporary); err != nil {
		return PolicyFile{}, err
	}
	return f, nil
}

func convertSubject(i int, r rawSubject) (PolicySubject, error) {
	at := fmt.Sprintf("subjects[%d]", i)
	if len(r.Scope) > 0 {
		return PolicySubject{}, errors.New(at + ".scope: not supported yet (leave it empty)")
	}
	s := PolicySubject{Kind: r.Kind}
	switch r.Kind {
	case KindSkill:
		if !ValidSkillName(r.Name) {
			return PolicySubject{}, errors.New(at + ".name: invalid skill name (" + SkillNameRule + ")")
		}
	case KindCommand, KindTool, KindAgent:
		if r.Name == "*" || !ValidSkillName(r.Name) {
			return PolicySubject{}, errors.New(at + ".name: invalid name (" + SubjectNameRule + ")")
		}
	case KindMCP:
		if !ValidMCPServerPattern(r.Name) {
			return PolicySubject{}, errors.New(at + ".name: invalid MCP server name (" + MCPServerRule + ")")
		}
	case "":
		return PolicySubject{}, errors.New(at + ".kind: required (skill, command, mcp, tool, agent)")
	default:
		return PolicySubject{}, errors.New(at + ".kind: must be one of skill, command, mcp, tool, agent")
	}
	s.Name = r.Name
	field := "subjects." + r.Kind + ":" + r.Name // the name is validated above

	notFor := func(key string) error {
		return fmt.Errorf("%s.%s: not allowed for kind %s", field, key, r.Kind)
	}
	set := map[string]bool{
		"grant": r.Grant != nil, "match": r.Match != nil, "tools": r.Tools != nil, "launch": r.Launch != nil,
		"paths": r.Paths != nil, "domains": r.Domains != nil, "skills": r.Skills != nil,
	}
	allowed := func(keys ...string) error {
		for _, k := range []string{"grant", "match", "tools", "launch", "paths", "domains", "skills"} {
			if set[k] && !contains(keys, k) {
				return notFor(k)
			}
		}
		return nil
	}
	convGrant := func(sub string, g *rawOverride) (*Override, error) {
		if g == nil {
			return nil, nil
		}
		o, err := convertOverride(field+"."+sub, g)
		if err != nil {
			return nil, err
		}
		return &o, nil
	}
	var err error
	switch r.Kind {
	case KindSkill:
		if err := allowed("grant"); err != nil {
			return PolicySubject{}, err
		}
		if s.Grant, err = convGrant("grant", r.Grant); err != nil {
			return PolicySubject{}, err
		}
	case KindCommand:
		if err := allowed("grant", "match"); err != nil {
			return PolicySubject{}, err
		}
		if r.Match == nil || (len(r.Match.Argv0) == 0 && len(r.Match.Glob) == 0) {
			return PolicySubject{}, errors.New(field + ".match: needs argv0 or glob")
		}
		if len(r.Match.Tools) > 0 || r.Match.AgentType != nil {
			return PolicySubject{}, errors.New(field + ".match: only argv0 and glob for kind command")
		}
		for j, a := range r.Match.Argv0 {
			if !validArgv0(a) {
				return PolicySubject{}, fmt.Errorf("%s.match.argv0[%d]: %s", field, j, argv0Rule)
			}
		}
		for j, g := range r.Match.Glob {
			if g == "" || len(g) > 1024 || strings.ContainsAny(g, "\x00\n\r") {
				return PolicySubject{}, fmt.Errorf("%s.match.glob[%d]: non-empty, one line, at most 1024 bytes", field, j)
			}
		}
		s.Match.Argv0, s.Match.Glob = r.Match.Argv0, r.Match.Glob
		if s.Grant, err = convGrant("grant", r.Grant); err != nil {
			return PolicySubject{}, err
		}
	case KindMCP:
		if err := allowed("tools", "launch"); err != nil {
			return PolicySubject{}, err
		}
		if len(r.Tools) > 0 {
			s.MCPTools = make(map[string]string, len(r.Tools))
			for _, k := range sortedKeys(r.Tools) {
				if !ValidToolPattern(k) {
					return PolicySubject{}, errors.New(field + ".tools: invalid tool pattern (" + ToolPatternRule + ")")
				}
				v, ok := r.Tools[k].(string)
				if !ok {
					return PolicySubject{}, errors.New(field + ".tools." + k + ": must be deny or ask")
				}
				switch v {
				case ActDeny, ActAsk:
				case "allow":
					return PolicySubject{}, errors.New(field + ".tools." + k + ": a gate cannot allow (deny | ask only; Claude Code's own permissions decide the rest)")
				default:
					return PolicySubject{}, errors.New(field + ".tools." + k + ": must be deny or ask")
				}
				s.MCPTools[k] = v
			}
		}
		if r.Launch != nil {
			l := &MCPLaunch{}
			if r.Launch.Sandbox != nil {
				l.Sandbox = *r.Launch.Sandbox
			}
			if l.Grant, err = convGrant("launch.grant", r.Launch.Grant); err != nil {
				return PolicySubject{}, err
			}
			s.Launch = l
		}
		if len(s.MCPTools) == 0 && s.Launch == nil {
			return PolicySubject{}, errors.New(field + ": needs tools or launch")
		}
	case KindTool:
		if err := allowed("match", "paths", "domains"); err != nil {
			return PolicySubject{}, err
		}
		if r.Match == nil || len(r.Match.Tools) == 0 {
			return PolicySubject{}, errors.New(field + ".match.tools: required")
		}
		if len(r.Match.Argv0)+len(r.Match.Glob) > 0 || r.Match.AgentType != nil {
			return PolicySubject{}, errors.New(field + ".match: only tools for kind tool")
		}
		for j, t := range r.Match.Tools {
			if !ValidToolPattern(t) {
				return PolicySubject{}, fmt.Errorf("%s.match.tools[%d]: %s", field, j, ToolPatternRule)
			}
		}
		s.Match.Tools = r.Match.Tools
		if s.Paths, err = convGate(field+".paths", r.Paths, validGatePath); err != nil {
			return PolicySubject{}, err
		}
		if s.Domains, err = convGate(field+".domains", r.Domains, validDomainPattern); err != nil {
			return PolicySubject{}, err
		}
		if s.Paths.IsEmpty() && s.Domains.IsEmpty() {
			return PolicySubject{}, errors.New(field + ": needs paths or domains")
		}
		// A path gate only reads a file tool's path: on Bash, a glob or any
		// other tool it would look like protection and check nothing.
		if !s.Paths.IsEmpty() {
			for j, t := range s.Match.Tools {
				if !PathGateTool(t) {
					return PolicySubject{}, fmt.Errorf("%s.match.tools[%d]: paths apply only to %s", field, j, strings.Join(PathGateTools[:], ", "))
				}
			}
		}
	case KindAgent:
		if err := allowed("match", "tools", "skills"); err != nil {
			return PolicySubject{}, err
		}
		if r.Match == nil || r.Match.AgentType == nil {
			return PolicySubject{}, errors.New(field + ".match.agent_type: required")
		}
		if len(r.Match.Argv0)+len(r.Match.Glob)+len(r.Match.Tools) > 0 {
			return PolicySubject{}, errors.New(field + ".match: only agent_type for kind agent")
		}
		if !ValidMCPServerPattern(*r.Match.AgentType) {
			return PolicySubject{}, errors.New(field + ".match.agent_type: invalid (" + MCPServerRule + ")")
		}
		s.Match.AgentType = *r.Match.AgentType
		if r.Tools != nil {
			g := &GateLists{}
			for _, k := range sortedKeys(r.Tools) {
				var dst *[]string
				switch k {
				case ActDeny:
					dst = &g.Deny
				case ActAsk:
					dst = &g.Ask
				case "allow":
					return PolicySubject{}, errors.New(field + ".tools.allow: a gate cannot allow (deny | ask only)")
				default:
					return PolicySubject{}, errors.New(field + ".tools: only deny and ask")
				}
				list, ok := toStringList(r.Tools[k])
				if !ok {
					return PolicySubject{}, errors.New(field + ".tools." + k + ": must be a list of tool names")
				}
				for j, t := range list {
					if !ValidToolPattern(t) {
						return PolicySubject{}, fmt.Errorf("%s.tools.%s[%d]: %s", field, k, j, ToolPatternRule)
					}
				}
				*dst = list
			}
			if !g.IsEmpty() {
				s.AgentTools = g
			}
		}
		if r.Skills != nil {
			if r.Skills.Allow == nil {
				return PolicySubject{}, errors.New(field + ".skills.allow: required (a list; [] allows no skill)")
			}
			for j, n := range r.Skills.Allow {
				if !ValidSkillName(n) {
					return PolicySubject{}, fmt.Errorf("%s.skills.allow[%d]: %s", field, j, SkillNameRule)
				}
			}
			s.AgentSkills = append([]string{}, r.Skills.Allow...)
		}
		if s.AgentTools == nil && s.AgentSkills == nil {
			return PolicySubject{}, errors.New(field + ": needs tools or skills")
		}
	}
	return s, nil
}

func convGate(field string, g *rawGate, valid func(string) bool) (*GateLists, error) {
	if g == nil {
		return nil, nil
	}
	for _, l := range []struct {
		key  string
		list []string
	}{{"deny", g.Deny}, {"ask", g.Ask}} {
		for j, p := range l.list {
			if !valid(p) {
				return nil, fmt.Errorf("%s.%s[%d]: invalid entry", field, l.key, j)
			}
		}
	}
	out := &GateLists{Deny: g.Deny, Ask: g.Ask}
	if out.IsEmpty() {
		return nil, nil
	}
	return out, nil
}

func toStringList(v any) ([]string, bool) {
	if v == nil {
		return []string{}, true
	}
	xs, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		s, ok := x.(string)
		if !ok {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

func sortedKeys[V any](m map[string]V) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func parseOnOff(s string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "on", "true", "yes":
		return true, true
	case "off", "false", "no":
		return false, true
	}
	return false, false
}

// ---- name rules ----

// SubjectNameRule describes the name of a command, tool or agent subject.
const SubjectNameRule = `letters, digits, '.', '_', '-' (not first), at most 128 characters`

// MCPServerRule describes an mcp subject name (and an agent_type).
const MCPServerRule = `letters, digits, '.', '_', '-', '*', '?' (not '-' first), at most 128 characters`

// ToolPatternRule describes a tool name or tool-name glob.
const ToolPatternRule = `letters, digits, '_', '.', '-', '*', '?' (not '-' first), at most 128 characters`

// PackIDRule describes a pack id.
const PackIDRule = `lower-case letters, digits, '-' (not first), at most 64 characters`

// RuleIDRule describes the id of a rule written in a policy file. It has
// no '/', so it can never name a built-in rule ("<pack>/<id>").
const RuleIDRule = `lower-case letters, digits, '.', '_', '-' (letter or digit first, no '/'), at most 128 characters`

// RuleKeyRule describes a rule_overrides key.
const RuleKeyRule = `<pack>/<rule id>: lower-case letters, digits, '.', '_', '-', one '/'`

const argv0Rule = `a program name or absolute path, no spaces or quotes, at most 256 bytes; or "*"`

func charsOK(s string, max int, extra string) bool {
	if s == "" || len(s) > max || s[0] == '-' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '_', c == '-':
		case strings.IndexByte(extra, c) >= 0:
		default:
			return false
		}
	}
	return true
}

// ValidMCPServerPattern reports whether s is an MCP server name, a glob of
// one, or "*". Also the rule for an agent subject's agent_type.
func ValidMCPServerPattern(s string) bool {
	return charsOK(s, 128, "*?") && s != "." && s != ".."
}

// PathGateTools are the tools a path gate reads: their file_path,
// notebook_path or (Grep, Glob) path.
var PathGateTools = [...]string{"Read", "Write", "Edit", "MultiEdit", "NotebookEdit", "Grep", "Glob"}

// PathGateTool reports whether t is one of PathGateTools (exactly; a glob
// could name a tool a path gate cannot read).
func PathGateTool(t string) bool {
	for _, x := range PathGateTools {
		if t == x {
			return true
		}
	}
	return false
}

// ValidToolPattern reports whether s is a tool name (Bash, Write,
// mcp__github__create_issue) or a glob of one.
func ValidToolPattern(s string) bool { return charsOK(s, 128, "*?") }

// ValidPackID reports whether s is a pack id such as secrets-read.
func ValidPackID(s string) bool {
	if s == "" || len(s) > 64 || s[0] == '-' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// ValidRuleID reports whether s is the id of a policy-file rule
// (no-prod-db): no '/', so a user or project rule can never shadow a
// built-in pack rule, whose ids are "<pack>/<id>".
func ValidRuleID(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	if c := s[0]; !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9') {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

// ValidRuleKey reports whether s is a rule_overrides key "<pack>/<id>"
// (exfil/curl-data-file).
func ValidRuleKey(s string) bool {
	pack, id, ok := strings.Cut(s, "/")
	return ok && ValidPackID(pack) && len(s) <= 192 && ValidRuleID(id)
}

func validArgv0(s string) bool {
	if s == "" || len(s) > 256 || strings.ContainsAny(s, " \t\r\n\x00\"'`|;&$<>()\\") {
		return false
	}
	return true
}

// validGatePath accepts an absolute path, ~/…, ${HOME}/… or a relative
// pattern starting with **/ (globs allowed, no '..' segments, no other
// variables): a gate is matched against a tool's absolute target path.
func validGatePath(p string) bool {
	if err := validatePath("x", p, true); err != nil {
		return false
	}
	switch {
	case strings.HasPrefix(p, "${") && !(p == "${HOME}" || strings.HasPrefix(p, "${HOME}/")):
		return false
	case strings.HasPrefix(p, "/"), strings.HasPrefix(p, "~"), strings.HasPrefix(p, "${HOME}"), strings.HasPrefix(p, "**/"):
		return true
	}
	return false
}

// validDomainPattern accepts a host name, "*.<host>" or "*".
func validDomainPattern(d string) bool {
	if d == "*" {
		return true
	}
	d = strings.TrimPrefix(d, "*.")
	if d == "" || len(d) > 253 || d[0] == '.' || d[0] == '-' {
		return false
	}
	for i := 0; i < len(d); i++ {
		c := d[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-') {
			return false
		}
	}
	return true
}
