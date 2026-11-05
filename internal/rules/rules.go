// Package rules holds watchdeck's built-in attack rule packs: data-only
// gate rules (M6.2) that look at a tool call's input and report hits with a
// deny, ask or log action. The packs are written as YAML under packs/ and
// compiled by `go generate` into packs_gen.go (static literals); matchers
// are built on first use and each regex compiles lazily, so linking this
// package into the hook binary costs nothing at init and no YAML is parsed
// at run time.
//
// A rule pack is a gate, never a sandbox: Eval only reports what matched. A
// caller (M6.3, not wired yet) turns deny/ask hits into a PreToolUse
// decision and never into an allow.
//
// Matching is lexical. Bash rules run regexes over the raw command string;
// `argv0` compiles into a command-position prefix (start of the command or
// after a pipe, `;`, `&`, `(`, `$(` or a control keyword, optional sudo and a
// path) rather than a mvdan/sh parse, which would cost a large share of the
// time budget per call and fails on partial input. Obfuscated commands
// (`eval`, variables holding the command name, base64-decoded scripts) slip
// past by design; the OS sandbox is the boundary for those.
package rules

import (
	"path"
	"strings"
)

// The packs' source of truth is packs/*.yaml; packs_gen.go holds them as Go
// literals so a hook process pays no YAML parse. TestGeneratedUpToDate (in
// ./gen) fails when the two drift.
//go:generate go run ./gen

// MaxInput is the number of bytes of Write/Edit content, WebFetch text, URLs
// and file paths that rules look at. Longer fields are cut, so text past the
// cap (for example the tail of a large Write) is not scanned. RE2 runs in
// linear time, so the cap bounds the cost of a call rather than guarding
// against ReDoS.
const MaxInput = 64 << 10

// MaxCommand is the number of bytes of a Bash command that rules look at.
// A command is scanned whole up to this size, so padding cannot push the
// dangerous part past the cap; a longer command gets an `ask` hit
// (RuleTooLarge) on top of whatever its first MaxCommand bytes match.
const MaxCommand = 256 << 10

// PackBuiltin and RuleTooLarge name the synthetic hit for an oversized
// command. Config cannot turn it off.
const (
	PackBuiltin  = "builtin"
	RuleTooLarge = "input-too-large"
)

// Action is what a hit asks the hook to do.
type Action string

const (
	Deny Action = "deny"
	Ask  Action = "ask"
	Log  Action = "log"
)

func (a Action) valid() bool { return a == Deny || a == Ask || a == Log }

// Severity grades a rule for display and records.
type Severity string

const (
	Low      Severity = "low"
	Medium   Severity = "medium"
	High     Severity = "high"
	Critical Severity = "critical"
)

func (s Severity) valid() bool { return s == Low || s == Medium || s == High || s == Critical }

// Input fields a rule can match.
const (
	FieldCommand  = "command"
	FieldFilePath = "file_path"
	FieldContent  = "content"
	FieldURL      = "url"
	FieldText     = "text"
)

// Input is the part of a tool call rules look at. The caller fills what the
// tool carries: Bash → Command; Read/Write/Edit → FilePath; Write → Content
// (Edit: new_string; MultiEdit: every new_string joined by newlines);
// WebFetch → URL and, after the fetch (PostToolUse), Text.
type Input struct {
	Command  string
	FilePath string
	Content  string
	URL      string
	Text     string
}

func (in Input) field(name string) string {
	switch name {
	case FieldCommand:
		return in.Command
	case FieldFilePath:
		return in.FilePath
	case FieldContent:
		return in.Content
	case FieldURL:
		return in.URL
	case FieldText:
		return in.Text
	}
	return ""
}

// Match is a rule's matcher. A rule fires when the field contains one of
// Literals (if any; a cheap pre-filter) and Regex matches. With Argv0 set,
// the regex must match inside the same simple command as one of those
// command names, anywhere after the name; with Anchored also set, it must
// match starting right after the name, so it can walk the command's own
// arguments one by one (exfil/scp-secret uses this to skip -i values).
//
// There is deliberately no "exclude" pattern: a negative match over the
// whole command is satisfiable by text elsewhere in a chained command
// (`...; echo -i .ssh/id_`) and so fails open.
type Match struct {
	Field    string   `yaml:"field,omitempty"`
	Regex    string   `yaml:"regex,omitempty"`
	Literals []string `yaml:"literals,omitempty"`
	Argv0    []string `yaml:"argv0,omitempty"`
	Anchored bool     `yaml:"anchored,omitempty"`
}

// Rule is one gate rule. Tool is a tool name, several joined by `|`, or `*`.
type Rule struct {
	ID          string   `yaml:"id"`
	Tool        string   `yaml:"tool"`
	Match       Match    `yaml:"match"`
	Severity    Severity `yaml:"severity"`
	Action      Action   `yaml:"action"`
	Description string   `yaml:"description"`
	FPNote      string   `yaml:"fp_note"`

	c *compiled // set by load; shared by copies of the Rule
}

// Pack is a versioned set of rules. Enabled is the default state; a Config
// can turn a pack on or off.
type Pack struct {
	Name        string `yaml:"pack"`
	Version     int    `yaml:"version"`
	Description string `yaml:"description"`
	Enabled     *bool  `yaml:"enabled,omitempty"`
	Rules       []Rule `yaml:"rules"`
}

// EnabledByDefault reports the pack's state with no Config.
func (p Pack) EnabledByDefault() bool { return p.Enabled == nil || *p.Enabled }

// Hit is one rule that matched. It carries no matched text, so a hit on a
// secret never echoes the secret.
type Hit struct {
	Pack        string   `json:"pack"`
	Version     int      `json:"version"`
	Rule        string   `json:"rule"`
	Field       string   `json:"field"`
	Severity    Severity `json:"severity"`
	Action      Action   `json:"action"`
	Description string   `json:"description"`
}

// Packs returns the embedded packs, parsed and validated. It returns nil if
// the embedded data is invalid (tests keep it valid; LoadError says why).
// Callers must not modify the returned rules.
func Packs() []Pack {
	l := load()
	if l.err != nil {
		return nil
	}
	return l.packs
}

// LoadError reports why the embedded packs failed to load, or nil.
func LoadError() error { return load().err }

// Eval runs every enabled rule for tool over in and returns the hits, in pack
// and rule order, with the action after cfg's overrides. A tool with no
// rules, or an invalid embedded pack set, yields no hits.
func Eval(cfg Config, tool string, in Input) []Hit {
	l := load()
	if l.err != nil {
		return nil
	}
	var fields fieldCache
	var hits []Hit
	if len(in.Command) > MaxCommand && hasCommandRules(l, cfg, tool) {
		hits = append(hits, Hit{
			Pack: PackBuiltin, Version: 1, Rule: RuleTooLarge, Field: FieldCommand,
			Severity: High, Action: Ask,
			Description: "The command is longer than 256 KiB; only its first 256 KiB was checked.",
		})
	}
	for pi := range l.packs {
		p := &l.packs[pi]
		pc, hasPC := cfg.Packs[p.Name]
		packOn := p.EnabledByDefault()
		if hasPC && pc.Enabled != nil {
			packOn = *pc.Enabled
		}
		for ri := range p.Rules {
			r := &p.Rules[ri]
			if !r.c.appliesTo(tool) {
				continue
			}
			rc, hasRC := cfg.Rules[p.Name+"/"+r.ID]
			on := packOn
			if hasRC && rc.Enabled != nil {
				on = *rc.Enabled
			}
			if !on {
				continue
			}
			if !r.c.match(&fields, in) {
				continue
			}
			act := r.Action
			if hasPC && pc.Action.valid() {
				act = pc.Action
			}
			if hasRC && rc.Action.valid() {
				act = rc.Action
			}
			hits = append(hits, Hit{
				Pack: p.Name, Version: p.Version, Rule: r.ID, Field: r.c.field,
				Severity: r.Severity, Action: act, Description: r.Description,
			})
		}
	}
	return hits
}

// HasRules reports whether any enabled rule applies to tool under cfg, so a
// caller can skip work (and a hook registration) for tools no rule watches.
func HasRules(cfg Config, tool string) bool {
	l := load()
	if l.err != nil {
		return false
	}
	for _, p := range l.packs {
		pc, hasPC := cfg.Packs[p.Name]
		packOn := p.EnabledByDefault()
		if hasPC && pc.Enabled != nil {
			packOn = *pc.Enabled
		}
		for _, r := range p.Rules {
			on := packOn
			if rc, ok := cfg.Rules[p.Name+"/"+r.ID]; ok && rc.Enabled != nil {
				on = *rc.Enabled
			}
			if on && r.c.appliesTo(tool) {
				return true
			}
		}
	}
	return false
}

func hasCommandRules(l *loaded, cfg Config, tool string) bool {
	for _, p := range l.packs {
		pc, hasPC := cfg.Packs[p.Name]
		packOn := p.EnabledByDefault()
		if hasPC && pc.Enabled != nil {
			packOn = *pc.Enabled
		}
		for _, r := range p.Rules {
			on := packOn
			if rc, ok := cfg.Rules[p.Name+"/"+r.ID]; ok && rc.Enabled != nil {
				on = *rc.Enabled
			}
			if on && r.c.field == FieldCommand && r.c.appliesTo(tool) {
				return true
			}
		}
	}
	return false
}

// fieldCache holds each input field prepared for matching (cut to its cap;
// a command with backslash-newline continuations joined; a file path
// cleaned), and its lower-case form for case-insensitive literal
// pre-filters, computed at most once per Eval.
type fieldCache struct {
	raw, lower [5]string
	haveRaw    [5]bool
	haveLower  [5]bool
}

func fieldIndex(name string) int {
	switch name {
	case FieldCommand:
		return 0
	case FieldFilePath:
		return 1
	case FieldContent:
		return 2
	case FieldURL:
		return 3
	}
	return 4
}

func (f *fieldCache) get(in Input, name string) string {
	i := fieldIndex(name)
	if !f.haveRaw[i] {
		s := in.field(name)
		limit := MaxInput
		if name == FieldCommand {
			limit = MaxCommand
		}
		if len(s) > limit {
			s = s[:limit]
		}
		switch name {
		case FieldCommand:
			if strings.Contains(s, "\\\n") || strings.Contains(s, "\\\r\n") {
				s = strings.NewReplacer("\\\r\n", " ", "\\\n", " ").Replace(s)
			}
		case FieldFilePath:
			if s != "" {
				s = path.Clean(s)
			}
		}
		f.raw[i], f.haveRaw[i] = s, true
	}
	return f.raw[i]
}

func (f *fieldCache) getLower(in Input, name string) string {
	i := fieldIndex(name)
	if !f.haveLower[i] {
		f.lower[i], f.haveLower[i] = strings.ToLower(f.get(in, name)), true
	}
	return f.lower[i]
}
