package rules

import (
	"fmt"
	"sort"
	"strings"
)

// Config turns packs and rules on or off and overrides their action. The zero
// Config means the embedded defaults. It is the shape a policy file (M6.1,
// version 2) maps onto:
//
//	packs: {secrets-read: on, prompt-injection: on, exfil: {action: ask}}
//	rule_overrides: {destructive/mkfs: {action: log}, exfil/pipe-to-netcat: off}
//
// A rule override beats its pack's; an empty Action keeps the rule's default.
type Config struct {
	Packs map[string]PackConfig `yaml:"packs,omitempty"`
	Rules map[string]RuleConfig `yaml:"rule_overrides,omitempty"` // key: "<pack>/<rule id>"
}

// PackConfig overrides one pack. In YAML it is `on`/`off`/a bool, or a map
// `{enabled: bool, action: deny|ask|log}`.
type PackConfig struct {
	Enabled *bool  `yaml:"enabled,omitempty"`
	Action  Action `yaml:"action,omitempty"`
}

// RuleConfig overrides one rule, in the same YAML forms as PackConfig.
type RuleConfig struct {
	Enabled *bool  `yaml:"enabled,omitempty"`
	Action  Action `yaml:"action,omitempty"`
}

// UnmarshalYAML accepts `on`, `off`, a bool, or a map.
func (p *PackConfig) UnmarshalYAML(unmarshal func(any) error) error {
	en, act, err := unmarshalToggle(unmarshal)
	if err != nil {
		return err
	}
	p.Enabled, p.Action = en, act
	return nil
}

// UnmarshalYAML accepts `on`, `off`, a bool, or a map.
func (r *RuleConfig) UnmarshalYAML(unmarshal func(any) error) error {
	en, act, err := unmarshalToggle(unmarshal)
	if err != nil {
		return err
	}
	r.Enabled, r.Action = en, act
	return nil
}

func unmarshalToggle(unmarshal func(any) error) (*bool, Action, error) {
	var v any
	if err := unmarshal(&v); err != nil {
		return nil, "", err
	}
	switch x := v.(type) {
	case bool:
		return &x, "", nil
	case string:
		switch strings.ToLower(x) {
		case "on", "true", "yes":
			t := true
			return &t, "", nil
		case "off", "false", "no":
			f := false
			return &f, "", nil
		}
		return nil, "", fmt.Errorf("want on, off or a map, got %q", x)
	case map[string]any:
		var en *bool
		var act Action
		for k, val := range x {
			switch k {
			case "enabled":
				b, ok := val.(bool)
				if !ok {
					return nil, "", fmt.Errorf("enabled: want a bool")
				}
				en = &b
			case "action":
				s, ok := val.(string)
				if !ok || !Action(s).valid() {
					return nil, "", fmt.Errorf("action: want deny, ask or log")
				}
				act = Action(s)
			default:
				return nil, "", fmt.Errorf("unknown key %q", k)
			}
		}
		return en, act, nil
	}
	return nil, "", fmt.Errorf("want on, off or a map")
}

// Validate reports unknown packs and rules and invalid actions in cfg, so a
// policy file's typo is reported rather than silently ignored.
func (cfg Config) Validate() error {
	l := load()
	if l.err != nil {
		return l.err
	}
	packs := map[string]bool{}
	rules := map[string]bool{}
	for _, p := range l.packs {
		packs[p.Name] = true
		for _, r := range p.Rules {
			rules[p.Name+"/"+r.ID] = true
		}
	}
	var errs []string
	for name, pc := range cfg.Packs {
		if !packs[name] {
			errs = append(errs, fmt.Sprintf("unknown pack %q", name))
		}
		if pc.Action != "" && !pc.Action.valid() {
			errs = append(errs, fmt.Sprintf("pack %q: invalid action %q", name, pc.Action))
		}
	}
	for key, rc := range cfg.Rules {
		if !rules[key] {
			errs = append(errs, fmt.Sprintf("unknown rule %q (want <pack>/<id>)", key))
		}
		if rc.Action != "" && !rc.Action.valid() {
			errs = append(errs, fmt.Sprintf("rule %q: invalid action %q", key, rc.Action))
		}
	}
	if len(errs) == 0 {
		return nil
	}
	sort.Strings(errs)
	return fmt.Errorf("rules config: %s", strings.Join(errs, "; "))
}
