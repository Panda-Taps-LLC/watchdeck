package rulebook

import (
	"errors"
	"fmt"
	"strings"

	"github.com/Panda-Taps-LLC/watchdeck/internal/manifest"
	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
	"github.com/Panda-Taps-LLC/watchdeck/internal/policy"
	"github.com/Panda-Taps-LLC/watchdeck/internal/rules"
)

// packRule finds a built-in pack rule by its "<pack>/<id>" key.
func packRule(key string) (rules.Pack, rules.Rule, bool) {
	name, id, ok := strings.Cut(key, "/")
	if !ok || name == "" || id == "" {
		return rules.Pack{}, rules.Rule{}, false
	}
	for _, p := range rules.Packs() {
		if p.Name != name {
			continue
		}
		for _, r := range p.Rules {
			if r.ID == id {
				return p, r, true
			}
		}
	}
	return rules.Pack{}, rules.Rule{}, false
}

// packAction reports whether a is an action a pack rule can be set to.
func packAction(a string) bool {
	return a == string(rules.Deny) || a == string(rules.Ask) || a == string(rules.Log)
}

// SetShadow switches shadow mode on or off in the user policy file
// (mode: shadow; enforce is the absence of the line) through editPolicy:
// one write, one backup; a file already in that state is no write.
func SetShadow(in Input, on bool) (Result, error) {
	res := Result{Written: []string{}, Backups: []string{}, RowIDs: []string{}}
	mode := manifest.ModeEnforce
	if on {
		mode = manifest.ModeShadow
	}
	err := editPolicy(in.Paths.OverridesFile(), &res, func(f *policy.File) (bool, error) {
		return policy.Apply(f, policy.Edit{SetMode: mode})
	})
	return res, err
}

// SetEnabled switches a built-in pack rule on or off in the user policy
// file (rule_overrides.<pack>/<id>.enabled), keeping any action override.
// Only pack rows (pack:<pack>/<id>) can be switched; any other row is
// refused, since a settings string, hook rule or subject is removed
// instead. Rule.State in List reflects the toggle.
func SetEnabled(in Input, rowID string, on bool) (Result, error) {
	res := Result{Written: []string{}, Backups: []string{}, RowIDs: []string{rowID}}
	key, ok := strings.CutPrefix(rowID, "pack:")
	if !ok {
		return res, errors.New("rulebook: only " + paths.BinaryName + " pack rules can be switched off; remove the rule instead")
	}
	if _, _, found := packRule(key); !found {
		return res, fmt.Errorf("rulebook: no rule %q", rowID)
	}
	err := editPolicy(in.Paths.OverridesFile(), &res, func(f *policy.File) (bool, error) {
		t := manifest.Toggle{}
		if cur, ok := f.RuleOverrides[key]; ok {
			t = cur.Clone()
		}
		v := on
		t.Enabled = &v
		return policy.Apply(f, policy.Edit{Rule: key, RuleOverride: &t})
	})
	return res, err
}
