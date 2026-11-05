package rulebook

import (
	"fmt"
	"sort"

	"github.com/Panda-Taps-LLC/watchdeck/internal/claudesettings"
)

// IntentPrefix starts the ledger intent id of every recommended rule.
const IntentPrefix = "recommended:"

// IntentID is the slug of a recommended rule's value: the value
// lower-cased, every byte that is not an ASCII letter or digit replaced by
// '-' one for one. Runs are not collapsed, so Read(.env) and
// Read(.env.*) never collide. The rule's ledger intent id is
// IntentPrefix + IntentID(value), for example
// "recommended:read----ssh-id---" for Read(~/.ssh/id_*).
func IntentID(value string) string {
	b := make([]byte, 0, len(value))
	for i := 0; i < len(value); i++ {
		c := value[i]
		switch {
		case c >= 'A' && c <= 'Z':
			b = append(b, c+('a'-'A'))
		case (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'):
			b = append(b, c)
		default:
			b = append(b, '-')
		}
	}
	return string(b)
}

// Recommended returns the twelve native rules watchdeck proposes, each at
// user scope with the pack rule it pairs with as Twin. State is off: the
// list is the catalogue, not what is installed (RecommendedMissing and List
// say that). A new slice on every call.
func Recommended() []Rule {
	seed := []struct{ key, value, twin string }{
		{claudesettings.KeyDeny, "Read(~/.ssh/id_*)", "secrets-read/read-ssh-private-key"},
		{claudesettings.KeyDeny, "Read(~/.aws/credentials)", "secrets-read/read-aws-credentials"},
		{claudesettings.KeyDeny, "Read(~/.netrc)", "secrets-read/read-other-credentials"},
		// bare names: Claude Code matches them at any depth under the
		// working directory (./.env would be the top level only)
		{claudesettings.KeyAsk, "Read(.env)", "secrets-read/read-dotenv"},
		{claudesettings.KeyAsk, "Read(.env.*)", "secrets-read/read-dotenv"},
		{claudesettings.KeyAsk, "Edit(~/.zshrc)", "persistence/shell-rc-write"},
		{claudesettings.KeyAsk, "Edit(~/.bashrc)", "persistence/shell-rc-write"},
		{claudesettings.KeyAsk, "Edit(~/.profile)", "persistence/shell-rc-write"},
		{claudesettings.KeyAsk, "Edit(~/.zprofile)", "persistence/shell-rc-write"},
		{claudesettings.KeyAsk, "Edit(~/.bash_profile)", "persistence/shell-rc-write"},
		{claudesettings.KeyAsk, "Edit(~/Library/LaunchAgents/**)", "persistence/launch-agent-write"},
		{claudesettings.KeyAsk, "Edit(~/.config/systemd/user/**)", "persistence/systemd-unit-write"},
	}
	out := make([]Rule, 0, len(seed))
	for _, s := range seed {
		r := nativeRow(kindForKey(s.key), claudesettings.Entry{Value: s.value, Scope: claudesettings.ScopeUser, Index: -1}, s.key)
		r.Owner = OwnerUs
		r.State = StateOff
		r.Recommended = true
		r.Twin = s.twin
		out = append(out, r)
	}
	return out
}

// recommendedFor returns the rule in rec (a Recommended() slice, built once
// by the caller) for a settings string under key, if it is one.
func recommendedFor(rec []Rule, key, value string) (Rule, bool) {
	for _, r := range rec {
		if r.Source.Key == key && r.Value == value {
			return r, true
		}
	}
	return Rule{}, false
}

// RecommendedMissing returns the recommended rules eff does not hold. A
// string counts as installed when it is in the same list at any scope,
// whoever wrote it (watchdeck never claims a string the person wrote); an
// ask recommendation also counts as installed when the same string is
// denied, which is stricter.
func RecommendedMissing(eff claudesettings.Effective) []Rule {
	var out []Rule
	for _, r := range Recommended() {
		if hasValue(listFor(eff, r.Source.Key), r.Value) {
			continue
		}
		if r.Source.Key == claudesettings.KeyAsk && hasValue(eff.Deny, r.Value) {
			continue
		}
		out = append(out, r)
	}
	return out
}

func hasValue(entries []claudesettings.Entry, value string) bool {
	for _, e := range entries {
		if e.Value == value {
			return true
		}
	}
	return false
}

// CoveredTwins returns the pack rules ("<pack>/<rule>", sorted) whose every
// recommended native string (the Recommended rules with that Twin) is in
// eff, by RecommendedMissing's test: the same list at any scope, or a deny
// for an ask recommendation. The hook need not watch a file tool for such a
// rule at its default action: Claude Code enforces those paths itself
// (policy.FilesNeed).
func CoveredTwins(eff claudesettings.Effective) []string {
	missing := map[string]bool{}
	for _, r := range RecommendedMissing(eff) {
		missing[r.Twin] = true
	}
	seen := map[string]bool{}
	var out []string
	for _, r := range Recommended() {
		if missing[r.Twin] || seen[r.Twin] {
			continue
		}
		seen[r.Twin] = true
		out = append(out, r.Twin)
	}
	sort.Strings(out)
	return out
}

// RecommendedPlan is the plan that adds the recommended rules in missing
// (rules from Recommended, by settings key and value) to the user settings
// file, each claimed under IntentPrefix + IntentID(value). The strings are
// written exactly as Recommended spells them: Propose would anchor the bare
// dotenv names (Read(.env) as Read(./.env)), so the steps are built here.
// A rule that is not in Recommended is an error.
func RecommendedPlan(in Input, missing []Rule) (Plan, error) {
	var plan Plan
	file, scope, err := nativeFile(in, claudesettings.ScopeUser)
	if err != nil {
		return Plan{}, err
	}
	rec := Recommended()
	for _, m := range missing {
		r, ok := recommendedFor(rec, m.Source.Key, m.Value)
		if !ok {
			return Plan{}, fmt.Errorf("rulebook: %q under %s is not a recommended rule", m.Value, m.Source.Key)
		}
		if err := checkNativeString(r.Value); err != nil {
			return Plan{}, err
		}
		kind := kindForKey(r.Source.Key)
		plan.Steps = append(plan.Steps, Step{
			Mechanism: MechNative, File: file, Key: r.Source.Key, Value: r.Value,
			RowID:    RowID(kind, scope, r.Source.Key, r.Value),
			Sentence: r.Sentence, IntentID: IntentPrefix + IntentID(r.Value),
		})
	}
	return plan, nil
}
