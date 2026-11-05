package rulebook

import (
	"reflect"
	"strings"
	"testing"

	"github.com/Panda-Taps-LLC/watchdeck/internal/claudesettings"
	"github.com/Panda-Taps-LLC/watchdeck/internal/rules"
)

func TestRecommendedNamesRealPackRules(t *testing.T) {
	known := map[string]bool{}
	for _, p := range rules.Packs() {
		for _, r := range p.Rules {
			known[p.Name+"/"+r.ID] = true
		}
	}
	if len(known) == 0 {
		t.Fatalf("no packs loaded: %v", rules.LoadError())
	}
	rec := Recommended()
	if len(rec) != 12 {
		t.Fatalf("Recommended() has %d rules, want 12", len(rec))
	}
	for _, r := range rec {
		if !known[r.Twin] {
			t.Errorf("%s: twin %q is not a built-in pack rule", r.Value, r.Twin)
		}
		if !r.Recommended || r.Scope != claudesettings.ScopeUser || r.Harness != HarnessClaudeCode {
			t.Errorf("%s: %+v", r.Value, r)
		}
		if r.Sentence == "" || r.ID == "" {
			t.Errorf("%s: empty sentence or id", r.Value)
		}
	}
}

func TestRecommendedNeverWrite(t *testing.T) {
	for _, r := range Recommended() {
		if strings.HasPrefix(r.Value, "Write(") {
			t.Errorf("recommended rule %q targets Write", r.Value)
		}
	}
}

func TestRecommendedUserScopeAnchors(t *testing.T) {
	// The two dotenv rules are bare file names on purpose: Claude Code
	// matches a bare name at any depth under the working directory, where
	// ./.env would cover the top level only.
	bare := map[string]bool{"Read(.env)": true, "Read(.env.*)": true}
	for _, r := range Recommended() {
		if bare[r.Value] {
			delete(bare, r.Value)
			continue
		}
		_, inner, ok := strings.Cut(r.Value, "(")
		if !ok {
			t.Errorf("%q has no path", r.Value)
			continue
		}
		if !(strings.HasPrefix(inner, "~/") || strings.HasPrefix(inner, "//") || strings.HasPrefix(inner, "./")) {
			t.Errorf("%q: path is not anchored for user scope", r.Value)
		}
	}
	if len(bare) != 0 {
		t.Errorf("recommended rules lack the bare dotenv strings %v", bare)
	}
}

func TestRecommendedIntentIDs(t *testing.T) {
	seen := map[string]string{}
	for _, r := range Recommended() {
		id := IntentPrefix + IntentID(r.Value)
		if IntentPrefix != "recommended:" || strings.ContainsAny(IntentID(r.Value), "()/~.*_:") {
			t.Errorf("%q: intent id %q", r.Value, id)
		}
		if prev, dup := seen[id]; dup {
			t.Errorf("%q and %q share intent id %q", prev, r.Value, id)
		}
		seen[id] = r.Value
	}
	for value, want := range map[string]string{
		"Read(.env)":        "read--env-",
		"Read(.env.*)":      "read--env---",
		"Read(~/.ssh/id_*)": "read----ssh-id---",
	} {
		if got := IntentID(value); got != want {
			t.Errorf("IntentID(%s) = %q, want %q", value, got, want)
		}
	}
}

func TestRecommendedMissing(t *testing.T) {
	rec := Recommended()
	var eff claudesettings.Effective
	eff.Deny = []claudesettings.Entry{{Value: rec[0].Value, Scope: claudesettings.ScopeUser}}
	eff.Ask = []claudesettings.Entry{
		{Value: rec[3].Value, Scope: claudesettings.ScopeProject},
		{Value: rec[11].Value, Scope: claudesettings.ScopeManaged},
	}
	missing := RecommendedMissing(eff)
	if len(missing) != 9 {
		t.Fatalf("missing %d, want 9: %+v", len(missing), missing)
	}
	for _, m := range missing {
		if m.Value == rec[0].Value || m.Value == rec[3].Value || m.Value == rec[11].Value {
			t.Errorf("%q reported missing but present", m.Value)
		}
	}
	// A string under a different list does not count: an allow is not a deny.
	eff2 := claudesettings.Effective{Allow: []claudesettings.Entry{{Value: rec[0].Value, Scope: claudesettings.ScopeUser}}}
	if got := len(RecommendedMissing(eff2)); got != 12 {
		t.Errorf("allow entry counted as installed: missing %d", got)
	}
}

func TestRecommendedNeverClaimsUserString(t *testing.T) {
	p := testEnv(t)
	settings := p.ClaudeSettings()
	writeFile(t, settings, `{"permissions": {"deny": ["Read(~/.ssh/id_*)"]}}`)
	led := &claudesettings.Ledger{V: 1} // owns nothing
	eff, err := claudesettings.Read(claudesettings.Locate(p, ""), led)
	if err != nil {
		t.Fatal(err)
	}
	missing := RecommendedMissing(eff)
	if len(missing) != 11 {
		t.Fatalf("missing %d, want 11", len(missing))
	}
	for _, m := range missing {
		if m.Value == "Read(~/.ssh/id_*)" {
			t.Fatal("the person's own string is reported missing")
		}
	}
	book, err := List(Input{Paths: p, Ledger: led})
	if err != nil {
		t.Fatal(err)
	}
	r, group, ok := findRow(book, RowID(KindNativeDeny, claudesettings.ScopeUser, claudesettings.KeyDeny, "Read(~/.ssh/id_*)"))
	if !ok {
		t.Fatalf("row missing: %+v", book.Groups)
	}
	if r.Owner != OwnerUser || group != GroupBlocked || !r.Recommended || r.Twin != "secrets-read/read-ssh-private-key" {
		t.Errorf("row %+v in %s", r, group)
	}
	if len(book.Recommended) != 11 {
		t.Errorf("Book.Recommended %d, want 11", len(book.Recommended))
	}
}

// TestCoveredTwins: a pack rule is covered when every recommended string
// with it as Twin is installed; a deny counts for an ask recommendation.
func TestCoveredTwins(t *testing.T) {
	if got := CoveredTwins(claudesettings.Effective{}); len(got) != 0 {
		t.Fatalf("empty: %v", got)
	}
	var full claudesettings.Effective
	for _, r := range Recommended() {
		// every string as a deny: for an ask recommendation, stricter
		full.Deny = append(full.Deny, claudesettings.Entry{Value: r.Value, Scope: claudesettings.ScopeUser})
	}
	want := []string{
		"persistence/launch-agent-write", "persistence/shell-rc-write", "persistence/systemd-unit-write",
		"secrets-read/read-aws-credentials", "secrets-read/read-dotenv", "secrets-read/read-other-credentials", "secrets-read/read-ssh-private-key",
	}
	if got := CoveredTwins(full); !reflect.DeepEqual(got, want) {
		t.Fatalf("full: %v", got)
	}
	// one of the two .env strings: read-dotenv is not covered
	var part claudesettings.Effective
	part.Ask = []claudesettings.Entry{{Value: "Read(.env)"}}
	part.Deny = []claudesettings.Entry{{Value: "Read(~/.ssh/id_*)"}}
	if got := CoveredTwins(part); !reflect.DeepEqual(got, []string{"secrets-read/read-ssh-private-key"}) {
		t.Fatalf("part: %v", got)
	}
}

// TestRecommendedPlanExactStrings: the plan writes every recommended
// string exactly as Recommended spells it (the bare dotenv names stay
// bare) to the user settings file under its recommended: intent; a rule
// that is not recommended is refused.
func TestRecommendedPlanExactStrings(t *testing.T) {
	p := testEnv(t)
	in := Input{Paths: p}
	rec := Recommended()
	plan, err := RecommendedPlan(in, rec)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Steps) != len(rec) {
		t.Fatalf("%d steps for %d rules", len(plan.Steps), len(rec))
	}
	for i, s := range plan.Steps {
		r := rec[i]
		if s.Mechanism != MechNative || s.File != p.ClaudeSettings() || s.Key != r.Source.Key || s.Value != r.Value ||
			s.IntentID != IntentPrefix+IntentID(r.Value) || s.Sentence != r.Sentence {
			t.Errorf("step %d %+v for %s", i, s, r.Value)
		}
	}
	other := rec[0]
	other.Value = "Read(~/.kube/config)"
	if _, err := RecommendedPlan(in, []Rule{other}); err == nil {
		t.Error("a rule that is not recommended was planned")
	}
}
