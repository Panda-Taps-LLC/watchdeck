package manifest

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// tempFile is a v2 file with a skill grant and the given temporary list
// (YAML lines, already indented under temporary:).
func tempFile(temps string) string {
	return "version: 2\nsubjects:\n  - {kind: skill, name: canary, grant: {write: [\"/tmp/out\"]}}\ntemporary:\n" + temps
}

func rfc(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// TestTemporaryStrictErrors: every malformed temporary entry is refused
// with an error that names the field and the rule, never the value, and a
// project file may not carry temporary at all (it only narrows).
func TestTemporaryStrictErrors(t *testing.T) {
	const evil = "EVIL| requested but not granted"
	good := "    until: \"2026-10-24T18:00:00Z\"\n    added: \"2026-10-24T10:00:00Z\"\n"
	cases := map[string]struct{ src, want string }{
		"no id":           {"  - kind: rule\n    rule: \"exfil/curl-data-file\"\n" + good, "temporary[0].id: required"},
		"bad id":          {"  - id: \"" + evil + "\"\n    kind: rule\n    rule: \"exfil/curl-data-file\"\n" + good, "temporary[0].id: required"},
		"bad kind":        {"  - id: \"t-0000abcd\"\n    kind: \"" + evil + "\"\n    rule: \"exfil/x\"\n" + good, "temporary.t-0000abcd.kind: must be rule or grant"},
		"no kind":         {"  - id: \"t-0000abcd\"\n    rule: \"exfil/x\"\n" + good, "temporary.t-0000abcd.kind: must be rule or grant"},
		"missing rule":    {"  - id: \"t-0000abcd\"\n    kind: rule\n" + good, "temporary.t-0000abcd.rule: required"},
		"bad rule":        {"  - id: \"t-0000abcd\"\n    kind: rule\n    rule: \"" + evil + "\"\n" + good, "temporary.t-0000abcd.rule: required"},
		"rule with skill": {"  - id: \"t-0000abcd\"\n    kind: rule\n    rule: \"exfil/x\"\n    skill: \"canary\"\n" + good, "temporary.t-0000abcd.skill: not allowed for kind rule"},
		"rule with grant": {"  - id: \"t-0000abcd\"\n    kind: rule\n    rule: \"exfil/x\"\n    grant: {network: all}\n" + good, "temporary.t-0000abcd.grant: not allowed for kind rule"},
		"missing skill":   {"  - id: \"t-0000abcd\"\n    kind: grant\n    grant: {network: all}\n" + good, "temporary.t-0000abcd.skill: required"},
		"bad skill":       {"  - id: \"t-0000abcd\"\n    kind: grant\n    skill: \"" + evil + "\"\n    grant: {network: all}\n" + good, "temporary.t-0000abcd.skill: required"},
		"star skill":      {"  - id: \"t-0000abcd\"\n    kind: grant\n    skill: \"*\"\n    grant: {network: all}\n" + good, "temporary.t-0000abcd.skill: required"},
		"missing grant":   {"  - id: \"t-0000abcd\"\n    kind: grant\n    skill: \"canary\"\n" + good, "temporary.t-0000abcd.grant: required"},
		"empty grant":     {"  - id: \"t-0000abcd\"\n    kind: grant\n    skill: \"canary\"\n    grant: {}\n" + good, "temporary.t-0000abcd.grant: required"},
		"auto_allow":      {"  - id: \"t-0000abcd\"\n    kind: grant\n    skill: \"canary\"\n    grant: {network: all, auto_allow: true}\n" + good, "temporary.t-0000abcd.grant.auto_allow: not allowed"},
		"auto_allow off":  {"  - id: \"t-0000abcd\"\n    kind: grant\n    skill: \"canary\"\n    grant: {network: all, auto_allow: false}\n" + good, "temporary.t-0000abcd.grant.auto_allow: not allowed"},
		"bad network":     {"  - id: \"t-0000abcd\"\n    kind: grant\n    skill: \"canary\"\n    grant: {network: \"" + evil + "\"}\n" + good, "temporary.t-0000abcd.grant.network: must be one of"},
		"deny path":       {"  - id: \"t-0000abcd\"\n    kind: grant\n    skill: \"canary\"\n    grant: {write: [\"~/.ssh\"]}\n" + good, "temporary.t-0000abcd.grant.write[0]"},
		"grant session":   {"  - id: \"t-0000abcd\"\n    kind: grant\n    skill: \"canary\"\n    grant: {network: all}\n    session: \"s1\"\n" + good, "temporary.t-0000abcd.session: not allowed for kind grant"},
		"bad session":     {"  - id: \"t-0000abcd\"\n    kind: rule\n    rule: \"exfil/x\"\n    session: \"" + evil + "\"\n" + good, "temporary.t-0000abcd.session: "},
		"no until":        {"  - id: \"t-0000abcd\"\n    kind: rule\n    rule: \"exfil/x\"\n    added: \"2026-10-24T10:00:00Z\"\n", "temporary.t-0000abcd.until: required"},
		"bad until":       {"  - id: \"t-0000abcd\"\n    kind: rule\n    rule: \"exfil/x\"\n    until: \"" + evil + "\"\n    added: \"2026-10-24T10:00:00Z\"\n", "temporary.t-0000abcd.until: required"},
		"no added":        {"  - id: \"t-0000abcd\"\n    kind: rule\n    rule: \"exfil/x\"\n    until: \"2026-10-24T18:00:00Z\"\n", "temporary.t-0000abcd.added: required"},
		"until first":     {"  - id: \"t-0000abcd\"\n    kind: rule\n    rule: \"exfil/x\"\n    until: \"2026-10-24T09:00:00Z\"\n    added: \"2026-10-24T10:00:00Z\"\n", "temporary.t-0000abcd.until: must be after added"},
		"session over 8h": {"  - id: \"t-0000abcd\"\n    kind: rule\n    rule: \"exfil/x\"\n    session: \"s1\"\n    until: \"2026-10-24T18:00:01Z\"\n    added: \"2026-10-24T10:00:00Z\"\n", "temporary.t-0000abcd.until: at most 8 hours after added"},
		"grant over 8h":   {"  - id: \"t-0000abcd\"\n    kind: grant\n    skill: \"canary\"\n    grant: {network: all}\n    until: \"2026-10-25T10:00:00Z\"\n    added: \"2026-10-24T10:00:00Z\"\n", "temporary.t-0000abcd.until: at most 8 hours after added"},
		"unknown key":     {"  - id: \"t-0000abcd\"\n    kind: rule\n    rule: \"exfil/x\"\n    \"" + evil + "\": 1\n" + good, "unknown field"},
		"duplicate id": {"  - id: \"t-0000abcd\"\n    kind: rule\n    rule: \"exfil/x\"\n" + good +
			"  - id: \"t-0000abcd\"\n    kind: rule\n    rule: \"exfil/y\"\n" + good, "temporary.t-0000abcd.id: duplicate"},
	}
	for name, c := range cases {
		src := tempFile(c.src)
		_, err := ParsePolicyFile([]byte(src))
		if err == nil {
			t.Errorf("%s: accepted\n%s", name, src)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %q, want %q", name, err, c.want)
		}
		if strings.Contains(err.Error(), "EVIL") || strings.Contains(err.Error(), "|") {
			t.Errorf("%s: error echoes the value: %v", name, err)
		}
		if _, oerr := ParseOverrides([]byte(src)); oerr == nil {
			t.Errorf("%s: ParseOverrides accepted", name)
		}
	}

	// A good entry parses.
	ok := tempFile("  - id: \"t-0000abcd\"\n    kind: rule\n    rule: \"user/no-prod-db\"\n    session: \"s1\"\n" + good)
	if _, err := ParsePolicyFile([]byte(ok)); err != nil {
		t.Fatalf("good entry: %v", err)
	}

	// The project file may not hold temporaries (it can only narrow).
	home := t.TempDir()
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proj, ProjectOverridesFile), []byte(ok), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := LoadOverrides("", proj)
	if err == nil || !strings.Contains(err.Error(), "temporary: not allowed in a project file") {
		t.Fatalf("project file with temporary: %v", err)
	}
	// The same bytes are fine as the user file.
	cfg := filepath.Join(home, "cfg")
	if err := os.MkdirAll(cfg, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg, UserOverridesFile), []byte(ok), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadOverrides(cfg, ""); err != nil {
		t.Fatalf("user file with temporary: %v", err)
	}
}

// TestSkillOverridesAtFoldsTemporaries (R7): an unexpired grant temporary
// widens the skill's block in the skill view every grant consumer reads;
// an expired one does not; BaseSkillOverrides never folds (the writers'
// view, so a timed grant is never saved as a permanent one).
func TestSkillOverridesAtFoldsTemporaries(t *testing.T) {
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	added := now.Add(-30 * time.Minute)
	src := tempFile(
		"  - id: \"t-00000001\"\n    kind: grant\n    skill: \"canary\"\n    grant: {network: all, write: [\"/tmp/more\"]}\n" +
			"    until: \"" + rfc(now.Add(30*time.Minute)) + "\"\n    added: \"" + rfc(added) + "\"\n" +
			"  - id: \"t-00000002\"\n    kind: grant\n    skill: \"fresh\"\n    grant: {network: localhost, caches: true}\n" +
			"    until: \"" + rfc(now.Add(time.Hour)) + "\"\n    added: \"" + rfc(added) + "\"\n" +
			"  - id: \"t-00000003\"\n    kind: grant\n    skill: \"canary\"\n    grant: {env: [\"OLD_TOKEN_NAME\"]}\n" +
			"    until: \"" + rfc(now) + "\"\n    added: \"" + rfc(added) + "\"\n" +
			"  - id: \"t-00000004\"\n    kind: rule\n    rule: \"exfil/x\"\n" +
			"    until: \"" + rfc(now.Add(time.Hour)) + "\"\n    added: \"" + rfc(added) + "\"\n")
	f, err := ParsePolicyFile([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Temporary) != 4 {
		t.Fatalf("temporary = %+v", f.Temporary)
	}

	o := SkillOverridesAt(now, &f)
	c := o.Skills["canary"]
	if c.Network == nil || *c.Network != NetAll {
		t.Errorf("canary network = %v", c.Network)
	}
	if !reflect.DeepEqual(c.Write, []string{"/tmp/out", "/tmp/more"}) {
		t.Errorf("canary write = %q", c.Write)
	}
	if len(c.Env) != 0 {
		t.Errorf("expired temporary folded: env %q", c.Env)
	}
	// While a timed grant is in force the skill always asks.
	if c.AutoAllow == nil || *c.AutoAllow {
		t.Errorf("auto_allow not pinned off: %v", c.AutoAllow)
	}
	fr, ok := o.Skills["fresh"]
	if !ok || fr.Network == nil || *fr.Network != NetLocalhost || !fr.Caches {
		t.Errorf("fresh = %+v (ok %v)", fr, ok)
	}
	// The grant widens what the skill gets.
	eff, _ := Grant("canary", o, Overrides{})
	if eff.Network != NetAll {
		t.Errorf("Grant network = %v", eff.Network)
	}

	// After every until: the base grant only.
	later := SkillOverridesAt(now.Add(2*time.Hour), &f)
	if lc := later.Skills["canary"]; lc.Network != nil || lc.AutoAllow != nil || !reflect.DeepEqual(lc.Write, []string{"/tmp/out"}) {
		t.Errorf("after expiry canary = %+v", lc)
	}
	if _, ok := later.Skills["fresh"]; ok {
		t.Errorf("after expiry fresh still present")
	}

	// The writers' view never folds.
	base := f.BaseSkillOverrides()
	if bc := base.Skills["canary"]; bc.Network != nil || len(bc.Write) != 1 {
		t.Errorf("base canary = %+v", bc)
	}
	if _, ok := base.Skills["fresh"]; ok {
		t.Errorf("base has fresh")
	}
	// Folding never changes the file it reads.
	if f.Subjects[0].Grant.Network != nil || len(f.Subjects[0].Grant.Write) != 1 {
		t.Errorf("SkillOverridesAt mutated the file: %+v", f.Subjects[0].Grant)
	}

	// SkillOverrides() and ParseOverrides use the wall clock: an until an
	// hour from now is in force.
	wall := time.Now()
	far := tempFile("  - id: \"t-00000001\"\n    kind: grant\n    skill: \"canary\"\n    grant: {network: all}\n" +
		"    until: \"" + rfc(wall.Add(time.Hour)) + "\"\n    added: \"" + rfc(wall.Add(-time.Minute)) + "\"\n")
	po, err := ParseOverrides([]byte(far))
	if err != nil {
		t.Fatal(err)
	}
	if n := po.Skills["canary"].Network; n == nil || *n != NetAll {
		t.Errorf("ParseOverrides did not fold: %+v", po.Skills["canary"])
	}
}

// TestTemporaryIDStable: the id is t- and fnv32a of the identifying
// fields, so the same pause written twice has one id.
func TestTemporaryIDStable(t *testing.T) {
	added := time.Date(2026, 10, 24, 10, 0, 0, 0, time.UTC)
	a := Temporary{Kind: TempRule, Rule: "exfil/x", Session: "s1", Added: added, Until: added.Add(time.Hour)}
	b := a
	b.Until = added.Add(8 * time.Hour)
	if TemporaryID(a) != TemporaryID(b) || !ValidTemporaryID(TemporaryID(a)) {
		t.Fatalf("ids %q %q", TemporaryID(a), TemporaryID(b))
	}
	c := a
	c.Session = "s2"
	if TemporaryID(c) == TemporaryID(a) {
		t.Fatal("session not in the id")
	}
	// fields are separated: rule "ab"+skill "" differs from rule "a"+skill "b"
	d := Temporary{Kind: TempRule, Rule: "ab", Added: added}
	e := Temporary{Kind: TempRule, Rule: "a", Skill: "b", Added: added}
	if TemporaryID(d) == TemporaryID(e) {
		t.Fatal("fields not separated")
	}
}
