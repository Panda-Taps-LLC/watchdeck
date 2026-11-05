package rulebook

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/Panda-Taps-LLC/watchdeck/internal/claudesettings"
	"github.com/Panda-Taps-LLC/watchdeck/internal/manifest"
	"github.com/Panda-Taps-LLC/watchdeck/internal/policy"
	"github.com/Panda-Taps-LLC/watchdeck/internal/rules"
)

// seedSettings is a user settings.json with keys around permissions.deny.
const seedSettings = `{
  "model": "fake-model",
  "permissions": {
    "allow": [
      "Bash(ls *)"
    ],
    "deny": [
      "Bash(rm *)"
    ],
    "defaultMode": "default"
  },
  "env": {
    "FAKE": "sk-FAKE-not-a-secret"
  }
}
`

func applyEnv(t *testing.T) (Input, string) {
	t.Helper()
	in := Input{Paths: testEnv(t), ProjectRoot: t.TempDir()}
	user := filepath.Join(in.Paths.ClaudeDir, "settings.json")
	writeFile(t, user, seedSettings)
	return in, user
}

func mustPropose(t *testing.T, in Input, req AddRequest) Plan {
	t.Helper()
	p, err := Propose(in, req)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func backups(t *testing.T, path string) []string {
	t.Helper()
	m, err := filepath.Glob(path + ".bak-*")
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func loadLedger(t *testing.T, in Input) *claudesettings.Ledger {
	t.Helper()
	led, err := claudesettings.LoadLedger(in.Paths.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	return led
}

// listAt returns the strings under a dotted key of a JSON file, and the
// rest of the document with that key removed.
func listAt(t *testing.T, path, key string) ([]string, map[string]any) {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(readBytes(t, path), &doc); err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(key, ".")
	obj := doc
	for _, p := range parts[:len(parts)-1] {
		obj, _ = obj[p].(map[string]any)
		if obj == nil {
			return nil, doc
		}
	}
	var out []string
	if arr, ok := obj[parts[len(parts)-1]].([]any); ok {
		for _, v := range arr {
			out = append(out, v.(string))
		}
	}
	delete(obj, parts[len(parts)-1])
	return out, doc
}

func TestApplyWritesNativeWithBackup(t *testing.T) {
	in, user := applyEnv(t)
	p := mustPropose(t, in, AddRequest{Action: "deny", What: WhatCommand, Value: "curl"})
	res, err := Apply(in, p)
	if err != nil {
		t.Fatal(err)
	}
	row := RowID(KindNativeDeny, claudesettings.ScopeUser, claudesettings.KeyDeny, "Bash(curl *)")
	if !reflect.DeepEqual(res.RowIDs, []string{row}) {
		t.Errorf("row ids = %v, want [%s]", res.RowIDs, row)
	}
	if !reflect.DeepEqual(res.Written, []string{user}) {
		t.Errorf("written = %v", res.Written)
	}
	deny, rest := listAt(t, user, claudesettings.KeyDeny)
	if !reflect.DeepEqual(deny, []string{"Bash(rm *)", "Bash(curl *)"}) {
		t.Errorf("deny = %v", deny)
	}
	_ = rest
	// Byte for byte: the written file minus the one added line is the seed.
	written := string(readBytes(t, user))
	if back := strings.Replace(written, "\"Bash(rm *)\",\n      \"Bash(curl *)\"\n", "\"Bash(rm *)\"\n", 1); back != seedSettings {
		t.Errorf("bytes outside the added line changed:\n%s\nwant\n%s", written, seedSettings)
	}
	// Key order outside the list is kept too.
	if b := string(readBytes(t, user)); strings.Index(b, `"model"`) > strings.Index(b, `"permissions"`) || strings.Index(b, `"permissions"`) > strings.Index(b, `"env"`) {
		t.Errorf("key order changed:\n%s", b)
	}
	bak := backups(t, user)
	if len(bak) != 1 || !reflect.DeepEqual(res.Backups, bak) {
		t.Fatalf("backups = %v, result %v", bak, res.Backups)
	}
	if string(readBytes(t, bak[0])) != seedSettings {
		t.Errorf("backup does not hold the previous bytes")
	}
	if got := loadLedger(t, in).Owners(user, claudesettings.KeyDeny, "Bash(curl *)"); !reflect.DeepEqual(got, []string{row}) {
		t.Errorf("owners = %v, want [%s]", got, row)
	}
	if got := loadLedger(t, in).Owners(user, claudesettings.KeyDeny, "Bash(rm *)"); got != nil {
		t.Errorf("the person's string is claimed: %v", got)
	}
}

func TestApplyRegexWritesOverrides(t *testing.T) {
	in, _ := applyEnv(t)
	p := mustPropose(t, in, AddRequest{Action: "deny", What: WhatRegex, Value: `curl\s+-d\s+@`})
	res, err := Apply(in, p)
	if err != nil {
		t.Fatal(err)
	}
	over := in.Paths.OverridesFile()
	id := "user-" + hash8(`curl\s+-d\s+@`)
	if !reflect.DeepEqual(res.RowIDs, []string{"user:" + id}) || !reflect.DeepEqual(res.Written, []string{over}) {
		t.Errorf("result = %+v", res)
	}
	pol, warns, err := policy.Load(over, "")
	if err != nil || len(warns) != 0 {
		t.Fatalf("load: %v %v", err, warns)
	}
	rs := pol.Rules()
	if len(rs) != 1 || rs[0].ID != id || rs[0].Tool != "Bash" || rs[0].Action != "deny" || rs[0].Match.Regex != `curl\s+-d\s+@` {
		t.Fatalf("rules = %+v", rs)
	}
	// The row List shows for it has the same id.
	book, err := List(in)
	if err != nil {
		t.Fatal(err)
	}
	if _, g, ok := findRow(book, "user:"+id); !ok || g != GroupWatchdeck {
		t.Errorf("row user:%s not listed (group %q)", id, g)
	}
}

func TestApplyTwice(t *testing.T) {
	in, user := applyEnv(t)
	over := in.Paths.OverridesFile()
	p := mustPropose(t, in, AddRequest{Action: "deny", What: WhatCommand, Value: "curl", Twin: true})
	if _, err := Apply(in, p); err != nil {
		t.Fatal(err)
	}
	ledBefore := readBytes(t, filepath.Join(in.Paths.StateDir, claudesettings.LedgerFile))
	settingsBefore, overBefore := readBytes(t, user), readBytes(t, over)
	nb, no := len(backups(t, user)), len(backups(t, over))

	res, err := Apply(in, mustPropose(t, in, AddRequest{Action: "deny", What: WhatCommand, Value: "curl", Twin: true}))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Backups) != 0 || len(res.Written) != 0 {
		t.Errorf("second apply wrote: %+v", res)
	}
	if len(res.RowIDs) != 2 {
		t.Errorf("row ids = %v", res.RowIDs)
	}
	if len(backups(t, user)) != nb || len(backups(t, over)) != no {
		t.Errorf("a new backup appeared")
	}
	if string(readBytes(t, user)) != string(settingsBefore) || string(readBytes(t, over)) != string(overBefore) {
		t.Errorf("files changed on the second apply")
	}
	deny, _ := listAt(t, user, claudesettings.KeyDeny)
	if strings.Count(strings.Join(deny, "\n"), "Bash(curl *)") != 1 {
		t.Errorf("deny = %v", deny)
	}
	if got := readBytes(t, filepath.Join(in.Paths.StateDir, claudesettings.LedgerFile)); string(got) != string(ledBefore) {
		t.Errorf("ledger changed:\n%s\n%s", ledBefore, got)
	}
}

func TestApplyRefusesForeignFile(t *testing.T) {
	in, _ := applyEnv(t)
	p := mustPropose(t, in, AddRequest{Action: "deny", What: WhatCommand, Value: "curl"})
	other := filepath.Join(t.TempDir(), "settings.json")
	p.Steps[0].File = other
	if _, err := Apply(in, p); !errors.Is(err, ErrScope) {
		t.Fatalf("err = %v", err)
	}
	if _, err := os.Stat(other); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("foreign file written")
	}
	p = mustPropose(t, in, AddRequest{Action: "deny", What: WhatRegex, Value: "x"})
	p.Steps[0].File = other
	if _, err := Apply(in, p); !errors.Is(err, ErrScope) {
		t.Fatalf("hook step err = %v", err)
	}
}

func TestApplyProjectScope(t *testing.T) {
	in, user := applyEnv(t)
	before := readBytes(t, user)
	res, err := Apply(in, mustPropose(t, in, AddRequest{Action: "ask", What: WhatPath, Value: "secrets/x", Tool: "Read", Scope: claudesettings.ScopeProject}))
	if err != nil {
		t.Fatal(err)
	}
	proj := filepath.Join(in.ProjectRoot, ".claude", "settings.json")
	ask, _ := listAt(t, proj, claudesettings.KeyAsk)
	if !reflect.DeepEqual(ask, []string{"Read(/secrets/x)"}) {
		t.Errorf("project ask = %v", ask)
	}
	if string(readBytes(t, user)) != string(before) {
		t.Errorf("user settings changed")
	}
	row := RowID(KindNativeAsk, claudesettings.ScopeProject, claudesettings.KeyAsk, "Read(/secrets/x)")
	if !reflect.DeepEqual(res.RowIDs, []string{row}) {
		t.Errorf("rows = %v", res.RowIDs)
	}
	if got := loadLedger(t, in).Owners(proj, claudesettings.KeyAsk, "Read(/secrets/x)"); !reflect.DeepEqual(got, []string{row}) {
		t.Errorf("owners = %v", got)
	}
	if _, err := Remove(in, row); err != nil {
		t.Fatal(err)
	}
	if ask, _ := listAt(t, proj, claudesettings.KeyAsk); len(ask) != 0 {
		t.Errorf("after remove ask = %v", ask)
	}
}

func TestRemoveNativeOwned(t *testing.T) {
	in, user := applyEnv(t)
	res, err := Apply(in, mustPropose(t, in, AddRequest{Action: "deny", What: WhatCommand, Value: "curl"}))
	if err != nil {
		t.Fatal(err)
	}
	nb := len(backups(t, user))
	row := res.RowIDs[0]
	rm, err := Remove(in, row)
	if err != nil {
		t.Fatal(err)
	}
	deny, _ := listAt(t, user, claudesettings.KeyDeny)
	if !reflect.DeepEqual(deny, []string{"Bash(rm *)"}) {
		t.Errorf("deny = %v", deny)
	}
	if got := loadLedger(t, in).Owners(user, claudesettings.KeyDeny, "Bash(curl *)"); got != nil {
		t.Errorf("ledger still owns it: %v", got)
	}
	if len(backups(t, user)) != nb+1 || len(rm.Backups) != 1 {
		t.Errorf("backups: %d → %d, result %v", nb, len(backups(t, user)), rm.Backups)
	}
	if !reflect.DeepEqual(rm.RowIDs, []string{row}) || !reflect.DeepEqual(rm.Written, []string{user}) {
		t.Errorf("result = %+v", rm)
	}
}

func TestRemoveNativeSharedRemovesAllClaims(t *testing.T) {
	in, user := applyEnv(t)
	for _, id := range []string{"intent-a", "intent-b"} {
		if _, err := Apply(in, mustPropose(t, in, AddRequest{Action: "deny", What: WhatCommand, Value: "curl", IntentID: id})); err != nil {
			t.Fatal(err)
		}
	}
	if got := loadLedger(t, in).Owners(user, claudesettings.KeyDeny, "Bash(curl *)"); !reflect.DeepEqual(got, []string{"intent-a", "intent-b"}) {
		t.Fatalf("owners = %v", got)
	}
	row := RowID(KindNativeDeny, claudesettings.ScopeUser, claudesettings.KeyDeny, "Bash(curl *)")
	if _, err := Remove(in, row); err != nil {
		t.Fatal(err)
	}
	deny, _ := listAt(t, user, claudesettings.KeyDeny)
	if !reflect.DeepEqual(deny, []string{"Bash(rm *)"}) {
		t.Errorf("deny = %v", deny)
	}
	if got := loadLedger(t, in).Owners(user, claudesettings.KeyDeny, "Bash(curl *)"); got != nil {
		t.Errorf("owners after remove = %v", got)
	}
}

func TestRemoveNativeUnownedErrors(t *testing.T) {
	in, user := applyEnv(t)
	row := RowID(KindNativeDeny, claudesettings.ScopeUser, claudesettings.KeyDeny, "Bash(rm *)")
	_, err := Remove(in, row)
	if !errors.Is(err, ErrNotOwned) {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(err.Error(), "remove it from "+user+" by hand") {
		t.Errorf("message = %q", err)
	}
	if string(readBytes(t, user)) != seedSettings || len(backups(t, user)) != 0 {
		t.Errorf("settings touched")
	}
	// A row that is nowhere is a different error.
	_, err = Remove(in, RowID(KindNativeDeny, claudesettings.ScopeUser, claudesettings.KeyDeny, "Bash(nothing *)"))
	if err == nil || errors.Is(err, ErrNotOwned) {
		t.Errorf("missing row err = %v", err)
	}
	// Rows of kinds watchdeck never writes are refused.
	for _, id := range []string{"automode:user:autoMode.hard_deny:00000000", "domain:user:sandbox.network.allowedDomains:00000000", "nonsense", "native:user"} {
		if _, err := Remove(in, id); err == nil {
			t.Errorf("%q: no error", id)
		}
	}
}

func TestRemovePackRuleClearsOverride(t *testing.T) {
	in, _ := applyEnv(t)
	p, r, key := firstPackRule(t)
	over := in.Paths.OverridesFile()
	off := false
	f := policy.File{Version: 2, RuleOverrides: map[string]manifest.Toggle{key: {Enabled: &off, Action: "ask"}}}
	if _, err := policy.Save(over, f); err != nil {
		t.Fatal(err)
	}
	row := RowID(KindPack, "", p.Name, r.ID)
	res, err := Remove(in, row)
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := policy.LoadFile(over)
	if err != nil {
		t.Fatal(err)
	}
	if tg, ok := got.RuleOverrides[key]; ok {
		t.Errorf("override still there: %+v", tg)
	}
	if len(res.Backups) != 1 || !reflect.DeepEqual(res.Written, []string{over}) {
		t.Errorf("result = %+v", res)
	}
	// The pack rule itself is still listed, back at its own action and state.
	pr := packRow(t, in, row)
	if pr.Action != string(r.Action) || pr.State != StateOn && p.EnabledByDefault() {
		t.Errorf("row after remove: %+v", pr)
	}
	// A rule with no override: nothing to write, no error.
	res, err = Remove(in, row)
	if err != nil || len(res.Written) != 0 {
		t.Errorf("second remove: %+v %v", res, err)
	}
	// An unknown pack rule is refused.
	if _, err := Remove(in, "pack:nope/nope"); err == nil {
		t.Error("unknown pack rule accepted")
	}
}

func TestApplyPackRuleWritesOverride(t *testing.T) {
	in, _ := applyEnv(t)
	p, r, key := firstPackRule(t)
	over := in.Paths.OverridesFile()
	off := false
	if _, err := policy.Save(over, policy.File{Version: 2, RuleOverrides: map[string]manifest.Toggle{key: {Enabled: &off}}}); err != nil {
		t.Fatal(err)
	}
	res, err := Apply(in, mustPropose(t, in, AddRequest{Action: "deny", What: WhatPackRule, Value: key}))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(res.RowIDs, []string{RowID(KindPack, "", p.Name, r.ID)}) || !reflect.DeepEqual(res.Written, []string{over}) || len(res.Backups) != 1 {
		t.Errorf("result = %+v", res)
	}
	pol, _, err := policy.Load(over, "")
	if err != nil {
		t.Fatal(err)
	}
	tg := pol.RulesConfig().Rules[key]
	if tg.Action != rules.Deny || tg.Enabled == nil || *tg.Enabled {
		t.Errorf("toggle = %+v (want deny, enabled kept false)", tg)
	}
	// Applying it again changes nothing.
	res, err = Apply(in, mustPropose(t, in, AddRequest{Action: "deny", What: WhatPackRule, Value: key}))
	if err != nil || len(res.Written) != 0 {
		t.Errorf("twice: %+v %v", res, err)
	}
	// A plan naming an unknown rule or a bad action is refused, not trusted.
	for _, v := range []string{"nope/nope: deny", key + ": allow", key} {
		bad := Plan{Steps: []Step{{Mechanism: MechHook, File: over, Key: "rule_overrides", Value: v}}}
		if _, err := Apply(in, bad); err == nil {
			t.Errorf("plan value %q accepted", v)
		}
	}
}

func TestRemoveUserRule(t *testing.T) {
	in, _ := applyEnv(t)
	res, err := Apply(in, mustPropose(t, in, AddRequest{Action: "ask", What: WhatText, Value: "git push --force"}))
	if err != nil {
		t.Fatal(err)
	}
	keep, err := Apply(in, mustPropose(t, in, AddRequest{Action: "deny", What: WhatRegex, Value: "^rm "}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Remove(in, res.RowIDs[0]); err != nil {
		t.Fatal(err)
	}
	f, _, err := policy.LoadFile(in.Paths.OverridesFile())
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Rules) != 1 || "user:"+f.Rules[0].ID != keep.RowIDs[0] {
		t.Errorf("rules = %+v", f.Rules)
	}
	if _, err := Remove(in, res.RowIDs[0]); err == nil {
		t.Error("removing a rule twice: no error")
	}
}

func TestApplyMCPLaunchKeepsToolsAndRemoveSubject(t *testing.T) {
	in, _ := applyEnv(t)
	over := in.Paths.OverridesFile()
	f := policy.File{Version: 2, Subjects: []manifest.PolicySubject{{Kind: policy.KindMCP, Name: "github", MCPTools: map[string]string{"delete_*": "deny"}}}}
	if _, err := policy.Save(over, f); err != nil {
		t.Fatal(err)
	}
	res, err := Apply(in, mustPropose(t, in, AddRequest{What: WhatMCPLaunch, Value: "github"}))
	if err != nil {
		t.Fatal(err)
	}
	got, _, _ := policy.LoadFile(over)
	if len(got.Subjects) != 1 || got.Subjects[0].Launch == nil || !got.Subjects[0].Launch.Sandbox || got.Subjects[0].MCPTools["delete_*"] != "deny" {
		t.Fatalf("subjects = %+v", got.Subjects)
	}
	if !reflect.DeepEqual(res.RowIDs, []string{"subject:mcp:github"}) {
		t.Errorf("rows = %v", res.RowIDs)
	}
	// Removing by an entry row (subject:<kind>:<name>:<hash>) deletes the whole subject.
	book, err := List(in)
	if err != nil {
		t.Fatal(err)
	}
	entry := ""
	for _, g := range book.Groups {
		for _, r := range g.Rows {
			if strings.HasPrefix(r.ID, "subject:mcp:github:") {
				entry = r.ID
			}
		}
	}
	if entry == "" {
		t.Fatal("no gate entry row for github")
	}
	if _, err := Remove(in, entry); err != nil {
		t.Fatal(err)
	}
	got, _, _ = policy.LoadFile(over)
	if len(got.Subjects) != 0 {
		t.Errorf("subjects after remove = %+v", got.Subjects)
	}
	if _, err := Remove(in, "subject:mcp:github"); err == nil {
		t.Error("removing a missing subject: no error")
	}
}

func TestRemoveSkillSubject(t *testing.T) {
	in, _ := applyEnv(t)
	over := in.Paths.OverridesFile()
	net := manifest.NetAll
	f := policy.File{Version: 2, Subjects: []manifest.PolicySubject{
		{Kind: policy.KindSkill, Name: "pdf-tools", Grant: &manifest.Override{Network: &net}},
		{Kind: policy.KindSkill, Name: "keep-me", Grant: &manifest.Override{Caches: true}},
	}}
	if _, err := policy.Save(over, f); err != nil {
		t.Fatal(err)
	}
	res, err := Remove(in, "subject:skill:pdf-tools")
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := policy.LoadFile(over)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Subjects) != 1 || got.Subjects[0].Name != "keep-me" {
		t.Errorf("subjects = %+v", got.Subjects)
	}
	if len(res.Backups) != 1 || len(backups(t, over)) != 1 {
		t.Errorf("backups: result %v, on disk %v", res.Backups, backups(t, over))
	}
	// Gone now: the not-found error still fires for a skill.
	if _, err := Remove(in, "subject:skill:pdf-tools"); err == nil {
		t.Error("removing a missing skill subject: no error")
	}
	// "*" is the defaults for every skill: refused, file untouched.
	before := readBytes(t, over)
	if _, err := Remove(in, "subject:skill:*"); err == nil {
		t.Error(`"*" accepted`)
	}
	if string(readBytes(t, over)) != string(before) {
		t.Error("file changed")
	}
}

func TestApplyChecksHookRuleValues(t *testing.T) {
	in, _ := applyEnv(t)
	for _, m := range []manifest.RuleMatch{
		{Regex: "a\nb"},
		{Literals: []string{"ok", "a\rb"}},
		{Argv0: []string{"cu\x1brl"}},
	} {
		p := mustPropose(t, in, AddRequest{Action: "deny", What: WhatText, Value: "placeholder"})
		r := *p.Steps[0].Rule
		r.Match = m
		p.Steps[0].Rule = &r
		if _, err := Apply(in, p); !errors.Is(err, ErrValue) {
			t.Errorf("%+v: err = %v", m, err)
		}
	}
	if _, err := os.Stat(in.Paths.OverridesFile()); !errors.Is(err, os.ErrNotExist) {
		t.Error("overrides file written")
	}
}

// TestApplyManyStepsOneBackup: a plan of every recommended rule (two keys,
// twelve intents) writes the user settings file once, with one backup;
// every string is claimed under its own recommended intent.
func TestApplyManyStepsOneBackup(t *testing.T) {
	in, user := applyEnv(t)
	var plan Plan
	for _, r := range Recommended() {
		plan.Steps = append(plan.Steps, Step{Mechanism: MechNative, File: user, Key: r.Source.Key, Value: r.Value,
			IntentID: IntentPrefix + IntentID(r.Value)})
	}
	res, err := Apply(in, plan)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Written) != 1 || len(res.RowIDs) != 12 {
		t.Fatalf("result %+v", res)
	}
	baks, _ := filepath.Glob(user + ".bak-*")
	if len(baks) != 1 || len(res.Backups) != 1 {
		t.Fatalf("backups %v (result %v)", baks, res.Backups)
	}
	if string(readBytes(t, baks[0])) != seedSettings {
		t.Errorf("first backup is not the original")
	}
	led, err := claudesettings.LoadLedger(in.Paths.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range Recommended() {
		got := led.Owners(user, r.Source.Key, r.Value)
		if !reflect.DeepEqual(got, []string{IntentPrefix + IntentID(r.Value)}) {
			t.Errorf("%s owners %v", r.Value, got)
		}
	}
}

// TestApplyRefusesParens: a deserialised plan whose native string holds a
// parenthesis inside the tool's brackets is refused before anything is
// written, as Propose refuses the value.
func TestApplyRefusesParens(t *testing.T) {
	in, user := applyEnv(t)
	before := readBytes(t, user)
	for _, v := range []string{"Bash(foo) *)", "Read(a)b)", "Read(./x(1))", "Bash(()", "mcp__s__t)", "WebFetch(domain:a(b.com)"} {
		p := mustPropose(t, in, AddRequest{Action: "deny", What: WhatCommand, Value: "curl"})
		p.Steps[0].Value = v
		if _, err := Apply(in, p); !errors.Is(err, ErrValue) {
			t.Errorf("%q: err = %v", v, err)
		}
	}
	if !reflect.DeepEqual(before, readBytes(t, user)) || len(backups(t, user)) != 0 {
		t.Error("settings written")
	}
	// A well-formed string still goes through.
	p := mustPropose(t, in, AddRequest{Action: "deny", What: WhatCommand, Value: "curl"})
	if _, err := Apply(in, p); err != nil {
		t.Fatalf("Bash(curl *): %v", err)
	}
}

// TestApplyRecomputesHookRuleID: a hook step's rule id is recomputed from
// its match (user-<fnv32a hex8>), never trusted from the plan, so a plan
// cannot overwrite a rule under another id.
func TestApplyRecomputesHookRuleID(t *testing.T) {
	in, _ := applyEnv(t)
	for _, req := range []AddRequest{
		{Action: "deny", What: WhatText, Value: "rm -rf /"},
		{Action: "ask", What: WhatRegex, Value: `curl\s+-d`},
	} {
		p := mustPropose(t, in, req)
		want := "user-" + hash8(req.Value)
		r := *p.Steps[0].Rule
		r.ID = "pack-override"
		p.Steps[0].Rule = &r
		res, err := Apply(in, p)
		if err != nil {
			t.Fatal(err)
		}
		if row := RowID(KindHookRegex, claudesettings.ScopeUser, "", want); !reflect.DeepEqual(res.RowIDs, []string{row}) {
			t.Errorf("%q: row ids %v, want [%s]", req.Value, res.RowIDs, row)
		}
		f, _, err := policy.LoadFile(in.Paths.OverridesFile())
		if err != nil {
			t.Fatal(err)
		}
		ids := map[string]bool{}
		for _, x := range f.Rules {
			ids[x.ID] = true
		}
		if ids["pack-override"] || !ids[want] {
			t.Errorf("%q: rules in the file %v, want %s", req.Value, ids, want)
		}
	}
}

func TestApplyUndeclinesRecommended(t *testing.T) {
	in, _ := applyEnv(t)
	rec := Recommended()
	intent := IntentPrefix + IntentID(rec[0].Value)
	other := IntentPrefix + IntentID(rec[1].Value)
	if err := Decline(in.Paths.StateDir, []string{intent, other}); err != nil {
		t.Fatal(err)
	}
	if b, _ := List(in); !b.Recommended[0].Declined {
		t.Fatal("not declined before install")
	}
	plan, err := RecommendedPlan(in, rec[:1])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(in, plan); err != nil {
		t.Fatal(err)
	}
	d, err := LoadDeclined(in.Paths.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	if d.Has(intent) || !d.Has(other) {
		t.Fatalf("declined after install: %v", d.IntentIDs)
	}
	// Found already present also un-declines.
	if err := Decline(in.Paths.StateDir, []string{intent}); err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(in, plan); err != nil {
		t.Fatal(err)
	}
	if d, _ := LoadDeclined(in.Paths.StateDir); d.Has(intent) {
		t.Fatalf("still declined after a second install: %v", d.IntentIDs)
	}
	b, err := List(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range b.Recommended {
		if r.Value == rec[0].Value {
			t.Fatalf("installed rule still recommended: %+v", r)
		}
		if r.Declined != (r.Value == rec[1].Value) {
			t.Errorf("%s: declined %v", r.Value, r.Declined)
		}
	}
}

// seedOverrides writes an empty version 2 policy file, so a later write
// takes exactly one backup of it.
func seedOverrides(t *testing.T, path string) {
	t.Helper()
	writeFile(t, path, policy.Render(policy.File{Version: 2}))
}

// intentRows returns the rows of book whose Intent is id, by row id.
func intentRows(b Book, id string) map[string]Rule {
	out := map[string]Rule{}
	for _, g := range b.Groups {
		for _, r := range g.Rows {
			if r.Intent != nil && r.Intent.ID == id {
				out[r.ID] = r
			}
		}
	}
	return out
}

func sortedCopy(s []string) []string {
	out := append([]string(nil), s...)
	sort.Strings(out)
	return out
}

// policyHasIntent reports whether the policy file at path holds a rule or
// subject named for an intent.
func policyHasIntent(t *testing.T, path string) bool {
	t.Helper()
	f, _, err := policy.LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range f.Rules {
		if strings.HasPrefix(r.ID, "intent-") {
			return true
		}
	}
	for _, s := range f.Subjects {
		if strings.HasPrefix(s.Name, "intent-") {
			return true
		}
	}
	return false
}

func TestApplyEverywherePathWritesThreeMechanisms(t *testing.T) {
	in, user := applyEnv(t)
	over := in.Paths.OverridesFile()
	seedOverrides(t, over)
	req := AddRequest{Action: "deny", What: WhatPath, Value: "~/.fake-env", Everywhere: true}
	intent := IntentFor(req)
	h := hash8(req.Value)
	p := mustPropose(t, in, req)
	res, err := Apply(in, p)
	if err != nil {
		t.Fatal(err)
	}
	var wantRows []string
	for _, s := range p.Steps {
		wantRows = append(wantRows, s.RowID)
	}
	if !reflect.DeepEqual(res.RowIDs, wantRows) {
		t.Errorf("row ids %v, want %v", res.RowIDs, wantRows)
	}
	deny, _ := listAt(t, user, claudesettings.KeyDeny)
	if !reflect.DeepEqual(deny, []string{"Bash(rm *)", "Read(~/.fake-env)", "Edit(~/.fake-env)"}) {
		t.Errorf("deny = %v", deny)
	}
	led := loadLedger(t, in)
	for _, v := range []string{"Read(~/.fake-env)", "Edit(~/.fake-env)"} {
		if got := led.Owners(user, claudesettings.KeyDeny, v); !reflect.DeepEqual(got, []string{intent}) {
			t.Errorf("%s claimed by %v, want [%s]", v, got, intent)
		}
	}
	f, _, err := policy.LoadFile(over)
	if err != nil {
		t.Fatal(err)
	}
	var gotSub *manifest.PolicySubject
	for i := range f.Subjects {
		if f.Subjects[i].Name == "intent-path-"+h {
			gotSub = &f.Subjects[i]
		}
	}
	if gotSub == nil || gotSub.Kind != policy.KindTool || !reflect.DeepEqual(gotSub.Match.Tools, []string{"Grep", "Glob"}) ||
		gotSub.Paths == nil || !reflect.DeepEqual(gotSub.Paths.Deny, []string{"~/.fake-env"}) {
		t.Errorf("subject %+v", gotSub)
	}
	if len(f.Rules) != 1 || f.Rules[0].ID != "intent-path-"+h+"-bash" || f.Rules[0].Tool != "Bash" || f.Rules[0].Action != "deny" ||
		!reflect.DeepEqual(f.Rules[0].Match.Literals, []string{"~/.fake-env", in.Paths.Home + "/.fake-env"}) {
		t.Errorf("rules %+v", f.Rules)
	}
	if b := backups(t, user); len(b) != 1 {
		t.Errorf("settings backups %v, want one", b)
	}
	if b := backups(t, over); len(b) != 1 {
		t.Errorf("overrides backups %v, want one", b)
	}
	if !containsStr(res.Written, user) || !containsStr(res.Written, over) || len(res.Written) != 2 {
		t.Errorf("written %v", res.Written)
	}
	// The same plan again writes nothing.
	res, err = Apply(in, p)
	if err != nil || len(res.Written) != 0 {
		t.Errorf("second apply wrote %v (%v)", res.Written, err)
	}
}

func TestApplyHostWritesDeniedDomains(t *testing.T) {
	in, user := applyEnv(t)
	req := AddRequest{Action: "deny", What: WhatHost, Value: "fake-example.com", Everywhere: true}
	intent := IntentFor(req)
	res, err := Apply(in, mustPropose(t, in, req))
	if err != nil {
		t.Fatal(err)
	}
	dd, _ := listAt(t, user, claudesettings.KeyDeniedDomains)
	if !reflect.DeepEqual(dd, []string{"fake-example.com"}) {
		t.Errorf("deniedDomains = %v", dd)
	}
	deny, _ := listAt(t, user, claudesettings.KeyDeny)
	if !containsStr(deny, "WebFetch(domain:fake-example.com)") {
		t.Errorf("deny = %v", deny)
	}
	led := loadLedger(t, in)
	if got := led.Owners(user, claudesettings.KeyDeniedDomains, "fake-example.com"); !reflect.DeepEqual(got, []string{intent}) {
		t.Errorf("deniedDomains claimed by %v, want [%s]", got, intent)
	}
	row := RowID(KindSandboxDomain, claudesettings.ScopeUser, claudesettings.KeyDeniedDomains, "fake-example.com")
	if !containsStr(res.RowIDs, row) {
		t.Errorf("row ids %v lack %s", res.RowIDs, row)
	}
	if b := backups(t, user); len(b) != 1 {
		t.Errorf("settings backups %v, want one for both keys", b)
	}
}

func TestApplyRefusesDeniedDomainsWithoutHostIntent(t *testing.T) {
	in, user := applyEnv(t)
	host := "fake-example.com"
	for _, intent := range []string{
		"",
		"native:user:sandbox.network.deniedDomains:" + hash8(host),
		"intent:path:" + hash8(host),
		"intent:command:" + hash8(host),
		"intent:host:nothex!!",
		IntentPrefix + "fake",
	} {
		p := Plan{Steps: []Step{{
			Mechanism: MechNative, File: user, Key: claudesettings.KeyDeniedDomains, Value: host,
			RowID: RowID(KindSandboxDomain, claudesettings.ScopeUser, claudesettings.KeyDeniedDomains, host), IntentID: intent,
		}}}
		if _, err := Apply(in, p); err == nil {
			t.Errorf("intent %q: deniedDomains written", intent)
		}
	}
	// A host intent's domain must be a plain host.
	p := Plan{Steps: []Step{{Mechanism: MechNative, File: user, Key: claudesettings.KeyDeniedDomains, Value: "*",
		IntentID: "intent:host:" + hash8("*")}}}
	if _, err := Apply(in, p); err == nil {
		t.Error("deniedDomains * written")
	}
	if string(readBytes(t, user)) != seedSettings {
		t.Error("a refused plan changed the settings file")
	}
}

func TestRemoveIntentRemovesEveryRow(t *testing.T) {
	in, user := applyEnv(t)
	over := in.Paths.OverridesFile()
	hostReq := AddRequest{Action: "deny", What: WhatHost, Value: "fake-example.com", Everywhere: true}
	pathReq := AddRequest{Action: "deny", What: WhatPath, Value: "~/.fake-env", Everywhere: true}
	hostRes, err := Apply(in, mustPropose(t, in, hostReq))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(in, mustPropose(t, in, pathReq)); err != nil {
		t.Fatal(err)
	}
	dd, _ := listAt(t, user, claudesettings.KeyDeniedDomains)
	if len(dd) != 1 {
		t.Fatalf("deniedDomains = %v", dd)
	}
	before, _ := List(in)
	if n := len(intentRows(before, IntentFor(hostReq))); n != 4 {
		t.Fatalf("host intent rows before = %d, want 4", n)
	}

	removed, err := RemoveIntent(in, IntentFor(hostReq))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := sortedCopy(removed.RowIDs), sortedCopy(hostRes.RowIDs); !reflect.DeepEqual(got, want) {
		t.Errorf("removed rows %v, want %v", got, want)
	}
	after, _ := List(in)
	if n := len(intentRows(after, IntentFor(hostReq))); n != 0 {
		t.Errorf("host intent rows after = %d, want 0", n)
	}
	if n := len(intentRows(after, IntentFor(pathReq))); n != 4 {
		t.Errorf("path intent rows after = %d, want 4 (untouched)", n)
	}
	if dd, _ := listAt(t, user, claudesettings.KeyDeniedDomains); len(dd) != 0 {
		t.Errorf("deniedDomains after = %v", dd)
	}
	if deny, _ := listAt(t, user, claudesettings.KeyDeny); containsStr(deny, "WebFetch(domain:fake-example.com)") {
		t.Errorf("deny after = %v", deny)
	}
	f, _, _ := policy.LoadFile(over)
	for _, s := range f.Subjects {
		if strings.HasPrefix(s.Name, "intent-host-") {
			t.Errorf("subject %s left", s.Name)
		}
	}
	for _, r := range f.Rules {
		if strings.HasPrefix(r.ID, "intent-host-") {
			t.Errorf("rule %s left", r.ID)
		}
	}
	for _, e := range loadLedger(t, in).Entries {
		if containsStr(e.RuleIDs, IntentFor(hostReq)) {
			t.Errorf("ledger still claims %s for the intent", e.Value)
		}
	}
	// Nothing left: an error, nothing written.
	if res, err := RemoveIntent(in, IntentFor(hostReq)); err == nil || len(res.Written) != 0 {
		t.Errorf("second RemoveIntent = %v, %v", res, err)
	}
	// Not an intent id.
	if _, err := RemoveIntent(in, "native:user:permissions.deny:00000000"); err == nil {
		t.Error("RemoveIntent took a row id")
	}
}

func TestRemoveIntentKeepsSharedClaim(t *testing.T) {
	in, user := applyEnv(t)
	// The same string added on its own first, then by an intent.
	if _, err := Apply(in, mustPropose(t, in, AddRequest{Action: "deny", What: WhatPath, Value: "~/.fake-env", Tool: "Read"})); err != nil {
		t.Fatal(err)
	}
	req := AddRequest{Action: "deny", What: WhatPath, Value: "~/.fake-env", Everywhere: true}
	if _, err := Apply(in, mustPropose(t, in, req)); err != nil {
		t.Fatal(err)
	}
	if _, err := RemoveIntent(in, IntentFor(req)); err != nil {
		t.Fatal(err)
	}
	deny, _ := listAt(t, user, claudesettings.KeyDeny)
	if !containsStr(deny, "Read(~/.fake-env)") || containsStr(deny, "Edit(~/.fake-env)") {
		t.Errorf("deny = %v, want the separately added Read kept and Edit gone", deny)
	}
}

func TestRemoveRowKeepsRestOfIntent(t *testing.T) {
	in, user := applyEnv(t)
	req := AddRequest{Action: "deny", What: WhatHost, Value: "fake-example.com", Everywhere: true}
	res, err := Apply(in, mustPropose(t, in, req))
	if err != nil {
		t.Fatal(err)
	}
	read := res.RowIDs[0] // WebFetch(domain:…)
	one, err := Remove(in, read)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(one.RowIDs, []string{read}) {
		t.Errorf("Remove rows %v, want [%s]", one.RowIDs, read)
	}
	b, _ := List(in)
	rows := intentRows(b, IntentFor(req))
	if len(rows) != 3 {
		t.Fatalf("intent rows after one remove = %d, want 3", len(rows))
	}
	for id, r := range rows {
		if r.Intent.Rows != 3 {
			t.Errorf("%s: intent rows %d, want 3", id, r.Intent.Rows)
		}
	}
	// The deniedDomains row an intent owns is removed on its own (R3).
	domain := RowID(KindSandboxDomain, claudesettings.ScopeUser, claudesettings.KeyDeniedDomains, "fake-example.com")
	if _, err := Remove(in, domain); err != nil {
		t.Fatalf("remove owned domain row: %v", err)
	}
	if dd, _ := listAt(t, user, claudesettings.KeyDeniedDomains); len(dd) != 0 {
		t.Errorf("deniedDomains = %v", dd)
	}
	// One the person wrote is still theirs.
	writeFile(t, user, `{"sandbox":{"network":{"deniedDomains":["fake-hand.example"]}}}`)
	hand := RowID(KindSandboxDomain, claudesettings.ScopeUser, claudesettings.KeyDeniedDomains, "fake-hand.example")
	if _, err := Remove(in, hand); !errors.Is(err, ErrNotOwned) {
		t.Errorf("remove hand-written domain row = %v, want ErrNotOwned", err)
	}
}

// pruneEmpty drops empty arrays and the objects left empty by that.
func pruneEmpty(v any) (any, bool) {
	switch x := v.(type) {
	case []any:
		return x, len(x) > 0
	case map[string]any:
		for k, c := range x {
			if p, keep := pruneEmpty(c); keep {
				x[k] = p
			} else {
				delete(x, k)
			}
		}
		return x, len(x) > 0
	}
	return v, true
}

func settingsObject(t *testing.T, path string) any {
	t.Helper()
	var doc any
	if err := json.Unmarshal(readBytes(t, path), &doc); err != nil {
		t.Fatal(err)
	}
	doc, _ = pruneEmpty(doc)
	return doc
}

func TestUndoEverywhereFixRestoresFiles(t *testing.T) {
	for _, req := range []AddRequest{
		{Action: "deny", What: WhatHost, Value: "fake-example.com", Everywhere: true},
		{Action: "deny", What: WhatPath, Value: "~/.fake-env", Everywhere: true},
		{Action: "ask", What: WhatCommand, Value: "fake-tool", Everywhere: true},
	} {
		t.Run(string(req.What), func(t *testing.T) {
			in, user := applyEnv(t)
			over := in.Paths.OverridesFile()
			pre := settingsObject(t, user)
			res, err := Apply(in, mustPropose(t, in, req))
			if err != nil {
				t.Fatal(err)
			}
			if err := Resolve(in.Paths.StateDir, Resolution{ID: "fake-item", Action: ResolveAddRule, RuleIDs: res.RowIDs}); err != nil {
				t.Fatal(err)
			}
			undo, err := Undo(in, "fake-item")
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(undo.RowIDs, res.RowIDs) {
				t.Errorf("undo rows %v, want %v", undo.RowIDs, res.RowIDs)
			}
			b, _ := List(in)
			if n := len(intentRows(b, IntentFor(req))); n != 0 {
				t.Errorf("%d rows of the intent left", n)
			}
			for _, e := range loadLedger(t, in).Entries {
				if containsStr(e.RuleIDs, IntentFor(req)) {
					t.Errorf("ledger entry %s still claimed by the intent", e.Value)
				}
			}
			if policyHasIntent(t, over) {
				t.Error("the policy file still holds an intent rule or subject")
			}
			if got := settingsObject(t, user); !reflect.DeepEqual(got, pre) {
				t.Errorf("settings after undo\n%v\nwant\n%v", got, pre)
			}
		})
	}
}

func TestApplyKeepsIntentRuleID(t *testing.T) {
	in, _ := applyEnv(t)
	req := AddRequest{Action: "deny", What: WhatPath, Value: "~/.fake-env", Everywhere: true}
	h := hash8(req.Value)
	p := mustPropose(t, in, req)
	res, err := Apply(in, p)
	if err != nil {
		t.Fatal(err)
	}
	want := "intent-path-" + h + "-bash"
	if !containsStr(res.RowIDs, "user:"+want) {
		t.Errorf("row ids %v lack user:%s", res.RowIDs, want)
	}
	f, _, _ := policy.LoadFile(in.Paths.OverridesFile())
	if len(f.Rules) != 1 || f.Rules[0].ID != want {
		t.Fatalf("rules %+v, want %s", f.Rules, want)
	}

	// An intent id that is not the step's own, or a step without an
	// intent, is recomputed as user-<hash8> as before.
	for _, tamper := range []struct{ id, intent string }{
		{"intent-path-00000000-bash", "intent:path:" + h},
		{want, ""},
		{want, "intent:host:" + h},
		{"intent-command-" + h + "-bash", "intent:path:" + h},
	} {
		in, _ := applyEnv(t)
		p := mustPropose(t, in, req)
		hook := p.Steps[3]
		r := *hook.Rule
		r.ID = tamper.id
		hook.Rule, hook.IntentID = &r, tamper.intent
		res, err := Apply(in, Plan{Steps: []Step{hook}})
		if err != nil {
			t.Fatal(err)
		}
		recomputed := "user-" + hash8(req.Value)
		if !reflect.DeepEqual(res.RowIDs, []string{"user:" + recomputed}) {
			t.Errorf("tampered %+v: rows %v, want user:%s", tamper, res.RowIDs, recomputed)
		}
	}
}

func TestListShowsIntentOnEveryRow(t *testing.T) {
	in, _ := applyEnv(t)
	for _, req := range []AddRequest{
		{Action: "deny", What: WhatPath, Value: "~/.fake-env", Everywhere: true},
		{Action: "deny", What: WhatHost, Value: "fake-example.com", Everywhere: true},
		{Action: "deny", What: WhatCommand, Value: "fake-tool", Everywhere: true},
	} {
		res, err := Apply(in, mustPropose(t, in, req))
		if err != nil {
			t.Fatal(err)
		}
		b, err := List(in)
		if err != nil {
			t.Fatal(err)
		}
		rows := intentRows(b, IntentFor(req))
		if got, want := sortedCopy(keys(rows)), sortedCopy(res.RowIDs); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: rows with the intent %v, want %v", req.What, got, want)
		}
		for id, r := range rows {
			if r.Intent.Rows != len(res.RowIDs) {
				t.Errorf("%s %s: intent rows %d, want %d", req.What, id, r.Intent.Rows, len(res.RowIDs))
			}
			if !strings.Contains(r.Intent.Sentence, req.Value) || !strings.Contains(r.Intent.Sentence, "every route") {
				t.Errorf("%s %s: intent sentence %q", req.What, id, r.Intent.Sentence)
			}
		}
	}
	// A row that belongs to no intent has none.
	if _, err := Apply(in, mustPropose(t, in, AddRequest{Action: "deny", What: WhatCommand, Value: "fake-other"})); err != nil {
		t.Fatal(err)
	}
	b, _ := List(in)
	r, _, ok := findRow(b, RowID(KindNativeDeny, claudesettings.ScopeUser, claudesettings.KeyDeny, "Bash(fake-other *)"))
	if !ok || r.Intent != nil {
		t.Errorf("plain row %+v found %v, want no intent", r.Intent, ok)
	}
}

func keys(m map[string]Rule) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestProjectScopeIntentWritesProjectFiles(t *testing.T) {
	in, user := applyEnv(t)
	root := in.ProjectRoot
	projSettings := filepath.Join(root, ".claude", "settings.json")
	projPolicy := filepath.Join(root, manifest.ProjectOverridesFile)
	req := AddRequest{Action: "deny", What: WhatPath, Value: "config/.fake-env", Scope: claudesettings.ScopeProject, Everywhere: true}
	p := mustPropose(t, in, req)
	res, err := Apply(in, p)
	if err != nil {
		t.Fatal(err)
	}
	deny, _ := listAt(t, projSettings, claudesettings.KeyDeny)
	if !reflect.DeepEqual(deny, []string{"Read(/config/.fake-env)", "Edit(/config/.fake-env)"}) {
		t.Errorf("project deny = %v", deny)
	}
	if string(readBytes(t, user)) != seedSettings {
		t.Error("the user settings changed")
	}
	if _, err := os.Stat(in.Paths.OverridesFile()); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("user overrides file written (%v)", err)
	}
	f, _, err := policy.LoadProjectFile(projPolicy)
	if err != nil {
		t.Fatal(err)
	}
	gate := tildify(in.Paths.Home, filepath.Join(root, "config", ".fake-env"))
	if len(f.Subjects) != 1 || f.Subjects[0].Paths == nil || !reflect.DeepEqual(f.Subjects[0].Paths.Deny, []string{gate}) {
		t.Errorf("project subjects %+v, want a deny on %s", f.Subjects, gate)
	}
	if len(f.Rules) != 1 || !strings.HasPrefix(f.Rules[0].ID, "intent-path-") {
		t.Errorf("project rules %+v", f.Rules)
	}
	b, _ := List(in)
	rows := intentRows(b, IntentFor(req))
	if len(rows) != 4 {
		t.Fatalf("project intent rows = %d, want 4: %v", len(rows), keys(rows))
	}
	for id, r := range rows {
		if r.Scope != claudesettings.ScopeProject {
			t.Errorf("%s scope %s", id, r.Scope)
		}
	}
	removed, err := RemoveIntent(in, IntentFor(req))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := sortedCopy(removed.RowIDs), sortedCopy(res.RowIDs); !reflect.DeepEqual(got, want) {
		t.Errorf("removed %v, want %v", got, want)
	}
	if deny, _ := listAt(t, projSettings, claudesettings.KeyDeny); len(deny) != 0 {
		t.Errorf("project deny after = %v", deny)
	}
	if policyHasIntentProject(t, projPolicy) {
		t.Error("the project policy file still holds the intent")
	}
	// A pack-rule override or an MCP launch still never goes to the project file.
	bad := Plan{Steps: []Step{{Mechanism: MechSubject, File: projPolicy, Key: "subjects", Value: "fakesrv"}}}
	if _, err := Apply(in, bad); !errors.Is(err, ErrScope) {
		t.Errorf("mcp launch to the project file = %v, want ErrScope", err)
	}
}

func policyHasIntentProject(t *testing.T, path string) bool {
	t.Helper()
	f, _, err := policy.LoadProjectFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return len(f.Rules)+len(f.Subjects) > 0
}

// TestApplyRefusedPolicyEditWritesNothing: a policy edit the policy file's
// own check refuses stops the plan before the settings are written.
func TestApplyRefusedPolicyEditWritesNothing(t *testing.T) {
	in, user := applyEnv(t)
	p := mustPropose(t, in, AddRequest{Action: "deny", What: WhatPath, Value: "~/.fake-env", Everywhere: true})
	sub := *p.Steps[2].Subject
	sub.Paths = &manifest.GateLists{Deny: []string{"fake-rel"}} // not a gate path: no /, ~ or **/
	p.Steps[2].Subject = &sub
	if _, err := Apply(in, p); err == nil {
		t.Fatal("a subject with an invalid gate path was applied")
	}
	if string(readBytes(t, user)) != seedSettings {
		t.Error("the settings file was written")
	}
	if n := len(loadLedger(t, in).Entries); n != 0 {
		t.Errorf("the ledger holds %d entries", n)
	}
	if _, err := os.Stat(in.Paths.OverridesFile()); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the overrides file exists (%v)", err)
	}
}

// TestRemoveIntentMalformedProjectFileWritesNothing: a project policy file
// that cannot be read stops a project intent's removal before any write,
// and is never read for a user-scope intent.
func TestRemoveIntentMalformedProjectFileWritesNothing(t *testing.T) {
	in, user := applyEnv(t)
	projSettings := filepath.Join(in.ProjectRoot, ".claude", "settings.json")
	projPolicy := filepath.Join(in.ProjectRoot, manifest.ProjectOverridesFile)
	ledgerPath := filepath.Join(in.Paths.StateDir, claudesettings.LedgerFile)

	projReq := AddRequest{Action: "deny", What: WhatPath, Value: "config/.fake-env", Scope: claudesettings.ScopeProject, Everywhere: true}
	if _, err := Apply(in, mustPropose(t, in, projReq)); err != nil {
		t.Fatal(err)
	}
	userReq := AddRequest{Action: "deny", What: WhatHost, Value: "fake-example.com", Everywhere: true}
	if _, err := Apply(in, mustPropose(t, in, userReq)); err != nil {
		t.Fatal(err)
	}
	const broken = "version: 2\nsubjects: [\n"
	writeFile(t, projPolicy, broken)
	projBefore, userBefore, ledBefore := readBytes(t, projSettings), readBytes(t, user), readBytes(t, ledgerPath)
	overBefore := readBytes(t, in.Paths.OverridesFile())

	// The project intent: the broken file stops it before any write.
	res, err := RemoveIntent(in, IntentFor(projReq))
	if err == nil {
		t.Fatal("removal went ahead past a malformed project policy file")
	}
	if len(res.Written) != 0 {
		t.Errorf("written %v", res.Written)
	}
	if string(readBytes(t, projSettings)) != string(projBefore) {
		t.Error("the project settings were written")
	}
	if string(readBytes(t, ledgerPath)) != string(ledBefore) {
		t.Error("the ledger changed")
	}
	if string(readBytes(t, user)) != string(userBefore) || string(readBytes(t, in.Paths.OverridesFile())) != string(overBefore) {
		t.Error("a user file changed")
	}

	// The user intent never reads the project file.
	if _, err := RemoveIntent(in, IntentFor(userReq)); err != nil {
		t.Fatalf("user intent with a malformed project file: %v", err)
	}
	if dd, _ := listAt(t, user, claudesettings.KeyDeniedDomains); len(dd) != 0 {
		t.Errorf("deniedDomains after = %v", dd)
	}
	if policyHasIntent(t, in.Paths.OverridesFile()) {
		t.Error("the user policy file still holds the host intent")
	}
	if string(readBytes(t, projPolicy)) != broken {
		t.Error("the malformed project file was rewritten")
	}
}
