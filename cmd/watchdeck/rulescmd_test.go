package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Panda-Taps-LLC/watchdeck/internal/claudesettings"
	"github.com/Panda-Taps-LLC/watchdeck/internal/manifest"
	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
	"github.com/Panda-Taps-LLC/watchdeck/internal/policy"
	"github.com/Panda-Taps-LLC/watchdeck/internal/rulebook"
	"github.com/Panda-Taps-LLC/watchdeck/internal/rules"
)

func rulesCmd(a []string, o, e *bytes.Buffer) int { return cmdRules(a, o, e) }
func inboxCmd(a []string, o, e *bytes.Buffer) int { return cmdInbox(a, o, e) }

// rulesEnv is newTestEnv with the managed settings directory pointed at an
// empty temp dir, so nothing reads /Library or /etc.
func rulesEnv(t *testing.T) testEnv {
	t.Helper()
	e := newTestEnv(t)
	managed := t.TempDir()
	prev := claudesettings.ManagedDirOverride
	claudesettings.ManagedDirOverride = func() string { return managed }
	t.Cleanup(func() { claudesettings.ManagedDirOverride = prev })
	return e
}

// settingsList reads permissions.<key> from a settings file.
func settingsList(t *testing.T, path, key string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Permissions map[string][]string `json:"permissions"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("%s: %v\n%s", path, err, b)
	}
	return doc.Permissions[key]
}

func has(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func TestRulesListShowsNativeAndPacks(t *testing.T) {
	e := rulesEnv(t)
	writeFile(t, filepath.Join(e.claude, "settings.json"),
		`{"permissions":{"deny":["Bash(rm -rf *)"],"ask":["WebFetch(domain:example.test)"]}}`)
	code, out, errs := call(t, rulesCmd, "list")
	if code != 0 {
		t.Fatalf("exit %d\n%s%s", code, out, errs)
	}
	denyID := rulebook.RowID(rulebook.KindNativeDeny, claudesettings.ScopeUser, claudesettings.KeyDeny, "Bash(rm -rf *)")
	for _, want := range []string{"Blocked", denyID, "rm -rf", "example.test", "rules", "pack:", "(native-deny, user, user)", "Recommended, not installed: 12 (watchdeck rules recommended --install)"} {
		if !strings.Contains(out, want) {
			t.Errorf("list lacks %q:\n%s", want, out)
		}
	}
	// Groups come in order: sandbox, blocked, auto mode, watchdeck, ask.
	if i, j := strings.Index(out, "Blocked"), strings.Index(out, "Ask first"); i < 0 || j < 0 || i > j {
		t.Errorf("groups out of order:\n%s", out)
	}
	code, out, _ = call(t, rulesCmd, "list", "--json")
	if code != 0 {
		t.Fatalf("--json exit %d", code)
	}
	var book rulebook.Book
	if err := json.Unmarshal([]byte(out), &book); err != nil {
		t.Fatalf("--json: %v\n%s", err, out)
	}
	if len(book.Groups) != 5 || len(book.Recommended) != 12 {
		t.Errorf("book: %d groups, %d recommended", len(book.Groups), len(book.Recommended))
	}
}

func TestRulesAddBlockCommandWritesSettings(t *testing.T) {
	e := rulesEnv(t)
	settingsPath := filepath.Join(e.claude, "settings.json")
	writeFile(t, settingsPath, "{}\n")
	code, out, errs := call(t, rulesCmd, "add", "--block", "--command", "curl", "--yes")
	if code != 0 {
		t.Fatalf("exit %d\n%s%s", code, out, errs)
	}
	if !has(settingsList(t, settingsPath, "deny"), "Bash(curl *)") {
		t.Fatalf("deny lacks Bash(curl *)")
	}
	led, err := claudesettings.LoadLedger(filepath.Join(e.state, "watchdeck"))
	if err != nil {
		t.Fatal(err)
	}
	if led.Owners(settingsPath, claudesettings.KeyDeny, "Bash(curl *)") == nil {
		t.Errorf("ledger does not claim it: %+v", led.Entries)
	}
	baks := backups(t, settingsPath)
	if len(baks) != 1 {
		t.Fatalf("backups = %v", baks)
	}
	for _, want := range []string{"native", "Bash(curl *)", "wrote", "backup", filepath.Base(baks[0]), "native:user:permissions.deny:"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestRulesAddNoTTYPrintsPlanExit1(t *testing.T) {
	e := rulesEnv(t)
	settingsPath := filepath.Join(e.claude, "settings.json")
	writeFile(t, settingsPath, "{}\n")
	code, out, errs := call(t, rulesCmd, "add", "--ask", "--domain", "example.test")
	if code != 1 {
		t.Fatalf("exit %d, want 1\n%s%s", code, out, errs)
	}
	if !strings.Contains(out, "WebFetch(domain:example.test)") || !strings.Contains(out, "native") {
		t.Errorf("plan not printed:\n%s", out)
	}
	if b, _ := os.ReadFile(settingsPath); string(b) != "{}\n" {
		t.Errorf("settings changed: %s", b)
	}
	if baks := backups(t, settingsPath); len(baks) != 0 {
		t.Errorf("backup written: %v", baks)
	}
}

func TestRulesAddProjectScope(t *testing.T) {
	e := rulesEnv(t)
	if err := os.MkdirAll(filepath.Join(e.proj, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	code, out, errs := call(t, rulesCmd, "add", "--block", "--read", "secrets/key.txt", "--project", "--yes")
	if code != 0 {
		t.Fatalf("exit %d\n%s%s", code, out, errs)
	}
	proj := filepath.Join(e.proj, ".claude", "settings.json")
	if !has(settingsList(t, proj, "deny"), "Read(/secrets/key.txt)") {
		b, _ := os.ReadFile(proj)
		t.Fatalf("project settings lack the rule:\n%s", b)
	}
	if _, err := os.Stat(filepath.Join(e.claude, "settings.json")); err == nil {
		t.Errorf("user settings written for --project")
	}
	// never settings.local.json
	if _, err := os.Stat(filepath.Join(e.proj, ".claude", "settings.local.json")); err == nil {
		t.Errorf("settings.local.json written for --project")
	}
	// --project with no project root is an error.
	t.Chdir(e.home)
	if code, out, errs := call(t, rulesCmd, "add", "--block", "--read", "x", "--project", "--yes"); code != 2 {
		t.Errorf("no root: exit %d, want 2\n%s%s", code, out, errs)
	}
}

func TestRulesRemoveOwned(t *testing.T) {
	e := rulesEnv(t)
	settingsPath := filepath.Join(e.claude, "settings.json")
	writeFile(t, settingsPath, "{}\n")
	if code, out, errs := call(t, rulesCmd, "add", "--block", "--command", "curl", "--yes"); code != 0 {
		t.Fatalf("add exit %d\n%s%s", code, out, errs)
	}
	id := rulebook.RowID(rulebook.KindNativeDeny, claudesettings.ScopeUser, claudesettings.KeyDeny, "Bash(curl *)")
	code, out, errs := call(t, rulesCmd, "remove", id, "--yes")
	if code != 0 {
		t.Fatalf("remove exit %d\n%s%s", code, out, errs)
	}
	if has(settingsList(t, settingsPath, "deny"), "Bash(curl *)") {
		t.Errorf("still denied")
	}
	if !strings.Contains(out, "wrote") || !strings.Contains(out, "backup") {
		t.Errorf("output lacks wrote/backup:\n%s", out)
	}
}

// TestRulesRemovePackTurnsOff: rules remove on a built-in pack rule
// switches it off (rulebook.SetEnabled), as before rulebook.Remove began
// clearing a pack rule's override instead.
func TestRulesRemovePackTurnsOff(t *testing.T) {
	e := rulesEnv(t)
	writeFile(t, filepath.Join(e.claude, "settings.json"), "{}\n")
	packs := rules.Packs()
	if len(packs) == 0 || len(packs[0].Rules) == 0 {
		t.Fatalf("no built-in packs: %v", rules.LoadError())
	}
	key := packs[0].Name + "/" + packs[0].Rules[0].ID
	code, out, errs := call(t, rulesCmd, "remove", "pack:"+key, "--yes")
	if code != 0 {
		t.Fatalf("remove exit %d\n%s%s", code, out, errs)
	}
	f, _, err := policy.LoadFile(filepath.Join(e.cfg, paths.BinaryName, "overrides.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if tg := f.RuleOverrides[key]; tg.Enabled == nil || *tg.Enabled {
		t.Errorf("toggle = %+v, want enabled: false", tg)
	}
	if !strings.Contains(out, "switched off pack:"+key+"\n") || strings.Contains(out, "removed") {
		t.Errorf("output:\n%s", out)
	}
}

func TestRulesRemoveUnownedExit2(t *testing.T) {
	e := rulesEnv(t)
	settingsPath := filepath.Join(e.claude, "settings.json")
	orig := `{"permissions":{"deny":["Bash(curl *)"]}}`
	writeFile(t, settingsPath, orig)
	id := rulebook.RowID(rulebook.KindNativeDeny, claudesettings.ScopeUser, claudesettings.KeyDeny, "Bash(curl *)")
	code, out, errs := call(t, rulesCmd, "remove", id, "--yes")
	if code != 2 {
		t.Fatalf("exit %d, want 2\n%s%s", code, out, errs)
	}
	if !strings.Contains(errs, "not added by") {
		t.Errorf("stderr lacks the reason:\n%s", errs)
	}
	if b, _ := os.ReadFile(settingsPath); string(b) != orig {
		t.Errorf("settings changed: %s", b)
	}
	// An id that names nothing is an error too.
	if code, _, _ := call(t, rulesCmd, "remove", "native:user:permissions.deny:00000000", "--yes"); code != 2 {
		t.Errorf("unknown id: exit %d, want 2", code)
	}
}

func TestRulesRecommendedInstall(t *testing.T) {
	e := rulesEnv(t)
	settingsPath := filepath.Join(e.claude, "settings.json")
	writeFile(t, settingsPath, "{}\n")
	code, out, _ := call(t, rulesCmd, "recommended")
	if code != 0 || strings.Count(out, "missing") != 12 {
		t.Fatalf("listing: exit %d\n%s", code, out)
	}
	code, out, errs := call(t, rulesCmd, "recommended", "--install", "--yes")
	if code != 0 {
		t.Fatalf("install exit %d\n%s%s", code, out, errs)
	}
	deny, ask := settingsList(t, settingsPath, "deny"), settingsList(t, settingsPath, "ask")
	for _, r := range rulebook.Recommended() {
		list := ask
		if r.Source.Key == claudesettings.KeyDeny {
			list = deny
		}
		if !has(list, r.Value) {
			t.Errorf("%s lacks %s", r.Source.Key, r.Value)
		}
	}
	// One write for the file: exactly one backup, holding the original.
	baks := backups(t, settingsPath)
	if len(baks) != 1 {
		t.Fatalf("backups = %v, want exactly one", baks)
	}
	if b, _ := os.ReadFile(baks[0]); string(b) != "{}\n" {
		t.Errorf("backup = %q", b)
	}
	// The ledger file's entries carry recommended: intent ids.
	raw, err := os.ReadFile(filepath.Join(e.state, "watchdeck", claudesettings.LedgerFile))
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Entries []struct {
			RuleIDs []string `json:"rule_ids"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(raw, &file); err != nil || len(file.Entries) != 12 {
		t.Fatalf("ledger file: %v, %d entries\n%s", err, len(file.Entries), raw)
	}
	for _, en := range file.Entries {
		if len(en.RuleIDs) != 1 || !strings.HasPrefix(en.RuleIDs[0], rulebook.IntentPrefix) {
			t.Errorf("ledger entry ids %v", en.RuleIDs)
		}
	}
	led, err := claudesettings.LoadLedger(filepath.Join(e.state, "watchdeck"))
	if err != nil {
		t.Fatal(err)
	}
	owners := led.Owners(settingsPath, claudesettings.KeyDeny, "Read(~/.ssh/id_*)")
	if len(owners) != 1 || owners[0] != rulebook.IntentPrefix+rulebook.IntentID("Read(~/.ssh/id_*)") || !strings.HasPrefix(owners[0], rulebook.IntentPrefix) {
		t.Errorf("ledger intent = %v", owners)
	}
	code, out, _ = call(t, rulesCmd, "recommended", "--install", "--yes")
	if code != 0 || !strings.Contains(out, "nothing to do") {
		t.Errorf("second run: exit %d\n%s", code, out)
	}
	_, out, _ = call(t, rulesCmd, "recommended")
	if strings.Count(out, "installed") < 12 {
		t.Errorf("after install:\n%s", out)
	}
}

func TestRulesGrantAliasesAllow(t *testing.T) {
	e := rulesEnv(t)
	if code, out, errs := call(t, rulesCmd, "grant", "docx", "--network", "all"); code != 0 {
		t.Fatalf("exit %d\n%s%s", code, out, errs)
	}
	user, _, err := manifest.LoadOverrides(filepath.Join(e.cfg, "watchdeck"), "")
	if err != nil {
		t.Fatal(err)
	}
	if n := user.Skills["docx"].Network; n == nil || *n != manifest.NetAll {
		t.Errorf("docx not granted: %+v", user.Skills)
	}
}

func TestRulesUsageExit3(t *testing.T) {
	rulesEnv(t)
	for _, args := range [][]string{
		nil,
		{"bogus"},
		{"add"},
		{"add", "--block"},
		{"add", "--command", "curl"},
		{"add", "--block", "--ask", "--command", "curl"},
		{"add", "--block", "--command", "curl", "--domain", "x.test"},
		{"add", "--block", "--command"},
		{"add", "--block", "--command", "curl", "--frob"},
		{"remove"},
		{"remove", "a", "b"},
		{"list", "--frob"},
		{"recommended", "--frob"},
	} {
		code, out, errs := call(t, rulesCmd, args...)
		if code != 3 {
			t.Errorf("%q: exit %d, want 3\n%s%s", args, code, out, errs)
		}
		if !strings.Contains(errs, "usage:") {
			t.Errorf("%q: no usage on stderr:\n%s", args, errs)
		}
	}
	if code, out, _ := call(t, rulesCmd, "--help"); code != 0 || !strings.Contains(out, "usage:") {
		t.Errorf("--help: exit %d\n%s", code, out)
	}
	for _, args := range [][]string{{"resolve"}, {"resolve", "id"}, {"resolve", "id", "frob"}, {"frob"}} {
		if code, _, errs := call(t, inboxCmd, args...); code != 3 || !strings.Contains(errs, "usage:") {
			t.Errorf("inbox %q: exit %d\n%s", args, code, errs)
		}
	}
}

// TestRulesAddUserScopeInsideProject: a user-scope add run from inside a
// git project writes the user settings file only; the project's
// .claude/settings.json is never created.
func TestRulesAddUserScopeInsideProject(t *testing.T) {
	e := rulesEnv(t)
	if err := os.MkdirAll(filepath.Join(e.proj, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	settingsPath := filepath.Join(e.claude, "settings.json")
	writeFile(t, settingsPath, "{}\n")
	if code, out, errs := call(t, rulesCmd, "add", "--block", "--read", "secrets/key.txt", "--yes"); code != 0 {
		t.Fatalf("exit %d\n%s%s", code, out, errs)
	}
	if !has(settingsList(t, settingsPath, "deny"), "Read(./secrets/key.txt)") {
		t.Fatalf("user settings lack the rule")
	}
	for _, f := range []string{"settings.json", "settings.local.json"} {
		if _, err := os.Stat(filepath.Join(e.proj, ".claude", f)); err == nil {
			t.Errorf("a user-scope add created %s in the project", f)
		}
	}
}

// TestRulesAddFailureNotNothingChanged: when Apply fails, the output never
// claims "nothing changed: every rule was already there".
func TestRulesAddFailureNotNothingChanged(t *testing.T) {
	e := rulesEnv(t)
	settingsPath := filepath.Join(e.claude, "settings.json")
	writeFile(t, settingsPath, `{"permissions": {"deny": "not a list"}}`+"\n")
	code, out, errs := call(t, rulesCmd, "add", "--block", "--command", "curl", "--yes")
	if code != 2 {
		t.Fatalf("exit %d, want 2\n%s%s", code, out, errs)
	}
	if strings.Contains(out, "nothing changed") {
		t.Errorf("a failed apply says nothing changed:\n%s", out)
	}
	// A real no-op still says so.
	writeFile(t, settingsPath, `{"permissions": {"deny": ["Bash(curl *)"]}}`+"\n")
	if code, out, errs := call(t, rulesCmd, "add", "--block", "--command", "curl", "--yes"); code != 0 || !strings.Contains(out, "nothing changed: every rule was already there") {
		t.Errorf("no-op: exit %d\n%s%s", code, out, errs)
	}
}

// dropSetting removes value from permissions.<key> of a settings file, as a
// person editing it by hand would.
func dropSetting(t *testing.T, path, key, value string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	perms, _ := doc["permissions"].(map[string]any)
	list, _ := perms[key].([]any)
	kept := []any{}
	found := false
	for _, v := range list {
		if v == value {
			found = true
			continue
		}
		kept = append(kept, v)
	}
	if !found {
		t.Fatalf("%s not in %s of %s", value, key, path)
	}
	perms[key] = kept
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(out, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

// recommendedIn reports which recommended values a settings file holds.
func recommendedIn(t *testing.T, path string) map[string]bool {
	t.Helper()
	got := map[string]bool{}
	for _, key := range []string{"deny", "ask"} {
		for _, v := range settingsList(t, path, key) {
			got[v] = true
		}
	}
	return got
}

func TestRulesRecommendedDecline(t *testing.T) {
	e := rulesEnv(t)
	settingsPath := filepath.Join(e.claude, "settings.json")
	writeFile(t, settingsPath, "{}\n")
	stateDir := filepath.Join(e.state, paths.BinaryName)
	rec := rulebook.Recommended()
	a, b := rec[0], rec[3]

	code, out, errs := call(t, rulesCmd, "recommended", "--decline", a.ID, b.ID)
	if code != 0 || out != "declined "+a.ID+"\ndeclined "+b.ID+"\n" {
		t.Fatalf("decline: exit %d\n%s%s", code, out, errs)
	}
	d, err := rulebook.LoadDeclined(stateDir)
	if err != nil || len(d.IntentIDs) != 2 || !d.Has(rulebook.IntentPrefix+rulebook.IntentID(a.Value)) || !d.Has(rulebook.IntentPrefix+rulebook.IntentID(b.Value)) {
		t.Fatalf("declined file %+v, %v", d, err)
	}
	if code, out, _ := call(t, rulesCmd, "recommended", "--decline", a.ID); code != 0 || out != "nothing to change\n" {
		t.Errorf("second decline: exit %d\n%s", code, out)
	}

	// the listing shows the two as declined, the rest missing
	_, out, _ = call(t, rulesCmd, "recommended")
	for _, r := range []rulebook.Rule{a, b} {
		if want := "  declined   " + r.ID + "  "; !strings.Contains(out, want) {
			t.Errorf("listing lacks %q:\n%s", want, out)
		}
	}
	if strings.Count(out, "  missing    ") != 10 || !strings.Contains(out, "10 not installed") || !strings.Contains(out, "2 declined: ") {
		t.Errorf("listing:\n%s", out)
	}

	// --install skips the declined two
	code, out, errs = call(t, rulesCmd, "recommended", "--install", "--yes")
	if code != 0 || !strings.Contains(out, "skipping 2 declined recommended rules") {
		t.Fatalf("install: exit %d\n%s%s", code, out, errs)
	}
	got := recommendedIn(t, settingsPath)
	if len(got) != 10 || got[a.Value] || got[b.Value] {
		t.Fatalf("after --install: %v", got)
	}
	if code, out, _ := call(t, rulesCmd, "recommended", "--install", "--yes"); code != 0 || !strings.Contains(out, "nothing to do: every missing recommended rule was declined") {
		t.Errorf("install again: exit %d\n%s", code, out)
	}

	// --install --all installs them, and an install takes them off the list
	code, out, errs = call(t, rulesCmd, "recommended", "--install", "--all", "--yes")
	if code != 0 {
		t.Fatalf("install --all: exit %d\n%s%s", code, out, errs)
	}
	if got := recommendedIn(t, settingsPath); len(got) != 12 {
		t.Fatalf("after --install --all: %v", got)
	}
	if d, _ := rulebook.LoadDeclined(stateDir); len(d.IntentIDs) != 0 {
		t.Errorf("installed rules still declined: %v", d.IntentIDs)
	}
	// nothing is missing, so all declines nothing
	if code, out, _ := call(t, rulesCmd, "recommended", "--decline", "all"); code != 0 || out != "nothing to change\n" {
		t.Errorf("decline all with nothing missing: exit %d\n%s", code, out)
	}

	// usage and unknown ids
	for _, args := range [][]string{
		{"recommended", "--decline"},
		{"recommended", "--all"},
		{"recommended", "--install", "--decline", a.ID},
		{"recommended", "--decline", a.ID, "--undecline", b.ID},
		{"recommended", a.ID},
	} {
		if code, _, _ := call(t, rulesCmd, args...); code != 3 {
			t.Errorf("%v: exit %d, want 3", args, code)
		}
	}
	if code, _, errs := call(t, rulesCmd, "recommended", "--decline", "native:user:permissions.deny:00000000"); code != 2 || !strings.Contains(errs, "no recommended rule") {
		t.Errorf("unknown id: exit %d\n%s", code, errs)
	}
}

func TestRulesRecommendedUndecline(t *testing.T) {
	e := rulesEnv(t)
	writeFile(t, filepath.Join(e.claude, "settings.json"), "{}\n")
	rec := rulebook.Recommended()
	code, out, _ := call(t, rulesCmd, "recommended", "--decline", "all")
	if code != 0 || strings.Count(out, "declined ") != 12 {
		t.Fatalf("decline all: exit %d\n%s", code, out)
	}
	code, out, _ = call(t, rulesCmd, "recommended", "--undecline", rec[1].ID)
	if code != 0 || out != "undeclined "+rec[1].ID+"\n" {
		t.Fatalf("undecline one: exit %d\n%s", code, out)
	}
	code, out, _ = call(t, rulesCmd, "recommended", "--undecline", "all")
	if code != 0 || strings.Count(out, "undeclined ") != 11 || strings.Contains(out, rec[1].ID) {
		t.Fatalf("undecline all: exit %d\n%s", code, out)
	}
	if code, out, _ := call(t, rulesCmd, "recommended", "--undecline", "all"); code != 0 || out != "nothing to change\n" {
		t.Errorf("undecline all again: exit %d\n%s", code, out)
	}
}

func TestRulesSetPackRule(t *testing.T) {
	e := rulesEnv(t)
	settingsPath := filepath.Join(e.claude, "settings.json")
	writeFile(t, settingsPath, `{"permissions": {"deny": ["Read(./mine)"]}}`+"\n")
	packs := rules.Packs()
	if len(packs) == 0 || len(packs[0].Rules) == 0 {
		t.Fatalf("no built-in packs: %v", rules.LoadError())
	}
	key := packs[0].Name + "/" + packs[0].Rules[0].ID
	overrides := filepath.Join(e.cfg, paths.BinaryName, "overrides.yaml")
	enabled := func() *bool {
		t.Helper()
		f, _, err := policy.LoadFile(overrides)
		if err != nil {
			t.Fatal(err)
		}
		return f.RuleOverrides[key].Enabled
	}

	// no terminal, no --yes: nothing written
	if code, out, _ := call(t, rulesCmd, "set", "pack:"+key, "off"); code != 1 || !strings.Contains(out, "Not applied") {
		t.Fatalf("no tty: exit %d\n%s", code, out)
	}
	if _, err := os.Stat(overrides); err == nil {
		t.Fatal("no tty but the overrides file was written")
	}
	code, out, errs := call(t, rulesCmd, "set", "pack:"+key, "off", "--yes")
	if code != 0 || !strings.Contains(out, "switched off pack:"+key+"\n") {
		t.Fatalf("off: exit %d\n%s%s", code, out, errs)
	}
	if on := enabled(); on == nil || *on {
		t.Fatalf("enabled = %v, want false", on)
	}
	code, out, errs = call(t, rulesCmd, "set", "pack:"+key, "on", "--yes")
	if code != 0 || !strings.Contains(out, "switched on pack:"+key+"\n") {
		t.Fatalf("on: exit %d\n%s%s", code, out, errs)
	}
	if on := enabled(); on == nil || !*on {
		t.Fatalf("enabled = %v, want true", on)
	}

	// a settings string is refused with SetEnabled's sentence, nothing asked or written
	native := rulebook.RowID(rulebook.KindNativeDeny, claudesettings.ScopeUser, claudesettings.KeyDeny, "Read(./mine)")
	code, out, errs = call(t, rulesCmd, "set", native, "off", "--yes")
	if code != 2 || errs != paths.BinaryName+" rules: "+native+" is not a built-in "+paths.BinaryName+" rule; remove the rule instead\n" || strings.Contains(out, "Apply?") {
		t.Errorf("native row: exit %d\n%s%s", code, out, errs)
	}
	if len(backups(t, settingsPath)) != 0 || !has(settingsList(t, settingsPath, "deny"), "Read(./mine)") {
		t.Error("a refused set touched the settings")
	}
	for _, args := range [][]string{{"set", "pack:" + key}, {"set", "pack:" + key, "maybe"}, {"set", "pack:" + key, "on", "--now"}} {
		if code, _, _ := call(t, rulesCmd, args...); code != 3 {
			t.Errorf("%v: exit %d, want 3", args, code)
		}
	}
	if code, _, _ := call(t, rulesCmd, "set", "pack:no/such-rule", "on", "--yes"); code != 2 {
		t.Errorf("unknown rule: exit %d, want 2", code)
	}
}

func TestRulesReconcilePrints(t *testing.T) {
	e := rulesEnv(t)
	settingsPath := filepath.Join(e.claude, "settings.json")
	writeFile(t, settingsPath, "{}\n")
	if code, out, errs := call(t, rulesCmd, "recommended", "--install", "--yes"); code != 0 {
		t.Fatalf("install: exit %d\n%s%s", code, out, errs)
	}
	if code, out, _ := call(t, rulesCmd, "reconcile"); code != 0 || out != "nothing to reconcile\n" {
		t.Fatalf("clean reconcile: exit %d\n%s", code, out)
	}
	dropSetting(t, settingsPath, "deny", "Read(~/.netrc)")
	code, out, errs := call(t, rulesCmd, "reconcile")
	row := rulebook.RowID(rulebook.KindNativeDeny, claudesettings.ScopeUser, claudesettings.KeyDeny, "Read(~/.netrc)")
	want := "forgot Read(~/.netrc) in " + displayHome(settingsPath, e.home) + " permissions.deny (removed by you)\ndeclined " + row + "\n"
	if code != 0 || out != want {
		t.Fatalf("reconcile: exit %d\n got %q\nwant %q\n%s", code, out, want, errs)
	}
	if led := ledgerOf(t, e); len(led.Entries) != 11 {
		t.Errorf("ledger has %d entries, want 11", len(led.Entries))
	}
	_, out, _ = call(t, rulesCmd, "recommended")
	if !strings.Contains(out, "  declined   "+row+"  ") {
		t.Errorf("listing does not show the hand-removed rule declined:\n%s", out)
	}
	if code, out, _ := call(t, rulesCmd, "reconcile"); code != 0 || out != "nothing to reconcile\n" {
		t.Errorf("second reconcile: exit %d\n%s", code, out)
	}
	if code, _, _ := call(t, rulesCmd, "reconcile", "--now"); code != 3 {
		t.Errorf("reconcile with an argument: exit %d, want 3", code)
	}
}

// TestRecommendedInstallWarnsOnCorruptDeclined: with a declined list that
// cannot be read every missing rule is offered, so rules recommended
// --install and setup --yes say so on stderr and still install; a
// --decline replaces the file and says it did.
func TestRecommendedInstallWarnsOnCorruptDeclined(t *testing.T) {
	const warning = "warning: rulebook: "
	corrupt := func(t *testing.T, e testEnv) {
		writeFile(t, filepath.Join(e.state, paths.BinaryName, rulebook.DeclinedFile), "{not json")
	}
	t.Run("install", func(t *testing.T) {
		e := rulesEnv(t)
		settingsPath := filepath.Join(e.claude, "settings.json")
		writeFile(t, settingsPath, "{}\n")
		corrupt(t, e)
		code, out, errs := call(t, rulesCmd, "recommended", "--install", "--yes")
		if code != 0 || !strings.HasPrefix(errs, warning) || !strings.Contains(errs, "delete it to start the declined list over; every missing recommended rule is offered\n") {
			t.Fatalf("exit %d\nstdout %s\nstderr %s", code, out, errs)
		}
		if got := recommendedIn(t, settingsPath); len(got) != 12 {
			t.Fatalf("installed %d rules", len(got))
		}
	})
	t.Run("setup", func(t *testing.T) {
		e := rulesEnv(t)
		passSelfTest(t)
		settingsPath := filepath.Join(e.claude, "settings.json")
		writeFile(t, settingsPath, "{}\n")
		corrupt(t, e)
		var out, errb bytes.Buffer
		c := &console{in: bufio.NewReader(strings.NewReader("")), out: &out, errw: &errb, assume: true}
		if code := runSetup(c, setupOptions{}); code != 0 {
			t.Fatalf("exit %d\n%s%s", code, out.String(), errb.String())
		}
		if !strings.HasPrefix(errb.String(), "   "+warning) {
			t.Errorf("setup stderr lacks the warning:\n%s", errb.String())
		}
		if got := recommendedIn(t, settingsPath); len(got) != 12 {
			t.Fatalf("installed %d rules", len(got))
		}
	})
	t.Run("decline", func(t *testing.T) {
		e := rulesEnv(t)
		writeFile(t, filepath.Join(e.claude, "settings.json"), "{}\n")
		corrupt(t, e)
		id := rulebook.Recommended()[0].ID
		code, out, errs := call(t, rulesCmd, "recommended", "--decline", id)
		if code != 0 || !strings.HasPrefix(errs, warning) || out != "replaced the unreadable declined list\ndeclined "+id+"\n" {
			t.Fatalf("exit %d\nstdout %q\nstderr %s", code, out, errs)
		}
		if d, err := rulebook.LoadDeclined(filepath.Join(e.state, paths.BinaryName)); err != nil || len(d.IntentIDs) != 1 {
			t.Fatalf("declined %v, %v", d.IntentIDs, err)
		}
	})
}

// planStepLines counts the step lines of a printed plan.
func planStepLines(out string) int {
	n := 0
	for _, l := range strings.Split(out, "\n") {
		for _, m := range []string{rulebook.MechNative, rulebook.MechHook, rulebook.MechSubject} {
			if strings.HasPrefix(l, "  "+m+" ") {
				n++
			}
		}
	}
	return n
}

// sandboxDenied reads sandbox.network.deniedDomains from a settings file.
func sandboxDenied(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Sandbox struct {
			Network struct {
				DeniedDomains []string `json:"deniedDomains"`
			} `json:"network"`
		} `json:"sandbox"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Sandbox.Network.DeniedDomains
}

func hostIntent() string {
	return rulebook.IntentFor(rulebook.AddRequest{What: rulebook.WhatHost, Value: "fake-example.test", Everywhere: true})
}

func TestRulesAddEverywhereHost(t *testing.T) {
	e := rulesEnv(t)
	settingsPath := filepath.Join(e.claude, "settings.json")
	writeFile(t, settingsPath, "{}\n")
	code, out, errs := call(t, rulesCmd, "add", "--block", "--domain", "fake-example.test", "--everywhere")
	if code != 1 {
		t.Fatalf("exit %d, want 1\n%s%s", code, out, errs)
	}
	if n := planStepLines(out); n != 4 {
		t.Errorf("plan lists %d steps, want 4:\n%s", n, out)
	}
	for _, want := range []string{"WebFetch(domain:fake-example.test)", "sandbox.network.deniedDomains", "subjects", "rules", hostIntent()} {
		if !strings.Contains(out, want) {
			t.Errorf("plan lacks %q:\n%s", want, out)
		}
	}
	if b, _ := os.ReadFile(settingsPath); string(b) != "{}\n" {
		t.Errorf("settings changed: %s", b)
	}
	code, out, errs = call(t, rulesCmd, "add", "--block", "--domain", "fake-example.test", "--everywhere", "--yes")
	if code != 0 {
		t.Fatalf("--yes exit %d\n%s%s", code, out, errs)
	}
	if !has(settingsList(t, settingsPath, "deny"), "WebFetch(domain:fake-example.test)") {
		t.Error("WebFetch rule not written")
	}
	if !has(sandboxDenied(t, settingsPath), "fake-example.test") {
		t.Error("deniedDomains not written")
	}
	// A kind with no everywhere form is refused, value-free.
	code, _, errs = call(t, rulesCmd, "add", "--block", "--regex", "fake-secret", "--everywhere", "--yes")
	if code != 2 || strings.Contains(errs, "fake-secret") {
		t.Errorf("regex --everywhere: exit %d\n%s", code, errs)
	}
}

func TestRulesRemoveIntentAsksAndRemovesAll(t *testing.T) {
	e := rulesEnv(t)
	settingsPath := filepath.Join(e.claude, "settings.json")
	writeFile(t, settingsPath, "{}\n")
	if code, out, errs := call(t, rulesCmd, "add", "--block", "--domain", "fake-example.test", "--everywhere", "--yes"); code != 0 {
		t.Fatalf("add exit %d\n%s%s", code, out, errs)
	}
	before, _ := os.ReadFile(settingsPath)
	code, out, errs := call(t, rulesCmd, "remove", "--intent", hostIntent())
	if code != 1 {
		t.Fatalf("no terminal: exit %d, want 1\n%s%s", code, out, errs)
	}
	if n := strings.Count(out, "\n  "); n != 4 {
		t.Errorf("listed %d rows, want 4:\n%s", n, out)
	}
	if after, _ := os.ReadFile(settingsPath); string(after) != string(before) {
		t.Error("settings changed without a confirm")
	}
	code, out, errs = call(t, rulesCmd, "remove", "--intent", hostIntent(), "--yes")
	if code != 0 {
		t.Fatalf("--yes exit %d\n%s%s", code, out, errs)
	}
	if strings.Count(out, "removed ") != 4 {
		t.Errorf("output does not name 4 removed rows:\n%s", out)
	}
	if len(settingsList(t, settingsPath, "deny")) != 0 || len(sandboxDenied(t, settingsPath)) != 0 {
		t.Errorf("settings still hold the intent: %s", readFileStr(t, settingsPath))
	}
	f, _, err := policy.LoadFile(filepath.Join(e.cfg, paths.BinaryName, "overrides.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Rules)+len(f.Subjects) != 0 {
		t.Errorf("overrides still hold %d rules, %d subjects", len(f.Rules), len(f.Subjects))
	}
	// Nothing left: exit 2.
	if code, _, _ := call(t, rulesCmd, "remove", "--intent", hostIntent(), "--yes"); code != 2 {
		t.Errorf("second remove --intent: exit %d, want 2", code)
	}
	// --intent needs an id; it takes no row id beside it.
	if code, _, _ := call(t, rulesCmd, "remove", "--intent"); code != 3 {
		t.Errorf("--intent without id: exit %d, want 3", code)
	}
	if code, _, _ := call(t, rulesCmd, "remove", "--intent", hostIntent(), "native:user:permissions.deny:00000000"); code != 3 {
		t.Errorf("--intent with a row id: exit %d, want 3", code)
	}
}

func TestRulesRemoveRowStaysOneRow(t *testing.T) {
	e := rulesEnv(t)
	settingsPath := filepath.Join(e.claude, "settings.json")
	writeFile(t, settingsPath, "{}\n")
	if code, out, errs := call(t, rulesCmd, "add", "--block", "--domain", "fake-example.test", "--everywhere", "--yes"); code != 0 {
		t.Fatalf("add exit %d\n%s%s", code, out, errs)
	}
	id := rulebook.RowID(rulebook.KindNativeDeny, claudesettings.ScopeUser, claudesettings.KeyDeny, "WebFetch(domain:fake-example.test)")
	code, out, errs := call(t, rulesCmd, "remove", id, "--yes")
	if code != 0 {
		t.Fatalf("remove exit %d\n%s%s", code, out, errs)
	}
	if has(settingsList(t, settingsPath, "deny"), "WebFetch(domain:fake-example.test)") {
		t.Error("the row was not removed")
	}
	if !has(sandboxDenied(t, settingsPath), "fake-example.test") {
		t.Error("the rest of the intent went with one row")
	}
	f, _, err := policy.LoadFile(filepath.Join(e.cfg, paths.BinaryName, "overrides.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Rules) != 1 || len(f.Subjects) != 1 {
		t.Errorf("overrides hold %d rules, %d subjects; want 1 and 1", len(f.Rules), len(f.Subjects))
	}
}

func readFileStr(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestRulesAddPathIntentWarnsAboutSearchHook(t *testing.T) {
	e := rulesEnv(t)
	writeFile(t, filepath.Join(e.claude, "settings.json"), "{}\n")
	code, out, errs := call(t, rulesCmd, "add", "--block", "--path", "~/.fake-env", "--everywhere", "--yes")
	if code != 0 {
		t.Fatalf("exit %d\n%s%s", code, out, errs)
	}
	if !strings.Contains(out, "Grep and Glob") || !strings.Contains(out, paths.BinaryName+" enforce install") {
		t.Errorf("output lacks the search warning:\n%s", out)
	}
	code, out, _ = call(t, rulesCmd, "add", "--block", "--command", "fake-tool", "--yes")
	if code != 0 || strings.Contains(out, "Grep and Glob") {
		t.Errorf("a plain command rule warns: exit %d\n%s", code, out)
	}
}
