package claudesettings

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestManageIdempotentAndUnclaimed(t *testing.T) {
	p := tempPaths(t)
	loc := userLoc(p)
	copyFixture(t, "owner-like.json", loc.Path) // permissions.allow has "Bash(git status *)"
	orig := readString(t, loc.Path)
	led := &Ledger{V: 1}

	// The person already has this string: no write, not claimed.
	ch, err := Manage(loc, led, "permissions.allow", []string{"Bash(git status *)"}, nil, "r1")
	if err != nil {
		t.Fatal(err)
	}
	if len(ch.Added) != 0 || ch.Backup != "" || len(led.Entries) != 0 || readString(t, loc.Path) != orig {
		t.Fatalf("existing add: change %+v ledger %+v", ch, led.Entries)
	}
	// TestManageAddExistingUserStringNotClaimed: a second rule id adding the
	// person's string does not claim it either.
	ch, err = Manage(loc, led, "permissions.allow", []string{"Bash(git status *)"}, nil, "r1b")
	if err != nil {
		t.Fatal(err)
	}
	if len(ch.Added) != 0 || ch.Backup != "" || len(led.Entries) != 0 || readString(t, loc.Path) != orig {
		t.Fatalf("existing add, second rule: change %+v ledger %+v", ch, led.Entries)
	}
	if got := led.Owners(loc.Path, "permissions.allow", "Bash(git status *)"); got != nil {
		t.Fatalf("the person's string has owners %v", got)
	}

	// A new string: written, backed up, claimed with the rule id.
	ch, err = Manage(loc, led, "permissions.deny", []string{"Bash(rm -rf *)"}, nil, "r2")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(ch.Added, []string{"Bash(rm -rf *)"}) || ch.Path != loc.Path || ch.Backup == "" {
		t.Fatalf("change %+v", ch)
	}
	if readString(t, ch.Backup) != orig {
		t.Fatal("backup does not hold the original bytes")
	}
	if len(led.Entries) != 1 {
		t.Fatalf("ledger %+v", led.Entries)
	}
	e := led.Entries[0]
	if e.Path != loc.Path || e.Key != "permissions.deny" || e.Value != "Bash(rm -rf *)" || !reflect.DeepEqual(e.RuleIDs, []string{"r2"}) || e.Added.IsZero() {
		t.Fatalf("ledger entry %+v", e)
	}
	after := readString(t, loc.Path)

	// Again: a no-op, the claim is not duplicated, no backup.
	ch, err = Manage(loc, led, "permissions.deny", []string{"Bash(rm -rf *)", "Bash(rm -rf *)"}, nil, "r2")
	if err != nil {
		t.Fatal(err)
	}
	if len(ch.Added) != 0 || ch.Backup != "" || len(led.Entries) != 1 || readString(t, loc.Path) != after {
		t.Fatalf("repeat: change %+v ledger %+v", ch, led.Entries)
	}

	// A stale claim (the person removed the string by hand, no Reconcile yet)
	// is replaced on re-add, never duplicated.
	led.Entries = append(led.Entries, LedgerEntry{Path: loc.Path, Key: "permissions.ask", Value: "Bash(git push *)", RuleIDs: []string{"old"}})
	if _, err := Manage(loc, led, "permissions.ask", []string{"Bash(git push *)"}, nil, "r4"); err != nil {
		t.Fatal(err)
	}
	claims := 0
	for _, e := range led.Entries {
		if e.Key == "permissions.ask" && e.Value == "Bash(git push *)" {
			claims++
			if !reflect.DeepEqual(e.RuleIDs, []string{"r4"}) {
				t.Fatalf("re-added claim kept rule ids %q", e.RuleIDs)
			}
		}
	}
	if claims != 1 {
		t.Fatalf("claims after re-add = %d, want 1: %+v", claims, led.Entries)
	}
	led.Entries = led.Entries[:1]

	// A missing user file is created.
	p2 := tempPaths(t)
	loc2 := userLoc(p2)
	ch, err = Manage(loc2, led, "sandbox.network.allowedDomains", []string{"example.com"}, nil, "r3")
	if err != nil || len(ch.Added) != 1 {
		t.Fatalf("new file: %+v %v", ch, err)
	}
	want := "{\n  \"sandbox\": {\n    \"network\": {\n      \"allowedDomains\": [\n        \"example.com\"\n      ]\n    }\n  }\n}\n"
	if got := readString(t, loc2.Path); got != want {
		t.Fatalf("new file = %q", got)
	}
}

func TestManageRemovesOnlyOwned(t *testing.T) {
	p := tempPaths(t)
	loc := userLoc(p)
	writeFile(t, loc.Path, "{\n  \"permissions\": {\n    \"deny\": [\n      \"Bash(curl *)\"\n    ]\n  }\n}\n")
	led := &Ledger{V: 1}
	if _, err := Manage(loc, led, "permissions.deny", []string{"Bash(rm *)"}, nil, "r1"); err != nil {
		t.Fatal(err)
	}
	// A claim whose string the person already removed by hand.
	led.Entries = append(led.Entries, LedgerEntry{Path: loc.Path, Key: "permissions.deny", Value: "Bash(gone *)", RuleIDs: []string{"r1"}})

	ch, err := Manage(loc, led, "permissions.deny", nil, []string{"Bash(curl *)", "Bash(rm *)", "Bash(gone *)"}, "r1")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(ch.Removed, []string{"Bash(rm *)"}) {
		t.Fatalf("Removed = %v, want only the owned string", ch.Removed)
	}
	if got := readString(t, loc.Path); got != "{\n  \"permissions\": {\n    \"deny\": [\n      \"Bash(curl *)\"\n    ]\n  }\n}\n" {
		t.Fatalf("file = %q", got)
	}
	if len(led.Entries) != 0 {
		t.Fatalf("ledger = %+v, want both claims dropped", led.Entries)
	}

	// $defaults and empty strings are refused either way.
	for _, bad := range [][2][]string{{{"$defaults"}, nil}, {nil, {"$defaults"}}, {{""}, nil}} {
		if _, err := Manage(loc, led, "permissions.deny", bad[0], bad[1], "r1"); err == nil {
			t.Fatalf("Manage(%v, %v): want error", bad[0], bad[1])
		}
	}
}

func TestManageRefusesManaged(t *testing.T) {
	dir := t.TempDir()
	loc := Location{Scope: ScopeManaged, Path: filepath.Join(dir, "managed-settings.json"), ReadOnly: true}
	led := &Ledger{V: 1}
	if _, err := Manage(loc, led, "permissions.deny", []string{"Bash(rm *)"}, nil, "r1"); err == nil {
		t.Fatal("Manage on a read-only location: want error")
	}
	if _, err := os.Stat(loc.Path); !os.IsNotExist(err) {
		t.Fatalf("managed file was created: %v", err)
	}
	if len(led.Entries) != 0 {
		t.Fatal("ledger changed")
	}
	// autoMode keys and unknown keys are refused too.
	p := tempPaths(t)
	for _, k := range []string{"autoMode.hard_deny", "permissions.defaultMode", "hooks"} {
		if _, err := Manage(userLoc(p), led, k, []string{"x"}, nil, "r1"); err == nil {
			t.Fatalf("key %s: want error", k)
		}
	}
	if _, err := os.Stat(userLoc(p).Path); !os.IsNotExist(err) {
		t.Fatal("refused key still created the user file")
	}
}

func TestManageRetriesOnDrift(t *testing.T) {
	p := tempPaths(t)
	loc := userLoc(p)
	writeFile(t, loc.Path, "{\n  \"model\": \"opus\"\n}\n")
	external := "{\n  \"model\": \"opus\",\n  \"permissions\": {\n    \"deny\": [\n      \"Bash(other *)\"\n    ]\n  }\n}\n"
	calls := 0
	beforeSave = func(path string) {
		calls++
		if calls == 1 { // Claude Code (or the person) writes between our load and save
			writeFile(t, path, external)
		}
	}
	t.Cleanup(func() { beforeSave = nil })

	led := &Ledger{V: 1}
	ch, err := Manage(loc, led, "permissions.deny", []string{"Bash(rm *)"}, nil, "r1")
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("beforeSave calls = %d, want 2 (one retry)", calls)
	}
	want := "{\n  \"model\": \"opus\",\n  \"permissions\": {\n    \"deny\": [\n      \"Bash(other *)\",\n      \"Bash(rm *)\"\n    ]\n  }\n}\n"
	if got := readString(t, loc.Path); got != want {
		t.Fatalf("file = %q, want the external write kept", got)
	}
	if len(ch.Added) != 1 || len(led.Entries) != 1 {
		t.Fatalf("change %+v ledger %+v", ch, led.Entries)
	}

	// Drift on every attempt: give up with an error, leave the other writer's bytes, claim nothing.
	n := 0
	beforeSave = func(path string) {
		n++
		writeFile(t, path, strings.Replace(external, "other", "other"+strings.Repeat("x", n), 1))
	}
	led2 := &Ledger{V: 1}
	if _, err := Manage(loc, led2, "permissions.deny", []string{"Bash(new *)"}, nil, "r2"); err == nil {
		t.Fatal("persistent drift: want error")
	}
	if n != 2 || len(led2.Entries) != 0 || strings.Contains(readString(t, loc.Path), "Bash(new *)") {
		t.Fatalf("persistent drift: calls %d ledger %+v", n, led2.Entries)
	}
}

// TestManageLeavesUnrelatedBytesIdentical is Review Focus 5: a user file
// with "$defaults" in autoMode arrays and permissions keys we do not manage.
// Adding then removing one deny entry changes only that one line.
func TestManageLeavesUnrelatedBytesIdentical(t *testing.T) {
	const orig = `{
  "env": {
    "EXAMPLE_FLAG": "1"
  },
  "permissions": {
    "allow": [
      "Bash(a && b)",
      "Read(<fake>/notes.txt)"
    ],
    "deny": [
      "Bash(curl *)"
    ],
    "defaultMode": "acceptEdits",
    "additionalDirectories": [
      "/Users/you/other"
    ]
  },
  "autoMode": {
    "hard_deny": [
      "$defaults",
      "Never run a shell command whose text contains the word fake-marker"
    ],
    "soft_deny": [
      "Ask before deleting files",
      "$defaults"
    ]
  },
  "model": "opus",
  "cleanupPeriodDays": 30,
  "unicode": "café"
}
`
	p := tempPaths(t)
	loc := userLoc(p)
	writeFile(t, loc.Path, orig)
	led := &Ledger{V: 1}
	if _, err := Manage(loc, led, "permissions.deny", []string{"Bash(rm *)"}, nil, "r1"); err != nil {
		t.Fatal(err)
	}
	wantAdded := strings.Replace(orig, "      \"Bash(curl *)\"\n", "      \"Bash(curl *)\",\n      \"Bash(rm *)\"\n", 1)
	if got := readString(t, loc.Path); got != wantAdded {
		t.Fatalf("after add:\n%s\nwant:\n%s", got, wantAdded)
	}
	if _, err := Manage(loc, led, "permissions.deny", nil, []string{"Bash(rm *)"}, "r1"); err != nil {
		t.Fatal(err)
	}
	if got := readString(t, loc.Path); got != orig {
		t.Fatalf("after remove, bytes differ from the original:\n%s", got)
	}
}

func TestManageSharedStringRefCounts(t *testing.T) {
	p := tempPaths(t)
	loc := userLoc(p)
	writeFile(t, loc.Path, "{\n  \"model\": \"opus\"\n}\n")
	led := &Ledger{V: 1}
	const x = "Bash(rm -rf *)"
	if ch, err := Manage(loc, led, KeyDeny, []string{x}, nil, "a"); err != nil || len(ch.Added) != 1 {
		t.Fatalf("add for a: %+v %v", ch, err)
	}
	afterA := readString(t, loc.Path)
	ch, err := Manage(loc, led, KeyDeny, []string{x}, nil, "b")
	if err != nil {
		t.Fatal(err)
	}
	if len(ch.Added) != 0 || ch.Backup != "" || readString(t, loc.Path) != afterA {
		t.Fatalf("add for b wrote the file: %+v", ch)
	}
	if strings.Count(readString(t, loc.Path), x) != 1 {
		t.Fatal("string written twice")
	}
	if len(led.Entries) != 1 || !reflect.DeepEqual(led.Entries[0].RuleIDs, []string{"a", "b"}) {
		t.Fatalf("ledger after b = %+v", led.Entries)
	}
	// b again: no duplicate claim.
	if _, err := Manage(loc, led, KeyDeny, []string{x}, nil, "b"); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(led.Entries[0].RuleIDs, []string{"a", "b"}) {
		t.Fatalf("repeat claim = %v", led.Entries[0].RuleIDs)
	}

	// a lets go: the string stays for b, the file is untouched.
	ch, err = Manage(loc, led, KeyDeny, nil, []string{x}, "a")
	if err != nil {
		t.Fatal(err)
	}
	if len(ch.Removed) != 0 || ch.Backup != "" || readString(t, loc.Path) != afterA {
		t.Fatalf("remove for a wrote the file: %+v", ch)
	}
	if len(led.Entries) != 1 || !reflect.DeepEqual(led.Entries[0].RuleIDs, []string{"b"}) {
		t.Fatalf("ledger after a lets go = %+v", led.Entries)
	}

	// b lets go: the last claim, so the string goes.
	ch, err = Manage(loc, led, KeyDeny, nil, []string{x}, "b")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(ch.Removed, []string{x}) || ch.Backup == "" || strings.Contains(readString(t, loc.Path), x) {
		t.Fatalf("remove for b: %+v\n%s", ch, readString(t, loc.Path))
	}
	if len(led.Entries) != 0 {
		t.Fatalf("ledger after the last claim = %+v", led.Entries)
	}
}

func TestManageRemoveUnknownRuleIsNoop(t *testing.T) {
	p := tempPaths(t)
	loc := userLoc(p)
	led := &Ledger{V: 1}
	const x = "Bash(rm *)"
	if _, err := Manage(loc, led, KeyDeny, []string{x}, nil, "a"); err != nil {
		t.Fatal(err)
	}
	before := readString(t, loc.Path)
	for _, id := range []string{"c", ""} {
		ch, err := Manage(loc, led, KeyDeny, nil, []string{x}, id)
		if err != nil {
			t.Fatal(err)
		}
		if len(ch.Removed) != 0 || ch.Backup != "" || readString(t, loc.Path) != before {
			t.Fatalf("remove for %q wrote: %+v", id, ch)
		}
		if len(led.Entries) != 1 || !reflect.DeepEqual(led.Entries[0].RuleIDs, []string{"a"}) {
			t.Fatalf("remove for %q changed the ledger: %+v", id, led.Entries)
		}
	}
}

// TestManageLeavesEmptyArray: removing the last owned string leaves the empty
// array and its parent object, which the person may have written.
func TestManageLeavesEmptyArray(t *testing.T) {
	p := tempPaths(t)
	loc := userLoc(p)
	writeFile(t, loc.Path, "{\n  \"model\": \"opus\"\n}\n")
	led := &Ledger{V: 1}
	if _, err := Manage(loc, led, KeyDeny, []string{"Bash(rm *)"}, nil, "a"); err != nil {
		t.Fatal(err)
	}
	if _, err := Manage(loc, led, KeyDeny, nil, []string{"Bash(rm *)"}, "a"); err != nil {
		t.Fatal(err)
	}
	want := "{\n  \"model\": \"opus\",\n  \"permissions\": {\n    \"deny\": []\n  }\n}\n"
	if got := readString(t, loc.Path); got != want {
		t.Fatalf("file = %q, want %q", got, want)
	}
}

// TestManageManyOneWrite: twelve adds under twelve rule ids are one load,
// apply and save: one backup, twelve ledger claims each with its own id,
// and the array in add order. A string added under two ids in the same
// call is appended once and claimed by both; removes release per id.
func TestManageManyOneWrite(t *testing.T) {
	p := tempPaths(t)
	loc := userLoc(p)
	writeFile(t, loc.Path, `{"permissions":{"deny":["Bash(keep *)"]}}`)
	orig := readString(t, loc.Path)
	led := &Ledger{V: 1}
	var adds []Claim
	var want []string
	for i := 0; i < 12; i++ {
		v := "Read(~/f" + string(rune('a'+i)) + ")"
		adds = append(adds, Claim{Value: v, RuleID: "id-" + string(rune('a'+i))})
		want = append(want, v)
	}
	adds = append(adds, Claim{Value: "Read(~/fa)", RuleID: "id-shared"})
	ch, err := ManageMany(loc, led, "permissions.deny", adds, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(ch.Added, want) || ch.Backup == "" {
		t.Fatalf("change %+v", ch)
	}
	baks, _ := filepath.Glob(loc.Path + ".bak-*")
	if len(baks) != 1 || readString(t, baks[0]) != orig {
		t.Fatalf("backups %v", baks)
	}
	eff, err := Read([]Location{loc}, led)
	if err != nil {
		t.Fatal(err)
	}
	if got := values(eff.Deny); !reflect.DeepEqual(got, append([]string{"Bash(keep *)"}, want...)) {
		t.Fatalf("array order %v", got)
	}
	if len(led.Entries) != 12 {
		t.Fatalf("ledger %d entries: %+v", len(led.Entries), led.Entries)
	}
	for i, e := range led.Entries {
		ids := []string{adds[i].RuleID}
		if i == 0 {
			ids = append(ids, "id-shared")
		}
		if e.Value != want[i] || !reflect.DeepEqual(e.RuleIDs, ids) {
			t.Fatalf("entry %d %+v, want ids %v", i, e, ids)
		}
	}
	// Remove: id-a releases its claim on fa (id-shared keeps it), id-b
	// drops fb (its only claim), an id that never claimed fc is a no-op.
	ch, err = ManageMany(loc, led, "permissions.deny", nil, []Claim{
		{Value: "Read(~/fa)", RuleID: "id-a"}, {Value: "Read(~/fb)", RuleID: "id-b"}, {Value: "Read(~/fc)", RuleID: "nobody"}})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(ch.Removed, []string{"Read(~/fb)"}) {
		t.Fatalf("removed %v", ch.Removed)
	}
	if got := led.Owners(loc.Path, "permissions.deny", "Read(~/fa)"); !reflect.DeepEqual(got, []string{"id-shared"}) {
		t.Fatalf("fa owners %v", got)
	}
	if led.Owners(loc.Path, "permissions.deny", "Read(~/fb)") != nil || led.Owners(loc.Path, "permissions.deny", "Read(~/fc)") == nil {
		t.Fatalf("ledger after remove %+v", led.Entries)
	}
	// An add with no rule id is refused, nothing written.
	if _, err := ManageMany(loc, led, "permissions.deny", []Claim{{Value: "Read(~/zz)"}}, nil); err == nil {
		t.Fatal("add without a rule id accepted")
	}
}

// TestManageKeysOneWriteAcrossKeys: deny and ask edits of one file are one
// write and one backup, each Change carrying it; a key twice is refused.
func TestManageKeysOneWriteAcrossKeys(t *testing.T) {
	p := tempPaths(t)
	loc := userLoc(p)
	writeFile(t, loc.Path, "{}\n")
	led := &Ledger{V: 1}
	chs, err := ManageKeys(loc, led, []KeyEdit{
		{Key: KeyDeny, Adds: []Claim{{Value: "Read(~/a)", RuleID: "x"}}},
		{Key: KeyAsk, Adds: []Claim{{Value: "Edit(~/b)", RuleID: "y"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	baks, _ := filepath.Glob(loc.Path + ".bak-*")
	if len(baks) != 1 || len(chs) != 2 || chs[0].Backup != baks[0] || chs[1].Backup != baks[0] {
		t.Fatalf("backups %v changes %+v", baks, chs)
	}
	if led.Owners(loc.Path, KeyDeny, "Read(~/a)") == nil || led.Owners(loc.Path, KeyAsk, "Edit(~/b)") == nil {
		t.Fatalf("ledger %+v", led.Entries)
	}
	if _, err := ManageKeys(loc, led, []KeyEdit{{Key: KeyDeny}, {Key: KeyDeny}}); err == nil {
		t.Fatal("duplicate key accepted")
	}
}

// TestManageKeysNoopLeavesBytes: in a multi-key call, an edit that changes
// nothing (removing a string nobody added from sandbox.network.allowedDomains)
// creates no parent object; only the real deny add lands.
func TestManageKeysNoopLeavesBytes(t *testing.T) {
	p := tempPaths(t)
	loc := userLoc(p)
	writeFile(t, loc.Path, "{\"model\": \"x\"}\n")
	led := &Ledger{V: 1}
	_, err := ManageKeys(loc, led, []KeyEdit{
		{Key: KeyAllowedDomains, Removes: []Claim{{Value: "example.test", RuleID: "x"}}},
		{Key: KeyDeny, Adds: []Claim{{Value: "Read(~/a)", RuleID: "y"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := readString(t, loc.Path)
	if strings.Contains(got, "sandbox") {
		t.Fatalf("a no-op edit created its parent object:\n%s", got)
	}
	if !strings.Contains(got, "Read(~/a)") {
		t.Fatalf("the deny add did not land:\n%s", got)
	}
	// A call whose every edit is a no-op leaves the file byte for byte.
	before := got
	if _, err := ManageKeys(loc, led, []KeyEdit{{Key: KeyAllowedDomains, Removes: []Claim{{Value: "nope.test", RuleID: "x"}}}}); err != nil {
		t.Fatal(err)
	}
	if after := readString(t, loc.Path); after != before {
		t.Fatalf("an all-no-op call changed the file:\n%s", after)
	}
}
