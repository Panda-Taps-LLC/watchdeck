package claudesettings

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestLedger0600(t *testing.T) {
	p := tempPaths(t)
	led, err := LoadLedger(p.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	if led.V != 1 || len(led.Entries) != 0 {
		t.Fatalf("empty ledger = %+v", led)
	}
	added := time.Date(2026, 10, 19, 1, 2, 3, 0, time.UTC)
	led.Entries = append(led.Entries, LedgerEntry{Path: "/Users/you/.claude/settings.json", Key: "permissions.deny", Value: "Bash(a && b)", RuleID: "r1", RuleIDs: []string{"r1"}, Added: added})
	if err := led.Save(p.StateDir); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(p.StateDir, LedgerFile)
	fi, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("ledger mode = %v, want 0600", fi.Mode().Perm())
	}
	raw := readString(t, file)
	for _, k := range []string{`"v": 1`, `"entries"`, `"path"`, `"key"`, `"value"`, `"rule_id"`, `"rule_ids"`, `"added"`, `Bash(a && b)`} {
		if !strings.Contains(raw, k) {
			t.Fatalf("ledger file lacks %s:\n%s", k, raw)
		}
	}
	got, err := LoadLedger(p.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Entries) != 1 || !reflect.DeepEqual(got.Entries[0], led.Entries[0]) {
		t.Fatalf("round trip = %+v", got.Entries)
	}
	// Saving over an existing ledger keeps 0600.
	if err := os.Chmod(file, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := got.Save(p.StateDir); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(file); fi.Mode().Perm() != 0o600 {
		t.Fatalf("re-saved mode = %v", fi.Mode().Perm())
	}
	// An unknown version is refused, never overwritten blindly.
	writeFile(t, file, `{"v": 2, "entries": []}`)
	if _, err := LoadLedger(p.StateDir); err == nil {
		t.Fatal("v2 ledger: want error")
	}
}

// TestLedgerMigratesRuleID: a v1 file written before rule_ids loads its one
// rule_id as RuleIDs, and saving writes both fields so an old reader still
// finds its rule_id.
func TestLedgerMigratesRuleID(t *testing.T) {
	p := tempPaths(t)
	file := filepath.Join(p.StateDir, LedgerFile)
	writeFile(t, file, `{"v": 1, "entries": [{"path": "/fake/settings.json", "key": "permissions.deny", "value": "Bash(rm *)", "rule_id": "a", "added": "2026-10-19T01:02:03Z"}, {"path": "/fake/settings.json", "key": "permissions.ask", "value": "Bash(x)", "added": "2026-10-19T01:02:03Z"}]}`)
	led, err := LoadLedger(p.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(led.Entries[0].RuleIDs, []string{"a"}) {
		t.Fatalf("RuleIDs = %#v, want [a]", led.Entries[0].RuleIDs)
	}
	if len(led.Entries[1].RuleIDs) != 0 {
		t.Fatalf("an entry with no rule_id migrated to %#v, want none", led.Entries[1].RuleIDs)
	}
	if got := led.Owners("/fake/settings.json", "permissions.deny", "Bash(rm *)"); !reflect.DeepEqual(got, []string{"a"}) {
		t.Fatalf("Owners = %v", got)
	}
	if got := led.Owners("/fake/settings.json", "permissions.deny", "Bash(nope)"); got != nil {
		t.Fatalf("Owners of an unowned string = %v, want nil", got)
	}
	// Two claims: rule_id stays the first one; the caller's entry is not rewritten.
	led.Entries[0].RuleIDs = []string{"b", "a"}
	led.Entries[0].RuleID = ""
	if err := led.Save(p.StateDir); err != nil {
		t.Fatal(err)
	}
	if led.Entries[0].RuleID != "" {
		t.Fatal("Save mutated the caller's ledger")
	}
	raw := readString(t, file)
	for _, want := range []string{`"rule_id": "b"`, `"rule_ids": [`, `"a"`} {
		if !strings.Contains(raw, want) {
			t.Fatalf("saved ledger lacks %s:\n%s", want, raw)
		}
	}
	got, err := LoadLedger(p.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Entries[0].RuleIDs, []string{"b", "a"}) || got.Entries[0].RuleID != "b" {
		t.Fatalf("reloaded entry %+v", got.Entries[0])
	}
	if strings.Contains(raw, "null") {
		t.Fatalf("an entry with no claims wrote null:\n%s", raw)
	}
	if strings.Count(raw, `"rule_id"`) != 1 {
		t.Fatalf("the unclaimed entry wrote an empty rule_id:\n%s", raw)
	}
}

// TestOwnersNilForOwnerlessEntry: a legacy entry with no rule_id and no
// rule_ids has no owner, so Owners is nil for it (rulebook.List shows the
// row as the person's and Remove refuses it, in agreement).
func TestOwnersNilForOwnerlessEntry(t *testing.T) {
	p := tempPaths(t)
	writeFile(t, filepath.Join(p.StateDir, LedgerFile), `{"v": 1, "entries": [{"path": "/fake/settings.json", "key": "permissions.ask", "value": "Bash(x)", "added": "2026-10-19T01:02:03Z"}]}`)
	led, err := LoadLedger(p.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	if got := led.Owners("/fake/settings.json", "permissions.ask", "Bash(x)"); got != nil {
		t.Fatalf("Owners of an ownerless entry = %#v, want nil", got)
	}
	// Built in memory with neither field set: the same.
	mem := &Ledger{V: 1, Entries: []LedgerEntry{{Path: "/fake/settings.json", Key: "permissions.deny", Value: "Bash(y)"}}}
	if got := mem.Owners("/fake/settings.json", "permissions.deny", "Bash(y)"); got != nil {
		t.Fatalf("Owners of an in-memory ownerless entry = %#v, want nil", got)
	}
}
