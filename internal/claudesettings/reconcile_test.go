package claudesettings

import (
	"errors"
	"reflect"
	"testing"
)

func TestReconcileUserRemoval(t *testing.T) {
	kept := LedgerEntry{Path: "/fake/user.json", Key: "permissions.deny", Value: "Bash(rm *)", RuleID: "r1"}
	removed := LedgerEntry{Path: "/fake/user.json", Key: "permissions.ask", Value: "Bash(git push *)", RuleID: "r2"}
	unreadable := LedgerEntry{Path: "/fake/broken.json", Key: "permissions.deny", Value: "Bash(x)", RuleID: "r3"}
	elsewhere := LedgerEntry{Path: "/fake/other-project.json", Key: "permissions.deny", Value: "Bash(y)", RuleID: "r4"}
	deleted := LedgerEntry{Path: "/fake/deleted.json", Key: "sandbox.network.deniedDomains", Value: "example.com", RuleID: "r5"}
	led := &Ledger{V: 1, Entries: []LedgerEntry{kept, removed, unreadable, elsewhere, deleted}}

	eff := Effective{
		Files: []FileState{
			{Location: Location{Scope: ScopeUser, Path: "/fake/user.json"}, Exists: true},
			{Location: Location{Scope: ScopeProject, Path: "/fake/broken.json"}, Exists: true, Err: errors.New("parse error")},
			{Location: Location{Scope: ScopeLocal, Path: "/fake/deleted.json"}, Exists: false},
		},
		// The same string under another key does not keep the "ask" claim alive.
		Deny: []Entry{{Value: "Bash(rm *)", Scope: ScopeUser, Path: "/fake/user.json"}, {Value: "Bash(git push *)", Scope: ScopeUser, Path: "/fake/user.json", Index: 1}},
	}
	drifts := Reconcile(led, eff)
	if len(drifts) != 2 {
		t.Fatalf("drifts = %+v", drifts)
	}
	if !reflect.DeepEqual(drifts[0].Entry, removed) || drifts[0].Reason != "removed by user" {
		t.Fatalf("drift 0 = %+v", drifts[0])
	}
	if !reflect.DeepEqual(drifts[1].Entry, deleted) || drifts[1].Reason != "removed by user" {
		t.Fatalf("drift 1 = %+v", drifts[1])
	}
	want := []LedgerEntry{kept, unreadable, elsewhere}
	if len(led.Entries) != len(want) {
		t.Fatalf("ledger after = %+v", led.Entries)
	}
	for i := range want {
		if !reflect.DeepEqual(led.Entries[i], want[i]) {
			t.Fatalf("ledger[%d] = %+v, want %+v", i, led.Entries[i], want[i])
		}
	}
	// A second pass finds nothing new.
	if d := Reconcile(led, eff); len(d) != 0 {
		t.Fatalf("second pass = %+v", d)
	}
}
