package rulebook

import (
	"encoding/json"
	"testing"

	"github.com/Panda-Taps-LLC/watchdeck/internal/claudesettings"
)

func TestReconcileDropsAndDeclines(t *testing.T) {
	in, user := applyEnv(t)
	rec := Recommended()[0]
	plan, err := RecommendedPlan(in, []Rule{rec})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(in, plan); err != nil {
		t.Fatal(err)
	}
	intent := IntentPrefix + IntentID(rec.Value)
	if led := loadLedger(t, in); len(led.Entries) != 1 || led.Entries[0].Value != rec.Value {
		t.Fatalf("ledger after install: %+v", led.Entries)
	}

	// The person deletes the string by hand.
	var doc map[string]any
	if err := json.Unmarshal(readBytes(t, user), &doc); err != nil {
		t.Fatal(err)
	}
	perms := doc["permissions"].(map[string]any)
	key := rec.Source.Key[len("permissions."):]
	var kept []any
	for _, v := range perms[key].([]any) {
		if v != rec.Value {
			kept = append(kept, v)
		}
	}
	perms[key] = kept
	b, _ := json.MarshalIndent(doc, "", "  ")
	writeFile(t, user, string(b))

	dropped, declined, err := Reconcile(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(dropped) != 1 || dropped[0].Entry.Value != rec.Value || dropped[0].Reason != claudesettings.ReasonRemovedByUser {
		t.Fatalf("dropped = %+v", dropped)
	}
	if len(declined) != 1 || declined[0] != intent {
		t.Fatalf("declined = %v", declined)
	}
	d, err := LoadDeclined(in.Paths.StateDir)
	if err != nil || !d.Has(intent) {
		t.Fatalf("declined file: %+v %v", d, err)
	}
	if led := loadLedger(t, in); len(led.Entries) != 0 {
		t.Fatalf("ledger still lists it: %+v", led.Entries)
	}
	// A second run has nothing to do.
	dropped, declined, err = Reconcile(in)
	if err != nil || len(dropped) != 0 || len(declined) != 0 {
		t.Fatalf("second run: %v %v %v", dropped, declined, err)
	}
	if offer := RecommendedOffer(in, []Rule{rec}, false); len(offer) != 0 {
		t.Fatalf("declined rule offered again: %+v", offer)
	}
}

// A hand-removed rule watchdeck added outside the recommended set is
// dropped from the ledger but not declined.
func TestReconcileNonRecommendedNotDeclined(t *testing.T) {
	in, user := applyEnv(t)
	if _, err := Apply(in, mustPropose(t, in, AddRequest{Action: "deny", What: WhatPath, Value: "~/.kube/config", Tool: PathRead})); err != nil {
		t.Fatal(err)
	}
	writeFile(t, user, seedSettings)
	dropped, declined, err := Reconcile(in)
	if err != nil || len(dropped) != 1 || len(declined) != 0 {
		t.Fatalf("%+v %v %v", dropped, declined, err)
	}
}
