package rulebook

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestDeclinedRoundTrip0600(t *testing.T) {
	p := testEnv(t)
	d, err := LoadDeclined(p.StateDir)
	if err != nil || len(d.IntentIDs) != 0 || d.Has("recommended:x") {
		t.Fatalf("missing file: %+v %v", d, err)
	}
	a, b := IntentPrefix+"read--netrc-", IntentPrefix+"read--aws-credentials-"
	if err := Decline(p.StateDir, []string{a, b, a}); err != nil {
		t.Fatal(err)
	}
	if err := Decline(p.StateDir, []string{b}); err != nil { // idempotent
		t.Fatal(err)
	}
	path := filepath.Join(p.StateDir, DeclinedFile)
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v, want 0600", fi.Mode().Perm())
	}
	d, err = LoadDeclined(p.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	if d.V != 1 || !reflect.DeepEqual(d.IntentIDs, []string{b, a}) || !d.Has(a) || !d.Has(b) {
		t.Fatalf("after decline: %+v", d)
	}
	if err := Undecline(p.StateDir, []string{a, "recommended:never-declined"}); err != nil {
		t.Fatal(err)
	}
	d, _ = LoadDeclined(p.StateDir)
	if !reflect.DeepEqual(d.IntentIDs, []string{b}) || d.Has(a) {
		t.Fatalf("after undecline: %+v", d)
	}
	// No temp files are left beside it.
	left, _ := filepath.Glob(filepath.Join(p.StateDir, ".declined-*"))
	if len(left) != 0 {
		t.Fatalf("temp files left: %v", left)
	}
	// A symlink at the path is not followed.
	dir := t.TempDir()
	q := testEnv(t)
	if err := os.MkdirAll(q.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "target.json"), filepath.Join(q.StateDir, DeclinedFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDeclined(q.StateDir); err == nil {
		t.Error("LoadDeclined followed a symlink")
	}
}

func TestListMarksDeclined(t *testing.T) {
	in, _ := applyEnv(t)
	rec := Recommended()
	if err := Decline(in.Paths.StateDir, []string{IntentPrefix + IntentID(rec[0].Value)}); err != nil {
		t.Fatal(err)
	}
	b, err := List(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Recommended) != len(rec) {
		t.Fatalf("%d recommended, want %d", len(b.Recommended), len(rec))
	}
	for _, r := range b.Recommended {
		if want := r.Value == rec[0].Value; r.Declined != want {
			t.Errorf("%s: declined %v, want %v", r.Value, r.Declined, want)
		}
	}
	// An unreadable declined file is a warning, never an error.
	writeFile(t, filepath.Join(in.Paths.StateDir, DeclinedFile), "{not json")
	b, err = List(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Warnings) == 0 {
		t.Error("no warning for a bad declined file")
	}
}

func TestRecommendedOfferSkipsDeclined(t *testing.T) {
	in, _ := applyEnv(t)
	rec := Recommended()
	if err := Decline(in.Paths.StateDir, []string{IntentPrefix + IntentID(rec[1].Value), IntentPrefix + IntentID(rec[2].Value)}); err != nil {
		t.Fatal(err)
	}
	got := RecommendedOffer(in, rec, false)
	if len(got) != len(rec)-2 {
		t.Fatalf("offered %d, want %d", len(got), len(rec)-2)
	}
	for _, r := range got {
		if r.Value == rec[1].Value || r.Value == rec[2].Value {
			t.Errorf("declined rule offered: %s", r.Value)
		}
	}
	if all := RecommendedOffer(in, rec, true); len(all) != len(rec) {
		t.Fatalf("all: offered %d, want %d", len(all), len(rec))
	}
}

func TestLoadDeclinedCorruptNamesFile(t *testing.T) {
	in, _ := applyEnv(t)
	path := filepath.Join(in.Paths.StateDir, DeclinedFile)
	writeFile(t, path, "{not json")
	_, err := LoadDeclined(in.Paths.StateDir)
	if err == nil || !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), "delete it") {
		t.Fatalf("err = %v", err)
	}
	// Reconcile reads it when a dropped recommended rule must be declined,
	// and then saves no ledger, so a rerun after the delete does both.
	rec := Recommended()[0]
	plan, err := RecommendedPlan(in, []Rule{rec})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(in, plan); err != nil {
		t.Fatalf("Apply with a corrupt declined list: %v", err)
	}
	writeFile(t, filepath.Join(in.Paths.ClaudeDir, "settings.json"), seedSettings) // removed by hand
	if _, _, err := Reconcile(in); err == nil || !strings.Contains(err.Error(), "delete it") || !strings.Contains(err.Error(), path) {
		t.Fatalf("Reconcile err = %v", err)
	}
	if led := loadLedger(t, in); len(led.Entries) != 1 {
		t.Fatalf("ledger saved after a failed decline: %+v", led.Entries)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	dropped, declined, err := Reconcile(in)
	if err != nil || len(dropped) != 1 || len(declined) != 1 {
		t.Fatalf("rerun: %v %v %v", dropped, declined, err)
	}
}

func TestListWarnsOnCorruptDeclined(t *testing.T) {
	in, _ := applyEnv(t)
	path := filepath.Join(in.Paths.StateDir, DeclinedFile)
	writeFile(t, path, "{not json")
	b, err := List(in)
	if err != nil {
		t.Fatal(err)
	}
	warned := false
	for _, w := range b.Warnings {
		if strings.Contains(w, path) && strings.Contains(w, "delete it") {
			warned = true
		}
	}
	if !warned {
		t.Errorf("no warning naming %s with the delete hint: %v", path, b.Warnings)
	}
	if len(b.Recommended) == 0 {
		t.Fatal("no recommended rows")
	}
	for _, r := range b.Recommended {
		if r.Declined {
			t.Errorf("%s marked declined from a corrupt file", r.Value)
		}
	}
}

func TestApplyIgnoresCorruptDeclined(t *testing.T) {
	in, user := applyEnv(t)
	path := filepath.Join(in.Paths.StateDir, DeclinedFile)
	writeFile(t, path, "{not json")
	plan, err := RecommendedPlan(in, Recommended())
	if err != nil {
		t.Fatal(err)
	}
	res, err := Apply(in, plan)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !reflect.DeepEqual(res.Written, []string{user}) {
		t.Fatalf("written = %v", res.Written)
	}
	if led := loadLedger(t, in); len(led.Entries) != len(plan.Steps) {
		t.Fatalf("ledger has %d entries, want %d", len(led.Entries), len(plan.Steps))
	}
}

func TestDeclineOverwritesCorruptFile(t *testing.T) {
	p := testEnv(t)
	path := filepath.Join(p.StateDir, DeclinedFile)
	writeFile(t, path, "{not json")
	a := IntentPrefix + "read--netrc-"
	if err := Decline(p.StateDir, []string{a}); err != nil {
		t.Fatal(err)
	}
	d, err := LoadDeclined(p.StateDir)
	if err != nil || !reflect.DeepEqual(d.IntentIDs, []string{a}) {
		t.Fatalf("after decline: %+v %v", d, err)
	}
	writeFile(t, path, `{"v":9,"intent_ids":["x"]}`)
	if err := Undecline(p.StateDir, []string{a}); err != nil {
		t.Fatal(err)
	}
	if err := Decline(p.StateDir, []string{a}); err != nil {
		t.Fatal(err)
	}
	if d, err := LoadDeclined(p.StateDir); err != nil || !reflect.DeepEqual(d.IntentIDs, []string{a}) {
		t.Fatalf("after a wrong-version file: %+v %v", d, err)
	}
}
