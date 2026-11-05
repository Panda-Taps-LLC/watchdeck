package claudesettings

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestReadMergesScopes(t *testing.T) {
	p := tempPaths(t)
	root := filepath.Join(p.Home, "proj")
	managed := t.TempDir()
	locs := locate(managed, p, root)
	writeFile(t, filepath.Join(managed, "managed-settings.json"), `{"sandbox": {"enabled": false}}`)
	writeFile(t, locs[1].Path, `{"permissions": {"deny": ["Bash(rm *)"]}, "sandbox": {"enabled": true, "excludedCommands": ["watchdeck"], "network": {"allowedDomains": ["example.com"]}}}`)
	writeFile(t, locs[2].Path, `{"permissions": {"ask": ["Bash(git push *)"]}}`)
	writeFile(t, locs[3].Path, `{"permissions": {"allow": [42, "Bash(ls *)"]}}`)

	led := &Ledger{V: 1, Entries: []LedgerEntry{{Path: locs[1].Path, Key: "permissions.deny", Value: "Bash(rm *)"}}}
	eff, err := Read(locs, led)
	if err != nil {
		t.Fatal(err)
	}
	want := func(es []Entry, e Entry) {
		t.Helper()
		if len(es) != 1 || es[0] != e {
			t.Fatalf("entries = %+v, want [%+v]", es, e)
		}
	}
	want(eff.Deny, Entry{Value: "Bash(rm *)", Scope: ScopeUser, Path: locs[1].Path, Index: 0, Owned: true})
	want(eff.Ask, Entry{Value: "Bash(git push *)", Scope: ScopeProject, Path: locs[2].Path, Index: 0})
	// Index is the position in that file's array; the number is skipped.
	want(eff.Allow, Entry{Value: "Bash(ls *)", Scope: ScopeLocal, Path: locs[3].Path, Index: 1})
	want(eff.Sandbox.Excluded, Entry{Value: "watchdeck", Scope: ScopeUser, Path: locs[1].Path})
	want(eff.Sandbox.AllowedDomains, Entry{Value: "example.com", Scope: ScopeUser, Path: locs[1].Path})
	// sandbox.enabled is a scalar: managed beats user.
	if eff.Sandbox.Enabled == nil || *eff.Sandbox.Enabled {
		t.Fatalf("Sandbox.Enabled = %v, want false from managed", eff.Sandbox.Enabled)
	}
	if len(eff.Files) != 4 {
		t.Fatalf("Files = %+v", eff.Files)
	}
	for _, f := range eff.Files {
		if !f.Exists || f.Err != nil || f.Size == 0 || f.ModTime.IsZero() {
			t.Fatalf("file state %+v", f)
		}
	}
}

// TestReadScalarPrecedence: local beats project beats user for sandbox.enabled.
func TestReadScalarPrecedence(t *testing.T) {
	p := tempPaths(t)
	root := filepath.Join(p.Home, "proj")
	locs := locate("", p, root)
	writeFile(t, locs[0].Path, `{"sandbox": {"enabled": false}}`)
	writeFile(t, locs[1].Path, `{"sandbox": {"enabled": false}}`)
	writeFile(t, locs[2].Path, `{"sandbox": {"enabled": true}}`)
	eff, err := Read(locs, nil)
	if err != nil {
		t.Fatal(err)
	}
	if eff.Sandbox.Enabled == nil || !*eff.Sandbox.Enabled {
		t.Fatalf("Enabled = %v, want true from local", eff.Sandbox.Enabled)
	}
}

func TestReadKeepsDefaultsEntry(t *testing.T) {
	p := tempPaths(t)
	loc := userLoc(p)
	writeFile(t, loc.Path, `{"autoMode": {
  "hard_deny": ["$defaults", "Never push to main"],
  "soft_deny": ["Ask before deleting", "$defaults"],
  "allow": ["$defaults"],
  "environment": ["Trusted repo: example"]
}}`)
	eff, err := Read([]Location{loc}, nil)
	if err != nil {
		t.Fatal(err)
	}
	checks := []struct {
		got  []Entry
		want []string
	}{
		{eff.AutoMode.HardDeny, []string{"$defaults", "Never push to main"}},
		{eff.AutoMode.SoftDeny, []string{"Ask before deleting", "$defaults"}},
		{eff.AutoMode.Allow, []string{"$defaults"}},
		{eff.AutoMode.Environment, []string{"Trusted repo: example"}},
	}
	for i, c := range checks {
		if !reflect.DeepEqual(values(c.got), c.want) {
			t.Fatalf("check %d: %v, want %v", i, values(c.got), c.want)
		}
	}
	if eff.AutoMode.SoftDeny[1].Index != 1 {
		t.Fatalf("$defaults index = %d, want 1", eff.AutoMode.SoftDeny[1].Index)
	}
}

func TestReadPerFileError(t *testing.T) {
	p := tempPaths(t)
	root := filepath.Join(p.Home, "proj")
	locs := locate("", p, root)
	writeFile(t, locs[0].Path, `{"permissions": {"deny": ["Bash(rm *)"]}`) // malformed: missing brace
	if err := os.MkdirAll(locs[1].Path, 0o755); err != nil {               // a directory where the file should be
		t.Fatal(err)
	}
	writeFile(t, locs[2].Path, `{"permissions": {"allow": ["Bash(ls *)"]}}`)

	eff, err := Read(locs, nil)
	if err != nil {
		t.Fatalf("Read errored with one readable file: %v", err)
	}
	if eff.Files[0].Err == nil || eff.Files[1].Err == nil || eff.Files[2].Err != nil {
		t.Fatalf("file errors = %v, %v, %v", eff.Files[0].Err, eff.Files[1].Err, eff.Files[2].Err)
	}
	if len(eff.Deny) != 0 || !reflect.DeepEqual(values(eff.Allow), []string{"Bash(ls *)"}) {
		t.Fatalf("deny %v allow %v", values(eff.Deny), values(eff.Allow))
	}

	// Every existing file unreadable: Read errors.
	if err := os.Remove(locs[2].Path); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(locs, nil); err == nil {
		t.Fatal("Read: want an error when no file could be read")
	}
	// All files missing is not an error: nothing configured.
	p2 := tempPaths(t)
	eff, err = Read(locate("", p2, filepath.Join(p2.Home, "proj")), nil)
	if err != nil || len(eff.Files) != 3 || eff.Files[0].Exists {
		t.Fatalf("all missing: %+v %v", eff.Files, err)
	}
}
