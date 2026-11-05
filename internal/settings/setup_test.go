package settings

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInstallExclusionAndPlan(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	orig := "{\"sandbox\":{\"enabled\":true}}\n"
	if err := os.WriteFile(path, []byte(orig), 0o644); err != nil {
		t.Fatal(err)
	}
	plan, err := Plan(path, "/opt/sp/watchdeck", true)
	if err != nil || len(plan) != 1 || plan[0] != "sandbox.excludedCommands: "+ExcludedCommand {
		t.Fatalf("exclusion plan = %v, %v", plan, err)
	}
	full, err := Plan(path, "/opt/sp/watchdeck", false)
	if err != nil || len(full) != HookCount+1 {
		t.Fatalf("full plan = %v, %v", full, err)
	}
	if b, _ := os.ReadFile(path); string(b) != orig {
		t.Fatalf("Plan wrote the file: %s", b)
	}
	ch, err := InstallExclusion(path)
	if err != nil || len(ch.Added) != 1 || ch.Backup == "" {
		t.Fatalf("InstallExclusion = %+v, %v", ch, err)
	}
	st, _ := Inspect(path)
	if !st.Excluded || st.Count() != 0 || !st.SandboxEnabled {
		t.Fatalf("status after exclusion only: %+v", st)
	}
	if ch, _ := InstallExclusion(path); ch.Changed() {
		t.Fatalf("second InstallExclusion changed: %+v", ch)
	}
}

func TestDuplicatesCountsOurHooks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	if _, err := Install(path, "/opt/sp/watchdeck"); err != nil {
		t.Fatal(err)
	}
	if d, err := Duplicates(path); err != nil || len(d) != 0 {
		t.Fatalf("fresh install duplicates = %v, %v", d, err)
	}
	obj, _, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	groups, hooks, err := eventGroups(obj, EventPre, false)
	if err != nil {
		t.Fatal(err)
	}
	hooks.Set(EventPre, append(groups, newHookGroup("/usr/local/bin/watchdeck", MatcherBash)))
	if _, err := Save(path, obj, false); err != nil {
		t.Fatal(err)
	}
	d, err := Duplicates(path)
	if err != nil || len(d) != 1 || d[0] != "PreToolUse Bash: 2 entries" {
		t.Fatalf("duplicates = %v, %v", d, err)
	}
	if d, err := Duplicates(filepath.Join(t.TempDir(), "absent.json")); err != nil || d != nil {
		t.Fatalf("absent file: %v, %v", d, err)
	}
}
