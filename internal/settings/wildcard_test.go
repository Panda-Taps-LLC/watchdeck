package settings

import (
	"bytes"
	"os"
	"reflect"
	"strings"
	"testing"
)

// TestWildcardReplacesSpecificGroups: when the policy needs a wildcard
// PreToolUse group, our hook lives only there (one spawn per call): the
// Bash, Skill and tool groups are not added and earlier ones are removed;
// Inspect, ExtraStatus and Duplicates agree. A later install without the
// wildcard puts the specific groups back and removes ours from the
// wildcard group; uninstall restores the original bytes.
func TestWildcardReplacesSpecificGroups(t *testing.T) {
	p := copyFixture(t)
	orig, _ := os.ReadFile(p)
	if _, err := InstallWith(p, testBinary, Extra{Pre: []string{MatcherFiles}}); err != nil {
		t.Fatal(err)
	}
	wild := Extra{Pre: []string{MatcherAnyTool}, Post: []string{MatcherPostWeb}}
	if plan, _ := PlanWith(p, testBinary, false, wild); !strings.Contains(strings.Join(plan, "\n"), "(remove) hooks.PreToolUse") {
		t.Fatalf("plan does not show the removals: %v", plan)
	}
	ch, err := InstallWith(p, testBinary, wild)
	if err != nil {
		t.Fatal(err)
	}
	if len(ch.Removed) != 3 || !strings.Contains(strings.Join(ch.Added, "\n"), "(matcher *)") {
		t.Fatalf("change: %+v", ch)
	}
	inst, _ := InstalledExtra(p)
	var pre []string
	for _, l := range inst {
		if strings.HasPrefix(l, EventPre) {
			pre = append(pre, l)
		}
	}
	if !reflect.DeepEqual(pre, []string{"PreToolUse *"}) {
		t.Fatalf("PreToolUse groups of ours beyond the base: %v", inst)
	}
	st, _ := Inspect(p)
	if !st.Complete || !st.HookInstalled || !st.SkillHook || st.HookCommand == "" {
		t.Fatalf("status with a wildcard: %+v", st)
	}
	if dups, _ := Duplicates(p); len(dups) != 0 {
		t.Fatalf("duplicates: %v", dups)
	}
	if _, missing, _ := ExtraStatus(p, Extra{Pre: []string{MatcherFiles, MatcherMCP}}); len(missing) != 0 {
		t.Fatalf("the wildcard does not cover the tool groups: %v", missing)
	}
	if ch, _ := InstallWith(p, testBinary, wild); ch.Changed() {
		t.Fatalf("second wildcard install changed: %+v", ch)
	}
	// back to specific groups
	ch, err = InstallWith(p, testBinary, Extra{Pre: []string{MatcherFiles}})
	if err != nil || len(ch.Removed) != 1 || !strings.Contains(ch.Removed[0], "(matcher *)") {
		t.Fatalf("unwild: %+v %v", ch, err)
	}
	if st, _ := Inspect(p); !st.Complete {
		t.Fatalf("status after unwild: %+v", st)
	}
	if dups, _ := Duplicates(p); len(dups) != 0 {
		t.Fatalf("duplicates after unwild: %v", dups)
	}
	if _, err := Uninstall(p); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(p)
	if !bytes.Equal(orig, after) {
		t.Fatalf("uninstall did not restore:\n%s", after)
	}
}

// TestDuplicatesSeeWildcardOverlap: our Bash or file group beside our
// wildcard group runs the hook twice for one call; Duplicates says so, and
// a foreign wildcard group does not count.
func TestDuplicatesSeeWildcardOverlap(t *testing.T) {
	p := writeSettings(t, `{"hooks":{"PreToolUse":[`+ourGroup("Bash", testBinary)+`,`+ourGroup(MatcherFiles, testBinary)+`,`+ourGroup("*", testBinary)+`]}}`)
	dups, err := Duplicates(p)
	got := strings.Join(dups, ";")
	if err != nil || !strings.Contains(got, "PreToolUse Bash: 2 entries") || !strings.Contains(got, MatcherFiles+": 1 entries besides a wildcard group") {
		t.Fatalf("dups %v %v", dups, err)
	}
	q := writeSettings(t, `{"hooks":{"PreToolUse":[`+ourGroup("Bash", testBinary)+`,`+ourGroup("*", "/usr/bin/other-tool")+`]}}`)
	if dups, _ := Duplicates(q); len(dups) != 0 {
		t.Fatalf("foreign wildcard counted: %v", dups)
	}
}
