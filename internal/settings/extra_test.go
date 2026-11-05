package settings

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
)

var testExtra = Extra{Pre: []string{MatcherFiles, MatcherWeb, MatcherMCP, "Glob|Task"}, Post: []string{MatcherPostWeb}}

// TestInstallWithExtraAndUninstall: the extra registrations are added after
// the base six, reported by ExtraStatus and InstalledExtra, idempotent, and
// removed (PostToolUse included) by Uninstall, which restores the bytes.
func TestInstallWithExtraAndUninstall(t *testing.T) {
	p := copyFixture(t)
	orig, _ := os.ReadFile(p)
	ch, err := InstallWith(p, testBinary, testExtra)
	if err != nil {
		t.Fatal(err)
	}
	var extraLines []string
	for _, l := range ch.Added {
		if strings.Contains(l, "Read|Write") || strings.Contains(l, "WebFetch") || strings.Contains(l, "mcp__") || strings.Contains(l, "Glob|Task") {
			extraLines = append(extraLines, l)
		}
	}
	if len(extraLines) != 5 || !strings.Contains(strings.Join(ch.Added, "\n"), "hooks.PostToolUse: "+testBinary+" hook (matcher WebFetch|WebSearch)") {
		t.Fatalf("added: %v", ch.Added)
	}
	st, err := Inspect(p)
	if err != nil || !st.Complete {
		t.Fatalf("base status: %+v %v", st, err)
	}
	present, missing, err := ExtraStatus(p, testExtra)
	if err != nil || len(missing) != 0 || len(present) != 5 {
		t.Fatalf("extra status: %v %v %v", present, missing, err)
	}
	inst, _ := InstalledExtra(p)
	if !reflect.DeepEqual(inst, testExtra.Labels()) {
		t.Fatalf("installed extra %v, want %v", inst, testExtra.Labels())
	}
	if ch, err := InstallWith(p, testBinary, testExtra); err != nil || ch.Changed() {
		t.Fatalf("second install: %+v %v", ch, err)
	}
	// a policy that now needs nothing: a base install does not remove extras
	if _, missing, _ := ExtraStatus(p, Extra{Pre: []string{"Grep"}}); !reflect.DeepEqual(missing, []string{"PreToolUse Grep"}) {
		t.Fatalf("missing %v", missing)
	}
	if _, err := Uninstall(p); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(p)
	if !bytes.Equal(orig, after) {
		t.Fatalf("uninstall did not restore the original:\n%s", after)
	}
}

// TestNeededExtra: registrations follow the policy.
func TestNeededExtra(t *testing.T) {
	dir := t.TempDir()
	up := filepath.Join(dir, "overrides.yaml")
	// defaults: packs watch the file tools only
	if e := NeededExtra(up, "", nil); !reflect.DeepEqual(e, Extra{Pre: []string{MatcherFiles}}) {
		t.Fatalf("defaults: %+v", e)
	}
	os.WriteFile(up, []byte(`version: 2
packs: {secrets-read: off, persistence: off, cred-in-write: off, prompt-injection: on}
subjects:
  - {kind: mcp, name: github, tools: {'delete_*': deny}}
  - {kind: tool, name: web, match: {tools: [WebFetch]}, domains: {deny: ['*.pastebin.com']}}
`), 0o600)
	if e := NeededExtra(up, "", nil); !reflect.DeepEqual(e, Extra{Pre: []string{MatcherWeb, MatcherMCP}, Post: []string{MatcherPostWeb}}) {
		t.Fatalf("gates: %+v", e)
	}
	os.WriteFile(up, []byte("version: 9\n"), 0o600)
	if e := NeededExtra(up, "", nil); len(e.Pre) != 3 {
		t.Fatalf("malformed: %+v", e)
	}
}

// TestPluginCoversSearchGates: the plugin's static hooks.json registers
// Grep and Glob, so a path gate on them fires for plugin users, and
// PluginUncovered names the gated tools the plugin does not register
// (review 2026-10-14).
func TestPluginCoversSearchGates(t *testing.T) {
	dir := t.TempDir()
	up := filepath.Join(dir, "overrides.yaml")
	os.WriteFile(up, []byte(`version: 2
subjects:
  - {kind: tool, name: secrets, match: {tools: [Read, Grep, Glob]}, paths: {deny: ['~/secrets/**']}}
`), 0o600)
	if got := PluginUncovered(NeededExtra(up, "", nil)); len(got) != 0 {
		t.Fatalf("search gates: plugin misses %v", got)
	}
	os.WriteFile(up, []byte(`version: 2
subjects:
  - {kind: agent, name: explorer, match: {agent_type: Explore}, tools: {deny: [Task, Grep]}}
`), 0o600)
	if got := PluginUncovered(NeededExtra(up, "", nil)); !reflect.DeepEqual(got, []string{"Task"}) {
		t.Fatalf("agent gate: plugin misses %v, want [Task]", got)
	}
	if got := PluginUncovered(Extra{Pre: []string{MatcherAll}}); !reflect.DeepEqual(got, []string{MatcherAnyTool}) {
		t.Fatalf("wildcard gate: plugin misses %v, want [*]", got)
	}
}

// allTwins are the pack rules the twelve recommended native rules cover
// (rulebook.CoveredTwins with every string installed).
var allTwins = []string{
	"persistence/launch-agent-write", "persistence/shell-rc-write", "persistence/systemd-unit-write",
	"secrets-read/read-aws-credentials", "secrets-read/read-dotenv", "secrets-read/read-other-credentials", "secrets-read/read-ssh-private-key",
}

const matcherWrites = "Write|Edit|MultiEdit|NotebookEdit"

// TestNeededExtraFilesByNativeCover: with the default policy the file-tools
// matcher names exactly the tools a rule without an installed native twin
// still needs: all five with nothing covered, the four write tools (the
// cred-in-write asks) with every twin covered.
func TestNeededExtraFilesByNativeCover(t *testing.T) {
	up := filepath.Join(t.TempDir(), "overrides.yaml")
	if e := NeededExtra(up, "", nil); !reflect.DeepEqual(e, Extra{Pre: []string{MatcherFiles}}) {
		t.Fatalf("nothing covered: %+v", e)
	}
	if e := NeededExtra(up, "", allTwins); !reflect.DeepEqual(e, Extra{Pre: []string{matcherWrites}}) {
		t.Fatalf("all covered: %+v", e)
	}
	os.WriteFile(up, []byte("version: 2\npacks: {cred-in-write: off}\n"), 0o600)
	if e := NeededExtra(up, "", allTwins); !e.IsEmpty() {
		t.Fatalf("cred-in-write off, all covered: %+v", e)
	}
	// a pack rule raised to deny keeps Read
	os.WriteFile(up, []byte("version: 2\npacks: {cred-in-write: off}\nrule_overrides: {secrets-read/read-ssh-private-key: {action: deny}}\n"), 0o600)
	if e := NeededExtra(up, "", allTwins); !reflect.DeepEqual(e, Extra{Pre: []string{"Read"}}) {
		t.Fatalf("pack deny: %+v", e)
	}
	// a malformed file still registers the three groups
	os.WriteFile(up, []byte("version: 9\n"), 0o600)
	if e := NeededExtra(up, "", allTwins); len(e.Pre) != 3 {
		t.Fatalf("malformed: %+v", e)
	}
}

// TestInstallWithDropsUnneededFiles: an install whose policy no longer needs
// the file tools removes our entry from the Read|Write|… group (and the
// group, when it held only ours); a plain Install leaves it.
func TestInstallWithDropsUnneededFiles(t *testing.T) {
	p := copyFixture(t)
	if _, err := InstallWith(p, testBinary, Extra{Pre: []string{MatcherFiles}}); err != nil {
		t.Fatal(err)
	}
	if ch, err := Install(p, testBinary); err != nil || ch.Changed() {
		t.Fatalf("base install changed: %+v %v", ch, err)
	}
	plan, err := PlanWith(p, testBinary, false, Extra{})
	if err != nil || len(plan) != 1 || !strings.HasPrefix(plan[0], "(remove) hooks.PreToolUse: ") || !strings.Contains(plan[0], MatcherFiles) {
		t.Fatalf("plan: %v %v", plan, err)
	}
	ch, err := InstallWith(p, testBinary, Extra{})
	if err != nil || len(ch.Removed) != 1 || len(ch.Added) != 0 {
		t.Fatalf("install: %+v %v", ch, err)
	}
	if inst, _ := InstalledExtra(p); len(inst) != 0 {
		t.Fatalf("still installed: %v", inst)
	}
	if st, _ := Inspect(p); !st.Complete {
		t.Fatalf("base hooks lost: %+v", st)
	}
}

// TestInstallWithReplacesFilesGroup: when the needed file-tools matcher
// changes, our entry moves from the old group to a new one; a person's own
// entry in the old group stays, and so does the group.
func TestInstallWithReplacesFilesGroup(t *testing.T) {
	p := copyFixture(t)
	if _, err := InstallWith(p, testBinary, Extra{Pre: []string{MatcherFiles}}); err != nil {
		t.Fatal(err)
	}
	// a superset group covers a narrower need (status), but install narrows it
	if _, missing, _ := ExtraStatus(p, Extra{Pre: []string{matcherWrites}}); len(missing) != 0 {
		t.Fatalf("superset reported missing: %v", missing)
	}
	ch, err := InstallWith(p, testBinary, Extra{Pre: []string{matcherWrites}})
	if err != nil || len(ch.Removed) != 1 || !strings.Contains(ch.Removed[0], MatcherFiles) || len(ch.Added) != 1 || !strings.Contains(ch.Added[0], matcherWrites) {
		t.Fatalf("narrow: %+v %v", ch, err)
	}
	if inst, _ := InstalledExtra(p); !reflect.DeepEqual(inst, []string{"PreToolUse " + matcherWrites}) {
		t.Fatalf("after narrow: %v", inst)
	}
	// the write-only group does not cover Read
	if _, missing, _ := ExtraStatus(p, Extra{Pre: []string{MatcherFiles}}); !reflect.DeepEqual(missing, []string{"PreToolUse " + MatcherFiles}) {
		t.Fatalf("subset: missing %v", missing)
	}
	ch, err = InstallWith(p, testBinary, Extra{Pre: []string{MatcherFiles}})
	if err != nil || len(ch.Removed) != 1 || len(ch.Added) != 1 {
		t.Fatalf("widen: %+v %v", ch, err)
	}
	if inst, _ := InstalledExtra(p); !reflect.DeepEqual(inst, []string{"PreToolUse " + MatcherFiles}) {
		t.Fatalf("after widen: %v", inst)
	}
	if ch, err := InstallWith(p, testBinary, Extra{Pre: []string{MatcherFiles}}); err != nil || ch.Changed() {
		t.Fatalf("second install: %+v %v", ch, err)
	}
}

// TestInstallWithReplacesSharedFilesGroup: our entry leaves a file-tools
// group it shares with someone else's hook; their entry and the group stay.
func TestInstallWithReplacesSharedFilesGroup(t *testing.T) {
	other := `{"type": "command", "command": "/usr/local/bin/other-hook"}`
	p := writeSettings(t, `{"hooks":{"PreToolUse":[{"matcher": "`+MatcherFiles+`", "hooks": [`+other+`, {"type": "command", "command": "`+testBinary+`", "args": ["hook"], "timeout": 5}]}]}}`)
	if _, err := InstallWith(p, testBinary, Extra{Pre: []string{matcherWrites}}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	got := string(b)
	if !strings.Contains(got, "/usr/local/bin/other-hook") || !strings.Contains(got, `"matcher": "`+MatcherFiles+`"`) {
		t.Fatalf("their entry or group lost:\n%s", got)
	}
	if inst, _ := InstalledExtra(p); !reflect.DeepEqual(inst, []string{"PreToolUse " + matcherWrites}) {
		t.Fatalf("installed %v", inst)
	}
	if _, err := Uninstall(p); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(p)
	if !strings.Contains(string(b), "/usr/local/bin/other-hook") {
		t.Fatalf("uninstall removed their hook:\n%s", b)
	}
}

func TestUnhookedTools(t *testing.T) {
	dir := t.TempDir()
	ours := `{"type":"command","command":"/fake/bin/` + paths.BinaryName + ` hook"}`
	theirs := `{"type":"command","command":"/fake/bin/other-tool"}`
	cases := []struct {
		name, body string
		want       []string
	}{
		{"missing file", "", []string{"Grep", "Glob"}},
		{"no hooks", `{}`, []string{"Grep", "Glob"}},
		{"other tools group", `{"hooks":{"PreToolUse":[{"matcher":"Glob|Grep|Task","hooks":[` + ours + `]}]}}`, nil},
		{"one of two", `{"hooks":{"PreToolUse":[{"matcher":"Grep","hooks":[` + ours + `]}]}}`, []string{"Glob"}},
		{"wildcard", `{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[` + ours + `]}]}}`, nil},
		{"matcher-less", `{"hooks":{"PreToolUse":[{"hooks":[` + ours + `]}]}}`, nil},
		{"someone else's", `{"hooks":{"PreToolUse":[{"matcher":"Grep|Glob","hooks":[` + theirs + `]}]}}`, []string{"Grep", "Glob"}},
		{"PostToolUse only", `{"hooks":{"PostToolUse":[{"matcher":"Grep|Glob","hooks":[` + ours + `]}]}}`, []string{"Grep", "Glob"}},
	}
	for i, c := range cases {
		p := filepath.Join(dir, "s"+string(rune('a'+i))+".json")
		if c.body != "" {
			if err := os.WriteFile(p, []byte(c.body), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		got, err := UnhookedTools(p, []string{"Grep", "Glob"})
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: unhooked %v, want %v", c.name, got, c.want)
		}
	}
}
