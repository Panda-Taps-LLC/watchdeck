package settings

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

const testBinary = "/opt/bin/watchdeck"

func copyFixture(t *testing.T) string {
	t.Helper()
	return copyNamedFixture(t, "owner-like.json")
}

func copyNamedFixture(t *testing.T, name string) string {
	t.Helper()
	src, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(dst, src, 0o644); err != nil {
		t.Fatal(err)
	}
	return dst
}

func writeSettings(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func parse(t *testing.T, path string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("parse %s: %v\n%s", path, err, b)
	}
	return m
}

// groups returns hooks.<event> from a parsed settings file (nil when absent).
func groups(m map[string]any, event string) []any {
	hooks, _ := m["hooks"].(map[string]any)
	arr, _ := hooks[event].([]any)
	return arr
}

// assertOurGroup checks one installed group: exact matcher, one exec-form hook entry.
func assertOurGroup(t *testing.T, g any, matcher, binary string) {
	t.Helper()
	gm, ok := g.(map[string]any)
	if !ok {
		t.Fatalf("group is %T", g)
	}
	if matcher == MatcherAll {
		if m, has := gm["matcher"]; has {
			t.Fatalf("matcher = %v, want none", m)
		}
	} else if gm["matcher"] != matcher {
		t.Fatalf("matcher = %v, want %q", gm["matcher"], matcher)
	}
	hs, _ := gm["hooks"].([]any)
	if len(hs) != 1 {
		t.Fatalf("group %q holds %d hooks, want 1", matcher, len(hs))
	}
	h := hs[0].(map[string]any)
	args, _ := h["args"].([]any)
	if h["type"] != "command" || h["command"] != binary || len(args) != 1 || args[0] != "hook" || h["timeout"].(float64) != 5 {
		t.Fatalf("hook entry for %q = %v", matcher, h)
	}
}

// lifecycleLines are the Added/Removed lines of the three lifecycle groups.
var lifecycleLines = []string{
	"hooks.SessionStart: /opt/bin/watchdeck hook",
	"hooks.SessionEnd: /opt/bin/watchdeck hook",
	"hooks.UserPromptSubmit: /opt/bin/watchdeck hook",
}

// assertLifecycleGroups checks the three lifecycle groups after an install
// on owner-like.json: SessionStart keeps the foreign matcher-less group first
// and gains ours; SessionEnd and UserPromptSubmit hold only ours.
func assertLifecycleGroups(t *testing.T, m map[string]any) {
	t.Helper()
	ss := groups(m, EventSessionStart)
	if len(ss) != 2 {
		t.Fatalf("SessionStart groups = %v", ss)
	}
	foreign := ss[0].(map[string]any)["hooks"].([]any)[0].(map[string]any)
	if foreign["command"] != "/Users/example/.config/iterm2/cc-status" {
		t.Fatalf("foreign SessionStart group changed: %v", ss[0])
	}
	assertOurGroup(t, ss[1], MatcherAll, testBinary)
	for _, ev := range []string{EventSessionEnd, EventPrompt} {
		g := groups(m, ev)
		if len(g) != 1 {
			t.Fatalf("%s groups = %v", ev, g)
		}
		assertOurGroup(t, g[0], MatcherAll, testBinary)
	}
}

func TestRoundTripIsByteEqual(t *testing.T) {
	p := copyFixture(t)
	orig, _ := os.ReadFile(p)
	obj, existed, err := Load(p)
	if err != nil || !existed {
		t.Fatalf("load: %v existed=%v", err, existed)
	}
	out, err := Encode(obj)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(orig, out) {
		t.Fatalf("round trip differs:\n%s", out)
	}
}

func TestInstallAppendsAndPreserves(t *testing.T) {
	p := copyFixture(t)
	ch, err := Install(p, testBinary)
	if err != nil {
		t.Fatal(err)
	}
	wantAdded := append([]string{
		"hooks.PreToolUse: /opt/bin/watchdeck hook (matcher Bash)",
		"hooks.PreToolUse: /opt/bin/watchdeck hook (matcher Skill)",
		"hooks.PermissionDenied: /opt/bin/watchdeck hook (matcher *)",
	}, append(append([]string(nil), lifecycleLines...), "sandbox.excludedCommands: watchdeck run *")...)
	if strings.Join(ch.Added, "\n") != strings.Join(wantAdded, "\n") || ch.Backup == "" {
		t.Fatalf("unexpected change: %+v", ch)
	}
	if _, err := os.Stat(ch.Backup); err != nil {
		t.Fatalf("backup missing: %v", err)
	}
	m := parse(t, p)
	pre := groups(m, EventPre)
	if len(pre) != 3 {
		t.Fatalf("want 3 PreToolUse groups, got %d", len(pre))
	}
	first := pre[0].(map[string]any)
	if _, has := first["matcher"]; has {
		t.Fatal("existing matcher-less group was modified")
	}
	assertOurGroup(t, pre[1], MatcherBash, testBinary)
	assertOurGroup(t, pre[2], MatcherSkill, testBinary)
	denied := groups(m, EventDenied)
	if len(denied) != 1 {
		t.Fatalf("want 1 PermissionDenied group, got %d", len(denied))
	}
	assertOurGroup(t, denied[0], MatcherDenied, testBinary)
	assertLifecycleGroups(t, m)
	ex := m["sandbox"].(map[string]any)["excludedCommands"].([]any)
	if len(ex) != 1 || ex[0] != ExcludedCommand {
		t.Fatalf("excludedCommands = %v", ex)
	}
	for _, k := range []string{"env", "permissions", "model", "enabledPlugins"} {
		if _, ok := m[k]; !ok {
			t.Fatalf("key %q lost", k)
		}
	}
	// key order preserved: env first, hooks before enabledPlugins, PermissionDenied
	// appended inside hooks after SessionStart, sandbox appended last
	b, _ := os.ReadFile(p)
	s := string(b)
	if !strings.HasPrefix(s, "{\n  \"env\"") || strings.Index(s, "\"hooks\"") > strings.Index(s, "\"enabledPlugins\"") || strings.LastIndex(s, "\"sandbox\"") < strings.Index(s, "\"enabledPlugins\"") {
		t.Fatalf("key order not preserved:\n%s", s)
	}
	if i, j := strings.Index(s, "\"SessionStart\""), strings.Index(s, "\"PermissionDenied\""); i < 0 || j < i || j > strings.Index(s, "\"enabledPlugins\"") {
		t.Fatalf("PermissionDenied not appended inside hooks after SessionStart:\n%s", s)
	}
	if i, j, k := strings.Index(s, "\"PermissionDenied\""), strings.Index(s, "\"SessionEnd\""), strings.Index(s, "\"UserPromptSubmit\""); j < i || k < j || k > strings.Index(s, "\"enabledPlugins\"") {
		t.Fatalf("SessionEnd and UserPromptSubmit not appended inside hooks after PermissionDenied:\n%s", s)
	}
	st, err := Inspect(p)
	if err != nil || !st.Complete {
		t.Fatalf("status after install = %+v (%v)", st, err)
	}
}

func TestInstallIsIdempotent(t *testing.T) {
	p := copyFixture(t)
	if _, err := Install(p, testBinary); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(p)
	ch, err := Install(p, "/other/watchdeck")
	if err != nil {
		t.Fatal(err)
	}
	if ch.Changed() {
		t.Fatalf("second install changed something: %+v", ch)
	}
	after, _ := os.ReadFile(p)
	if !bytes.Equal(before, after) {
		t.Fatal("file rewritten on idempotent install")
	}
}

func TestUninstallRestoresBytes(t *testing.T) {
	p := copyFixture(t)
	orig, _ := os.ReadFile(p)
	if _, err := Install(p, testBinary); err != nil {
		t.Fatal(err)
	}
	ch, err := Uninstall(p)
	if err != nil {
		t.Fatal(err)
	}
	wantRemoved := append([]string{
		"hooks.PreToolUse: /opt/bin/watchdeck hook (matcher Bash)",
		"hooks.PreToolUse: /opt/bin/watchdeck hook (matcher Skill)",
		"hooks.PermissionDenied: /opt/bin/watchdeck hook (matcher *)",
	}, append(append([]string(nil), lifecycleLines...), "sandbox.excludedCommands: watchdeck run *")...)
	if strings.Join(ch.Removed, "\n") != strings.Join(wantRemoved, "\n") {
		t.Fatalf("removed = %v", ch.Removed)
	}
	after, _ := os.ReadFile(p)
	if !bytes.Equal(orig, after) {
		t.Fatalf("uninstall did not restore the original:\n%s", after)
	}
	ch, err = Uninstall(p)
	if err != nil || ch.Changed() {
		t.Fatalf("second uninstall: %+v %v", ch, err)
	}
}

// olderInstallUpgrades starts from a settings file written by an older
// `enforce install` (testdata/v01-installed.json and m4-installed.json, each
// owner-like.json plus that install). Install adds exactly wantAdded, reports
// wantUpdated (an old PermissionDenied matcher widened in place), and leaves
// every other existing group byte-identical in its place; a second Install
// changes nothing, and Uninstall returns the file to owner-like.json byte for
// byte.
func olderInstallUpgrades(t *testing.T, fixture string, wantAdded, wantUpdated []string) {
	t.Helper()
	p := copyNamedFixture(t, fixture)
	beforeObj, _, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	st, err := Inspect(p)
	if err != nil || st.Complete || st.Count() == 0 || !st.Excluded {
		t.Fatalf("older install status = %+v count %d (%v)", st, st.Count(), err)
	}
	ch, err := Install(p, testBinary)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(ch.Added, "\n") != strings.Join(wantAdded, "\n") {
		t.Fatalf("added = %q", ch.Added)
	}
	if strings.Join(ch.Updated, "\n") != strings.Join(wantUpdated, "\n") {
		t.Fatalf("updated = %q", ch.Updated)
	}
	afterObj, _, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range []string{EventPre, EventSessionStart} {
		before, _, _ := eventGroups(beforeObj, ev, false)
		after, _, _ := eventGroups(afterObj, ev, false)
		if len(after) < len(before) {
			t.Fatalf("%s groups before/after = %d/%d", ev, len(before), len(after))
		}
		for i := range before { // the existing groups keep their place and bytes
			b1, _ := Encode(before[i].(*Object))
			b2, _ := Encode(after[i].(*Object))
			if !bytes.Equal(b1, b2) {
				t.Fatalf("%s[%d] changed:\n%s\n--\n%s", ev, i, b1, b2)
			}
		}
	}
	m := parse(t, p)
	if d := groups(m, EventDenied); len(d) != 1 {
		t.Fatalf("PermissionDenied groups = %d", len(d))
	} else {
		assertOurGroup(t, d[0], MatcherDenied, testBinary)
	}
	assertLifecycleGroups(t, m)
	if st, err := Inspect(p); err != nil || !st.Complete || st.Count() != HookCount || len(st.Missing()) != 0 {
		t.Fatalf("status after upgrade = %+v (%v)", st, err)
	}
	if ch, err := Install(p, testBinary); err != nil || ch.Changed() {
		t.Fatalf("second install: %+v %v", ch, err)
	}
	if _, err := Uninstall(p); err != nil {
		t.Fatal(err)
	}
	orig, _ := os.ReadFile(filepath.Join("testdata", "owner-like.json"))
	got, _ := os.ReadFile(p)
	if !bytes.Equal(orig, got) {
		t.Fatalf("uninstall after upgrade did not return to owner-like.json:\n%s", got)
	}
}

// TestUpgradeFromV01: testdata/v01-installed.json is owner-like.json after a
// v0.1 `enforce install` (Bash group + exclusion, generated by the v0.1 code
// on 2026-10-12). Install adds the Skill, PermissionDenied and lifecycle
// groups and keeps the exclusion.
func TestUpgradeFromV01(t *testing.T) {
	added := append([]string{
		"hooks.PreToolUse: /opt/bin/watchdeck hook (matcher Skill)",
		"hooks.PermissionDenied: /opt/bin/watchdeck hook (matcher *)",
	}, lifecycleLines...)
	olderInstallUpgrades(t, "v01-installed.json", added, nil)
}

// TestUpgradeFromM4: testdata/m4-installed.json is owner-like.json after an
// M4 `enforce install` (three groups + exclusion, generated by the M4 code at
// on 2026-10-13). Install adds the three lifecycle groups, appending
// to the existing SessionStart array, and widens the Bash|Skill
// PermissionDenied matcher to "*" in place.
func TestUpgradeFromM4(t *testing.T) {
	olderInstallUpgrades(t, "m4-installed.json", lifecycleLines,
		[]string{"hooks.PermissionDenied: /opt/bin/watchdeck hook (matcher Bash|Skill -> *)"})
}

func ourGroup(matcher, command string) string {
	return `{"matcher": "` + matcher + `", "hooks": [{"type": "command", "command": "` + command + `", "args": ["hook"], "timeout": 5}]}`
}

// TestInspectReportsEveryHook: each of the HookCount registrations is
// reported on its own; Complete needs all of them plus the exclusion; a
// foreign hook under the right event and matcher does not count.
func TestInspectReportsEveryHook(t *testing.T) {
	type grp struct{ event, json string }
	all := []grp{
		{EventPre, ourGroup(MatcherBash, testBinary)},
		{EventPre, ourGroup(MatcherSkill, testBinary)},
		{EventDenied, ourGroup(MatcherDenied, testBinary)},
		{EventSessionStart, ourGroup(MatcherAll, testBinary)},
		{EventSessionEnd, ourGroup(MatcherAll, testBinary)},
		{EventPrompt, ourGroup(MatcherAll, testBinary)},
	}
	exclusion := `"sandbox": {"excludedCommands": ["watchdeck run *"]}`
	build := func(gs []grp, extra string) string {
		byEvent := map[string][]string{}
		var order []string
		for _, g := range gs {
			if _, ok := byEvent[g.event]; !ok {
				order = append(order, g.event)
			}
			byEvent[g.event] = append(byEvent[g.event], g.json)
		}
		var parts []string
		for _, ev := range order {
			parts = append(parts, `"`+ev+`": [`+strings.Join(byEvent[ev], ",")+`]`)
		}
		s := `{"hooks": {` + strings.Join(parts, ", ") + `}`
		if extra != "" {
			s += ", " + extra
		}
		return s + "}\n"
	}
	full := Status{Exists: true, HookInstalled: true, HookCommand: testBinary, SkillHook: true, DeniedHook: true,
		StartHook: true, EndHook: true, PromptHook: true, Excluded: true, Complete: true}
	t.Run("all seven", func(t *testing.T) {
		got, err := Inspect(writeSettings(t, build(all, exclusion)))
		if err != nil || got != full || got.Count() != HookCount || len(got.Missing()) != 0 || !got.Lifecycle() {
			t.Fatalf("status = %+v (%v)", got, err)
		}
	})
	t.Run("no exclusion", func(t *testing.T) {
		want := full
		want.Excluded, want.Complete = false, false
		if got, _ := Inspect(writeSettings(t, build(all, ""))); got != want {
			t.Fatalf("status = %+v", got)
		}
	})
	labels := []string{"PreToolUse Bash", "PreToolUse Skill", "PermissionDenied *", "SessionStart", "SessionEnd", "UserPromptSubmit"}
	for drop := range all {
		for _, foreign := range []bool{false, true} {
			name := "without " + labels[drop]
			if foreign {
				name += ", foreign hook in its place"
			}
			t.Run(name, func(t *testing.T) {
				var gs []grp
				for i, g := range all {
					if i != drop {
						gs = append(gs, g)
					} else if foreign {
						gs = append(gs, grp{g.event, ourGroup(registrations[i].matcher, "/x/other-hook")})
					}
				}
				got, err := Inspect(writeSettings(t, build(gs, exclusion)))
				if err != nil {
					t.Fatal(err)
				}
				want := full
				want.Complete = false
				switch drop {
				case 0:
					want.HookInstalled = false
				case 1:
					want.SkillHook = false
				case 2:
					want.DeniedHook = false
				case 3:
					want.StartHook = false
				case 4:
					want.EndHook = false
				case 5:
					want.PromptHook = false
				}
				if got != want {
					t.Fatalf("status = %+v\nwant     %+v", got, want)
				}
				if got.Count() != HookCount-1 || strings.Join(got.Missing(), ",") != labels[drop] {
					t.Fatalf("count %d missing %v", got.Count(), got.Missing())
				}
			})
		}
	}
	t.Run("v0.1 only", func(t *testing.T) {
		got, _ := Inspect(writeSettings(t, build(all[:1], exclusion)))
		want := Status{Exists: true, HookInstalled: true, HookCommand: testBinary, Excluded: true}
		if got != want || got.Count() != 1 {
			t.Fatalf("status = %+v", got)
		}
	})
	t.Run("lifecycle only", func(t *testing.T) {
		got, _ := Inspect(writeSettings(t, build(all[3:], "")))
		want := Status{Exists: true, HookCommand: testBinary, StartHook: true, EndHook: true, PromptHook: true}
		if got != want || !got.Lifecycle() {
			t.Fatalf("status = %+v", got)
		}
	})
}

func TestInstallOnMissingFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "nested", "settings.json")
	ch, err := Install(p, testBinary)
	if err != nil {
		t.Fatal(err)
	}
	if ch.Backup != "" {
		t.Fatal("backup for a file that did not exist")
	}
	if len(ch.Added) != HookCount+1 {
		t.Fatalf("added = %v", ch.Added)
	}
	st, err := Inspect(p)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Exists || st.Count() != HookCount || !st.Excluded || !st.Complete || st.HookCommand != testBinary {
		t.Fatalf("status = %+v", st)
	}
	m := parse(t, p)
	if len(groups(m, EventPre)) != 2 || len(groups(m, EventDenied)) != 1 || len(groups(m, EventSessionStart)) != 1 || len(groups(m, EventSessionEnd)) != 1 || len(groups(m, EventPrompt)) != 1 {
		t.Fatalf("groups = %v", m["hooks"])
	}
}

func TestInspect(t *testing.T) {
	p := copyFixture(t)
	st, err := Inspect(p)
	if err != nil {
		t.Fatal(err)
	}
	if st.Count() != 0 || st.Excluded || st.SandboxEnabled || st.Complete || !st.Exists {
		t.Fatalf("status before install = %+v", st)
	}
	st, _ = Inspect(filepath.Join(t.TempDir(), "none.json"))
	if st.Exists {
		t.Fatal("missing file reported as existing")
	}
}

func TestExistingExcludedCommandsAreKept(t *testing.T) {
	p := writeSettings(t, "{\n  \"sandbox\": {\n    \"enabled\": true,\n    \"excludedCommands\": [\n      \"docker *\"\n    ]\n  }\n}\n")
	if _, err := Install(p, testBinary); err != nil {
		t.Fatal(err)
	}
	st, _ := Inspect(p)
	if !st.SandboxEnabled || !st.Excluded || !st.Complete {
		t.Fatalf("status = %+v", st)
	}
	if _, err := Uninstall(p); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	if !strings.Contains(string(b), "docker *") || strings.Contains(string(b), ExcludedCommand) || !strings.Contains(string(b), "\"enabled\": true") || strings.Contains(string(b), "\"hooks\"") {
		t.Fatalf("after uninstall:\n%s", b)
	}
}

// TestUninstallKeepsForeignEntries: a foreign PermissionDenied group survives,
// a mixed group loses only our entry, and containers that still hold something
// are not dropped.
func TestUninstallKeepsForeignEntries(t *testing.T) {
	foreignDenied := `{"matcher": "Bash", "hooks": [{"type": "command", "command": "/x/other-hook"}]}`
	mixedSkill := `{"matcher": "Skill", "hooks": [{"type": "command", "command": "/x/other-hook"}, {"type": "command", "command": "/opt/bin/watchdeck", "args": ["hook"], "timeout": 5}]}`
	p := writeSettings(t, `{"hooks": {"PreToolUse": [`+ourGroup(MatcherBash, testBinary)+`, `+mixedSkill+`], "PermissionDenied": [`+foreignDenied+`, `+ourGroup(MatcherDenied, testBinary)+`]}}`+"\n")
	ch, err := Uninstall(p)
	if err != nil {
		t.Fatal(err)
	}
	wantRemoved := []string{
		"hooks.PreToolUse: /opt/bin/watchdeck hook (matcher Bash)",
		"hooks.PreToolUse: /opt/bin/watchdeck hook (matcher Skill)",
		"hooks.PermissionDenied: /opt/bin/watchdeck hook (matcher *)",
	}
	if strings.Join(ch.Removed, "\n") != strings.Join(wantRemoved, "\n") {
		t.Fatalf("removed = %v", ch.Removed)
	}
	m := parse(t, p)
	pre := groups(m, EventPre)
	if len(pre) != 1 || pre[0].(map[string]any)["matcher"] != "Skill" || len(pre[0].(map[string]any)["hooks"].([]any)) != 1 {
		t.Fatalf("PreToolUse after uninstall = %v", pre)
	}
	den := groups(m, EventDenied)
	if len(den) != 1 || den[0].(map[string]any)["matcher"] != "Bash" {
		t.Fatalf("PermissionDenied after uninstall = %v", den)
	}
	st, _ := Inspect(p)
	if st.HookInstalled || st.SkillHook || st.DeniedHook {
		t.Fatalf("status after uninstall = %+v", st)
	}
}

// TestIsOurHookNames pins which hook entries Install treats as already
// present and Uninstall removes: a watchdeck binary under any path, the
// shell form, and a renamed build that runs the hook subcommand; never the
// plugin's hook.sh or someone else's command.
func TestIsOurHookNames(t *testing.T) {
	entry := func(command string, args ...string) *Object {
		h := NewObject()
		h.Set("type", "command")
		h.Set("command", command)
		if args != nil {
			a := make([]any, len(args))
			for i, s := range args {
				a[i] = s
			}
			h.Set("args", a)
		}
		return h
	}
	cases := []struct {
		h    *Object
		want bool
	}{
		{entry("/opt/bin/watchdeck", "hook"), true},
		{entry("/opt/bin/watchdeck"), true},
		{entry("watchdeck", "hook"), true},
		{entry("/opt/bin/watchdeck hook"), true},
		{entry("watchdeck hook"), true},
		{entry("/tmp/build/watchdeck-dev", "hook"), true},
		{entry("/tmp/build/watchdeck_darwin_arm64", "hook"), true},
		{entry("/tmp/build/watchdeck-dev"), false},
		{entry("/tmp/build/watchdeck-dev", "run"), false},
		{entry(`"${CLAUDE_PLUGIN_ROOT}"/bin/hook.sh`), false},
		{entry("/Users/example/.config/iterm2/cc-status"), false},
		{entry("/x/other", "hook"), false},
		{entry("/x/mywatchdeck", "hook"), false},
	}
	for _, c := range cases {
		cmd, _ := c.h.Get("command")
		if _, got := isOurHook(c.h); got != c.want {
			t.Errorf("isOurHook(%v args=%v) = %v, want %v", cmd, func() any { a, _ := c.h.Get("args"); return a }(), got, c.want)
		}
	}
	if _, ok := isOurHook("not an object"); ok {
		t.Error("non-object entry accepted")
	}
}

// TestMalformedHooksIsAnError: a "hooks", "hooks.<event>", "sandbox" or
// "sandbox.excludedCommands" value of the wrong type is reported, never
// overwritten, by Install, Uninstall and Inspect.
func TestMalformedHooksIsAnError(t *testing.T) {
	for _, c := range []string{
		`{"hooks": "nope"}` + "\n",
		`{"hooks": {"PreToolUse": {"matcher": "Bash"}}}` + "\n",
		`{"hooks": {"PermissionDenied": 1}}` + "\n",
		`{"sandbox": true}` + "\n",
		`{"sandbox": {"excludedCommands": "watchdeck run *"}}` + "\n",
	} {
		p := writeSettings(t, c)
		before, _ := os.ReadFile(p)
		if _, err := Install(p, testBinary); err == nil {
			t.Fatalf("Install accepted %s", c)
		}
		if _, err := Uninstall(p); err == nil {
			t.Fatalf("Uninstall accepted %s", c)
		}
		if _, err := Inspect(p); err == nil {
			t.Fatalf("Inspect accepted %s", c)
		}
		after, _ := os.ReadFile(p)
		if !bytes.Equal(before, after) {
			t.Fatalf("malformed file was rewritten:\n%s", after)
		}
	}
}

// TestPluginHooksJSONShape pins plugin/hooks/hooks.json to the same six
// registrations Install writes (the lifecycle groups without a matcher). A top-level "modules" key (the in-session mod)
// is tolerated; anything else at the top level is not.
func TestPluginHooksJSONShape(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "plugin", "hooks", "hooks.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for k, v := range m {
		switch k {
		case "description", "hooks":
		case "modules":
			mods, ok := v.([]any)
			if !ok || len(mods) == 0 {
				t.Fatalf("modules = %v", v)
			}
			for _, mod := range mods {
				if _, ok := mod.(string); !ok {
					t.Fatalf("modules entry %v is not a string", mod)
				}
			}
		default:
			t.Fatalf("unexpected top-level key %q", k)
		}
	}
	desc, _ := m["description"].(string)
	for _, want := range []string{EventPre, EventDenied, "Skill", EventSessionStart, EventSessionEnd, EventPrompt} {
		if !strings.Contains(desc, want) {
			t.Fatalf("description does not mention %q: %q", want, desc)
		}
	}
	hooks, _ := m["hooks"].(map[string]any)
	if len(hooks) != len(events())+1 { // + PostToolUse (PluginExtra)
		t.Fatalf("hooks has keys %v, want exactly %v and %s", hooks, events(), EventPost)
	}
	const cmd = `"${CLAUDE_PLUGIN_ROOT}"/bin/hook.sh`
	check := func(event string, matchers ...string) {
		t.Helper()
		gs, ok := hooks[event].([]any)
		if !ok || len(gs) != len(matchers) {
			t.Fatalf("hooks.%s = %v, want %d groups", event, hooks[event], len(matchers))
		}
		for i, want := range matchers {
			g := gs[i].(map[string]any)
			if m, has := g["matcher"]; want == MatcherAll && has || want != MatcherAll && m != want {
				t.Fatalf("hooks.%s[%d].matcher = %v, want %q", event, i, g["matcher"], want)
			}
			hs, _ := g["hooks"].([]any)
			if len(hs) != 1 {
				t.Fatalf("hooks.%s[%d] holds %d hooks", event, i, len(hs))
			}
			h := hs[0].(map[string]any)
			if h["type"] != "command" || h["command"] != cmd || h["timeout"].(float64) != 5 {
				t.Fatalf("hooks.%s[%d].hooks[0] = %v", event, i, h)
			}
		}
	}
	n := 0
	all := append(append([]registration(nil), registrations...), PluginExtra().regs()...)
	for _, ev := range append(events(), EventPost) {
		var ms []string
		for _, r := range all {
			if r.event == ev {
				ms = append(ms, r.matcher)
			}
		}
		check(ev, ms...)
		n += len(ms)
	}
	if n != HookCount+len(PluginExtra().regs()) {
		t.Fatalf("checked %d registrations, want %d", n, HookCount+len(PluginExtra().regs()))
	}
}

// TestUninstallLifecycleKeepsForeign: our entry in a mixed matcher-less
// SessionStart group is removed and the foreign entry stays; a foreign
// UserPromptSubmit group is untouched.
func TestUninstallLifecycleKeepsForeign(t *testing.T) {
	mixed := `{"hooks": [{"type": "command", "command": "/x/other-hook"}, {"type": "command", "command": "/opt/bin/watchdeck", "args": ["hook"], "timeout": 5}]}`
	foreign := `{"hooks": [{"type": "command", "command": "/x/prompt-hook"}]}`
	p := writeSettings(t, `{"hooks": {"SessionStart": [`+mixed+`], "UserPromptSubmit": [`+foreign+`, `+ourGroup(MatcherAll, testBinary)+`], "SessionEnd": [`+ourGroup(MatcherAll, testBinary)+`]}}`+"\n")
	st, _ := Inspect(p)
	if !st.Lifecycle() {
		t.Fatalf("status = %+v", st)
	}
	ch, err := Uninstall(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(ch.Removed) != 3 {
		t.Fatalf("removed = %v", ch.Removed)
	}
	m := parse(t, p)
	ss := groups(m, EventSessionStart)
	if len(ss) != 1 || len(ss[0].(map[string]any)["hooks"].([]any)) != 1 {
		t.Fatalf("SessionStart = %v", ss)
	}
	if up := groups(m, EventPrompt); len(up) != 1 {
		t.Fatalf("UserPromptSubmit = %v", up)
	}
	if _, has := m["hooks"].(map[string]any)[EventSessionEnd]; has {
		t.Fatal("empty SessionEnd kept")
	}
	if st, _ := Inspect(p); st.Count() != 0 {
		t.Fatalf("status after uninstall = %+v", st)
	}
}

// TestBackupsInTheSameSecondDoNotCollide: an install and an uninstall in the
// same second each keep their own backup, and the first holds the original
// bytes (it used to be overwritten with the installed state).
func TestBackupsInTheSameSecondDoNotCollide(t *testing.T) {
	fixed := time.Unix(1_760_000_000, 0)
	saved := backupNow
	backupNow = func() time.Time { return fixed }
	t.Cleanup(func() { backupNow = saved })

	p := copyFixture(t)
	orig, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	ins, err := Install(p, testBinary)
	if err != nil {
		t.Fatal(err)
	}
	installed, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	un, err := Uninstall(p)
	if err != nil {
		t.Fatal(err)
	}
	want := p + ".bak-1760000000"
	if ins.Backup != want || un.Backup != want+"-2" {
		t.Fatalf("backups = %q, %q; want %q, %q", ins.Backup, un.Backup, want, want+"-2")
	}
	if b, _ := os.ReadFile(ins.Backup); !bytes.Equal(b, orig) {
		t.Fatalf("first backup does not hold the original bytes:\n%s", b)
	}
	if b, _ := os.ReadFile(un.Backup); !bytes.Equal(b, installed) {
		t.Fatalf("second backup does not hold the installed bytes:\n%s", b)
	}

	// A third save in the same second takes -3; none is overwritten.
	obj, _, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	third, err := Save(p, obj, true)
	if err != nil || third != want+"-3" {
		t.Fatalf("third backup = %q, %v; want %q", third, err, want+"-3")
	}
	if b, _ := os.ReadFile(ins.Backup); !bytes.Equal(b, orig) {
		t.Fatal("first backup changed after a later save")
	}
	fi, err := os.Stat(third)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("backup stat = %v, %v; want mode 0600", fi, err)
	}
}

// TestEncodeKeepsAmpersand pins that Load + Encode reproduces a Claude
// Code-style file byte for byte when its strings hold &, < and >: the
// standard encoder would write &, < and >, which changes
// bytes Claude Code (and the person) wrote.
func TestEncodeKeepsAmpersand(t *testing.T) {
	const content = `{
  "permissions": {
    "allow": [
      "Bash(a && b)",
      "Bash(echo <x> > out)"
    ]
  },
  "nested": {
    "deeper": {
      "s": "x & y"
    }
  }
}
`
	p := writeSettings(t, content)
	obj, _, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	out, err := Encode(obj)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != content {
		t.Fatalf("round trip changed bytes:\n got: %q\nwant: %q", out, content)
	}
	mj, err := obj.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(mj, []byte(`\u0026`)) || bytes.Contains(mj, []byte(`\u003c`)) {
		t.Fatalf("MarshalJSON escaped HTML: %s", mj)
	}
}

// TestSaveSyncWritesAndBacksUp checks SaveSync writes the new content,
// keeps the file mode, and backs up the previous bytes beside it.
func TestSaveSyncWritesAndBacksUp(t *testing.T) {
	orig := "{\n  \"model\": \"opus\"\n}\n"
	p := writeSettings(t, orig)
	if err := os.Chmod(p, 0o640); err != nil {
		t.Fatal(err)
	}
	obj, _, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	obj.Set("x", "a && b")
	bak, err := SaveSync(p, obj, true)
	if err != nil {
		t.Fatal(err)
	}
	if bak == "" {
		t.Fatal("no backup path returned")
	}
	b, err := os.ReadFile(bak)
	if err != nil || string(b) != orig {
		t.Fatalf("backup = %q, %v; want original", b, err)
	}
	got, _ := os.ReadFile(p)
	want := "{\n  \"model\": \"opus\",\n  \"x\": \"a && b\"\n}\n"
	if string(got) != want {
		t.Fatalf("saved %q, want %q", got, want)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o640 {
		t.Fatalf("mode = %v, want 0640", fi.Mode().Perm())
	}
	// A new file is created when none exists, without a backup.
	np := filepath.Join(t.TempDir(), "sub", "settings.json")
	bak, err = SaveSync(np, obj, true)
	if err != nil || bak != "" {
		t.Fatalf("new file: bak=%q err=%v", bak, err)
	}
	if _, err := os.Stat(np); err != nil {
		t.Fatal(err)
	}
}

// TestDeniedMatcherMigrates: an install made before 2026-10-19 registered
// PermissionDenied with matcher Bash|Skill. Install widens that one group to
// "*" in place (never a second group), leaves every other byte alone, and
// Inspect and Uninstall then see it.
func TestDeniedMatcherMigrates(t *testing.T) {
	old := ourGroup(MatcherDeniedOld, testBinary)
	base := func(denied string) string {
		return `{"env": {"A": "1"}, "hooks": {"PreToolUse": [` + ourGroup(MatcherBash, testBinary) + `, ` + ourGroup(MatcherSkill, testBinary) + `], "PermissionDenied": [` + denied + `], "SessionStart": [{"hooks": [{"type": "command", "command": "` + testBinary + `", "args": ["hook"], "timeout": 5}]}], "SessionEnd": [{"hooks": [{"type": "command", "command": "` + testBinary + `", "args": ["hook"], "timeout": 5}]}], "UserPromptSubmit": [{"hooks": [{"type": "command", "command": "` + testBinary + `", "args": ["hook"], "timeout": 5}]}]}, "sandbox": {"excludedCommands": ["` + ExcludedCommand + `"]}}` + "\n"
	}
	denied := func(t *testing.T, p string) []any { return groups(parse(t, p), EventDenied) }

	t.Run("in place", func(t *testing.T) {
		p := writeSettings(t, base(old))
		ch, err := Install(p, testBinary)
		if err != nil || len(ch.Updated) != 1 || len(ch.Added) != 0 || ch.Backup == "" {
			t.Fatalf("change %+v err %v", ch, err)
		}
		if !strings.Contains(ch.Updated[0], "Bash|Skill -> *") {
			t.Fatalf("update line %q", ch.Updated[0])
		}
		// Save re-indents a compact file, so compare the parsed documents:
		// only the matcher differs from the input.
		var want map[string]any
		if err := json.Unmarshal([]byte(strings.Replace(base(old), `"matcher": "Bash|Skill"`, `"matcher": "*"`, 1)), &want); err != nil {
			t.Fatal(err)
		}
		if got := parse(t, p); !reflect.DeepEqual(got, want) {
			t.Fatalf("document differs beyond the matcher:\n%v\nwant\n%v", got, want)
		}
		if g := denied(t, p); len(g) != 1 {
			t.Fatalf("want one PermissionDenied group, got %d", len(g))
		}
		st, err := Inspect(p)
		if err != nil || !st.DeniedHook || !st.Complete {
			t.Fatalf("inspect %+v %v", st, err)
		}
		if d, _ := Duplicates(p); len(d) != 0 {
			t.Fatalf("duplicates %v", d)
		}
		if ch, err := Install(p, testBinary); err != nil || ch.Changed() {
			t.Fatalf("second install %+v %v", ch, err)
		}
		if _, err := Uninstall(p); err != nil {
			t.Fatal(err)
		}
		if g := denied(t, p); len(g) != 0 {
			t.Fatalf("uninstall left %v", g)
		}
	})
	t.Run("not yet migrated is not complete", func(t *testing.T) {
		st, err := Inspect(writeSettings(t, base(old)))
		if err != nil || st.DeniedHook || strings.Join(st.Missing(), ",") != "PermissionDenied *" {
			t.Fatalf("inspect %+v %v", st, err)
		}
	})
	t.Run("a star group of ours already exists", func(t *testing.T) {
		p := writeSettings(t, base(old+`, `+ourGroup(MatcherDenied, testBinary)))
		if _, err := Install(p, testBinary); err != nil {
			t.Fatal(err)
		}
		g := denied(t, p)
		if len(g) != 1 {
			t.Fatalf("want one group, got %d", len(g))
		}
		assertOurGroup(t, g[0], MatcherDenied, testBinary)
	})
	t.Run("a foreign hook shares the old group", func(t *testing.T) {
		mixed := `{"matcher": "Bash|Skill", "hooks": [{"type": "command", "command": "/x/foreign"}, {"type": "command", "command": "` + testBinary + `", "args": ["hook"], "timeout": 5}]}`
		p := writeSettings(t, base(mixed))
		if _, err := Install(p, testBinary); err != nil {
			t.Fatal(err)
		}
		g := denied(t, p)
		if len(g) != 2 {
			t.Fatalf("want 2 groups, got %d", len(g))
		}
		first := g[0].(map[string]any)
		if first["matcher"] != "Bash|Skill" || len(first["hooks"].([]any)) != 1 {
			t.Fatalf("foreign group changed: %v", first)
		}
		assertOurGroup(t, g[1], MatcherDenied, testBinary)
	})
}

// --- Registration (doctor --prove) ---

func TestRegistrationExecForm(t *testing.T) {
	p := filepath.Join(t.TempDir(), "settings.json")
	if _, err := Install(p, "/opt/x/watchdeck"); err != nil {
		t.Fatal(err)
	}
	r, found, err := Registration(p)
	if err != nil || !found {
		t.Fatalf("found=%v err=%v", found, err)
	}
	if r.Command != "/opt/x/watchdeck" || !reflect.DeepEqual(r.Args, []string{"hook"}) || r.Timeout != 5*time.Second || r.Matcher != MatcherBash || r.Shell {
		t.Fatalf("got %+v", r)
	}
	if r.Text() != "/opt/x/watchdeck hook" {
		t.Fatalf("Text() = %q", r.Text())
	}
}

func TestRegistrationShellForm(t *testing.T) {
	p := writeSettings(t, `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"/usr/local/bin/watchdeck hook"}]}]}}`)
	r, found, err := Registration(p)
	if err != nil || !found {
		t.Fatalf("found=%v err=%v", found, err)
	}
	if !r.Shell || r.Args != nil || r.Timeout != 0 || r.Command != "/usr/local/bin/watchdeck hook" {
		t.Fatalf("got %+v", r)
	}
	if r.Text() != "/usr/local/bin/watchdeck hook" {
		t.Fatalf("Text() = %q", r.Text())
	}
}

func TestRegistrationWildcardGroup(t *testing.T) {
	ours := `{"type":"command","command":"/opt/x/watchdeck","args":["hook"],"timeout":7}`
	p := writeSettings(t, `{"hooks":{"PreToolUse":[{"matcher":"Skill","hooks":[`+ours+`]},{"matcher":"*","hooks":[`+ours+`]}]}}`)
	r, found, err := Registration(p)
	if err != nil || !found || r.Matcher != MatcherAnyTool || r.Timeout != 7*time.Second {
		t.Fatalf("star group: found=%v err=%v r=%+v", found, err, r)
	}
	p = writeSettings(t, `{"hooks":{"PreToolUse":[{"hooks":[`+ours+`]}]}}`)
	r, found, err = Registration(p)
	if err != nil || !found || r.Matcher != MatcherAll {
		t.Fatalf("matcher-less group: found=%v err=%v r=%+v", found, err, r)
	}
	// the Bash group wins over a wildcard group listed first
	p = writeSettings(t, `{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"/a/watchdeck","args":["hook"]}]},{"matcher":"Bash","hooks":[`+ours+`]}]}}`)
	r, found, err = Registration(p)
	if err != nil || !found || r.Matcher != MatcherBash || r.Command != "/opt/x/watchdeck" {
		t.Fatalf("bash first: found=%v err=%v r=%+v", found, err, r)
	}
}

func TestRegistrationIgnoresOtherGroups(t *testing.T) {
	ours := `{"type":"command","command":"/opt/x/watchdeck","args":["hook"],"timeout":5}`
	p := writeSettings(t, `{"hooks":{"PreToolUse":[{"matcher":"Skill","hooks":[`+ours+`]}],"PermissionDenied":[{"matcher":"*","hooks":[`+ours+`]}]}}`)
	r, found, err := Registration(p)
	if err != nil || found {
		t.Fatalf("found=%v err=%v r=%+v; want not found", found, err, r)
	}
}

func TestRegistrationAbsent(t *testing.T) {
	_, found, err := Registration(filepath.Join(t.TempDir(), "missing.json"))
	if err != nil || found {
		t.Fatalf("missing file: found=%v err=%v", found, err)
	}
	if _, _, err := Registration(writeSettings(t, "{not json")); err == nil {
		t.Fatal("malformed file: want an error")
	}
}

func TestRegistrationPluginShellNotOurs(t *testing.T) {
	p := writeSettings(t, `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"\"${CLAUDE_PLUGIN_ROOT}\"/bin/hook.sh"}]}]}}`)
	if _, found, err := Registration(p); err != nil || found {
		t.Fatalf("found=%v err=%v; the plugin's hook.sh is not ours", found, err)
	}
}
