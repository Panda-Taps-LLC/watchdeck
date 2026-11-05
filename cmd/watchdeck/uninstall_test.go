package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Panda-Taps-LLC/watchdeck/internal/claudesettings"
	"github.com/Panda-Taps-LLC/watchdeck/internal/mcpconfig"
	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
	"github.com/Panda-Taps-LLC/watchdeck/internal/rulebook"
	"github.com/Panda-Taps-LLC/watchdeck/internal/settings"
	"github.com/Panda-Taps-LLC/watchdeck/internal/userconfig"
)

// fakeSelf points uninstallSelf at path for one test.
func fakeSelf(t *testing.T, path string) {
	t.Helper()
	old := uninstallSelf
	uninstallSelf = func() (string, error) { return path, nil }
	t.Cleanup(func() { uninstallSelf = old })
}

// installedSettings writes a user settings file with an unrelated hook and
// key, then installs watchdeck's hooks and exclusion into it.
func installedSettings(t *testing.T, e testEnv) (path string) {
	t.Helper()
	path = filepath.Join(e.claude, "settings.json")
	writeFile(t, path, `{
  "model": "x",
  "hooks": {
    "PreToolUse": [
      {"matcher": "Bash", "hooks": [{"type": "command", "command": "/opt/other/guard"}]}
    ]
  },
  "sandbox": {"enabled": true, "excludedCommands": ["docker *"]}
}
`)
	if _, err := settings.Install(path, "/fake/bin/watchdeck"); err != nil {
		t.Fatal(err)
	}
	for _, b := range backups(t, path) {
		os.Remove(b)
	}
	return path
}

func TestUninstallNoTerminalPrintsPlanWritesNothing(t *testing.T) {
	e := newTestEnv(t)
	path := installedSettings(t, e)
	before, _ := os.ReadFile(path)
	cfgPath := filepath.Join(e.cfg, "watchdeck", "config.yaml")
	if err := userconfig.SetAutostartUI(cfgPath, true); err != nil {
		t.Fatal(err)
	}
	c, out := testConsole("", false, false)
	if code := runUninstall(c, uninstallOptions{purge: true}); code != 1 {
		t.Fatalf("exit %d, want 1\n%s", code, out)
	}
	s := out.String()
	for _, want := range []string{"watchdeck uninstall will:", "remove from", "hooks.PreToolUse", "sandbox.excludedCommands: watchdeck run *", "turn ui.autostart off", "(--purge)", "no terminal to confirm on"} {
		if !strings.Contains(s, want) {
			t.Errorf("output lacks %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, e.home+"/") {
		t.Errorf("paths under home are not shown with ~:\n%s", s)
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Fatalf("settings changed without a confirm:\n%s", after)
	}
	if len(backups(t, path)) != 0 {
		t.Fatal("a backup was written without a confirm")
	}
	if cfg, _ := userconfig.Load(cfgPath); func() bool { on, _ := cfg.AutostartUI(); return !on }() {
		t.Fatal("autostart changed without a confirm")
	}
	if _, err := os.Stat(filepath.Join(e.cfg, "watchdeck")); err != nil {
		t.Fatal("config dir removed without a confirm")
	}
}

func TestUninstallYesRemovesOurHooksOnly(t *testing.T) {
	e := newTestEnv(t)
	path := installedSettings(t, e)
	cfgPath := filepath.Join(e.cfg, "watchdeck", "config.yaml")
	if err := userconfig.SetAutostartUI(cfgPath, true); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(e.cfg, "watchdeck", "overrides.yaml"), "version: 1\n")
	c, out := testConsole("", false, true)
	if code := runUninstall(c, uninstallOptions{}); code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	st, err := settings.Inspect(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Count() != 0 || st.Excluded {
		t.Fatalf("our hooks remain: %+v\n%s", st, out)
	}
	var got struct {
		Model string `json:"model"`
		Hooks struct {
			PreToolUse []struct {
				Matcher string `json:"matcher"`
				Hooks   []struct {
					Command string `json:"command"`
				} `json:"hooks"`
			} `json:"PreToolUse"`
		} `json:"hooks"`
		Sandbox struct {
			Enabled  bool     `json:"enabled"`
			Excluded []string `json:"excludedCommands"`
		} `json:"sandbox"`
	}
	b, _ := os.ReadFile(path)
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.Model != "x" || !got.Sandbox.Enabled || len(got.Sandbox.Excluded) != 1 || got.Sandbox.Excluded[0] != "docker *" {
		t.Fatalf("unrelated settings changed:\n%s", b)
	}
	if len(got.Hooks.PreToolUse) != 1 || len(got.Hooks.PreToolUse[0].Hooks) != 1 || got.Hooks.PreToolUse[0].Hooks[0].Command != "/opt/other/guard" {
		t.Fatalf("the unrelated hook did not survive:\n%s", b)
	}
	if len(backups(t, path)) != 1 {
		t.Fatalf("want one backup, got %v", backups(t, path))
	}
	if cfg, _ := userconfig.Load(cfgPath); func() bool { on, set := cfg.AutostartUI(); return on || !set }() {
		t.Fatal("ui.autostart not turned off")
	}
	// without --purge the grants stay, and the output says where
	if _, err := os.Stat(filepath.Join(e.cfg, "watchdeck", "overrides.yaml")); err != nil {
		t.Fatal("overrides.yaml removed without --purge")
	}
	s := out.String()
	if !strings.Contains(s, "kept: your grants in") || !strings.Contains(s, "Done: removed") {
		t.Errorf("output lacks the kept note or the summary:\n%s", s)
	}
	// a second run has nothing left to do
	c, out = testConsole("", false, false)
	if code := runUninstall(c, uninstallOptions{}); code != 0 || !strings.Contains(out.String(), "nothing to remove") {
		t.Fatalf("second run: exit %d\n%s", code, out)
	}
}

func TestUninstallPurgeRemovesOwnDirsOnly(t *testing.T) {
	e := newTestEnv(t)
	own := []string{filepath.Join(e.cfg, "watchdeck"), filepath.Join(e.state, "watchdeck"), filepath.Join(e.cache, "watchdeck")}
	writeFile(t, filepath.Join(own[0], "overrides.yaml"), "version: 1\n")
	writeFile(t, filepath.Join(own[1], "activity.jsonl"), "{}\n")
	writeFile(t, filepath.Join(own[2], "index.json"), "{}\n")
	others := []string{filepath.Join(e.cfg, "other", "keep"), filepath.Join(e.state, "other", "keep"), filepath.Join(e.cache, "other", "keep")}
	for _, o := range others {
		writeFile(t, o, "x")
	}
	c, out := testConsole("", false, true)
	if code := runUninstall(c, uninstallOptions{purge: true}); code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	for _, d := range own {
		if _, err := os.Lstat(d); err == nil {
			t.Errorf("%s survived --purge", d)
		}
		if !strings.Contains(out.String(), "deleted "+d) {
			t.Errorf("output does not name %s:\n%s", d, out)
		}
	}
	for _, o := range others {
		if _, err := os.Stat(o); err != nil {
			t.Errorf("--purge removed %s", o)
		}
	}
}

// TestPurgeRefusesOtherDirs: --purge deletes only dirs named after this
// binary; another tool's config dir is refused, this binary's accepted, and
// a relative path refused.
func TestPurgeRefusesOtherDirs(t *testing.T) {
	home := t.TempDir()
	if err := purgeable(filepath.Join(home, ".config", "othertool")); err == nil {
		t.Error("--purge would delete ~/.config/othertool")
	}
	if err := purgeable(filepath.Join(home, ".config", paths.BinaryName)); err != nil {
		t.Errorf("--purge refuses ~/.config/%s: %v", paths.BinaryName, err)
	}
	if err := purgeable(filepath.Join(".config", paths.BinaryName)); err == nil {
		t.Error("--purge would delete a relative path")
	}
}

func TestUninstallBinary(t *testing.T) {
	t.Run("outside the installer dir stays", func(t *testing.T) {
		e := newTestEnv(t)
		bin := filepath.Join(e.home, "go", "bin", "watchdeck")
		writeFile(t, bin, "#!/bin/sh\n")
		fakeSelf(t, bin)
		installedSettings(t, e)
		c, out := testConsole("", false, true)
		if code := runUninstall(c, uninstallOptions{}); code != 0 {
			t.Fatalf("exit %d\n%s", code, out)
		}
		if _, err := os.Stat(bin); err != nil {
			t.Fatal("a binary outside the installer dir was removed")
		}
		if !strings.Contains(out.String(), "remove it with: rm "+bin) {
			t.Errorf("no rm hint:\n%s", out)
		}
	})
	t.Run("Homebrew gets brew uninstall", func(t *testing.T) {
		e := newTestEnv(t)
		bin := filepath.Join(e.home, "brew", "Cellar", "watchdeck", "0.2.0", "bin", "watchdeck")
		writeFile(t, bin, "#!/bin/sh\n")
		fakeSelf(t, bin)
		c, out := testConsole("", false, true)
		if code := runUninstall(c, uninstallOptions{}); code != 0 {
			t.Fatalf("exit %d\n%s", code, out)
		}
		if _, err := os.Stat(bin); err != nil || !strings.Contains(out.String(), "brew uninstall watchdeck") {
			t.Fatalf("Homebrew binary: err %v\n%s", err, out)
		}
	})
	t.Run("installer dir and link removed after the hooks", func(t *testing.T) {
		e := newTestEnv(t)
		bin := filepath.Join(e.home, ".local", "share", "watchdeck", "bin", "watchdeck")
		writeFile(t, bin, "#!/bin/sh\n")
		if r, err := filepath.EvalSymlinks(bin); err == nil {
			bin = r // t.TempDir may sit under a symlink (/var on macOS)
		}
		link := filepath.Join(e.home, ".local", "bin", "watchdeck")
		if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(bin, link); err != nil {
			t.Fatal(err)
		}
		fakeSelf(t, bin)
		path := installedSettings(t, e)
		c, out := testConsole("", false, true)
		if code := runUninstall(c, uninstallOptions{}); code != 0 {
			t.Fatalf("exit %d\n%s", code, out)
		}
		if _, err := os.Lstat(bin); err == nil {
			t.Error("installer binary survived")
		}
		if _, err := os.Lstat(link); err == nil {
			t.Error("~/.local/bin link survived")
		}
		s := out.String()
		if h, b := strings.Index(s, "removed 7 entries"), strings.Index(s, "deleted the binary"); h < 0 || b < 0 || b < h {
			t.Errorf("the binary must go after the hooks:\n%s", s)
		}
		if st, _ := settings.Inspect(path); st.Count() != 0 {
			t.Error("hooks remain")
		}
	})
	t.Run("keep-binary", func(t *testing.T) {
		e := newTestEnv(t)
		bin := filepath.Join(e.home, ".local", "share", "watchdeck", "bin", "watchdeck")
		writeFile(t, bin, "#!/bin/sh\n")
		fakeSelf(t, bin)
		installedSettings(t, e)
		c, out := testConsole("", false, true)
		if code := runUninstall(c, uninstallOptions{keepBinary: true}); code != 0 {
			t.Fatalf("exit %d\n%s", code, out)
		}
		if _, err := os.Stat(bin); err != nil {
			t.Fatal("--keep-binary removed the binary")
		}
	})
}

func TestUninstallDryRunWritesNothing(t *testing.T) {
	e := newTestEnv(t)
	path := installedSettings(t, e)
	before, _ := os.ReadFile(path)
	bin := filepath.Join(e.home, ".local", "share", "watchdeck", "bin", "watchdeck")
	writeFile(t, bin, "#!/bin/sh\n")
	fakeSelf(t, bin)
	writeFile(t, filepath.Join(e.state, "watchdeck", "activity.jsonl"), "{}\n")
	c, out := testConsole("", true, true) // even with --yes and a terminal
	if code := runUninstall(c, uninstallOptions{dryRun: true, purge: true}); code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if !strings.Contains(out.String(), "dry run: nothing changed") {
		t.Errorf("no dry-run line:\n%s", out)
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) || len(backups(t, path)) != 0 {
		t.Fatal("--dry-run changed the settings")
	}
	for _, p := range []string{bin, filepath.Join(e.state, "watchdeck", "activity.jsonl")} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("--dry-run removed %s", p)
		}
	}
}

func TestUninstallProjectSettings(t *testing.T) {
	e := newTestEnv(t)
	proj := filepath.Join(e.proj, ".claude", "settings.json")
	writeFile(t, proj, "{}\n")
	if _, err := settings.Install(proj, "/fake/bin/watchdeck"); err != nil {
		t.Fatal(err)
	}
	c, out := testConsole("", false, true)
	if code := runUninstall(c, uninstallOptions{}); code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if !strings.Contains(out.String(), "watchdeck enforce uninstall --project") {
		t.Errorf("no --project hint:\n%s", out)
	}
	if st, _ := settings.Inspect(proj); st.Count() == 0 {
		t.Fatal("the project file was changed without --project")
	}
	c, out = testConsole("", false, true)
	if code := runUninstall(c, uninstallOptions{project: true}); code != 0 {
		t.Fatalf("--project: exit %d\n%s", code, out)
	}
	if st, _ := settings.Inspect(proj); st.Count() != 0 || st.Excluded {
		t.Fatalf("--project left hooks: %+v\n%s", st, out)
	}
}

func TestUninstallUnwrapsMCPServers(t *testing.T) {
	e := newTestEnv(t)
	cfg := filepath.Join(e.claude, ".claude.json")
	data := []byte(`{"mcpServers":{"a":{"command":"/bin/a","args":["x"]},"b":{"command":"/bin/b"},"c":{"command":"/bin/c"}}}` + "\n")
	for _, n := range []string{"a", "b"} {
		out, _, _, err := mcpconfig.Wrap(data, n, "/fake/bin/watchdeck", false)
		if err != nil {
			t.Fatal(err)
		}
		data = out
	}
	writeFile(t, cfg, string(data))
	c, out := testConsole("", false, true)
	if code := runUninstall(c, uninstallOptions{}); code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	got, _ := os.ReadFile(cfg)
	list, err := mcpconfig.List(got)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"a": "/bin/a", "b": "/bin/b", "c": "/bin/c"}
	for _, s := range list {
		if s.Wrapped() || s.Command != want[s.Name] {
			t.Errorf("%s: wrapped %v, command %q\n%s", s.Name, s.Wrapped(), s.Command, got)
		}
	}
	if !strings.Contains(out.String(), "unwrapped a, b") {
		t.Errorf("output:\n%s", out)
	}
}

// withRecommended writes a user settings file holding the person's own deny
// and ask strings, installs the hooks into it and then the recommended rules
// watchdeck is missing (so a recommended string the person already wrote stays
// theirs). It returns the settings path and the strings watchdeck added.
func withRecommended(t *testing.T, e testEnv, deny, ask []string) (string, []string) {
	t.Helper()
	path := filepath.Join(e.claude, "settings.json")
	deny, ask = append([]string{}, deny...), append([]string{}, ask...) // [] in JSON, never null
	b, err := json.Marshal(map[string]any{"model": "x", "permissions": map[string][]string{"deny": deny, "ask": ask}})
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, string(b)+"\n")
	if _, err := settings.Install(path, "/fake/bin/watchdeck"); err != nil {
		t.Fatal(err)
	}
	if code, o, errOut := call(t, rulesCmd, "recommended", "--install", "--yes"); code != 0 {
		t.Fatalf("rules recommended --install: exit %d\n%s%s", code, o, errOut)
	}
	var added []string
	for _, e := range ledgerOf(t, e).Entries {
		added = append(added, e.Value)
	}
	for _, b := range backups(t, path) {
		os.Remove(b)
	}
	return path, added
}

func TestUninstallRemovesOwnedNativeRules(t *testing.T) {
	e := newTestEnv(t)
	path, added := withRecommended(t, e, []string{"Read(./secret.txt)"}, nil)
	if len(added) != 12 {
		t.Fatalf("installed %d recommended rules", len(added))
	}
	c, out := testConsole("", false, true)
	if code := runUninstall(c, uninstallOptions{}); code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if !strings.Contains(out.String(), "- remove the 12 rules watchdeck added to "+path+" (yours stay)") {
		t.Errorf("plan line missing:\n%s", out)
	}
	deny, ask := settingsPerms(t, path)
	if !slices.Equal(deny, []string{"Read(./secret.txt)"}) || len(ask) != 0 {
		t.Fatalf("after uninstall deny %v ask %v\n%s", deny, ask, out)
	}
	if led := ledgerOf(t, e); len(led.Entries) != 0 {
		t.Fatalf("ledger still claims %v", led.Entries)
	}
	// one backup for the rules (one ManageKeys write), one for the hooks
	if bk := backups(t, path); len(bk) != 2 {
		t.Fatalf("backups = %v, want 2", bk)
	}
	if st, _ := settings.Inspect(path); st.Count() != 0 || st.Excluded {
		t.Fatalf("hooks remain: %+v", st)
	}
	// a second run has nothing left to do
	c, out = testConsole("", false, false)
	if code := runUninstall(c, uninstallOptions{}); code != 0 || !strings.Contains(out.String(), "nothing to remove") {
		t.Fatalf("second run: exit %d\n%s", code, out)
	}
}

func TestUninstallLeavesUserStrings(t *testing.T) {
	e := newTestEnv(t)
	path, added := withRecommended(t, e, []string{"Read(~/.netrc)", "Read(./mine)"}, []string{"Edit(~/.zshrc)"})
	if len(added) != 10 || slices.Contains(added, "Read(~/.netrc)") || slices.Contains(added, "Edit(~/.zshrc)") {
		t.Fatalf("installed %v", added)
	}
	c, out := testConsole("", false, true)
	if code := runUninstall(c, uninstallOptions{}); code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if !strings.Contains(out.String(), "remove the 10 rules watchdeck added to") {
		t.Errorf("count wrong:\n%s", out)
	}
	deny, ask := settingsPerms(t, path)
	if !slices.Equal(deny, []string{"Read(~/.netrc)", "Read(./mine)"}) || !slices.Equal(ask, []string{"Edit(~/.zshrc)"}) {
		t.Fatalf("the person's strings changed: deny %v ask %v", deny, ask)
	}
}

func TestUninstallDryRunListsOwned(t *testing.T) {
	e := newTestEnv(t)
	path, added := withRecommended(t, e, nil, nil)
	before, _ := os.ReadFile(path)
	c, out := testConsole("", true, true)
	if code := runUninstall(c, uninstallOptions{dryRun: true}); code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	for _, v := range added {
		if !strings.Contains(out.String(), "        "+v+"\n") {
			t.Errorf("dry run does not list %s:\n%s", v, out)
		}
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) || len(backups(t, path)) != 0 {
		t.Fatal("--dry-run changed the settings")
	}
	if led := ledgerOf(t, e); len(led.Entries) != 12 {
		t.Fatalf("--dry-run changed the ledger: %d entries", len(led.Entries))
	}
}

func TestUninstallPurgeAfterRemoval(t *testing.T) {
	e := newTestEnv(t)
	path, _ := withRecommended(t, e, []string{"Read(./secret.txt)"}, nil)
	stateDir := filepath.Join(e.state, "watchdeck")
	c, out := testConsole("", false, true)
	if code := runUninstall(c, uninstallOptions{purge: true}); code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if _, err := os.Lstat(stateDir); err == nil {
		t.Fatalf("state dir survived --purge\n%s", out)
	}
	deny, ask := settingsPerms(t, path)
	if !slices.Equal(deny, []string{"Read(./secret.txt)"}) || len(ask) != 0 {
		t.Fatalf("owned strings left after --purge: deny %v ask %v\n%s", deny, ask, out)
	}
	s := out.String()
	if i, j := strings.Index(s, "removed 12 rules"), strings.Index(s, "deleted "+stateDir); i < 0 || j < 0 || i > j {
		t.Errorf("rules not removed before the state dir went:\n%s", s)
	}
}

// saveTestLedger writes a ledger of entries into the test state dir.
func saveTestLedger(t *testing.T, e testEnv, entries ...claudesettings.LedgerEntry) {
	t.Helper()
	led := &claudesettings.Ledger{V: 1, Entries: entries}
	if err := led.Save(filepath.Join(e.state, "watchdeck")); err != nil {
		t.Fatal(err)
	}
}

// TestUninstallRemovesOwnedInProjectFile: a string the ledger says
// watchdeck added to a project's .claude/settings.json is removed by a
// plain uninstall (no --project needed: the ledger names the file); the
// person's strings in that file stay.
func TestUninstallRemovesOwnedInProjectFile(t *testing.T) {
	e := newTestEnv(t)
	proj := filepath.Join(e.proj, ".claude", "settings.json")
	writeFile(t, proj, `{"permissions": {"deny": ["Bash(mine *)", "Read(/secrets/**)"]}}`+"\n")
	saveTestLedger(t, e, claudesettings.LedgerEntry{Path: proj, Key: claudesettings.KeyDeny, Value: "Read(/secrets/**)", RuleIDs: []string{"native:project:permissions.deny:00000000"}})
	c, out := testConsole("", false, true)
	if code := runUninstall(c, uninstallOptions{}); code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	deny, _ := settingsPerms(t, proj)
	if !slices.Equal(deny, []string{"Bash(mine *)"}) {
		t.Fatalf("project deny after uninstall %v\n%s", deny, out)
	}
	if len(backups(t, proj)) != 1 {
		t.Errorf("no backup of the project file")
	}
	if led := ledgerOf(t, e); len(led.Entries) != 0 {
		t.Fatalf("ledger still claims %v", led.Entries)
	}
	if !strings.Contains(out.String(), "remove the 1 rule watchdeck added to ~/proj/.claude/settings.json") {
		t.Errorf("plan line missing:\n%s", out)
	}
}

const purgeRefused = "NOT deleting the state dir: "

// TestUninstallPurgeRefusedWhenLedgerUnreadable: a ledger that does not
// load means the strings watchdeck added cannot be found, so --purge keeps
// the state dir (and the ledger in it) for a retry.
func TestUninstallPurgeRefusedWhenLedgerUnreadable(t *testing.T) {
	e := newTestEnv(t)
	stateDir := filepath.Join(e.state, "watchdeck")
	writeFile(t, filepath.Join(stateDir, claudesettings.LedgerFile), "not json at all {{{")
	c, out := testConsole("", false, true)
	code := runUninstall(c, uninstallOptions{purge: true})
	if _, err := os.Stat(stateDir); err != nil {
		t.Fatalf("the state dir went (exit %d)\n%s", code, out)
	}
	if !strings.Contains(out.String(), "  - "+purgeRefused) || !strings.Contains(out.String(), "the ledger stays so you can retry") {
		t.Errorf("no refusal line:\n%s", out)
	}
}

// TestUninstallPurgeRefusedWhenProjectFileGone: the ledger names a project
// settings file that no longer exists; its strings cannot be removed, so
// --purge keeps the state dir and says how many and where.
func TestUninstallPurgeRefusedWhenProjectFileGone(t *testing.T) {
	e := newTestEnv(t)
	stateDir := filepath.Join(e.state, "watchdeck")
	gone := filepath.Join(e.home, "gone", ".claude", "settings.json")
	saveTestLedger(t, e,
		claudesettings.LedgerEntry{Path: gone, Key: claudesettings.KeyDeny, Value: "Read(/a)", RuleIDs: []string{"x"}},
		claudesettings.LedgerEntry{Path: gone, Key: claudesettings.KeyAsk, Value: "Read(/b)", RuleIDs: []string{"y"}})
	writeFile(t, filepath.Join(e.cfg, "watchdeck", "config.yaml"), "installed_at: \"2026-10-19T00:00:00Z\"\n")
	c, out := testConsole("", false, true)
	code := runUninstall(c, uninstallOptions{purge: true})
	if _, err := os.Stat(stateDir); err != nil {
		t.Fatalf("the state dir went (exit %d)\n%s", code, out)
	}
	want := "  - " + purgeRefused + "2 rules watchdeck added could not be removed from ~/gone/.claude/settings.json; the ledger stays so you can retry"
	if !strings.Contains(out.String(), want) {
		t.Errorf("output lacks %q:\n%s", want, out)
	}
	if led := ledgerOf(t, e); len(led.Entries) != 2 {
		t.Errorf("the ledger changed: %v", led.Entries)
	}
	// The config dir is still purged: only the state dir is refused.
	if _, err := os.Stat(filepath.Join(e.cfg, "watchdeck")); err == nil {
		t.Errorf("config dir kept\n%s", out)
	}
}

// TestUninstallListsStuckRulesWithoutPurge: without --purge a ledger file
// whose strings cannot be removed is still named in the plan.
func TestUninstallListsStuckRulesWithoutPurge(t *testing.T) {
	e := newTestEnv(t)
	gone := filepath.Join(e.home, "gone", ".claude", "settings.json")
	saveTestLedger(t, e, claudesettings.LedgerEntry{Path: gone, Key: claudesettings.KeyDeny, Value: "Read(/a)", RuleIDs: []string{"x"}})
	c, out := testConsole("", false, true)
	runUninstall(c, uninstallOptions{})
	want := "  - 1 rule watchdeck added could not be removed from ~/gone/.claude/settings.json; it stays, and so does the ledger, so you can retry"
	if !strings.Contains(out.String(), want) {
		t.Errorf("output lacks %q:\n%s", want, out)
	}
	if strings.Contains(out.String(), purgeRefused) {
		t.Errorf("a run without --purge talks about the state dir:\n%s", out)
	}
}

// TestUninstallIgnoresOwnerlessLedgerPath: a ledger path outside any
// project whose entries no rule claims (a legacy or hand-edited ledger)
// holds nothing to remove, so it never blocks --purge and is not listed.
func TestUninstallIgnoresOwnerlessLedgerPath(t *testing.T) {
	e := newTestEnv(t)
	stateDir := filepath.Join(e.state, "watchdeck")
	local := filepath.Join(e.home, "proj", ".claude", "settings.local.json")
	saveTestLedger(t, e, claudesettings.LedgerEntry{Path: local, Key: claudesettings.KeyDeny, Value: "Read(/a)"})
	c, out := testConsole("", false, true)
	code := runUninstall(c, uninstallOptions{purge: true})
	if _, err := os.Stat(stateDir); err == nil {
		t.Fatalf("the state dir was kept for an ownerless ledger path (exit %d)\n%s", code, out)
	}
	if strings.Contains(out.String(), "could not be removed") || strings.Contains(out.String(), purgeRefused) {
		t.Errorf("an ownerless path was reported as stuck:\n%s", out)
	}
}

// TestUninstallReconcilesFirst: a string watchdeck added and the person
// removed by hand is forgotten before anything is removed (a recommended
// one is declined), never counts as stuck, and --purge goes ahead. A
// declined file that cannot be read only warns.
func TestUninstallReconcilesFirst(t *testing.T) {
	t.Run("purge", func(t *testing.T) {
		e := rulesEnv(t)
		path, _ := withRecommended(t, e, nil, nil)
		dropSetting(t, path, "deny", "Read(~/.netrc)")
		stateDir := filepath.Join(e.state, "watchdeck")
		c, out := testConsole("", false, true)
		if code := runUninstall(c, uninstallOptions{purge: true}); code != 0 {
			t.Fatalf("exit %d\n%s", code, out)
		}
		s := out.String()
		for _, want := range []string{
			"forget the 1 rule watchdeck added that you removed by hand",
			"- remove the 11 rules watchdeck added to ",
			"forgot 1 rule you had removed by hand; declined 1 recommended rule",
		} {
			if !strings.Contains(s, want) {
				t.Errorf("output lacks %q:\n%s", want, s)
			}
		}
		if strings.Contains(s, "could not be removed") || strings.Contains(s, purgeRefused) {
			t.Errorf("a hand-removed string counted as stuck:\n%s", s)
		}
		if i, j := strings.Index(s, "forgot 1 rule"), strings.Index(s, "removed 11 rules"); i < 0 || j < 0 || i > j {
			t.Errorf("not reconciled before the removal:\n%s", s)
		}
		if _, err := os.Lstat(stateDir); err == nil {
			t.Fatalf("state dir survived --purge\n%s", s)
		}
	})
	t.Run("keep", func(t *testing.T) {
		e := rulesEnv(t)
		path, _ := withRecommended(t, e, nil, nil)
		dropSetting(t, path, "ask", "Edit(~/.zshrc)")
		stateDir := filepath.Join(e.state, "watchdeck")
		// the dry run lists what it would forget and changes nothing
		c, out := testConsole("", false, true)
		if code := runUninstall(c, uninstallOptions{dryRun: true}); code != 0 || !strings.Contains(out.String(), "        Edit(~/.zshrc) in "+path+" permissions.ask\n") {
			t.Fatalf("dry run: exit %d\n%s", code, out)
		}
		if led := ledgerOf(t, e); len(led.Entries) != 12 {
			t.Fatalf("dry run changed the ledger: %d entries", len(led.Entries))
		}
		c, out = testConsole("", false, true)
		if code := runUninstall(c, uninstallOptions{}); code != 0 {
			t.Fatalf("exit %d\n%s", code, out)
		}
		if led := ledgerOf(t, e); len(led.Entries) != 0 {
			t.Fatalf("ledger still claims %v", led.Entries)
		}
		d, err := rulebook.LoadDeclined(stateDir)
		if err != nil || !slices.Equal(d.IntentIDs, []string{rulebook.IntentPrefix + rulebook.IntentID("Edit(~/.zshrc)")}) {
			t.Fatalf("declined %v, %v", d.IntentIDs, err)
		}
		// the next plan names the declined list among what stays
		c, out = testConsole("", false, true)
		if code := runUninstall(c, uninstallOptions{dryRun: true}); code != 0 || !strings.Contains(out.String(), "the recommended rules you declined in ") {
			t.Errorf("kept note does not name the declined list: exit %d\n%s", code, out)
		}
		// a --purge dry run names the declined file with the state dir
		c, out = testConsole("", false, true)
		if code := runUninstall(c, uninstallOptions{dryRun: true, purge: true}); code != 0 || !strings.Contains(out.String(), "- with "+rulebook.DeclinedFile+" (the recommended rules you declined)") {
			t.Errorf("purge dry run: exit %d\n%s", code, out)
		}
	})
	t.Run("corrupt declined file", func(t *testing.T) {
		e := rulesEnv(t)
		path, _ := withRecommended(t, e, nil, nil)
		dropSetting(t, path, "deny", "Read(~/.netrc)")
		writeFile(t, filepath.Join(e.state, "watchdeck", rulebook.DeclinedFile), "{not json")
		c, out := testConsole("", false, true)
		if code := runUninstall(c, uninstallOptions{}); code != 0 {
			t.Fatalf("exit %d\n%s", code, out)
		}
		s := out.String()
		if !strings.Contains(s, "warning: could not forget the rules you removed by hand") || !strings.Contains(s, "delete it to start the declined list over") {
			t.Errorf("no warning:\n%s", s)
		}
		if deny, ask := settingsPerms(t, path); len(deny)+len(ask) != 0 {
			t.Fatalf("the uninstall stopped at the warning: deny %v ask %v\n%s", deny, ask, s)
		}
	})
}
