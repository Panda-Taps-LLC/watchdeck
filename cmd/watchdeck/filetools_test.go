package main

import (
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Panda-Taps-LLC/watchdeck/internal/claudesettings"
	"github.com/Panda-Taps-LLC/watchdeck/internal/rulebook"
	"github.com/Panda-Taps-LLC/watchdeck/internal/settings"
)

// noManaged points the managed-settings directory at an empty temp dir so a
// test never reads the real /Library or /etc.
func noManaged(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	old := claudesettings.ManagedDirOverride
	claudesettings.ManagedDirOverride = func() string { return dir }
	t.Cleanup(func() { claudesettings.ManagedDirOverride = old })
}

// recommendedSettings is a settings.json holding every recommended native
// rule except the values in skip.
func recommendedSettings(t *testing.T, skip ...string) string {
	t.Helper()
	perms := map[string][]string{}
	for _, r := range rulebook.Recommended() {
		if slices.Contains(skip, r.Value) {
			continue
		}
		k := strings.TrimPrefix(r.Source.Key, "permissions.")
		perms[k] = append(perms[k], r.Value)
	}
	b, err := json.Marshal(map[string]any{"permissions": perms})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func installedExtra(t *testing.T, path string) string {
	t.Helper()
	inst, err := settings.InstalledExtra(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Join(inst, ", ")
}

const (
	preFiles  = "PreToolUse Read|Write|Edit|MultiEdit|NotebookEdit"
	preWrites = "PreToolUse Write|Edit|MultiEdit|NotebookEdit"
	writes    = "Write|Edit|MultiEdit|NotebookEdit"
)

// TestFilesHookedWhenNativeDeclined: `enforce install` registers the whole
// file-tools group while a recommended native rule is missing, only the
// write tools (the cred-in-write asks have no native twin) once all twelve
// are there, and Grep|Glob only for a search gate.
func TestFilesHookedWhenNativeDeclined(t *testing.T) {
	e := newTestEnv(t)
	noManaged(t)
	user := filepath.Join(e.claude, "settings.json")
	install := func() {
		t.Helper()
		if code := cmdEnforce([]string{"install"}); code != 0 {
			t.Fatalf("install = %d", code)
		}
	}

	writeFile(t, user, recommendedSettings(t, "Read(~/.ssh/id_*)")) // eleven strings
	install()
	if got := installedExtra(t, user); got != preFiles {
		t.Fatalf("eleven strings: extra = %q", got)
	}

	// all twelve: the same install narrows the group to the write tools
	writeFile(t, user, recommendedSettings(t))
	install()
	if got := installedExtra(t, user); got != preWrites {
		t.Fatalf("twelve strings: extra = %q", got)
	}
	if st, _ := settings.Inspect(user); !st.Complete {
		t.Fatalf("base hooks: %+v", st)
	}

	// a search gate adds Grep|Glob, and nothing else changes
	writeFile(t, filepath.Join(e.cfg, "watchdeck", "overrides.yaml"), "version: 2\nsubjects:\n  - {kind: tool, name: s, match: {tools: [Grep, Glob]}, paths: {deny: ['~/secrets/**']}}\n")
	install()
	if got := installedExtra(t, user); got != preWrites+", PreToolUse Glob|Grep" {
		t.Fatalf("search gate: extra = %q", got)
	}

	// native rules only in the project file do not cover a user install
	writeFile(t, filepath.Join(e.cfg, "watchdeck", "overrides.yaml"), "version: 2\n")
	writeFile(t, user, "{}")
	writeFile(t, filepath.Join(e.proj, ".claude", "settings.json"), recommendedSettings(t))
	install()
	if got := installedExtra(t, user); got != preFiles {
		t.Fatalf("project-only native, user install: extra = %q", got)
	}
}

// TestDoctorFileToolsLine: every form of doctor's file-tools check.
func TestDoctorFileToolsLine(t *testing.T) {
	e := newTestEnv(t)
	noManaged(t)
	passSelfTest(t)
	user := filepath.Join(e.claude, "settings.json")
	ov := filepath.Join(e.cfg, "watchdeck", "overrides.yaml")
	bin := filepath.Join(e.home, "bin", "watchdeck")
	writeFile(t, bin, "#!/bin/sh\n")
	const credWhy = "hooked for Write, Edit, MultiEdit, NotebookEdit (cred-in-write/aws-access-key-id asks before a write)"
	cases := []struct {
		name, settingsJSON, policy, group, status, msg string
	}{
		{"nothing covered, all hooked", "{}", "version: 2\n", settings.MatcherFiles, statusPass,
			"hooked for Read, Write, Edit, MultiEdit, NotebookEdit (secrets-read/read-ssh-private-key asks before a read)"},
		{"native covers reads", recommendedSettings(t), "version: 2\n", writes, statusPass,
			credWhy + "; Read not hooked, the recommended Claude Code rules cover reads"},
		{"hooked though nothing needs it", recommendedSettings(t), "version: 2\n", settings.MatcherFiles, statusPass,
			credWhy + "; Read hooked though nothing needs it (watchdeck enforce install drops it)"},
		{"needed, not hooked", recommendedSettings(t), "version: 2\nrules:\n  - {id: no-pem, tool: Read, match: {regex: '\\.pem$'}, action: ask}\n", writes, statusWarn,
			credWhy + "; Read not hooked but your rule no-pem needs it: watchdeck enforce install"},
		{"native not all installed", recommendedSettings(t, "Read(~/.ssh/id_*)"), "version: 2\n", writes, statusWarn,
			credWhy + "; Read not hooked but secrets-read/read-ssh-private-key asks before a read (the recommended Claude Code rules are not all installed): watchdeck enforce install"},
		{"pack deny", recommendedSettings(t), "version: 2\nrule_overrides: {secrets-read/read-ssh-private-key: {action: deny}}\n", settings.MatcherFiles, statusPass,
			"hooked for Read, Write, Edit, MultiEdit, NotebookEdit (secrets-read/read-ssh-private-key set to deny)"},
		{"no rule watches", "{}", "version: 2\npacks: {secrets-read: off, persistence: off, cred-in-write: off}\n", "", statusPass,
			"Read, Write, Edit, MultiEdit, NotebookEdit not hooked, no enabled rule watches them"},
		{"mixed native and none", recommendedSettings(t), "version: 2\npacks: {cred-in-write: off}\n", "", statusPass,
			"Read not hooked, the recommended Claude Code rules cover reads; Write, Edit, MultiEdit not hooked, the recommended Claude Code rules cover edits; NotebookEdit not hooked, no enabled rule watches it"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			writeFile(t, user, c.settingsJSON)
			writeFile(t, ov, c.policy)
			extra := settings.Extra{}
			if c.group != "" {
				extra.Pre = []string{c.group}
			}
			if _, err := settings.InstallWith(user, bin, extra); err != nil {
				t.Fatal(err)
			}
			if got := checkNamed(t, runDoctor(false), "file tools"); got.Status != c.status || got.Message != c.msg {
				t.Fatalf("got  %s %q\nwant %s %q", got.Status, got.Message, c.status, c.msg)
			}
		})
	}
}

// TestSetupDefaultLeavesReadUnhooked: setup --yes on a fresh home with the
// default packs adds the recommended native rules first, so the hook's
// file-tools group is the write tools only: Read is left to Claude Code's
// own rules.
func TestSetupDefaultLeavesReadUnhooked(t *testing.T) {
	e := newTestEnv(t)
	noManaged(t)
	passSelfTest(t)
	user := filepath.Join(e.claude, "settings.json")
	c, out := testConsole("", false, true)
	if code := runSetup(c, setupOptions{}); code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if got := installedExtra(t, user); got != preWrites {
		t.Fatalf("extra = %q, want %q\n%s", got, preWrites, out)
	}
}
