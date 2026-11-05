package manifest

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// widenU applies an override as the trusted user source; the project
// source is exercised in TestProjectOverrideIsClipped.
func widenU(b Effective, o Override) Effective { e, _ := Widen(b, o, SourceUser); return e }

func TestProjectOverrideIsClipped(t *testing.T) {
	all, local := NetAll, NetLocalhost
	yes := true
	project := Overrides{
		Defaults: Override{AutoAllow: &yes, Caches: true},
		Skills: map[string]Override{
			"pdf":  {Network: &all, Write: []string{"${CWD}/build", "~/Library/Caches/pip", "/etc"}, Env: []string{"API_KEY"}},
			"xlsx": {Network: &local, Read: []string{"${TMP}/in", "~/Documents"}},
		},
	}
	eff, ignored := Grant("pdf", Overrides{}, project)
	if eff.Network != NetNone {
		t.Errorf("project network all honoured: %s", eff.Network)
	}
	if eff.AutoAllow {
		t.Error("project auto_allow honoured")
	}
	if !reflect.DeepEqual(eff.Write, []string{"${CWD}", "${TMP}", "${CWD}/build"}) {
		t.Errorf("Write = %q", eff.Write)
	}
	if !reflect.DeepEqual(eff.Env, Default().Env) {
		t.Errorf("Env = %q", eff.Env)
	}
	want := []string{
		"project override ignored: caches",
		"project override ignored: auto_allow",
		"project override ignored: network: all (only the user override can grant this)",
		"project override ignored: write: ~/Library/Caches/pip (outside ${CWD})",
		"project override ignored: write: /etc (outside ${CWD})",
		"project override ignored: env: API_KEY",
	}
	if !reflect.DeepEqual(ignored, want) {
		t.Errorf("ignored =\n%q\nwant\n%q", ignored, want)
	}

	eff, ignored = Grant("xlsx", Overrides{}, project)
	if eff.Network != NetLocalhost {
		t.Errorf("project localhost should be honoured, got %s", eff.Network)
	}
	if eff.Read != nil {
		t.Errorf("Read should stay nil (open) when the base is open: %q", eff.Read)
	}
	if len(ignored) != 3 || ignored[2] != "project override ignored: read: ~/Documents (outside ${CWD})" {
		t.Errorf("ignored = %q", ignored)
	}

	// the user layer is applied after the project layer and is not clipped
	user := Overrides{Skills: map[string]Override{"pdf": {Network: &all, AutoAllow: &yes, Caches: true}}}
	eff, _ = Grant("pdf", user, project)
	if eff.Network != NetAll || !eff.AutoAllow || !contains(eff.Write, "~/.cache") {
		t.Errorf("user grant not applied: %+v", eff)
	}
}

func TestClipScriptsOnlyWiden(t *testing.T) {
	req := Manifest{Version: 1, Scripts: []string{"bin/**"}}
	eff, _ := Clip(req, Default())
	if !reflect.DeepEqual(eff.Scripts, []string{"scripts/**", "bin/**"}) {
		t.Errorf("Scripts = %q, want the grant's globs kept and the request's appended", eff.Scripts)
	}
	req = Manifest{Version: 1, Scripts: []string{"nothing/**"}}
	eff, _ = Clip(req, Default())
	if !contains(eff.Scripts, "scripts/**") {
		t.Errorf("request shrank script coverage: %q", eff.Scripts)
	}
}

func TestResolveProjectScopedFollowsSymlinks(t *testing.T) {
	outside := t.TempDir()
	cwd := t.TempDir()
	tmp := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(cwd, "build")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(cwd, "out"), 0o755); err != nil {
		t.Fatal(err)
	}
	realCWD, _ := filepath.EvalSymlinks(cwd)
	realTMP, _ := filepath.EvalSymlinks(tmp)

	project := Overrides{Skills: map[string]Override{"pdf": {Write: []string{"./build", "./out", "./new/dir", "${TMP}/x"}}}}
	eff, ignored := Grant("pdf", Overrides{}, project)
	if len(ignored) != 0 {
		t.Fatalf("lexical check should accept all: %q", ignored)
	}
	if want := []string{"${CWD}/build", "${CWD}/out", "${CWD}/new/dir", "${TMP}/x"}; !reflect.DeepEqual(eff.ProjectScoped, want) {
		t.Fatalf("ProjectScoped = %q", eff.ProjectScoped)
	}

	eff, ignored = ResolveProjectScoped(eff, realCWD, realTMP)
	if want := []string{"${CWD}", "${TMP}", "${CWD}/out", "${CWD}/new/dir", "${TMP}/x"}; !reflect.DeepEqual(eff.Write, want) {
		t.Errorf("Write = %q, want %q", eff.Write, want)
	}
	if len(ignored) != 1 || !strings.HasPrefix(ignored[0], "project override ignored: ${CWD}/build (resolves to ") {
		t.Errorf("ignored = %q", ignored)
	}

	// a symlinked ancestor of a path that does not exist yet is also caught
	project = Overrides{Skills: map[string]Override{"pdf": {Write: []string{"./build/sub/dir"}}}}
	eff, _ = Grant("pdf", Overrides{}, project)
	eff, ignored = ResolveProjectScoped(eff, realCWD, realTMP)
	if len(ignored) != 1 || contains(eff.Write, "${CWD}/build/sub/dir") {
		t.Errorf("symlinked ancestor not caught: write=%q ignored=%q", eff.Write, ignored)
	}

	// user-sourced entries are never re-checked
	user := Overrides{Skills: map[string]Override{"pdf": {Write: []string{"~/anything"}}}}
	eff, _ = Grant("pdf", user, Overrides{})
	eff, ignored = ResolveProjectScoped(eff, realCWD, realTMP)
	if len(ignored) != 0 || !contains(eff.Write, "~/anything") {
		t.Errorf("user entry touched: write=%q ignored=%q", eff.Write, ignored)
	}
}

// TestIntersectKeepsProjectScoped: a run that touches two skills intersects
// their grants; the project marks must survive, or ResolveProjectScoped sees
// nothing to re-check and a symlinked project write path escapes the project.
func TestIntersectKeepsProjectScoped(t *testing.T) {
	outside := t.TempDir()
	cwd := t.TempDir()
	tmp := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(cwd, "build")); err != nil {
		t.Fatal(err)
	}
	realCWD, _ := filepath.EvalSymlinks(cwd)
	realTMP, _ := filepath.EvalSymlinks(tmp)

	project := Overrides{Defaults: Override{Write: []string{"${CWD}/build"}}}
	a, _ := Grant("a", Overrides{}, project)
	b, _ := Grant("b", Overrides{}, project)
	eff := Intersect(a, b)
	if !contains(eff.ProjectScoped, "${CWD}/build") {
		t.Fatalf("ProjectScoped lost in Intersect: %q", eff.ProjectScoped)
	}
	eff, ignored := ResolveProjectScoped(eff, realCWD, realTMP)
	if contains(eff.Write, "${CWD}/build") || len(ignored) != 1 {
		t.Errorf("symlinked project write kept: write=%q ignored=%q", eff.Write, ignored)
	}
}

// TestClipRequestPathsFollowSymlinks: a manifest that narrows the default
// write grant to ${CWD}/build (or below) must not end up writing through a
// repository symlink to a directory outside the project, with or without a
// project file granting ${CWD}/build. An entry the grant holds exactly is the
// grant's and is left alone.
func TestClipRequestPathsFollowSymlinks(t *testing.T) {
	outside := t.TempDir()
	cwd := t.TempDir()
	tmp := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(cwd, "build")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(cwd, "out"), 0o755); err != nil {
		t.Fatal(err)
	}
	realCWD, _ := filepath.EvalSymlinks(cwd)
	realTMP, _ := filepath.EvalSymlinks(tmp)

	var req Manifest
	req.Filesystem.Write = []string{"${CWD}/build", "${CWD}/build/out", "${CWD}/out"}
	for _, tc := range []struct {
		name    string
		project Overrides
	}{
		{"no project file", Overrides{}},
		{"project grants build", Overrides{Defaults: Override{Write: []string{"${CWD}/build"}}}},
	} {
		grant, _ := Grant("pdf", Overrides{}, tc.project)
		eff, _ := Clip(req, grant)
		eff, ignored := ResolveProjectScoped(eff, realCWD, realTMP)
		if want := []string{"${CWD}/out"}; !reflect.DeepEqual(eff.Write, want) {
			t.Errorf("%s: Write = %q, want %q (ignored %q)", tc.name, eff.Write, want, ignored)
		}
		if len(ignored) != 2 {
			t.Errorf("%s: ignored = %q", tc.name, ignored)
		}
	}

	// a user grant of the exact entry is the user's choice
	user := Overrides{Skills: map[string]Override{"pdf": {Write: []string{"${CWD}/build"}}}}
	grant, _ := Grant("pdf", user, Overrides{})
	req.Filesystem.Write = []string{"${CWD}/build"}
	eff, _ := Clip(req, grant)
	eff, ignored := ResolveProjectScoped(eff, realCWD, realTMP)
	if !contains(eff.Write, "${CWD}/build") || len(ignored) != 0 {
		t.Errorf("user-granted entry touched: write=%q ignored=%q", eff.Write, ignored)
	}
}
