package skills

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestMain keeps the suite hermetic: no test probes the machine's real
// managed-skills directory. TestEnterprise sets its own and restores it.
func TestMain(m *testing.M) {
	enterpriseSkillsDir = ""
	os.Exit(m.Run())
}

// fixtureHome copies testdata/home into a temp dir (keeping the beta symlink),
// rewrites the __HOME__ placeholder in installed_plugins.json to the copy's
// absolute path, and adds the two files git cannot be trusted to carry:
// proj/.git/HEAD (git refuses paths with a .git component) and
// .claude/settings.local.json (commonly globally ignored), which re-enables
// on@mkt after settings.json disabled it, so "later wins" is exercised.
func fixtureHome(t *testing.T) string {
	t.Helper()
	src, err := filepath.Abs(filepath.Join("..", "..", "testdata", "home"))
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "home")
	err = filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, path)
		target := filepath.Join(dst, rel)
		switch {
		case d.Type()&fs.ModeSymlink != 0:
			link, err := os.Readlink(path)
			if err != nil {
				return err
			}
			return os.Symlink(link, target)
		case d.IsDir():
			return os.MkdirAll(target, 0o755)
		default:
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if d.Name() == "installed_plugins.json" {
				b = bytes.ReplaceAll(b, []byte("__HOME__"), []byte(dst))
			}
			return os.WriteFile(target, b, 0o644)
		}
	})
	if err != nil {
		t.Fatalf("copy fixture: %v", err)
	}
	gitDir := filepath.Join(dst, "proj", ".git")
	if err := os.MkdirAll(gitDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gitDir, "HEAD"), []byte("ref: refs/heads/main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	local := filepath.Join(dst, ".claude", "settings.local.json")
	if err := os.WriteFile(local, []byte("{\n  \"enabledPlugins\": {\n    \"on@mkt\": true\n  }\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dst
}

func scan(t *testing.T, r Roots) []Skill {
	t.Helper()
	got, err := Scan(r)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	return got
}

func byKind(sk []Skill) map[Kind]int {
	m := map[Kind]int{}
	for _, s := range sk {
		m[s.Kind]++
	}
	return m
}

func find(sk []Skill, name string) *Skill {
	for i := range sk {
		if sk[i].Name == name {
			return &sk[i]
		}
	}
	return nil
}

func names(sk []Skill) []string {
	out := make([]string, len(sk))
	for i, s := range sk {
		out[i] = s.Kind.String() + ":" + s.Name
	}
	return out
}

func mustReal(t *testing.T, p string) string {
	t.Helper()
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestScanDefault(t *testing.T) {
	home := fixtureHome(t)
	got := scan(t, Roots{Home: home, Cwd: filepath.Join(home, "proj", "sub")})

	want := map[Kind]int{Personal: 3, Project: 1, Synced: 2, Plugin: 2}
	if counts := byKind(got); len(counts) != len(want) || counts[Personal] != 3 || counts[Project] != 1 || counts[Synced] != 2 || counts[Plugin] != 2 {
		t.Errorf("counts per kind = %v, want %v\n%s", counts, want, strings.Join(names(got), "\n"))
	}

	// Sorted by Kind then Name.
	wantOrder := []string{
		"personal:alpha", "personal:beta", "personal:broken",
		"project:epsilon",
		"claude.ai sync:delta", "claude.ai sync:gamma",
		"plugin:on-one", "plugin:on-two",
	}
	if got := names(got); strings.Join(got, ",") != strings.Join(wantOrder, ",") {
		t.Errorf("order = %v\nwant %v", got, wantOrder)
	}

	// beta: once, Root under .claude/skills, RealRoot under .agents/skills.
	beta := find(got, "beta")
	if beta == nil {
		t.Fatal("beta not found")
	}
	if beta.Root != filepath.Join(home, ".claude", "skills", "beta") {
		t.Errorf("beta.Root = %s", beta.Root)
	}
	if want := mustReal(t, filepath.Join(home, ".agents", "skills", "beta")); beta.RealRoot != want {
		t.Errorf("beta.RealRoot = %s, want %s", beta.RealRoot, want)
	}
	if beta.DirName != "beta" || beta.Kind != Personal || !beta.Enabled {
		t.Errorf("beta = %+v", *beta)
	}

	// Disabled plugin and decoy absent; enabled plugin tagged.
	if find(got, "off-one") != nil {
		t.Error("off@mkt skill present without All")
	}
	if find(got, "decoy") != nil {
		t.Error("decoy under plugins/marketplaces was discovered")
	}
	on := find(got, "on-one")
	if on.PluginID != "on@mkt" || !on.Enabled {
		t.Errorf("on-one = %+v", *on)
	}
	if !strings.HasPrefix(on.Root, filepath.Join(home, ".claude", "plugins", "cache", "mkt", "on")) {
		t.Errorf("on-one.Root = %s", on.Root)
	}

	// Project skill found from proj/sub.
	eps := find(got, "epsilon")
	if eps.Root != filepath.Join(home, "proj", ".claude", "skills", "epsilon") {
		t.Errorf("epsilon.Root = %s", eps.Root)
	}

	// Synced skills carry the account id and have no problems.
	gamma := find(got, "gamma")
	if gamma.SyncID != "acct_org" || len(gamma.Problems) != 0 {
		t.Errorf("gamma = %+v", *gamma)
	}

	// Frontmatter problems propagate; malformed SKILL.md still yields a Skill.
	broken := find(got, "broken")
	if broken == nil {
		t.Fatal("broken not found")
	}
	if len(broken.Problems) == 0 || !strings.Contains(strings.Join(broken.Problems, "\n"), "YAML parse error") {
		t.Errorf("broken.Problems = %v", broken.Problems)
	}
	if len(broken.Frontmatter.Problems) == 0 || broken.Frontmatter.Problems[0] != broken.Problems[0] {
		t.Errorf("frontmatter problems not propagated: %v vs %v", broken.Frontmatter.Problems, broken.Problems)
	}

	// Clean skills have no problems, and every RealRoot is unique.
	seen := map[string]bool{}
	for _, s := range got {
		if s.Name != "broken" && len(s.Problems) != 0 {
			t.Errorf("%s: unexpected problems %v", s.Name, s.Problems)
		}
		if seen[s.RealRoot] {
			t.Errorf("duplicate RealRoot %s", s.RealRoot)
		}
		seen[s.RealRoot] = true
		if s.Frontmatter.Name != "" && s.Frontmatter.Name != s.Name {
			t.Errorf("%s: Name should come from frontmatter", s.Name)
		}
	}
}

func TestScanAllIncludesDisabledPlugins(t *testing.T) {
	home := fixtureHome(t)
	got := scan(t, Roots{Home: home, Cwd: filepath.Join(home, "proj", "sub"), All: true})
	if c := byKind(got)[Plugin]; c != 3 {
		t.Fatalf("plugin count with All = %d, want 3\n%s", c, strings.Join(names(got), "\n"))
	}
	off := find(got, "off-one")
	if off == nil || off.Enabled || off.PluginID != "off@mkt" {
		t.Errorf("off-one = %+v", off)
	}
	if on := find(got, "on-one"); !on.Enabled {
		t.Error("on-one should be enabled (settings.local.json re-enables it)")
	}
	if find(got, "decoy") != nil {
		t.Error("decoy discovered under All")
	}
}

func TestDeepFindsNested(t *testing.T) {
	home := fixtureHome(t)
	cwd := filepath.Join(home, "proj", "sub")
	if got := scan(t, Roots{Home: home, Cwd: cwd}); find(got, "theta") != nil {
		t.Error("theta found without Deep")
	}
	got := scan(t, Roots{Home: home, Cwd: cwd, Deep: true})
	theta := find(got, "theta")
	if theta == nil || theta.Kind != Nested {
		t.Fatalf("theta = %+v", theta)
	}
	if c := byKind(got); c[Nested] != 1 || c[Project] != 1 {
		t.Errorf("counts = %v", c)
	}

	// From the project root, its own .claude/skills stays Project, not Nested.
	got = scan(t, Roots{Home: home, Cwd: filepath.Join(home, "proj"), Deep: true})
	if eps := find(got, "epsilon"); eps == nil || eps.Kind != Project {
		t.Errorf("epsilon = %+v", eps)
	}
	if c := byKind(got); c[Nested] != 1 || c[Project] != 1 {
		t.Errorf("counts from proj = %v", c)
	}
}

func TestProjectWalkStopsAtGitRoot(t *testing.T) {
	home := fixtureHome(t)
	// Cwd above proj: proj/.claude/skills is below, not above, so not found.
	got := scan(t, Roots{Home: home, Cwd: home})
	if find(got, "epsilon") != nil {
		t.Error("epsilon found from Home")
	}
	if c := byKind(got)[Personal]; c != 3 {
		t.Errorf("personal from Cwd=Home = %d (Home must not be treated as a project dir)", c)
	}
	// No Cwd at all: no project skills, nothing else changes.
	got = scan(t, Roots{Home: home})
	if c := byKind(got); c[Project] != 0 || c[Personal] != 3 || c[Synced] != 2 || c[Plugin] != 2 {
		t.Errorf("counts without Cwd = %v", c)
	}
}

func TestProjectSettingsOverride(t *testing.T) {
	home := fixtureHome(t)
	extra := filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(extra, []byte(`{"enabledPlugins":{"on@mkt":false}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	r := Roots{Home: home, Cwd: filepath.Join(home, "proj", "sub"), ProjectSettings: []string{extra}}
	if got := scan(t, r); byKind(got)[Plugin] != 0 {
		t.Errorf("later settings should disable on@mkt: %v", names(got))
	}
	r.All = true
	got := scan(t, r)
	if on := find(got, "on-one"); on == nil || on.Enabled {
		t.Errorf("on-one under All = %+v", on)
	}

	// Project-level .claude/settings.local.json at the git root is merged too.
	local := filepath.Join(home, "proj", ".claude", "settings.local.json")
	if err := os.WriteFile(local, []byte(`{"enabledPlugins":{"off@mkt":true}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	got = scan(t, Roots{Home: home, Cwd: filepath.Join(home, "proj", "sub")})
	if off := find(got, "off-one"); off == nil || !off.Enabled {
		t.Errorf("project settings.local.json should re-enable off@mkt: %v", names(got))
	}
}

func TestExtraDirsAndEnv(t *testing.T) {
	home := fixtureHome(t)
	r := Roots{
		Home:      home,
		ExtraDirs: []string{filepath.Join(home, "extra", "skills"), filepath.Join(home, "extra", "nofm")},
		Env:       map[string]string{"CLAUDE_SKILL_DIR": filepath.Join(home, ".agents", "skills", "beta")},
	}
	got := scan(t, r)
	c := byKind(got)
	if c[Dir] != 3 || c[Env] != 0 {
		t.Errorf("counts = %v\n%s", c, strings.Join(names(got), "\n"))
	}
	for _, n := range []string{"zeta", "eta"} {
		if s := find(got, n); s == nil || s.Kind != Dir || len(s.Problems) != 0 {
			t.Errorf("%s = %+v", n, s)
		}
	}
	nofm := find(got, "nofm")
	if nofm == nil || nofm.Kind != Dir || nofm.DirName != "nofm" {
		t.Fatalf("nofm = %+v", nofm)
	}
	if len(nofm.Problems) != 1 || nofm.Problems[0] != "SKILL.md: no frontmatter" {
		t.Errorf("nofm.Problems = %v", nofm.Problems)
	}
	// beta via CLAUDE_SKILL_DIR resolves to the personal copy: once, Personal.
	if beta := find(got, "beta"); beta == nil || beta.Kind != Personal {
		t.Errorf("beta = %+v", beta)
	}

	// CLAUDE_SKILL_DIR pointing at a fresh skill dir yields an Env skill.
	got = scan(t, Roots{Home: home, Env: map[string]string{"CLAUDE_SKILL_DIR": filepath.Join(home, "extra", "skills", "zeta")}})
	if z := find(got, "zeta"); z == nil || z.Kind != Env {
		t.Errorf("zeta via env = %+v", z)
	}
	// A dangling CLAUDE_SKILL_DIR is ignored; a missing --dir is an error.
	scan(t, Roots{Home: home, Env: map[string]string{"CLAUDE_SKILL_DIR": filepath.Join(home, "nope")}})
	if _, err := Scan(Roots{Home: home, ExtraDirs: []string{filepath.Join(home, "nope")}}); err == nil {
		t.Error("missing --dir should be an error")
	}
}

func TestEnterprise(t *testing.T) {
	home := fixtureHome(t)
	saved := enterpriseSkillsDir
	t.Cleanup(func() { enterpriseSkillsDir = saved })

	enterpriseSkillsDir = filepath.Join(home, "enterprise", "skills")
	got := scan(t, Roots{Home: home})
	if iota := find(got, "iota"); iota == nil || iota.Kind != Enterprise {
		t.Errorf("iota = %+v", iota)
	}

	enterpriseSkillsDir = filepath.Join(home, "missing-enterprise")
	if got := scan(t, Roots{Home: home}); byKind(got)[Enterprise] != 0 {
		t.Error("missing enterprise dir should be skipped")
	}
}

func TestSyncedManifestProblems(t *testing.T) {
	home := fixtureHome(t)
	acct := filepath.Join(home, ".claude", "skills", "synced", "acct_org")
	// A skill dir not in the manifest is flagged; a bad manifest flags every skill.
	if err := os.MkdirAll(filepath.Join(acct, "orphan"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(acct, "orphan", "SKILL.md"), []byte("---\nname: orphan\ndescription: x\n---\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := scan(t, Roots{Home: home})
	if o := find(got, "orphan"); o == nil || len(o.Problems) != 1 || o.Problems[0] != "not listed in manifest.json" {
		t.Errorf("orphan = %+v", o)
	}
	if g := find(got, "gamma"); len(g.Problems) != 0 {
		t.Errorf("gamma = %v", g.Problems)
	}
	if err := os.WriteFile(filepath.Join(acct, "manifest.json"), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	got = scan(t, Roots{Home: home})
	if g := find(got, "gamma"); len(g.Problems) != 1 || !strings.HasPrefix(g.Problems[0], "manifest.json:") {
		t.Errorf("gamma with bad manifest = %v", g.Problems)
	}
}

func TestMalformedRegistriesAreErrors(t *testing.T) {
	home := fixtureHome(t)
	reg := filepath.Join(home, ".claude", "plugins", "installed_plugins.json")
	if err := os.WriteFile(reg, []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Scan(Roots{Home: home}); err == nil || !strings.Contains(err.Error(), "installed_plugins.json") {
		t.Errorf("malformed registry: err = %v", err)
	}
	if err := os.Remove(reg); err != nil {
		t.Fatal(err)
	}
	if got := scan(t, Roots{Home: home}); byKind(got)[Plugin] != 0 {
		t.Error("missing registry should mean no plugins, not an error")
	}

	bad := filepath.Join(home, ".claude", "settings.local.json")
	if err := os.WriteFile(filepath.Join(home, ".claude", "plugins", "installed_plugins.json"), []byte(`{"version":2,"plugins":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bad, []byte("nope"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Scan(Roots{Home: home}); err == nil || !strings.Contains(err.Error(), "settings.local.json") {
		t.Errorf("malformed settings: err = %v", err)
	}
}

func TestRegistryV1Shape(t *testing.T) {
	home := fixtureHome(t)
	reg := filepath.Join(home, ".claude", "plugins", "installed_plugins.json")
	v1 := `{"version":1,"plugins":{"on@mkt":{"installPath":"` + filepath.Join(home, ".claude", "plugins", "cache", "mkt", "on", "1.0.0") + `","version":"1.0.0"}}}`
	if err := os.WriteFile(reg, []byte(v1), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := scan(t, Roots{Home: home}); byKind(got)[Plugin] != 2 {
		t.Errorf("v1 single-object registry: %v", names(got))
	}
}

func TestKindString(t *testing.T) {
	want := []string{"personal", "project", "nested", "claude.ai sync", "plugin", "enterprise", "dir", "env"}
	for i, w := range want {
		if got := Kind(i).String(); got != w {
			t.Errorf("Kind(%d) = %q, want %q", i, got, w)
		}
	}
	if got := Kind(99).String(); got != "Kind(99)" {
		t.Errorf("Kind(99) = %q", got)
	}
}
