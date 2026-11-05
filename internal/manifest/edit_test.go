package manifest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func boolp(v bool) *bool      { return &v }
func netp(n Network) *Network { return &n }
func mustApply(t *testing.T, o Overrides, skill string, e Edit, wantChanged bool) Overrides {
	t.Helper()
	out, changed, err := Apply(o, skill, e)
	if err != nil {
		t.Fatalf("Apply(%s, %+v): %v", skill, e, err)
	}
	if changed != wantChanged {
		t.Fatalf("Apply(%s, %+v): changed = %v, want %v", skill, e, changed, wantChanged)
	}
	return out
}

func TestApplyWidenAndRevoke(t *testing.T) {
	var o Overrides

	// add two writes (relative rooted at ${CWD}), then take one back
	o = mustApply(t, o, "pdf", Edit{AddWrite: []string{"build", "~/Documents"}}, true)
	if got := o.Skills["pdf"].Write; !reflect.DeepEqual(got, []string{"${CWD}/build", "~/Documents"}) {
		t.Fatalf("write after add = %v", got)
	}
	o = mustApply(t, o, "pdf", Edit{AddWrite: []string{"./build/"}}, false) // same path, normalised
	o = mustApply(t, o, "pdf", Edit{RemoveWrite: []string{"./build"}}, true)
	if got := o.Skills["pdf"].Write; !reflect.DeepEqual(got, []string{"~/Documents"}) {
		t.Fatalf("write after remove = %v", got)
	}
	o = mustApply(t, o, "pdf", Edit{RemoveWrite: []string{"/nowhere"}}, false)

	// network all, idempotent, then none (revoke keeps the key, grants only widen)
	o = mustApply(t, o, "pdf", Edit{Network: netp(NetAll)}, true)
	o = mustApply(t, o, "pdf", Edit{Network: netp(NetAll)}, false)
	o = mustApply(t, o, "pdf", Edit{Network: netp(NetNone)}, true)
	if n := o.Skills["pdf"].Network; n == nil || *n != NetNone {
		t.Fatalf("network = %v", n)
	}
	o = mustApply(t, o, "pdf", Edit{ClearNetwork: true}, true)
	if o.Skills["pdf"].Network != nil {
		t.Fatal("network key not cleared")
	}
	o = mustApply(t, o, "pdf", Edit{ClearNetwork: true}, false)

	// caches on/off, auto on/off/clear
	o = mustApply(t, o, "pdf", Edit{Caches: boolp(true)}, true)
	o = mustApply(t, o, "pdf", Edit{Caches: boolp(true)}, false)
	o = mustApply(t, o, "pdf", Edit{Caches: boolp(false)}, true)
	o = mustApply(t, o, "pdf", Edit{AutoAllow: boolp(true)}, true)
	o = mustApply(t, o, "pdf", Edit{AutoAllow: boolp(false)}, true)
	if a := o.Skills["pdf"].AutoAllow; a == nil || *a {
		t.Fatalf("auto_allow = %v", a)
	}
	o = mustApply(t, o, "pdf", Edit{ClearAutoAllow: true}, true)
	if o.Skills["pdf"].AutoAllow != nil {
		t.Fatal("auto_allow not cleared")
	}

	// env and read through the API
	o = mustApply(t, o, "pdf", Edit{AddEnv: []string{"FOO", "BAR"}, AddRead: []string{"~/data"}}, true)
	o = mustApply(t, o, "pdf", Edit{RemoveEnv: []string{"FOO", "NOPE"}}, true)
	if got := o.Skills["pdf"]; !reflect.DeepEqual(got.Env, []string{"BAR"}) || !reflect.DeepEqual(got.Read, []string{"~/data"}) {
		t.Fatalf("env/read = %v / %v", got.Env, got.Read)
	}

	// Removing the last entries deletes the (now empty) block.
	o = mustApply(t, o, "pdf", Edit{RemoveEnv: []string{"BAR"}, RemoveRead: []string{"~/data"}, RemoveWrite: []string{"~/Documents"}}, true)
	if _, ok := o.Skills["pdf"]; ok {
		t.Fatalf("empty block should be deleted: %+v", o.Skills["pdf"])
	}
	if o.Skills != nil {
		t.Fatalf("skills map should be nil when empty: %v", o.Skills)
	}

	// Reset deletes a block in one go; a second reset changes nothing.
	o = mustApply(t, o, "pdf", Edit{Network: netp(NetAll), Caches: boolp(true), AutoAllow: boolp(true)}, true)
	o = mustApply(t, o, "pdf", Edit{Reset: true}, true)
	if _, ok := o.Skills["pdf"]; ok {
		t.Fatal("reset did not delete the block")
	}
	o = mustApply(t, o, "pdf", Edit{Reset: true}, false)

	// Reset combined with a field: the block is rebuilt from scratch.
	o = mustApply(t, o, "pdf", Edit{Network: netp(NetAll), Caches: boolp(true)}, true)
	o = mustApply(t, o, "pdf", Edit{Reset: true, AutoAllow: boolp(true)}, true)
	if got := o.Skills["pdf"]; got.Network != nil || got.Caches || got.AutoAllow == nil || !*got.AutoAllow {
		t.Fatalf("reset+auto = %+v", got)
	}

	// The input is never modified.
	in := Overrides{Skills: map[string]Override{"x": {Write: []string{"~/a"}}}}
	before := RenderOverrides(in)
	out := mustApply(t, in, "x", Edit{AddWrite: []string{"~/b"}, Network: netp(NetLocalhost)}, true)
	if RenderOverrides(in) != before {
		t.Fatal("Apply mutated its input")
	}
	if len(out.Skills["x"].Write) != 2 || len(in.Skills["x"].Write) != 1 {
		t.Fatalf("in/out writes = %v / %v", in.Skills["x"].Write, out.Skills["x"].Write)
	}
	if e := (Edit{}); !e.Empty() {
		t.Error("zero Edit should be Empty")
	}
	if e := (Edit{Reset: true}); e.Empty() {
		t.Error("Reset edit should not be Empty")
	}
}

func TestApplyRejectsInvalid(t *testing.T) {
	base := Overrides{Skills: map[string]Override{"pdf": {Write: []string{"~/Documents"}}}}
	snapshot := RenderOverrides(base)
	cases := []struct {
		name  string
		skill string
		e     Edit
		want  string // substring of the error
	}{
		{"deny path", "pdf", Edit{AddWrite: []string{"~/.ssh"}}, "built-in deny"},
		{"deny pattern", "pdf", Edit{AddRead: []string{"${CWD}/.env"}}, "built-in deny"},
		{"bad env", "pdf", Edit{AddEnv: []string{"lower"}}, "^[A-Z_][A-Z0-9_]*$"},
		{"empty path", "pdf", Edit{AddWrite: []string{""}}, "empty path"},
		{"dotdot", "pdf", Edit{AddWrite: []string{"/tmp/../etc"}}, "'..'"},
		{"bad name slash", "../x", Edit{Network: netp(NetAll)}, "invalid skill name"},
		{"bad name space", "a b", Edit{Network: netp(NetAll)}, "invalid skill name"},
		{"bad name empty", "", Edit{Network: netp(NetAll)}, "invalid skill name"},
		{"bad name semicolon", "x;rm", Edit{Network: netp(NetAll)}, "invalid skill name"},
		{"bad name dot", ".", Edit{Network: netp(NetAll)}, "invalid skill name"},
		{"bad name dotdot", "..", Edit{Network: netp(NetAll)}, "invalid skill name"},
		{"bad name too long", strings.Repeat("a", 129), Edit{Network: netp(NetAll)}, "invalid skill name"},
		{"network conflict", "pdf", Edit{Network: netp(NetAll), ClearNetwork: true}, "exclusive"},
		{"auto conflict", "pdf", Edit{AutoAllow: boolp(true), ClearAutoAllow: true}, "exclusive"},
	}
	for _, c := range cases {
		out, changed, err := Apply(base, c.skill, c.e)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want containing %q", c.name, err, c.want)
		}
		if changed {
			t.Errorf("%s: changed = true", c.name)
		}
		if RenderOverrides(out) != snapshot {
			t.Errorf("%s: returned overrides differ from the input", c.name)
		}
	}
	if RenderOverrides(base) != snapshot {
		t.Fatal("input mutated by a failed Apply")
	}
	for _, ok := range []string{"*", "pdf", "my.skill_v2-beta", "A1", "...", ".hidden", "_x", "a-", strings.Repeat("a", 128)} {
		if !ValidSkillName(ok) {
			t.Errorf("ValidSkillName(%q) = false", ok)
		}
	}
	for _, bad := range []string{"", "a/b", "a b", "*x", "**", "a\tb", "$(x)", "ünï", "-x", "--network", ".", "..", strings.Repeat("a", 129), "x|y", "a:b"} {
		if ValidSkillName(bad) {
			t.Errorf("ValidSkillName(%q) = true", bad)
		}
	}
}

// TestApplyRefusesAbsoluteDenyPath: with Edit.Home set (the CLI sets it),
// an absolute spelling of a built-in deny path, a path under one, a symlink
// to one and an absolute .env are refused with the ~/.ssh message.
func TestApplyRefusesAbsoluteDenyPath(t *testing.T) {
	home := t.TempDir() // under /var/folders on macOS: a symlinked ancestor
	realHome, err := filepath.EvalSymlinks(home)
	if err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(filepath.Join(home, ".ssh"), 0o700)
	os.MkdirAll(filepath.Join(home, "proj"), 0o755)
	if err := os.Symlink(filepath.Join(home, ".ssh"), filepath.Join(home, "proj", "keys")); err != nil {
		t.Fatal(err)
	}
	_, _, symErr := Apply(Overrides{}, "canary-basic", Edit{AddWrite: []string{"~/.ssh"}})
	const sshMsg = "skills.canary-basic.write[0]: cannot grant built-in deny path ~/.ssh"
	if symErr == nil || symErr.Error() != sshMsg {
		t.Fatalf("~/.ssh: err = %v, want %q", symErr, sshMsg)
	}
	cases := []struct {
		name, skill string
		e           Edit
		want        string
	}{
		{"abs .ssh", "canary-basic", Edit{AddWrite: []string{home + "/.ssh"}}, sshMsg},
		{"abs .ssh trailing slash", "canary-basic", Edit{AddWrite: []string{home + "/.ssh/"}}, sshMsg},
		{"abs .ssh/sub", "canary-basic", Edit{AddWrite: []string{home + "/.ssh/sub"}}, sshMsg},
		{"real-path spelling", "canary-basic", Edit{AddWrite: []string{realHome + "/.ssh"}}, sshMsg},
		{"symlink to .ssh", "canary-basic", Edit{AddWrite: []string{home + "/proj/keys"}}, sshMsg},
		{"under a symlink to .ssh", "canary-basic", Edit{AddWrite: []string{home + "/proj/keys/new"}}, sshMsg},
		{"${HOME} spelling", "canary-basic", Edit{AddWrite: []string{"${HOME}/.ssh"}}, sshMsg},
		{"abs .env", "canary-basic", Edit{AddWrite: []string{home + "/proj/.env"}}, "skills.canary-basic.write[0]: cannot grant built-in deny pattern **/.env"},
		{"abs .aws read", "canary-basic", Edit{AddRead: []string{home + "/.aws/credentials"}}, "skills.canary-basic.read[0]: cannot grant built-in deny path ~/.aws"},
		{"defaults", "*", Edit{AddWrite: []string{home + "/.gnupg"}}, "defaults.write[0]: cannot grant built-in deny path ~/.gnupg"},
		{"second entry", "canary-basic", Edit{AddWrite: []string{home + "/proj/out", home + "/.claude/x"}}, "skills.canary-basic.write[1]: cannot grant built-in deny path ~/.claude"},
		// Case variants: the same directory on a case-insensitive filesystem.
		{"abs .SSH", "canary-basic", Edit{AddWrite: []string{home + "/.SSH"}}, sshMsg},
		{"abs .Ssh/x", "canary-basic", Edit{AddWrite: []string{home + "/.Ssh/x"}}, sshMsg},
		{"~/.SSH", "canary-basic", Edit{AddWrite: []string{"~/.SSH"}}, sshMsg},
		{"${HOME}/.Aws read", "canary-basic", Edit{AddRead: []string{"${HOME}/.Aws/credentials"}}, "skills.canary-basic.read[0]: cannot grant built-in deny path ~/.aws"},
		{"abs .ENV", "canary-basic", Edit{AddWrite: []string{home + "/proj/.ENV"}}, "skills.canary-basic.write[0]: cannot grant built-in deny pattern **/.env"},
		{"relative .ENV", "canary-basic", Edit{AddWrite: []string{".ENV"}}, "skills.canary-basic.write[0]: cannot grant built-in deny pattern **/.env"},
		{"${CWD}/sub/.Env", "canary-basic", Edit{AddWrite: []string{"${CWD}/sub/.Env"}}, "skills.canary-basic.write[0]: cannot grant built-in deny pattern **/.env"},
		// Unicode simple folding: U+017F (long s) folds to s, U+212A (Kelvin
		// sign) to k; APFS treats these spellings as the same names.
		{"abs .ſſh", "canary-basic", Edit{AddWrite: []string{home + "/.ſſh"}}, sshMsg},
		{"abs .ſsh/x", "canary-basic", Edit{AddWrite: []string{home + "/.ſsh/x"}}, sshMsg},
		{"~/.awſ", "canary-basic", Edit{AddWrite: []string{"~/.awſ"}}, "skills.canary-basic.write[0]: cannot grant built-in deny path ~/.aws"},
		{"abs .docKer (Kelvin)", "canary-basic", Edit{AddWrite: []string{home + "/.docKer/config.json"}}, "skills.canary-basic.write[0]: cannot grant built-in deny path ~/.docker/config.json"},
	}
	base := Overrides{}
	for _, c := range cases {
		c.e.Home = home
		out, changed, err := Apply(base, c.skill, c.e)
		if err == nil || err.Error() != c.want {
			t.Errorf("%s: err = %v, want %q", c.name, err, c.want)
		}
		if changed || RenderOverrides(out) != RenderOverrides(base) {
			t.Errorf("%s: overrides changed on a refused edit", c.name)
		}
	}
	// Ordinary paths, including home itself (a parent of the deny paths,
	// which the profile still denies), are accepted.
	for _, p := range []string{home + "/proj/out", home, home + "/proj/.envrc", "/opt/data"} {
		if _, _, err := Apply(base, "canary-basic", Edit{AddWrite: []string{p}, Home: home}); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}
}

func TestApplyDefaultsStar(t *testing.T) {
	o := Overrides{Skills: map[string]Override{"pdf": {Network: netp(NetLocalhost)}}}
	o = mustApply(t, o, "*", Edit{Network: netp(NetAll), Caches: boolp(true), AddWrite: []string{"~/shared"}}, true)
	if d := o.Defaults; d.Network == nil || *d.Network != NetAll || !d.Caches || !reflect.DeepEqual(d.Write, []string{"~/shared"}) {
		t.Fatalf("defaults = %+v", d)
	}
	if n := o.Skills["pdf"].Network; n == nil || *n != NetLocalhost {
		t.Fatalf("per-skill block touched: %+v", o.Skills["pdf"])
	}
	if _, ok := o.Skills["*"]; ok {
		t.Fatal(`"*" must edit Defaults, not skills["*"]`)
	}
	// The grant for any skill now sees the defaults.
	eff, _ := Grant("other", o, Overrides{})
	if eff.Network != NetAll || !contains(eff.Write, "~/shared") || !contains(eff.Write, CacheDirs[0]) {
		t.Fatalf("grant = %+v", eff)
	}
	o = mustApply(t, o, "*", Edit{Reset: true}, true)
	if !emptyOverride(o.Defaults) {
		t.Fatalf("defaults after reset = %+v", o.Defaults)
	}
	o = mustApply(t, o, "*", Edit{Reset: true}, false)
	if cmd, ok := AllowCommand("*", Edit{Network: netp(NetAll)}); !ok || cmd != "watchdeck allow '*' --network all" {
		t.Errorf("AllowCommand(*) = %q, %v", cmd, ok)
	}
}

// renderFixture is what `watchdeck allow` wrote before the edit API existed.
const renderFixture = "# watchdeck user overrides. Edited by `watchdeck allow`; hand edits are fine.\n" +
	"version: 1\n" +
	"defaults:\n" +
	"    caches: true\n" +
	"skills:\n" +
	"  \"pdf\":\n" +
	"    network: all\n" +
	"    write: [\"${CWD}/build\", \"~/Documents\"]\n" +
	"    auto_allow: true\n" +
	"  \"zeta\":\n" +
	"    read: [\"~/data\"]\n" +
	"    env: [\"FOO\"]\n"

func fixtureOverrides() Overrides {
	return Overrides{
		Defaults: Override{Caches: true},
		Skills: map[string]Override{
			"zeta": {Read: []string{"~/data"}, Env: []string{"FOO"}},
			"pdf":  {Network: netp(NetAll), Write: []string{"${CWD}/build", "~/Documents"}, AutoAllow: boolp(true)},
		},
	}
}

func TestRenderRoundTrip(t *testing.T) {
	o := fixtureOverrides()
	text := RenderOverrides(o)
	if text != renderFixture {
		t.Fatalf("RenderOverrides changed format:\n%s\nwant:\n%s", text, renderFixture)
	}
	parsed, err := ParseOverrides([]byte(text))
	if err != nil {
		t.Fatalf("ParseOverrides(rendered): %v", err)
	}
	if !reflect.DeepEqual(parsed, o) {
		t.Fatalf("round trip lost data:\n got %+v\nwant %+v", parsed, o)
	}
	if again := RenderOverrides(parsed); again != text {
		t.Fatalf("second render differs:\n%s", again)
	}
	// Empty overrides render to the header and version only.
	if got := RenderOverrides(Overrides{}); got != "# watchdeck user overrides. Edited by `watchdeck allow`; hand edits are fine.\nversion: 1\n" {
		t.Fatalf("empty render = %q", got)
	}
	// Duplicates are collapsed on render.
	dup := Overrides{Skills: map[string]Override{"x": {Write: []string{"~/a", "~/a"}}}}
	if got := RenderOverrides(dup); !strings.Contains(got, "write: [\"~/a\"]\n") {
		t.Fatalf("dedupe on render: %q", got)
	}
}

func TestSaveOverridesAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cfg", "watchdeck", "overrides.yaml")
	o := fixtureOverrides()
	if err := SaveOverrides(path, o); err != nil {
		t.Fatalf("SaveOverrides: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != renderFixture {
		t.Fatalf("file content:\n%s", b)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("mode = %o, want 0600", st.Mode().Perm())
	}
	assertNoTemp := func() {
		t.Helper()
		entries, err := os.ReadDir(filepath.Dir(path))
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if e.Name() != "overrides.yaml" {
				t.Errorf("leftover file %s", e.Name())
			}
		}
	}
	assertNoTemp()

	// An invalid Overrides is refused before anything touches the disk.
	bad := Overrides{Skills: map[string]Override{"x": {Write: []string{"~/.ssh"}}}}
	if err := SaveOverrides(path, bad); err == nil || !strings.Contains(err.Error(), "refusing to write") {
		t.Fatalf("SaveOverrides(invalid) = %v", err)
	}
	after, _ := os.ReadFile(path)
	if string(after) != renderFixture {
		t.Fatal("invalid save changed the file")
	}
	assertNoTemp()

	// A second valid save replaces the content in place.
	o2 := mustApply(t, o, "pdf", Edit{Network: netp(NetNone)}, true)
	if err := SaveOverrides(path, o2); err != nil {
		t.Fatal(err)
	}
	got, exists, err := LoadOverridesFile(path)
	if err != nil || !exists {
		t.Fatalf("LoadOverridesFile: exists %v, err %v", exists, err)
	}
	if n := got.Skills["pdf"].Network; n == nil || *n != NetNone {
		t.Fatalf("reloaded network = %v", n)
	}
	assertNoTemp()

	// LoadOverridesFile: absent is not an error; malformed names the path.
	if _, exists, err := LoadOverridesFile(filepath.Join(dir, "missing.yaml")); err != nil || exists {
		t.Errorf("missing file: exists %v, err %v", exists, err)
	}
	badPath := filepath.Join(dir, "bad.yaml")
	os.WriteFile(badPath, []byte("version: 9\n"), 0o600)
	if _, exists, err := LoadOverridesFile(badPath); err == nil || !exists || !strings.Contains(err.Error(), badPath) {
		t.Errorf("malformed file: exists %v, err %v", exists, err)
	}
}

func TestAllowCommandMapping(t *testing.T) {
	cases := []struct {
		name  string
		skill string
		e     Edit
		want  string
		ok    bool
	}{
		{"network all", "pdf", Edit{Network: netp(NetAll)}, "watchdeck allow pdf --network all", true},
		{"network none revokes", "pdf", Edit{Network: netp(NetNone)}, "watchdeck allow pdf --network none", true},
		{"network localhost", "pdf", Edit{Network: netp(NetLocalhost)}, "watchdeck allow pdf --network localhost", true},
		{"star quoted", "*", Edit{Network: netp(NetAll)}, "watchdeck allow '*' --network all", true},
		{"write repeat and quoting", "pdf", Edit{AddWrite: []string{"${CWD}/build", "/tmp/x y", "/plain/path"}}, "watchdeck allow pdf --write '${CWD}/build' --write '/tmp/x y' --write /plain/path", true},
		{"remove-write", "pdf", Edit{RemoveWrite: []string{"~/Documents"}}, "watchdeck allow pdf --remove-write '~/Documents'", true},
		{"caches", "pdf", Edit{Caches: boolp(true)}, "watchdeck allow pdf --caches", true},
		{"no-caches", "pdf", Edit{Caches: boolp(false)}, "watchdeck allow pdf --no-caches", true},
		{"auto", "pdf", Edit{AutoAllow: boolp(true)}, "watchdeck allow pdf --auto", true},
		{"no-auto", "pdf", Edit{AutoAllow: boolp(false)}, "watchdeck allow pdf --no-auto", true},
		{"reset", "pdf", Edit{Reset: true}, "watchdeck allow pdf --reset", true},
		{"order", "pdf", Edit{AutoAllow: boolp(true), Caches: boolp(true), RemoveWrite: []string{"/b"}, AddWrite: []string{"/a"}, Network: netp(NetAll)}, "watchdeck allow pdf --network all --write /a --remove-write /b --caches --auto", true},
		{"quote escape", "pdf", Edit{AddWrite: []string{"/it's"}}, `watchdeck allow pdf --write '/it'\''s'`, true},
		// no CLI equivalent
		{"clear network", "pdf", Edit{ClearNetwork: true}, "", false},
		{"clear auto", "pdf", Edit{ClearAutoAllow: true}, "", false},
		{"read", "pdf", Edit{AddRead: []string{"~/data"}}, "", false},
		{"remove read", "pdf", Edit{RemoveRead: []string{"~/data"}}, "", false},
		{"env", "pdf", Edit{AddEnv: []string{"CANARY_SECRET"}}, "", false},
		{"remove env", "pdf", Edit{RemoveEnv: []string{"CANARY_SECRET"}}, "", false},
		{"env with network", "pdf", Edit{Network: netp(NetAll), AddEnv: []string{"X"}}, "", false},
		{"empty", "pdf", Edit{}, "", false},
		{"bad name", "a b", Edit{Network: netp(NetAll)}, "", false},
	}
	for _, c := range cases {
		got, ok := AllowCommand(c.skill, c.e)
		if got != c.want || ok != c.ok {
			t.Errorf("%s: AllowCommand = %q, %v; want %q, %v", c.name, got, ok, c.want, c.ok)
		}
	}
}

func TestViewOfEffectiveAndManifest(t *testing.T) {
	def := Default()
	v := def.View()
	if v.Network != "none" || !reflect.DeepEqual(v.Write, []string{"${CWD}", "${TMP}"}) || v.Read != nil ||
		len(v.Deny) != 7 || !reflect.DeepEqual(v.DenyPatterns, []string{"**/.env"}) ||
		!v.ExecAny || v.Exec != nil || !reflect.DeepEqual(v.Env, []string{"PATH", "HOME", "LANG", "TMPDIR"}) ||
		v.AutoAllow || v.Summary != def.Summary() {
		t.Fatalf("Default().View() = %+v", v)
	}
	// Slices are copies.
	v.Write[0] = "mutated"
	if def.Write[0] != "${CWD}" {
		t.Fatal("View shares the Effective's slice")
	}
	// A zero Effective still renders arrays for write, deny and env.
	z := Effective{}.View()
	if z.Write == nil || z.Deny == nil || z.Env == nil || len(z.Write)+len(z.Deny)+len(z.Env) != 0 {
		t.Fatalf("zero view = %+v", z)
	}
	zb, _ := json.Marshal(z)
	if s := string(zb); !strings.Contains(s, `"write":[]`) || !strings.Contains(s, `"deny":[]`) || !strings.Contains(s, `"env":[]`) || strings.Contains(s, `"read"`) {
		t.Fatalf("zero view json = %s", s)
	}

	// Request as written: omitted fields stay nil.
	req, err := ParseBytes([]byte("version: 1\nnetwork: all\nenv: [\"PATH\", \"HOME\", \"LANG\", \"TMPDIR\", \"CANARY_SECRET\"]\nnotes: \"asks for more\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	rv := req.View()
	if rv.Network != "all" || rv.Write != nil || rv.Read != nil || rv.Deny != nil || rv.DenyPatterns != nil ||
		!rv.ExecAny || rv.Exec != nil || len(rv.Env) != 5 || rv.AutoAllow ||
		rv.Summary != "network=all write=- env=PATH,HOME,LANG,TMPDIR,CANARY_SECRET" {
		t.Fatalf("request view = %+v", rv)
	}
	rb, _ := json.Marshal(rv)
	if s := string(rb); !strings.Contains(s, `"write":null`) || !strings.Contains(s, `"deny":null`) || strings.Contains(s, `"read"`) || !strings.Contains(s, `"autoAllow":false`) {
		t.Fatalf("request view json = %s", s)
	}

	// Request with an exec list, writes and a deny list keeps them verbatim.
	full, err := ParseBytes([]byte("version: 1\nfilesystem:\n  write: [\"${CWD}/out\"]\n  deny: [\"~/.ssh\", \"~/.aws\", \"~/.gnupg\", \"~/.claude\", \"~/.config/gcloud\", \"~/.netrc\", \"~/.docker/config.json\", \"**/.env\", \"~/private\"]\nexec: [\"/usr/bin/python3\"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	fv := full.View()
	if fv.ExecAny || !reflect.DeepEqual(fv.Exec, []string{"/usr/bin/python3"}) || !reflect.DeepEqual(fv.Write, []string{"${CWD}/out"}) || len(fv.Deny) != 9 || fv.Env != nil || fv.Network != "none" {
		t.Fatalf("full request view = %+v", fv)
	}

	// Clip then View: the effective view's summary is the row's effective string.
	eff, ungranted := Clip(req, def)
	ev := eff.View()
	if ev.Network != "none" || ev.Summary != eff.Summary() || !reflect.DeepEqual(ev.Env, []string{"PATH", "HOME", "LANG", "TMPDIR"}) {
		t.Fatalf("effective view = %+v (ungranted %v)", ev, ungranted)
	}
	if !reflect.DeepEqual(ungranted, []string{"network: all", "env: CANARY_SECRET"}) {
		t.Fatalf("ungranted = %v", ungranted)
	}
}
