package audit

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Panda-Taps-LLC/watchdeck/internal/manifest"
	"github.com/Panda-Taps-LLC/watchdeck/internal/skills"
)

// Every test runs against a copy of testdata/home under t.TempDir() with the
// canary skills copied into <home>/.claude/skills. Nothing reads the
// developer's real home.

var canaries = []string{"canary-basic", "canary-request", "canary-localhost", "canary-exec", "canary-malformed", "canary-prose", "canary-shell"}

// fixtureHome mirrors skills_test.go's helper (unexported there): copy
// testdata/home keeping the beta symlink, rewrite __HOME__ in
// installed_plugins.json, add proj/.git/HEAD and .claude/settings.local.json,
// then copy every canary skill under .claude/skills.
func fixtureHome(t *testing.T) string {
	t.Helper()
	src, err := filepath.Abs(filepath.Join("..", "..", "testdata", "home"))
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "home")
	copyTree(t, src, dst, func(name string, b []byte) []byte {
		if name == "installed_plugins.json" {
			return bytes.ReplaceAll(b, []byte("__HOME__"), []byte(dst))
		}
		return b
	})
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
	skillsSrc, err := filepath.Abs(filepath.Join("..", "..", "testdata", "skills"))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range canaries {
		copyTree(t, filepath.Join(skillsSrc, c), filepath.Join(dst, ".claude", "skills", c), nil)
	}
	return dst
}

// copyTree copies src to dst preserving symlinks and file modes; edit, when
// non-nil, may rewrite a file's bytes by name.
func copyTree(t *testing.T, src, dst string, edit func(name string, b []byte) []byte) {
	t.Helper()
	err := filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
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
			if edit != nil {
				b = edit(d.Name(), b)
			}
			info, err := d.Info()
			if err != nil {
				return err
			}
			return os.WriteFile(target, b, info.Mode().Perm())
		}
	})
	if err != nil {
		t.Fatalf("copy %s: %v", src, err)
	}
}

func options(home string, verbose bool) Options {
	cwd := filepath.Join(home, "proj")
	return Options{
		Roots:       skills.Roots{Home: home, Cwd: cwd},
		UserCfgDir:  filepath.Join(home, ".config", "watchdeck"),
		ProjectRoot: cwd,
		Verbose:     verbose,
	}
}

func rowByName(t *testing.T, rep Report, name string) Row {
	t.Helper()
	for _, r := range rep.Rows {
		if r.Name == name {
			return r
		}
	}
	t.Fatalf("no row %q in %d rows", name, len(rep.Rows))
	return Row{}
}

func TestBuildFixtureHome(t *testing.T) {
	home := fixtureHome(t)
	rep, err := Build(options(home, true))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(rep.Errors) != 0 {
		t.Errorf("unexpected errors: %v", rep.Errors)
	}

	// canary-request asks for network: all and CANARY_SECRET; nothing grants them.
	req := rowByName(t, rep, "canary-request")
	if req.ManifestStatus != "ok" || req.Request == nil {
		t.Fatalf("canary-request manifest = %q, request = %v", req.ManifestStatus, req.Request)
	}
	if req.Request.Network != "all" {
		t.Errorf("request.network = %q, want all", req.Request.Network)
	}
	if req.Request.Write != nil || req.Request.Read != nil || !req.Request.ExecAny || req.Request.AutoAllow {
		t.Errorf("request view should keep omitted fields nil: %+v", *req.Request)
	}
	if want := []string{"PATH", "HOME", "LANG", "TMPDIR", "CANARY_SECRET"}; !reflect.DeepEqual(req.Request.Env, want) {
		t.Errorf("request.env = %v, want %v", req.Request.Env, want)
	}
	if req.Grant.Network != "none" || req.EffectiveDetail.Network != "none" {
		t.Errorf("grant.network = %q, effectiveDetail.network = %q, want none/none", req.Grant.Network, req.EffectiveDetail.Network)
	}
	if want := []string{"network: all", "env: CANARY_SECRET"}; !reflect.DeepEqual(req.Ungranted, want) {
		t.Errorf("ungranted = %v, want %v", req.Ungranted, want)
	}
	if req.Effective != req.EffectiveDetail.Summary || req.Effective != manifest.Default().Summary() {
		t.Errorf("effective = %q, effectiveDetail.summary = %q", req.Effective, req.EffectiveDetail.Summary)
	}
	if !strings.Contains(req.Profile, "asks[network: all; env: CANARY_SECRET]") {
		t.Errorf("profile = %q", req.Profile)
	}
	if req.Description == "" || !strings.HasPrefix(req.Description, "Test fixture.") {
		t.Errorf("description = %q", req.Description)
	}
	if len(req.Hits) == 0 {
		t.Error("verbose row has no hits")
	}
	if req.Grant.Write == nil || req.Grant.Deny == nil || req.Grant.Env == nil {
		t.Errorf("grant view must carry arrays, not nil: %+v", req.Grant)
	}

	// canary-basic has no manifest: request is nil, grant == effective.
	basic := rowByName(t, rep, "canary-basic")
	if basic.ManifestStatus != "none" || basic.Request != nil {
		t.Errorf("canary-basic manifest = %q, request = %v", basic.ManifestStatus, basic.Request)
	}
	if !reflect.DeepEqual(basic.Grant, basic.EffectiveDetail) {
		t.Errorf("without a manifest grant and effectiveDetail must agree:\n%+v\n%+v", basic.Grant, basic.EffectiveDetail)
	}
	if basic.Profile != "default (needs net)" {
		t.Errorf("canary-basic profile = %q", basic.Profile)
	}

	// canary-malformed: invalid manifest, no request view.
	bad := rowByName(t, rep, "canary-malformed")
	if bad.ManifestStatus != "invalid" || bad.Request != nil || bad.ManifestError == "" {
		t.Errorf("canary-malformed = %q / %v / %q", bad.ManifestStatus, bad.Request, bad.ManifestError)
	}

	// Prose-only skills: no scripts, PROFILE "n/a", and ProfileCell says so.
	prose := rowByName(t, rep, "canary-prose")
	if len(prose.Scripts) != 0 || prose.Profile != "n/a" {
		t.Errorf("canary-prose scripts = %v, profile = %q", prose.Scripts, prose.Profile)
	}
	if got := ProfileCell(prose, manifest.Default(), false); got != "n/a" {
		t.Errorf("ProfileCell(prose) = %q", got)
	}
	if prose.Effective != manifest.Default().Summary() {
		t.Errorf("prose effective = %q", prose.Effective)
	}

	// Totals still count the canaries.
	if rep.Totals.Invalid != 1 || rep.Totals.WithManifest != 4 {
		t.Errorf("totals = %+v", rep.Totals)
	}
}

func TestJSONTagsStable(t *testing.T) {
	home := fixtureHome(t)
	rep, err := Build(options(home, true))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	encode := func(r Row) map[string]any {
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		return m
	}

	req := encode(rowByName(t, rep, "canary-request"))
	for _, k := range []string{"name", "source", "root", "realRoot", "enabled", "description", "scripts", "scriptsSummary", "caps", "capsSummary", "hits", "manifest", "manifestPath", "profile", "effective", "ungranted", "hash", "request", "grant", "effectiveDetail"} {
		if _, ok := req[k]; !ok {
			t.Errorf("key %q missing from canary-request row: %v", k, keys(req))
		}
	}
	if _, ok := req["effective"].(string); !ok {
		t.Errorf("effective must stay a string, got %T", req["effective"])
	}
	scripts, _ := req["scripts"].([]any)
	if len(scripts) == 0 {
		t.Fatal("scripts empty")
	}
	s0 := scripts[0].(map[string]any)
	if s0["rel"] != "scripts/probe.py" || s0["lang"] != "py" || s0["inGlob"] != true {
		t.Errorf("scripts[0] = %v", s0)
	}
	hits, _ := req["hits"].([]any)
	if len(hits) == 0 {
		t.Fatal("hits empty")
	}
	h0 := hits[0].(map[string]any)
	for _, k := range []string{"category", "file", "line", "pattern", "snippet"} {
		if _, ok := h0[k]; !ok {
			t.Errorf("hits[0] missing %q: %v", k, h0)
		}
	}
	if _, ok := h0["category"].(string); !ok {
		t.Errorf("hits[0].category = %T", h0["category"])
	}
	request := req["request"].(map[string]any)
	if request["network"] != "all" || request["autoAllow"] != false {
		t.Errorf("request = %v", request)
	}
	if _, ok := request["write"]; !ok {
		t.Error("request.write must be present (null) for an omitted field")
	} else if request["write"] != nil {
		t.Errorf("request.write = %v, want null", request["write"])
	}
	for _, k := range []string{"network", "write", "deny", "execAny", "env", "autoAllow", "summary"} {
		if _, ok := req["grant"].(map[string]any)[k]; !ok {
			t.Errorf("grant missing %q", k)
		}
		if _, ok := req["effectiveDetail"].(map[string]any)[k]; !ok {
			t.Errorf("effectiveDetail missing %q", k)
		}
	}
	if eff := req["effectiveDetail"].(map[string]any); eff["summary"] != req["effective"] {
		t.Errorf("effectiveDetail.summary %v != effective %v", eff["summary"], req["effective"])
	}

	// A skill without a manifest carries request: null, not an absent key.
	basic := encode(rowByName(t, rep, "canary-basic"))
	if v, ok := basic["request"]; !ok || v != nil {
		t.Errorf("canary-basic request = %v (present %v), want null", v, ok)
	}

	// Report-level keys.
	var buf bytes.Buffer
	if err := rep.JSON(&buf); err != nil {
		t.Fatal(err)
	}
	var top map[string]any
	if err := json.Unmarshal(buf.Bytes(), &top); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"skills", "totals"} {
		if _, ok := top[k]; !ok {
			t.Errorf("report missing %q", k)
		}
	}
}

func keys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestBuildOne(t *testing.T) {
	home := fixtureHome(t)
	o := options(home, true)
	rep, err := Build(o)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	for _, name := range []string{"canary-request", "canary-basic", "canary-prose", "on-one"} {
		row, ok, err := BuildOne(name, o)
		if err != nil || !ok {
			t.Fatalf("BuildOne(%s) = ok %v, err %v", name, ok, err)
		}
		want := rowByName(t, rep, name)
		got, _ := json.Marshal(row)
		exp, _ := json.Marshal(want)
		if !bytes.Equal(got, exp) {
			t.Errorf("BuildOne(%s) differs from Build:\n%s\n%s", name, got, exp)
		}
	}
	if _, ok, err := BuildOne("no-such-skill", o); ok || err != nil {
		t.Errorf("unknown skill: ok %v, err %v", ok, err)
	}
	// A disabled plugin's skill needs Roots.All, like `audit --all`.
	if _, ok, _ := BuildOne("off-one", o); ok {
		t.Error("off-one found without All")
	}
	all := o
	all.Roots.All = true
	if row, ok, err := BuildOne("off-one", all); err != nil || !ok || row.Enabled {
		t.Errorf("off-one with All: ok %v, err %v, enabled %v", ok, err, row.Enabled)
	}
}
