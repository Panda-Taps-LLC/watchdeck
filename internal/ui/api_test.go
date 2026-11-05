package ui

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/manifest"
)

var canaries = []string{"canary-basic", "canary-request", "canary-localhost", "canary-exec", "canary-malformed", "canary-prose", "canary-shell"}

// fixtureHome mirrors internal/audit's helper (unexported there): a copy of
// testdata/home under t.TempDir() with __HOME__ rewritten, proj/.git, and
// every canary under .claude/skills. Nothing reads the developer's home.
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
	skillsSrc, err := filepath.Abs(filepath.Join("..", "..", "testdata", "skills"))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range canaries {
		copyTree(t, filepath.Join(skillsSrc, c), filepath.Join(dst, ".claude", "skills", c), nil)
	}
	return dst
}

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
		t.Fatal(err)
	}
}

// fixtureOptions is a server over the fixture home, cwd = <home>/proj.
func fixtureOptions(t *testing.T) Options {
	t.Helper()
	home := fixtureHome(t)
	return Options{Paths: tempPaths(t, home), Cwd: filepath.Join(home, "proj"), Version: "test", Idle: 30 * time.Minute}
}

func decode(t *testing.T, b []byte, v any) {
	t.Helper()
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("decode %.200s: %v", b, err)
	}
}

// view is the subset of manifest.View the tests read.
type view struct {
	Network string   `json:"network"`
	Write   []string `json:"write"`
	Summary string   `json:"summary"`
}

type row struct {
	Name            string `json:"name"`
	Manifest        string `json:"manifest"`
	Effective       any    `json:"effective"`
	Request         *view  `json:"request"`
	Grant           *view  `json:"grant"`
	EffectiveDetail *view  `json:"effectiveDetail"`
	Hits            []struct {
		Category string `json:"category"`
		File     string `json:"file"`
	} `json:"hits"`
	Ungranted []string `json:"ungranted"`
}

func TestSkillsReportShape(t *testing.T) {
	var clock atomic.Int64
	clock.Store(time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC).UnixNano())
	o := fixtureOptions(t)
	o.Now = func() time.Time { return time.Unix(0, clock.Load()) }
	ts := startServer(t, o)
	tok := ts.s.Token()

	resp, b := ts.do(t, req{Path: "/api/skills", Token: tok})
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "application/json; charset=utf-8" {
		t.Fatalf("GET /api/skills = %d %q %.300s", resp.StatusCode, resp.Header.Get("Content-Type"), b)
	}
	var rep struct {
		Skills      []row          `json:"skills"`
		Totals      map[string]any `json:"totals"`
		GeneratedAt string         `json:"generatedAt"`
	}
	decode(t, b, &rep)
	if rep.GeneratedAt != "2026-10-12T09:00:00Z" {
		t.Errorf("generatedAt = %q", rep.GeneratedAt)
	}
	if rep.Totals == nil || rep.Totals["skills"] == nil {
		t.Errorf("totals missing: %v", rep.Totals)
	}
	byName := map[string]row{}
	for _, r := range rep.Skills {
		byName[r.Name] = r
	}
	cr := byName["canary-request"]
	if cr.Request == nil || cr.Request.Network != "all" {
		t.Fatalf("canary-request request = %+v", cr.Request)
	}
	if cr.Grant == nil || cr.Grant.Network != "none" || cr.EffectiveDetail == nil || cr.EffectiveDetail.Network != "none" {
		t.Errorf("canary-request grant/effective = %+v / %+v", cr.Grant, cr.EffectiveDetail)
	}
	if _, ok := cr.Effective.(string); !ok {
		t.Errorf("effective is %T, want the summary string", cr.Effective)
	}
	if len(cr.Ungranted) == 0 {
		t.Error("canary-request has no ungranted items")
	}
	basic, ok := byName["canary-basic"]
	if !ok || basic.Request != nil || len(basic.Hits) == 0 || basic.Hits[0].Category == "" {
		t.Errorf("canary-basic = %+v (want request null and verbose hits)", basic)
	}
	if !strings.Contains(string(b), `"request":null`) {
		t.Error("a skill without a manifest must carry request: null")
	}

	// Cached: the clock moves, the report does not.
	clock.Add(int64(time.Hour))
	_, b = ts.do(t, req{Path: "/api/skills", Token: tok})
	decode(t, b, &rep)
	if rep.GeneratedAt != "2026-10-12T09:00:00Z" {
		t.Errorf("second GET rebuilt the report: %q", rep.GeneratedAt)
	}
	_, b = ts.do(t, req{Path: "/api/skills?refresh=1", Token: tok})
	decode(t, b, &rep)
	if rep.GeneratedAt != "2026-10-12T10:00:00Z" {
		t.Errorf("refresh=1 did not rebuild: %q", rep.GeneratedAt)
	}
	// A POST without the token is refused before it can drop the cache.
	clock.Add(int64(time.Hour))
	if resp, _ := ts.do(t, req{Method: "POST", Path: "/api/skills/canary-request/grant", Origin: "auto", Body: `{}`, Header: jsonCT()}); resp.StatusCode != 401 {
		t.Fatalf("POST without token = %d", resp.StatusCode)
	}
	_, b = ts.do(t, req{Path: "/api/skills", Token: tok})
	decode(t, b, &rep)
	if rep.GeneratedAt != "2026-10-12T10:00:00Z" {
		t.Errorf("an unauthenticated POST invalidated the cache: %q", rep.GeneratedAt)
	}
	// A non-GET outside /api/ is 405 before any check or side effect.
	for _, q := range []req{
		{Method: "POST", Path: "/", Origin: "auto", Body: `{}`, Header: jsonCT()},
		{Method: "POST", Path: "/app.js", Body: `x`},
		{Method: "DELETE", Path: "/", Origin: "auto", Token: tok},
	} {
		resp, b := ts.do(t, q)
		if resp.StatusCode != 405 || resp.Header.Get("Allow") != "GET, HEAD" || resp.Header.Get("Content-Security-Policy") == "" {
			t.Errorf("%s %s = %d Allow=%q %s", q.Method, q.Path, resp.StatusCode, resp.Header.Get("Allow"), b)
		}
	}
	_, b = ts.do(t, req{Path: "/api/skills", Token: tok})
	decode(t, b, &rep)
	if rep.GeneratedAt != "2026-10-12T10:00:00Z" {
		t.Errorf("a static POST invalidated the cache: %q", rep.GeneratedAt)
	}
	// Any authorised POST drops the cache, even one the handler rejects.
	ts.do(t, req{Method: "POST", Path: "/api/skills/canary-request/grant", Origin: "auto", Token: tok, Body: `{"bogus":1}`, Header: jsonCT()})
	_, b = ts.do(t, req{Path: "/api/skills", Token: tok})
	decode(t, b, &rep)
	if rep.GeneratedAt != "2026-10-12T11:00:00Z" {
		t.Errorf("POST did not invalidate the cache: %q", rep.GeneratedAt)
	}
}

func TestSkillDetail(t *testing.T) {
	ts := startServer(t, fixtureOptions(t))
	tok := ts.s.Token()
	resp, b := ts.do(t, req{Path: "/api/skills/canary-request", Token: tok})
	if resp.StatusCode != 200 {
		t.Fatalf("detail = %d %s", resp.StatusCode, b)
	}
	var d struct {
		Row          row              `json:"row"`
		Override     *json.RawMessage `json:"override"`
		Defaults     *json.RawMessage `json:"defaults"`
		ManifestText *string          `json:"manifestText"`
	}
	decode(t, b, &d)
	if d.Row.Name != "canary-request" || d.Row.Request == nil {
		t.Errorf("row = %+v", d.Row)
	}
	if d.ManifestText == nil || !strings.Contains(*d.ManifestText, "network") {
		t.Errorf("manifestText = %v", d.ManifestText)
	}
	for _, k := range []string{`"override":null`, `"defaults":null`} {
		if !strings.Contains(string(b), k) {
			t.Errorf("no overrides file yet: want %s", k)
		}
	}

	_, b = ts.do(t, req{Path: "/api/skills/canary-basic", Token: tok})
	if !strings.Contains(string(b), `"manifestText":null`) {
		t.Errorf("canary-basic has no manifest: %.200s", b)
	}
	for _, p := range []string{"/api/skills/no-such-skill", "/api/skills/%2A", "/api/skills/bad%20name"} {
		resp, b := ts.do(t, req{Path: p, Token: tok})
		if resp.StatusCode != 404 {
			t.Errorf("GET %s = %d %s, want 404", p, resp.StatusCode, b)
		}
	}
}

func TestGrantPostWritesOverrides(t *testing.T) {
	o := fixtureOptions(t)
	ts := startServer(t, o)
	tok := ts.s.Token()
	file := o.Paths.OverridesFile()
	grant := func(name, body string) (int, []byte) {
		resp, b := ts.do(t, req{Method: "POST", Path: "/api/skills/" + name + "/grant", Origin: "auto", Token: tok, Body: body, Header: jsonCT()})
		return resp.StatusCode, b
	}
	type result struct {
		Row           *row    `json:"row"`
		Changed       bool    `json:"changed"`
		AllowCommand  *string `json:"allowCommand"`
		OverridesPath string  `json:"overridesPath"`
	}

	code, b := grant("canary-request", `{"network":"all"}`)
	if code != 200 {
		t.Fatalf("grant = %d %s", code, b)
	}
	var r result
	decode(t, b, &r)
	if r.AllowCommand == nil || *r.AllowCommand != "watchdeck allow canary-request --network all" {
		t.Errorf("allowCommand = %v", r.AllowCommand)
	}
	if !r.Changed || r.OverridesPath != file {
		t.Errorf("changed=%v overridesPath=%q, want true %q", r.Changed, r.OverridesPath, file)
	}
	if r.Row == nil || r.Row.EffectiveDetail == nil || r.Row.EffectiveDetail.Network != "all" {
		t.Fatalf("row after grant = %+v", r.Row)
	}
	text, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	ov, err := manifest.ParseOverrides(text)
	if err != nil {
		t.Fatalf("written file does not parse: %v\n%s", err, text)
	}
	if blk := ov.Skills["canary-request"]; blk.Network == nil || *blk.Network != manifest.NetAll {
		t.Fatalf("file lacks network: all for canary-request:\n%s", text)
	}
	if fi, err := os.Stat(file); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("overrides mode = %v, %v; want 0600", fi.Mode().Perm(), err)
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(file), ".overrides-*")); len(left) != 0 {
		t.Errorf("temp files left behind: %v", left)
	}

	// Same edit again: 200, changed false, file untouched.
	code, b = grant("canary-request", `{"network":"all"}`)
	decode(t, b, &r)
	if code != 200 || r.Changed {
		t.Errorf("repeat grant = %d changed=%v", code, r.Changed)
	}

	// Invalid edits are 400 and leave the file byte for byte.
	for _, body := range []string{
		`{"addWrite":["~/.ssh"]}`,
		`{"addEnv":["lower_case"]}`,
		`{"network":"everything"}`,
		`{"network":"all","clearNetwork":true}`,
		`{"netwrok":"all"}`,
		`{"addWrite":"not-a-list"}`,
	} {
		code, b := grant("canary-request", body)
		if code != 400 {
			t.Errorf("%s = %d %s, want 400", body, code, b)
		}
		errorBody(t, b)
		after, _ := os.ReadFile(file)
		if !bytes.Equal(after, text) {
			t.Fatalf("%s changed the file:\n%s", body, after)
		}
	}
	_, b = grant("canary-request", `{"addWrite":["~/.ssh"]}`)
	if !strings.Contains(errorBody(t, b), ".ssh") {
		t.Errorf("400 message should come from manifest.Apply: %s", b)
	}

	// Names: "*" via %2A edits defaults (row null); a bad name is 400.
	code, b = grant("%2A", `{"caches":true}`)
	if code != 200 {
		t.Fatalf("grant * = %d %s", code, b)
	}
	r = result{}
	decode(t, b, &r)
	if r.Row != nil || r.AllowCommand == nil || *r.AllowCommand != "watchdeck allow '*' --caches" {
		t.Errorf("grant * = row %v allowCommand %v", r.Row, r.AllowCommand)
	}
	text, _ = os.ReadFile(file)
	if ov, err = manifest.ParseOverrides(text); err != nil || !ov.Defaults.Caches {
		t.Errorf("defaults lack caches: %v\n%s", err, text)
	}
	for _, name := range []string{"..%2Fx", "a%20b", "x%3By"} {
		if code, b := grant(name, `{"network":"all"}`); code != 400 {
			t.Errorf("name %s = %d %s, want 400", name, code, b)
		}
	}
	// A name no installed skill has is accepted (revoking a stale block).
	code, b = grant("gone-skill", `{"network":"localhost"}`)
	r = result{}
	decode(t, b, &r)
	if code != 200 || r.Row != nil || !r.Changed {
		t.Errorf("grant gone-skill = %d row=%v changed=%v", code, r.Row, r.Changed)
	}
	// An edit with no CLI form answers allowCommand null.
	code, b = grant("canary-request", `{"addEnv":["CANARY_SECRET"]}`)
	if code != 200 || !strings.Contains(string(b), `"allowCommand":null`) {
		t.Errorf("env edit = %d %s", code, b)
	}

	// The CLI may write between requests: the next POST re-reads the file.
	cli, _, _ := manifest.LoadOverridesFile(file)
	cli, _, err = manifest.Apply(cli, "canary-exec", manifest.Edit{AddWrite: []string{"/tmp/cli-wrote-this"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := manifest.SaveOverrides(file, cli); err != nil {
		t.Fatal(err)
	}
	if code, b := grant("canary-request", `{"reset":true}`); code != 200 {
		t.Fatalf("reset = %d %s", code, b)
	}
	text, _ = os.ReadFile(file)
	if !strings.Contains(string(text), "/tmp/cli-wrote-this") || strings.Contains(string(text), `"canary-request"`) {
		t.Errorf("after CLI write + reset:\n%s", text)
	}

	// GET /api/overrides reflects the file.
	resp, b := ts.do(t, req{Path: "/api/overrides", Token: tok})
	if resp.StatusCode != 200 {
		t.Fatalf("overrides = %d %s", resp.StatusCode, b)
	}
	var ovr struct {
		Path     string                    `json:"path"`
		Exists   bool                      `json:"exists"`
		Text     string                    `json:"text"`
		Defaults map[string]any            `json:"defaults"`
		Skills   map[string]map[string]any `json:"skills"`
	}
	decode(t, b, &ovr)
	if ovr.Path != file || !ovr.Exists || ovr.Text != string(text) || ovr.Defaults["caches"] != true {
		t.Errorf("overrides view = %+v", ovr)
	}
	if ovr.Skills["gone-skill"]["network"] != "localhost" || ovr.Skills["canary-exec"]["write"] == nil {
		t.Errorf("overrides skills = %v", ovr.Skills)
	}
}

// TestGrantRefusesAbsoluteDenyPath: the dashboard's grant endpoint applies
// the same deny-path check as `watchdeck allow`, with Edit.Home taken from
// the server's own Paths.Home. Absolute, real-path, symlinked, ${HOME} and
// case-variant (.SSH, .Ssh/x) spellings of ~/.ssh, and case variants of
// .env, are a 400 with the CLI's message and leave
// overrides.yaml byte for byte; an ordinary path under home is a 200. A
// client cannot supply the home itself.
func TestGrantRefusesAbsoluteDenyPath(t *testing.T) {
	o := fixtureOptions(t)
	home := o.Paths.Home
	realHome, err := filepath.EvalSymlinks(home)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, ".ssh"), filepath.Join(home, "proj", "keys")); err != nil {
		t.Fatal(err)
	}
	ts := startServer(t, o)
	tok := ts.s.Token()
	file := o.Paths.OverridesFile()
	grant := func(body string) (int, []byte) {
		resp, b := ts.do(t, req{Method: "POST", Path: "/api/skills/canary-basic/grant", Origin: "auto", Token: tok, Body: body, Header: jsonCT()})
		return resp.StatusCode, b
	}
	// Seed the file so "unchanged" compares real bytes, not two read errors.
	if code, b := grant(`{"network":"localhost"}`); code != 200 {
		t.Fatalf("seed grant = %d %s", code, b)
	}
	text, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	const sshMsg = "skills.canary-basic.write[0]: cannot grant built-in deny path ~/.ssh"
	for _, p := range []string{
		home + "/.ssh",
		home + "/.ssh/x",
		realHome + "/.ssh",
		home + "/proj/keys",
		home + "/proj/keys/x",
		"${HOME}/.ssh",
		home + "/.SSH",
		home + "/.Ssh/x",
		"~/.SSH",
		home + "/.ſſh", // U+017F folds to s
		home + "/.ſsh/x",
	} {
		code, b := grant(`{"addWrite":[` + jsonString(p) + `]}`)
		if code != 400 {
			t.Errorf("%s = %d %s, want 400", p, code, b)
			continue
		}
		if msg := errorBody(t, b); msg != sshMsg {
			t.Errorf("%s: error = %q, want %q", p, msg, sshMsg)
		}
		if after, _ := os.ReadFile(file); !bytes.Equal(after, text) {
			t.Fatalf("%s changed the file:\n%s", p, after)
		}
	}
	for p, want := range map[string]string{
		home + "/.awſ":                "skills.canary-basic.write[0]: cannot grant built-in deny path ~/.aws",
		home + "/.docKer/config.json": "skills.canary-basic.write[0]: cannot grant built-in deny path ~/.docker/config.json", // Kelvin sign
	} {
		code, b := grant(`{"addWrite":[` + jsonString(p) + `]}`)
		if code != 400 || errorBody(t, b) != want {
			t.Errorf("%s = %d %s, want 400 %q", p, code, b, want)
		}
		if after, _ := os.ReadFile(file); !bytes.Equal(after, text) {
			t.Fatalf("%s changed the file:\n%s", p, after)
		}
	}
	const envMsg = "skills.canary-basic.write[0]: cannot grant built-in deny pattern **/.env"
	for _, p := range []string{home + "/proj/.ENV", ".ENV", "${CWD}/sub/.Env"} {
		code, b := grant(`{"addWrite":[` + jsonString(p) + `]}`)
		if code != 400 || errorBody(t, b) != envMsg {
			t.Errorf("%s = %d %s, want 400 %q", p, code, b, envMsg)
		}
		if after, _ := os.ReadFile(file); !bytes.Equal(after, text) {
			t.Fatalf("%s changed the file:\n%s", p, after)
		}
	}
	// The home is the server's, never the client's: an extra key is a 400.
	if code, b := grant(`{"addWrite":["/opt/data"],"home":"/nonexistent"}`); code != 400 {
		t.Errorf("client home = %d %s, want 400", code, b)
	}
	if after, _ := os.ReadFile(file); !bytes.Equal(after, text) {
		t.Fatalf("client home changed the file:\n%s", after)
	}

	out := home + "/proj/out"
	if code, b := grant(`{"addWrite":[` + jsonString(out) + `]}`); code != 200 {
		t.Fatalf("%s = %d %s, want 200", out, code, b)
	}
	after, _ := os.ReadFile(file)
	ov, err := manifest.ParseOverrides(after)
	if err != nil || !reflect.DeepEqual(ov.Skills["canary-basic"].Write, []string{out}) {
		t.Fatalf("write not saved: %v\n%s", err, after)
	}
}

func TestOverridesAbsentAndMalformed(t *testing.T) {
	o := emptyOptions(t)
	ts := startServer(t, o)
	tok := ts.s.Token()
	_, b := ts.do(t, req{Path: "/api/overrides", Token: tok})
	want := `{"path":` + jsonString(o.Paths.OverridesFile()) + `,"exists":false,"text":"","defaults":null,"skills":{}}` + "\n"
	if string(b) != want {
		t.Errorf("absent overrides:\n got %s\nwant %s", b, want)
	}

	if err := os.MkdirAll(o.Paths.ConfigDir, 0o755); err != nil {
		t.Fatal(err)
	}
	bad := "version: 9\n"
	if err := os.WriteFile(o.Paths.OverridesFile(), []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	resp, b := ts.do(t, req{Path: "/api/overrides", Token: tok})
	var v struct {
		Exists     bool   `json:"exists"`
		Text       string `json:"text"`
		ParseError string `json:"parseError"`
	}
	decode(t, b, &v)
	if resp.StatusCode != 200 || !v.Exists || v.Text != bad || v.ParseError == "" {
		t.Errorf("malformed overrides = %d %+v", resp.StatusCode, v)
	}
	// A grant against a malformed file refuses and leaves it alone.
	resp, _ = ts.do(t, req{Method: "POST", Path: "/api/skills/x/grant", Origin: "auto", Token: tok, Body: `{"network":"all"}`, Header: jsonCT()})
	if resp.StatusCode != 500 {
		t.Errorf("grant over malformed file = %d, want 500", resp.StatusCode)
	}
	if after, _ := os.ReadFile(o.Paths.OverridesFile()); string(after) != bad {
		t.Errorf("malformed file rewritten: %q", after)
	}
}

func TestSkillDetailWithMalformedOverrides(t *testing.T) {
	o := fixtureOptions(t)
	if err := os.MkdirAll(o.Paths.ConfigDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(o.Paths.OverridesFile(), []byte("version: 1\nskills:\n  \"canary-request\":\n    network: everything\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ts := startServer(t, o)
	resp, b := ts.do(t, req{Path: "/api/skills/canary-request", Token: ts.s.Token()})
	if resp.StatusCode != 200 {
		t.Fatalf("detail over malformed overrides = %d %s", resp.StatusCode, b)
	}
	var d struct {
		Row        row    `json:"row"`
		ParseError string `json:"parseError"`
	}
	decode(t, b, &d)
	if d.Row.Name != "canary-request" || d.Row.Grant == nil || d.Row.Grant.Network != "none" || d.ParseError == "" {
		t.Errorf("row %+v parseError %q", d.Row, d.ParseError)
	}
	for _, k := range []string{`"override":null`, `"defaults":null`} {
		if !strings.Contains(string(b), k) {
			t.Errorf("want %s in %.300s", k, b)
		}
	}
	// A parseable file has no parseError key.
	if err := os.WriteFile(o.Paths.OverridesFile(), []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, b = ts.do(t, req{Path: "/api/skills/canary-request", Token: ts.s.Token()})
	if strings.Contains(string(b), "parseError") {
		t.Errorf("parseError on a valid file: %.300s", b)
	}
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func TestStatusReportsNoTranscripts(t *testing.T) {
	o := fixtureOptions(t)
	o.NoTranscripts = true
	if err := os.MkdirAll(o.Paths.StateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(o.Paths.Activity, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ts := startServer(t, o)
	resp, b := ts.do(t, req{Path: "/api/status", Token: ts.s.Token()})
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d %s", resp.StatusCode, b)
	}
	var st statusView
	decode(t, b, &st)
	home := o.Paths.Home
	checkStatus(t, st, o, home)

	// Activity off, no settings file, injected settings paths.
	o2 := emptyOptions(t)
	o2.Paths.Activity = ""
	missing := filepath.Join(t.TempDir(), "settings.json")
	o2.Settings = func() (string, string) { return missing, "" }
	ts2 := startServer(t, o2)
	_, b = ts2.do(t, req{Path: "/api/status", Token: ts2.s.Token()})
	st = statusView{}
	decode(t, b, &st)
	if st.Activity.Enabled || st.Activity.Size != 0 || st.Hook["path"] != missing || st.Hook["exists"] != false || st.ProjectRoot != "" {
		t.Errorf("empty status = %+v", st)
	}
}

type statusView struct {
	Version              string `json:"version"`
	Platform             string `json:"platform"`
	EnforcementAvailable *bool  `json:"enforcementAvailable"`
	Cwd                  string `json:"cwd"`
	ProjectRoot          string `json:"projectRoot"`
	OverridesPath        string `json:"overridesPath"`
	ClaudeDir            string `json:"claudeDir"`
	NoTranscripts        bool   `json:"noTranscripts"`
	Activity             struct {
		Path    string `json:"path"`
		Enabled bool   `json:"enabled"`
		Size    int64  `json:"size"`
	} `json:"activity"`
	Hook        map[string]any `json:"hook"`
	IdleMinutes int            `json:"idleMinutes"`
}

func checkStatus(t *testing.T, st statusView, o Options, home string) {
	t.Helper()
	if st.Version != "test" || st.Platform == "" || st.EnforcementAvailable == nil {
		t.Errorf("version/platform/enforcement = %q %q %v", st.Version, st.Platform, st.EnforcementAvailable)
	}
	if st.Cwd != filepath.Join(home, "proj") || st.ProjectRoot != filepath.Join(home, "proj") {
		t.Errorf("cwd %q projectRoot %q", st.Cwd, st.ProjectRoot)
	}
	if st.OverridesPath != o.Paths.OverridesFile() || st.ClaudeDir != filepath.Join(home, ".claude") {
		t.Errorf("overridesPath %q claudeDir %q", st.OverridesPath, st.ClaudeDir)
	}
	if !st.NoTranscripts || st.IdleMinutes != 30 {
		t.Errorf("noTranscripts %v idleMinutes %d", st.NoTranscripts, st.IdleMinutes)
	}
	if st.Activity.Path != o.Paths.Activity || !st.Activity.Enabled || st.Activity.Size != 3 {
		t.Errorf("activity = %+v", st.Activity)
	}
	if st.Hook["path"] != filepath.Join(home, ".claude", "settings.json") || st.Hook["exists"] != true || st.Hook["hookInstalled"] != false {
		t.Errorf("hook = %v", st.Hook)
	}
	for _, k := range []string{"hookCommand", "excluded", "sandboxEnabled", "skillHook", "deniedHook", "complete"} {
		if _, ok := st.Hook[k]; !ok {
			t.Errorf("hook lacks %q: %v", k, st.Hook)
		}
	}
}
