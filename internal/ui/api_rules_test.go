package ui

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Panda-Taps-LLC/watchdeck/internal/claudesettings"
	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
	"github.com/Panda-Taps-LLC/watchdeck/internal/rulebook"
)

// rulesView is the subset of GET /api/rules the tests read. Recommended
// stays raw so a test can see which keys are present.
type rulesView struct {
	Groups      []rulebook.Group  `json:"groups"`
	Recommended []json.RawMessage `json:"recommended"`
	Drift       []json.RawMessage `json:"drift"`
	Files       []struct {
		Scope    string  `json:"scope"`
		Path     string  `json:"path"`
		ReadOnly *bool   `json:"read_only"`
		Exists   *bool   `json:"exists"`
		Error    *string `json:"error"`
	} `json:"files"`
	Warnings        []string `json:"warnings"`
	ProjectRoot     *string  `json:"project_root"`
	Home            string   `json:"home"`
	Updated         string   `json:"updated"`
	Nonce           string   `json:"nonce"`
	NonceTTLSeconds int      `json:"nonce_ttl_seconds"`
}

func getRules(t *testing.T, ts *testServer, query string) rulesView {
	t.Helper()
	resp, b := ts.do(t, req{Path: "/api/rules" + query, Token: ts.s.Token()})
	if resp.StatusCode != 200 {
		t.Fatalf("GET /api/rules%s = %d %s", query, resp.StatusCode, b)
	}
	var v rulesView
	decode(t, b, &v)
	if v.Groups == nil || v.Recommended == nil || v.Drift == nil || v.Files == nil || v.Warnings == nil {
		t.Fatalf("GET /api/rules%s: a list is null: %s", query, b)
	}
	return v
}

func checkNonce(t *testing.T, n string, ttl int) {
	t.Helper()
	if _, err := hex.DecodeString(n); err != nil || len(n) != 32 {
		t.Errorf("nonce %q is not 32 hex", n)
	}
	if ttl != 300 {
		t.Errorf("nonce_ttl_seconds = %d, want 300", ttl)
	}
}

func TestRulesShapeAndNonce(t *testing.T) {
	o := fixtureOptions(t)
	ts := startServer(t, o)
	v := getRules(t, ts, "")

	want := []string{rulebook.GroupSandbox, rulebook.GroupBlocked, rulebook.GroupAutoMode, rulebook.GroupWatchdeck, rulebook.GroupAsk}
	if len(v.Groups) != len(want) {
		t.Fatalf("groups = %d, want %d", len(v.Groups), len(want))
	}
	for i, g := range v.Groups {
		if g.ID != want[i] || g.Title == "" || g.Rows == nil {
			t.Errorf("group %d = %q %q rows nil %v, want id %q", i, g.ID, g.Title, g.Rows == nil, want[i])
		}
	}
	if len(v.Recommended) != 12 {
		t.Fatalf("recommended = %d rows, want 12 on a fresh home", len(v.Recommended))
	}
	for _, raw := range v.Recommended {
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		if _, ok := m["declined"]; ok {
			t.Errorf("recommended row carries declined on a fresh home: %s", raw)
		}
		if m["recommended"] != true || m["value"] == "" {
			t.Errorf("recommended row = %s", raw)
		}
	}
	if len(v.Files) == 0 {
		t.Fatal("files is empty")
	}
	sawUser := false
	for _, f := range v.Files {
		if f.Scope == "" || f.Path == "" || f.ReadOnly == nil || f.Exists == nil || f.Error == nil {
			t.Errorf("files row missing a key: %+v", f)
		}
		if f.Scope == "user" {
			sawUser = true
			if !*f.Exists || *f.Error != "" {
				t.Errorf("user settings row = exists %v error %q", *f.Exists, *f.Error)
			}
		}
	}
	if !sawUser {
		t.Error("no user settings row in files")
	}
	checkNonce(t, v.Nonce, v.NonceTTLSeconds)
	if v.Home != o.Paths.Home {
		t.Errorf("home = %q, want %q", v.Home, o.Paths.Home)
	}
	if v.ProjectRoot == nil || *v.ProjectRoot != paths.ProjectRoot(o.Cwd, o.Paths.Home) || *v.ProjectRoot == "" {
		t.Errorf("project_root = %v, want %q", v.ProjectRoot, paths.ProjectRoot(o.Cwd, o.Paths.Home))
	}
	if v.Updated == "" {
		t.Error("updated is empty")
	}

	// A nonce is minted per GET and only for the rules purpose.
	v2 := getRules(t, ts, "")
	if v2.Nonce == v.Nonce {
		t.Error("two GETs returned the same nonce")
	}
	if ts.s.spendNonce(v.Nonce, purposeEnforce) {
		t.Error("a rules nonce was spent as an enforce nonce")
	}
	if !ts.s.spendNonce(v.Nonce, purposeRules) {
		t.Error("the rules nonce was not issued for purposeRules")
	}

	// Auto mode without ?project=: no project root.
	ao := emptyOptions(t)
	ao.Cwd = ""
	av := getRules(t, startServer(t, ao), "")
	if av.ProjectRoot == nil || *av.ProjectRoot != "" {
		t.Errorf("auto mode project_root = %v, want empty", av.ProjectRoot)
	}

	// An unknown ?project= is a 400 like the sibling routes.
	resp, b := ts.do(t, req{Path: "/api/rules?project=/nowhere/at/all", Token: ts.s.Token()})
	if resp.StatusCode != 400 {
		t.Errorf("unknown project = %d %s, want 400", resp.StatusCode, b)
	}
}

// breakUserSettings writes a file that does not parse over the fixture's
// user settings.
func breakUserSettings(t *testing.T, o Options) string {
	t.Helper()
	p := filepath.Join(o.Paths.Home, ".claude", "settings.json")
	if err := os.WriteFile(p, []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRulesFilesErrorAsString(t *testing.T) {
	o := fixtureOptions(t)
	p := breakUserSettings(t, o)
	ts := startServer(t, o)
	v := getRules(t, ts, "")
	found := false
	for _, f := range v.Files {
		if f.Scope == "user" {
			found = true
			if f.Error == nil || *f.Error == "" {
				t.Errorf("user settings row has no error text: %+v", f)
			}
			if f.Path != p {
				t.Errorf("user settings row path = %q, want %q", f.Path, p)
			}
		}
	}
	if !found {
		t.Fatal("no user settings row")
	}
	if len(v.Groups) != 5 || len(v.Recommended) != 12 {
		t.Errorf("groups %d recommended %d, want 5 and 12 with a broken file", len(v.Groups), len(v.Recommended))
	}
	if len(v.Warnings) == 0 {
		t.Error("no warning for the broken file")
	}
}

type proposeView struct {
	Refused string `json:"refused"`
	Plan    struct {
		Steps []struct {
			Mechanism string `json:"mechanism"`
			File      string `json:"file"`
			Key       string `json:"key"`
			Value     string `json:"value"`
			RowID     string `json:"row_id"`
			Sentence  string `json:"sentence"`
		} `json:"steps"`
		Suggested *rulebook.AddRequest `json:"suggested"`
	} `json:"plan"`
}

func postPropose(t *testing.T, ts *testServer, body string) (int, []byte) {
	t.Helper()
	resp, b := ts.do(t, req{Method: "POST", Path: "/api/rules/propose", Body: body, Origin: "auto", Token: ts.s.Token(), Header: jsonCT()})
	return resp.StatusCode, b
}

// TestProposeRefusedIs200: a request the rulebook refuses answers 200,
// plan null, and refused the specific reason without the generic
// "value holds a control character or is empty" wrapper, the package
// prefix or the quoted value ahead of a reason.
func TestProposeRefusedIs200(t *testing.T) {
	ts := startServer(t, fixtureOptions(t))
	cases := []struct{ body, want string }{
		{`{"request":{"action":"deny","what":"path","value":""}}`, "the value is empty"},
		{`{"request":{"action":"deny","what":"path","value":"a\u0007b"}}`, "the value holds a control character"},
		{`{"request":{"action":"deny","what":"host","value":"https://example.com/x"}}`, "a domain is a bare host such as example.com"},
		{`{"request":{"action":"deny","what":"path","value":"a(b"}}`, "a native rule value cannot hold ( or )"},
		{`{"request":{"action":"deny","what":"path","value":"../up"}}`, `"../up" climbs out of its directory; use an absolute path`},
		{`{"request":{"action":"deny","what":"command","value":"rm *"}}`, "a command prefix cannot hold *; the rule already matches what follows it"},
		{`{"request":{"action":"deny","what":"path","value":"/tmp/x","scope":"local"}}`, "rules are written to user or project settings only"},
		{`{"request":{"action":"deny","what":"text","value":"x","scope":"project"}}`, "text rules are written to the user policy file only"},
		{`{"request":{"action":"deny","what":"pack-rule","value":"nopack/norule"}}`, `no built-in pack rule "nopack/norule"`},
		{`{"request":{"action":"allow","what":"path","value":"/tmp/x"}}`, `action "allow": rules are added as deny or ask`},
	}
	for _, c := range cases {
		code, b := postPropose(t, ts, c.body)
		var v struct {
			Plan    *json.RawMessage `json:"plan"`
			Refused string           `json:"refused"`
		}
		if code != 200 || json.Unmarshal(b, &v) != nil {
			t.Errorf("%s = %d %s, want 200", c.body, code, b)
			continue
		}
		if v.Plan != nil || !strings.Contains(string(b), `"plan":null`) {
			t.Errorf("%s: plan = %s, want null", c.body, b)
		}
		if v.Refused != c.want {
			t.Errorf("%s: refused = %q, want %q", c.body, v.Refused, c.want)
		}
	}
	// A bare sentinel keeps its own text; errors.Is is untouched.
	if got := refusalReason(rulebook.ErrValue); got != "value holds a control character or is empty" {
		t.Errorf("bare ErrValue = %q", got)
	}
}

func TestProposeRoundTrip(t *testing.T) {
	o := fixtureOptions(t)
	ts := startServer(t, o)

	code, b := postPropose(t, ts, `{"request":{"action":"deny","what":"path","value":"/tmp/wd-propose/secret.txt","tool":"Read"}}`)
	if code != 200 {
		t.Fatalf("propose = %d %s", code, b)
	}
	var v proposeView
	decode(t, b, &v)
	if len(v.Plan.Steps) != 1 {
		t.Fatalf("steps = %+v", v.Plan.Steps)
	}
	st := v.Plan.Steps[0]
	if st.Mechanism != rulebook.MechNative || !strings.HasPrefix(st.Value, "Read(//") || st.Sentence == "" || st.File == "" || st.RowID == "" {
		t.Errorf("step = %+v", st)
	}
	if !strings.Contains(string(b), `"suggested":null`) {
		t.Errorf("suggested is not null for a path rule: %s", b)
	}
	// Nothing was written.
	sb, err := os.ReadFile(filepath.Join(o.Paths.Home, ".claude", "settings.json"))
	if err != nil || strings.Contains(string(sb), "wd-propose") {
		t.Errorf("propose wrote settings: %s %v", sb, err)
	}

	// A command rule suggests its hook twin.
	code, b = postPropose(t, ts, `{"request":{"action":"ask","what":"command","value":"curl"}}`)
	if code != 200 {
		t.Fatalf("command propose = %d %s", code, b)
	}
	decode(t, b, &v)
	if v.Plan.Suggested == nil || v.Plan.Suggested.What != rulebook.WhatText || v.Plan.Suggested.Value != "curl" {
		t.Errorf("command propose suggested = %+v (%s)", v.Plan.Suggested, b)
	}

	if v.Refused != "" {
		t.Errorf("refused = %q on a plan", v.Refused)
	}

	// A refused request is a 200 with plan null and the reason
	// (TestProposeRefusedIs200 has the reasons); a malformed body is a 400.
	for _, body := range []string{
		`{"request":{"action":"deny","what":"path","value":"/tmp/x","scope":"local"}}`,
		`{"request":{"action":"deny","what":"pack-rule","value":"nopack/norule"}}`,
		`{"request":{"action":"deny","what":"path","value":""}}`,
	} {
		code, b = postPropose(t, ts, body)
		if code != 200 || !strings.Contains(string(b), `"plan":null`) || !strings.Contains(string(b), `"refused":"`) {
			t.Errorf("%s = %d %s, want 200 with plan null and a reason", body, code, b)
		}
	}
	code, b = postPropose(t, ts, `{"request":{},"extra":1}`)
	if code != 400 {
		t.Errorf("unknown field = %d %s, want 400", code, b)
	}
	// The guard applies: no Origin, no write.
	resp, b := ts.do(t, req{Method: "POST", Path: "/api/rules/propose", Body: `{"request":{}}`, Token: ts.s.Token(), Header: jsonCT()})
	if resp.StatusCode != 403 {
		t.Errorf("propose without Origin = %d %s, want 403", resp.StatusCode, b)
	}
	resp, _ = ts.do(t, req{Method: "POST", Path: "/api/rules/propose", Body: `{"request":{}}`, Origin: "auto", Header: jsonCT()})
	if resp.StatusCode != 401 {
		t.Errorf("propose without token = %d, want 401", resp.StatusCode)
	}
}

type writeView struct {
	Warning string   `json:"warning"`
	Written []string `json:"written"`
	Backups []string `json:"backups"`
	RowIDs  []string `json:"row_ids"`
	Nonce   string   `json:"nonce"`
	Error   string   `json:"error"`
}

func postJSON(t *testing.T, ts *testServer, path, body string) (int, writeView, []byte) {
	t.Helper()
	resp, b := ts.do(t, req{Method: "POST", Path: path, Body: body, Origin: "auto", Token: ts.s.Token(), Header: jsonCT()})
	var v writeView
	decode(t, b, &v)
	return resp.StatusCode, v, b
}

func jsonStr(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func userSettingsPath(o Options) string {
	return filepath.Join(o.Paths.Home, ".claude", "settings.json")
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// rowByValue is the rulebook row whose value is v, from GET /api/rules.
func rowByValue(t *testing.T, ts *testServer, v string) (rulebook.Rule, bool) {
	t.Helper()
	for _, g := range getRules(t, ts, "").Groups {
		for _, r := range g.Rows {
			if r.Value == v {
				return r, true
			}
		}
	}
	return rulebook.Rule{}, false
}

const pathDenyAdd = `"add":{"action":"deny","what":"path","value":"/tmp/wd-t8/secret.txt","tool":"Read"}`

func TestRulesAddWritesNativeWithBackup(t *testing.T) {
	o := fixtureOptions(t)
	ts := startServer(t, o)
	n := getRules(t, ts, "").Nonce

	code, v, b := postJSON(t, ts, "/api/rules", `{"nonce":"`+n+`",`+pathDenyAdd+`}`)
	if code != 200 {
		t.Fatalf("add = %d %s", code, b)
	}
	sp := userSettingsPath(o)
	if len(v.Written) != 1 || v.Written[0] != sp || len(v.RowIDs) != 1 || v.RowIDs[0] == "" {
		t.Errorf("add result = %s", b)
	}
	checkNonce(t, v.Nonce, 300)
	if !strings.Contains(readFile(t, sp), "Read(//tmp/wd-t8/secret.txt)") {
		t.Fatalf("settings lack the rule: %s", readFile(t, sp))
	}
	baks, _ := filepath.Glob(sp + ".bak-*")
	if len(baks) != 1 || len(v.Backups) != 1 || v.Backups[0] != baks[0] {
		t.Errorf("backups on disk %v, in answer %v; want one", baks, v.Backups)
	}
	led, err := claudesettings.LoadLedger(o.Paths.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(led.Owners(sp, claudesettings.KeyDeny, "Read(//tmp/wd-t8/secret.txt)")) == 0 {
		t.Error("the ledger does not claim the new string")
	}
	if _, ok := rowByValue(t, ts, "Read(//tmp/wd-t8/secret.txt)"); !ok {
		t.Error("the new rule is not in GET /api/rules")
	}

	// The same add again, with the fresh nonce, writes nothing.
	code, v, b = postJSON(t, ts, "/api/rules", `{"nonce":"`+v.Nonce+`",`+pathDenyAdd+`}`)
	if code != 200 || len(v.Written) != 0 || v.Written == nil || v.Backups == nil {
		t.Errorf("second add = %d %s, want 200 with written []", code, b)
	}

	// A request Propose refuses is a 400 that still carries a fresh nonce.
	code, v, b = postJSON(t, ts, "/api/rules", `{"nonce":"`+v.Nonce+`","add":{"action":"deny","what":"path","value":"/tmp/x","scope":"local"}}`)
	if code != 400 || !strings.Contains(v.Error, "user or project") || v.Nonce == "" {
		t.Errorf("local scope = %d %s", code, b)
	}
	// A page-chosen ledger intent is ignored.
	code, v, b = postJSON(t, ts, "/api/rules", `{"nonce":"`+v.Nonce+`","add":{"action":"deny","what":"path","value":"/tmp/wd-t8/other","tool":"Read","intent_id":"recommended:read----ssh-id---"}}`)
	if code != 200 {
		t.Fatalf("add with intent = %d %s", code, b)
	}
	led, _ = claudesettings.LoadLedger(o.Paths.StateDir)
	for _, id := range led.Owners(sp, claudesettings.KeyDeny, "Read(//tmp/wd-t8/other)") {
		if strings.HasPrefix(id, rulebook.IntentPrefix) {
			t.Errorf("the page's intent was used: %v", id)
		}
	}
}

func TestRulesRemoveNotOwned409(t *testing.T) {
	o := fixtureOptions(t)
	sp := userSettingsPath(o)
	if err := os.WriteFile(sp, []byte(`{"permissions":{"deny":["Read(//tmp/wd-hand)"]}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	ts := startServer(t, o)
	row, ok := rowByValue(t, ts, "Read(//tmp/wd-hand)")
	if !ok {
		t.Fatal("hand-written rule not listed")
	}
	n := getRules(t, ts, "").Nonce
	code, v, b := postJSON(t, ts, "/api/rules", jsonStr(t, map[string]string{"nonce": n, "remove": row.ID}))
	if code != 409 || !strings.Contains(v.Error, "by hand") || v.Nonce == "" {
		t.Errorf("remove hand-written = %d %s, want 409 naming by hand with a nonce", code, b)
	}
	if !strings.Contains(readFile(t, sp), "Read(//tmp/wd-hand)") {
		t.Error("the hand-written rule was removed")
	}

	// An id that names no row is a 400, not a 500.
	code, v, b = postJSON(t, ts, "/api/rules", jsonStr(t, map[string]string{"nonce": v.Nonce, "remove": "native:user:permissions.deny:00000000"}))
	if code != 400 || !strings.Contains(v.Error, "no rule") || v.Nonce == "" {
		t.Errorf("remove unknown = %d %s", code, b)
	}

	// A rule watchdeck added is removed, and its string leaves the file.
	code, v, b = postJSON(t, ts, "/api/rules", `{"nonce":"`+v.Nonce+`",`+pathDenyAdd+`}`)
	if code != 200 {
		t.Fatalf("add = %d %s", code, b)
	}
	id := v.RowIDs[0]
	code, v, b = postJSON(t, ts, "/api/rules", jsonStr(t, map[string]string{"nonce": v.Nonce, "remove": id}))
	if code != 200 || len(v.Written) != 1 || len(v.RowIDs) != 1 || v.RowIDs[0] != id {
		t.Errorf("remove owned = %d %s", code, b)
	}
	if strings.Contains(readFile(t, sp), "wd-t8") {
		t.Error("the owned rule is still in the settings file")
	}
}

func TestRulesSetPackRule(t *testing.T) {
	o := fixtureOptions(t)
	ts := startServer(t, o)
	pack, rid := builtinPackRule(t)
	id := "pack:" + pack + "/" + rid
	state := func() rulebook.State {
		for _, g := range getRules(t, ts, "").Groups {
			for _, r := range g.Rows {
				if r.ID == id {
					return r.State
				}
			}
		}
		t.Fatalf("pack row %s not listed", id)
		return ""
	}
	if state() != rulebook.StateOn {
		t.Fatalf("pack row %s is not on to start", id)
	}
	n := getRules(t, ts, "").Nonce
	code, v, b := postJSON(t, ts, "/api/rules", jsonStr(t, map[string]any{"nonce": n, "set": map[string]any{"id": id, "enabled": false}}))
	if code != 200 || len(v.Written) != 1 || v.Written[0] != o.Paths.OverridesFile() || len(v.RowIDs) != 1 || v.RowIDs[0] != id {
		t.Fatalf("set off = %d %s", code, b)
	}
	if state() != rulebook.StateOff {
		t.Error("pack row is not off after set false")
	}
	code, v, b = postJSON(t, ts, "/api/rules", jsonStr(t, map[string]any{"nonce": v.Nonce, "set": map[string]any{"id": id, "enabled": true}}))
	if code != 200 || state() != rulebook.StateOn {
		t.Errorf("set on = %d %s", code, b)
	}
	// Only pack rows switch; another row is a 400 that writes nothing.
	code, v, b = postJSON(t, ts, "/api/rules", `{"nonce":"`+v.Nonce+`",`+pathDenyAdd+`}`)
	if code != 200 {
		t.Fatalf("add = %d %s", code, b)
	}
	native := v.RowIDs[0]
	before := readFile(t, userSettingsPath(o))
	code, v, b = postJSON(t, ts, "/api/rules", jsonStr(t, map[string]any{"nonce": v.Nonce, "set": map[string]any{"id": native, "enabled": false}}))
	if code != 400 || !strings.Contains(v.Error, "pack rules") || v.Nonce == "" {
		t.Errorf("set native = %d %s", code, b)
	}
	if readFile(t, userSettingsPath(o)) != before {
		t.Error("set on a native row changed the settings file")
	}
	code, _, b = postJSON(t, ts, "/api/rules", jsonStr(t, map[string]any{"nonce": v.Nonce, "set": map[string]any{"id": "pack:nopack/norule", "enabled": false}}))
	if code != 400 {
		t.Errorf("set unknown pack = %d %s", code, b)
	}
}

func TestRulesNonceOneUse(t *testing.T) {
	o := fixtureOptions(t)
	ts := startServer(t, o)
	n := getRules(t, ts, "").Nonce
	code, v, b := postJSON(t, ts, "/api/rules", `{"nonce":"`+n+`",`+pathDenyAdd+`}`)
	if code != 200 {
		t.Fatalf("first use = %d %s", code, b)
	}
	code, v2, b := postJSON(t, ts, "/api/rules", `{"nonce":"`+n+`",`+pathDenyAdd+`}`)
	if code != 403 || v2.Error != "stale nonce" || v2.Nonce == "" || v2.Nonce == v.Nonce {
		t.Errorf("second use = %d %s, want 403 stale nonce with a new nonce", code, b)
	}
	// The 403's nonce is good.
	code, _, b = postJSON(t, ts, "/api/rules", `{"nonce":"`+v2.Nonce+`",`+pathDenyAdd+`}`)
	if code != 200 {
		t.Errorf("403's nonce = %d %s", code, b)
	}
	// A nonce of another purpose is stale here.
	other, err := ts.s.issueNonce(purposeEnforce)
	if err != nil {
		t.Fatal(err)
	}
	code, _, b = postJSON(t, ts, "/api/rules", `{"nonce":"`+other+`",`+pathDenyAdd+`}`)
	if code != 403 {
		t.Errorf("enforce nonce = %d %s", code, b)
	}
	needs, _ := getNeeds(t, ts)
	code, _, b = postJSON(t, ts, "/api/rules", `{"nonce":"`+needs.Nonce+`",`+pathDenyAdd+`}`)
	if code != 403 {
		t.Errorf("needs nonce on rules = %d %s", code, b)
	}
	// No nonce at all is a 400.
	code, _, b = postJSON(t, ts, "/api/rules", `{`+pathDenyAdd+`}`)
	if code != 400 || !strings.Contains(string(b), "nonce") {
		t.Errorf("no nonce = %d %s", code, b)
	}
}

func TestRulesExactlyOne(t *testing.T) {
	o := fixtureOptions(t)
	ts := startServer(t, o)
	n := getRules(t, ts, "").Nonce
	for _, body := range []string{
		`{"nonce":"` + n + `"}`,
		`{"nonce":"` + n + `",` + pathDenyAdd + `,"remove":"pack:a/b"}`,
		`{"nonce":"` + n + `","remove":"pack:a/b","set":{"id":"pack:a/b","enabled":true}}`,
		`{"nonce":"` + n + `","remove":"pack:a/b","remove_intent":"intent:path:00000000"}`,
	} {
		code, v, b := postJSON(t, ts, "/api/rules", body)
		if code != 400 || v.Error != "one of add, remove, remove_intent, set, end_temporary" {
			t.Errorf("%s = %d %s", body, code, b)
		}
	}
	// Unknown fields are refused before the spend too.
	code, _, b := postJSON(t, ts, "/api/rules", `{"nonce":"`+n+`","drop":"x"}`)
	if code != 400 {
		t.Errorf("unknown field = %d %s", code, b)
	}
	// None of that spent the nonce.
	code, _, b = postJSON(t, ts, "/api/rules", `{"nonce":"`+n+`",`+pathDenyAdd+`}`)
	if code != 200 {
		t.Errorf("nonce after 400s = %d %s, want it still good", code, b)
	}
}

type declinedView struct {
	Declined []string `json:"declined"`
	Nonce    string   `json:"nonce"`
	Error    string   `json:"error"`
}

func TestRecommendedInstallSkipsDeclined(t *testing.T) {
	o := fixtureOptions(t)
	ts := startServer(t, o)
	rec := rulebook.Recommended()
	if len(rec) != 12 {
		t.Fatalf("recommended = %d", len(rec))
	}
	a, c := rec[0], rec[3]
	n := getRules(t, ts, "").Nonce

	resp, b := ts.do(t, req{Method: "POST", Path: "/api/rules/recommended", Origin: "auto", Token: ts.s.Token(), Header: jsonCT(),
		Body: jsonStr(t, map[string]any{"nonce": n, "action": "decline", "ids": []string{a.ID, c.ID}})})
	var d declinedView
	decode(t, b, &d)
	wantA, wantC := rulebook.IntentPrefix+rulebook.IntentID(a.Value), rulebook.IntentPrefix+rulebook.IntentID(c.Value)
	if resp.StatusCode != 200 || len(d.Declined) != 2 || !contains(d.Declined, wantA) || !contains(d.Declined, wantC) || d.Nonce == "" {
		t.Fatalf("decline = %d %s", resp.StatusCode, b)
	}

	code, v, b := postJSON(t, ts, "/api/rules/recommended", jsonStr(t, map[string]any{"nonce": d.Nonce, "action": "install"}))
	if code != 200 || len(v.RowIDs) != 10 || len(v.Written) != 1 || len(v.Backups) != 1 {
		t.Fatalf("install offer = %d %s, want ten rows in one file", code, b)
	}
	s := readFile(t, userSettingsPath(o))
	if strings.Contains(s, a.Value) || strings.Contains(s, jsonEsc(c.Value)) {
		t.Errorf("a declined rule was installed: %s", s)
	}
	if !strings.Contains(s, rec[1].Value) {
		t.Errorf("an offered rule is missing: %s", s)
	}

	// ids naming a declined rule install it, and it leaves the declined list.
	code, v, b = postJSON(t, ts, "/api/rules/recommended", jsonStr(t, map[string]any{"nonce": v.Nonce, "action": "install", "ids": []string{a.ID}}))
	if code != 200 || len(v.RowIDs) != 1 || v.RowIDs[0] != a.ID {
		t.Fatalf("install declined id = %d %s", code, b)
	}
	if !strings.Contains(readFile(t, userSettingsPath(o)), a.Value) {
		t.Error("the named declined rule was not installed")
	}
	dl, err := rulebook.LoadDeclined(o.Paths.StateDir)
	if err != nil || dl.Has(wantA) || !dl.Has(wantC) {
		t.Errorf("declined after install = %v %v, want only %s", dl.IntentIDs, err, wantC)
	}
	// An id already installed is skipped, never claimed again.
	code, v, b = postJSON(t, ts, "/api/rules/recommended", jsonStr(t, map[string]any{"nonce": v.Nonce, "action": "install", "ids": []string{rec[1].ID}}))
	if code != 200 || len(v.Written) != 0 || len(v.RowIDs) != 0 {
		t.Errorf("install of an installed id = %d %s, want nothing written", code, b)
	}

	// Undecline lists what stays declined.
	resp, b = ts.do(t, req{Method: "POST", Path: "/api/rules/recommended", Origin: "auto", Token: ts.s.Token(), Header: jsonCT(),
		Body: jsonStr(t, map[string]any{"nonce": v.Nonce, "action": "undecline", "ids": []string{c.ID}})})
	decode(t, b, &d)
	if resp.StatusCode != 200 || d.Declined == nil || len(d.Declined) != 0 {
		t.Errorf("undecline = %d %s, want declined []", resp.StatusCode, b)
	}

	// Validation before the spend: a bad action, decline without ids, an
	// id that is not a recommended rule.
	for _, body := range []map[string]any{
		{"nonce": d.Nonce, "action": "zap"},
		{"nonce": d.Nonce, "action": "decline"},
		{"nonce": d.Nonce, "action": "decline", "ids": []string{"native:user:permissions.deny:00000000"}},
	} {
		code, _, b := postJSON(t, ts, "/api/rules/recommended", jsonStr(t, body))
		if code != 400 {
			t.Errorf("%v = %d %s", body, code, b)
		}
	}
	code, _, b = postJSON(t, ts, "/api/rules/recommended", jsonStr(t, map[string]any{"nonce": d.Nonce, "action": "install"}))
	if code != 200 {
		t.Errorf("nonce after 400s = %d %s", code, b)
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// jsonEsc is s as it appears inside a JSON string.
func jsonEsc(s string) string {
	b, _ := json.Marshal(s)
	return string(b[1 : len(b)-1])
}

func TestRemoveRefusedRows(t *testing.T) {
	for _, c := range []struct {
		id    string
		scope claudesettings.Scope
		want  bool
	}{
		{"automode:user:autoMode.soft_deny:0a1b2c3d", claudesettings.ScopeUser, true},
		{"domain:user:sandbox.network.allowedDomains:0a1b2c3d", claudesettings.ScopeUser, true},
		{"excluded:user:sandbox.excludedCommands:0a1b2c3d", claudesettings.ScopeUser, true},
		{"subject:skill:*", claudesettings.ScopeUser, true},
		{"subject:skill:*:0a1b2c3d", claudesettings.ScopeUser, true},
		{"subject:skill:demo", claudesettings.ScopeUser, false},
		{"subject:mcp:srv", claudesettings.ScopeProject, true},
		{"user:my-rule", claudesettings.ScopeProject, true},
		{"user:my-rule", claudesettings.ScopeUser, false},
		{"native:user:permissions.deny:0a1b2c3d", claudesettings.ScopeUser, false},
		{"native:project:permissions.deny:0a1b2c3d", claudesettings.ScopeProject, false},
		{"pack:secrets-read/read-dotenv", claudesettings.ScopeUser, false},
	} {
		if got := removeRefused(rulebook.Rule{ID: c.id, Scope: c.scope}); got != c.want {
			t.Errorf("removeRefused(%s, %s) = %v, want %v", c.id, c.scope, got, c.want)
		}
	}
}

// mcpSubjectOverrides is a user policy file with one MCP subject that has
// three tool gates, so three rows: the bare subject id and two entries.
const mcpSubjectOverrides = "version: 2\nsubjects:\n  - {kind: mcp, name: wdsrv, tools: {'delete_*': deny, 'merge_*': ask, 'drop_*': deny}}\n"

// subjectRows is the ids of the rows of subject:mcp:wdsrv in GET /api/rules.
func subjectRows(t *testing.T, ts *testServer) []string {
	t.Helper()
	var out []string
	for _, g := range getRules(t, ts, "").Groups {
		for _, r := range g.Rows {
			if r.ID == "subject:mcp:wdsrv" || strings.HasPrefix(r.ID, "subject:mcp:wdsrv:") {
				out = append(out, r.ID)
			}
		}
	}
	return out
}

func writeOverrides(t *testing.T, o Options, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(o.Paths.OverridesFile()), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(o.Paths.OverridesFile(), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestRulesRemoveSubjectEntryRefused(t *testing.T) {
	o := fixtureOptions(t)
	writeOverrides(t, o, mcpSubjectOverrides)
	ts := startServer(t, o)
	rows := subjectRows(t, ts)
	if len(rows) != 3 || rows[0] != "subject:mcp:wdsrv" {
		t.Fatalf("subject rows = %v, want the bare id first and two entries", rows)
	}
	before := readFile(t, o.Paths.OverridesFile())
	n := getRules(t, ts, "").Nonce
	code, v, b := postJSON(t, ts, "/api/rules", jsonStr(t, map[string]string{"nonce": n, "remove": rows[1]}))
	want := "remove the mcp wdsrv from its first row (subject:mcp:wdsrv); this row is one of its entries"
	if code != 400 || v.Error != want || v.Nonce == "" {
		t.Errorf("remove an entry row = %d %s, want 400 %q with a nonce", code, b, want)
	}
	if readFile(t, o.Paths.OverridesFile()) != before {
		t.Error("refusing an entry row changed the overrides file")
	}
	if got := subjectRows(t, ts); len(got) != 3 {
		t.Errorf("rows after the refusal = %v", got)
	}
}

func TestRulesRemoveSubjectReportsEveryRow(t *testing.T) {
	o := fixtureOptions(t)
	writeOverrides(t, o, mcpSubjectOverrides)
	ts := startServer(t, o)
	rows := subjectRows(t, ts)
	if len(rows) != 3 {
		t.Fatalf("subject rows = %v", rows)
	}
	n := getRules(t, ts, "").Nonce
	code, v, b := postJSON(t, ts, "/api/rules", jsonStr(t, map[string]string{"nonce": n, "remove": "subject:mcp:wdsrv"}))
	if code != 200 || len(v.Written) != 1 || v.Written[0] != o.Paths.OverridesFile() {
		t.Fatalf("remove the subject = %d %s", code, b)
	}
	got := map[string]bool{}
	for _, id := range v.RowIDs {
		got[id] = true
	}
	for _, id := range rows {
		if !got[id] {
			t.Errorf("row_ids %v lack %s", v.RowIDs, id)
		}
	}
	if len(v.RowIDs) != 3 {
		t.Errorf("row_ids = %v, want exactly the subject's three rows", v.RowIDs)
	}
	if left := subjectRows(t, ts); len(left) != 0 {
		t.Errorf("rows left = %v", left)
	}
}

// TestRulesRecommendedInstallReconcilesFirst: Add all on the Rules page
// does not put back a recommended rule the person removed by hand; the
// install reconciles first, so the intent lands on the declined list (final
// review of Plan 04, finding 2, 2026-10-19).
func TestRulesRecommendedInstallReconcilesFirst(t *testing.T) {
	const removed = "Read(~/.ssh/id_*)"
	o := emptyOptions(t)
	ts := startServer(t, o)
	code, v, b := postJSON(t, ts, "/api/rules/recommended", jsonStr(t, map[string]any{"nonce": getRules(t, ts, "").Nonce, "action": "install"}))
	if code != 200 || len(v.RowIDs) != 12 {
		t.Fatalf("install = %d %s", code, b)
	}
	p := userSettingsPath(o)
	s := readFile(t, p)
	if !strings.Contains(s, `"`+removed+`"`) {
		t.Fatalf("settings lack %s: %s", removed, s)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(s), &doc); err != nil {
		t.Fatal(err)
	}
	perms := doc["permissions"].(map[string]any)
	kept := []any{}
	for _, x := range perms["deny"].([]any) {
		if x != removed {
			kept = append(kept, x)
		}
	}
	perms["deny"] = kept
	nb, _ := json.MarshalIndent(doc, "", "  ")
	if err := os.WriteFile(p, nb, 0o600); err != nil {
		t.Fatal(err)
	}

	code, v, b = postJSON(t, ts, "/api/rules/recommended", jsonStr(t, map[string]any{"nonce": v.Nonce, "action": "install"}))
	if code != 200 || len(v.Written) != 0 {
		t.Fatalf("second install = %d %s, want nothing written", code, b)
	}
	if strings.Contains(readFile(t, p), removed) {
		t.Errorf("Add all put the hand-removed rule back")
	}
	d, err := rulebook.LoadDeclined(o.Paths.StateDir)
	if want := rulebook.IntentPrefix + rulebook.IntentID(removed); err != nil || !d.Has(want) {
		t.Errorf("declined = %v %v, want %s", d.IntentIDs, err, want)
	}
}

// TestRulesRemoveIntent: remove_intent takes every row of an everywhere
// intent; remove on one of its rows still takes that row only (R5).
func TestRulesRemoveIntent(t *testing.T) {
	o := fixtureOptions(t)
	ts := startServer(t, o)
	n := getRules(t, ts, "").Nonce
	add := `"add":{"action":"deny","what":"host","value":"fake-example.com","everywhere":true}`
	code, v, b := postJSON(t, ts, "/api/rules", `{"nonce":"`+n+`",`+add+`}`)
	if code != 200 || len(v.RowIDs) != 4 {
		t.Fatalf("add everywhere = %d %s, want 4 rows", code, b)
	}
	added := v.RowIDs
	intent := rulebook.IntentFor(rulebook.AddRequest{What: rulebook.WhatHost, Value: "fake-example.com", Everywhere: true})
	inIntent := func() int {
		c := 0
		for _, g := range getRules(t, ts, "").Groups {
			for _, r := range g.Rows {
				if r.Intent != nil && r.Intent.ID == intent {
					if r.Intent.Rows == 0 || r.Intent.Sentence == "" {
						t.Errorf("row %s intent %+v", r.ID, r.Intent)
					}
					c++
				}
			}
		}
		return c
	}
	if got := inIntent(); got != 4 {
		t.Fatalf("rows with the intent = %d, want 4", got)
	}

	// One row only.
	code, v, b = postJSON(t, ts, "/api/rules", `{"nonce":"`+v.Nonce+`","remove":"`+added[0]+`"}`)
	if code != 200 || len(v.RowIDs) != 1 || v.RowIDs[0] != added[0] {
		t.Fatalf("remove one row = %d %s", code, b)
	}
	if got := inIntent(); got != 3 {
		t.Errorf("rows with the intent after one remove = %d, want 3", got)
	}

	// The rest of the intent.
	code, v, b = postJSON(t, ts, "/api/rules", `{"nonce":"`+v.Nonce+`","remove_intent":"`+intent+`"}`)
	if code != 200 || len(v.RowIDs) != 3 {
		t.Fatalf("remove_intent = %d %s, want 3 rows", code, b)
	}
	checkNonce(t, v.Nonce, 300)
	if got := inIntent(); got != 0 {
		t.Errorf("rows with the intent after remove_intent = %d", got)
	}
	if s := readFile(t, userSettingsPath(o)); strings.Contains(s, "fake-example.com") {
		t.Errorf("settings still name the host: %s", s)
	}

	// Nothing left, or not an intent id: 400 with a fresh nonce.
	for _, id := range []string{intent, "native:user:permissions.deny:00000000"} {
		code, v, b = postJSON(t, ts, "/api/rules", `{"nonce":"`+v.Nonce+`","remove_intent":"`+id+`"}`)
		if code != 400 || v.Nonce == "" {
			t.Errorf("remove_intent %s = %d %s, want 400 with a nonce", id, code, b)
		}
	}
}

// TestRulesAddPathIntentWarnsAboutSearchHook: a path intent added while the
// hook is not registered for Grep and Glob says so in the answer's
// warning; once it is (an install's group for them), it does not.
func TestRulesAddPathIntentWarnsAboutSearchHook(t *testing.T) {
	o := fixtureOptions(t)
	ts := startServer(t, o)
	n := getRules(t, ts, "").Nonce
	add := `"add":{"action":"deny","what":"path","value":"~/.fake-env","everywhere":true}`
	code, v, b := postJSON(t, ts, "/api/rules", `{"nonce":"`+n+`",`+add+`}`)
	if code != 200 {
		t.Fatalf("add = %d %s", code, b)
	}
	if !strings.Contains(v.Warning, "Grep and Glob") || !strings.Contains(v.Warning, "enforce install") {
		t.Errorf("warning = %q, want one naming Grep and Glob and enforce install", v.Warning)
	}
	// A host intent writes no search rule: no warning.
	code, v, _ = postJSON(t, ts, "/api/rules", `{"nonce":"`+v.Nonce+`","add":{"action":"deny","what":"host","value":"fake-example.com","everywhere":true}}`)
	if code != 200 || v.Warning != "" {
		t.Errorf("host add = %d warning %q", code, v.Warning)
	}
	// With our hook registered for Grep and Glob in the user settings, a
	// second path intent adds no warning.
	sp := userSettingsPath(o)
	var doc map[string]any
	if err := json.Unmarshal([]byte(readFile(t, sp)), &doc); err != nil {
		t.Fatal(err)
	}
	doc["hooks"] = map[string]any{"PreToolUse": []any{map[string]any{
		"matcher": "Glob|Grep",
		"hooks":   []any{map[string]any{"type": "command", "command": "/fake/bin/" + paths.BinaryName + " hook"}},
	}}}
	nb, _ := json.Marshal(doc)
	if err := os.WriteFile(sp, nb, 0o600); err != nil {
		t.Fatal(err)
	}
	code, v, b = postJSON(t, ts, "/api/rules", `{"nonce":"`+v.Nonce+`","add":{"action":"deny","what":"path","value":"~/.fake-other","everywhere":true}}`)
	if code != 200 || v.Warning != "" {
		t.Errorf("add with search registered = %d warning %q (%s)", code, v.Warning, b)
	}
}
