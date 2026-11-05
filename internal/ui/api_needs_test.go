package ui

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/activity"
	"github.com/Panda-Taps-LLC/watchdeck/internal/claudesettings"
	"github.com/Panda-Taps-LLC/watchdeck/internal/manifest"
	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
	"github.com/Panda-Taps-LLC/watchdeck/internal/rulebook"
	"github.com/Panda-Taps-LLC/watchdeck/internal/rules"
)

type needsView struct {
	Items []struct {
		rulebook.Item
		Fixes []struct {
			Request   rulebook.AddRequest `json:"request"`
			Sentence  string              `json:"sentence"`
			Mechanism string              `json:"mechanism"`
			File      string              `json:"file"`
		} `json:"fixes"`
	} `json:"items"`
	Count           int    `json:"count"`
	Since           string `json:"since"`
	ActivityEnabled bool   `json:"activity_enabled"`
	Nonce           string `json:"nonce"`
	NonceTTLSeconds int    `json:"nonce_ttl_seconds"`
}

func getNeeds(t *testing.T, ts *testServer) (needsView, string) {
	t.Helper()
	resp, b := ts.do(t, req{Path: "/api/needs", Token: ts.s.Token()})
	if resp.StatusCode != 200 {
		t.Fatalf("GET /api/needs = %d %s", resp.StatusCode, b)
	}
	var v needsView
	decode(t, b, &v)
	return v, string(b)
}

// builtinPackRule is the first built-in pack rule, "<pack>/<id>".
func builtinPackRule(t *testing.T) (string, string) {
	t.Helper()
	packs := rules.Packs()
	if len(packs) == 0 || len(packs[0].Rules) == 0 {
		t.Fatalf("no built-in packs: %v", rules.LoadError())
	}
	return packs[0].Name, packs[0].Rules[0].ID
}

func TestNeedsShapeFromDenied(t *testing.T) {
	o := fixtureOptions(t)
	pack, id := builtinPackRule(t)
	// TS is left empty: Append stamps now, inside the inbox window.
	appendRec(t, o.Paths.Activity, activity.Record{Kind: activity.KindDenied, SessionID: "s1", ToolUseID: "t1",
		ToolName: "Bash", Argv0: "curl", Reason: "auto mode classifier: sends data out", Cwd: o.Cwd})
	appendRec(t, o.Paths.Activity, activity.Record{Kind: activity.KindDecision, SessionID: "s1", ToolUseID: "t2",
		ToolName: "Read", Decision: "ask", Enforcement: activity.EnforcementGate, Target: "~/.netrc", Reason: "a rule asked",
		Rules: []activity.RuleHit{{Pack: pack, ID: id, Action: "ask"}}, Cwd: o.Cwd})
	ts := startServer(t, o)
	v, raw := getNeeds(t, ts)

	if len(v.Items) != 2 || v.Count != 2 {
		t.Fatalf("items %d count %d, want 2: %s", len(v.Items), v.Count, raw)
	}
	if !v.ActivityEnabled || v.Since == "" {
		t.Errorf("activity_enabled %v since %q", v.ActivityEnabled, v.Since)
	}
	checkNonce(t, v.Nonce, v.NonceTTLSeconds)
	if !ts.s.spendNonce(v.Nonce, purposeNeeds) {
		t.Error("the needs nonce was not issued for purposeNeeds")
	}
	var ask, denial bool
	for _, it := range v.Items {
		if it.Fixes == nil {
			t.Errorf("item %s fixes is null", it.ID)
		}
		switch it.Kind {
		case rulebook.ItemAsk:
			ask = true
			if len(it.RuleIDs) == 0 || it.RuleIDs[0] != pack+"/"+id {
				t.Errorf("ask rule_ids = %v, want [%s/%s]", it.RuleIDs, pack, id)
			}
			if len(it.Fixes) == 0 {
				t.Fatalf("ask item has no fixes: %s", raw)
			}
			f := it.Fixes[0]
			if f.Request.What != rulebook.WhatPackRule || f.Sentence == "" || f.Mechanism != rulebook.MechHook || f.File == "" {
				t.Errorf("ask first fix = %+v", f)
			}
			if len(it.Fixes) < 2 || it.Fixes[1].Request.What != rulebook.WhatPath || it.Fixes[1].Mechanism != rulebook.MechNative {
				t.Errorf("ask second fix = %+v", it.Fixes)
			}
		case rulebook.ItemDenial:
			denial = true
			if it.What != "Bash · curl" || it.Authority != "classifier" {
				t.Errorf("denial = %+v", it.Item)
			}
			if len(it.Fixes) != 1 || it.Fixes[0].Request.What != rulebook.WhatCommand || it.Fixes[0].Sentence == "" {
				t.Errorf("denial fixes = %+v", it.Fixes)
			}
		}
	}
	if !ask || !denial {
		t.Errorf("ask %v denial %v: %s", ask, denial, raw)
	}
}

func TestNeedsWithBrokenSettings(t *testing.T) {
	o := fixtureOptions(t)
	breakUserSettings(t, o)
	appendRec(t, o.Paths.Activity, activity.Record{Kind: activity.KindDenied, SessionID: "s1", ToolUseID: "t1",
		ToolName: "Bash", Argv0: "curl", Reason: "auto mode classifier: no"})
	ts := startServer(t, o)
	v, raw := getNeeds(t, ts)
	if len(v.Items) != 1 || v.Count != 1 {
		t.Errorf("items = %s", raw)
	}
}

func TestNeedsActivityOff(t *testing.T) {
	o := fixtureOptions(t)
	o.Paths.Activity = ""
	ts := startServer(t, o)
	v, raw := getNeeds(t, ts)
	if !strings.Contains(raw, `"items":[]`) || v.Count != 0 || v.ActivityEnabled {
		t.Errorf("activity off = %s", raw)
	}
	checkNonce(t, v.Nonce, v.NonceTTLSeconds)
}

type needsWriteView struct {
	ID      string   `json:"id"`
	Action  string   `json:"action"`
	Written []string `json:"written"`
	Backups []string `json:"backups"`
	RowIDs  []string `json:"row_ids"`
	Nonce   string   `json:"nonce"`
	Error   string   `json:"error"`
}

func postNeed(t *testing.T, ts *testServer, id, body string) (int, needsWriteView, []byte) {
	t.Helper()
	resp, b := ts.do(t, req{Method: "POST", Path: "/api/needs/" + id, Body: body, Origin: "auto", Token: ts.s.Token(), Header: jsonCT()})
	var v needsWriteView
	decode(t, b, &v)
	return resp.StatusCode, v, b
}

// curlDenial appends an auto-mode denial of curl; its only fix is an ask
// on the curl command.
func curlDenial(t *testing.T, o Options, toolUse string) {
	t.Helper()
	appendRec(t, o.Paths.Activity, activity.Record{Kind: activity.KindDenied, SessionID: "s1", ToolUseID: toolUse,
		ToolName: "Bash", Argv0: "curl", Reason: "auto mode classifier: sends data out", Cwd: o.Cwd})
}

func itemIDs(v needsView) []string {
	var out []string
	for _, it := range v.Items {
		out = append(out, it.ID)
	}
	return out
}

func TestNeedsAddRuleClosesItem(t *testing.T) {
	o := fixtureOptions(t)
	curlDenial(t, o, "t1")
	ts := startServer(t, o)
	v, raw := getNeeds(t, ts)
	if len(v.Items) != 1 || len(v.Items[0].Fix) == 0 {
		t.Fatalf("needs = %s", raw)
	}
	id := v.Items[0].ID
	code, w, b := postNeed(t, ts, id, `{"nonce":"`+v.Nonce+`","action":"add_rule"}`)
	if code != 200 || w.ID != id || w.Action != "add_rule" || len(w.RowIDs) == 0 || len(w.Written) != 1 || w.Nonce == "" {
		t.Fatalf("add_rule = %d %s", code, b)
	}
	v, raw = getNeeds(t, ts)
	if len(v.Items) != 0 {
		t.Errorf("item still open after add_rule: %s", raw)
	}
	found := false
	for _, g := range getRules(t, ts, "").Groups {
		for _, r := range g.Rows {
			if r.ID == w.RowIDs[0] {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("rule %s not in GET /api/rules", w.RowIDs[0])
	}
	if !strings.Contains(readFile(t, userSettingsPath(o)), "curl") {
		t.Error("the settings file lacks the curl rule")
	}
}

func TestNeedsAddRuleFixBounds(t *testing.T) {
	o := fixtureOptions(t)
	curlDenial(t, o, "t1")
	// A sandbox refusal carries no fix.
	appendRec(t, o.Paths.Activity, activity.Record{Kind: activity.KindRun, SessionID: "s1", ToolUseID: "t2",
		Skill: "demo", Outcome: activity.OutcomePolicyError, Error: "malformed manifest", Argv0: "python3", Cwd: o.Cwd})
	ts := startServer(t, o)
	v, raw := getNeeds(t, ts)
	var curl, nofix string
	for _, it := range v.Items {
		if len(it.Fix) == 0 {
			nofix = it.ID
		} else {
			curl = it.ID
		}
	}
	if curl == "" || nofix == "" {
		t.Fatalf("want a curl item and a fixless item: %s", raw)
	}
	code, w, b := postNeed(t, ts, curl, `{"nonce":"`+v.Nonce+`","action":"add_rule","fix":5}`)
	if code != 400 || !strings.Contains(w.Error, "out of range") || w.Nonce == "" {
		t.Errorf("fix 5 = %d %s", code, b)
	}
	code, _, b = postNeed(t, ts, curl, `{"nonce":"`+w.Nonce+`","action":"add_rule","fix":-1}`)
	if code != 400 {
		t.Errorf("fix -1 = %d %s", code, b)
	}
	code, w2, b := postNeed(t, ts, nofix, `{"nonce":"`+w.Nonce+`","action":"add_rule"}`)
	if code != 400 || w2.Error != "this item has no rule to add" {
		t.Errorf("no fixes = %d %s", code, b)
	}
	code, _, b = postNeed(t, ts, curl, `{"nonce":"`+w2.Nonce+`","action":"zap"}`)
	if code != 400 {
		t.Errorf("bad action = %d %s", code, b)
	}
}

func TestNeedsDismissSuppressesSignature(t *testing.T) {
	o := fixtureOptions(t)
	curlDenial(t, o, "t1")
	curlDenial(t, o, "t2")
	ts := startServer(t, o)
	v, raw := getNeeds(t, ts)
	if len(v.Items) != 2 {
		t.Fatalf("needs = %s", raw)
	}
	code, w, b := postNeed(t, ts, v.Items[0].ID, `{"nonce":"`+v.Nonce+`","action":"dismiss"}`)
	if code != 200 || w.Action != "dismiss" || len(w.Written) != 0 || w.Written == nil || w.RowIDs == nil {
		t.Fatalf("dismiss = %d %s", code, b)
	}
	// Both items share the signature; a later one is suppressed too.
	curlDenial(t, o, "t3")
	v, raw = getNeeds(t, ts)
	if len(v.Items) != 0 {
		t.Errorf("items after dismiss = %s", raw)
	}
	// Nothing was written to settings.
	if strings.Contains(readFile(t, userSettingsPath(o)), "curl") {
		t.Error("dismiss wrote a rule")
	}
}

func TestNeedsUndoReopens(t *testing.T) {
	o := fixtureOptions(t)
	curlDenial(t, o, "t1")
	ts := startServer(t, o)
	v, _ := getNeeds(t, ts)
	id := v.Items[0].ID
	code, w, b := postNeed(t, ts, id, `{"nonce":"`+v.Nonce+`","action":"add_rule"}`)
	if code != 200 {
		t.Fatalf("add_rule = %d %s", code, b)
	}
	added := w.RowIDs
	code, w, b = postNeed(t, ts, id, `{"nonce":"`+w.Nonce+`","action":"undo"}`)
	if code != 200 || w.Action != "undo" || len(w.RowIDs) != len(added) || w.RowIDs[0] != added[0] || len(w.Written) != 1 {
		t.Fatalf("undo add_rule = %d %s, want rows %v removed", code, b, added)
	}
	v, raw := getNeeds(t, ts)
	if len(v.Items) != 1 || v.Items[0].ID != id {
		t.Errorf("item did not reopen: %s", raw)
	}
	if strings.Contains(readFile(t, userSettingsPath(o)), "curl") {
		t.Error("undo left the rule in the settings file")
	}

	// An acknowledge undoes too, with nothing written.
	code, w, b = postNeed(t, ts, id, `{"nonce":"`+v.Nonce+`","action":"acknowledge"}`)
	if code != 200 {
		t.Fatalf("acknowledge = %d %s", code, b)
	}
	if v2, _ := getNeeds(t, ts); len(v2.Items) != 0 {
		t.Errorf("item open after acknowledge: %v", itemIDs(v2))
	}
	code, w, b = postNeed(t, ts, id, `{"nonce":"`+w.Nonce+`","action":"undo"}`)
	if code != 200 || len(w.RowIDs) != 0 || len(w.Written) != 0 {
		t.Errorf("undo acknowledge = %d %s", code, b)
	}
	if v3, _ := getNeeds(t, ts); len(v3.Items) != 1 {
		t.Errorf("item did not reopen after undo of acknowledge: %v", itemIDs(v3))
	}
	// Nothing left to undo is a 404.
	code, w, b = postNeed(t, ts, id, `{"nonce":"`+w.Nonce+`","action":"undo"}`)
	if code != 404 || !strings.Contains(w.Error, "nothing to undo") || w.Nonce == "" {
		t.Errorf("second undo = %d %s", code, b)
	}
}

func TestNeedsUnknown404(t *testing.T) {
	o := fixtureOptions(t)
	curlDenial(t, o, "t1")
	ts := startServer(t, o)
	v, _ := getNeeds(t, ts)
	n := v.Nonce
	for _, action := range []string{rulebook.ResolveAddRule, rulebook.ResolveAcknowledge, rulebook.ResolveDismiss, rulebook.ResolveUndo} {
		code, w, b := postNeed(t, ts, "0123456789abcdef", `{"nonce":"`+n+`","action":"`+action+`"}`)
		if code != 404 || w.Nonce == "" {
			t.Errorf("%s on an unknown id = %d %s, want 404 with a nonce", action, code, b)
		}
		n = w.Nonce
	}
	// A rules nonce is stale here.
	rn := getRules(t, ts, "").Nonce
	code, _, b := postNeed(t, ts, v.Items[0].ID, `{"nonce":"`+rn+`","action":"acknowledge"}`)
	if code != 403 {
		t.Errorf("rules nonce on needs = %d %s", code, b)
	}
	// With the log off nothing is open.
	off := fixtureOptions(t)
	off.Paths.Activity = ""
	ots := startServer(t, off)
	ov, _ := getNeeds(t, ots)
	code, _, b = postNeed(t, ots, v.Items[0].ID, `{"nonce":"`+ov.Nonce+`","action":"acknowledge"}`)
	if code != 404 {
		t.Errorf("log off = %d %s", code, b)
	}
}

func TestNeedsFixIndex(t *testing.T) {
	// A project-scope fix with no project (auto mode) is refused by
	// Propose and dropped; the next fix keeps its index in the raw list.
	o := emptyOptions(t)
	o.Cwd = ""
	ts := startServer(t, o)
	in, err := ts.s.rulebookInput(httptest.NewRequest("GET", "/api/needs", nil))
	if err != nil {
		t.Fatal(err)
	}
	fixes := fixesFor(in, "", []rulebook.AddRequest{
		{Action: "deny", What: rulebook.WhatPath, Value: "/tmp/wd-idx/a", Tool: rulebook.PathRead, Scope: "project"},
		{Action: "ask", What: rulebook.WhatCommand, Value: "curl"},
	}, o.Paths.Home, func(string) bool { return false })
	if len(fixes) != 1 || fixes[0].Index != 1 || fixes[0].Request.Value != "curl" {
		t.Fatalf("fixes = %+v, want only curl at index 1", fixes)
	}

	// Through the route: every fix carries its index.
	fo := fixtureOptions(t)
	curlDenial(t, fo, "t1")
	fts := startServer(t, fo)
	_, raw := getNeeds(t, fts)
	if !strings.Contains(raw, `"fixes":[{"index":0,`) {
		t.Errorf("fixes lack index: %s", raw)
	}
}

// Plan 05 Task 7 (2026-10-20): the inbox dialog names the file it writes
// as "~/…", so GET /api/needs serves fixes[].file in the display form; the
// write path is still computed server-side from the raw fix.
func TestNeedsFixFileIsTildified(t *testing.T) {
	o := fixtureOptions(t)
	curlDenial(t, o, "t1")
	ts := startServer(t, o)
	v, raw := getNeeds(t, ts)
	if len(v.Items) == 0 || len(v.Items[0].Fixes) == 0 {
		t.Fatalf("no fixes: %s", raw)
	}
	if f := v.Items[0].Fixes[0].File; !strings.HasPrefix(f, "~/") {
		t.Errorf("fixes[0].file = %q, want ~/…", f)
	}
	if strings.Contains(raw, o.Paths.Home) {
		t.Errorf("needs JSON carries the home dir: %s", raw)
	}
}

// Plan 06 Task 6 (S2): an observed verdict is never a need. The silent
// shadow record has decision "shadow" (not deny or ask) and the shadowed
// rewrite is enforcement sandbox, so neither opens an inbox item through
// rulebook.Open or GET /api/needs. A real gate ask beside them still does,
// so the check is not vacuous.
func TestShadowRecordIsNotANeed(t *testing.T) {
	o := fixtureOptions(t)
	for _, r := range shadowRecords(o.Cwd) {
		r.TS = "" // Append stamps now, inside the inbox window
		appendRec(t, o.Paths.Activity, r)
	}
	appendRec(t, o.Paths.Activity, activity.Record{Kind: activity.KindDecision, SessionID: "s", ToolUseID: "u-real",
		ToolName: "Read", Decision: "ask", Enforcement: activity.EnforcementGate, Target: "~/.netrc", Reason: "a rule asked", Cwd: o.Cwd})

	items, err := rulebook.Open(rulebook.InboxInput{Paths: o.Paths, Since: time.Now().Add(-time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].ToolUseID != "u-real" {
		t.Fatalf("rulebook.Open = %+v, want only the real ask", items)
	}

	v, raw := getNeeds(t, startServer(t, o))
	if v.Count != 1 || len(v.Items) != 1 || v.Items[0].ToolUseID != "u-real" {
		t.Fatalf("/api/needs = %s, want only the real ask", raw)
	}
	for _, bad := range []string{"u-silent", "u-rewrite"} {
		if strings.Contains(raw, bad) {
			t.Errorf("/api/needs lists %s: %s", bad, raw)
		}
	}
}

// leakOptions is fixtureOptions with the activity log off and one leak
// watch finding served by Options.Leaks.
func leakOptions(t *testing.T) Options {
	t.Helper()
	o := fixtureOptions(t)
	o.Paths.Activity = ""
	o.Leaks = func(since time.Time) []rulebook.Leak {
		return []rulebook.Leak{{SessionID: "s1", Ref: "toolu_env", Tool: "Read", Target: "~/proj/.env", Where: "result",
			Pattern: "slack-token", Label: "Slack token", Project: "~/proj", TS: time.Now().Add(-time.Minute)}}
	}
	return o
}

// TestNeedsListsLeakItemsWithoutActivity: leak items come from the session
// index, so they are listed with the activity log off (Plan 08 D4).
func TestNeedsListsLeakItemsWithoutActivity(t *testing.T) {
	ts := startServer(t, leakOptions(t))
	v, raw := getNeeds(t, ts)
	if v.ActivityEnabled || len(v.Items) != 1 || v.Count != 1 {
		t.Fatalf("needs = %s", raw)
	}
	it := v.Items[0]
	if it.Kind != rulebook.KindLeak || it.What != "Read · ~/proj/.env" || it.Why != "Slack token appeared in the result" ||
		it.Authority != "leak" || len(it.Fixes) != 2 || it.Fixes[0].Request.What != rulebook.WhatPath ||
		it.Fixes[0].Request.Everywhere || !it.Fixes[1].Request.Everywhere {
		t.Errorf("leak item = %s", raw)
	}
}

func TestNeedsLeakDismiss(t *testing.T) {
	ts := startServer(t, leakOptions(t))
	v, raw := getNeeds(t, ts)
	if len(v.Items) != 1 {
		t.Fatalf("needs = %s", raw)
	}
	id := v.Items[0].ID
	code, w, b := postNeed(t, ts, id, `{"nonce":"`+v.Nonce+`","action":"dismiss"}`)
	if code != 200 || w.Action != "dismiss" {
		t.Fatalf("dismiss = %d %s", code, b)
	}
	if v, raw = getNeeds(t, ts); len(v.Items) != 0 {
		t.Errorf("leak item still listed after dismiss: %s", raw)
	}

	// A leak in a model reply has no rule to add (only a file leak does,
	// Plan 08 Task 5).
	o := fixtureOptions(t)
	o.Paths.Activity = ""
	o.Leaks = func(time.Time) []rulebook.Leak {
		return []rulebook.Leak{{SessionID: "s1", Ref: "uuid-1", Where: "reply", Pattern: "slack-token", Label: "Slack token", TS: time.Now().Add(-time.Minute)}}
	}
	ts = startServer(t, o)
	v, raw = getNeeds(t, ts)
	if len(v.Items) != 1 || len(v.Items[0].Fixes) != 0 {
		t.Fatalf("reply leak = %s", raw)
	}
	code, w, b = postNeed(t, ts, v.Items[0].ID, `{"nonce":"`+v.Nonce+`","action":"add_rule"}`)
	if code != 400 || w.Error != "this item has no rule to add" {
		t.Errorf("add_rule on a reply leak = %d %s", code, b)
	}
}

// ---------------------------------------------------------------- Plan 08 Task 5: allow for a while, every-route fixes

// allowView is a needs item's allow fields and its fixes' steps.
type allowView struct {
	Items []struct {
		ID       string            `json:"id"`
		Kind     rulebook.ItemKind `json:"kind"`
		What     string            `json:"what"`
		Pausable bool              `json:"pausable"`
		AllowFor []string          `json:"allow_for"`
		Fixes    []struct {
			Index   int                 `json:"index"`
			Request rulebook.AddRequest `json:"request"`
			Steps   []string            `json:"steps"`
			Files   []string            `json:"files"`
		} `json:"fixes"`
	} `json:"items"`
	LeakWatch bool   `json:"leak_watch"`
	AllowFile string `json:"allow_file"`
	Nonce     string `json:"nonce"`
}

func getAllow(t *testing.T, ts *testServer) (allowView, string) {
	t.Helper()
	resp, b := ts.do(t, req{Path: "/api/needs", Token: ts.s.Token()})
	if resp.StatusCode != 200 {
		t.Fatalf("GET /api/needs = %d %s", resp.StatusCode, b)
	}
	var v allowView
	decode(t, b, &v)
	return v, string(b)
}

// twoPackRules is two built-in pack rules, "<pack>/<id>" each.
func twoPackRules(t *testing.T) (string, string) {
	t.Helper()
	var out []string
	for _, p := range rules.Packs() {
		for _, r := range p.Rules {
			out = append(out, p.Name+"/"+r.ID)
		}
	}
	if len(out) < 2 {
		t.Fatalf("fewer than two built-in pack rules: %v", rules.LoadError())
	}
	return out[0], out[1]
}

func hit(key, action string) activity.RuleHit {
	pack, id, _ := strings.Cut(key, "/")
	return activity.RuleHit{Pack: pack, ID: id, Action: action}
}

// packAsk appends a gate ask that rules a and b fired on.
func packAsk(t *testing.T, o Options, session, toolUse, a, b string) {
	t.Helper()
	appendRec(t, o.Paths.Activity, activity.Record{Kind: activity.KindDecision, SessionID: session, ToolUseID: toolUse,
		ToolName: "Bash", Argv0: "curl", Decision: "ask", Enforcement: activity.EnforcementGate, Reason: "a rule asked",
		Rules: []activity.RuleHit{hit(a, "ask"), hit(b, "log")}, Cwd: o.Cwd})
}

func temporaries(t *testing.T, o Options) []rulebook.TemporaryView {
	t.Helper()
	return rulebook.ListTemporaries(rulebook.Input{Paths: o.Paths})
}

// TestNeedsAllowSessionPausesEveryRule: "Allow for this session" on an ask
// pauses every rule on the item (R10), each for the item's session, and
// the allow resolution closes the item.
func TestNeedsAllowSessionPausesEveryRule(t *testing.T) {
	o := fixtureOptions(t)
	a, b := twoPackRules(t)
	packAsk(t, o, "sess-1", "t1", a, b)
	ts := startServer(t, o)
	v, raw := getAllow(t, ts)
	if len(v.Items) != 1 || !v.Items[0].Pausable || strings.Join(v.Items[0].AllowFor, ",") != "session,1h" {
		t.Fatalf("needs = %s", raw)
	}
	if v.AllowFile != "~/.config/watchdeck/overrides.yaml" && !strings.HasSuffix(v.AllowFile, "overrides.yaml") {
		t.Errorf("allow_file = %q", v.AllowFile)
	}
	id := v.Items[0].ID
	resp, body := ts.do(t, req{Method: "POST", Path: "/api/needs/" + id, Body: `{"nonce":"` + v.Nonce + `","action":"allow","for":"session"}`,
		Origin: "auto", Token: ts.s.Token(), Header: jsonCT()})
	var w struct {
		Action       string   `json:"action"`
		TemporaryIDs []string `json:"temporary_ids"`
		Nonce        string   `json:"nonce"`
	}
	decode(t, body, &w)
	if resp.StatusCode != 200 || w.Action != "allow" || len(w.TemporaryIDs) != 2 || w.Nonce == "" {
		t.Fatalf("allow = %d %s", resp.StatusCode, body)
	}
	temps := temporaries(t, o)
	if len(temps) != 2 {
		t.Fatalf("temporaries = %+v", temps)
	}
	for i, tv := range temps {
		if tv.ID != w.TemporaryIDs[i] || tv.Kind != "rule" || tv.Session != "sess-1" {
			t.Errorf("temporary %d = %+v", i, tv)
		}
	}
	if v, raw := getAllow(t, ts); len(v.Items) != 0 {
		t.Errorf("item still open after allow: %s", raw)
	}
}

// TestNeedsAllowHourGrantsSkill: "Allow for an hour" on a skill's request
// widens that skill's grant for an hour (R11); for one session it is a 409
// (D9: a sandboxed run carries no session id).
func TestNeedsAllowHourGrantsSkill(t *testing.T) {
	o := fixtureOptions(t)
	appendRec(t, o.Paths.Activity, activity.Record{Kind: activity.KindDecision, SessionID: "sess-1", ToolUseID: "t1",
		ToolName: "Bash", Decision: "rewrite", Enforcement: activity.EnforcementSandbox, Skills: []string{"demo"},
		Ungranted: []string{"demo: network: all", "demo: exec: /bin/sh"}, Cwd: o.Cwd})
	ts := startServer(t, o)
	v, raw := getAllow(t, ts)
	if len(v.Items) != 1 || v.Items[0].Kind != rulebook.ItemSkillRequest || !v.Items[0].Pausable || strings.Join(v.Items[0].AllowFor, ",") != "1h" {
		t.Fatalf("needs = %s", raw)
	}
	id := v.Items[0].ID
	code, w, b := postNeed(t, ts, id, `{"nonce":"`+v.Nonce+`","action":"allow","for":"session"}`)
	if code != 409 || !strings.Contains(w.Error, "for an hour, not for one session") || w.Nonce == "" {
		t.Fatalf("allow for a session = %d %s", code, b)
	}
	if n := len(temporaries(t, o)); n != 0 {
		t.Fatalf("a refused allow wrote %d temporaries", n)
	}
	resp, body := ts.do(t, req{Method: "POST", Path: "/api/needs/" + id, Body: `{"nonce":"` + w.Nonce + `","action":"allow","for":"1h"}`,
		Origin: "auto", Token: ts.s.Token(), Header: jsonCT()})
	if resp.StatusCode != 200 || !strings.Contains(string(body), `"temporary_ids":["`) {
		t.Fatalf("allow for an hour = %d %s", resp.StatusCode, body)
	}
	temps := temporaries(t, o)
	if len(temps) != 1 || temps[0].Kind != "grant" || temps[0].Session != "" || !strings.Contains(temps[0].Sentence, "demo also gets network all") {
		t.Fatalf("temporaries = %+v", temps)
	}
	until, err := time.Parse(time.RFC3339, temps[0].Until)
	if err != nil || time.Until(until) > time.Hour+time.Minute || time.Until(until) < 58*time.Minute {
		t.Errorf("until %q, want an hour from now", temps[0].Until)
	}
	if v, raw := getAllow(t, ts); len(v.Items) != 0 {
		t.Errorf("item still open after allow: %s", raw)
	}
}

// TestNeedsAllowRefusedForNativeDenial: auto mode's denial and an ask a
// Claude Code settings rule made cannot be allowed for a while: a 409
// with the D9 sentence, a fresh nonce, nothing written.
func TestNeedsAllowRefusedForNativeDenial(t *testing.T) {
	o := fixtureOptions(t)
	a, _ := twoPackRules(t)
	curlDenial(t, o, "t1")
	appendRec(t, o.Paths.Activity, activity.Record{Kind: activity.KindDecision, SessionID: "s1", ToolUseID: "t2",
		ToolName: "Bash", Argv0: "rm", Decision: "deny", Enforcement: activity.EnforcementGate, Reason: "your settings deny it",
		Rules: []activity.RuleHit{hit(a, "ask"), {Pack: activity.PackClaudeSettings, ID: "Bash(rm *)", Action: "deny"}}, Cwd: o.Cwd})
	ts := startServer(t, o)
	v, raw := getAllow(t, ts)
	if len(v.Items) != 2 {
		t.Fatalf("needs = %s", raw)
	}
	nonce := v.Nonce
	for _, it := range v.Items {
		if it.Pausable || it.AllowFor == nil || len(it.AllowFor) != 0 {
			t.Errorf("%s: pausable %v allow_for %v", it.What, it.Pausable, it.AllowFor)
		}
		for _, f := range []string{"1h", "session"} {
			code, w, b := postNeed(t, ts, it.ID, `{"nonce":"`+nonce+`","action":"allow","for":"`+f+`"}`)
			if code != 409 || !strings.Contains(w.Error, rulebook.NativeRuleSentence) || w.Nonce == "" {
				t.Errorf("%s for %s = %d %s", it.What, f, code, b)
			}
			nonce = w.Nonce
		}
	}
	if _, err := os.Stat(o.Paths.OverridesFile()); !os.IsNotExist(err) {
		t.Errorf("the policy file was written: %v", err)
	}
	if v, _ := getAllow(t, ts); len(v.Items) != 2 {
		t.Error("a refused allow closed an item")
	}
	// for is checked before the nonce is spent.
	code, _, b := postNeed(t, ts, v.Items[0].ID, `{"nonce":"`+nonce+`","action":"allow","for":"8h"}`)
	if code != 400 || !ts.s.spendNonce(nonce, purposeNeeds) {
		t.Errorf("for 8h = %d %s (or the nonce was spent)", code, b)
	}
}

// TestNeedsPausableFlag: pausable and allow_for are computed server-side
// (R10, R11): an ask whose every rule is a pack or policy-file rule, a
// skill item with something to grant; nothing else.
func TestNeedsPausableFlag(t *testing.T) {
	o := fixtureOptions(t)
	a, b := twoPackRules(t)
	writeOverrides(t, o, "version: 2\nrules:\n  - id: no-prod\n    tool: Bash\n    action: ask\n    match:\n      literals: [prod-db]\n")
	gate := func(tu string, hits []activity.RuleHit, mod func(*activity.Record)) {
		r := activity.Record{Kind: activity.KindDecision, SessionID: "sess-1", ToolUseID: tu, ToolName: "Bash", Argv0: "x" + tu,
			Decision: "ask", Enforcement: activity.EnforcementGate, Reason: "asked " + tu, Rules: hits, Cwd: o.Cwd}
		if mod != nil {
			mod(&r)
		}
		appendRec(t, o.Paths.Activity, r)
	}
	gate("packs", []activity.RuleHit{hit(a, "ask"), hit(b, "log")}, nil)
	gate("user", []activity.RuleHit{{Pack: "user", ID: "no-prod", Action: "ask"}}, nil)
	gate("native", []activity.RuleHit{hit(a, "ask"), {Pack: activity.PackClaudeSettings, ID: "Bash(x *)", Action: "ask"}}, nil)
	gate("norules", nil, nil)
	gate("subject", []activity.RuleHit{hit(a, "log")}, func(r *activity.Record) {
		r.Subject = &activity.Subject{Kind: "tool", Name: "files"}
	})
	gate("nosession", []activity.RuleHit{hit(a, "ask")}, func(r *activity.Record) { r.SessionID = "" })
	appendRec(t, o.Paths.Activity, activity.Record{Kind: activity.KindDecision, SessionID: "sess-1", ToolUseID: "skill",
		ToolName: "Bash", Decision: "rewrite", Enforcement: activity.EnforcementSandbox, Skills: []string{"demo"},
		Ungranted: []string{"demo: network: all"}, Cwd: o.Cwd})
	appendRec(t, o.Paths.Activity, activity.Record{Kind: activity.KindDecision, SessionID: "sess-1", ToolUseID: "skillexec",
		ToolName: "Bash", Decision: "rewrite", Enforcement: activity.EnforcementSandbox, Skills: []string{"other"},
		Ungranted: []string{"other: exec: /bin/sh"}, Cwd: o.Cwd})
	appendRec(t, o.Paths.Activity, activity.Record{Kind: activity.KindRun, SessionID: "sess-1", ToolUseID: "run",
		Skills: []string{"demo"}, Argv0: "python3", Outcome: activity.OutcomeOK, Cwd: o.Cwd,
		Hints: []activity.Hint{{Kind: activity.HintNetwork, Text: "The sandbox blocked a network connection."}}})
	curlDenial(t, o, "denial")

	ts := startServer(t, o)
	v, raw := getAllow(t, ts)
	got := map[string]string{}
	for _, it := range v.Items {
		got[string(it.Kind)+" "+it.What] = strings.Join(it.AllowFor, ",")
		if it.Pausable != (len(it.AllowFor) > 0) {
			t.Errorf("%s: pausable %v with allow_for %v", it.What, it.Pausable, it.AllowFor)
		}
	}
	want := map[string]string{
		"ask Bash · xpacks":              "session,1h",
		"ask Bash · xuser":               "session,1h",
		"ask Bash · xnative":             "",
		"ask Bash · xnorules":            "",
		"ask Bash · xsubject":            "",
		"ask Bash · xnosession":          "1h",
		"skill_request Bash · demo":      "1h",
		"skill_request Bash · other":     "",
		"sandbox_refusal Bash · python3": "1h",
		"denial Bash · curl":             "",
	}
	for k, w := range want {
		g, ok := got[k]
		if !ok {
			t.Errorf("no item %q in %s", k, raw)
			continue
		}
		if g != w {
			t.Errorf("%s: allow_for %q, want %q", k, g, w)
		}
	}
}

// TestNeedsAllowUndoEndsTemporaries: Undo of an allow ends every
// temporary it wrote (R10) and reopens the item.
func TestNeedsAllowUndoEndsTemporaries(t *testing.T) {
	o := fixtureOptions(t)
	a, b := twoPackRules(t)
	packAsk(t, o, "sess-1", "t1", a, b)
	ts := startServer(t, o)
	v, raw := getAllow(t, ts)
	if len(v.Items) != 1 {
		t.Fatalf("needs = %s", raw)
	}
	id := v.Items[0].ID
	code, w, body := postNeed(t, ts, id, `{"nonce":"`+v.Nonce+`","action":"allow","for":"1h"}`)
	if code != 200 || len(temporaries(t, o)) != 2 {
		t.Fatalf("allow = %d %s; temporaries %+v", code, body, temporaries(t, o))
	}
	code, w, body = postNeed(t, ts, id, `{"nonce":"`+w.Nonce+`","action":"undo"}`)
	if code != 200 || w.Action != "undo" {
		t.Fatalf("undo = %d %s", code, body)
	}
	if temps := temporaries(t, o); len(temps) != 0 {
		t.Errorf("temporaries after undo: %+v", temps)
	}
	if v, raw := getAllow(t, ts); len(v.Items) != 1 || v.Items[0].ID != id {
		t.Errorf("item not reopened after undo: %s", raw)
	}
	// A temporary already gone (ended on the Rules page) is no reason for
	// the undo to fail.
	v, _ = getAllow(t, ts)
	code, w, body = postNeed(t, ts, id, `{"nonce":"`+v.Nonce+`","action":"allow","for":"1h"}`)
	if code != 200 {
		t.Fatalf("allow again = %d %s", code, body)
	}
	if err := rulebook.End(rulebook.Input{Paths: o.Paths}, "all"); err != nil {
		t.Fatal(err)
	}
	if code, _, body = postNeed(t, ts, id, `{"nonce":"`+w.Nonce+`","action":"undo"}`); code != 200 {
		t.Errorf("undo with the temporaries already ended = %d %s", code, body)
	}
}

// TestNeedsEverywhereFixAndUndo: a path item's second fix is the
// everywhere form, listing every step and file (D8); Undo removes the
// intent as RemoveIntent does, so a string another rule also claims stays.
func TestNeedsEverywhereFixAndUndo(t *testing.T) {
	o := fixtureOptions(t)
	appendRec(t, o.Paths.Activity, activity.Record{Kind: activity.KindDecision, SessionID: "s1", ToolUseID: "t1",
		ToolName: "Read", Decision: "ask", Enforcement: activity.EnforcementGate, Target: "~/.netrc", Reason: "a rule asked", Cwd: o.Cwd})
	ts := startServer(t, o)
	v, raw := getAllow(t, ts)
	if len(v.Items) != 1 || len(v.Items[0].Fixes) != 2 {
		t.Fatalf("needs = %s", raw)
	}
	if strings.Contains(raw, o.Paths.Home) {
		t.Errorf("needs JSON carries the home dir: %s", raw)
	}
	plain, every := v.Items[0].Fixes[0], v.Items[0].Fixes[1]
	if plain.Request.Everywhere || !every.Request.Everywhere || every.Index != 1 || len(every.Steps) < 4 || len(every.Files) != 2 || len(plain.Steps) != 1 {
		t.Fatalf("fixes = %s", raw)
	}
	// The plain Read rule, added by itself on the Rules page first.
	code, _, b := postJSON(t, ts, "/api/rules", `{"nonce":"`+getRules(t, ts, "").Nonce+`","add":{"action":"deny","what":"path","value":"~/.netrc","tool":"Read"}}`)
	if code != 200 {
		t.Fatalf("plain add = %d %s", code, b)
	}
	v, _ = getAllow(t, ts)
	if len(v.Items) != 0 {
		t.Fatalf("the plain rule should close the item: %+v", v.Items)
	}
	// Undo nothing; reopen by adding the everywhere fix to a second item.
	appendRec(t, o.Paths.Activity, activity.Record{Kind: activity.KindDecision, SessionID: "s1", ToolUseID: "t2",
		ToolName: "Read", Decision: "ask", Enforcement: activity.EnforcementGate, Target: "~/.pgpass", Reason: "a rule asked", Cwd: o.Cwd})
	v, raw = getAllow(t, ts)
	if len(v.Items) != 1 || len(v.Items[0].Fixes) != 2 {
		t.Fatalf("needs = %s", raw)
	}
	id := v.Items[0].ID
	code, w, b := postNeed(t, ts, id, `{"nonce":"`+v.Nonce+`","action":"add_rule","fix":1}`)
	if code != 200 || len(w.RowIDs) < 4 {
		t.Fatalf("everywhere add = %d %s", code, b)
	}
	settings := readFile(t, userSettingsPath(o))
	if !strings.Contains(settings, "Read(~/.pgpass)") || !strings.Contains(settings, "Edit(~/.pgpass)") || !strings.Contains(readFile(t, o.Paths.OverridesFile()), "intent-path-") {
		t.Fatalf("everywhere rules missing: %s", settings)
	}
	code, w, b = postNeed(t, ts, id, `{"nonce":"`+w.Nonce+`","action":"undo"}`)
	if code != 200 {
		t.Fatalf("undo = %d %s", code, b)
	}
	settings = readFile(t, userSettingsPath(o))
	if strings.Contains(settings, "~/.pgpass") || strings.Contains(readFile(t, o.Paths.OverridesFile()), "intent-path-") {
		t.Errorf("undo left the intent's rules: %s", settings)
	}
	if !strings.Contains(settings, "Read(~/.netrc)") {
		t.Errorf("undo removed the plain rule too: %s", settings)
	}
	if v, _ := getAllow(t, ts); len(v.Items) != 1 || v.Items[0].ID != id {
		t.Error("the item did not reopen")
	}
}

// TestNeedsLeakItemCarriesNoSecret (Review Focus 1 on the API): a leak
// whose target is itself secret-shaped reaches /api/needs with neither the
// value nor its first bytes anywhere, its fixes included; a leak with an
// ordinary path gets the path fix and its everywhere form.
func TestNeedsLeakItemCarriesNoSecret(t *testing.T) {
	o := fixtureOptions(t)
	o.Paths.Activity = ""
	key := "xox" + "b-" + "1234567890" + "-" + "abcdefghijKLMNOPqrst"
	now := time.Now().Add(-time.Minute)
	o.Leaks = func(time.Time) []rulebook.Leak {
		return []rulebook.Leak{
			{SessionID: "s1", Ref: "toolu_key", Tool: "Read", Target: "~/proj/" + key, Where: "result", Pattern: "slack-token", Label: "Slack token", TS: now},
			{SessionID: "s1", Ref: "toolu_env", Tool: "Read", Target: "~/proj/.env", Where: "result", Pattern: "slack-token", Label: "Slack token", TS: now},
		}
	}
	ts := startServer(t, o)
	v, raw := getAllow(t, ts)
	if !v.LeakWatch || len(v.Items) != 2 {
		t.Fatalf("needs = %s", raw)
	}
	if strings.Contains(raw, key) || strings.Contains(raw, key[:9]) {
		t.Errorf("/api/needs holds the key-shaped value or its first 9 bytes")
	}
	for _, it := range v.Items {
		if it.Pausable || len(it.AllowFor) != 0 {
			t.Errorf("%s: a leak is not pausable", it.What)
		}
		switch it.What {
		case "Read":
			if len(it.Fixes) != 0 {
				t.Errorf("the key-shaped target still gave a fix: %+v", it.Fixes)
			}
		case "Read · ~/proj/.env":
			if len(it.Fixes) != 2 || it.Fixes[0].Request.Everywhere || !it.Fixes[1].Request.Everywhere {
				t.Errorf("leak fixes = %+v", it.Fixes)
			}
		default:
			t.Errorf("unexpected item %q", it.What)
		}
	}
	code, w, b := postNeed(t, ts, v.Items[0].ID, `{"nonce":"`+v.Nonce+`","action":"allow","for":"1h"}`)
	if code != 409 || strings.Contains(string(b), key[:9]) {
		t.Errorf("allow on a leak = %d %s", code, b)
	}
	_ = w
	// Under --no-transcripts there is no leak watch.
	o2 := fixtureOptions(t)
	if v, raw := getAllow(t, startServer(t, o2)); v.LeakWatch {
		t.Errorf("leak_watch without Options.Leaks: %s", raw)
	}
}

// TestNeedsAllowGoneRuleIs409: an ask whose policy-file rule is gone (the
// Home page names no project, so a project file's rule counts as gone) is
// a 409 that names the rule, not a 500.
func TestNeedsAllowGoneRuleIs409(t *testing.T) {
	o := fixtureOptions(t)
	appendRec(t, o.Paths.Activity, activity.Record{Kind: activity.KindDecision, SessionID: "sess-1", ToolUseID: "t1",
		ToolName: "Bash", Argv0: "psql", Decision: "ask", Enforcement: activity.EnforcementGate, Reason: "rule no-prod asked",
		Rules: []activity.RuleHit{{Pack: "user", ID: "no-prod", Action: "ask"}}, Cwd: o.Cwd})
	ts := startServer(t, o)
	v, raw := getAllow(t, ts)
	if len(v.Items) != 1 || !v.Items[0].Pausable {
		t.Fatalf("needs = %s", raw)
	}
	code, w, b := postNeed(t, ts, v.Items[0].ID, `{"nonce":"`+v.Nonce+`","action":"allow","for":"1h"}`)
	if code != 409 || !strings.Contains(w.Error, "no-prod") || w.Nonce == "" {
		t.Errorf("allow = %d %s", code, b)
	}
}

// TestNeedsAllowSkipsLongerPause (Task 5 fix round 1): "Allow for an hour"
// leaves a rule the person already paused for longer alone (it is neither
// shortened nor ended by the Undo); with nothing left to pause it is a 409.
func TestNeedsAllowSkipsLongerPause(t *testing.T) {
	o := fixtureOptions(t)
	a, b := twoPackRules(t)
	in := rulebook.Input{Paths: o.Paths}
	long, err := rulebook.Pause(in, []string{"pack:" + a}, "8h")
	if err != nil {
		t.Fatal(err)
	}
	packAsk(t, o, "sess-1", "t1", a, b)
	ts := startServer(t, o)
	v, raw := getAllow(t, ts)
	if len(v.Items) != 1 {
		t.Fatalf("needs = %s", raw)
	}
	id := v.Items[0].ID
	code, w, body := postNeed(t, ts, id, `{"nonce":"`+v.Nonce+`","action":"allow","for":"1h"}`)
	if code != 200 {
		t.Fatalf("allow = %d %s", code, body)
	}
	var got struct {
		TemporaryIDs []string `json:"temporary_ids"`
	}
	decode(t, body, &got)
	if len(got.TemporaryIDs) != 1 || got.TemporaryIDs[0] == long[0].ID {
		t.Errorf("temporary_ids = %v, want only b's", got.TemporaryIDs)
	}
	stillLong := func() bool {
		for _, tv := range temporaries(t, o) {
			if tv.ID == long[0].ID {
				until, _ := time.Parse(time.RFC3339, tv.Until)
				return time.Until(until) > 7*time.Hour
			}
		}
		return false
	}
	if !stillLong() {
		t.Errorf("the 8 h pause was replaced: %+v", temporaries(t, o))
	}
	if code, _, body = postNeed(t, ts, id, `{"nonce":"`+w.Nonce+`","action":"undo"}`); code != 200 {
		t.Fatalf("undo = %d %s", code, body)
	}
	if temps := temporaries(t, o); len(temps) != 1 || !stillLong() {
		t.Errorf("after undo: %+v", temps)
	}

	// Every rule already paused for at least that long: a 409, nothing written.
	appendRec(t, o.Paths.Activity, activity.Record{Kind: activity.KindDecision, SessionID: "sess-1", ToolUseID: "t2",
		ToolName: "Bash", Argv0: "sh", Decision: "ask", Enforcement: activity.EnforcementGate, Reason: "asked",
		Rules: []activity.RuleHit{hit(a, "ask")}, Cwd: o.Cwd})
	if _, err := rulebook.Pause(in, []string{"pack:" + a}, "session=sess-1"); err != nil {
		t.Fatal(err)
	}
	v, raw = getAllow(t, ts)
	var only string
	for _, it := range v.Items {
		if it.What == "Bash · sh" {
			only = it.ID
		}
	}
	if only == "" {
		t.Fatalf("needs = %s", raw)
	}
	before := temporaries(t, o)
	nonce := v.Nonce
	for _, f := range []string{"1h", "session"} {
		code, w, body = postNeed(t, ts, only, `{"nonce":"`+nonce+`","action":"allow","for":"`+f+`"}`)
		if code != 409 || !strings.Contains(w.Error, "already paused") {
			t.Errorf("allow %s with every rule paused = %d %s", f, code, body)
		}
		nonce = w.Nonce
	}
	if after := temporaries(t, o); len(after) != len(before) {
		t.Errorf("a refused allow changed the temporaries: %+v -> %+v", before, after)
	}
}

// ---------------------------------------------------------------- project-scoped fixes (the decision sheet's "only in this project")

// projectNeedsOptions is fixtureOptions in auto mode (no Cwd of its own),
// with the fixture's <home>/proj (a git root) as the one known project. A
// record appended with Cwd root makes an item whose Project is "~/proj".
func projectNeedsOptions(t *testing.T) (Options, string) {
	t.Helper()
	o := fixtureOptions(t)
	root := o.Cwd
	o.Cwd = ""
	o.ProjectRoots = func() []string { return []string{root} }
	return o, root
}

func postNeedAt(t *testing.T, ts *testServer, id, query, body string) (int, needsWriteView, []byte) {
	t.Helper()
	resp, b := ts.do(t, req{Method: "POST", Path: "/api/needs/" + id + query, Body: body, Origin: "auto", Token: ts.s.Token(), Header: jsonCT()})
	var v needsWriteView
	decode(t, b, &v)
	return resp.StatusCode, v, b
}

// TestNeedsAddRuleProjectScope: add_rule with scope project and ?project=
// naming the item's own project writes the rule into that project's
// settings file, not the user's; the resolution carries the project root,
// so an undo with no ?project= (auto mode, or the CLI from another
// directory) still finds and removes the row and reopens the item.
func TestNeedsAddRuleProjectScope(t *testing.T) {
	o, root := projectNeedsOptions(t)
	appendRec(t, o.Paths.Activity, activity.Record{Kind: activity.KindDenied, SessionID: "s1", ToolUseID: "t1",
		ToolName: "Bash", Argv0: "curl", Reason: "auto mode classifier: sends data out", Cwd: root})
	ts := startServer(t, o)
	v, raw := getNeeds(t, ts)
	if len(v.Items) != 1 || v.Items[0].Project != "~/proj" || len(v.Items[0].Fix) == 0 {
		t.Fatalf("needs = %s", raw)
	}
	id := v.Items[0].ID
	proj := filepath.Join(root, ".claude", "settings.json")
	userBefore := readFile(t, userSettingsPath(o))
	code, w, b := postNeedAt(t, ts, id, "?project="+root, `{"nonce":"`+v.Nonce+`","action":"add_rule","scope":"project"}`)
	if code != 200 || w.ID != id || len(w.RowIDs) != 1 || len(w.Written) != 1 || w.Written[0] != proj || w.Nonce == "" {
		t.Fatalf("add_rule at project scope = %d %s", code, b)
	}
	if want := "native:" + string(claudesettings.ScopeProject) + ":"; !strings.HasPrefix(w.RowIDs[0], want) {
		t.Errorf("row_ids = %v, want a %s… row", w.RowIDs, want)
	}
	if !strings.Contains(readFile(t, proj), "Bash(curl *)") {
		t.Errorf("the project settings file lacks the rule: %s", readFile(t, proj))
	}
	if readFile(t, userSettingsPath(o)) != userBefore {
		t.Error("the user settings file changed")
	}
	inbox := readFile(t, filepath.Join(o.Paths.StateDir, rulebook.InboxFile))
	if !strings.Contains(inbox, `"action":"add_rule"`) || !strings.Contains(inbox, `"project":"`+root+`"`) {
		t.Errorf("resolution line lacks the project root: %s", inbox)
	}
	if v, raw := getNeeds(t, ts); len(v.Items) != 0 {
		t.Errorf("item still open after add_rule: %s", raw)
	}
	added := w.RowIDs[0]
	code, w, b = postNeed(t, ts, id, `{"nonce":"`+w.Nonce+`","action":"undo"}`)
	if code != 200 || w.Action != "undo" || len(w.RowIDs) != 1 || w.RowIDs[0] != added || len(w.Written) != 1 || w.Written[0] != proj {
		t.Fatalf("undo without ?project= = %d %s", code, b)
	}
	if strings.Contains(readFile(t, proj), "curl") {
		t.Errorf("undo left the rule in the project settings file: %s", readFile(t, proj))
	}
	if v, raw := getNeeds(t, ts); len(v.Items) != 1 || v.Items[0].ID != id {
		t.Errorf("item did not reopen: %s", raw)
	}
	// scope user and no scope still write the user file.
	v, _ = getNeeds(t, ts)
	code, w, b = postNeed(t, ts, id, `{"nonce":"`+v.Nonce+`","action":"add_rule","scope":"user"}`)
	if code != 200 || len(w.Written) != 1 || w.Written[0] != userSettingsPath(o) || !strings.HasPrefix(w.RowIDs[0], "native:user:") {
		t.Fatalf("add_rule at user scope = %d %s", code, b)
	}
	lines := strings.Split(strings.TrimSpace(readFile(t, filepath.Join(o.Paths.StateDir, rulebook.InboxFile))), "\n")
	if last := lines[len(lines)-1]; strings.Contains(last, `"project"`) {
		t.Errorf("the user-scope resolution carries a project: %s", last)
	}
}

// TestNeedsAddRuleProjectScopeOtherProjectRefused: a bad scope word, a
// scope on an action other than add_rule, and scope project with no
// project root are refused before the nonce is spent; ?project= naming a
// known project that is not the item's is refused after it, with a fresh
// nonce, no path in the text, and nothing written anywhere.
func TestNeedsAddRuleProjectScopeOtherProjectRefused(t *testing.T) {
	o, root := projectNeedsOptions(t)
	other := filepath.Join(o.Paths.Home, "other")
	if err := os.MkdirAll(filepath.Join(other, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	o.ProjectRoots = func() []string { return []string{root, other} }
	appendRec(t, o.Paths.Activity, activity.Record{Kind: activity.KindDenied, SessionID: "s1", ToolUseID: "t1",
		ToolName: "Bash", Argv0: "curl", Reason: "auto mode classifier: sends data out", Cwd: root})
	ts := startServer(t, o)
	v, raw := getNeeds(t, ts)
	if len(v.Items) != 1 {
		t.Fatalf("needs = %s", raw)
	}
	id, n := v.Items[0].ID, v.Nonce
	for _, tc := range []struct{ query, body, want string }{
		{"", `{"action":"add_rule","scope":"zap"}`, "scope must be"},
		{"", `{"action":"acknowledge","scope":"project"}`, "scope"},
		{"", `{"action":"dismiss","scope":"user"}`, "scope"},
		{"", `{"action":"add_rule","scope":"project"}`, "project"},
		{"?project=/nowhere/at/all", `{"action":"add_rule","scope":"project"}`, "unknown project"},
	} {
		code, _, b := postNeedAt(t, ts, id, tc.query, `{"nonce":"`+n+`",`+tc.body[1:])
		if code != 400 || !strings.Contains(errorBody(t, b), tc.want) {
			t.Errorf("%s %s = %d %s, want 400 %q", tc.query, tc.body, code, b, tc.want)
		}
	}
	if !ts.s.spendNonce(n, purposeNeeds) {
		t.Fatal("a pre-spend refusal spent the nonce")
	}
	v, _ = getNeeds(t, ts)
	code, w, b := postNeedAt(t, ts, id, "?project="+other, `{"nonce":"`+v.Nonce+`","action":"add_rule","scope":"project"}`)
	if code != 400 || !strings.Contains(w.Error, "project the call happened in") || w.Nonce == "" {
		t.Fatalf("other project = %d %s", code, b)
	}
	if strings.Contains(string(b), o.Paths.Home) || strings.Contains(string(b), "/proj") || strings.Contains(string(b), "/other") || strings.Contains(string(b), "~") {
		t.Errorf("the refusal echoes a path: %s", b)
	}
	if ts.s.spendNonce(v.Nonce, purposeNeeds) {
		t.Error("the post-spend refusal left the old nonce usable")
	}
	for _, p := range []string{filepath.Join(root, ".claude", "settings.json"), filepath.Join(other, ".claude", "settings.json")} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s was written: %v", p, err)
		}
	}
	if v, raw := getNeeds(t, ts); len(v.Items) != 1 {
		t.Errorf("a refused add closed the item: %s", raw)
	}
}

// projectFilesView is a needs item's project and its fixes' project_files.
type projectFilesView struct {
	Items []struct {
		ID      string            `json:"id"`
		Kind    rulebook.ItemKind `json:"kind"`
		Project string            `json:"project"`
		Fixes   []struct {
			Request      rulebook.AddRequest `json:"request"`
			Files        []string            `json:"files"`
			ProjectFiles []string            `json:"project_files"`
		} `json:"fixes"`
	} `json:"items"`
}

// TestNeedsFixesCarryProjectFiles: each fix names the files its project
// scope form would write (display form), empty for a fix Propose refuses
// at project scope (a pack rule) and for an item with no project; never
// null, and the user-scope files are unchanged.
func TestNeedsFixesCarryProjectFiles(t *testing.T) {
	o := fixtureOptions(t)
	// Project files are offered only for a git root: the write resolves the
	// project to its git root and refuses a plain directory.
	if err := os.MkdirAll(filepath.Join(o.Cwd, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	pack, id := builtinPackRule(t)
	curlDenial(t, o, "t1")
	appendRec(t, o.Paths.Activity, activity.Record{Kind: activity.KindDecision, SessionID: "s1", ToolUseID: "t2",
		ToolName: "Bash", Argv0: "wget", Decision: "ask", Enforcement: activity.EnforcementGate, Reason: "a rule asked",
		Rules: []activity.RuleHit{{Pack: pack, ID: id, Action: "ask"}}, Cwd: o.Cwd})
	appendRec(t, o.Paths.Activity, activity.Record{Kind: activity.KindDenied, SessionID: "s2", ToolUseID: "t3",
		ToolName: "Bash", Argv0: "curl", Reason: "auto mode classifier: sends data out"})
	// A call from a plain directory (no .git above it, under home): no
	// project files, since the write would refuse that scope.
	plain := filepath.Join(o.Paths.Home, "plain")
	if err := os.MkdirAll(plain, 0o700); err != nil {
		t.Fatal(err)
	}
	appendRec(t, o.Paths.Activity, activity.Record{Kind: activity.KindDenied, SessionID: "s3", ToolUseID: "t4",
		ToolName: "Bash", Argv0: "wget", Reason: "auto mode classifier: sends data out", Cwd: plain})
	// A git root ?project= would not accept (not the server's cwd and not a
	// known root): no project files either, since the write would refuse it.
	stranger := filepath.Join(o.Paths.Home, "stranger")
	if err := os.MkdirAll(filepath.Join(stranger, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	appendRec(t, o.Paths.Activity, activity.Record{Kind: activity.KindDenied, SessionID: "s4", ToolUseID: "t5",
		ToolName: "Bash", Argv0: "nc", Reason: "auto mode classifier: sends data out", Cwd: stranger})
	o.ProjectRoots = func() []string { return nil }
	ts := startServer(t, o)
	resp, b := ts.do(t, req{Path: "/api/needs", Token: ts.s.Token()})
	if resp.StatusCode != 200 {
		t.Fatalf("GET /api/needs = %d %s", resp.StatusCode, b)
	}
	if strings.Contains(string(b), o.Paths.Home) {
		t.Errorf("needs JSON carries the home dir: %s", b)
	}
	var v projectFilesView
	decode(t, b, &v)
	if len(v.Items) != 5 {
		t.Fatalf("needs = %s", b)
	}
	seen := 0
	for _, it := range v.Items {
		for _, f := range it.Fixes {
			if f.ProjectFiles == nil {
				t.Errorf("%s %s: project_files is null", it.Kind, f.Request.What)
			}
			if len(f.Files) != 1 {
				t.Errorf("%s %s: files = %v", it.Kind, f.Request.What, f.Files)
			}
			var want []string
			if it.Project == "~/proj" && f.Request.What == rulebook.WhatCommand {
				want = []string{"~/proj/.claude/settings.json"}
			}
			if strings.Join(f.ProjectFiles, ",") != strings.Join(want, ",") {
				t.Errorf("%s project %q %s: project_files = %v, want %v", it.Kind, it.Project, f.Request.What, f.ProjectFiles, want)
			}
			seen++
		}
	}
	if seen < 5 {
		t.Errorf("only %d fixes seen: %s", seen, b)
	}
	plainSeen, strangerSeen := false, false
	for _, it := range v.Items {
		if it.Project == "~/plain" {
			plainSeen = true
		}
		if it.Project == "~/stranger" {
			strangerSeen = true
		}
	}
	if !plainSeen || !strangerSeen {
		t.Errorf("items from the plain and the stranger directories missing: %s", b)
	}
}

// TestNeedsProjectScopeNotForHome: a home directory that is itself a git
// root is no project: its "project" settings file is the user file. The GET
// offers no project files for a call that ran there, and a project-scope
// add naming it is refused before the nonce is spent.
func TestNeedsProjectScopeNotForHome(t *testing.T) {
	o := fixtureOptions(t)
	home := o.Paths.Home
	if err := os.MkdirAll(filepath.Join(home, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	o.Cwd = ""
	o.ProjectRoots = func() []string { return []string{home} }
	appendRec(t, o.Paths.Activity, activity.Record{Kind: activity.KindDenied, SessionID: "s1", ToolUseID: "t1",
		ToolName: "Bash", Argv0: "curl", Reason: "auto mode classifier: sends data out", Cwd: home})
	ts := startServer(t, o)
	resp, b := ts.do(t, req{Path: "/api/needs", Token: ts.s.Token()})
	if resp.StatusCode != 200 {
		t.Fatalf("GET /api/needs = %d %s", resp.StatusCode, b)
	}
	var v projectFilesView
	decode(t, b, &v)
	if len(v.Items) != 1 || v.Items[0].Project != "~" || len(v.Items[0].Fixes) == 0 {
		t.Fatalf("needs = %s", b)
	}
	for _, f := range v.Items[0].Fixes {
		if len(f.ProjectFiles) != 0 {
			t.Errorf("a call in the home directory got project files %v", f.ProjectFiles)
		}
	}
	var nv needsView
	decode(t, b, &nv)
	id := nv.Items[0].ID
	userBefore := readFile(t, userSettingsPath(o))
	code, _, b := postNeedAt(t, ts, id, "?project="+home, `{"nonce":"`+nv.Nonce+`","action":"add_rule","scope":"project"}`)
	if code != 400 || !strings.Contains(string(b), "home directory") || strings.Contains(string(b), home) {
		t.Fatalf("project scope on the home directory = %d %s", code, b)
	}
	if readFile(t, userSettingsPath(o)) != userBefore {
		t.Error("the user settings file changed")
	}
	if !ts.s.spendNonce(nv.Nonce, purposeNeeds) {
		t.Error("the refusal spent the nonce")
	}
}

// TestNeedsEverywhereFixProjectScopeKeepsUserTwin: an intent id carries no
// scope, so a project-scope add of an everywhere fix records its rows, not
// the intent; its undo removes those rows alone and the same value added
// everywhere at user scope stays.
func TestNeedsEverywhereFixProjectScopeKeepsUserTwin(t *testing.T) {
	o, root := projectNeedsOptions(t)
	appendRec(t, o.Paths.Activity, activity.Record{Kind: activity.KindDecision, SessionID: "s1", ToolUseID: "t1",
		ToolName: "Read", Decision: "ask", Enforcement: activity.EnforcementGate, Target: "~/.pgpass", Reason: "a rule asked", Cwd: root})
	ts := startServer(t, o)
	v, raw := getAllow(t, ts)
	if len(v.Items) != 1 || len(v.Items[0].Fixes) != 2 || !v.Items[0].Fixes[1].Request.Everywhere {
		t.Fatalf("needs = %s", raw)
	}
	id := v.Items[0].ID
	projSettings := paths.ProjectSettings(root)
	projPolicy := filepath.Join(root, manifest.ProjectOverridesFile)
	code, w, b := postNeedAt(t, ts, id, "?project="+root, `{"nonce":"`+v.Nonce+`","action":"add_rule","fix":1,"scope":"project"}`)
	if code != 200 || len(w.RowIDs) < 3 {
		t.Fatalf("everywhere add at project scope = %d %s", code, b)
	}
	if !strings.Contains(readFile(t, projSettings), "Read(~/.pgpass)") || !strings.Contains(readFile(t, projPolicy), "intent-path-") {
		t.Fatalf("project files lack the intent: %s / %s", readFile(t, projSettings), readFile(t, projPolicy))
	}
	inbox := readFile(t, filepath.Join(o.Paths.StateDir, rulebook.InboxFile))
	if strings.Contains(inbox, `"intent_id"`) || !strings.Contains(inbox, `"project":"`+root+`"`) {
		t.Errorf("the project-scope resolution should carry rows and the project, not the intent: %s", inbox)
	}
	// The same value, everywhere, at user scope: the twin that shares the intent id.
	code, _, b = postJSON(t, ts, "/api/rules", `{"nonce":"`+getRules(t, ts, "").Nonce+`","add":{"action":"deny","what":"path","value":"~/.pgpass","everywhere":true}}`)
	if code != 200 {
		t.Fatalf("user-scope twin add = %d %s", code, b)
	}
	if !strings.Contains(readFile(t, userSettingsPath(o)), "Read(~/.pgpass)") || !strings.Contains(readFile(t, o.Paths.OverridesFile()), "intent-path-") {
		t.Fatalf("user files lack the twin: %s", readFile(t, userSettingsPath(o)))
	}
	code, w, b = postNeed(t, ts, id, `{"nonce":"`+w.Nonce+`","action":"undo"}`)
	if code != 200 || len(w.RowIDs) < 3 {
		t.Fatalf("undo = %d %s", code, b)
	}
	if strings.Contains(readFile(t, projSettings), "pgpass") || strings.Contains(readFile(t, projPolicy), "intent-path-") {
		t.Errorf("undo left the project rows: %s / %s", readFile(t, projSettings), readFile(t, projPolicy))
	}
	if !strings.Contains(readFile(t, userSettingsPath(o)), "Read(~/.pgpass)") || !strings.Contains(readFile(t, o.Paths.OverridesFile()), "intent-path-") {
		t.Errorf("undo of the project add removed the user-scope twin: %s / %s", readFile(t, userSettingsPath(o)), readFile(t, o.Paths.OverridesFile()))
	}
}
