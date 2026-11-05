package ui

import (
	"os"
	"strings"
	"testing"

	"github.com/Panda-Taps-LLC/watchdeck/internal/activity"
)

// GET /api/rules/stats (Plan 08 Task 4, D11): per-rule counts folded from
// the activity log by offset, once per record per rule id.

type statView struct {
	Fired      int    `json:"fired"`
	LastTS     string `json:"last_ts"`
	LastAction string `json:"last_action"`
	Shadow     int    `json:"shadow"`
}

type statsView struct {
	ActivityEnabled bool `json:"activity_enabled"`
	Window          struct {
		Since   string `json:"since"`
		Until   string `json:"until"`
		Records int    `json:"records"`
		Rotated bool   `json:"rotated"`
	} `json:"window"`
	Pack   map[string]statView `json:"pack"`
	User   map[string]statView `json:"user"`
	Native map[string]statView `json:"native"`
}

func getStats(t *testing.T, ts *testServer, query string) statsView {
	t.Helper()
	resp, b := ts.do(t, req{Path: "/api/rules/stats" + query, Token: ts.s.Token()})
	if resp.StatusCode != 200 {
		t.Fatalf("GET /api/rules/stats%s = %d %s", query, resp.StatusCode, b)
	}
	var v statsView
	decode(t, b, &v)
	if v.Pack == nil || v.User == nil || v.Native == nil {
		t.Fatalf("a map is null: %s", b)
	}
	return v
}

func ruleHit(pack, id, action string) activity.RuleHit {
	return activity.RuleHit{Pack: pack, ID: id, Action: action}
}

// packRec is a decision record with one pack hit at ts.
func packRec(ts string) activity.Record {
	return activity.Record{Kind: activity.KindDecision, TS: ts, Decision: "ask", Rules: []activity.RuleHit{ruleHit("destructive", "mkfs", "ask")}}
}

func TestStatsFoldsPackUserAndNative(t *testing.T) {
	o := emptyOptions(t)
	log := o.Paths.Activity
	const (
		t0 = "2026-10-24T09:00:00Z"
		t1 = "2026-10-24T10:00:00Z"
		t2 = "2026-10-24T10:05:00Z"
		t3 = "2026-10-24T10:10:00Z"
		t4 = "2026-10-24T10:15:00Z"
	)
	rm := ruleHit("destructive", "rm-root-or-home", "deny")
	// a deny carrying the pack rule twice (once per record) and a user rule
	appendRec(t, log, activity.Record{Kind: activity.KindDecision, TS: t1, Decision: "deny", Rules: []activity.RuleHit{rm, rm, ruleHit("user", "no-prod-db", "deny")}})
	// the person's Claude Code rule, honoured before a rewrite
	appendRec(t, log, activity.Record{Kind: activity.KindDecision, TS: t2, Decision: "ask", Rules: []activity.RuleHit{ruleHit(activity.PackClaudeSettings, "Bash(curl *)", "ask")}})
	// a log-only hit
	appendRec(t, log, activity.Record{Kind: activity.KindRuleLog, TS: t3, Rules: []activity.RuleHit{ruleHit("user", "tf-plan", "log")}})
	// shadow mode observed the pack rule
	appendRec(t, log, activity.Record{Kind: activity.KindDecision, TS: t4, Decision: activity.DecisionShadow, Shadow: true, Would: "deny", Rules: []activity.RuleHit{rm}})
	// a run with no rules, and an older hit written later
	appendRec(t, log, activity.Record{Kind: activity.KindRun, TS: t2, Skills: []string{"pdf"}})
	appendRec(t, log, activity.Record{Kind: activity.KindDecision, TS: t0, Decision: "ask", Rules: []activity.RuleHit{ruleHit("destructive", "rm-root-or-home", "ask")}})

	ts := startServer(t, o)
	v := getStats(t, ts, "")
	if !v.ActivityEnabled || v.Window.Records != 6 || v.Window.Since != t0 || v.Window.Until != t4 || v.Window.Rotated {
		t.Fatalf("window: %+v enabled %v", v.Window, v.ActivityEnabled)
	}
	want := map[string]statView{"destructive/rm-root-or-home": {3, t4, "deny", 1}}
	if len(v.Pack) != 1 || v.Pack["destructive/rm-root-or-home"] != want["destructive/rm-root-or-home"] {
		t.Errorf("pack: %+v", v.Pack)
	}
	if len(v.User) != 2 || v.User["no-prod-db"] != (statView{1, t1, "deny", 0}) || v.User["tf-plan"] != (statView{1, t3, "log", 0}) {
		t.Errorf("user: %+v", v.User)
	}
	if len(v.Native) != 1 || v.Native["Bash(curl *)"] != (statView{1, t2, "ask", 0}) {
		t.Errorf("native: %+v", v.Native)
	}

	// The fold is incremental: a new line adds to what is held.
	appendRec(t, log, activity.Record{Kind: activity.KindRuleLog, TS: "2026-10-24T11:00:00Z", Rules: []activity.RuleHit{rm}})
	v = getStats(t, ts, "")
	if got := v.Pack["destructive/rm-root-or-home"]; got != (statView{4, "2026-10-24T11:00:00Z", "log", 1}) || v.Window.Records != 7 {
		t.Errorf("after append: %+v, records %d", got, v.Window.Records)
	}
	fi, _ := os.Stat(log)
	ts.s.stats.mu.Lock()
	next := ts.s.stats.next
	ts.s.stats.mu.Unlock()
	if next != fi.Size() {
		t.Errorf("fold offset %d, want the file's end %d", next, fi.Size())
	}

	// ?project= picks no rows here, but a project the server does not
	// know is refused like every other project-scoped route.
	resp, b := ts.do(t, req{Path: "/api/rules/stats?project=/nowhere", Token: ts.s.Token()})
	if resp.StatusCode != 400 {
		t.Errorf("unknown project: %d %s", resp.StatusCode, b)
	}
}

// TestStatsAcrossRotation: the hook renames the log to <log>.1 at 8 MiB
// and starts a new one (Review Focus 5). Every record in the two files
// counts once: when the new file is already longer than the old offset,
// when only <log>.1 exists, and on every poll after.
func TestStatsAcrossRotation(t *testing.T) {
	o := emptyOptions(t)
	log := o.Paths.Activity
	ts := startServer(t, o)
	const mkfsRule = "destructive/mkfs"
	fired := func(want, records int, rotated bool) {
		t.Helper()
		v := getStats(t, ts, "")
		if got := v.Pack[mkfsRule].Fired; got != want || v.Window.Records != records || v.Window.Rotated != rotated {
			t.Fatalf("fired %d records %d rotated %v, want %d %d %v", got, v.Window.Records, v.Window.Rotated, want, records, rotated)
		}
	}
	for i := 0; i < 3; i++ {
		appendRec(t, log, packRec("2026-10-24T10:00:0"+string(rune('0'+i))+"Z"))
	}
	fired(3, 3, false)

	// rotation, and the new file grows past the old offset before the
	// next poll: no shrink to see, the file is another one
	if err := os.Rename(log, log+".1"); err != nil {
		t.Fatal(err)
	}
	pad := strings.Repeat("x", 400)
	for i := 0; i < 5; i++ {
		r := packRec("2026-10-24T11:00:0" + string(rune('0'+i)) + "Z")
		r.Reason = pad
		appendRec(t, log, r)
	}
	if a, b := fileSize(t, log+".1"), fileSize(t, log); b <= a {
		t.Fatalf("the new file (%d) must be longer than the old offset (%d)", b, a)
	}
	fired(8, 8, true)
	fired(8, 8, true)
	appendRec(t, log, packRec("2026-10-24T12:00:00Z"))
	fired(9, 9, true)

	// a second rotation, polled while only <log>.1 exists: the oldest file
	// is gone, and its records with it
	if err := os.Rename(log, log+".1"); err != nil {
		t.Fatal(err)
	}
	fired(6, 6, true)
	fired(6, 6, true)
	appendRec(t, log, packRec("2026-10-24T13:00:00Z"))
	fired(7, 7, true)
	fired(7, 7, true)
}

// TestStatsResetRefolds: a log that shrank in place (truncated, the same
// file) drops what the fold held and counts what is there now.
func TestStatsResetRefolds(t *testing.T) {
	o := emptyOptions(t)
	log := o.Paths.Activity
	for i := 0; i < 4; i++ {
		appendRec(t, log, packRec("2026-10-24T10:00:0"+string(rune('0'+i))+"Z"))
	}
	ts := startServer(t, o)
	if v := getStats(t, ts, ""); v.Pack["destructive/mkfs"].Fired != 4 {
		t.Fatalf("before: %+v", v.Pack)
	}
	before, _ := os.Stat(log)
	if err := os.Truncate(log, 0); err != nil {
		t.Fatal(err)
	}
	appendRec(t, log, activity.Record{Kind: activity.KindDecision, TS: "2026-10-24T11:00:00Z", Decision: "deny", Rules: []activity.RuleHit{ruleHit("user", "no-prod-db", "deny")}})
	if after, _ := os.Stat(log); !os.SameFile(before, after) {
		t.Fatal("the truncated log is another file; the test proves nothing about Reset")
	}
	v := getStats(t, ts, "")
	if len(v.Pack) != 0 || v.User["no-prod-db"].Fired != 1 || v.Window.Records != 1 || v.Window.Since != "2026-10-24T11:00:00Z" {
		t.Fatalf("after reset: pack %+v user %+v window %+v", v.Pack, v.User, v.Window)
	}
}

// TestStatsResetRefoldsWithRotated: the same shrink with <log>.1 present.
// The Reset read returns both files again, and each record counts once.
func TestStatsResetRefoldsWithRotated(t *testing.T) {
	o := emptyOptions(t)
	log := o.Paths.Activity
	for i := 0; i < 3; i++ {
		appendRec(t, log, packRec("2026-10-24T09:00:0"+string(rune('0'+i))+"Z"))
	}
	if err := os.Rename(log, log+".1"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		appendRec(t, log, packRec("2026-10-24T10:00:0"+string(rune('0'+i))+"Z"))
	}
	ts := startServer(t, o)
	if v := getStats(t, ts, ""); v.Pack["destructive/mkfs"].Fired != 7 || v.Window.Records != 7 || !v.Window.Rotated {
		t.Fatalf("before: pack %+v window %+v", v.Pack, v.Window)
	}
	before, _ := os.Stat(log)
	if err := os.Truncate(log, 0); err != nil {
		t.Fatal(err)
	}
	appendRec(t, log, activity.Record{Kind: activity.KindDecision, TS: "2026-10-24T11:00:00Z", Decision: "deny", Rules: []activity.RuleHit{ruleHit("user", "no-prod-db", "deny")}})
	if after, _ := os.Stat(log); !os.SameFile(before, after) {
		t.Fatal("the truncated log is another file; the test proves nothing about Reset")
	}
	v := getStats(t, ts, "")
	if v.Pack["destructive/mkfs"].Fired != 3 || v.User["no-prod-db"].Fired != 1 || v.Window.Records != 4 || !v.Window.Rotated ||
		v.Window.Since != "2026-10-24T09:00:00Z" || v.Window.Until != "2026-10-24T11:00:00Z" {
		t.Fatalf("after reset: pack %+v user %+v window %+v", v.Pack, v.User, v.Window)
	}
	if v2 := getStats(t, ts, ""); v2.Pack["destructive/mkfs"].Fired != 3 || v2.Window.Records != 4 {
		t.Fatalf("second poll: pack %+v window %+v", v2.Pack, v2.Window)
	}
}

func TestStatsActivityOff(t *testing.T) {
	o := emptyOptions(t)
	appendRec(t, o.Paths.Activity, packRec("2026-10-24T10:00:00Z"))
	o.Paths.Activity = "" // WATCHDECK_ACTIVITY=off
	ts := startServer(t, o)
	resp, b := ts.do(t, req{Path: "/api/rules/stats", Token: ts.s.Token()})
	if resp.StatusCode != 200 {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	if got := strings.TrimSpace(string(b)); got != `{"activity_enabled":false,"window":{"since":"","until":"","records":0,"rotated":false},"pack":{},"user":{},"native":{}}` {
		t.Fatalf("body %s", got)
	}
}

func fileSize(t *testing.T, p string) int64 {
	t.Helper()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Size()
}
