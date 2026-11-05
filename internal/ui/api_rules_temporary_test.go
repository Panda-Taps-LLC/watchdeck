package ui

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/rulebook"
)

// Temporary allows on the rules routes (Plan 08).

func temporaryOverrides() string {
	now := time.Now().UTC().Truncate(time.Second)
	f := func(t time.Time) string { return t.Format(time.RFC3339) }
	return "version: 2\ntemporary:\n" +
		"  - {id: t-00000001, kind: rule, rule: pipe-to-shell/curl-pipe-shell, session: s1, until: \"" + f(now.Add(time.Hour)) + "\", added: \"" + f(now.Add(-time.Minute)) + "\"}\n" +
		"  - {id: t-00000002, kind: grant, skill: web, grant: {network: all}, until: \"" + f(now.Add(time.Hour)) + "\", added: \"" + f(now.Add(-time.Minute)) + "\"}\n" +
		"  - {id: t-00000003, kind: rule, rule: exfil/scp-secret, until: \"" + f(now.Add(-time.Minute)) + "\", added: \"" + f(now.Add(-time.Hour)) + "\"}\n"
}

func getTemporaries(t *testing.T, ts *testServer) []rulebook.TemporaryView {
	t.Helper()
	resp, b := ts.do(t, req{Path: "/api/rules", Token: ts.s.Token()})
	if resp.StatusCode != 200 {
		t.Fatalf("GET /api/rules = %d %s", resp.StatusCode, b)
	}
	var v struct {
		Temporaries []rulebook.TemporaryView `json:"temporaries"`
	}
	decode(t, b, &v)
	if v.Temporaries == nil {
		t.Fatalf("temporaries is null: %s", b)
	}
	return v.Temporaries
}

// TestRulesListsTemporaries: GET /api/rules lists the temporaries in
// force, never null; an expired one is not listed.
func TestRulesListsTemporaries(t *testing.T) {
	o := fixtureOptions(t)
	ts := startServer(t, o)
	if got := getTemporaries(t, ts); len(got) != 0 {
		t.Fatalf("no file: %+v", got)
	}
	writeOverrides(t, o, temporaryOverrides())
	got := getTemporaries(t, ts)
	if len(got) != 2 || got[0].ID != "t-00000001" || got[0].Kind != "rule" || got[0].Session != "s1" ||
		got[1].ID != "t-00000002" || got[1].Kind != "grant" || got[1].Sentence == "" || got[1].Until == "" {
		t.Fatalf("temporaries %+v", got)
	}
	if _, err := time.Parse(time.RFC3339, got[0].Until); err != nil {
		t.Fatalf("until %q: %v", got[0].Until, err)
	}
}

// TestRulesEndTemporaryNeedsNonce: end_temporary is a write: no nonce is a
// 400, a stale one a 403 that writes nothing, a good one removes the
// entry, and an id not in the file is a 400.
func TestRulesEndTemporaryNeedsNonce(t *testing.T) {
	o := fixtureOptions(t)
	ts := startServer(t, o)
	writeOverrides(t, o, temporaryOverrides())
	before := readFile(t, o.Paths.OverridesFile())

	code, _, b := postJSON(t, ts, "/api/rules", `{"end_temporary":"t-00000001"}`)
	if code != 400 || !strings.Contains(string(b), "nonce") {
		t.Fatalf("no nonce = %d %s", code, b)
	}
	code, v, b := postJSON(t, ts, "/api/rules", `{"nonce":"`+strings.Repeat("0", 32)+`","end_temporary":"t-00000001"}`)
	if code != 403 || v.Nonce == "" {
		t.Fatalf("stale nonce = %d %s", code, b)
	}
	if readFile(t, o.Paths.OverridesFile()) != before {
		t.Fatal("a stale nonce wrote")
	}
	// end_temporary with another field is refused before the nonce.
	n := getRules(t, ts, "").Nonce
	code, _, b = postJSON(t, ts, "/api/rules", `{"nonce":"`+n+`","end_temporary":"t-00000001","remove":"pack:a/b"}`)
	if code != 400 {
		t.Fatalf("two fields = %d %s", code, b)
	}
	code, v, b = postJSON(t, ts, "/api/rules", `{"nonce":"`+n+`","end_temporary":"t-00000001"}`)
	if code != 200 || v.Nonce == "" || len(v.RowIDs) != 1 || v.RowIDs[0] != "t-00000001" {
		t.Fatalf("end = %d %s", code, b)
	}
	got := getTemporaries(t, ts)
	if len(got) != 1 || got[0].ID != "t-00000002" {
		t.Fatalf("after end %+v", got)
	}
	code, v, b = postJSON(t, ts, "/api/rules", `{"nonce":"`+v.Nonce+`","end_temporary":"t-00000001"}`)
	if code != 400 || v.Nonce == "" || !strings.Contains(v.Error, "no temporary") {
		t.Fatalf("absent id = %d %s", code, b)
	}
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
}
