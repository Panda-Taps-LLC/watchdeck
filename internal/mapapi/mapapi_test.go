package mapapi

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/mapmodel"
)

type sessionRow struct {
	ID           string   `json:"id"`
	Cwd          string   `json:"cwd"`
	Live         bool     `json:"live"`
	Started      string   `json:"started"`
	LastActivity string   `json:"last_activity"`
	Decisions    int      `json:"decisions"`
	Denials      int      `json:"denials"`
	Skills       []string `json:"skills"`
	Source       string   `json:"source"`
	Subagents    int      `json:"subagents"`
}

func (e *env) sessions(t *testing.T) []sessionRow {
	t.Helper()
	resp, b := e.get(t, "/api/sessions", nil)
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "application/json; charset=utf-8" {
		t.Fatalf("GET /api/sessions = %d %q %s", resp.StatusCode, resp.Header.Get("Content-Type"), b)
	}
	var rows []sessionRow
	if err := json.Unmarshal(b, &rows); err != nil {
		t.Fatalf("%v: %s", err, b)
	}
	return rows
}

func findRow(rows []sessionRow, id string) *sessionRow {
	for i := range rows {
		if rows[i].ID == id {
			return &rows[i]
		}
	}
	return nil
}

func TestSessionsOpensNoTranscript(t *testing.T) {
	e := newEnv(t)
	// Unreadable after copying: Stat still works (the dir is readable), any
	// open would fail. The load counter is the second witness.
	for _, p := range []string{e.transcriptA(), e.subagentA()} {
		if err := os.Chmod(p, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(p, 0o644) })
	}
	rows := e.sessions(t)
	if len(rows) != 1 {
		t.Fatalf("sessions = %+v", rows)
	}
	r := rows[0]
	if r.ID != sidA || r.Cwd != cwdA || r.Source != "both" || r.Decisions != 2 || r.Denials != 1 ||
		strings.Join(r.Skills, ",") != "canary-basic,canary-request" || r.Subagents != 1 || r.Live || r.Started == "" || r.LastActivity == "" {
		t.Fatalf("row = %+v", r)
	}
	if n := e.loads.Load(); n != 0 {
		t.Fatalf("transcript.Load called %d times", n)
	}
}

func TestMap200Then304(t *testing.T) {
	e := newEnv(t)
	g, tag := e.mapOK(t, sidA, "topology", false)
	for _, id := range []string{"you", "agent:main", "agent:" + agentA, "tool:Bash", "skill:canary-request", "skill:canary-basic", "sandbox"} {
		if !g.has(id) {
			t.Errorf("no node %s", id)
		}
	}
	cut := false
	for _, ed := range g.Edges {
		if len(ed.Cut) > 0 && string(ed.Cut) != "null" {
			cut = true
		}
	}
	if !cut {
		t.Error("no cut edge")
	}
	if f := g.fix(t, "canary-request"); f != "watchdeck allow canary-request --network all" {
		t.Errorf("fix = %q", f)
	}
	if g.Session.Cwd != cwdA || g.Session.TranscriptMissing || g.Session.NoTranscripts {
		t.Errorf("session = %+v", g.Session)
	}
	loads := e.loads.Load()

	resp, b := e.get(t, mapPath(sidA, "topology", false), map[string]string{"If-None-Match": tag})
	if resp.StatusCode != http.StatusNotModified || len(b) != 0 || resp.Header.Get("ETag") != tag {
		t.Fatalf("conditional GET = %d %q %q", resp.StatusCode, resp.Header.Get("ETag"), b)
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q", resp.Header.Get("Cache-Control"))
	}
	if e.loads.Load() != loads {
		t.Error("the 304 path loaded the transcript")
	}
	// Weak and listed forms match too; another view is another tag.
	resp, _ = e.get(t, mapPath(sidA, "topology", false), map[string]string{"If-None-Match": `"x", W/` + tag})
	if resp.StatusCode != http.StatusNotModified {
		t.Errorf("weak list = %d", resp.StatusCode)
	}
	resp, _ = e.get(t, mapPath(sidA, "timeline", false), map[string]string{"If-None-Match": tag})
	if resp.StatusCode != 200 {
		t.Errorf("timeline with the topology tag = %d", resp.StatusCode)
	}
	resp, _ = e.get(t, mapPath(sidA, "topology", true), map[string]string{"If-None-Match": tag})
	if resp.StatusCode != 200 {
		t.Errorf("hide_none=1 with the hide_none=0 tag = %d", resp.StatusCode)
	}
}

// changed asserts the old tag now gets a 200 with a different tag.
func (e *env) changed(t *testing.T, id, old string) graph {
	t.Helper()
	resp, b := e.get(t, mapPath(id, "topology", false), map[string]string{"If-None-Match": old})
	if resp.StatusCode != 200 {
		t.Fatalf("after the change: %d (want 200)", resp.StatusCode)
	}
	if nt := resp.Header.Get("ETag"); nt == old || nt == "" {
		t.Fatalf("ETag unchanged: %q", nt)
	}
	return decodeGraph(t, b)
}

func TestETagChangesOnActivityAppend(t *testing.T) {
	e := newEnv(t)
	_, tag := e.mapOK(t, sidA, "topology", false)
	appendFile(t, e.paths.Activity, `{"v":1,"kind":"run","ts":"2026-10-13T02:19:00Z","cwd":"/Users/you/proj","skills":["canary-basic"],"command":"python3 x.py","exit":0,"outcome":"ok"}`)
	e.changed(t, sidA, tag)
}

func TestETagChangesOnSubagentGrowth(t *testing.T) {
	e := newEnv(t)
	_, tag := e.mapOK(t, sidA, "topology", false)
	dir := filepath.Dir(e.subagentA())
	before, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	appendFile(t, e.subagentA(), `{"type":"future-kind"}`)
	after, _ := os.Stat(dir)
	if !after.ModTime().Equal(before.ModTime()) {
		t.Log("note: the subagents dir mtime changed too")
	}
	e.changed(t, sidA, tag)
}

func TestETagChangesOnOverridesEdit(t *testing.T) {
	e := newEnv(t)
	g, tag := e.mapOK(t, sidA, "topology", false)
	if g.fix(t, "canary-request") == "" {
		t.Fatal("no fix before the grant")
	}
	resp, b := e.do(t, http.MethodPost, "/api/skills/canary-request/grant", "", `{"network":"all"}`,
		map[string]string{"Content-Type": "application/json", "Origin": e.base})
	if resp.StatusCode != 200 {
		t.Fatalf("grant = %d %s", resp.StatusCode, b)
	}
	g = e.changed(t, sidA, tag)
	if f := g.fix(t, "canary-request"); f != "" {
		t.Fatalf("fix after the grant = %q", f)
	}
}

func TestBadSessionID(t *testing.T) {
	e := newEnv(t)
	for _, p := range []string{
		"/api/sessions/a%20b/map",
		"/api/sessions/..%2Fx/map",
		"/api/sessions/" + strings.Repeat("a", 97) + "/map",
		"/api/sessions/direct:xyz/map",
		"/api/sessions/direct:ABCDEF012345/map",
		"/api/sessions/direct:0123456789abc/map",
		"/api/sessions/" + sidA + "/map?view=graph",
		"/api/sessions/" + sidA + "/map?hide_none=2",
	} {
		if resp, b := e.get(t, p, nil); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s = %d %s", p, resp.StatusCode, b)
		}
	}
	if e.loads.Load() != 0 {
		t.Error("a bad request loaded a transcript")
	}
}

func TestUnknownSession(t *testing.T) {
	e := newEnv(t)
	for _, id := range []string{"00000000-0000-4000-8000-000000000000", "direct:000000000000"} {
		resp, b := e.get(t, mapPath(id, "topology", false), nil)
		if resp.StatusCode != http.StatusNotFound || !strings.Contains(string(b), `"error"`) {
			t.Errorf("%s = %d %s", id, resp.StatusCode, b)
		}
	}
}

func TestNoTranscripts(t *testing.T) {
	e := newEnv(t, noTranscripts)
	rows := e.sessions(t)
	if len(rows) != 1 || rows[0].Source != "activity" {
		t.Fatalf("sessions = %+v", rows)
	}
	for _, view := range []string{"topology", "timeline"} {
		g, _ := e.mapOK(t, sidA, view, false)
		if !g.Session.NoTranscripts || g.Session.TranscriptMissing || g.has("you") {
			t.Errorf("%s: session %+v, you=%v", view, g.Session, g.has("you"))
		}
	}
	if !func() bool { g, _ := e.mapOK(t, sidA, "topology", false); return g.has("skill:canary-request") }() {
		t.Error("activity-only graph lost the skill")
	}
	if n := e.loads.Load(); n != 0 {
		t.Fatalf("transcript.Load called %d times under NoTranscripts", n)
	}
}

func TestTranscriptOutsideProjectsRefused(t *testing.T) {
	e := newEnv(t)
	// Two sessions whose records name a transcript outside the projects dir:
	// directly, and through a symlink inside it. Both files are valid copies
	// of fixture A's transcript, so loading either would draw a "you" node.
	const (
		sidOut  = "c0ffee00-0000-4000-8000-000000000001"
		sidLink = "c0ffee00-0000-4000-8000-000000000002"
	)
	outside := filepath.Join(e.root, "outside", projA)
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	src, err := os.ReadFile(e.transcriptA())
	if err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join(outside, sidOut+".jsonl")
	linkTarget := filepath.Join(outside, sidLink+".jsonl")
	for _, p := range []string{outPath, linkTarget} {
		if err := os.WriteFile(p, src, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	linkPath := filepath.Join(e.paths.ClaudeProjectsDir(), projA, sidLink+".jsonl")
	if err := os.Symlink(linkTarget, linkPath); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ sid, path string }{{sidOut, outPath}, {sidLink, linkPath}} {
		appendFile(t, e.paths.Activity, `{"v":1,"kind":"decision","ts":"2026-10-13T03:00:00Z","session_id":"`+c.sid+
			`","tool_use_id":"toolu_x","transcript_path":"`+c.path+`","cwd":"/Users/you/proj","skills":["canary-basic"],"command":"python3 x.py","decision":"allow","rewritten":"watchdeck run --skill canary-basic -c 'python3 x.py'","confidence":"high"}`)
	}

	rows := e.sessions(t)
	for _, sid := range []string{sidOut, sidLink} {
		r := findRow(rows, sid)
		if r == nil || r.Source != "activity" {
			t.Errorf("%s row = %+v", sid, r)
		}
		g, _ := e.mapOK(t, sid, "topology", false)
		if !g.Session.TranscriptMissing || g.has("you") {
			t.Errorf("%s: session %+v, you=%v", sid, g.Session, g.has("you"))
		}
		if p := g.Session.TranscriptPath; !strings.HasSuffix(p, "/"+projA+"/"+sid+".jsonl") || strings.HasPrefix(p, "/") {
			t.Errorf("%s: transcript_path display = %q", sid, p)
		}
	}
	if n := e.loads.Load(); n != 0 {
		t.Fatalf("transcript.Load called %d times", n)
	}
}

func TestDirectPseudoSession(t *testing.T) {
	e := newEnv(t)
	const other = "/Users/you/other"
	// Newer than the transcript's mtime (the copy was made just now), so the
	// pseudo-session sorts first.
	ts := time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano)
	appendFile(t, e.paths.Activity, `{"v":1,"kind":"run","ts":"`+ts+`","cwd":"`+other+`","skills":["canary-basic"],"command":"python3 .claude/skills/canary-basic/scripts/probe.py net","exit":0,"outcome":"ok","backend":"seatbelt"}`)
	id := directID(other)
	if !validSessionID(id) {
		t.Fatalf("directID %q fails validSessionID", id)
	}
	rows := e.sessions(t)
	r := findRow(rows, id)
	if r == nil || r.Source != "activity" || r.Cwd != other || strings.Join(r.Skills, ",") != "canary-basic" {
		t.Fatalf("direct row = %+v (rows %+v)", r, rows)
	}
	if rows[0].ID != id {
		t.Errorf("newest first: rows[0] = %s", rows[0].ID)
	}
	g, tag := e.mapOK(t, id, "topology", false)
	if !g.has("skill:canary-basic") || !g.has("sandbox") || g.has("you") || g.has("tool:Bash") || g.Session.Cwd != other {
		t.Errorf("direct graph: %+v", g)
	}
	if resp, _ := e.get(t, mapPath(id, "topology", false), map[string]string{"If-None-Match": tag}); resp.StatusCode != http.StatusNotModified {
		t.Errorf("direct conditional GET = %d", resp.StatusCode)
	}
	if n := e.loads.Load(); n != 0 {
		t.Errorf("a direct session loaded %d transcripts", n)
	}
}

// TestNoAbsolutePathsInJSON walks every string of every response. The only
// absolute paths allowed are the session cwd display values (as recorded):
// cwdA and the direct session's cwd.
func TestNoAbsolutePathsInJSON(t *testing.T) {
	t.Run("cwd", func(t *testing.T) { noAbsolutePaths(t, newEnv(t), "") })
	// M5.3: a server with no cwd (auto/service mode), plain and with a
	// known ?project=.
	cwdless := func(d *Deps) {
		d.Cwd = ""
		d.ProjectRoots = func() []string { return []string{cwdA, "/Users/you/other"} }
	}
	t.Run("cwd-less", func(t *testing.T) { noAbsolutePaths(t, newEnv(t, cwdless), "") })
	t.Run("cwd-less ?project", func(t *testing.T) { noAbsolutePaths(t, newEnv(t, cwdless), "project="+cwdA) })
}

func noAbsolutePaths(t *testing.T, e *env, query string) {
	sep := func(p string) string {
		if query == "" {
			return p
		}
		if strings.Contains(p, "?") {
			return p + "&" + query
		}
		return p + "?" + query
	}
	const other = "/Users/you/other"
	appendFile(t, e.paths.Activity, `{"v":1,"kind":"run","ts":"2026-10-13T04:00:00Z","cwd":"`+other+`","skills":["canary-basic"],"command":"python3 x.py","exit":0,"outcome":"ok"}`)
	realRoot, err := filepath.EvalSymlinks(e.root)
	if err != nil {
		t.Fatal(err)
	}
	forbidden := []string{e.root, realRoot, e.home}
	allowed := map[string]bool{cwdA: true, other: true}

	var bodies [][]byte
	_, b := e.get(t, sep("/api/sessions"), nil)
	bodies = append(bodies, b)
	for _, id := range []string{sidA, directID(other)} {
		for _, view := range []string{"topology", "timeline"} {
			for _, hide := range []bool{false, true} {
				resp, b := e.get(t, sep(mapPath(id, view, hide)), nil)
				if resp.StatusCode != 200 {
					t.Fatalf("%s %s = %d", id, view, resp.StatusCode)
				}
				bodies = append(bodies, b)
			}
		}
	}
	n := 0
	for _, b := range bodies {
		var v any
		if err := json.Unmarshal(b, &v); err != nil {
			t.Fatal(err)
		}
		walkStrings(v, func(s string) {
			n++
			for _, f := range forbidden {
				if strings.Contains(s, f) {
					t.Errorf("response string contains a temp path: %q", s)
				}
			}
			if strings.HasPrefix(s, "/Users/") && !allowed[s] {
				t.Errorf("absolute path in a response: %q", s)
			}
		})
	}
	if n < 50 {
		t.Fatalf("only %d strings walked", n)
	}
}

func walkStrings(v any, f func(string)) {
	switch x := v.(type) {
	case string:
		f(x)
	case []any:
		for _, y := range x {
			walkStrings(y, f)
		}
	case map[string]any:
		for k, y := range x {
			f(k)
			walkStrings(y, f)
		}
	}
}

func TestRoutesAreGuarded(t *testing.T) {
	e := newEnv(t)
	for _, p := range []string{"/api/sessions", mapPath(sidA, "topology", false)} {
		for _, tok := range []string{"-", "wrong-token"} {
			resp, _ := e.do(t, http.MethodGet, p, tok, "", nil)
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("%s with token %q = %d", p, tok, resp.StatusCode)
			}
		}
		resp, _ := e.do(t, http.MethodPost, p, "", "{}", map[string]string{"Content-Type": "application/json", "Origin": e.base})
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("POST %s = %d", p, resp.StatusCode)
		}
	}
	if e.loads.Load() != 0 {
		t.Error("an unauthenticated request loaded a transcript")
	}
}

func TestNotModified(t *testing.T) {
	for _, c := range []struct {
		h    string
		want bool
	}{
		{`"0123456789abcdef"`, true},
		{`W/"0123456789abcdef"`, true},
		{`"x", "0123456789abcdef"`, true},
		{`*`, true},
		{``, false},
		{`"0123456789abcdee"`, false},
	} {
		if got := notModified(c.h, "0123456789abcdef"); got != c.want {
			t.Errorf("notModified(%q) = %v", c.h, got)
		}
	}
}

func TestRoutesKeys(t *testing.T) {
	r := Routes(Deps{})
	if len(r) != 2 || r[PatternSessions] == nil || r[PatternMap] == nil {
		t.Fatalf("Routes = %v", r)
	}
}

// TestMapAuthorityParam: ?authority=a,b filters the calls drawn (shown counts
// them, totals stay the session's), an unknown word is a 400 with the word
// list, the ETag differs between a filter and none (and the fast path never
// answers one with the other's tag), and hide_none=1 still works.
func TestMapAuthorityParam(t *testing.T) {
	e := newEnv(t)
	base := "/api/sessions/" + sidA + "/map?view=timeline"
	type body struct {
		Nodes []struct {
			ID        string `json:"id"`
			Authority string `json:"authority"`
		} `json:"nodes"`
		Ticks []struct {
			Authority string `json:"authority"`
		} `json:"ticks"`
		Totals struct {
			ByAuthority map[string]int `json:"by_authority"`
		} `json:"totals"`
		Shown *int `json:"shown"`
	}
	fetch := func(path string, hdr map[string]string) (*http.Response, body) {
		t.Helper()
		resp, b := e.get(t, path, hdr)
		var out body
		if resp.StatusCode == http.StatusOK {
			if err := json.Unmarshal(b, &out); err != nil {
				t.Fatalf("%s: %v", path, err)
			}
		}
		return resp, out
	}

	resp, all := fetch(base, nil)
	if resp.StatusCode != http.StatusOK || all.Shown == nil || *all.Shown != 6 {
		t.Fatalf("no filter = %d shown %v", resp.StatusCode, all.Shown)
	}
	allTag := resp.Header.Get("ETag")

	resp, sb := fetch(base+"&authority=sandbox", nil)
	if resp.StatusCode != http.StatusOK || sb.Shown == nil || *sb.Shown != 3 {
		t.Fatalf("authority=sandbox = %d shown %v, want 3", resp.StatusCode, sb.Shown)
	}
	if len(sb.Ticks) != 6 || sb.Totals.ByAuthority[mapmodel.AuthoritySandbox] != 2 || sb.Totals.ByAuthority[mapmodel.AuthorityAllowRule] != 2 {
		t.Errorf("authority=sandbox changed ticks or totals: %d %v", len(sb.Ticks), sb.Totals.ByAuthority)
	}
	for _, n := range sb.Nodes {
		// Spawns are structure: they stay whatever decided them.
		if n.Authority != "" && n.Authority != mapmodel.AuthoritySandbox && !strings.HasPrefix(n.ID, "ev:spawn:") {
			t.Errorf("authority=sandbox kept %s (%s)", n.ID, n.Authority)
		}
	}
	sbTag := resp.Header.Get("ETag")

	resp, hk := fetch(base+"&authority=hook", nil)
	if resp.StatusCode != http.StatusOK || hk.Shown == nil || *hk.Shown != 1 {
		t.Fatalf("authority=hook = %d shown %v, want 1 (the spawn)", resp.StatusCode, hk.Shown)
	}
	hookTag := resp.Header.Get("ETag")
	if hookTag == "" || hookTag == allTag || hookTag == sbTag || sbTag == allTag {
		t.Errorf("tags: all %s sandbox %s hook %s", allTag, sbTag, hookTag)
	}
	// The fast path keys on the filter: no filter with the hook tag is a 200,
	// and the hook filter with its own tag is a 304.
	if resp, _ := fetch(base, map[string]string{"If-None-Match": hookTag}); resp.StatusCode != http.StatusOK {
		t.Errorf("no filter with the hook tag = %d", resp.StatusCode)
	}
	if resp, _ := fetch(base+"&authority=hook", map[string]string{"If-None-Match": hookTag}); resp.StatusCode != http.StatusNotModified {
		t.Errorf("hook filter with its own tag = %d", resp.StatusCode)
	}
	// Order, repeats and spaces do not make another filter.
	resp, _ = fetch(base+"&authority=sandbox,allow_rule", nil)
	t1 := resp.Header.Get("ETag")
	resp, two := fetch(base+"&authority=allow_rule,%20sandbox,sandbox", nil)
	if resp.StatusCode != http.StatusOK || resp.Header.Get("ETag") != t1 || two.Shown == nil || *two.Shown != 5 {
		t.Errorf("allow_rule,sandbox = %d tag %s vs %s shown %v, want 5", resp.StatusCode, resp.Header.Get("ETag"), t1, two.Shown)
	}
	// An empty value is no filter.
	if resp, _ := fetch(base+"&authority=", nil); resp.StatusCode != http.StatusOK || resp.Header.Get("ETag") != allTag {
		t.Errorf("authority= : %d tag %s, want the unfiltered %s", resp.StatusCode, resp.Header.Get("ETag"), allTag)
	}

	const msg = "authority must be a comma list of deny_rule, classifier, auto, allow_rule, user, hook, sandbox, blocked, none"
	for _, bad := range []string{"bogus", "hook,bogus", "Hook", "hook,", ",", "deny"} {
		resp, b := e.get(t, base+"&authority="+bad, nil)
		if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(b), msg) {
			t.Errorf("authority=%s = %d %s", bad, resp.StatusCode, b)
		}
	}

	// hide_none still works, alone and with a filter, on every view.
	resp, hn := fetch(base+"&hide_none=1", nil)
	if resp.StatusCode != http.StatusOK || hn.Shown == nil || *hn.Shown != 3 {
		t.Errorf("hide_none=1 = %d shown %v, want 3", resp.StatusCode, hn.Shown)
	}
	if resp.Header.Get("ETag") == allTag {
		t.Error("hide_none=1 shares the unfiltered tag")
	}
	resp, both := fetch(base+"&hide_none=1&authority=allow_rule", nil)
	if resp.StatusCode != http.StatusOK || both.Shown == nil || *both.Shown != 1 {
		t.Errorf("hide_none=1&authority=allow_rule = %d shown %v, want 1 (the spawn)", resp.StatusCode, both.Shown)
	}
	for _, v := range []string{"topology", "ticks"} {
		resp, g := fetch("/api/sessions/"+sidA+"/map?view="+v+"&authority=sandbox", nil)
		if resp.StatusCode != http.StatusOK || g.Shown == nil || *g.Shown != 3 {
			t.Errorf("%s authority=sandbox = %d shown %v", v, resp.StatusCode, g.Shown)
		}
	}
}
