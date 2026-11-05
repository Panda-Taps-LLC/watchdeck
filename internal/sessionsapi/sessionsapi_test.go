package sessionsapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/Panda-Taps-LLC/watchdeck/internal/activity"
	"github.com/Panda-Taps-LLC/watchdeck/internal/lifecycle"
)

func TestCrossProjectListing(t *testing.T) {
	e := newEnv(t, envOpts{})
	l := e.list(t, "")
	got := map[string]Row{}
	for _, r := range l.Sessions {
		got[r.ID] = r
	}
	for _, id := range []string{sidA, sidB, sidAlpha} {
		if _, ok := got[id]; !ok {
			t.Fatalf("session %s missing from %v", id, ids(l.Sessions))
		}
	}
	a, b, al := got[sidA], got[sidB], got[sidAlpha]
	if a.Project != cwdA || a.ProjectName != "proj" || a.State != StateUnknown || a.Denials != 1 || a.Decisions != 2 || a.Title == "" || len(a.Models) == 0 {
		t.Errorf("fixture A row: %+v", a)
	}
	if a.LastDenial == nil || !strings.Contains(a.LastDenial.Label, "net") {
		t.Errorf("fixture A last denial: %+v", a.LastDenial)
	}
	if b.Project != cwdB || b.State != StateEnded {
		t.Errorf("fixture B row: %+v", b)
	}
	if al.Project != "~/work/alpha" || al.ProjectName != "alpha" || al.State != StateLive || al.Branch != "feature/x" {
		t.Errorf("alpha row: %+v", al)
	}
	if !l.Transcripts || l.Total != len(l.Sessions) || l.NextCursor != "" {
		t.Errorf("list envelope: %+v", l)
	}

	var pj struct{ Projects []Project }
	e.getJSON(t, "/api/projects", &pj)
	names := map[string]Project{}
	for _, p := range pj.Projects {
		names[p.Project] = p
	}
	for _, want := range []string{cwdA, cwdB, "~/work/alpha"} {
		if _, ok := names[want]; !ok {
			t.Errorf("project %s missing: %+v", want, pj.Projects)
		}
	}
	if names["~/work/alpha"].Live != 1 || names[cwdA].Denials != 1 {
		t.Errorf("project counts: %+v", pj.Projects)
	}
}

func TestFilters(t *testing.T) {
	e := newEnv(t, envOpts{})
	for q, want := range map[string][]string{
		"?state=live":    {sidAlpha},
		"?state=ended":   {sidB},
		"?state=unknown": {sidA},
		"?denials=1":     {sidA},
		"?project=" + url.QueryEscape("~/work/alpha"):       {sidAlpha},
		"?project=" + url.QueryEscape(e.alphaCwd):           {sidAlpha},
		"?project=" + url.QueryEscape(cwdA):                 {sidA},
		"?project=" + url.QueryEscape(cwdA) + "&state=live": {},
		"?since=2099-01-01":                                 {},
		"?until=2000-01-01":                                 {},
		"?q=alphaword":                                      {sidAlpha},
		"?q=DENIED(1)&project=" + url.QueryEscape(cwdA):     {sidA},
	} {
		l := e.list(t, q)
		if fmt.Sprint(ids(l.Sessions)) != fmt.Sprint(want) && !(len(want) == 0 && len(l.Sessions) == 0) {
			t.Errorf("%s: %v, want %v", q, ids(l.Sessions), want)
		}
		if strings.Contains(q, "q=alphaword") && (len(l.Sessions) != 1 || !strings.Contains(l.Sessions[0].Snippet, "alphaword")) {
			t.Errorf("snippet missing: %+v", l.Sessions)
		}
	}
	// since keeps the sessions with fresh lifecycle records (alpha live, B just ended), not fixture A.
	since := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	if l := e.list(t, "?since="+since); len(l.Sessions) != 2 || containsStr(ids(l.Sessions), sidA) {
		t.Errorf("since: %v", ids(l.Sessions))
	}
	for _, bad := range []string{"?state=zombie", "?denials=yes", "?since=yesterday", "?until=x", "?limit=0", "?cursor=!!", "?project=relative/dir", "?project=" + url.QueryEscape("/Users/you/nowhere"), "?project=" + url.QueryEscape("~/../etc"), "?q=" + strings.Repeat("x", 300)} {
		resp, b := e.get(t, "/api/sessions"+bad)
		if resp.StatusCode != 400 {
			t.Errorf("%s = %d %s", bad, resp.StatusCode, b)
		}
		if strings.Contains(string(b), "nowhere") || strings.Contains(string(b), "etc") {
			t.Errorf("%s: error echoes the value: %s", bad, b)
		}
	}
}

func TestDetail(t *testing.T) {
	e := newEnv(t, envOpts{})
	var d Detail
	e.getJSON(t, "/api/sessions/"+sidA, &d)
	if d.ID != sidA || d.Runs != 2 || d.Risk.Denials != 1 || d.Risk.RuleHits == nil || d.Risk.Ungranted == nil || !d.Transcripts || d.CCVersion == "" || len(d.Skills) == 0 {
		t.Errorf("detail: %+v", d)
	}
	if len(d.Agents) != 1 {
		t.Errorf("agent types: %v", d.Agents)
	}
	for path, code := range map[string]int{
		"/api/sessions/not%20valid":                               400,
		"/api/sessions/" + "deadbeef-0000-4000-8000-000000000000": 404,
	} {
		if resp, b := e.get(t, path); resp.StatusCode != code {
			t.Errorf("%s = %d %s", path, resp.StatusCode, b)
		}
	}
	// A direct pseudo-session (a run typed by hand) is listed and its id is
	// the one the map route knows.
	appendAct(t, e.paths, activity.Record{V: 1, Kind: activity.KindRun, TS: activity.Now(), Cwd: "/Users/you/hand", Skills: []string{"canary-basic"}, Command: "python3 x.py", Outcome: "ok"})
	e.cat.Refresh(false)
	var direct *Row
	for _, r := range e.list(t, "").Sessions {
		if r.Direct {
			direct = &r
			break
		}
	}
	if direct == nil {
		t.Fatal("direct row missing")
	}
	if resp, b := e.get(t, "/api/sessions/"+direct.ID+"/map?view=topology"); resp.StatusCode != 200 {
		t.Errorf("map of the direct row = %d %s", resp.StatusCode, b)
	}
}

// A cwd-less server (auto/service mode) can open the map of a session that
// only the index knows, by passing the row's project back as ?project=.
func TestCwdlessMapViaProject(t *testing.T) {
	e := newEnv(t, envOpts{})
	l := e.list(t, "?state=live")
	if len(l.Sessions) != 1 {
		t.Fatalf("live: %v", ids(l.Sessions))
	}
	r := l.Sessions[0]
	path := "/api/sessions/" + r.ID + "/map?view=topology&project=" + url.QueryEscape(r.Project)
	if resp, b := e.get(t, path); resp.StatusCode != 200 {
		t.Fatalf("%s = %d %s", path, resp.StatusCode, b)
	}
	if resp, _ := e.get(t, "/api/sessions/"+r.ID+"/map?view=topology"); resp.StatusCode != 404 {
		t.Errorf("without ?project the cwd-less map should not find an index-only session: %d", resp.StatusCode)
	}
}

func TestPaginationCursorStable(t *testing.T) {
	root, home, p := newFixture(t)
	proj := filepath.Join(home, "work", "many")
	base := time.Now().Add(-10 * time.Hour)
	var want []string
	for i := 0; i < 7; i++ {
		id := fmt.Sprintf("d0000000-0000-4000-8000-%012d", i)
		at := base.Add(time.Duration(i) * time.Minute)
		writeSession(t, p, proj, id, synthSession(id, proj, fmt.Sprintf("w%d", i), at), at)
		want = append([]string{id}, want...) // newest first
	}
	e := serve(t, root, home, p, envOpts{})
	q := "?project=" + url.QueryEscape("~/work/many") + "&limit=3"
	p1 := e.list(t, q)
	if fmt.Sprint(ids(p1.Sessions)) != fmt.Sprint(want[:3]) || p1.NextCursor == "" || p1.Total != 7 {
		t.Fatalf("page 1: %v next %q total %d", ids(p1.Sessions), p1.NextCursor, p1.Total)
	}
	// A newer session arrives between the two requests.
	nid := "d0000000-0000-4000-8000-000000000099"
	writeSession(t, p, proj, nid, synthSession(nid, proj, "late", time.Now()), time.Now().Add(-time.Minute))
	e.cat.Refresh(true)
	p2 := e.list(t, q+"&cursor="+p1.NextCursor)
	if fmt.Sprint(ids(p2.Sessions)) != fmt.Sprint(want[3:6]) {
		t.Fatalf("page 2 shifted: %v want %v", ids(p2.Sessions), want[3:6])
	}
	p3 := e.list(t, q+"&cursor="+p2.NextCursor)
	if fmt.Sprint(ids(p3.Sessions)) != fmt.Sprint(want[6:]) || p3.NextCursor != "" {
		t.Fatalf("page 3: %v next %q", ids(p3.Sessions), p3.NextCursor)
	}
	if again := e.list(t, q); again.Sessions[0].ID != nid {
		t.Errorf("the late session is not first on a fresh page 1: %v", ids(again.Sessions))
	}
	// 100 per page at most.
	if l := e.list(t, "?limit=1000"); len(l.Sessions) > PageSize {
		t.Errorf("page of %d", len(l.Sessions))
	}
}

func TestSearchSnippetBounds(t *testing.T) {
	root, home, p := newFixture(t)
	proj := filepath.Join(home, "work", "big")
	long := strings.Repeat("ünïcødé filler ", 200)
	for i := 0; i < 60; i++ {
		id := fmt.Sprintf("e0000000-0000-4000-8000-%012d", i)
		at := time.Now().Add(-time.Duration(100+i) * time.Minute)
		writeSession(t, p, proj, id, synthSession(id, proj, long+" needle "+long, at), at)
	}
	e := serve(t, root, home, p, envOpts{})
	var res struct {
		Hits []struct {
			SessionID, Snippet, Project, State string
		}
		Disabled bool
	}
	e.getJSON(t, "/api/search?q=NEEDLE", &res)
	if len(res.Hits) != MaxSearchHits || res.Disabled {
		t.Fatalf("hits %d (want %d), disabled %v", len(res.Hits), MaxSearchHits, res.Disabled)
	}
	for _, h := range res.Hits {
		if len(h.Snippet) > 240 || !utf8.ValidString(h.Snippet) || !strings.Contains(h.Snippet, "needle") || h.Project != "~/work/big" {
			t.Fatalf("hit: %+v (%d bytes)", h, len(h.Snippet))
		}
	}
	e.getJSON(t, "/api/search?q=needle&limit=5", &res)
	if len(res.Hits) != 5 {
		t.Errorf("limit 5: %d", len(res.Hits))
	}
	e.getJSON(t, "/api/search?q=", &res)
	if len(res.Hits) != 0 {
		t.Errorf("empty query: %d hits", len(res.Hits))
	}
	if resp, _ := e.get(t, "/api/search?q="+strings.Repeat("y", 257)); resp.StatusCode != 400 {
		t.Errorf("long query = %d", resp.StatusCode)
	}
	// Busy: both search slots taken → 429.
	e.cat.searchSem <- struct{}{}
	e.cat.searchSem <- struct{}{}
	if resp, _ := e.get(t, "/api/search?q=needle"); resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("busy search = %d", resp.StatusCode)
	}
	<-e.cat.searchSem
	<-e.cat.searchSem
	// Cancelled: a done context stops the scan.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.cat.Search(ctx, "needle", 50); err == nil {
		t.Error("cancelled search returned no error")
	}
}

func TestNoTranscriptsMetadataOnly(t *testing.T) {
	e := newEnv(t, envOpts{noTranscripts: true})
	l := e.list(t, "")
	got := map[string]Row{}
	for _, r := range l.Sessions {
		got[r.ID] = r
	}
	for _, id := range []string{sidA, sidB, sidAlpha} {
		r, ok := got[id]
		if !ok {
			t.Fatalf("%s missing: %v", id, ids(l.Sessions))
		}
		if r.Title != "" || len(r.Models) != 0 || r.Branch != "" || r.Turns != 0 || containsStr(r.Sources, "index") {
			t.Errorf("%s carries transcript content: %+v", id, r)
		}
	}
	if got[sidAlpha].State != StateLive || got[sidB].State != StateEnded || got[sidA].Denials != 1 {
		t.Errorf("states/counts: %+v %+v %+v", got[sidAlpha], got[sidB], got[sidA])
	}
	if l.Transcripts {
		t.Error("transcripts reported on")
	}
	if l := e.list(t, "?q=alphaword"); !l.SearchDisabled || len(l.Sessions) != 0 {
		t.Errorf("search under --no-transcripts: %+v", l)
	}
	var res struct {
		Hits     []any
		Disabled bool
	}
	e.getJSON(t, "/api/search?q=alphaword", &res)
	if !res.Disabled || len(res.Hits) != 0 {
		t.Errorf("search: %+v", res)
	}
	if _, err := os.Stat(e.paths.SessionIndexDir()); !os.IsNotExist(err) {
		t.Errorf("index dir created under --no-transcripts: %v", err)
	}
}

func TestRoutesAreGuarded(t *testing.T) {
	e := newEnv(t, envOpts{})
	for _, p := range []string{"/api/sessions", "/api/sessions/" + sidA, "/api/projects", "/api/search?q=x", "/api/events"} {
		if resp, b := e.getH(t, p, nil); resp.StatusCode != 401 || strings.Contains(string(b), sidA+"\"") {
			t.Errorf("%s without a token: %d %s", p, resp.StatusCode, b)
		}
		if resp, _ := e.getH(t, p, map[string]string{"Authorization": "Bearer " + e.tok, "Host": "evil.example:80"}); resp.StatusCode == 200 {
			t.Errorf("%s with a foreign Host answered 200", p)
		}
	}
}

func TestEventsRequireBearer(t *testing.T) {
	e := newEnv(t, envOpts{})
	for name, hdr := range map[string]map[string]string{
		"none":   nil,
		"wrong":  {"Authorization": "Bearer nope"},
		"basic":  {"Authorization": "Basic " + e.tok},
		"cookie": {"Cookie": "t=" + e.tok},
	} {
		if resp, _ := e.getH(t, "/api/events", hdr); resp.StatusCode != 401 {
			t.Errorf("%s: %d", name, resp.StatusCode)
		}
	}
	// A token in the URL is never accepted, query or path.
	for _, p := range []string{"/api/events?token=" + e.tok, "/api/events?t=" + e.tok, "/api/events?access_token=" + e.tok} {
		if resp, _ := e.getH(t, p, nil); resp.StatusCode != 401 {
			t.Errorf("%s: %d", strings.Replace(p, e.tok, "<tok>", 1), resp.StatusCode)
		}
	}
	if e.srv.Streams() != 0 || e.cat.Subscribers() != 0 {
		t.Errorf("refused requests left streams open: %d %d", e.srv.Streams(), e.cat.Subscribers())
	}
}

func TestEventStreamDeliversAndKeepsAlive(t *testing.T) {
	e := newEnv(t, envOpts{keepalive: 50 * time.Millisecond})
	e.list(t, "") // first snapshot
	s := e.openStream(t)
	defer s.resp.Body.Close()
	if s.resp.StatusCode != 200 || !strings.HasPrefix(s.resp.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("stream: %d %s", s.resp.StatusCode, s.resp.Header.Get("Content-Type"))
	}
	if csp := s.resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") {
		t.Errorf("stream CSP: %q", csp)
	}
	if n, _ := s.next(t, 2*time.Second); n != "hello" {
		t.Fatalf("first frame %q", n)
	}
	if n, d := s.next(t, 2*time.Second); n != "" || d != "keepalive" {
		t.Fatalf("keepalive frame: %q %q", n, d)
	}
	// A session starts: a "session" event names it.
	newID := "f0000000-0000-4000-8000-000000000001"
	st := lifecycle.Store{Log: e.paths.Sessions, Live: e.paths.LiveDir}
	if _, err := st.Start(newID, "", "/Users/you/proj", "startup"); err != nil {
		t.Fatal(err)
	}
	e.cat.Refresh(false)
	var ev map[string]string
	data := s.until(t, "session", 2*time.Second)
	json.Unmarshal([]byte(data), &ev)
	if ev["id"] != newID || ev["state"] != StateLive {
		t.Errorf("session event: %s", data)
	}
	// It ends.
	st.End(newID, "", "/Users/you/proj", "other")
	e.cat.Refresh(false)
	json.Unmarshal([]byte(s.until(t, "session", 2*time.Second)), &ev)
	if ev["id"] != newID || ev["state"] != StateEnded || ev["prev"] != StateLive {
		t.Errorf("end event: %v", ev)
	}
	// New activity.
	appendAct(t, e.paths, activity.Record{V: 1, Kind: activity.KindDenied, TS: activity.Now(), SessionID: sidAlpha, Cwd: e.alphaCwd, Skills: []string{"canary-request"}})
	e.cat.Refresh(false)
	var act struct {
		Sessions []string
		Records  int
	}
	json.Unmarshal([]byte(s.until(t, "activity", 2*time.Second)), &act)
	if fmt.Sprint(act.Sessions) != fmt.Sprint([]string{sidAlpha}) || act.Records != 1 {
		t.Errorf("activity event: %+v", act)
	}
	// The denial shows on the row, with the home dir never echoed.
	l := e.list(t, "?denials=1&state=live")
	if len(l.Sessions) != 1 || l.Sessions[0].LastDenial == nil {
		t.Errorf("denials after event: %+v", l.Sessions)
	}
	// The index changes: an "index" event.
	id2 := "f0000000-0000-4000-8000-000000000002"
	writeSession(t, e.paths, e.alphaCwd, id2, synthSession(id2, e.alphaCwd, "fresh", time.Now()), time.Now().Add(-time.Hour))
	e.cat.Refresh(true)
	s.until(t, "index", 2*time.Second)
}

func TestStreamCapAndCleanup(t *testing.T) {
	e := newEnv(t, envOpts{})
	var open []*stream
	for i := 0; i < 8; i++ {
		s := e.openStream(t)
		if s.resp.StatusCode != 200 {
			t.Fatalf("stream %d: %d", i, s.resp.StatusCode)
		}
		s.next(t, 2*time.Second) // hello
		open = append(open, s)
	}
	waitFor(t, "8 streams", func() bool { return e.srv.Streams() == 8 && e.cat.Subscribers() == 8 })
	resp, b := e.get(t, "/api/events")
	if resp.StatusCode != http.StatusTooManyRequests || !strings.Contains(string(b), "at most 8") {
		t.Errorf("9th stream: %d %s", resp.StatusCode, b)
	}
	// Disconnecting releases the stream and the subscription.
	open[0].resp.Body.Close()
	waitFor(t, "a released stream", func() bool { return e.srv.Streams() == 7 && e.cat.Subscribers() == 7 })
	s := e.openStream(t)
	if s.resp.StatusCode != 200 {
		t.Errorf("stream after release: %d", s.resp.StatusCode)
	}
	open = append(open[1:], s)
	for _, s := range open {
		s.resp.Body.Close()
	}
	waitFor(t, "every stream released", func() bool { return e.srv.Streams() == 0 && e.cat.Subscribers() == 0 })
}

// Shutting the server down ends open streams promptly instead of holding
// the graceful shutdown for its timeout.
func TestStreamEndsOnShutdown(t *testing.T) {
	root, home, p := newFixture(t)
	e := serve(t, root, home, p, envOpts{})
	s := e.openStream(t)
	s.next(t, 2*time.Second)
	e.srv.RequestStop()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			if _, err := s.rd.ReadString('\n'); err != nil {
				return
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("stream still open 3 s after the server was asked to stop")
	}
}

// The catalog's goroutine refreshes while handlers read and search; run
// with -race.
func TestConcurrentRefreshAndReads(t *testing.T) {
	root, home, p := newFixture(t)
	e := serve(t, root, home, p, envOpts{})
	e.cat.o.Watch, e.cat.o.Refresh = 5*time.Millisecond, 20*time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e.cat.Start(ctx)
	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() { // writer: grows a transcript and the activity log
		defer wg.Done()
		f, err := os.OpenFile(filepath.Join(p.ClaudeProjectsDir(), "-Users-you-proj", sidA+".jsonl"), os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			t.Error(err)
			return
		}
		defer f.Close()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			f.WriteString(jsonLine(map[string]any{"type": "user", "timestamp": time.Now().UTC().Format(time.RFC3339Nano), "message": map[string]any{"role": "user", "content": fmt.Sprintf("more %d", i)}}))
			activity.Append(p.Activity, activity.Record{V: 1, Kind: activity.KindDecision, TS: activity.Now(), SessionID: sidA, Cwd: cwdA, Decision: "ask", Skills: []string{"canary-request"}})
			time.Sleep(3 * time.Millisecond)
		}
	}()
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 15; i++ {
				e.get(t, "/api/sessions")
				e.get(t, "/api/search?q=more")
				e.get(t, "/api/projects")
				e.get(t, "/api/sessions/"+sidA)
			}
		}()
	}
	time.Sleep(300 * time.Millisecond)
	close(stop)
	wg.Wait()
	cancel()
	select {
	case <-e.cat.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("catalog goroutine did not stop")
	}
}

// No response carries the temp root, its real path or the home dir; the
// cwd-less server is checked plain and with ?project= on every route.
func TestNoAbsolutePathsInJSON(t *testing.T) {
	for _, tc := range []struct {
		name  string
		o     envOpts
		query string
	}{
		{"cwd", envOpts{cwd: cwdA}, ""},
		{"cwd-less", envOpts{}, ""},
		{"cwd-less ?project", envOpts{}, "project=" + url.QueryEscape("~/work/alpha")},
		{"cwd-less ?project abs", envOpts{}, "project=" + url.QueryEscape(cwdA)},
		{"no-transcripts", envOpts{noTranscripts: true}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, tc.o)
			// A denial whose reason and ungranted line name the home dir.
			appendAct(t, e.paths, activity.Record{V: 1, Kind: activity.KindDecision, TS: activity.Now(), SessionID: sidAlpha, Cwd: e.alphaCwd, Decision: "ask",
				Skills: []string{"canary-request"}, Ungranted: []string{"canary-request: write: " + filepath.Join(e.home, "out")}})
			e.cat.Refresh(false)
			sep := func(p string) string {
				if tc.query == "" {
					return p
				}
				if strings.Contains(p, "?") {
					return p + "&" + tc.query
				}
				return p + "?" + tc.query
			}
			paths := []string{"/api/sessions", "/api/projects", "/api/search?q=alphaword", "/api/search?q=proj", "/api/sessions?q=look"}
			for _, id := range []string{sidA, sidB, sidAlpha} {
				paths = append(paths, "/api/sessions/"+id)
			}
			realRoot, _ := filepath.EvalSymlinks(e.root)
			forbidden := []string{e.root, realRoot, e.home}
			if r, err := filepath.EvalSymlinks(e.home); err == nil {
				forbidden = append(forbidden, r)
			}
			n := 0
			for _, p := range paths {
				resp, b := e.get(t, sep(p))
				if resp.StatusCode != 200 {
					t.Fatalf("%s = %d %s", sep(p), resp.StatusCode, b)
				}
				var v any
				if err := json.Unmarshal(b, &v); err != nil {
					t.Fatal(err)
				}
				walkStrings(v, func(s string) {
					n++
					for _, f := range forbidden {
						if strings.Contains(s, f) {
							t.Errorf("%s: response string contains a temp path: %q", p, s)
						}
					}
					if strings.HasPrefix(s, "/") && !strings.Contains(s, " ") && s != cwdA && s != cwdB && s != "/Users/you/hand" {
						t.Errorf("%s: absolute path in a response: %q", p, s)
					}
				})
			}
			if n < 20 {
				t.Errorf("only %d strings checked", n)
			}
		})
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
