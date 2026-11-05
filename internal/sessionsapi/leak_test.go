package sessionsapi

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/rulebook"
)

// Leak watch (DESIGN §14 "Leak watch"). Key-shaped values are built by
// concatenation so no file in the repo holds a whole one.
var (
	fakeSlack  = "xoxb" + "-" + strings.Repeat("0", 10) + "-FAKE"
	fakeGitHub = "ghp" + "_" + "FAKE" + strings.Repeat("0", 32)
	fakeStripe = "sk" + "_live_" + "FAKE" + strings.Repeat("0", 16)
	fakeAnth   = "sk" + "-ant-" + "api03-" + "FAKE" + strings.Repeat("0", 32)
	fakeAWSID  = "AKIA" + "IOSFODNN7" + "EXAMPLE"
	fakePEM    = "-----BEGIN OPENSSH " + "PRIVATE KEY-----"
	fakeOpenAI = "sk" + "-proj-" + "FAKE" + strings.Repeat("0", 32)
	fakeAWSSec = "FAKE" + strings.Repeat("0", 36)
)

const sidLeak = "d0000000-0000-4000-8000-0000000000d1"

// leakySession writes a session under <home>/work/leaky whose Read of
// .env returned a Slack-shaped token (at-2h) and whose reply then repeated
// a GitHub-shaped one (at-1h).
func leakySession(t *testing.T, e *env, at time.Time) string {
	t.Helper()
	cwd := filepath.Join(e.home, "work", "leaky")
	stamp := func(d time.Duration) string { return at.Add(d).UTC().Format(time.RFC3339Nano) }
	content := jsonLine(map[string]any{"type": "user", "timestamp": stamp(-3 * time.Hour), "cwd": cwd, "sessionId": sidLeak, "version": "2.1.296",
		"message": map[string]any{"role": "user", "content": "read the env file"}}) +
		jsonLine(map[string]any{"type": "assistant", "timestamp": stamp(-150 * time.Minute), "cwd": cwd, "uuid": "u-tool",
			"message": map[string]any{"role": "assistant", "model": "claude-test-1", "content": []any{map[string]any{"type": "tool_use", "id": "toolu_env", "name": "Read",
				"input": map[string]any{"file_path": filepath.Join(cwd, ".env")}}}}}) +
		jsonLine(map[string]any{"type": "user", "timestamp": stamp(-2 * time.Hour), "cwd": cwd,
			"message": map[string]any{"role": "user", "content": []any{map[string]any{"type": "tool_result", "tool_use_id": "toolu_env", "content": "SLACK=" + fakeSlack}}}}) +
		jsonLine(map[string]any{"type": "assistant", "timestamp": stamp(-time.Hour), "cwd": cwd, "uuid": "u-reply",
			"message": map[string]any{"role": "assistant", "model": "claude-test-1", "content": []any{map[string]any{"type": "text", "text": "It also mentions " + fakeGitHub}}}})
	writeSession(t, e.paths, cwd, sidLeak, content, at.Add(-time.Hour))
	e.cat.Refresh(true)
	return cwd
}

func TestRowAndDetailLeaks(t *testing.T) {
	e := newEnv(t, envOpts{})
	leakySession(t, e, time.Now())
	var row *Row
	for _, r := range e.list(t, "").Sessions {
		if r.ID == sidLeak {
			row = &r
		} else if r.Leaks != 0 {
			t.Errorf("row %s has %d leaks", r.ID, r.Leaks)
		}
	}
	if row == nil || row.Leaks != 2 {
		t.Fatalf("leaky row: %+v", row)
	}
	var d Detail
	e.getJSON(t, "/api/sessions/"+sidLeak, &d)
	if d.Leaks != 2 || len(d.Risk.Leaks) != 2 {
		t.Fatalf("detail leaks: %d %+v", d.Leaks, d.Risk.Leaks)
	}
	f := d.Risk.Leaks[0]
	if f.Pattern != "slack-token" || f.Where != "result" || f.Tool != "Read" || f.Target != "~/work/leaky/.env" || f.Ref != "toolu_env" {
		t.Errorf("first finding: %+v", f)
	}
	if g := d.Risk.Leaks[1]; g.Pattern != "github-token" || g.Where != "reply" || g.Ref != "u-reply" || g.Target != "" {
		t.Errorf("second finding: %+v", g)
	}
	// A session with no findings has none in its detail.
	var a Detail
	e.getJSON(t, "/api/sessions/"+sidA, &a)
	if a.Leaks != 0 || a.Risk.Leaks != nil {
		t.Errorf("fixture A leaks: %d %+v", a.Leaks, a.Risk.Leaks)
	}
	// Neither response names the temp home or holds a key-shaped value.
	for _, p := range []string{"/api/sessions", "/api/sessions/" + sidLeak} {
		_, b := e.get(t, p)
		for _, bad := range []string{e.home, fakeSlack, fakeGitHub} {
			if strings.Contains(string(b), bad) {
				t.Errorf("%s holds %d forbidden bytes", p, len(bad))
			}
		}
	}
}

func TestCatalogLeaksSince(t *testing.T) {
	e := newEnv(t, envOpts{})
	now := time.Now()
	leakySession(t, e, now)
	all := e.cat.Leaks(time.Time{})
	if len(all) != 2 {
		t.Fatalf("all leaks: %+v", all)
	}
	var res, rep = all[0], all[1]
	if res.Where != "result" {
		res, rep = rep, res
	}
	if res.SessionID != sidLeak || res.Ref != "toolu_env" || res.Tool != "Read" || res.Target != "~/work/leaky/.env" ||
		res.Pattern != "slack-token" || res.Label != "Slack token" || res.Project != "~/work/leaky" || res.TS.Sub(now.Add(-2*time.Hour)).Abs() > time.Millisecond {
		t.Errorf("result leak: %+v", res)
	}
	if rep.Where != "reply" || rep.Ref != "u-reply" || rep.Pattern != "github-token" || rep.Project != "~/work/leaky" {
		t.Errorf("reply leak: %+v", rep)
	}
	recent := e.cat.Leaks(now.Add(-90 * time.Minute))
	if len(recent) != 1 || recent[0].Where != "reply" {
		t.Errorf("since 90 minutes ago: %+v", recent)
	}
	if got := e.cat.Leaks(now); len(got) != 0 {
		t.Errorf("since now: %+v", got)
	}
}

func TestCatalogLeaksOffWithoutTranscripts(t *testing.T) {
	e := newEnv(t, envOpts{noTranscripts: true})
	leakySession(t, e, time.Now())
	if got := e.cat.Leaks(time.Time{}); len(got) != 0 {
		t.Errorf("leaks under --no-transcripts: %+v", got)
	}
}

const sidVault = "d0000000-0000-4000-8000-0000000000d2"

// TestLeakSurfacesCarryNoSecret: with all eight kinds planted in one
// session (one as the Bash program, one inside a file path longer than the
// 120-byte target cut, where the cut lands inside the key), no surface leak
// watch feeds holds a key or the start of one: /api/sessions, the session
// detail, Catalog.Leaks, the rulebook items built from it, and /api/needs.
func TestLeakSurfacesCarryNoSecret(t *testing.T) {
	e := newEnv(t, envOpts{})
	cwd := filepath.Join(e.home, "work", "vault")
	at := time.Now().Add(-time.Hour)
	stamp := func(i int) string { return at.Add(time.Duration(i) * time.Second).UTC().Format(time.RFC3339Nano) }
	tool := func(i int, id, name string, in map[string]any) string {
		return jsonLine(map[string]any{"type": "assistant", "timestamp": stamp(i), "cwd": cwd, "uuid": "u-" + id,
			"message": map[string]any{"role": "assistant", "model": "claude-test-1", "content": []any{
				map[string]any{"type": "tool_use", "id": id, "name": name, "input": in}}}})
	}
	result := func(i int, id, text string) string {
		return jsonLine(map[string]any{"type": "user", "timestamp": stamp(i), "cwd": cwd,
			"message": map[string]any{"role": "user", "content": []any{map[string]any{"type": "tool_result", "tool_use_id": id, "content": text}}}})
	}
	// "/tmp/" + 105 bytes + "/" is 111 bytes: the cut keeps 9 bytes of the key.
	longPath := "/tmp/" + strings.Repeat("d", 105) + "/" + fakeGitHub + ".txt"
	content := jsonLine(map[string]any{"type": "user", "timestamp": stamp(0), "cwd": cwd, "sessionId": sidVault, "version": "2.1.296",
		"message": map[string]any{"role": "user", "content": "check the config"}}) +
		tool(1, "toolu_prog", "Bash", map[string]any{"command": fakeStripe + " --version"}) +
		result(2, "toolu_prog", "v1 "+fakeAnth) +
		tool(3, "toolu_long", "Read", map[string]any{"file_path": longPath}) +
		result(4, "toolu_long", fakePEM+"\n"+fakeOpenAI) +
		jsonLine(map[string]any{"type": "assistant", "timestamp": stamp(5), "cwd": cwd, "uuid": "u-reply",
			"message": map[string]any{"role": "assistant", "model": "claude-test-1", "content": []any{
				map[string]any{"type": "text", "text": "found " + fakeAWSID + " and aws_secret_access_key = " + fakeAWSSec}}}}) +
		tool(6, "toolu_write", "Write", map[string]any{"file_path": filepath.Join(cwd, "notes.md"), "content": "slack: " + fakeSlack}) +
		result(7, "toolu_write", "ok")
	writeSession(t, e.paths, cwd, sidVault, content, at)
	e.cat.Refresh(true)

	keys := []string{fakeSlack, fakeGitHub, fakeStripe, fakeAnth, fakeAWSID, fakePEM, fakeOpenAI, fakeAWSSec}
	check := func(surface string, b []byte) {
		t.Helper()
		for _, k := range keys {
			if strings.Contains(string(b), k) {
				t.Errorf("%s holds a key-shaped value (%d bytes)", surface, len(k))
			} else if strings.Contains(string(b), k[:9]) {
				t.Errorf("%s holds the first 9 bytes of a key-shaped value", surface)
			}
		}
	}
	mustJSON := func(v any) []byte {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	leaks := e.cat.Leaks(time.Time{})
	patterns := map[string]bool{}
	for _, l := range leaks {
		if l.SessionID != sidVault {
			continue
		}
		patterns[l.Pattern] = true
		if (l.Ref == "toolu_prog" || l.Ref == "toolu_long") && l.Target != "" {
			t.Errorf("a key-shaped target was kept: %+v", l)
		}
	}
	if len(patterns) != 8 {
		t.Fatalf("want all eight patterns, got %v", patterns)
	}
	check("Catalog.Leaks", mustJSON(leaks))

	items, err := rulebook.Open(rulebook.InboxInput{Paths: e.paths, Leaks: leaks})
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, it := range items {
		if it.Kind == rulebook.KindLeak {
			n++
		}
	}
	if n == 0 {
		t.Fatal("no leak items")
	}
	check("rulebook items", mustJSON(items))

	for _, p := range []string{"/api/sessions", "/api/sessions/" + sidVault, "/api/needs"} {
		resp, b := e.get(t, p)
		if resp.StatusCode != 200 {
			t.Fatalf("%s = %d %s", p, resp.StatusCode, b)
		}
		if p == "/api/needs" && !strings.Contains(string(b), `"kind":"leak"`) {
			t.Fatalf("/api/needs lists no leak item: %.300s", b)
		}
		check(p, b)
	}
}

const sidCut = "d0000000-0000-4000-8000-0000000000d3"

// TestCatalogLeaksCarryTargetCut (Task 5 fix round 1): the index's
// target_cut reaches rulebook.Leak.TargetCut, and a whole target stays
// false.
func TestCatalogLeaksCarryTargetCut(t *testing.T) {
	e := newEnv(t, envOpts{})
	at := time.Now()
	cwd := filepath.Join(e.home, "work", "cut")
	stamp := func(d time.Duration) string { return at.Add(d).UTC().Format(time.RFC3339Nano) }
	read := func(id, path string, d time.Duration) string {
		return jsonLine(map[string]any{"type": "assistant", "timestamp": stamp(d), "cwd": cwd, "uuid": "u-" + id,
			"message": map[string]any{"role": "assistant", "model": "claude-test-1", "content": []any{map[string]any{"type": "tool_use", "id": id, "name": "Read",
				"input": map[string]any{"file_path": path}}}}}) +
			jsonLine(map[string]any{"type": "user", "timestamp": stamp(d + time.Minute), "cwd": cwd,
				"message": map[string]any{"role": "user", "content": []any{map[string]any{"type": "tool_result", "tool_use_id": id, "content": "SLACK=" + fakeSlack}}}})
	}
	content := jsonLine(map[string]any{"type": "user", "timestamp": stamp(-3 * time.Hour), "cwd": cwd, "sessionId": sidCut, "version": "2.1.296",
		"message": map[string]any{"role": "user", "content": "read them"}}) +
		read("toolu_long", filepath.Join(cwd, strings.Repeat("d", 130), ".env"), -2*time.Hour) +
		read("toolu_short", filepath.Join(cwd, ".env"), -time.Hour)
	writeSession(t, e.paths, cwd, sidCut, content, at.Add(-time.Hour))
	e.cat.Refresh(true)
	got := map[string]rulebook.Leak{}
	for _, l := range e.cat.Leaks(time.Time{}) {
		got[l.Ref] = l
	}
	if l, ok := got["toolu_long"]; !ok || !l.TargetCut {
		t.Errorf("long leak: %+v", l)
	}
	if l, ok := got["toolu_short"]; !ok || l.TargetCut || l.Target != "~/work/cut/.env" {
		t.Errorf("short leak: %+v", l)
	}
}
