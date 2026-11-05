package sessionsapi

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/activity"
	"github.com/Panda-Taps-LLC/watchdeck/internal/lifecycle"
	"github.com/Panda-Taps-LLC/watchdeck/internal/mapapi"
	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
	"github.com/Panda-Taps-LLC/watchdeck/internal/rulebook"
	"github.com/Panda-Taps-LLC/watchdeck/internal/transcript"
	"github.com/Panda-Taps-LLC/watchdeck/internal/ui"
)

// The fixture home: a temp HOME with three projects under .claude/projects
// and nothing read from the developer's home.
//
//   - fixture A (internal/transcript/testdata/e2e-canary), cwd /Users/you/proj,
//     with its activity log (one sandbox denial); no lifecycle record;
//   - fixture B (synthetic-subagents), cwd /Users/you/proj-b; ended;
//   - a synthetic session in <home>/work/alpha (shown as ~/work/alpha); live.
const (
	sidA     = "a9896c55-0b77-4f85-a0e0-9be2948b8aa6"
	sidB     = "b0000000-0000-4000-8000-00000000000b"
	sidAlpha = "c0000000-0000-4000-8000-0000000000a1"
	cwdA     = "/Users/you/proj"
	cwdB     = "/Users/you/proj-b"
	homeTag  = "/Users/you/.claude/projects"
)

type env struct {
	root, home string
	paths      paths.Paths
	cat        *Catalog
	srv        *ui.Server
	base, tok  string
	alphaCwd   string
}

type envOpts struct {
	noTranscripts bool
	cwd           string
	keepalive     time.Duration
}

func repoPath(t testing.TB, parts ...string) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(append([]string{filepath.Dir(file), "..", ".."}, parts...)...)
}

func copyTree(t testing.TB, src, dst string) {
	t.Helper()
	err := filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if info.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o700)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), b, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func jsonLine(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b) + "\n"
}

// synthSession is a small transcript: one prompt, one reply, one Bash call.
func synthSession(id, cwd, word string, at time.Time) string {
	t := func(i int) string { return at.Add(time.Duration(i) * time.Second).UTC().Format(time.RFC3339Nano) }
	return jsonLine(map[string]any{"type": "user", "timestamp": t(0), "cwd": cwd, "sessionId": id, "gitBranch": "feature/x", "version": "2.1.296", "entrypoint": "cli",
		"message": map[string]any{"role": "user", "content": "please look for " + word}}) +
		jsonLine(map[string]any{"type": "assistant", "timestamp": t(1), "cwd": cwd, "sessionId": id,
			"message": map[string]any{"role": "assistant", "model": "claude-test-1", "content": []any{map[string]any{"type": "text", "text": "looking for " + word}}}}) +
		jsonLine(map[string]any{"type": "assistant", "timestamp": t(2), "cwd": cwd, "sessionId": id,
			"message": map[string]any{"role": "assistant", "model": "claude-test-1", "content": []any{map[string]any{"type": "tool_use", "id": "toolu_" + word, "name": "Bash", "input": map[string]any{"command": "grep -r " + word + " ."}}}}})
}

// writeSession writes a transcript under the projects dir and sets its
// mtime (old enough not to count as live unless the test says so).
func writeSession(t testing.TB, p paths.Paths, cwd, id, content string, mtime time.Time) string {
	t.Helper()
	d := filepath.Join(p.ClaudeProjectsDir(), transcript.EscapeProjectDir(cwd))
	if err := os.MkdirAll(d, 0o700); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(d, id+".jsonl")
	if err := os.WriteFile(f, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(f, mtime, mtime); err != nil {
		t.Fatal(err)
	}
	return f
}

// ageTree sets every file's mtime under dir to at.
func ageTree(t testing.TB, dir string, at time.Time) {
	t.Helper()
	filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			os.Chtimes(p, at, at)
		}
		return nil
	})
}

func newFixture(t *testing.T) (root, home string, p paths.Paths) {
	t.Helper()
	root = t.TempDir()
	home = filepath.Join(root, "home")
	p = paths.Resolve(home, map[string]string{
		"XDG_CONFIG_HOME": filepath.Join(root, "cfg"),
		"XDG_CACHE_HOME":  filepath.Join(root, "cache"),
		"XDG_STATE_HOME":  filepath.Join(root, "state"),
	})
	projects := p.ClaudeProjectsDir()
	copyTree(t, repoPath(t, "internal", "transcript", "testdata", "e2e-canary", "projects"), projects)
	copyTree(t, repoPath(t, "internal", "transcript", "testdata", "synthetic-subagents", "projects"), projects)
	old := time.Now().Add(-48 * time.Hour)
	ageTree(t, projects, old)

	b, err := os.ReadFile(repoPath(t, "internal", "mapmodel", "testdata", "activity-a.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	b = bytes.ReplaceAll(b, []byte(homeTag), []byte(projects))
	if err := os.MkdirAll(filepath.Dir(p.Activity), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.Activity, b, 0o600); err != nil {
		t.Fatal(err)
	}

	alpha := filepath.Join(home, "work", "alpha")
	if err := os.MkdirAll(alpha, 0o700); err != nil {
		t.Fatal(err)
	}
	tp := writeSession(t, p, alpha, sidAlpha, synthSession(sidAlpha, alpha, "alphaword", time.Now().Add(-2*time.Hour)), time.Now().Add(-2*time.Hour))

	st := lifecycle.Store{Log: p.Sessions, Live: p.LiveDir}
	if _, err := st.Start(sidAlpha, tp, alpha, "startup"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Start(sidB, "", cwdB, "startup"); err != nil {
		t.Fatal(err)
	}
	if err := st.End(sidB, "", cwdB, "other"); err != nil {
		t.Fatal(err)
	}
	return root, home, p
}

func newEnv(t *testing.T, o envOpts) *env {
	t.Helper()
	root, home, p := newFixture(t)
	return serve(t, root, home, p, o)
}

func serve(t *testing.T, root, home string, p paths.Paths, o envOpts) *env {
	t.Helper()
	e := &env{root: root, home: home, paths: p, alphaCwd: filepath.Join(home, "work", "alpha")}
	e.cat = New(Options{Paths: p, NoTranscripts: o.noTranscripts})
	routes := mapapi.Routes(mapapi.Deps{Paths: p, Cwd: o.cwd, Version: "test", NoTranscripts: o.noTranscripts, ProjectRoots: e.cat.ProjectRoots})
	delete(routes, mapapi.PatternSessions)
	for k, v := range e.cat.Routes() {
		routes[k] = v
	}
	// Leak watch is wired as cmd/watchdeck/ui.go wires it: nil without transcripts.
	var leaks func(time.Time) []rulebook.Leak
	if !o.noTranscripts {
		leaks = e.cat.Leaks
	}
	srv, err := ui.New(ui.Options{Paths: p, Cwd: o.cwd, Version: "test", NoTranscripts: o.noTranscripts,
		Routes: routes, Events: e.cat, EventsKeepalive: o.keepalive, ProjectRoots: e.cat.ProjectRoots, Leaks: leaks})
	if err != nil {
		t.Fatal(err)
	}
	e.srv = srv
	ln, err := ui.Listen(0)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		e.cat.Close()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("Serve did not return")
		}
	})
	e.base = "http://127.0.0.1:" + strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	e.tok = srv.Token()
	for i := 0; ; i++ {
		resp, _ := e.get(t, "/api/status")
		if resp.StatusCode == 200 {
			break
		}
		if i > 200 {
			t.Fatalf("server not serving: %d", resp.StatusCode)
		}
		time.Sleep(5 * time.Millisecond)
	}
	return e
}

func (e *env) request(t testing.TB, path string, hdr map[string]string) *http.Response {
	t.Helper()
	r, err := http.NewRequest(http.MethodGet, e.base+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range hdr {
		if k == "Host" {
			r.Host = v // the client sends r.Host, never a Host header
			continue
		}
		r.Header.Set(k, v)
	}
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(r)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func (e *env) getH(t testing.TB, path string, hdr map[string]string) (*http.Response, []byte) {
	t.Helper()
	resp := e.request(t, path, hdr)
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, b
}

func (e *env) get(t testing.TB, path string) (*http.Response, []byte) {
	return e.getH(t, path, map[string]string{"Authorization": "Bearer " + e.tok})
}

func (e *env) getJSON(t testing.TB, path string, v any) {
	t.Helper()
	resp, b := e.get(t, path)
	if resp.StatusCode != 200 {
		t.Fatalf("GET %s = %d %s", path, resp.StatusCode, b)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("GET %s: %v: %s", path, err, b)
	}
}

type listResp struct {
	Sessions       []Row  `json:"sessions"`
	NextCursor     string `json:"next_cursor"`
	Total          int    `json:"total"`
	Transcripts    bool   `json:"transcripts"`
	SearchDisabled bool   `json:"search_disabled"`
}

func (e *env) list(t testing.TB, query string) listResp {
	t.Helper()
	var l listResp
	e.getJSON(t, "/api/sessions"+query, &l)
	return l
}

func ids(rows []Row) []string {
	out := make([]string, len(rows))
	for i := range rows {
		out[i] = rows[i].ID
	}
	return out
}

// stream opens GET /api/events with the bearer and returns a line reader.
type stream struct {
	resp *http.Response
	rd   *bufio.Reader
}

func (e *env) openStream(t testing.TB) *stream {
	t.Helper()
	r, err := http.NewRequest(http.MethodGet, e.base+"/api/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Authorization", "Bearer "+e.tok)
	resp, err := (&http.Client{}).Do(r)
	if err != nil {
		t.Fatal(err)
	}
	return &stream{resp: resp, rd: bufio.NewReader(resp.Body)}
}

// next returns the next frame's event name and data ("" name for a
// comment), failing after d.
func (s *stream) next(t testing.TB, d time.Duration) (string, string) {
	t.Helper()
	type res struct {
		name, data string
		err        error
	}
	ch := make(chan res, 1)
	go func() {
		var name, data string
		for {
			line, err := s.rd.ReadString('\n')
			if err != nil {
				ch <- res{err: err}
				return
			}
			line = strings.TrimRight(line, "\n")
			switch {
			case line == "":
				ch <- res{name: name, data: data}
				return
			case strings.HasPrefix(line, ":"):
				name, data = "", strings.TrimSpace(line[1:])
			case strings.HasPrefix(line, "event: "):
				name = line[len("event: "):]
			case strings.HasPrefix(line, "data: "):
				data = line[len("data: "):]
			}
		}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("stream: %v", r.err)
		}
		return r.name, r.data
	case <-time.After(d):
		t.Fatalf("no frame within %v", d)
	}
	return "", ""
}

// until reads frames until one named name arrives (skipping others).
func (s *stream) until(t testing.TB, name string, d time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		n, data := s.next(t, time.Until(deadline))
		if n == name {
			return data
		}
	}
	t.Fatalf("no %q event within %v", name, d)
	return ""
}

func appendAct(t testing.TB, p paths.Paths, r activity.Record) {
	t.Helper()
	if err := activity.Append(p.Activity, r); err != nil {
		t.Fatal(err)
	}
}

func waitFor(t testing.TB, what string, cond func() bool) {
	t.Helper()
	for i := 0; i < 400; i++ {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}
