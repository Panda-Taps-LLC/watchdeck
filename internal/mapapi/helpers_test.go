package mapapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
	"github.com/Panda-Taps-LLC/watchdeck/internal/transcript"
	"github.com/Panda-Taps-LLC/watchdeck/internal/ui"
)

// Fixture A (internal/transcript/testdata/e2e-canary): one session with a
// main agent, one Explore subagent, and the activity log of
// internal/mapmodel/testdata/activity-a.jsonl (ids from its hook-stdin.jsonl).
const (
	sidA     = "a9896c55-0b77-4f85-a0e0-9be2948b8aa6"
	agentA   = "a3033ade8c1d9c1a5"
	projA    = "-Users-you-proj"
	cwdA     = "/Users/you/proj" // the fixture's recorded cwd: a display value, not a real dir
	homeTag  = "/Users/you/.claude/projects"
	fixtureA = "e2e-canary"
)

// env is a temp HOME with fixture A under .claude/projects, the canaries
// under .claude/skills, the activity log under the XDG state dir, and a
// real dashboard server (ui.Listen(0) + Serve) carrying this package's
// routes. Nothing reads the developer's home.
type env struct {
	root, home string
	paths      paths.Paths
	api        *api
	loads      atomic.Int32 // transcript.Load calls
	base, tok  string
}

type envOpt func(*Deps)

func noTranscripts(d *Deps) { d.NoTranscripts = true }

func newEnv(t *testing.T, opts ...envOpt) *env {
	t.Helper()
	root := t.TempDir()
	e := &env{root: root, home: filepath.Join(root, "home")}
	copyTree(t, fromRepo(t, "internal", "transcript", "testdata", fixtureA, "projects"), filepath.Join(e.home, ".claude", "projects"))
	for _, c := range []string{"canary-basic", "canary-request"} {
		copyTree(t, fromRepo(t, "testdata", "skills", c), filepath.Join(e.home, ".claude", "skills", c))
	}
	e.paths = paths.Resolve(e.home, map[string]string{
		"XDG_CONFIG_HOME": filepath.Join(root, "cfg"),
		"XDG_CACHE_HOME":  filepath.Join(root, "cache"),
		"XDG_STATE_HOME":  filepath.Join(root, "state"),
	})
	b, err := os.ReadFile(fromRepo(t, "internal", "mapmodel", "testdata", "activity-a.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	b = bytes.ReplaceAll(b, []byte(homeTag), []byte(e.paths.ClaudeProjectsDir()))
	if err := os.MkdirAll(filepath.Dir(e.paths.Activity), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(e.paths.Activity, b, 0o600); err != nil {
		t.Fatal(err)
	}

	d := Deps{Paths: e.paths, Cwd: cwdA, Version: "test",
		// An hour ahead: nothing is live, so the liveness bit never flips mid-test.
		Now: func() time.Time { return time.Now().Add(time.Hour) }}
	for _, o := range opts {
		o(&d)
	}
	e.api = newAPI(d)
	e.api.load = func(p string, o transcript.Options) (*transcript.Session, error) {
		e.loads.Add(1)
		return transcript.Load(p, o)
	}

	srv, err := ui.New(ui.Options{Paths: e.paths, Cwd: cwdA, Version: "test", Idle: 30 * time.Minute,
		NoTranscripts: d.NoTranscripts, Routes: e.api.routes()})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := ui.Listen(0)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("Serve did not return")
		}
	})
	e.base = "http://127.0.0.1:" + strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	e.tok = srv.Token()
	// Serve records the port before answering; wait until it does.
	for i := 0; ; i++ {
		resp, _ := e.get(t, "/api/status", nil)
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

func fromRepo(t *testing.T, parts ...string) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join(append([]string{"..", ".."}, parts...)...))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// do sends one request; token "" means e.tok, "-" means none.
func (e *env) do(t *testing.T, method, path, token, body string, hdr map[string]string) (*http.Response, []byte) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r, err := http.NewRequest(method, e.base+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	switch token {
	case "":
		r.Header.Set("Authorization", "Bearer "+e.tok)
	case "-":
	default:
		r.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

func (e *env) get(t *testing.T, path string, hdr map[string]string) (*http.Response, []byte) {
	t.Helper()
	return e.do(t, http.MethodGet, path, "", "", hdr)
}

func mapPath(id, view string, hide bool) string {
	h := "0"
	if hide {
		h = "1"
	}
	return "/api/sessions/" + id + "/map?view=" + view + "&hide_none=" + h
}

// graph is the subset of mapmodel.Graph the tests read.
type graph struct {
	Session struct {
		ID                string `json:"id"`
		Cwd               string `json:"cwd"`
		NoTranscripts     bool   `json:"no_transcripts"`
		TranscriptMissing bool   `json:"transcript_missing"`
		TranscriptPath    string `json:"transcript_path"`
	} `json:"session"`
	Nodes []struct {
		ID     string          `json:"id"`
		Kind   string          `json:"kind"`
		Count  int             `json:"count"`
		Detail json.RawMessage `json:"detail"`
	} `json:"nodes"`
	Edges []struct {
		ID  string          `json:"id"`
		Cut json.RawMessage `json:"cut"`
	} `json:"edges"`
	ETag string `json:"etag"`
}

func decodeGraph(t *testing.T, b []byte) graph {
	t.Helper()
	var g graph
	if err := json.Unmarshal(b, &g); err != nil {
		t.Fatalf("graph: %v: %.300s", err, b)
	}
	return g
}

func (g graph) has(id string) bool {
	for _, n := range g.Nodes {
		if n.ID == id {
			return true
		}
	}
	return false
}

// fix is the skill card's fix string ("" when absent).
func (g graph) fix(t *testing.T, skill string) string {
	t.Helper()
	for _, n := range g.Nodes {
		if n.ID == "skill:"+skill {
			var d struct {
				Fix string `json:"fix"`
			}
			if err := json.Unmarshal(n.Detail, &d); err != nil {
				t.Fatal(err)
			}
			return d.Fix
		}
	}
	t.Fatalf("no node skill:%s", skill)
	return ""
}

// mapOK fetches a map and fails unless it is 200 with a matching ETag.
func (e *env) mapOK(t *testing.T, id, view string, hide bool) (graph, string) {
	t.Helper()
	resp, b := e.get(t, mapPath(id, view, hide), nil)
	if resp.StatusCode != 200 {
		t.Fatalf("map %s = %d %s", id, resp.StatusCode, b)
	}
	g := decodeGraph(t, b)
	tag := resp.Header.Get("ETag")
	if tag == "" || tag != `"`+g.ETag+`"` || len(g.ETag) != 16 {
		t.Fatalf("ETag header %q, body etag %q", tag, g.ETag)
	}
	return g, tag
}

func appendFile(t *testing.T, path, line string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(line + "\n"); err != nil {
		t.Fatal(err)
	}
}

// transcriptA is fixture A's main transcript under the temp HOME.
func (e *env) transcriptA() string {
	return filepath.Join(e.paths.ClaudeProjectsDir(), projA, sidA+".jsonl")
}

func (e *env) subagentA() string {
	return filepath.Join(e.paths.ClaudeProjectsDir(), projA, sidA, "subagents", "agent-"+agentA+".jsonl")
}
