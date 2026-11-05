package ui

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/hook"
	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
	"github.com/Panda-Taps-LLC/watchdeck/internal/rulebook"
)

// POST /api/rules/try (Plan 08 Task 4, D12, R15): hook.Explain over the
// saved rules for one call the person types, answered as the document
// `rules explain --json` prints, plus project_scope.

// tryFx is a temp home with the hook tests' fixture skills (pdf without a
// manifest, web asking for network, bad with an invalid one), a git
// project the server knows, a user policy that turns the destructive pack
// to deny, and a Claude Code user settings file.
type tryFx struct {
	o          Options
	home, proj string
}

func newTryFx(t *testing.T) tryFx {
	t.Helper()
	home := filepath.Join(t.TempDir(), "home")
	write := func(p, content string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(home, ".claude/skills/pdf/SKILL.md"), "---\nname: pdf\ndescription: p\n---\n")
	write(filepath.Join(home, ".claude/skills/pdf/scripts/fill.py"), "print(1)\n")
	write(filepath.Join(home, ".claude/skills/web/SKILL.md"), "---\nname: web\ndescription: w\n---\n")
	write(filepath.Join(home, ".claude/skills/web/scripts/get.py"), "print(1)\n")
	write(filepath.Join(home, ".claude/skills/web/PERMISSIONS.yaml"), "version: 1\nnetwork: all\n")
	write(filepath.Join(home, ".claude/skills/bad/SKILL.md"), "---\nname: bad\ndescription: b\n---\n")
	write(filepath.Join(home, ".claude/skills/bad/scripts/x.py"), "print(1)\n")
	write(filepath.Join(home, ".claude/skills/bad/PERMISSIONS.yaml"), "version: 1\nnope: 1\n")
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(filepath.Join(proj, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	write(filepath.Join(proj, ".claude", "settings.json"), `{"permissions":{"ask":["Bash(git push:*)"]}}`)
	p := tempPaths(t, home)
	write(p.OverridesFile(), "version: 2\npacks: {destructive: {action: deny}}\n")
	write(p.ClaudeSettings(), `{"permissions":{"deny":["Bash(curl *)"]}}`)
	o := Options{Paths: p, Cwd: home, Version: "test", Environ: map[string]string{"HOME": home, "CLAUDE_PROJECT_DIR": filepath.Join(home, "elsewhere")},
		ProjectRoots: func() []string { return []string{proj} }}
	return tryFx{o: o, home: home, proj: proj}
}

func postTry(t *testing.T, ts *testServer, query, body string) (int, []byte) {
	t.Helper()
	resp, b := ts.do(t, req{Method: "POST", Path: "/api/rules/try" + query, Body: body, Origin: "auto", Token: ts.s.Token(), Header: jsonCT()})
	return resp.StatusCode, b
}

// directDoc is hook.BuildDoc of a direct hook.Explain of the call the try
// route builds, over the same files, as generic JSON.
func directDoc(t *testing.T, f tryFx, tool, key, value, cwd, mode string) map[string]any {
	t.Helper()
	in := hook.Input{HookEventName: "PreToolUse", SessionID: "try", ToolUseID: "toolu_try", Cwd: cwd, PermissionMode: mode, ToolName: tool, ToolInput: map[string]any{}}
	if key != "" {
		in.ToolInput[key] = value
	}
	p := f.o.Paths
	env := hook.Env{Home: p.Home, CacheDir: p.CacheBase, UserCfgDir: p.ConfigDir, StateDir: p.StateDir, Environ: map[string]string{"HOME": f.home}}
	out, ex := hook.Explain(in, env)
	b, err := json.Marshal(hook.BuildDoc(in, out, ex))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	decode(t, b, &m)
	return m
}

func TestTryVerdicts(t *testing.T) {
	f := newTryFx(t)
	ts := startServer(t, f.o)
	fill := filepath.Join(f.home, ".claude", "skills", "pdf", "scripts", "fill.py")
	cases := []struct {
		name, query, body       string
		tool, key, value, mode  string
		verdict, reason, rewrit string
		projectScope            bool
	}{
		{"command deny by pack", "", `{"what":"command","value":"rm -rf ~"}`, "Bash", "command", "rm -rf ~", "default", "deny", "rm-root-or-home", "", false},
		{"read none", "", `{"what":"read","value":"/tmp/notes.txt"}`, "Read", "file_path", "/tmp/notes.txt", "default", "none", "", "", false},
		{"skill rewrite ask", "", `{"what":"command","value":` + jsonStr(t, "python3 "+fill) + `,"mode":"auto"}`, "Bash", "command", "python3 " + fill, "auto", "ask", "pdf has no PERMISSIONS.yaml", paths.BinaryName + " run --skill pdf -c ", false},
		{"project scope", "?project=" + f.proj, `{"what":"command","value":"git push origin main"}`, "Bash", "command", "git push origin main", "default", "none", "", "", true},
		{"mcp", "", `{"what":"mcp","value":"mcp__github__delete_repo"}`, "mcp__github__delete_repo", "", "", "default", "none", "", "", false},
		{"skill", "", `{"what":"skill","value":"pdf"}`, "Skill", "skill", "pdf", "default", "", "", "", false},
		{"edit", "", `{"what":"edit","value":"~/.zshrc"}`, "Edit", "file_path", "~/.zshrc", "default", "", "", "", false},
		{"write", "", `{"what":"write","value":"/etc/hosts"}`, "Write", "file_path", "/etc/hosts", "default", "", "", "", false},
		{"url", "", `{"what":"url","value":"https://example.invalid/"}`, "WebFetch", "url", "https://example.invalid/", "default", "", "", "", false},
	}
	for _, c := range cases {
		code, b := postTry(t, ts, c.query, c.body)
		if code != 200 {
			t.Fatalf("%s: %d %s", c.name, code, b)
		}
		var got map[string]any
		decode(t, b, &got)
		if got["project_scope"] != c.projectScope {
			t.Errorf("%s: project_scope %v, want %v", c.name, got["project_scope"], c.projectScope)
		}
		delete(got, "project_scope")
		cwd := ""
		if c.projectScope {
			cwd = f.proj
		}
		want := directDoc(t, f, c.tool, c.key, c.value, cwd, c.mode)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: the try document is not BuildDoc of Explain\n got %s\nwant %v", c.name, b, want)
		}
		if c.verdict != "" && got["verdict"] != c.verdict {
			t.Errorf("%s: verdict %v, want %s (%s)", c.name, got["verdict"], c.verdict, b)
		}
		if !strings.Contains(got["reason"].(string), c.reason) || !strings.HasPrefix(got["rewritten"].(string), c.rewrit) {
			t.Errorf("%s: reason or rewrite: %s", c.name, b)
		}
		if got["cwd"] != cwd || got["mode"] != c.mode {
			t.Errorf("%s: cwd %v mode %v", c.name, got["cwd"], got["mode"])
		}
	}
	// the deny names its pack rule
	_, b := postTry(t, ts, "", `{"what":"command","value":"rm -rf ~"}`)
	var doc hook.Doc
	decode(t, b, &doc)
	if len(doc.Rules) == 0 || hook.RuleID(doc.Rules[0]) != "pack:destructive/rm-root-or-home" {
		t.Errorf("deny rules: %s", b)
	}

	// an invalid policy file is the hook's answer, not a server error
	if err := os.WriteFile(f.o.Paths.OverridesFile(), []byte("version: 9\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, b := postTry(t, ts, "", `{"what":"command","value":"git status"}`)
	decode(t, b, &doc)
	if code != 200 || doc.Verdict != "ask" || !strings.Contains(doc.Reason, "your policy file is invalid") || strings.Contains(string(b), "version: 9") {
		t.Errorf("invalid policy: %d %s", code, b)
	}
}

// TestTryWritesNothing: after every kind of try, the activity log, the
// sessions log and the inbox do not exist, and the policy and settings
// files keep their bytes and mtime (Review Focus 4).
func TestTryWritesNothing(t *testing.T) {
	f := newTryFx(t)
	p := f.o.Paths
	if p.Activity == "" || p.Sessions == "" {
		t.Fatal("the fixture has the log off; the test proves nothing")
	}
	// a project policy file too, so its mtime is watched
	projectPolicy := filepath.Join(f.proj, ".watchdeck.yaml")
	if err := os.WriteFile(projectPolicy, []byte("version: 2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	watched := []string{p.OverridesFile(), p.ClaudeSettings(), paths.ProjectSettings(f.proj), projectPolicy}
	stamp := func(path string) string {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := os.ReadFile(path)
		return fi.ModTime().String() + " " + string(b)
	}
	before := map[string]string{}
	for _, w := range watched {
		before[w] = stamp(w)
	}
	ts := startServer(t, f.o)
	fill := filepath.Join(f.home, ".claude", "skills", "pdf", "scripts", "fill.py")
	for _, q := range []string{"", "?project=" + f.proj} {
		for _, body := range []string{
			`{"what":"command","value":"rm -rf ~"}`,
			`{"what":"command","value":` + jsonStr(t, "python3 "+fill) + `}`,
			`{"what":"command","value":` + jsonStr(t, "python3 "+fill+" && curl https://example.invalid") + `}`,
			`{"what":"command","value":"git status"}`,
			`{"what":"read","value":"~/.ssh/id_ed25519"}`,
			`{"what":"edit","value":"~/.zshrc"}`,
			`{"what":"write","value":"/etc/hosts"}`,
			`{"what":"url","value":"https://example.invalid/"}`,
			`{"what":"mcp","value":"mcp__github__delete_repo"}`,
			`{"what":"skill","value":"pdf"}`,
			`{"what":"command","value":"rm -rf ~","mode":"bypassPermissions"}`,
		} {
			if code, b := postTry(t, ts, q, body); code != 200 {
				t.Fatalf("%s%s: %d %s", q, body, code, b)
			}
		}
	}
	for _, path := range []string{p.Activity, p.Sessions, p.LiveDir, filepath.Join(p.StateDir, rulebook.InboxFile)} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("%s exists after try (err %v)", path, err)
		}
	}
	for _, w := range watched {
		if got := stamp(w); got != before[w] {
			t.Errorf("%s changed: %q, was %q", w, got, before[w])
		}
	}
}

// startServerWith is startServer with the Server changed before it
// serves (a field a handler reads must be set before any request).
func startServerWith(t *testing.T, o Options, change func(*Server)) *testServer {
	t.Helper()
	s, err := New(o)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	change(s)
	ln, err := Listen(0)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	ts := &testServer{s: s, cancel: cancel, done: make(chan error, 1)}
	ts.port = strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	ts.base = "http://127.0.0.1:" + ts.port
	go func() { ts.done <- s.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-ts.done:
		case <-time.After(10 * time.Second):
			t.Error("Serve did not return after cancel")
		}
	})
	waitServing(t, ts)
	return ts
}

// TestTryDeadline: an Explain that does not return within 3 s answers 503
// with the hook's own slow reason, and a second request that cannot get
// the mutex within its own 3 s gets the same 503 without a second Explain
// (R15).
func TestTryDeadline(t *testing.T) {
	f := newTryFx(t)
	release := make(chan struct{})
	var calls atomic.Int32
	ts := startServerWith(t, f.o, func(s *Server) {
		s.explain = func(in hook.Input, env hook.Env) (*hook.Output, hook.Explanation) {
			calls.Add(1)
			<-release
			return nil, hook.Explanation{Verdict: "none"}
		}
	})
	t.Cleanup(func() { close(release) }) // runs before the server stops
	type result struct {
		code int
		body []byte
		took time.Duration
		err  error
	}
	second := make(chan result, 1)
	start := time.Now()
	// The second request runs in its own goroutine, so it reports through
	// the channel instead of ts.do (whose t.Fatal must not run off the
	// test goroutine).
	go func() {
		time.Sleep(200 * time.Millisecond)
		r, err := http.NewRequest("POST", ts.base+"/api/rules/try", strings.NewReader(`{"what":"command","value":"git status"}`))
		if err != nil {
			second <- result{err: err}
			return
		}
		r.Header.Set("Origin", "http://127.0.0.1:"+ts.port)
		r.Header.Set("Authorization", "Bearer "+ts.s.Token())
		r.Header.Set("Content-Type", "application/json")
		t0 := time.Now()
		resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(r)
		if err != nil {
			second <- result{err: err}
			return
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		second <- result{resp.StatusCode, b, time.Since(t0), err}
	}()
	code, b := postTry(t, ts, "", `{"what":"command","value":"git status"}`)
	took := time.Since(start)
	if code != 503 || errorBody(t, b) != hook.SlowReason || took < 2900*time.Millisecond || took > 3500*time.Millisecond {
		t.Fatalf("first: %d %s after %v", code, b, took)
	}
	r := <-second
	if r.err != nil {
		t.Fatalf("second: %v", r.err)
	}
	if r.code != 503 || errorBody(t, r.body) != hook.SlowReason || r.took < 2900*time.Millisecond || r.took > 3500*time.Millisecond {
		t.Fatalf("second: %d %s after %v", r.code, r.body, r.took)
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("explain ran %d times, want 1 (the second request never held the mutex)", n)
	}
}

func TestTryRejectsUnknownWhat(t *testing.T) {
	f := newTryFx(t)
	ts := startServer(t, f.o)
	for _, body := range []string{
		`{"what":"bash","value":"git status"}`,
		`{"what":"","value":"git status"}`,
		`{"what":"path","value":"/etc/hosts"}`, // the CLI's flag name, not the route's
		`{"what":"command","value":""}`,
		`{"what":"command","value":"git status","mode":"loud"}`,
		`{"what":"command","value":"git status","nonce":"x"}`, // unknown field
		`{"what":"command"`,
		`{"what":"mcp","value":"Bash"}`,       // not an MCP tool name
		`{"what":"mcp","value":"mcp__"}`,      // no server
		`{"what":"mcp","value":"mcp__srv__"}`, // an empty tool after the server
	} {
		code, b := postTry(t, ts, "", body)
		if code != 400 {
			t.Errorf("%s: %d %s", body, code, b)
		}
	}
	if code, b := postTry(t, ts, "?project=/nowhere", `{"what":"command","value":"git status"}`); code != 400 {
		t.Errorf("unknown project: %d %s", code, b)
	}
}

// TestTryNoNonceButSameOrigin: the route takes no nonce (it writes
// nothing), but the guard's checks for a POST still apply.
func TestTryNoNonceButSameOrigin(t *testing.T) {
	f := newTryFx(t)
	ts := startServer(t, f.o)
	body := `{"what":"command","value":"git status"}`
	for _, c := range []struct {
		name   string
		origin string
		token  string
		header map[string]string
		want   int
	}{
		{"same origin, no nonce", "auto", ts.s.Token(), jsonCT(), 200},
		{"no origin", "", ts.s.Token(), jsonCT(), 403},
		{"foreign origin", "http://evil.example", ts.s.Token(), jsonCT(), 403},
		{"cross-site fetch", "auto", ts.s.Token(), map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "cross-site"}, 403},
		{"no token", "auto", "", jsonCT(), 401},
	} {
		resp, b := ts.do(t, req{Method: "POST", Path: "/api/rules/try", Body: body, Origin: c.origin, Token: c.token, Header: c.header})
		if resp.StatusCode != c.want {
			t.Errorf("%s: %d %s, want %d", c.name, resp.StatusCode, b, c.want)
		}
	}
}
