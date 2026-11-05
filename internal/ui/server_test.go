package ui

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
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
)

// Tests bind 127.0.0.1:0 with Listen and run Serve in a goroutine; no
// httptest server, no browser, never a non-loopback address. Every HOME and
// XDG dir is under t.TempDir().

// testServer is a running Server and how to reach it.
type testServer struct {
	s      *Server
	port   string
	base   string // http://127.0.0.1:<port>
	cancel context.CancelFunc
	done   chan error
}

// startServer builds a Server from o, serves it on an ephemeral loopback
// port and stops it when the test ends.
func startServer(t *testing.T, o Options) *testServer {
	t.Helper()
	s, err := New(o)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
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

// waitServing polls until Serve has recorded the port (requests 403 before).
func waitServing(t *testing.T, ts *testServer) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if ts.s.port.Load() != 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("server never started")
}

// req is one test request. Host overrides the Host header; Token "" sends
// no Authorization; Origin "auto" sends the matching origin.
type req struct {
	Method, Path, Body string
	Host, Origin       string
	Token              string
	Header             map[string]string
}

func (ts *testServer) do(t *testing.T, q req) (*http.Response, []byte) {
	t.Helper()
	if q.Method == "" {
		q.Method = http.MethodGet
	}
	var body io.Reader
	if q.Body != "" {
		body = strings.NewReader(q.Body)
	}
	r, err := http.NewRequest(q.Method, ts.base+q.Path, body)
	if err != nil {
		t.Fatal(err)
	}
	if q.Host != "" {
		r.Host = q.Host
	}
	switch q.Origin {
	case "":
	case "auto":
		r.Header.Set("Origin", "http://"+r.Host)
		if r.Host == "" {
			r.Header.Set("Origin", "http://127.0.0.1:"+ts.port)
		}
	default:
		r.Header.Set("Origin", q.Origin)
	}
	if q.Token != "" {
		r.Header.Set("Authorization", "Bearer "+q.Token)
	}
	for k, v := range q.Header {
		r.Header.Set(k, v)
	}
	c := &http.Client{Timeout: 30 * time.Second}
	resp, err := c.Do(r)
	if err != nil {
		t.Fatalf("%s %s: %v", q.Method, q.Path, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, b
}

// emptyOptions is a server over an empty temp home (no skills).
func emptyOptions(t *testing.T) Options {
	t.Helper()
	home := filepath.Join(t.TempDir(), "home")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	return Options{Paths: tempPaths(t, home), Cwd: home, Version: "test"}
}

// tempPaths resolves paths for home with every XDG dir under t.TempDir().
func tempPaths(t *testing.T, home string) paths.Paths {
	t.Helper()
	tmp := t.TempDir()
	return paths.Resolve(home, map[string]string{
		"XDG_CONFIG_HOME": filepath.Join(tmp, "cfg"),
		"XDG_CACHE_HOME":  filepath.Join(tmp, "cache"),
		"XDG_STATE_HOME":  filepath.Join(tmp, "state"),
	})
}

func errorBody(t *testing.T, b []byte) string {
	t.Helper()
	var e struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(b, &e); err != nil {
		t.Fatalf("error body is not JSON: %q", b)
	}
	return e.Error
}

func TestListenLoopbackOnly(t *testing.T) {
	ln, err := Listen(0)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	addr, ok := ln.Addr().(*net.TCPAddr)
	if !ok || addr.IP.String() != "127.0.0.1" || addr.IP.To4() == nil || addr.Port == 0 {
		t.Fatalf("Listen(0) bound %v, want 127.0.0.1:<ephemeral>", ln.Addr())
	}
	if ln.Addr().Network() != "tcp" {
		t.Fatalf("network %q", ln.Addr().Network())
	}
	for _, p := range []int{-1, 65536} {
		if l, err := Listen(p); err == nil {
			l.Close()
			t.Errorf("Listen(%d) succeeded", p)
		}
	}

	// Serve refuses a listener that is not on loopback, before accepting.
	s, err := New(emptyOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeListener{addr: &net.TCPAddr{IP: net.IPv4zero, Port: 8080}}
	if err := s.Serve(context.Background(), fake); err == nil {
		t.Fatal("Serve accepted a 0.0.0.0 listener")
	}
	if fake.accepted.Load() {
		t.Fatal("Serve called Accept on a non-loopback listener")
	}
}

type fakeListener struct {
	addr     net.Addr
	accepted atomic.Bool
}

func (f *fakeListener) Accept() (net.Conn, error) {
	f.accepted.Store(true)
	return nil, errors.New("fake")
}
func (f *fakeListener) Close() error   { return nil }
func (f *fakeListener) Addr() net.Addr { return f.addr }

func TestStaticServedWithCSP(t *testing.T) {
	ts := startServer(t, emptyOptions(t))
	resp, body := ts.do(t, req{Path: "/"})
	if resp.StatusCode != 200 {
		t.Fatalf("GET / = %d", resp.StatusCode)
	}
	want := map[string]string{
		"Content-Security-Policy":      "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
		"X-Content-Type-Options":       "nosniff",
		"Referrer-Policy":              "no-referrer",
		"Cache-Control":                "no-store",
		"X-Frame-Options":              "DENY",
		"Cross-Origin-Opener-Policy":   "same-origin",
		"Cross-Origin-Resource-Policy": "same-origin",
		"Content-Type":                 "text/html; charset=utf-8",
	}
	for k, v := range want {
		if got := resp.Header.Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	index, err := fs.ReadFile(StaticFS, "static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, index) {
		t.Error("GET / did not serve static/index.html")
	}

	for path, ct := range map[string]string{
		"/app.js":       "text/javascript; charset=utf-8",
		"/app.css":      "text/css; charset=utf-8",
		"/pages.js":     "text/javascript; charset=utf-8",
		"/copy.js":      "text/javascript; charset=utf-8",
		"/home.css":     "text/css; charset=utf-8",
		"/pages.css":    "text/css; charset=utf-8",
		"/sessions.css": "text/css; charset=utf-8",
		"/index.html":   "text/html; charset=utf-8",
	} {
		resp, _ := ts.do(t, req{Path: path})
		if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != ct {
			t.Errorf("GET %s = %d %q, want 200 %q", path, resp.StatusCode, resp.Header.Get("Content-Type"), ct)
		}
		if resp.Header.Get("Content-Security-Policy") == "" {
			t.Errorf("GET %s: no CSP", path)
		}
	}

	// HEAD carries the headers and no body.
	resp, body = ts.do(t, req{Method: "HEAD", Path: "/app.js"})
	if resp.StatusCode != 200 || len(body) != 0 || resp.Header.Get("Content-Type") != "text/javascript; charset=utf-8" {
		t.Errorf("HEAD /app.js = %d, %d bytes, %q", resp.StatusCode, len(body), resp.Header.Get("Content-Type"))
	}

	// Misses, directories (including the font directory that left on
	// 2026-10-28) and traversal are 404 JSON, still with CSP.
	for _, p := range []string{"/nope.js", "/fonts", "/fonts/", "/../go.mod", "/static/index.html"} {
		resp, b := ts.do(t, req{Path: p})
		if resp.StatusCode != 404 || resp.Header.Get("Content-Security-Policy") == "" {
			t.Errorf("GET %s = %d (CSP %q), want 404", p, resp.StatusCode, resp.Header.Get("Content-Security-Policy"))
			continue
		}
		errorBody(t, b)
	}
}

func TestRoutesMustBeUnderAPI(t *testing.T) {
	ok := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	bad := map[string]map[string]http.Handler{
		"outside /api/":       {"GET /x": ok},
		"static path":         {"GET /app.js": ok},
		"no method":           {"/api/x": ok},
		"bare prefix":         {"GET /api/": ok},
		"api without slash":   {"GET /api": ok},
		"host pattern":        {"GET example.com/api/x": ok},
		"nil handler":         {"GET /api/x": nil},
		"conflicts with core": {"GET /api/status": ok},
	}
	for name, routes := range bad {
		o := emptyOptions(t)
		o.Routes = routes
		if _, err := New(o); err == nil {
			t.Errorf("%s: New accepted %v", name, routes)
		}
	}
	o := emptyOptions(t)
	o.Routes = map[string]http.Handler{"GET /api/sessions/{id}/map": ok, "POST /api/sessions": ok}
	if _, err := New(o); err != nil {
		t.Fatalf("valid routes rejected: %v", err)
	}
}

func TestExtraRouteIsGuarded(t *testing.T) {
	o := emptyOptions(t)
	o.Routes = map[string]http.Handler{
		"GET /api/sessions/{id}/map": http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, 200, map[string]string{"id": r.PathValue("id")})
		}),
	}
	ts := startServer(t, o)
	tok := ts.s.Token()

	resp, b := ts.do(t, req{Path: "/api/sessions/abc/map"})
	if resp.StatusCode != 401 || errorBody(t, b) != "unauthorized" {
		t.Fatalf("no token: %d %s", resp.StatusCode, b)
	}
	if resp.Header.Get("Content-Security-Policy") == "" {
		t.Error("401 without security headers")
	}
	resp, b = ts.do(t, req{Path: "/api/sessions/abc/map", Token: tok, Host: "evil.example:" + ts.port})
	if resp.StatusCode != 403 {
		t.Fatalf("foreign Host: %d %s", resp.StatusCode, b)
	}
	resp, b = ts.do(t, req{Path: "/api/sessions/abc/map", Token: tok})
	if resp.StatusCode != 200 || !strings.Contains(string(b), `"id":"abc"`) {
		t.Fatalf("with token: %d %s", resp.StatusCode, b)
	}
	// A method the route does not take is 405 JSON with Allow.
	resp, b = ts.do(t, req{Method: "POST", Path: "/api/sessions/abc/map", Token: tok, Origin: "auto", Body: "{}", Header: map[string]string{"Content-Type": "application/json"}})
	if resp.StatusCode != 405 || resp.Header.Get("Allow") != "GET, HEAD" {
		t.Fatalf("wrong method: %d Allow=%q %s", resp.StatusCode, resp.Header.Get("Allow"), b)
	}
	errorBody(t, b)
	// Unknown API paths are 404 JSON once authorised, 401 before.
	resp, b = ts.do(t, req{Path: "/api/nope", Token: tok})
	if resp.StatusCode != 404 || errorBody(t, b) != "not found" {
		t.Fatalf("unknown route: %d %s", resp.StatusCode, b)
	}
	resp, _ = ts.do(t, req{Path: "/api/nope"})
	if resp.StatusCode != 401 {
		t.Fatalf("unknown route without token: %d", resp.StatusCode)
	}
}

// TestConditionalPassThrough: the guard leaves If-None-Match to the handler
// and a handler's 304 + ETag reaches the client untouched (Phase B polling).
func TestConditionalPassThrough(t *testing.T) {
	o := emptyOptions(t)
	o.Routes = map[string]http.Handler{
		"GET /api/thing": http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("ETag", `"v1"`)
			if r.Header.Get("If-None-Match") == `"v1"` {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			writeJSON(w, 200, map[string]int{"n": 1})
		}),
	}
	ts := startServer(t, o)
	resp, b := ts.do(t, req{Path: "/api/thing", Token: ts.s.Token(), Header: map[string]string{"If-None-Match": `"v1"`}})
	if resp.StatusCode != 304 || resp.Header.Get("ETag") != `"v1"` || len(b) != 0 {
		t.Fatalf("conditional GET = %d ETag=%q body=%q", resp.StatusCode, resp.Header.Get("ETag"), b)
	}
}

func TestIdleExit(t *testing.T) {
	var clock atomic.Int64
	clock.Store(time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC).UnixNano())
	o := emptyOptions(t)
	o.Idle = 50 * time.Millisecond
	o.Now = func() time.Time { return time.Unix(0, clock.Load()) }
	s, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := Listen(0)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Serve(context.Background(), ln) }()
	ts := &testServer{s: s, port: strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)}
	ts.base = "http://127.0.0.1:" + ts.port
	waitServing(t, ts)
	stillServing := func(why string) {
		t.Helper()
		select {
		case err := <-done:
			t.Fatalf("Serve returned (%v): %s", err, why)
		case <-time.After(200 * time.Millisecond):
		}
	}

	// The injected clock does not move, so wall time passing is not idleness.
	if resp, _ := ts.do(t, req{Path: "/"}); resp.StatusCode != 200 {
		t.Fatalf("GET / = %d", resp.StatusCode)
	}
	stillServing("the injected clock stood still")

	// A request that passes the guard resets the idle clock: 40ms, request,
	// 40ms is 80ms since start but 40ms since the last hit.
	step := int64(40 * time.Millisecond)
	clock.Add(step)
	if resp, _ := ts.do(t, req{Path: "/api/status", Token: s.Token()}); resp.StatusCode != 200 {
		t.Fatalf("GET /api/status = %d", resp.StatusCode)
	}
	clock.Add(step)
	stillServing("a request 40ms ago must keep a 50ms idle server up")

	// Only authenticated /api/ requests count: 45ms after the last one, a
	// flood of static GETs, static POSTs and refused API calls, then 30ms
	// more (75ms since the last authenticated hit) must end in an exit.
	clock.Add(int64(5 * time.Millisecond))
	for i := 0; i < 5; i++ {
		for _, q := range []req{
			{Path: "/"},
			{Path: "/app.js"},
			{Method: "POST", Path: "/", Origin: "auto", Body: `{}`, Header: jsonCT()},
			{Path: "/api/status"},
			{Path: "/api/status", Token: s.Token() + "x"},
		} {
			ts.do(t, q)
		}
	}
	stillServing("45ms since the last authenticated request")
	clock.Add(int64(30 * time.Millisecond))
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("idle exit returned %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not exit after the idle limit")
	}
	if c, err := net.DialTimeout("tcp4", "127.0.0.1:"+ts.port, time.Second); err == nil {
		c.Close()
		t.Error("listener still accepting after idle exit")
	}
}

// TestOptionsStarIsGuarded: with DisableGeneralOptionsHandler, "OPTIONS *"
// reaches the guard and gets the security headers and a 405 (net/http would
// otherwise answer 200 itself, without them).
func TestOptionsStarIsGuarded(t *testing.T) {
	ts := startServer(t, emptyOptions(t))
	for host, want := range map[string]string{"127.0.0.1:" + ts.port: "405", "evil.example:" + ts.port: "403"} {
		c, err := net.Dial("tcp4", "127.0.0.1:"+ts.port)
		if err != nil {
			t.Fatal(err)
		}
		c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Write([]byte("OPTIONS * HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n")); err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(c)
		c.Close()
		resp := string(raw)
		if !strings.HasPrefix(resp, "HTTP/1.1 "+want+" ") || !strings.Contains(resp, "Content-Security-Policy: default-src 'none'") || !strings.Contains(resp, "X-Frame-Options: DENY") {
			t.Errorf("OPTIONS * (Host %s):\n%s", host, resp)
		}
	}
	// OPTIONS on a path is treated the same way.
	resp, _ := ts.do(t, req{Method: "OPTIONS", Path: "/"})
	if resp.StatusCode != 405 || resp.Header.Get("Content-Security-Policy") == "" {
		t.Errorf("OPTIONS / = %d", resp.StatusCode)
	}
}

func TestNoTokenInLogsOrURLPrint(t *testing.T) {
	// Capture everything the process writes to stdout and stderr while the
	// server runs (not parallel: os.Stdout/os.Stderr are swapped).
	outFile := filepath.Join(t.TempDir(), "out")
	f, err := os.Create(outFile)
	if err != nil {
		t.Fatal(err)
	}
	oldOut, oldErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = f, f
	restore := func() { os.Stdout, os.Stderr = oldOut, oldErr }
	defer restore()

	o := emptyOptions(t)
	s, err := New(o)
	if err != nil {
		restore()
		t.Fatal(err)
	}
	ln, err := Listen(0)
	if err != nil {
		restore()
		t.Fatal(err)
	}
	tok := s.Token()
	url := s.URL(ln)
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, ln) }()
	ts := &testServer{s: s, port: port, base: "http://127.0.0.1:" + port}
	waitServing(t, ts)

	ts.do(t, req{Path: "/api/status", Token: tok})
	ts.do(t, req{Path: "/api/status?t=" + tok, Token: tok + "x"})
	ts.do(t, req{Path: "/api/skills/" + tok, Token: tok})
	ts.do(t, req{Path: "/", Host: "evil.example:" + port})
	ts.do(t, req{Method: "POST", Path: "/api/skills/x/grant", Token: tok, Origin: "auto", Body: "{", Header: map[string]string{"Content-Type": "application/json"}})
	// Malformed HTTP on a raw connection: the server's error log path.
	if c, err := net.Dial("tcp4", "127.0.0.1:"+port); err == nil {
		c.Write([]byte("GET /" + tok + " HTTP/9.9\r\nHost: \x00\r\n\r\n"))
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		io.Copy(io.Discard, c)
		c.Close()
	}
	cancel()
	<-done
	restore()
	f.Close()

	printed, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatal(err)
	}
	if len(printed) != 0 {
		t.Errorf("server wrote %d bytes to stdout/stderr: %q", len(printed), printed)
	}
	if len(tok) != 43 {
		t.Errorf("token length %d, want 43 (32 bytes base64url)", len(tok))
	}
	want := "http://127.0.0.1:" + port + "/#t=" + tok
	if url != want {
		t.Errorf("URL = %q, want %q", url, want)
	}
	if strings.Count(url, tok) != 1 || strings.Contains(url, "?") {
		t.Errorf("token must appear once, in the fragment: %q", url)
	}
	other, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	if other.Token() == tok {
		t.Error("two servers share a token")
	}
}

func TestHandlerBeforeServeRefuses(t *testing.T) {
	s, err := New(emptyOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	w := &recorder{h: http.Header{}}
	r, _ := http.NewRequest("GET", "http://127.0.0.1:1/", nil)
	s.Handler().ServeHTTP(w, r)
	if w.code != 403 || w.h.Get("Content-Security-Policy") == "" {
		t.Fatalf("Handler before Serve = %d, want 403 with headers", w.code)
	}
}

// recorder is a minimal ResponseWriter (no httptest).
type recorder struct {
	h    http.Header
	code int
	body bytes.Buffer
}

func (r *recorder) Header() http.Header { return r.h }
func (r *recorder) WriteHeader(c int) {
	if r.code == 0 {
		r.code = c
	}
}
func (r *recorder) Write(b []byte) (int, error) {
	if r.code == 0 {
		r.code = 200
	}
	return r.body.Write(b)
}

// TestPackageIsInitFree keeps internal/ui free of init work: it is linked
// into the hook binary. Non-test files may not import packages whose own
// init is heavy or that tempt package-level setup (regexp, mime,
// html/template, text/template, net/http/pprof), and package-level vars may
// hold neither calls nor map literals. The embed.FS in static.go is static
// data. GODEBUG=inittrace=1 on a binary is the end-to-end check (DESIGN).
func TestPackageIsInitFree(t *testing.T) {
	banned := []string{`"regexp"`, `"mime"`, `"html/template"`, `"text/template"`, `"net/http/pprof"`, `"expvar"`}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range f.Imports {
			for _, b := range banned {
				if imp.Path.Value == b {
					t.Errorf("%s imports %s", name, b)
				}
			}
		}
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil && fd.Name.Name == "init" {
				t.Errorf("%s declares func init", name)
			}
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.VAR {
				continue
			}
			ast.Inspect(gd, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.CallExpr:
					t.Errorf("%s: package-level var calls a function at %s", name, fset.Position(x.Pos()))
				case *ast.CompositeLit:
					if _, isMap := x.Type.(*ast.MapType); isMap {
						t.Errorf("%s: package-level map literal at %s", name, fset.Position(x.Pos()))
					}
				}
				return true
			})
		}
	}
}
