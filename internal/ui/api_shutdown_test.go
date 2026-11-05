package ui

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func shutdownNonce(t *testing.T, ts *testServer) string {
	t.Helper()
	resp, b := ts.do(t, req{Path: "/api/shutdown", Token: ts.s.Token()})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/shutdown = %d %s", resp.StatusCode, b)
	}
	var v shutdownView
	decode(t, b, &v)
	if v.Nonce == "" || v.PID != os.Getpid() || v.Mode != "auto" {
		t.Fatalf("GET /api/shutdown = %+v", v)
	}
	return v.Nonce
}

func stillServing(t *testing.T, ts *testServer) {
	t.Helper()
	select {
	case err := <-ts.done:
		t.Fatalf("Serve returned (%v) before an accepted shutdown", err)
	default:
	}
	if ts.s.Stopped() {
		t.Fatal("Stopped() before an accepted shutdown")
	}
}

// TestStopRequiresAuth: POST /api/shutdown goes through the whole guard
// (bearer, Origin, Sec-Fetch-Site, JSON) and needs a one-use nonce; only
// then does Serve return.
func TestStopRequiresAuth(t *testing.T) {
	o := emptyOptions(t)
	o.Mode = "auto"
	ts := startServer(t, o)
	tok := ts.s.Token()
	json := map[string]string{"Content-Type": "application/json"}

	if resp, _ := ts.do(t, req{Path: "/api/shutdown"}); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("GET without token = %d", resp.StatusCode)
	}
	nonce := shutdownNonce(t, ts)
	body := `{"nonce":"` + nonce + `"}`
	// The wrong token differs from tok in its first byte, always: "x"+tok[1:]
	// equals tok whenever tok starts with x.
	wrong := "x" + tok[1:]
	if tok[0] == 'x' {
		wrong = "y" + tok[1:]
	}
	cases := []struct {
		name string
		q    req
		want int
	}{
		{"no token", req{Method: "POST", Path: "/api/shutdown", Body: body, Origin: "auto", Header: json}, 401},
		{"wrong token", req{Method: "POST", Path: "/api/shutdown", Body: body, Origin: "auto", Header: json, Token: wrong}, 401},
		{"no origin", req{Method: "POST", Path: "/api/shutdown", Body: body, Token: tok, Header: json}, 403},
		{"foreign origin", req{Method: "POST", Path: "/api/shutdown", Body: body, Origin: "http://evil.example", Token: tok, Header: json}, 403},
		{"cross-site", req{Method: "POST", Path: "/api/shutdown", Body: body, Origin: "auto", Token: tok, Header: map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "cross-site"}}, 403},
		{"form post", req{Method: "POST", Path: "/api/shutdown", Body: body, Origin: "auto", Token: tok, Header: map[string]string{"Content-Type": "text/plain"}}, 415},
		{"no nonce", req{Method: "POST", Path: "/api/shutdown", Body: `{}`, Origin: "auto", Token: tok, Header: json}, 400},
		{"unknown nonce", req{Method: "POST", Path: "/api/shutdown", Body: `{"nonce":"00"}`, Origin: "auto", Token: tok, Header: json}, 403},
		{"bad host", req{Method: "POST", Path: "/api/shutdown", Body: body, Host: "evil.example:" + ts.port, Origin: "auto", Token: tok, Header: json}, 403},
	}
	for _, c := range cases {
		resp, b := ts.do(t, c.q)
		if resp.StatusCode != c.want {
			t.Errorf("%s: %d %s, want %d", c.name, resp.StatusCode, b, c.want)
		}
		stillServing(t, ts)
	}

	// The refused requests above spent nothing but "unknown nonce"; the
	// real one still works, once.
	resp, b := ts.do(t, req{Method: "POST", Path: "/api/shutdown", Body: body, Origin: "auto", Token: tok, Header: json})
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("POST = %d %s", resp.StatusCode, b)
	}
	select {
	case err := <-ts.done:
		if err != nil {
			t.Fatalf("Serve: %v", err)
		}
		ts.done <- nil // for the cleanup
	case <-time.After(10 * time.Second):
		t.Fatal("Serve did not return after an accepted shutdown")
	}
	if !ts.s.Stopped() {
		t.Fatal("Stopped() is false")
	}
}

func TestShutdownNonceOneUse(t *testing.T) {
	o := emptyOptions(t)
	o.Mode = "auto"
	ts := startServer(t, o)
	jsonHdr := map[string]string{"Content-Type": "application/json"}
	// An enforce nonce does not stop the server, and a shutdown nonce does
	// not edit settings: nonces are tagged by purpose.
	_, eb := ts.do(t, req{Path: "/api/enforce", Token: ts.s.Token()})
	var ev struct{ Nonce string }
	decode(t, eb, &ev)
	if resp, _ := ts.do(t, req{Method: "POST", Path: "/api/shutdown", Body: `{"nonce":"` + ev.Nonce + `"}`, Origin: "auto", Token: ts.s.Token(), Header: jsonHdr}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("enforce nonce on shutdown: %d, want 403", resp.StatusCode)
	}
	stillServing(t, ts)
	nonce := shutdownNonce(t, ts)
	if ts.s.spendNonce(nonce, purposeEnforce) {
		t.Fatal("a shutdown nonce was spent as an enforce nonce")
	}
	if !ts.s.spendNonce(nonce, purposeShutdown) {
		t.Fatal("nonce not issued")
	}
	resp, _ := ts.do(t, req{Method: "POST", Path: "/api/shutdown", Body: `{"nonce":"` + nonce + `"}`, Origin: "auto", Token: ts.s.Token(), Header: map[string]string{"Content-Type": "application/json"}})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("spent nonce: %d, want 403", resp.StatusCode)
	}
	stillServing(t, ts)
}

// TestTokenSourceSwitches: with TokenSource the server answers to whatever
// it returns now (ui --rotate-token), and refuses everything on "".
func TestTokenSourceSwitches(t *testing.T) {
	o := emptyOptions(t)
	cur := "first-token-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	o.TokenSource = func() string { return cur }
	ts := startServer(t, o)
	if resp, _ := ts.do(t, req{Path: "/api/status", Token: "first-token-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}); resp.StatusCode != 200 {
		t.Fatalf("first token = %d", resp.StatusCode)
	}
	cur = "second-token-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if resp, _ := ts.do(t, req{Path: "/api/status", Token: "first-token-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}); resp.StatusCode != 401 {
		t.Fatalf("old token after rotation = %d, want 401", resp.StatusCode)
	}
	if resp, _ := ts.do(t, req{Path: "/api/status", Token: cur}); resp.StatusCode != 200 {
		t.Fatalf("new token = %d", resp.StatusCode)
	}
	cur = ""
	for _, tok := range []string{"x", "second-token-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"} {
		if resp, _ := ts.do(t, req{Path: "/api/status", Token: tok}); resp.StatusCode != 401 {
			t.Fatalf("empty source, token %q = %d, want 401", tok, resp.StatusCode)
		}
	}
}

// TestCwdlessProjectParam: a server with no cwd (auto/service mode) works
// in user scope, and takes ?project= only for a known root.
func TestCwdlessProjectParam(t *testing.T) {
	o := emptyOptions(t)
	proj := filepath.Join(o.Paths.Home, "proj")
	if err := os.MkdirAll(filepath.Join(proj, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	o.Cwd = ""
	o.ProjectRoots = func() []string { return []string{proj} }
	ts := startServer(t, o)
	tok := ts.s.Token()

	var st statusJSON
	resp, b := ts.do(t, req{Path: "/api/status", Token: tok})
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d %s", resp.StatusCode, b)
	}
	if err := json.Unmarshal(b, &st); err != nil || st.Cwd != "" || st.ProjectRoot != "" {
		t.Fatalf("cwd-less status: %s", b)
	}
	resp, b = ts.do(t, req{Path: "/api/status?project=" + proj, Token: tok})
	if resp.StatusCode != 200 || json.Unmarshal(b, &st) != nil || st.Cwd != proj || st.ProjectRoot != proj {
		t.Fatalf("status?project = %d %s", resp.StatusCode, b)
	}
	resp, b = ts.do(t, req{Path: "/api/enforce?project=" + proj, Token: tok})
	var ev struct {
		Targets []struct{ ID, Path string }
	}
	if resp.StatusCode != 200 || json.Unmarshal(b, &ev) != nil || len(ev.Targets) != 2 || ev.Targets[1].Path != filepath.Join(proj, ".claude", "settings.json") {
		t.Fatalf("enforce?project = %d %s", resp.StatusCode, b)
	}
	resp, b = ts.do(t, req{Path: "/api/enforce", Token: tok})
	if resp.StatusCode != 200 || json.Unmarshal(b, &ev) != nil || len(ev.Targets) != 1 {
		t.Fatalf("cwd-less enforce lists a project target: %s", b)
	}

	other := filepath.Join(o.Paths.Home, "elsewhere")
	os.MkdirAll(other, 0o755)
	for _, bad := range []string{other, "proj", proj + "/", proj + "/../proj", "/", "/etc"} {
		for _, path := range []string{"/api/status", "/api/skills", "/api/skills/x", "/api/enforce"} {
			resp, b := ts.do(t, req{Path: path + "?project=" + bad, Token: tok})
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("%s?project=%s = %d %s, want 400", path, bad, resp.StatusCode, b)
			}
		}
	}
	// the refusal never echoes the value
	_, b = ts.do(t, req{Path: "/api/status?project=" + other, Token: tok})
	if e := errorBody(t, b); e == "" || strings.Contains(e, other) {
		t.Errorf("error %q", e)
	}
}
