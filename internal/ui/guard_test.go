package ui

import (
	"io"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"
)

// The guard matrix runs against a tiny extra route, POST /api/echo, so it
// does not depend on audit or the overrides file. It counts how often the
// handler ran: a refused request must never reach it.
func echoServer(t *testing.T) (*testServer, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	o := emptyOptions(t)
	o.Routes = map[string]http.Handler{
		"POST /api/echo": http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var v map[string]any
			if !readJSON(w, r, &v) {
				return
			}
			hits.Add(1)
			writeJSON(w, 200, v)
		}),
	}
	return startServer(t, o), &hits
}

// jsonCT is the request header a JSON POST carries. A function, not a
// package-level map, so the test binary stays init-free too.
func jsonCT() map[string]string { return map[string]string{"Content-Type": "application/json"} }

func TestAPIRequiresBearer(t *testing.T) {
	ts := startServer(t, emptyOptions(t))
	tok := ts.s.Token()
	cases := []struct {
		name   string
		header string
		want   int
	}{
		{"no header", "", 401},
		{"wrong token", "Bearer " + tok + "x", 401},
		{"prefix of token", "Bearer " + tok[:42], 401},
		{"no scheme", tok, 401},
		{"basic scheme", "Basic " + tok, 401},
		{"lower-case scheme", "bearer " + tok, 401},
		{"right token", "Bearer " + tok, 200},
	}
	for _, c := range cases {
		q := req{Path: "/api/status"}
		if c.header != "" {
			q.Header = map[string]string{"Authorization": c.header}
		}
		resp, b := ts.do(t, q)
		if resp.StatusCode != c.want {
			t.Errorf("%s: %d, want %d", c.name, resp.StatusCode, c.want)
			continue
		}
		if c.want == 401 && errorBody(t, b) != "unauthorized" {
			t.Errorf("%s: body %s", c.name, b)
		}
	}
	// The compare is constant-time (crypto/subtle), not ==.
	src, err := os.ReadFile("guard.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "subtle.ConstantTimeCompare(") {
		t.Error("guard.go no longer uses subtle.ConstantTimeCompare for the token")
	}
	// Static paths need no token.
	if resp, _ := ts.do(t, req{Path: "/app.js"}); resp.StatusCode != 200 {
		t.Errorf("static without token = %d", resp.StatusCode)
	}
}

func TestHostCheck(t *testing.T) {
	ts := startServer(t, emptyOptions(t))
	tok := ts.s.Token()
	for host, want := range map[string]int{
		"127.0.0.1:" + ts.port:    200,
		"localhost:" + ts.port:    200,
		"evil.example:" + ts.port: 403,
		"127.0.0.1":               403,
		"localhost":               403,
		"127.0.0.1:1":             403,
		"[::1]:" + ts.port:        403,
		"LOCALHOST:" + ts.port:    403,
		"127.0.0.1.:" + ts.port:   403,
	} {
		for _, path := range []string{"/api/status", "/"} {
			resp, _ := ts.do(t, req{Path: path, Host: host, Token: tok})
			if resp.StatusCode != want {
				t.Errorf("Host %q %s = %d, want %d", host, path, resp.StatusCode, want)
			}
			if resp.Header.Get("Content-Security-Policy") == "" {
				t.Errorf("Host %q %s: no CSP", host, path)
			}
		}
	}
}

func TestPostNeedsOrigin(t *testing.T) {
	ts, hits := echoServer(t)
	tok := ts.s.Token()
	cases := []struct {
		name, host, origin string
		want               int
	}{
		{"no Origin", "", "", 403},
		{"Origin localhost while Host is 127.0.0.1", "", "http://localhost:" + ts.port, 403},
		{"https Origin", "", "https://127.0.0.1:" + ts.port, 403},
		{"other port", "", "http://127.0.0.1:1", 403},
		{"null Origin", "", "null", 403},
		{"evil Origin", "", "http://evil.example", 403},
		{"matching Origin", "", "auto", 200},
		{"matching Origin on localhost", "localhost:" + ts.port, "http://localhost:" + ts.port, 200},
	}
	for _, c := range cases {
		resp, b := ts.do(t, req{Method: "POST", Path: "/api/echo", Host: c.host, Origin: c.origin, Token: tok, Body: `{"a":1}`, Header: jsonCT()})
		if resp.StatusCode != c.want {
			t.Errorf("%s: %d %s, want %d", c.name, resp.StatusCode, b, c.want)
		}
	}
	if n := hits.Load(); n != 2 {
		t.Errorf("handler ran %d times, want 2 (only the matching origins)", n)
	}
	// The Origin check comes before the token check: a cross-origin POST
	// is refused even with a valid token, and a missing token still 401s.
	resp, _ := ts.do(t, req{Method: "POST", Path: "/api/echo", Origin: "auto", Body: `{}`, Header: jsonCT()})
	if resp.StatusCode != 401 {
		t.Errorf("same-origin POST without token = %d, want 401", resp.StatusCode)
	}
	// Other unsafe methods are held to the same rule.
	for _, m := range []string{"PUT", "DELETE", "PATCH"} {
		resp, _ := ts.do(t, req{Method: m, Path: "/api/echo", Token: tok, Body: `{}`, Header: jsonCT()})
		if resp.StatusCode != 403 {
			t.Errorf("%s without Origin = %d, want 403", m, resp.StatusCode)
		}
	}
}

func TestSecFetchSiteCrossSiteRejected(t *testing.T) {
	ts, hits := echoServer(t)
	tok := ts.s.Token()
	for site, want := range map[string]int{
		"cross-site":  403,
		"same-site":   403,
		"bogus":       403,
		"same-origin": 200,
		"none":        200,
	} {
		h := map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": site}
		resp, b := ts.do(t, req{Method: "POST", Path: "/api/echo", Origin: "auto", Token: tok, Body: `{}`, Header: h})
		if resp.StatusCode != want {
			t.Errorf("Sec-Fetch-Site %s = %d %s, want %d", site, resp.StatusCode, b, want)
		}
	}
	if n := hits.Load(); n != 2 {
		t.Errorf("handler ran %d times, want 2", n)
	}
	// GET is not subject to it (the token guards reads).
	resp, _ := ts.do(t, req{Path: "/api/status", Token: tok, Header: map[string]string{"Sec-Fetch-Site": "cross-site"}})
	if resp.StatusCode != 200 {
		t.Errorf("GET with Sec-Fetch-Site cross-site = %d", resp.StatusCode)
	}
}

func TestContentTypeAndBodyCap(t *testing.T) {
	ts, hits := echoServer(t)
	tok := ts.s.Token()
	post := func(ct, body string, hdr map[string]string) (int, []byte) {
		h := map[string]string{}
		if ct != "" {
			h["Content-Type"] = ct
		}
		for k, v := range hdr {
			h[k] = v
		}
		resp, b := ts.do(t, req{Method: "POST", Path: "/api/echo", Origin: "auto", Token: tok, Body: body, Header: h})
		return resp.StatusCode, b
	}
	for _, ct := range []string{"", "text/plain", "application/x-www-form-urlencoded", "multipart/form-data; boundary=x", "application/jsonx"} {
		if code, b := post(ct, `{}`, nil); code != 415 {
			t.Errorf("Content-Type %q = %d %s, want 415", ct, code, b)
		}
	}
	for _, ct := range []string{"application/json", "application/json; charset=utf-8", "Application/JSON;charset=UTF-8"} {
		if code, _ := post(ct, `{"k":"v"}`, nil); code != 200 {
			t.Errorf("Content-Type %q = %d, want 200", ct, code)
		}
	}

	// 1 MiB + 1 with Content-Length: refused before the handler.
	big := `{"k":"` + strings.Repeat("a", 1<<20) + `"}`
	before := hits.Load()
	if code, b := post("application/json", big, nil); code != 413 {
		t.Errorf("1 MiB+ body = %d %s, want 413", code, b)
	}
	// Exactly at the cap is fine.
	exact := `{"k":"` + strings.Repeat("a", 1<<20-8) + `"}`
	if len(exact) != 1<<20 {
		t.Fatalf("exact body is %d bytes", len(exact))
	}
	if code, b := post("application/json", exact, nil); code != 200 {
		t.Errorf("1 MiB body = %d %.80s, want 200", code, b)
	}
	if hits.Load() != before+1 {
		t.Errorf("handler ran %d times for the two size cases, want 1", hits.Load()-before)
	}

	// Chunked (no Content-Length): MaxBytesReader catches it in readJSON.
	r, err := http.NewRequest("POST", ts.base+"/api/echo", &chunked{s: big})
	if err != nil {
		t.Fatal(err)
	}
	r.ContentLength = -1
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "http://127.0.0.1:"+ts.port)
	r.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 413 {
		t.Errorf("chunked 1 MiB+ = %d, want 413", resp.StatusCode)
	}

	// Malformed JSON, unknown trailing data: 400.
	for _, body := range []string{"{", `{} {}`, `[`, ``} {
		if code, _ := post("application/json", body, nil); code != 400 {
			t.Errorf("body %q = %d, want 400", body, code)
		}
	}
}

// chunked hides its length from net/http so the request is sent chunked.
type chunked struct {
	s string
	i int
}

func (c *chunked) Read(p []byte) (int, error) {
	if c.i >= len(c.s) {
		return 0, io.EOF
	}
	n := copy(p, c.s[c.i:])
	c.i += n
	return n, nil
}
