package ui

import (
	"bufio"
	"net/http"
	"strings"
	"testing"
	"time"
)

type fakeSource struct{ ch chan Event }

func (f fakeSource) Subscribe() (<-chan Event, func()) { return f.ch, func() {} }

func TestEventsRouteOnlyWithASource(t *testing.T) {
	ts := startServer(t, emptyOptions(t))
	if resp, _ := ts.do(t, req{Path: "/api/events", Token: ts.s.Token()}); resp.StatusCode != 404 {
		t.Errorf("no source: %d", resp.StatusCode)
	}
}

func TestEventsStreamMaxAge(t *testing.T) {
	o := emptyOptions(t)
	o.Events = fakeSource{ch: make(chan Event)}
	o.EventsMaxAge = 100 * time.Millisecond
	ts := startServer(t, o)
	start := time.Now()
	resp, _ := ts.do(t, req{Path: "/api/events", Token: ts.s.Token()}) // reads to EOF
	if resp.StatusCode != 200 || time.Since(start) > 5*time.Second {
		t.Fatalf("stream: %d after %v", resp.StatusCode, time.Since(start))
	}
	for i := 0; i < 100 && ts.s.Streams() != 0; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if ts.s.Streams() != 0 {
		t.Errorf("stream slot not released: %d", ts.s.Streams())
	}
}

func TestEventsStreamFramesAndAuth(t *testing.T) {
	o := emptyOptions(t)
	src := fakeSource{ch: make(chan Event, 4)}
	o.Events = src
	ts := startServer(t, o)
	if resp, _ := ts.do(t, req{Path: "/api/events"}); resp.StatusCode != 401 {
		t.Errorf("no bearer: %d", resp.StatusCode)
	}
	if resp, _ := ts.do(t, req{Method: http.MethodHead, Path: "/api/events", Token: ts.s.Token()}); resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		t.Errorf("HEAD: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	r, _ := http.NewRequest(http.MethodGet, ts.base+"/api/events", nil)
	r.Header.Set("Authorization", "Bearer "+ts.s.Token())
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.Header.Get("X-Frame-Options") != "DENY" || resp.Header.Get("Cache-Control") == "" {
		t.Errorf("security headers missing on the stream: %v", resp.Header)
	}
	// A newline inside a name or data never splits a frame.
	src.ch <- Event{Name: "session\nevent: forged", Data: []byte("{\"a\":1}\n\ndata: x")}
	rd := bufio.NewReader(resp.Body)
	var lines []string
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && len(lines) < 7 {
		l, err := rd.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, strings.TrimRight(l, "\n"))
	}
	got := strings.Join(lines, "|")
	want := "retry: 5000|event: hello|data: {\"keepalive_ms\":25000}||event: sessionevent: forged|data: {\"a\":1}data: x|"
	if got != want {
		t.Errorf("frames:\n got %q\nwant %q", got, want)
	}
}
