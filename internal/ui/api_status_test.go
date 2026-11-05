package ui

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Panda-Taps-LLC/watchdeck/internal/lifecycle"
)

// The header tells "hook seen recently, not in your settings" from "hook off"
// by the newest decision record's ts; a run or skill_invoked logged after it
// does not move it.
func TestStatusLastDecision(t *testing.T) {
	o := fixtureOptions(t)
	if err := os.MkdirAll(o.Paths.StateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	log := `{"v":1,"kind":"decision","ts":"2026-10-13T02:18:34.702Z","session_id":"s1","skills":["canary-request"],"decision":"ask"}
{"v":1,"kind":"run","ts":"2026-10-13T02:18:38.412Z","session_id":"s1","skills":["canary-request"],"outcome":"ok"}
{"v":1,"kind":"skill_invoked","ts":"2026-10-13T02:19:00Z","session_id":"s1","skill":"canary-request"}
`
	if err := os.WriteFile(o.Paths.Activity, []byte(log), 0o600); err != nil {
		t.Fatal(err)
	}
	ts := startServer(t, o)
	_, b := ts.do(t, req{Path: "/api/status", Token: ts.s.Token()})
	var st struct {
		Activity struct {
			LastDecision string `json:"lastDecision"`
		} `json:"activity"`
	}
	decode(t, b, &st)
	if st.Activity.LastDecision != "2026-10-13T02:18:34.702Z" {
		t.Errorf("lastDecision = %q, want the decision's ts; body %s", st.Activity.LastDecision, b)
	}

	// No decision in the log: the field is absent.
	if err := os.WriteFile(o.Paths.Activity, []byte("{\"v\":1,\"kind\":\"run\",\"ts\":\"2026-10-13T02:18:38Z\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var raw struct {
		Activity map[string]any `json:"activity"`
	}
	_, b = ts.do(t, req{Path: "/api/status", Token: ts.s.Token()})
	decode(t, b, &raw)
	if _, ok := raw.Activity["lastDecision"]; ok {
		t.Errorf("lastDecision present without a decision record: %s", b)
	}
}

// Plan 04 Task 1: /api/status carries live, the lifecycle store's live
// count (the header pill's " · N live"); 0 with no sessions, an off store
// or an unreadable one.
func TestStatusLive(t *testing.T) {
	o := emptyOptions(t)
	ts := startServer(t, o)
	live := func() int {
		t.Helper()
		_, b := ts.do(t, req{Path: "/api/status", Token: ts.s.Token()})
		var st map[string]any
		decode(t, b, &st)
		v, ok := st["live"].(float64)
		if !ok {
			t.Fatalf("status has no numeric live: %s", b)
		}
		return int(v)
	}
	if n := live(); n != 0 {
		t.Fatalf("live = %d with no sessions, want 0", n)
	}
	ls := lifecycle.Store{Log: o.Paths.Sessions, Live: o.Paths.LiveDir}
	for _, id := range []string{"a1b2c3d4-0000-4000-8000-000000000001", "a1b2c3d4-0000-4000-8000-000000000002"} {
		if _, err := ls.Start(id, "", o.Paths.Home, "startup"); err != nil {
			t.Fatal(err)
		}
	}
	if n := live(); n != 2 {
		t.Fatalf("live = %d after two starts, want 2", n)
	}
	if err := ls.End("a1b2c3d4-0000-4000-8000-000000000002", "", o.Paths.Home, "other"); err != nil {
		t.Fatal(err)
	}
	if n := live(); n != 1 {
		t.Fatalf("live = %d after one end, want 1", n)
	}

	off := o.Paths
	off.Sessions = ""
	if n := liveCount(off); n != 0 {
		t.Errorf("liveCount with the store off = %d, want 0", n)
	}
	bad := o.Paths
	bad.Sessions = filepath.Join(t.TempDir(), "dir-not-file")
	if err := os.MkdirAll(bad.Sessions, 0o700); err != nil {
		t.Fatal(err)
	}
	if n := liveCount(bad); n != 0 {
		t.Errorf("liveCount with an unreadable log = %d, want 0", n)
	}
}

// Plan 06 Task 6 (S2): /api/status carries shadow, read from the user
// overrides file with policy.ShadowOn: true only for mode: shadow; false
// for a plain file, an invalid one and none. The key is always present.
func TestStatusShadowField(t *testing.T) {
	o := fixtureOptions(t)
	up := o.Paths.OverridesFile()
	if err := os.MkdirAll(filepath.Dir(up), 0o700); err != nil {
		t.Fatal(err)
	}
	ts := startServer(t, o)
	shadow := func(name string) bool {
		t.Helper()
		_, b := ts.do(t, req{Path: "/api/status", Token: ts.s.Token()})
		var st map[string]any
		decode(t, b, &st)
		v, ok := st["shadow"].(bool)
		if !ok {
			t.Fatalf("%s: status has no boolean shadow: %s", name, b)
		}
		return v
	}
	for _, c := range []struct {
		name, body string
		want       bool
	}{
		{"shadow", "version: 2\nmode: shadow\n", true},
		{"plain", "version: 2\n", false},
		{"invalid", "version: 9\n", false},
		{"absent", "", false},
	} {
		if c.name == "absent" {
			if err := os.Remove(up); err != nil {
				t.Fatal(err)
			}
		} else if err := os.WriteFile(up, []byte(c.body), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := shadow(c.name); got != c.want {
			t.Errorf("%s: shadow = %v, want %v", c.name, got, c.want)
		}
	}
}
