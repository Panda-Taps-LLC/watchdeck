package ui

import (
	"os"
	"strconv"
	"testing"

	"github.com/Panda-Taps-LLC/watchdeck/internal/activity"
)

type activityView struct {
	Records []activity.Record `json:"records"`
	Next    *int64            `json:"next"`
	Reset   bool              `json:"reset"`
	Skipped int               `json:"skipped"`
	Path    string            `json:"path"`
	Enabled bool              `json:"enabled"`
}

func getActivity(t *testing.T, ts *testServer, query string) activityView {
	t.Helper()
	resp, b := ts.do(t, req{Path: "/api/activity" + query, Token: ts.s.Token()})
	if resp.StatusCode != 200 {
		t.Fatalf("GET /api/activity%s = %d %s", query, resp.StatusCode, b)
	}
	var v activityView
	decode(t, b, &v)
	if v.Records == nil || v.Next == nil {
		t.Fatalf("GET /api/activity%s: records or next missing: %s", query, b)
	}
	return v
}

func appendRec(t *testing.T, path string, r activity.Record) {
	t.Helper()
	if err := activity.Append(path, r); err != nil {
		t.Fatal(err)
	}
}

func commands(recs []activity.Record) []string {
	out := make([]string, len(recs))
	for i, r := range recs {
		out[i] = r.Command
	}
	return out
}

// TestActivityPolling follows the page: ?after=0 (or tail) first, then
// ?after=<next>, and a truncated file answers reset.
func TestActivityPolling(t *testing.T) {
	o := emptyOptions(t)
	path := o.Paths.Activity
	ts := startServer(t, o)

	appendRec(t, path, activity.Record{Kind: activity.KindDecision, SessionID: "s1", Command: "echo one", Decision: "ask"})
	appendRec(t, path, activity.Record{Kind: activity.KindSkillInvoked, SessionID: "s2", Command: "echo two"})

	v := getActivity(t, ts, "?after=0")
	if got := commands(v.Records); len(got) != 2 || got[0] != "echo one" || got[1] != "echo two" {
		t.Fatalf("after=0 records = %v", got)
	}
	if !v.Enabled || v.Path != path || v.Reset || v.Skipped != 0 || *v.Next <= 0 {
		t.Fatalf("after=0 = %+v", v)
	}
	next := *v.Next

	appendRec(t, path, activity.Record{Kind: activity.KindDecision, SessionID: "s1", Command: "echo three", Decision: "allow"})
	v = getActivity(t, ts, "?after="+strconv.FormatInt(next, 10))
	if got := commands(v.Records); len(got) != 1 || got[0] != "echo three" {
		t.Fatalf("after=next records = %v", got)
	}
	if v.Reset || *v.Next <= next {
		t.Fatalf("after=next = reset %v next %d (was %d)", v.Reset, *v.Next, next)
	}
	next = *v.Next

	// Nothing new: an empty array, next unchanged.
	v = getActivity(t, ts, "?after="+strconv.FormatInt(next, 10))
	if len(v.Records) != 0 || *v.Next != next {
		t.Fatalf("idle poll = %+v", v)
	}

	// First load: tail=1 is the newest record only, next at EOF.
	v = getActivity(t, ts, "?after=0&tail=1")
	if got := commands(v.Records); len(got) != 1 || got[0] != "echo three" || *v.Next != next {
		t.Fatalf("tail=1 = %v next %d, want [echo three] next %d", got, *v.Next, next)
	}
	// limit cuts the page and next points after the last record returned;
	// tail is ignored once after > 0.
	v = getActivity(t, ts, "?after=0&limit=1")
	if got := commands(v.Records); len(got) != 1 || got[0] != "echo one" || *v.Next <= 0 || *v.Next >= next {
		t.Fatalf("limit=1 = %v next %d", got, *v.Next)
	}
	v = getActivity(t, ts, "?after="+strconv.FormatInt(*v.Next, 10)+"&tail=1")
	if got := commands(v.Records); len(got) != 2 || got[0] != "echo two" || got[1] != "echo three" || *v.Next != next {
		t.Fatalf("after=<first>&tail=1 = %v next %d, want tail ignored", got, *v.Next)
	}

	// Filters.
	v = getActivity(t, ts, "?after=0&kinds=decision")
	if got := commands(v.Records); len(got) != 2 || got[0] != "echo one" || got[1] != "echo three" {
		t.Fatalf("kinds=decision = %v", got)
	}
	v = getActivity(t, ts, "?after=0&kinds=,skill_invoked,")
	if got := commands(v.Records); len(got) != 1 || got[0] != "echo two" {
		t.Fatalf("kinds=,skill_invoked, = %v", got)
	}
	v = getActivity(t, ts, "?after=0&session=s2")
	if got := commands(v.Records); len(got) != 1 || got[0] != "echo two" {
		t.Fatalf("session=s2 = %v", got)
	}

	// Truncated (or rotated) under the reader: reset, from offset 0.
	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	v = getActivity(t, ts, "?after="+strconv.FormatInt(next, 10))
	if !v.Reset || len(v.Records) != 0 || *v.Next != 0 {
		t.Fatalf("after truncate = %+v", v)
	}
}

// TestActivityResetAfterRotation: a poll past the end of a rotated log gets
// the newest records (at most the default limit), ending at the last record of
// the current file, and a next at the current file's end, so the page carries
// on polling instead of re-tailing (which showed the oldest records twice).
func TestActivityResetAfterRotation(t *testing.T) {
	o := emptyOptions(t)
	path := o.Paths.Activity
	ts := startServer(t, o)

	for i := range 600 {
		appendRec(t, path, activity.Record{Kind: activity.KindDecision, Command: "old " + strconv.Itoa(i)})
	}
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	for i := range 10 {
		appendRec(t, path, activity.Record{Kind: activity.KindDecision, Command: "new " + strconv.Itoa(i)})
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	size := fi.Size()

	v := getActivity(t, ts, "?after=999999")
	if !v.Reset || len(v.Records) != activityDefaultLimit {
		t.Fatalf("reset: reset %v, %d records, want true and %d", v.Reset, len(v.Records), activityDefaultLimit)
	}
	got := commands(v.Records)
	if got[0] != "old 110" || got[len(got)-1] != "new 9" {
		t.Fatalf("reset records run %q .. %q, want \"old 110\" .. \"new 9\"", got[0], got[len(got)-1])
	}
	if *v.Next != size {
		t.Fatalf("reset next = %d, want the current file size %d", *v.Next, size)
	}

	v = getActivity(t, ts, "?after="+strconv.FormatInt(size, 10))
	if v.Reset || len(v.Records) != 0 || *v.Next != size {
		t.Fatalf("poll after reset = %+v", v)
	}
}

// TestActivityOff:WATCHDECK_ACTIVITY=off is a 200 with enabled false.
func TestActivityOff(t *testing.T) {
	o := emptyOptions(t)
	o.Paths.Activity = ""
	ts := startServer(t, o)
	v := getActivity(t, ts, "?after=0&tail=200")
	if v.Enabled || v.Path != "" || len(v.Records) != 0 || *v.Next != 0 || v.Reset {
		t.Fatalf("log off = %+v", v)
	}

	// On but the file does not exist yet: enabled, empty.
	ts2 := startServer(t, emptyOptions(t))
	v = getActivity(t, ts2, "?after=0")
	if !v.Enabled || v.Path == "" || len(v.Records) != 0 || *v.Next != 0 {
		t.Fatalf("absent log = %+v", v)
	}
}

func TestActivityBadParams(t *testing.T) {
	ts := startServer(t, emptyOptions(t))
	for _, q := range []string{"?after=-1", "?after=x", "?after=1.5", "?limit=-3", "?limit=ten", "?tail=-1", "?tail=0x10", "?after=99999999999999999999"} {
		resp, b := ts.do(t, req{Path: "/api/activity" + q, Token: ts.s.Token()})
		if resp.StatusCode != 400 || errorBody(t, b) == "" {
			t.Errorf("GET /api/activity%s = %d %s, want 400 with an error", q, resp.StatusCode, b)
		}
	}
	// Oversized limit and tail are clamped, not refused.
	for _, q := range []string{"?limit=999999", "?after=0&tail=999999", "?limit=0"} {
		if resp, b := ts.do(t, req{Path: "/api/activity" + q, Token: ts.s.Token()}); resp.StatusCode != 200 {
			t.Errorf("GET /api/activity%s = %d %s, want 200", q, resp.StatusCode, b)
		}
	}
	// The route is behind the guard.
	if resp, _ := ts.do(t, req{Path: "/api/activity"}); resp.StatusCode != 401 {
		t.Errorf("no token = %d, want 401", resp.StatusCode)
	}
}
