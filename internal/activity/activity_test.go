package activity

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func logPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "state", "watchdeck", "activity.jsonl")
}

func mustAppend(t *testing.T, path string, r Record) {
	t.Helper()
	if err := Append(path, r); err != nil {
		t.Fatal(err)
	}
}

func ts(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func decision(at time.Time, id, cwd, cmd string, skills ...string) Record {
	return Record{Kind: KindDecision, TS: ts(at), SessionID: "s-" + id, ToolUseID: id, Transcript: "/t/" + id + ".jsonl",
		AgentID: "a-" + id, AgentType: "Explore", PermMode: "default", Cwd: cwd, Skills: skills, Command: cmd,
		Decision: "ask", Rewritten: "watchdeck run --skill x -c " + cmd, Confidence: "high"}
}

func run(at time.Time, cwd, cmd string, skills ...string) Record {
	zero := 0
	return Record{Kind: KindRun, TS: ts(at), Cwd: cwd, Skills: skills, Command: cmd, Exit: &zero, Outcome: OutcomeOK}
}

func TestAppendCreatesFile0600(t *testing.T) {
	p := logPath(t)
	mustAppend(t, p, Record{Kind: KindDecision, Command: "x"})
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("file mode %v", fi.Mode().Perm())
	}
	di, _ := os.Stat(filepath.Dir(p))
	if di.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %v", di.Mode().Perm())
	}
	b, _ := os.ReadFile(p)
	var r Record
	if err := json.Unmarshal(bytes.TrimSpace(b), &r); err != nil {
		t.Fatal(err)
	}
	if r.V != Version || r.TS == "" || r.Offset != 0 || !strings.HasSuffix(string(b), "\n") {
		t.Fatalf("record %+v line %q", r, b)
	}
	if strings.Contains(string(b), `"offset"`) {
		t.Fatalf("offset written to disk: %s", b)
	}
}

func TestAppendOffIsNoop(t *testing.T) {
	dir := t.TempDir()
	if err := Append("", Record{Kind: KindRun}); err != nil {
		t.Fatal(err)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Fatalf("created %v", ents)
	}
	res, err := Read("", ReadOptions{})
	if err != nil || len(res.Records) != 0 {
		t.Fatalf("read off: %+v %v", res, err)
	}
}

func TestRotateAtMaxBytes(t *testing.T) {
	old := MaxBytes
	MaxBytes = 300
	t.Cleanup(func() { MaxBytes = old })
	p := logPath(t)
	for i := 0; i < 4; i++ {
		mustAppend(t, p, Record{Kind: KindDecision, Command: strings.Repeat("a", 100) + string(rune('0'+i))})
	}
	if _, err := os.Stat(p + ".1"); err != nil {
		t.Fatalf("no rotated file: %v", err)
	}
	res, err := Read(p, ReadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 4 {
		t.Fatalf("got %d records", len(res.Records))
	}
	for i, r := range res.Records {
		if !strings.HasSuffix(r.Command, string(rune('0'+i))) {
			t.Fatalf("order: record %d is %q", i, r.Command)
		}
	}
	cur, _ := os.Stat(p)
	if res.Next != cur.Size() {
		t.Fatalf("Next %d, current size %d", res.Next, cur.Size())
	}
}

func TestReadAfterOffsetAndTornLine(t *testing.T) {
	p := logPath(t)
	mustAppend(t, p, Record{Kind: KindDecision, Command: "one"})
	mustAppend(t, p, Record{Kind: KindDecision, Command: "two"})
	res, err := Read(p, ReadOptions{})
	if err != nil || len(res.Records) != 2 {
		t.Fatalf("%+v %v", res, err)
	}
	fi, _ := os.Stat(p)
	if res.Next != fi.Size() || res.Records[0].Offset != 0 || res.Records[1].Offset == 0 {
		t.Fatalf("next %d size %d offsets %d %d", res.Next, fi.Size(), res.Records[0].Offset, res.Records[1].Offset)
	}
	next := res.Next
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o600)
	f.WriteString(`{"v":1,"kind":"run","comm`)
	f.Close()
	res, err = Read(p, ReadOptions{After: next})
	if err != nil || len(res.Records) != 0 || res.Next != next || res.Reset {
		t.Fatalf("torn line: %+v %v", res, err)
	}
	// the writer finishes the line: the next poll reads it whole
	f, _ = os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o600)
	f.WriteString(`and":"three"}` + "\n")
	f.Close()
	res, _ = Read(p, ReadOptions{After: next})
	if len(res.Records) != 1 || res.Records[0].Command != "three" || res.Records[0].Offset != next {
		t.Fatalf("completed line: %+v", res)
	}
	// a garbage complete line is counted, not returned
	f, _ = os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o600)
	f.WriteString("not json\n")
	f.Close()
	res, _ = Read(p, ReadOptions{})
	if res.Skipped != 1 || len(res.Records) != 3 {
		t.Fatalf("garbage: %+v", res)
	}
}

func TestReadTail(t *testing.T) {
	p := logPath(t)
	for i := 0; i < 5; i++ {
		mustAppend(t, p, Record{Kind: KindDecision, Command: string(rune('a' + i))})
	}
	res, err := Read(p, ReadOptions{Tail: 2})
	if err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(p)
	if len(res.Records) != 2 || res.Records[0].Command != "d" || res.Records[1].Command != "e" || res.Next != fi.Size() {
		t.Fatalf("%+v", res)
	}
}

func TestActivityTailThenPoll(t *testing.T) {
	p := logPath(t)
	for i := 0; i < 3; i++ {
		mustAppend(t, p, Record{Kind: KindDecision, Command: string(rune('a' + i))})
	}
	res, _ := Read(p, ReadOptions{Tail: 2})
	mustAppend(t, p, Record{Kind: KindDecision, Command: "new"})
	res2, err := Read(p, ReadOptions{After: res.Next})
	if err != nil || len(res2.Records) != 1 || res2.Records[0].Command != "new" || res2.Reset {
		t.Fatalf("%+v %v", res2, err)
	}
	res3, _ := Read(p, ReadOptions{After: res2.Next})
	if len(res3.Records) != 0 || res3.Next != res2.Next {
		t.Fatalf("idle poll: %+v", res3)
	}
}

func TestReadReset(t *testing.T) {
	p := logPath(t)
	mustAppend(t, p, Record{Kind: KindDecision, Command: "a"})
	mustAppend(t, p, Record{Kind: KindDecision, Command: "b"})
	res, _ := Read(p, ReadOptions{})
	os.Truncate(p, 0)
	mustAppend(t, p, Record{Kind: KindDecision, Command: "c"})
	res2, err := Read(p, ReadOptions{After: res.Next})
	if err != nil || !res2.Reset || len(res2.Records) != 1 || res2.Records[0].Command != "c" {
		t.Fatalf("%+v %v", res2, err)
	}
}

// TestReadResetAfterRotationKeepsNewest: a poll whose offset is past the end
// of a freshly rotated file gets the newest Limit records, not the oldest, and
// a Next at the current file's end so the following poll is empty.
func TestReadResetAfterRotationKeepsNewest(t *testing.T) {
	p := logPath(t)
	for i := range 6 {
		mustAppend(t, p, Record{Kind: KindDecision, Command: "old" + strconv.Itoa(i)})
	}
	if err := os.Rename(p, p+".1"); err != nil {
		t.Fatal(err)
	}
	mustAppend(t, p, Record{Kind: KindDecision, Command: "new0"})
	mustAppend(t, p, Record{Kind: KindDecision, Command: "new1"})
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	res, err := Read(p, ReadOptions{After: 1 << 20, Limit: 3})
	if err != nil || !res.Reset || len(res.Records) != 3 {
		t.Fatalf("reset read = %+v %v", res, err)
	}
	if got := []string{res.Records[0].Command, res.Records[1].Command, res.Records[2].Command}; got[0] != "old5" || got[1] != "new0" || got[2] != "new1" {
		t.Fatalf("reset records = %v, want [old5 new0 new1]", got)
	}
	if res.Next != fi.Size() {
		t.Fatalf("reset next = %d, want the current size %d", res.Next, fi.Size())
	}
	res, err = Read(p, ReadOptions{After: res.Next, Limit: 3})
	if err != nil || res.Reset || len(res.Records) != 0 || res.Next != fi.Size() {
		t.Fatalf("poll after reset = %+v %v", res, err)
	}
}

func TestReadFilters(t *testing.T) {
	p := logPath(t)
	now := time.Now()
	d := decision(now.Add(-2*time.Minute), "toolu_1", "/w", "cmd", "k")
	mustAppend(t, p, d)
	mustAppend(t, p, Record{Kind: KindSkillInvoked, TS: ts(now.Add(-time.Minute)), SessionID: "other", ToolName: "Skill", Skill: "k"})
	mustAppend(t, p, run(now, "/w", "cmd", "k"))
	res, _ := Read(p, ReadOptions{SessionID: "s-toolu_1"})
	if len(res.Records) != 2 || res.Records[1].Kind != KindRun || res.Records[1].JoinedBy != JoinedByHeuristic {
		t.Fatalf("session filter must see the joined run: %+v", res.Records)
	}
	res, _ = Read(p, ReadOptions{Kinds: []string{KindSkillInvoked}})
	if len(res.Records) != 1 || res.Records[0].Kind != KindSkillInvoked {
		t.Fatalf("kinds: %+v", res.Records)
	}
	res, _ = Read(p, ReadOptions{Since: now.Add(-90 * time.Second)})
	if len(res.Records) != 2 {
		t.Fatalf("since: %+v", res.Records)
	}
	res, _ = Read(p, ReadOptions{Limit: 1})
	if len(res.Records) != 1 || res.Next != res.Records[0].Offset+lineLen(t, p, 0) {
		t.Fatalf("limit: %+v", res)
	}
}

func lineLen(t *testing.T, p string, n int) int64 {
	b, _ := os.ReadFile(p)
	return int64(len(strings.SplitAfter(string(b), "\n")[n]))
}

func TestStat(t *testing.T) {
	p := logPath(t)
	if n, m, err := Stat(p); n != 0 || !m.IsZero() || err != nil {
		t.Fatalf("absent: %d %v %v", n, m, err)
	}
	mustAppend(t, p, Record{Kind: KindDecision})
	if n, m, err := Stat(p); n == 0 || m.IsZero() || err != nil {
		t.Fatalf("present: %d %v %v", n, m, err)
	}
}

func TestConcurrentAppend(t *testing.T) {
	p := logPath(t)
	var wg sync.WaitGroup
	for g := 0; g < 100; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 10; i++ {
				if err := Append(p, Record{Kind: KindRun, Command: strings.Repeat("x", 200), Warnings: []string{string(rune('a' + g%26))}}); err != nil {
					t.Error(err)
				}
			}
		}(g)
	}
	wg.Wait()
	res, err := Read(p, ReadOptions{})
	if err != nil || len(res.Records) != 1000 || res.Skipped != 0 {
		t.Fatalf("records %d skipped %d err %v", len(res.Records), res.Skipped, err)
	}
}

func TestJoinHeuristic(t *testing.T) {
	now := time.Now()
	cwd := t.TempDir()
	recs := []Record{
		decision(now.Add(-3*time.Second), "toolu_a", cwd, "python3 a.py", "k"),
		decision(now.Add(-2*time.Second), "toolu_b", cwd, "python3 b.py", "k"),
		run(now, cwd, "python3 b.py", "k"),
	}
	Join(recs)
	if recs[2].ToolUseID != "toolu_b" || recs[2].JoinedBy != JoinedByHeuristic || recs[2].SessionID != "s-toolu_b" ||
		recs[2].Transcript != "/t/toolu_b.jsonl" || recs[2].AgentID != "a-toolu_b" || recs[2].AgentType != "Explore" || recs[2].PermMode != "default" {
		t.Fatalf("matching command: %+v", recs[2])
	}

	// skills compare as sets
	recs = []Record{decision(now.Add(-time.Second), "toolu_c", cwd, "c", "y", "x"), run(now, cwd, "c", "x", "y")}
	if Join(recs)[1].ToolUseID != "toolu_c" {
		t.Fatal("sorted skills did not join")
	}

	// cwd differs → no join; same dir through a symlink → join
	other := t.TempDir()
	recs = []Record{decision(now.Add(-time.Second), "toolu_d", other, "c", "k"), run(now, cwd, "c", "k")}
	if Join(recs)[1].JoinedBy != "" {
		t.Fatal("different cwd joined")
	}
	link := filepath.Join(t.TempDir(), "link")
	os.Symlink(cwd, link)
	recs = []Record{decision(now.Add(-time.Second), "toolu_e", link, "c", "k"), run(now, cwd+"/.", "c", "k")}
	if Join(recs)[1].ToolUseID != "toolu_e" {
		t.Fatal("symlinked cwd did not join")
	}

	// decision 11 minutes older → no join; decision after the run → no join
	recs = []Record{decision(now.Add(-11*time.Minute), "toolu_f", cwd, "c", "k"), run(now, cwd, "c", "k")}
	if Join(recs)[1].JoinedBy != "" {
		t.Fatal("stale decision joined")
	}
	// an unrewritten decision (low confidence ask) never joins
	d := decision(now.Add(-time.Second), "toolu_g", cwd, "c", "k")
	d.Rewritten = ""
	recs = []Record{d, run(now, cwd, "c", "k")}
	if Join(recs)[1].JoinedBy != "" {
		t.Fatal("unrewritten decision joined")
	}

	// decline then retry: two identical decisions, one run → the newer one
	recs = []Record{
		decision(now.Add(-time.Minute), "toolu_declined", cwd, "c", "k"),
		decision(now.Add(-time.Second), "toolu_retry", cwd, "c", "k"),
		run(now, cwd, "c", "k"),
	}
	if got := Join(recs)[2].ToolUseID; got != "toolu_retry" {
		t.Fatalf("decline-then-retry joined %q", got)
	}
}

func TestJoinNoDoubleUse(t *testing.T) {
	now := time.Now()
	cwd := t.TempDir()
	recs := []Record{
		decision(now.Add(-3*time.Second), "toolu_1", cwd, "c", "k"),
		run(now.Add(-2*time.Second), cwd, "c", "k"),
		run(now, cwd, "c", "k"),
	}
	Join(recs)
	if recs[1].ToolUseID != "toolu_1" || recs[2].JoinedBy != "" || recs[2].ToolUseID != "" {
		t.Fatalf("one decision joined two runs: %+v / %+v", recs[1], recs[2])
	}
	// interleaved d1 r1 d2 r2 pairs in order
	recs = []Record{
		decision(now.Add(-4*time.Second), "toolu_1", cwd, "c", "k"),
		run(now.Add(-3*time.Second), cwd, "c", "k"),
		decision(now.Add(-2*time.Second), "toolu_2", cwd, "c", "k"),
		run(now, cwd, "c", "k"),
	}
	Join(recs)
	if recs[1].ToolUseID != "toolu_1" || recs[3].ToolUseID != "toolu_2" {
		t.Fatalf("interleaved: %q %q", recs[1].ToolUseID, recs[3].ToolUseID)
	}
}

func TestJoinTrustsWriteTimeIds(t *testing.T) {
	now := time.Now()
	cwd := t.TempDir()
	d1 := decision(now.Add(-4*time.Second), "toolu_1", cwd, "c", "k")
	d2 := decision(now.Add(-3*time.Second), "toolu_2", cwd, "c", "k")
	// an unjoined run that appears before the write-time owner of d2 must not take d2
	early := run(now.Add(-2*time.Second), cwd, "c", "k")
	owner := run(now.Add(-time.Second), cwd, "c", "k")
	owner.SessionID, owner.ToolUseID, owner.JoinedBy = "s-toolu_2", "toolu_2", JoinedByWrite
	// a racing run stored the same id at write time; the reader re-joins it
	dup := run(now, cwd, "c", "k")
	dup.SessionID, dup.ToolUseID, dup.JoinedBy = "s-toolu_2", "toolu_2", JoinedByWrite
	recs := []Record{d1, d2, early, owner, dup}
	Join(recs)
	if recs[2].ToolUseID != "toolu_1" || recs[2].JoinedBy != JoinedByHeuristic {
		t.Fatalf("early run: %+v", recs[2])
	}
	if recs[3].ToolUseID != "toolu_2" || recs[3].JoinedBy != JoinedByWrite {
		t.Fatalf("owner changed: %+v", recs[3])
	}
	if recs[4].ToolUseID != "" || recs[4].JoinedBy != "" || recs[4].SessionID != "" {
		t.Fatalf("duplicate id kept (no decision left for it): %+v", recs[4])
	}
	// with a third decision available the duplicate is re-joined to it
	d3 := decision(now.Add(-500*time.Millisecond), "toolu_3", cwd, "c", "k")
	dup2 := run(now, cwd, "c", "k")
	dup2.ToolUseID, dup2.JoinedBy = "toolu_2", JoinedByWrite
	owner2 := owner
	recs = []Record{d2, owner2, d3, dup2}
	Join(recs)
	if recs[3].ToolUseID != "toolu_3" || recs[3].JoinedBy != JoinedByHeuristic {
		t.Fatalf("duplicate not re-joined: %+v", recs[3])
	}
}

func TestCorrelateWriteTime(t *testing.T) {
	p := logPath(t)
	cwd := t.TempDir()
	now := time.Now()
	cand := run(now, cwd, "python3 x.py", "k")
	// absent file → unchanged, no panic
	if got := Correlate(p, cand); got.JoinedBy != "" || got.ToolUseID != "" {
		t.Fatalf("absent file: %+v", got)
	}
	if got := Correlate("", cand); got.JoinedBy != "" {
		t.Fatal("log off correlated")
	}
	mustAppend(t, p, decision(now.Add(-5*time.Second), "toolu_1", cwd, "python3 x.py", "k"))
	mustAppend(t, p, decision(now.Add(-4*time.Second), "toolu_2", cwd, "python3 other.py", "k"))
	got := Correlate(p, cand)
	if got.ToolUseID != "toolu_1" || got.SessionID != "s-toolu_1" || got.JoinedBy != JoinedByWrite || got.Transcript != "/t/toolu_1.jsonl" ||
		got.AgentID != "a-toolu_1" || got.AgentType != "Explore" || got.PermMode != "default" || got.Outcome != OutcomeOK {
		t.Fatalf("correlated: %+v", got)
	}
	mustAppend(t, p, got)
	// the decision is claimed now: a second identical run finds nothing
	if again := Correlate(p, run(now.Add(time.Second), cwd, "python3 x.py", "k")); again.JoinedBy != "" {
		t.Fatalf("claimed decision reused: %+v", again)
	}
	// no match → unchanged
	if miss := Correlate(p, run(now, cwd, "python3 nope.py", "k")); miss.JoinedBy != "" || miss.ToolUseID != "" {
		t.Fatalf("no match: %+v", miss)
	}
}

func TestCorrelateReadsRotatedTail(t *testing.T) {
	p := logPath(t)
	cwd := t.TempDir()
	now := time.Now()
	mustAppend(t, p, decision(now.Add(-time.Second), "toolu_rot", cwd, "c", "k"))
	if err := os.Rename(p, p+".1"); err != nil {
		t.Fatal(err)
	}
	mustAppend(t, p, Record{Kind: KindSkillInvoked, ToolName: "Skill"})
	if got := Correlate(p, run(now, cwd, "c", "k")); got.ToolUseID != "toolu_rot" || got.JoinedBy != JoinedByWrite {
		t.Fatalf("rotated decision not found: %+v", got)
	}
	// only .1 exists (between rotation and the next append)
	os.Remove(p)
	if got := Correlate(p, run(now, cwd, "c", "k")); got.ToolUseID != "toolu_rot" {
		t.Fatalf("rotated-only: %+v", got)
	}
}

func TestCorrelateTailWindow(t *testing.T) {
	p := logPath(t)
	cwd := t.TempDir()
	now := time.Now()
	mustAppend(t, p, decision(now.Add(-time.Minute), "toolu_far", cwd, "c", "k"))
	filler := strings.Repeat("f", 4<<10)
	for i := 0; i < 70; i++ { // > 256 KiB after the decision
		mustAppend(t, p, Record{Kind: KindSkillInvoked, ToolName: "Skill", Skill: filler})
	}
	if got := Correlate(p, run(now, cwd, "c", "k")); got.JoinedBy != "" {
		t.Fatalf("decision beyond the tail window was found: %+v", got.ToolUseID)
	}
}

// TestCorrelateCommandSubject: a command subject's run has no skills; it
// joins the decision with the same subject and command, never one with a
// different subject or a skill decision with the same text (M6.4).
func TestCorrelateCommandSubject(t *testing.T) {
	p := logPath(t)
	cwd := t.TempDir()
	now := time.Now()
	sub := func(r Record, name string) Record {
		r.Subject = &Subject{Kind: "command", Name: name}
		r.Enforcement = EnforcementSandbox
		return r
	}
	mustAppend(t, p, sub(decision(now.Add(-3*time.Second), "toolu_a", cwd, "npm run build"), "npm-scripts"))
	mustAppend(t, p, sub(decision(now.Add(-2*time.Second), "toolu_b", cwd, "npm run build"), "other"))
	mustAppend(t, p, decision(now.Add(-time.Second), "toolu_c", cwd, "npm run build", "k"))
	got := Correlate(p, sub(run(now, cwd, "npm run build"), "npm-scripts"))
	if got.ToolUseID != "toolu_a" || got.JoinedBy != JoinedByWrite || got.Subject == nil || got.Subject.Name != "npm-scripts" {
		t.Fatalf("command subject run: %+v", got)
	}
	// a skill run never takes a command-subject decision
	if got := Correlate(p, run(now, cwd, "npm run build")); got.JoinedBy != "" {
		t.Fatalf("subject-less run joined a subject decision: %+v", got)
	}
}
