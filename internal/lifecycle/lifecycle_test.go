package lifecycle

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// clock is a fake clock tests advance by hand.
type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) add(d time.Duration)     { c.t = c.t.Add(d) }
func newClock() *clock                   { return &clock{t: time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)} }
func store(t *testing.T, c *clock) Store { return storeIn(t, t.TempDir(), c) }

func storeIn(t *testing.T, state string, c *clock) Store {
	t.Helper()
	s := Store{Log: filepath.Join(state, "watchdeck", "sessions.jsonl"), Live: filepath.Join(state, "watchdeck", "live")}
	if c != nil {
		s.Now = c.now
	}
	return s
}

const sid = "3027c809-eb87-4265-922d-c76f134e6155"

func records(t *testing.T, s Store) []Record {
	t.Helper()
	recs, err := s.readLog()
	if err != nil {
		t.Fatal(err)
	}
	return recs
}

func TestStartWritesRecordAndMarker(t *testing.T) {
	c := newClock()
	s := store(t, c)
	r, err := s.Start(sid, "/Users/you/.claude/projects/-Users-you-proj/"+sid+".jsonl", "/Users/you/proj/", "startup")
	if err != nil {
		t.Fatal(err)
	}
	if r.Kind != KindStart || r.Source != "startup" || r.Cwd != "/Users/you/proj" || r.V != 1 {
		t.Fatalf("record = %+v", r)
	}
	recs := records(t, s)
	if len(recs) != 1 || recs[0] != r {
		t.Fatalf("log = %+v", recs)
	}
	for _, p := range []string{s.Log, filepath.Join(s.Live, sid)} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("%s mode %v, want 0600", p, fi.Mode().Perm())
		}
	}
	di, err := os.Stat(s.Live)
	if err != nil || di.Mode().Perm() != 0o700 {
		t.Fatalf("live dir = %v, %v; want 0700", di, err)
	}
	fi, _ := os.Stat(filepath.Join(s.Live, sid))
	if !fi.ModTime().Equal(c.t) {
		t.Errorf("marker mtime %v, want %v", fi.ModTime(), c.t)
	}
	if st, _ := s.State(sid); st != Live {
		t.Errorf("state = %s, want live", st)
	}
	// no temp file left behind
	ents, _ := os.ReadDir(s.Live)
	if len(ents) != 1 {
		t.Errorf("live dir holds %d entries", len(ents))
	}
}

func TestEndRemovesMarker(t *testing.T) {
	c := newClock()
	s := store(t, c)
	if _, err := s.Start(sid, "", "/p", "startup"); err != nil {
		t.Fatal(err)
	}
	c.add(time.Second)
	if err := s.End(sid, "", "/p", "prompt_input_exit"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(s.Live, sid)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("marker still there: %v", err)
	}
	recs := records(t, s)
	if len(recs) != 2 || recs[1].Kind != KindEnd || recs[1].Reason != "prompt_input_exit" {
		t.Fatalf("log = %+v", recs)
	}
	if st, _ := s.State(sid); st != Ended {
		t.Fatalf("state = %s, want ended", st)
	}
	// End of a session never started: record, no error.
	if err := s.End("other", "", "", "other"); err != nil {
		t.Fatal(err)
	}
	// End before any live dir exists: record, no error.
	fresh := store(t, c)
	if err := fresh.End(sid, "", "", "other"); err != nil {
		t.Fatalf("End without a live dir = %v", err)
	}
	if st, _ := fresh.State(sid); st != Ended {
		t.Fatalf("state = %s", st)
	}
}

// TestBeatOnlyTouchesWithinBeatEvery: a second beat inside 60 s appends no
// line and only moves the marker's mtime; the next one after 60 s appends.
func TestBeatOnlyTouchesWithinBeatEvery(t *testing.T) {
	c := newClock()
	s := store(t, c)
	if _, err := s.Start(sid, "", "/p", "startup"); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(s.Live, sid)
	before, _ := os.ReadFile(marker)
	for i := 0; i < 5; i++ {
		c.add(10 * time.Second) // 10..50 s after the start record
		if err := s.Beat(sid, "", "/p"); err != nil {
			t.Fatal(err)
		}
		if n := len(records(t, s)); n != 1 {
			t.Fatalf("beat %d appended a line (%d records)", i, n)
		}
		fi, _ := os.Stat(marker)
		if !fi.ModTime().Equal(c.t) {
			t.Fatalf("beat %d: marker mtime %v, want %v", i, fi.ModTime(), c.t)
		}
		if after, _ := os.ReadFile(marker); string(after) != string(before) {
			t.Fatalf("beat %d rewrote the marker", i)
		}
	}
	// Touches from other events do not reset the throttle: it counts from
	// the last appended record, not the last mtime.
	if err := s.Touch(sid); err != nil {
		t.Fatal(err)
	}
	c.add(11 * time.Second) // 61 s after the start record
	if err := s.Beat(sid, "", "/p"); err != nil {
		t.Fatal(err)
	}
	recs := records(t, s)
	if len(recs) != 2 || recs[1].Kind != KindBeat {
		t.Fatalf("log = %+v", recs)
	}
	c.add(30 * time.Second)
	_ = s.Beat(sid, "", "/p")
	if n := len(records(t, s)); n != 2 {
		t.Fatalf("beat 30 s after a beat appended (%d records)", n)
	}
}

// TestBeatCreatesMissingMarker: the hook installed mid-session sees a beat
// before any start; the marker is created and a beat appended.
func TestBeatCreatesMissingMarker(t *testing.T) {
	c := newClock()
	s := store(t, c)
	if err := s.Beat(sid, "/t.jsonl", "/p"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(s.Live, sid)); err != nil {
		t.Fatal(err)
	}
	if recs := records(t, s); len(recs) != 1 || recs[0].Kind != KindBeat {
		t.Fatalf("log = %+v", recs)
	}
	if st, _ := s.State(sid); st != Live {
		t.Fatalf("state = %s", st)
	}
}

func TestTouchNeverCreates(t *testing.T) {
	c := newClock()
	s := store(t, c)
	if err := s.Touch(sid); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Dir(s.Live)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("touch created the state dir: %v", err)
	}
	if _, err := s.Start(sid, "", "", ""); err != nil {
		t.Fatal(err)
	}
	c.add(time.Minute)
	if err := s.Touch(sid); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(filepath.Join(s.Live, sid))
	if !fi.ModTime().Equal(c.t) {
		t.Fatalf("mtime %v, want %v", fi.ModTime(), c.t)
	}
	if n := len(records(t, s)); n != 1 {
		t.Fatalf("touch appended (%d records)", n)
	}
	if err := s.Touch("unknown-session"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(s.Live, "unknown-session")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("touch created a marker")
	}
}

// TestOffNeverOpensFiles: the zero Store writes nothing and reads nothing.
func TestOffNeverOpensFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil { // any create under it would fail loudly
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })
	for _, s := range []Store{{}, {Log: filepath.Join(dir, "x.jsonl")}, {Live: filepath.Join(dir, "live")}} {
		if _, err := s.Start(sid, "", "", ""); err != nil {
			t.Fatal(err)
		}
		if err := s.Beat(sid, "", ""); err != nil {
			t.Fatal(err)
		}
		if err := s.Touch(sid); err != nil {
			t.Fatal(err)
		}
		if err := s.End(sid, "", "", ""); err != nil {
			t.Fatal(err)
		}
		if st, err := s.State(sid); err != nil || st != Unknown {
			t.Fatalf("state = %s, %v", st, err)
		}
		if l, err := s.List(); err != nil || l != nil {
			t.Fatalf("list = %v, %v", l, err)
		}
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 0 {
		t.Fatalf("off store created %v", ents)
	}
}

func TestInvalidSessionIDRejected(t *testing.T) {
	s := store(t, newClock())
	for _, id := range []string{"", ".", "..", "../x", "a/b", ".hidden", ".tmp-x", "a b", strings.Repeat("a", 97), "x\x00"} {
		if _, err := s.Start(id, "", "", ""); !errors.Is(err, ErrInvalidID) {
			t.Errorf("Start(%q) = %v", id, err)
		}
		if err := s.Beat(id, "", ""); !errors.Is(err, ErrInvalidID) {
			t.Errorf("Beat(%q) = %v", id, err)
		}
		if err := s.End(id, "", "", ""); !errors.Is(err, ErrInvalidID) {
			t.Errorf("End(%q) = %v", id, err)
		}
		if err := s.Touch(id); err != nil {
			t.Errorf("Touch(%q) = %v", id, err)
		}
		if _, err := s.State(id); !errors.Is(err, ErrInvalidID) {
			t.Errorf("State(%q) = %v", id, err)
		}
	}
	if _, err := os.Stat(filepath.Dir(s.Log)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("an invalid id created the state dir")
	}
}

// TestSymlinkedLogRefused: a symlink planted at sessions.jsonl is not
// followed; the file it points at stays untouched.
func TestSymlinkedLogRefused(t *testing.T) {
	s := store(t, newClock())
	if err := os.MkdirAll(filepath.Dir(s.Log), 0o700); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("original\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, s.Log); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Start(sid, "", "", "startup"); err == nil {
		t.Fatal("start through a symlinked log succeeded")
	}
	if b, _ := os.ReadFile(victim); string(b) != "original\n" {
		t.Fatalf("victim written: %q", b)
	}
	if _, err := s.State(sid); err == nil {
		t.Fatal("State read through a symlinked log")
	}
}

// TestSymlinkedLiveDirRefused: a live dir that is a symlink is never written
// through, touched through, or listed.
func TestSymlinkedLiveDirRefused(t *testing.T) {
	c := newClock()
	s := store(t, c)
	if err := os.MkdirAll(filepath.Dir(s.Live), 0o700); err != nil {
		t.Fatal(err)
	}
	elsewhere := t.TempDir()
	if err := os.WriteFile(filepath.Join(elsewhere, sid), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	_ = os.Chtimes(filepath.Join(elsewhere, sid), old, old)
	if err := os.Symlink(elsewhere, s.Live); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Start(sid, "", "", "startup"); !errors.Is(err, ErrSymlink) {
		t.Fatalf("Start = %v, want ErrSymlink", err)
	}
	if err := s.Touch(sid); !errors.Is(err, ErrSymlink) {
		t.Fatalf("Touch = %v, want ErrSymlink", err)
	}
	if err := s.End(sid, "", "", "other"); !errors.Is(err, ErrSymlink) {
		t.Fatalf("End = %v, want ErrSymlink", err)
	}
	fi, err := os.Stat(filepath.Join(elsewhere, sid))
	if err != nil || !fi.ModTime().Equal(old) {
		t.Fatalf("target touched or removed: %v %v", fi, err)
	}
	ents, _ := os.ReadDir(elsewhere)
	if len(ents) != 1 {
		t.Fatalf("files created through the symlink: %v", ents)
	}
}

// TestSymlinkedMarkerNotFollowed: a marker that is a symlink is not touched
// through and a start replaces it with a regular file.
func TestSymlinkedMarkerNotFollowed(t *testing.T) {
	c := newClock()
	s := store(t, c)
	if err := os.MkdirAll(s.Live, 0o700); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(t.TempDir(), "victim")
	_ = os.WriteFile(victim, []byte("v"), 0o600)
	old := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	_ = os.Chtimes(victim, old, old)
	m := filepath.Join(s.Live, sid)
	if err := os.Symlink(victim, m); err != nil {
		t.Fatal(err)
	}
	if err := s.Touch(sid); !errors.Is(err, ErrSymlink) {
		t.Fatalf("Touch = %v", err)
	}
	if _, err := s.Start(sid, "", "", "startup"); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Lstat(m)
	if !fi.Mode().IsRegular() {
		t.Fatalf("marker is %v after start", fi.Mode())
	}
	vi, _ := os.Stat(victim)
	if b, _ := os.ReadFile(victim); string(b) != "v" || !vi.ModTime().Equal(old) {
		t.Fatal("victim changed")
	}
}

// TestStateTransitions walks live → idle → live (transcript) → idle → ended
// → live again (resume) with a fake clock.
func TestStateTransitions(t *testing.T) {
	c := newClock()
	s := store(t, c)
	tr := filepath.Join(t.TempDir(), sid+".jsonl")
	if err := os.WriteFile(tr, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := c.t.Add(-time.Hour)
	_ = os.Chtimes(tr, old, old)

	if st, _ := s.State(sid); st != Unknown {
		t.Fatalf("before start: %s", st)
	}
	if _, err := s.Start(sid, tr, "/p", "startup"); err != nil {
		t.Fatal(err)
	}
	check := func(want string) {
		t.Helper()
		if st, err := s.State(sid); err != nil || st != want {
			t.Fatalf("at %v: state %s (%v), want %s", c.t, st, err, want)
		}
	}
	check(Live)
	c.add(LiveWindow - time.Second)
	check(Live)
	c.add(2 * time.Second)
	check(Idle)
	// the transcript was just written: live although the marker is old
	_ = os.Chtimes(tr, c.t.Add(-5*time.Second), c.t.Add(-5*time.Second))
	check(Live)
	s.NoTranscriptStat = true
	check(Idle)
	s.NoTranscriptStat = false
	c.add(TranscriptWindow)
	check(Idle)
	// any hook event touches the marker
	if err := s.Touch(sid); err != nil {
		t.Fatal(err)
	}
	check(Live)
	c.add(time.Second)
	if err := s.End(sid, tr, "/p", "clear"); err != nil {
		t.Fatal(err)
	}
	check(Ended)
	// ended wins over a marker someone recreated by hand
	_ = os.WriteFile(filepath.Join(s.Live, sid), []byte("{}"), 0o600)
	check(Ended)
	// --resume: SessionStart with the same id after the end record
	c.add(time.Second)
	if _, err := s.Start(sid, tr, "/p", "resume"); err != nil {
		t.Fatal(err)
	}
	check(Live)
}

func TestListAndCounts(t *testing.T) {
	c := newClock()
	s := store(t, c)
	_, _ = s.Start("a", "", "/a", "startup")
	c.add(time.Minute)
	_, _ = s.Start("b", "", "/b", "startup")
	c.add(time.Minute)
	_, _ = s.Start("c", "", "/c", "startup")
	_ = s.End("c", "", "/c", "logout")
	c.add(LiveWindow - 30*time.Second) // a is 11.5 min old, b 10.5, c ended
	_ = s.Touch("b")
	// a marker without any record (log rotated away)
	_ = os.WriteFile(filepath.Join(s.Live, "d"), []byte("{}"), 0o600)
	_ = os.Chtimes(filepath.Join(s.Live, "d"), c.t.Add(-time.Hour), c.t.Add(-time.Hour))
	// a leftover temp file is not a session
	_ = os.WriteFile(filepath.Join(s.Live, ".tmp-x-1"), []byte("{}"), 0o600)

	l, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Session{}
	var order []string
	for _, ss := range l {
		got[ss.SessionID] = ss
		order = append(order, ss.SessionID)
	}
	if len(l) != 4 {
		t.Fatalf("list = %+v", l)
	}
	want := map[string]string{"a": Idle, "b": Live, "c": Ended, "d": Idle}
	for id, st := range want {
		if got[id].State != st {
			t.Errorf("%s: %s, want %s", id, got[id].State, st)
		}
	}
	if got["c"].Reason != "logout" || got["c"].Ended == "" || got["a"].Cwd != "/a" || got["a"].Source != "startup" {
		t.Errorf("fields: %+v", got)
	}
	if order[0] != "b" {
		t.Errorf("newest first: %v", order)
	}
	live, idle, ended, unknown := Counts(l)
	if live != 1 || idle != 2 || ended != 1 || unknown != 0 {
		t.Errorf("counts = %d %d %d %d", live, idle, ended, unknown)
	}
}

// TestRotation: past MaxBytes the log moves to .1 and the reader still sees
// both files, so an end record in .1 keeps its session ended.
func TestRotation(t *testing.T) {
	saved := MaxBytes
	MaxBytes = 300
	t.Cleanup(func() { MaxBytes = saved })
	c := newClock()
	s := store(t, c)
	_, _ = s.Start(sid, "", "/p", "startup")
	_ = s.End(sid, "", "/p", "other")
	for i := 0; i < 5; i++ {
		c.add(BeatEvery)
		_ = s.Beat("other-session", "", "/q")
	}
	if _, err := os.Stat(s.Log + ".1"); err != nil {
		t.Fatalf("no rotation: %v", err)
	}
	fi, _ := os.Stat(s.Log)
	if fi.Size() > MaxBytes+200 {
		t.Fatalf("log not rotated: %d bytes", fi.Size())
	}
	if st, _ := s.State("other-session"); st != Live {
		t.Fatalf("other-session = %s", st)
	}
}

// TestRecordNeverHoldsUnknownFields pins the on-disk keys.
func TestRecordKeys(t *testing.T) {
	c := newClock()
	s := store(t, c)
	_, _ = s.Start(sid, "/t", "/p", "startup")
	_ = s.End(sid, "/t", "/p", "other")
	f, _ := os.Open(s.Log)
	defer f.Close()
	sc := bufio.NewScanner(f)
	allowed := map[string]bool{"v": true, "kind": true, "ts": true, "session_id": true, "transcript_path": true, "cwd": true, "source": true, "reason": true, "harness": true}
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatal(err)
		}
		for k := range m {
			if !allowed[k] {
				t.Errorf("unexpected key %q in %s", k, sc.Bytes())
			}
		}
	}
}

// TestOnSessionStartIsNil: the M5.3 extension point does nothing in M5.2.
func TestOnSessionStartIsNil(t *testing.T) {
	if OnSessionStart != nil {
		t.Fatal("OnSessionStart is set")
	}
}
