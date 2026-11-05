package lifecycle

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unicode/utf8"
)

// TestFIFONeverBlocks: a FIFO planted at a marker, the log, its .1 or the
// lock is refused at once (O_NONBLOCK + regular-file check), never waited on.
func TestFIFONeverBlocks(t *testing.T) {
	for _, where := range []string{"marker", "log", "log.1", "lock"} {
		t.Run(where, func(t *testing.T) {
			c := newClock()
			s := store(t, c)
			if err := os.MkdirAll(s.Live, 0o700); err != nil {
				t.Fatal(err)
			}
			p := map[string]string{"marker": filepath.Join(s.Live, sid), "log": s.Log, "log.1": s.Log + ".1", "lock": s.Log + ".lock"}[where]
			if err := syscall.Mkfifo(p, 0o600); err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			go func() {
				defer close(done)
				_ = s.Beat(sid, "", "/p")
				c.add(BeatEvery)
				_ = s.Beat(sid, "", "/p")
				_, _ = s.Start(sid, "", "/p", "startup")
				_ = s.Touch(sid)
				_, _ = s.State(sid)
				_, _ = s.List()
				_ = s.End(sid, "", "/p", "other")
			}()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatalf("blocked on a FIFO at the %s", where)
			}
		})
	}
}

// TestFutureMtimeIsNotLive: a marker mtime more than a minute ahead is idle,
// not live forever; a small skew still counts as live.
func TestFutureMtimeIsNotLive(t *testing.T) {
	c := newClock()
	s := store(t, c)
	if _, err := s.Start(sid, "", "/p", "startup"); err != nil {
		t.Fatal(err)
	}
	m := filepath.Join(s.Live, sid)
	_ = os.Chtimes(m, c.t.Add(30*time.Second), c.t.Add(30*time.Second))
	if st, _ := s.State(sid); st != Live {
		t.Fatalf("30 s ahead: %s, want live", st)
	}
	_ = os.Chtimes(m, c.t.Add(24*time.Hour), c.t.Add(24*time.Hour))
	if st, _ := s.State(sid); st != Idle {
		t.Fatalf("a day ahead: %s, want idle", st)
	}
}

// TestFieldsCapped: transcript_path and cwd are cut to 4 KiB on a UTF-8
// boundary in the record and the marker.
func TestFieldsCapped(t *testing.T) {
	s := store(t, newClock())
	long := "/" + strings.Repeat("é", 5000)
	r, err := s.Start(sid, long, long, "startup")
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Transcript) > maxField || len(r.Cwd) > maxField || !utf8.ValidString(r.Transcript) || !utf8.ValidString(r.Cwd) {
		t.Fatalf("lengths %d %d", len(r.Transcript), len(r.Cwd))
	}
	if fi, _ := os.Stat(s.Log); fi.Size() > 3*maxField {
		t.Fatalf("log line is %d bytes", fi.Size())
	}
	if mk, ok := s.readMarker(sid); !ok || len(mk.Transcript) > maxField {
		t.Fatalf("marker %v, %d bytes", ok, len(mk.Transcript))
	}
}

// TestStartPrunesOldTmp: a live/.tmp-* left by a killed hook is removed by a
// later Start once it is over an hour old; a fresh one is kept.
func TestStartPrunesOldTmp(t *testing.T) {
	c := newClock()
	s := store(t, c)
	if err := os.MkdirAll(s.Live, 0o700); err != nil {
		t.Fatal(err)
	}
	old := filepath.Join(s.Live, ".tmp-x-old")
	fresh := filepath.Join(s.Live, ".tmp-x-fresh")
	for _, p := range []string{old, fresh} {
		_ = os.WriteFile(p, []byte("{}"), 0o600)
	}
	_ = os.Chtimes(old, c.t.Add(-2*time.Hour), c.t.Add(-2*time.Hour))
	_ = os.Chtimes(fresh, c.t.Add(-time.Minute), c.t.Add(-time.Minute))
	if _, err := s.Start(sid, "", "/p", "startup"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(old); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("old tmp kept")
	}
	if _, err := os.Lstat(fresh); err != nil {
		t.Fatal("fresh tmp removed")
	}
}

// TestConcurrentRotationLosesNothing: appenders racing past MaxBytes rotate
// once, under the lock. Without the lock a second rename moved the fresh
// file over the rotated one and records were lost.
func TestConcurrentRotationLosesNothing(t *testing.T) {
	saved := MaxBytes
	MaxBytes = 18 << 10 // ~160 records of ~140 bytes (harness field included) rotate exactly once
	t.Cleanup(func() { MaxBytes = saved })
	s := store(t, nil)
	const workers, each = 8, 20
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < each; i++ {
				if err := s.append(s.record(KindBeat, sid, "", "/p", time.Now())); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
	if n := len(records(t, s)); n != workers*each {
		t.Fatalf("%d records across sessions.jsonl and .1, want %d", n, workers*each)
	}
	if _, err := os.Stat(s.Log + ".1"); err != nil {
		t.Fatalf("no rotation: %v", err)
	}
	fi, err := os.Stat(s.Log + ".lock")
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("lock = %v, %v", fi, err)
	}
}
