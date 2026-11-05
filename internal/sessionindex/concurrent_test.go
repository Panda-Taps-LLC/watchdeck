package sessionindex

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// Four Index values updating at once stand in for separate processes: each
// opens meta.json on its own and takes the flock on its own file descriptor.
// While they race, a writer keeps appending to the transcripts. After every
// racing round, before anything could repair the files, meta.json must parse,
// every indexed text file must be exactly text_bytes long, and no prompt may
// appear twice. After a final quiet update every prompt appears exactly once.
func TestConcurrentUpdatesDoNotCorrupt(t *testing.T) {
	e := newEnv(t)
	const n = 60
	paths := make([]string, n)
	for i := 0; i < n; i++ {
		paths[i] = writeSession(t, e.projects, fmt.Sprintf("-p%d", i%3), sid(i), session("/p", fmt.Sprintf("seed%d", i)))
	}
	const rounds = 6
	for r := 0; r < rounds; r++ {
		var wg sync.WaitGroup
		errs := make(chan error, 5)
		for g := 0; g < 4; g++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ix, err := Open(Options{Dir: e.dir, ProjectsDir: e.projects})
				if err == nil {
					_, err = ix.Update()
				}
				errs <- err
			}()
		}
		wg.Add(1)
		go func(r int) { // the transcripts grow during the race
			defer wg.Done()
			for i, p := range paths {
				appendFile(t, p, userPrompt(10+r, "/p", fmt.Sprintf("round%d-session%d-prompt", r, i)))
				bumpMtime(t, p, time.Duration(r+1)*time.Second)
			}
			errs <- nil
		}(r)
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatal(err)
			}
		}
		checkConsistent(t, e, n, r, false)
	}
	ix, _ := e.update(t)
	if got := len(ix.Entries()); got != n {
		t.Fatalf("entries: %d", got)
	}
	checkConsistent(t, e, n, rounds-1, true)
	for i := 0; i < n; i++ {
		en, _ := ix.Get(sid(i))
		if en.Turns != 1+rounds {
			t.Errorf("session %d: turns %d", i, en.Turns)
		}
	}
}

// checkConsistent reads meta.json and the text files as they are on disk.
// exact demands every prompt once; otherwise at most once.
func checkConsistent(t *testing.T, e env, n, round int, exact bool) {
	t.Helper()
	ix := e.open(t)
	for i := 0; i < n; i++ {
		en, ok := ix.Get(sid(i))
		if !ok {
			if exact {
				t.Fatalf("session %d missing", i)
			}
			continue
		}
		text := readText(t, e, sid(i))
		if int64(len(text)) != en.TextBytes {
			t.Fatalf("round %d session %d: text %d bytes, text_bytes %d", round, i, len(text), en.TextBytes)
		}
		want := []string{fmt.Sprintf("please look for seed%d\n", i)}
		for r := 0; r <= round; r++ {
			want = append(want, fmt.Sprintf("round%d-session%d-prompt", r, i))
		}
		for _, w := range want {
			c := strings.Count(text, w)
			if c > 1 || (exact && c != 1) {
				t.Fatalf("round %d session %d: %q %d times", round, i, w, c)
			}
		}
	}
}
