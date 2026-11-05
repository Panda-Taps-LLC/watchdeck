//go:build unix

package hook

import (
	"bytes"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"
)

// TestWatchdogSpawnsIndexBuild (M6.1 verifier note b): when the watchdog
// fires while the call is loading the index, a detached `watchdeck index`
// is started once (in the call's cwd), and not again within a minute; when
// it fires elsewhere, nothing is spawned.
func TestWatchdogSpawnsIndexBuild(t *testing.T) {
	f := newFx(t)
	oldT, oldSpawn := DecideTimeout, spawnIndex
	DecideTimeout = 50 * time.Millisecond
	var mu sync.Mutex
	var spawned []string
	spawnIndex = func(cwd string) error { mu.Lock(); spawned = append(spawned, cwd); mu.Unlock(); return nil }
	release := make(chan struct{})
	var wg sync.WaitGroup
	t.Cleanup(func() {
		close(release)
		wg.Wait()
		testDelay = nil
		DecideTimeout, spawnIndex = oldT, oldSpawn
		testDelayEnv = nil
	})
	// Each abandoned call stops at release (runtime.Goexit), so it never goes
	// on to write into the test's temp dirs after the test ends.
	wg.Add(3)
	testDelayEnv = func(e Env) { defer wg.Done(); e.loading.Store(true); <-release; runtime.Goexit() }
	var out bytes.Buffer
	runHook(t, f.env, f.in("git status"), &out)
	runHook(t, f.env, f.in("git status"), &out)
	mu.Lock()
	got := append([]string(nil), spawned...)
	mu.Unlock()
	if len(got) != 1 || got[0] != f.cwd {
		t.Fatalf("spawned %v, want one build in %s", got, f.cwd)
	}
	if !bytes.Contains(out.Bytes(), []byte(SlowReason)) {
		t.Fatalf("no ask: %s", out.String())
	}

	// not loading the index: no spawn
	testDelayEnv = nil
	testDelay = func() { defer wg.Done(); <-release; runtime.Goexit() }
	g := newFx(t)
	runHook(t, g.env, g.in("git status"), &out)
	mu.Lock()
	defer mu.Unlock()
	if len(spawned) != 1 {
		t.Fatalf("spawned outside an index load: %v", spawned)
	}
}

// TestIndexCmdDetached: the child is this binary's `index`, in its own
// session, with no stdio inherited.
func TestIndexCmdDetached(t *testing.T) {
	c := indexCmd("/bin/watchdeck", "/proj")
	if c.Path != "/bin/watchdeck" || len(c.Args) != 2 || c.Args[1] != "index" || c.Dir != "/proj" ||
		c.SysProcAttr == nil || !c.SysProcAttr.Setsid || c.Stdin != nil || c.Stdout != nil || c.Stderr != nil {
		t.Fatalf("cmd: %+v", c)
	}
	_ = os.Getpid
}
