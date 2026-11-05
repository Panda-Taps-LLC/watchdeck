package claudesettings

import (
	"bufio"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"testing"
	"time"
)

// Helper-process environment: the marker selects the role, the others carry
// the state dir, the rule id and how long to hold the lock.
const (
	helperEnv      = "WATCHDECK_CLAUDESETTINGS_HELPER"
	helperStateEnv = "WATCHDECK_CLAUDESETTINGS_HELPER_STATE"
	helperRuleEnv  = "WATCHDECK_CLAUDESETTINGS_HELPER_RULE"
	helperHoldEnv  = "WATCHDECK_CLAUDESETTINGS_HELPER_HOLD"
	sharedValue    = "Bash(rm -rf *)"
	sharedPath     = "/fake/settings.json"
)

// TestTransactHelperProcess is not a test: the parent re-executes the test
// binary with helperEnv set. "transact" takes Transact, says "ready", sleeps
// the hold inside fn and appends its rule id to the shared entry; "hold"
// takes the raw lock, says "ready" and sleeps the hold.
func TestTransactHelperProcess(t *testing.T) {
	role := os.Getenv(helperEnv)
	if role == "" {
		return
	}
	dir := os.Getenv(helperStateEnv)
	hold, _ := time.ParseDuration(os.Getenv(helperHoldEnv))
	switch role {
	case "transact":
		err := Transact(dir, func(led *Ledger) error {
			os.Stdout.WriteString("ready\n")
			time.Sleep(hold)
			id := os.Getenv(helperRuleEnv)
			if i := led.find(sharedPath, KeyDeny, sharedValue); i >= 0 {
				led.Entries[i].RuleIDs = append(led.Entries[i].RuleIDs, id)
			} else {
				led.Entries = append(led.Entries, LedgerEntry{Path: sharedPath, Key: KeyDeny, Value: sharedValue, RuleIDs: []string{id}})
			}
			return nil
		})
		if err != nil {
			os.Stderr.WriteString(err.Error() + "\n")
			os.Exit(2)
		}
	case "hold":
		l, err := takeLock(dir, time.Second)
		if err != nil {
			os.Stderr.WriteString(err.Error() + "\n")
			os.Exit(2)
		}
		os.Stdout.WriteString("ready\n")
		time.Sleep(hold)
		l.release()
	}
	os.Exit(0)
}

// startHelper runs the helper and returns once it has printed "ready".
func startHelper(t *testing.T, role, dir, rule string, hold time.Duration) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestTransactHelperProcess$")
	cmd.Env = append(os.Environ(), helperEnv+"="+role, helperStateEnv+"="+dir, helperRuleEnv+"="+rule, helperHoldEnv+"="+hold.String())
	cmd.Stderr = os.Stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	line, err := bufio.NewReader(out).ReadString('\n')
	if err != nil || line != "ready\n" {
		t.Fatalf("helper %s: read %q, %v", rule, line, err)
	}
	return cmd
}

func skipNoLock(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no cross-process lock on Windows")
	}
}

func TestTransactLoadsEditsSaves(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	entry := LedgerEntry{Path: sharedPath, Key: KeyDeny, Value: sharedValue, RuleID: "a", RuleIDs: []string{"a"}, Added: time.Date(2026, 10, 19, 1, 2, 3, 0, time.UTC)}
	if err := Transact(dir, func(led *Ledger) error {
		led.Entries = append(led.Entries, entry)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(dir, LedgerFile))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("ledger mode = %v", fi.Mode().Perm())
	}
	led, err := LoadLedger(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(led.Entries) != 1 || !reflect.DeepEqual(led.Entries[0], entry) {
		t.Fatalf("saved ledger = %+v", led.Entries)
	}

	// fn's error comes back as is, and nothing is saved.
	boom := errors.New("boom")
	err = Transact(dir, func(led *Ledger) error {
		led.Entries = nil
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("Transact error = %v, want fn's", err)
	}
	if led, _ := LoadLedger(dir); len(led.Entries) != 1 {
		t.Fatalf("a failed fn saved: %+v", led.Entries)
	}
	// The lock is released after both: a third Transact does not wait.
	start := time.Now()
	if err := Transact(dir, func(*Ledger) error { return nil }); err != nil || time.Since(start) > time.Second {
		t.Fatalf("third Transact: %v after %v", err, time.Since(start))
	}
}

func TestTransactSerialisesProcesses(t *testing.T) {
	skipNoLock(t)
	dir := filepath.Join(t.TempDir(), "state")
	done := make(chan error, 2)
	for _, id := range []string{"h1", "h2"} {
		go func(id string) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestTransactHelperProcess$")
			cmd.Env = append(os.Environ(), helperEnv+"=transact", helperStateEnv+"="+dir, helperRuleEnv+"="+id, helperHoldEnv+"=200ms")
			out, err := cmd.CombinedOutput()
			if err != nil {
				err = errors.New(id + ": " + err.Error() + ": " + string(out))
			}
			done <- err
		}(id)
	}
	for i := 0; i < 2; i++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	led, err := LoadLedger(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := led.Owners(sharedPath, KeyDeny, sharedValue)
	sort.Strings(got)
	if !reflect.DeepEqual(got, []string{"h1", "h2"}) {
		t.Fatalf("owners = %v, want both helpers' claims (a lost update otherwise)", got)
	}
}

func TestTransactTimesOut(t *testing.T) {
	skipNoLock(t)
	dir := filepath.Join(t.TempDir(), "state")
	startHelper(t, "hold", dir, "holder", 3*time.Second)
	start := time.Now()
	called := false
	err := Transact(dir, func(*Ledger) error { called = true; return nil })
	elapsed := time.Since(start)
	if !errors.Is(err, ErrLockTimeout) {
		t.Fatalf("Transact = %v, want ErrLockTimeout", err)
	}
	if called {
		t.Fatal("fn ran without the lock")
	}
	if elapsed < 1900*time.Millisecond || elapsed > 2500*time.Millisecond {
		t.Fatalf("timed out after %v, want about 2 s", elapsed)
	}
	if fi, err := os.Lstat(filepath.Join(dir, LockFile)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("lock file: %v %v", fi, err)
	}
}

func TestManagedDirOverride(t *testing.T) {
	md := t.TempDir()
	writeFile(t, filepath.Join(md, "managed-settings.json"), "{}\n")
	ManagedDirOverride = func() string { return md }
	t.Cleanup(func() { ManagedDirOverride = nil })
	p := tempPaths(t)
	locs := Locate(p, "")
	if len(locs) != 2 {
		t.Fatalf("Locate = %+v", locs)
	}
	if locs[0] != (Location{Scope: ScopeManaged, Path: filepath.Join(md, "managed-settings.json"), ReadOnly: true}) {
		t.Fatalf("managed = %+v", locs[0])
	}
	for _, l := range locs {
		if l.Scope == ScopeManaged && filepath.Dir(l.Path) != md {
			t.Fatalf("managed location outside the override: %+v", l)
		}
	}
	if locs[1] != userLoc(p) {
		t.Fatalf("user = %+v", locs[1])
	}
}

func TestLockedRunsUnderLock(t *testing.T) {
	skipNoLock(t)
	dir := filepath.Join(t.TempDir(), "state")
	called := false
	if err := Locked(dir, func() error {
		called = true
		// The lock is held: Transact from here would time out.
		if err := Transact(dir, func(*Ledger) error { return nil }); !errors.Is(err, ErrLockTimeout) {
			t.Errorf("nested Transact = %v, want ErrLockTimeout", err)
		}
		return nil
	}); err != nil || !called {
		t.Fatalf("Locked = %v, called %v", err, called)
	}
	if _, err := os.Stat(filepath.Join(dir, LedgerFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Locked wrote a ledger: %v", err)
	}
	if err := Transact(dir, func(*Ledger) error { return nil }); err != nil {
		t.Fatalf("lock not released: %v", err)
	}
}
