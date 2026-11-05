//go:build unix

package uistate

import (
	"context"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
	"github.com/Panda-Taps-LLC/watchdeck/internal/uiproof"
	"github.com/Panda-Taps-LLC/watchdeck/internal/userconfig"
)

// Every path is under t.TempDir(); nothing touches the developer's state dir.
func tempPaths(t *testing.T) paths.Paths {
	t.Helper()
	root := t.TempDir()
	return paths.Resolve(filepath.Join(root, "home"), map[string]string{
		"XDG_CONFIG_HOME": filepath.Join(root, "cfg"),
		"XDG_CACHE_HOME":  filepath.Join(root, "cache"),
		"XDG_STATE_HOME":  filepath.Join(root, "state"),
	})
}

func perm(t *testing.T, p string) fs.FileMode {
	t.Helper()
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

func TestStateFile0600(t *testing.T) {
	old := syscall.Umask(0)
	defer syscall.Umask(old)
	p := tempPaths(t)
	if err := WriteState(p, State{PID: 42, Port: 4242, Mode: ModeAuto, Version: "test", Binary: "/x/watchdeck"}); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateToken(p); err != nil {
		t.Fatal(err)
	}
	l, err := TryLock(p)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Release()
	if got := perm(t, p.StateDir); got != 0o700 {
		t.Errorf("state dir %o, want 700", got)
	}
	for _, name := range []string{StateFile, TokenFile, LockFile} {
		if got := perm(t, Path(p, name)); got != 0o600 {
			t.Errorf("%s %o, want 600", name, got)
		}
	}
	st, ok, err := ReadState(p)
	if err != nil || !ok || st.V != 1 || st.PID != 42 || st.Port != 4242 || st.Mode != ModeAuto {
		t.Fatalf("ReadState = %+v %v %v", st, ok, err)
	}
	// rotation keeps 0600
	if _, err := RotateToken(p); err != nil {
		t.Fatal(err)
	}
	if got := perm(t, Path(p, TokenFile)); got != 0o600 {
		t.Errorf("rotated token %o", got)
	}
	// a looser existing dir is tightened
	os.Chmod(p.StateDir, 0o755)
	if err := EnsureDir(p); err != nil || perm(t, p.StateDir) != 0o700 {
		t.Errorf("EnsureDir did not tighten: %v %o", err, perm(t, p.StateDir))
	}
}

func TestFilesRefuseSymlinks(t *testing.T) {
	p := tempPaths(t)
	if err := EnsureDir(p); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "elsewhere")
	os.WriteFile(target, []byte(strings.Repeat("A", 43)+"\n"), 0o600)
	for _, name := range []string{StateFile, TokenFile, LockFile} {
		if err := os.Symlink(target, Path(p, name)); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := ReadState(p); err == nil {
		t.Error("ReadState followed a symlink")
	}
	if _, err := ReadToken(p); err == nil {
		t.Error("ReadToken followed a symlink")
	}
	if _, err := TryLock(p); err == nil {
		t.Error("TryLock followed a symlink")
	}
	// LoadOrCreateToken replaces the link (rename), never writes through it
	if _, err := LoadOrCreateToken(p); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(target); string(b) != strings.Repeat("A", 43)+"\n" {
		t.Fatalf("the link target was written: %q", b)
	}
	if fi, _ := os.Lstat(Path(p, TokenFile)); fi.Mode()&fs.ModeSymlink != 0 {
		t.Fatal("token is still a symlink")
	}
}

func TestStableTokenAcrossRestart(t *testing.T) {
	p := tempPaths(t)
	a, err := LoadOrCreateToken(p)
	if err != nil {
		t.Fatal(err)
	}
	if !validToken(a) {
		t.Fatalf("token %q", a)
	}
	b, err := LoadOrCreateToken(p)
	if err != nil || b != a {
		t.Fatalf("second load %q %v, want %q", b, err, a)
	}
	// a damaged file is replaced, not trusted
	os.WriteFile(Path(p, TokenFile), []byte("short\n"), 0o600)
	c, err := LoadOrCreateToken(p)
	if err != nil || c == a || !validToken(c) {
		t.Fatalf("damaged file: %q %v", c, err)
	}
}

func TestRotateToken(t *testing.T) {
	p := tempPaths(t)
	a, _ := LoadOrCreateToken(p)
	w := NewTokenWatcher(p)
	if w.Token() != a {
		t.Fatal("watcher does not start from the file")
	}
	b, err := RotateToken(p)
	if err != nil || b == a || !validToken(b) {
		t.Fatalf("rotate: %q %v", b, err)
	}
	if got, _ := ReadToken(p); got != b {
		t.Fatalf("file holds %q, want %q", got, b)
	}
	if w.Token() != b {
		t.Fatal("watcher kept the old token after a rotation")
	}
	os.Remove(Path(p, TokenFile))
	if w.Token() != "" {
		t.Fatal("watcher answers a token with the file gone")
	}
}

// TestSecondInstanceExits (lock half): flock is per open file description,
// so a second TryLock, in this process or another, is refused until the
// first is released. The command half is in cmd/watchdeck.
func TestSecondInstanceExits(t *testing.T) {
	p := tempPaths(t)
	a, err := TryLock(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := TryLock(p); !errors.Is(err, ErrLocked) {
		t.Fatalf("second TryLock: %v, want ErrLocked", err)
	}
	if held, err := Locked(p); err != nil || !held {
		t.Fatalf("Locked = %v %v", held, err)
	}
	start := time.Now()
	if _, err := LockOrWait(p, 100*time.Millisecond); !errors.Is(err, ErrLocked) || time.Since(start) < 100*time.Millisecond {
		t.Fatalf("LockOrWait: %v after %s", err, time.Since(start))
	}
	a.Release()
	a.Release() // twice is fine
	b, err := TryLock(p)
	if err != nil {
		t.Fatalf("after release: %v", err)
	}
	b.Release()
	if held, _ := Locked(p); held {
		t.Fatal("Locked after every release")
	}
}

// fakeDashboard answers /api/status the way the real one does: 401 with
// the CSP without the token, 200 with JSON with it.
func fakeDashboard(t *testing.T, token string, sawAuth *atomic.Int32) int {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	self := ln.Addr().(*net.TCPAddr).Port
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" && sawAuth != nil {
			sawAuth.Add(1)
		}
		if r.URL.Path != "/api/status" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Security-Policy", "default-src 'none'")
		if c := r.Header.Get(uiproof.ChallengeHeader); uiproof.ValidChallenge(c) {
			w.Header().Set(uiproof.ProofHeader, uiproof.Proof(token, self, c))
		}
		if r.Header.Get("Authorization") != "Bearer "+token {
			w.WriteHeader(401)
			return
		}
		w.Write([]byte(`{"version":"test","platform":"darwin","mode":"auto","pid":7,"idleMinutes":0}`))
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().(*net.TCPAddr).Port
}

func TestProbe(t *testing.T) {
	tok := strings.Repeat("t", 43)
	port := fakeDashboard(t, tok, nil)
	st, err := Probe(context.Background(), port, tok)
	if err != nil || st.Platform != "darwin" || st.Mode != "auto" {
		t.Fatalf("Probe = %+v %v", st, err)
	}
	if _, err := Probe(context.Background(), port, strings.Repeat("x", 43)); err == nil {
		t.Fatal("Probe accepted a wrong token")
	}
}

// TestProbeNeverSendsTokenToAForeignServer: a port recycled by another
// local service that answers 200 to anyone never sees the bearer.
func TestProbeNeverSendsTokenToAForeignServer(t *testing.T) {
	var saw atomic.Int32
	ln, _ := net.Listen("tcp4", "127.0.0.1:0")
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			saw.Add(1)
		}
		w.Write([]byte(`{"platform":"x"}`))
	})}
	go srv.Serve(ln)
	defer srv.Close()
	if _, err := Probe(context.Background(), ln.Addr().(*net.TCPAddr).Port, strings.Repeat("t", 43)); err == nil {
		t.Fatal("Probe accepted a foreign server")
	}
	if saw.Load() != 0 {
		t.Fatal("the token was sent to a foreign server")
	}
}

func TestProbeTimesOut(t *testing.T) {
	ln, _ := net.Listen("tcp4", "127.0.0.1:0")
	defer ln.Close() // accepts (backlog) but never answers
	start := time.Now()
	if _, err := Probe(context.Background(), ln.Addr().(*net.TCPAddr).Port, strings.Repeat("t", 43)); err == nil {
		t.Fatal("Probe of a silent port succeeded")
	}
	if d := time.Since(start); d > ProbeTimeout+300*time.Millisecond {
		t.Fatalf("Probe took %s", d)
	}
}

// TestStaleStateRecycledPid: ui.json names a live pid (this test's) and a
// port nobody serves, but no process holds ui.lock: nothing is running.
// The pid is never signalled or trusted.
func TestStaleStateRecycledPid(t *testing.T) {
	p := tempPaths(t)
	ln, _ := net.Listen("tcp4", "127.0.0.1:0")
	dead := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	LoadOrCreateToken(p)
	WriteState(p, State{PID: os.Getpid(), Port: dead, Mode: ModeAuto})
	if _, err := Running(context.Background(), p); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("Running = %v, want ErrNotRunning", err)
	}
	// Held lock, same stale ui.json: unhealthy, not running.
	l, _ := TryLock(p)
	defer l.Release()
	if _, err := probeState(context.Background(), p); !errors.Is(err, ErrUnhealthy) {
		t.Fatalf("probeState = %v, want ErrUnhealthy", err)
	}
	// Held lock and a ui.json naming a healthy server: running.
	tok, _ := ReadToken(p)
	port := fakeDashboard(t, tok, nil)
	WriteState(p, State{PID: 7, Port: port, Mode: ModeAuto})
	inst, err := probeState(context.Background(), p)
	if err != nil || inst.URL() != URL(port, tok) {
		t.Fatalf("probeState = %+v %v", inst, err)
	}
}

func TestClearPIDKeepsPort(t *testing.T) {
	p := tempPaths(t)
	WriteState(p, State{PID: 9, Port: 5555})
	ClearPID(p, 8) // someone else's: untouched
	if st, _, _ := ReadState(p); st.PID != 9 {
		t.Fatal("ClearPID cleared another pid")
	}
	ClearPID(p, 9)
	if st, _, _ := ReadState(p); st.PID != 0 || st.Port != 5555 {
		t.Fatalf("after ClearPID: %+v", st)
	}
}

// fakeBinary is a script that records its argv and sleeps; it stands in for
// watchdeck when only the spawn is under test.
func fakeBinary(t *testing.T) (bin, rec string) {
	t.Helper()
	dir := t.TempDir()
	rec = filepath.Join(dir, "argv")
	bin = filepath.Join(dir, "fake-watchdeck")
	script := "#!/bin/sh\necho \"$@\" >> '" + rec + "'\npwd >> '" + rec + "'\nexec sleep 5\n"
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return bin, rec
}

func killLater(t *testing.T, pid int) {
	t.Cleanup(func() { syscall.Kill(pid, syscall.SIGKILL) })
}

// TestEnsureReturnsFast: Ensure is one flock attempt plus one fork/exec; it
// never waits for the server. Budget 50 ms (the SessionStart hook calls it).
func TestEnsureReturnsFast(t *testing.T) {
	p := tempPaths(t)
	bin, rec := fakeBinary(t)
	var best time.Duration
	for i := 0; i < 5; i++ {
		start := time.Now()
		spawned, pid, err := Ensure(p, bin, SpawnOptions{Mode: ModeAuto})
		d := time.Since(start)
		if err != nil || !spawned || pid <= 0 {
			t.Fatalf("Ensure = %v %d %v", spawned, pid, err)
		}
		killLater(t, pid)
		if i == 0 || d < best {
			best = d
		}
		// own session: setsid made it a process-group leader
		if pgid, err := syscall.Getpgid(pid); err == nil && pgid != pid {
			t.Errorf("spawned pid %d in group %d", pid, pgid)
		}
	}
	t.Logf("Ensure (spawn path) best of 5: %s", best)
	if best > 50*time.Millisecond {
		t.Errorf("Ensure took %s, budget 50 ms", best)
	}
	// argv and cwd of the child
	deadline := time.Now().Add(3 * time.Second)
	for {
		b, _ := os.ReadFile(rec)
		if strings.Contains(string(b), "ui --mode auto --no-open\n/\n") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("child argv/cwd: %q", b)
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Lock held: nothing is spawned, and it is faster still.
	l, _ := TryLock(p)
	defer l.Release()
	start := time.Now()
	spawned, _, err := Ensure(p, bin, SpawnOptions{})
	if err != nil || spawned {
		t.Fatalf("held lock: spawned=%v err=%v", spawned, err)
	}
	t.Logf("Ensure (already running): %s", time.Since(start))

	if _, _, err := Ensure(p, "relative/watchdeck", SpawnOptions{}); err == nil {
		t.Fatal("Ensure ran a relative binary")
	}
}

func TestEnsureRunningRespectsAutostart(t *testing.T) {
	p := tempPaths(t)
	bin, rec := fakeBinary(t)
	t.Setenv(AutostartEnv, "")
	// default: never asked → off
	if err := EnsureRunning(p, bin); err != nil {
		t.Fatal(err)
	}
	if err := userconfig.SetAutostartUI(p.ConfigFile(), false); err != nil {
		t.Fatal(err)
	}
	EnsureRunning(p, bin)
	time.Sleep(100 * time.Millisecond)
	if _, err := os.Stat(rec); err == nil {
		t.Fatal("EnsureRunning started a server with autostart off")
	}
	if _, err := os.Stat(Path(p, LockFile)); err == nil {
		t.Fatal("EnsureRunning touched the state dir with autostart off")
	}
	userconfig.SetAutostartUI(p.ConfigFile(), true)
	t.Setenv(AutostartEnv, " OFF ")
	EnsureRunning(p, bin)
	time.Sleep(100 * time.Millisecond)
	if _, err := os.Stat(rec); err == nil {
		t.Fatal("EnsureRunning ignored WATCHDECK_UI_AUTOSTART=off")
	}
	t.Setenv(AutostartEnv, "")
	if !AutostartOn(p, map[string]string{}) {
		t.Fatal("AutostartOn false with ui.autostart: true")
	}
	if err := EnsureRunning(p, bin); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		if b, _ := os.ReadFile(rec); strings.Contains(string(b), "ui --mode auto") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("EnsureRunning did not start the server with autostart on")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
