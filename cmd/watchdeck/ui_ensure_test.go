package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/uistate"
)

// These run the built binary against a temp HOME and XDG dirs
// (newTestEnv); BROWSER is /usr/bin/false or a stub, so no browser opens.
// Every server a test starts is stopped or killed at cleanup.

func runBin(t *testing.T, bin string, args ...string) (int, string, string, time.Duration) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	start := time.Now()
	err := cmd.Run()
	d := time.Since(start)
	code := 0
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("%v: %v", args, err)
	}
	return code, out.String(), errb.String(), d
}

// running waits for the env's dashboard and registers it for cleanup.
func running(t *testing.T) uistate.Instance {
	t.Helper()
	hp, _, err := hostPaths()
	if err != nil {
		t.Fatal(err)
	}
	inst, err := uistate.WaitRunning(context.Background(), hp, 5*time.Second)
	if err != nil {
		t.Fatalf("no dashboard running: %v", err)
	}
	killOnCleanup(t, inst.State.PID)
	return inst
}

func notRunning(t *testing.T) {
	t.Helper()
	hp, _, _ := hostPaths()
	deadline := time.Now().Add(5 * time.Second)
	for {
		held, err := uistate.Locked(hp)
		if err == nil && !held {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the dashboard still holds the lock")
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func statusOf(t *testing.T, inst uistate.Instance, token string) (int, map[string]any) {
	t.Helper()
	resp, body := get(t, uistate.BaseURL(inst.State.Port)+"api/status", token)
	var m map[string]any
	json.Unmarshal(body, &m)
	return resp.StatusCode, m
}

func TestUIEnsureReuseAndStop(t *testing.T) {
	bin := testBinary(t)
	newTestEnv(t)
	t.Setenv("BROWSER", "/usr/bin/false")

	var times []time.Duration
	code, out, errOut, d := runBin(t, bin, "ui", "--ensure")
	if code != 0 || out != "" || !strings.Contains(errOut, "started pid") {
		t.Fatalf("ui --ensure: %d %q %q", code, out, errOut)
	}
	times = append(times, d)
	inst := running(t)
	if inst.Status.Mode != uistate.ModeAuto || inst.Status.IdleMinutes != 0 {
		t.Fatalf("ensure started %+v", inst.Status)
	}
	if code, st := statusOf(t, inst, inst.Token); code != 200 || st["cwd"] != "" {
		t.Fatalf("auto mode status %d %v (cwd must be empty)", code, st)
	}

	// Again: one flock attempt, nothing spawned.
	for i := 0; i < 5; i++ {
		code, out, errOut, d = runBin(t, bin, "ui", "--ensure")
		if code != 0 || out != "" || !strings.Contains(errOut, "already running") {
			t.Fatalf("second ui --ensure: %d %q %q", code, out, errOut)
		}
		times = append(times, d)
	}
	sort.Slice(times, func(i, j int) bool { return times[i] < times[j] })
	t.Logf("watchdeck ui --ensure wall time (process start included): min %s, median %s, max %s", times[0], times[len(times)/2], times[len(times)-1])
	if times[len(times)/2] > 150*time.Millisecond {
		t.Errorf("ui --ensure median %s", times[len(times)/2])
	}

	// A terminal `ui` reuses it: same port, same token, on stdout only.
	code, out, errOut, _ = runBin(t, bin, "ui", "--no-open")
	if code != 0 || strings.TrimSpace(out) != inst.URL() || !strings.Contains(errOut, "already running") || strings.Contains(errOut, inst.Token) {
		t.Fatalf("ui --no-open reuse: %d %q %q", code, out, errOut)
	}
	// --detach too.
	code, out, _, _ = runBin(t, bin, "ui", "--detach", "--no-open")
	if code != 0 || strings.TrimSpace(out) != inst.URL() {
		t.Fatalf("ui --detach reuse: %d %q", code, out)
	}

	code, out, _, _ = runBin(t, bin, "ui", "--stop")
	if code != 0 || !strings.Contains(out, "stopped pid") {
		t.Fatalf("ui --stop: %d %q", code, out)
	}
	notRunning(t)
	code, out, _, _ = runBin(t, bin, "ui", "--stop")
	if code != 0 || !strings.Contains(out, "not running") {
		t.Fatalf("second --stop: %d %q", code, out)
	}
}

// TestUIEnsureOpen: --ensure --open waits for the dashboard and hands the
// tokened URL to the opener; stdout carries no token.
func TestUIEnsureOpen(t *testing.T) {
	bin := testBinary(t)
	newTestEnv(t)
	stub, rec := browserStub(t, 0)
	t.Setenv("BROWSER", stub)
	code, out, errOut, _ := runBin(t, bin, "ui", "--ensure", "--open")
	inst := running(t)
	if code != 0 || out != "watchdeck ui: opened "+uistate.BaseURL(inst.State.Port)+" in your browser\n" {
		t.Fatalf("--ensure --open: %d %q %q", code, out, errOut)
	}
	opened, _ := os.ReadFile(rec)
	if strings.TrimSpace(string(opened)) != inst.URL() {
		t.Fatalf("opener got %q, want the launch URL", opened)
	}
	if strings.Contains(out+errOut, inst.Token) {
		t.Fatal("token printed")
	}
	// already running: opens again, still no token printed
	os.Remove(rec)
	code, out, errOut, _ = runBin(t, bin, "ui", "--ensure", "--open")
	if b, _ := os.ReadFile(rec); code != 0 || strings.TrimSpace(string(b)) != inst.URL() || strings.Contains(out+errOut, inst.Token) {
		t.Fatalf("reuse --ensure --open: %d %q %q opener %q", code, out, errOut, b)
	}
	runBin(t, bin, "ui", "--stop")
}

// TestSecondInstanceExitsCommand: a second server in the same state dir
// exits 0, naming the first, which keeps serving.
func TestSecondInstanceExitsCommand(t *testing.T) {
	bin := testBinary(t)
	newTestEnv(t)
	t.Setenv("BROWSER", "/usr/bin/false")
	first := exec.Command(bin, "ui", "--service")
	if err := first.Start(); err != nil {
		t.Fatal(err)
	}
	killOnCleanup(t, first.Process.Pid)
	inst := running(t)
	if inst.State.PID != first.Process.Pid {
		t.Fatalf("running pid %d, want %d", inst.State.PID, first.Process.Pid)
	}
	code, _, errOut, d := runBin(t, bin, "ui", "--service")
	if code != 0 || !strings.Contains(errOut, "already running") {
		t.Fatalf("second --service: %d %q", code, errOut)
	}
	if d > 4*time.Second {
		t.Errorf("the loser took %s to exit", d)
	}
	if code, _ := statusOf(t, inst, inst.Token); code != 200 {
		t.Fatalf("first instance stopped answering: %d", code)
	}
	runBin(t, bin, "ui", "--stop")
	done := make(chan error, 1)
	go func() { done <- first.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("service exit after --stop: %v (want 0: launchd and systemd restart only on failure)", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("service did not exit after --stop")
	}
}

func TestServiceModeNoIdle(t *testing.T) {
	bin := testBinary(t)
	newTestEnv(t)
	t.Setenv("BROWSER", "/usr/bin/false")
	cmd := exec.Command(bin, "ui", "--service", "--idle", "1")
	var errb bytes.Buffer
	cmd.Stderr = &errb
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	killOnCleanup(t, cmd.Process.Pid)
	inst := running(t)
	code, st := statusOf(t, inst, inst.Token)
	if code != 200 || st["mode"] != "service" || st["idleMinutes"] != float64(0) || st["cwd"] != "" {
		t.Fatalf("service status %d %v", code, st)
	}
	runBin(t, bin, "ui", "--stop")
	cmd.Wait()
	if !strings.Contains(errb.String(), "(service mode, no idle exit)") {
		t.Fatalf("stderr %q", errb.String())
	}
}

// TestStableTokenAndPortAcrossRestart: a restarted dashboard keeps the
// token from ui.token and binds the port ui.json last recorded.
func TestStableTokenAndPortAcrossRestart(t *testing.T) {
	bin := testBinary(t)
	newTestEnv(t)
	t.Setenv("BROWSER", "/usr/bin/false")
	runBin(t, bin, "ui", "--ensure")
	a := running(t)
	runBin(t, bin, "ui", "--stop")
	notRunning(t)
	runBin(t, bin, "ui", "--ensure")
	b := running(t)
	if b.Token != a.Token || b.State.Port != a.State.Port || b.State.PID == a.State.PID {
		t.Fatalf("restart: port %d→%d, same token %v, pid %d→%d", a.State.Port, b.State.Port, a.Token == b.Token, a.State.PID, b.State.PID)
	}
	runBin(t, bin, "ui", "--stop")
}

func TestRotateTokenCommand(t *testing.T) {
	bin := testBinary(t)
	newTestEnv(t)
	t.Setenv("BROWSER", "/usr/bin/false")
	runBin(t, bin, "ui", "--ensure")
	inst := running(t)
	code, out, errOut, _ := runBin(t, bin, "ui", "--rotate-token")
	if code != 0 || strings.Contains(out+errOut, inst.Token) {
		t.Fatalf("--rotate-token: %d %q %q", code, out, errOut)
	}
	hp, _, _ := hostPaths()
	fresh, err := uistate.ReadToken(hp)
	if err != nil || fresh == inst.Token || strings.Contains(out+errOut, fresh) {
		t.Fatalf("new token: %v (printed or unchanged)", err)
	}
	if code, _ := statusOf(t, inst, inst.Token); code != 401 {
		t.Fatalf("old token after rotation: %d, want 401", code)
	}
	if code, _ := statusOf(t, inst, fresh); code != 200 {
		t.Fatalf("new token: %d", code)
	}
	runBin(t, bin, "ui", "--stop")
}

// TestStaleStateRecycledPidCommand: ui.json names a live pid (the test's
// own) and a dead port; --ensure starts a fresh dashboard anyway.
func TestStaleStateRecycledPidCommand(t *testing.T) {
	bin := testBinary(t)
	newTestEnv(t)
	t.Setenv("BROWSER", "/usr/bin/false")
	hp, _, _ := hostPaths()
	ln, _ := net.Listen("tcp4", "127.0.0.1:0")
	dead := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	if _, err := uistate.LoadOrCreateToken(hp); err != nil {
		t.Fatal(err)
	}
	if err := uistate.WriteState(hp, uistate.State{PID: os.Getpid(), Port: dead, Mode: uistate.ModeAuto}); err != nil {
		t.Fatal(err)
	}
	code, _, errOut, _ := runBin(t, bin, "ui", "--ensure")
	if code != 0 || !strings.Contains(errOut, "started pid") {
		t.Fatalf("--ensure over stale state: %d %q", code, errOut)
	}
	inst := running(t)
	if inst.State.PID == os.Getpid() {
		t.Fatal("the stale pid was trusted")
	}
	runBin(t, bin, "ui", "--stop")
}

func TestUIActionFlagsExcludeEachOther(t *testing.T) {
	newTestEnv(t)
	t.Setenv("BROWSER", "/usr/bin/false")
	for _, args := range [][]string{
		{"--ensure", "--stop"},
		{"--detach", "--ensure"},
		{"--service", "--rotate-token"},
		{"--mode", "bogus"},
		{"--mode", "auto", "--stop"},
	} {
		var out, errb bytes.Buffer
		if code := cmdUI(args, &out, &errb); code != 3 {
			t.Errorf("ui %v: exit %d, want 3", args, code)
		}
	}
}
