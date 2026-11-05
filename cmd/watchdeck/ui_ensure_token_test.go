package main

import (
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/Panda-Taps-LLC/watchdeck/internal/uistate"
)

// TestEnsureNeverPrintsToken: `ui --ensure` runs from /watchdeck:open and
// the mod, whose output reaches the model and the transcript. On every path
// (spawn, already running, opener failing) neither stream carries `#t=` or
// the token; an opener failure exits 1 and says to run watchdeck ui.
func TestEnsureNeverPrintsToken(t *testing.T) {
	bin := testBinary(t)
	newTestEnv(t)
	failing, _ := browserStub(t, 1)
	t.Setenv("BROWSER", failing)

	check := func(name string, code, want int, out, errOut string) {
		t.Helper()
		if strings.Contains(out+errOut, "#t=") {
			t.Fatalf("%s: a launch URL was printed: stdout %q stderr %q", name, out, errOut)
		}
		if code != want {
			t.Fatalf("%s: exit %d, want %d (stderr %q)", name, code, want, errOut)
		}
	}
	// spawn path, opener fails
	code, out, errOut, _ := runBin(t, bin, "ui", "--ensure", "--open")
	check("spawn + failing opener", code, 1, out, errOut)
	if !strings.Contains(errOut, "run `watchdeck ui` in a terminal") {
		t.Fatalf("stderr %q", errOut)
	}
	inst := running(t)
	// running path, opener fails
	code, out, errOut, _ = runBin(t, bin, "ui", "--ensure", "--open")
	check("running + failing opener", code, 1, out, errOut)
	// plain --ensure, both paths
	code, out, errOut, _ = runBin(t, bin, "ui", "--ensure")
	check("plain, running", code, 0, out, errOut)
	if strings.Contains(out+errOut, inst.Token) {
		t.Fatal("token printed")
	}
	runBin(t, bin, "ui", "--stop")
	notRunning(t)
	code, out, errOut, _ = runBin(t, bin, "ui", "--ensure")
	check("plain, spawn", code, 0, out, errOut)
	running(t)
	runBin(t, bin, "ui", "--stop")
}

// TestPortTakenRotatesToken: when the recorded port is held by another
// process, the server listens elsewhere and rotates the token, so a token a
// browser remembered on the old origin is worthless to whatever serves
// there now.
func TestPortTakenRotatesToken(t *testing.T) {
	bin := testBinary(t)
	newTestEnv(t)
	t.Setenv("BROWSER", "/usr/bin/false")
	runBin(t, bin, "ui", "--ensure")
	a := running(t)
	runBin(t, bin, "ui", "--stop")
	notRunning(t)

	squat, err := net.Listen("tcp4", "127.0.0.1:"+strconv.Itoa(a.State.Port))
	if err != nil {
		t.Skipf("could not take port %d: %v", a.State.Port, err)
	}
	defer squat.Close()
	code, _, errOut, _ := runBin(t, bin, "ui", "--ensure")
	if code != 0 {
		t.Fatalf("ensure: %d %q", code, errOut)
	}
	b := running(t)
	if b.State.Port == a.State.Port || b.Token == a.Token {
		t.Fatalf("port %d→%d, token rotated %v", a.State.Port, b.State.Port, a.Token != b.Token)
	}
	hp, _, _ := hostPaths()
	if st, _, _ := uistate.ReadState(hp); st.Port != b.State.Port {
		t.Fatalf("ui.json port %d", st.Port)
	}
	runBin(t, bin, "ui", "--stop")
}
