//go:build unix

package uistate

import (
	"context"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/uiproof"
)

// mimic answers exactly like the dashboard's guard without the token: 401
// with the CSP to an unauthenticated request (and a made-up proof header),
// 200 with JSON to any bearer. It counts every bearer it receives.
func mimic(t *testing.T, saw *atomic.Int32) int {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'none'")
		if a := r.Header.Get("Authorization"); a != "" {
			saw.Add(1)
			w.Write([]byte(`{"platform":"darwin","mode":"auto","pid":1}`))
			return
		}
		w.Header().Set(uiproof.ProofHeader, uiproof.Proof("a guessed token", 0, r.Header.Get(uiproof.ChallengeHeader)))
		w.WriteHeader(401)
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().(*net.TCPAddr).Port
}

// TestMimicNeverReceivesBearer: a look-alike that answers 401+CSP and then
// 200 to any bearer (what a sandboxed script with network: localhost could
// bind while the dashboard is down) never gets the token: from Probe,
// Running, WaitRunning or Stop.
func TestMimicNeverReceivesBearer(t *testing.T) {
	var saw atomic.Int32
	port := mimic(t, &saw)
	tok := strings.Repeat("t", 43)
	if _, err := Probe(context.Background(), port, tok); err == nil {
		t.Fatal("Probe accepted the mimic")
	}

	p := tempPaths(t)
	LoadOrCreateToken(p)
	WriteState(p, State{PID: 4242, Port: port, Mode: ModeAuto})
	l, err := TryLock(p) // a live lock holder, as if a real server ran
	if err != nil {
		t.Fatal(err)
	}
	defer l.Release()
	// Locked() from this process sees the lock as held (another open file).
	if _, err := Running(context.Background(), p); err != ErrUnhealthy {
		t.Fatalf("Running = %v, want ErrUnhealthy", err)
	}
	if _, err := WaitRunning(context.Background(), p, 200*time.Millisecond); err == nil {
		t.Fatal("WaitRunning accepted the mimic")
	}
	if _, err := Stop(context.Background(), p, 100*time.Millisecond); err == nil {
		t.Fatal("Stop talked to the mimic")
	}
	if n := saw.Load(); n != 0 {
		t.Fatalf("the mimic received the bearer %d times", n)
	}
}

// TestStartingServerHidesOldPort: while a server starts it holds the lock
// and has replaced ui.json with port 0 (MarkStarting), so a concurrent
// Running never probes the old port, whatever listens there now.
func TestStartingServerHidesOldPort(t *testing.T) {
	var saw atomic.Int32
	port := mimic(t, &saw)
	p := tempPaths(t)
	LoadOrCreateToken(p)
	WriteState(p, State{PID: 4242, Port: port, Mode: ModeAuto})
	l, err := TryLock(p)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Release()
	if err := MarkStarting(p, 77, ModeAuto); err != nil {
		t.Fatal(err)
	}
	st, _, _ := ReadState(p)
	if st.PID != 77 || st.Port != 0 || st.LastPort != port {
		t.Fatalf("starting state %+v", st)
	}
	if _, err := Running(context.Background(), p); err != ErrUnhealthy {
		t.Fatalf("Running = %v, want ErrUnhealthy", err)
	}
	if saw.Load() != 0 {
		t.Fatal("a probe reached the old port")
	}
	if HintPort(st) != port {
		t.Fatalf("HintPort = %d", HintPort(st))
	}
}

func TestProofHeaderOnlyForWellFormedChallenge(t *testing.T) {
	c, _ := uiproof.NewChallenge()
	if !uiproof.ValidChallenge(c) || uiproof.ValidChallenge("short") || uiproof.ValidChallenge(strings.Repeat("!", 43)) {
		t.Fatal("ValidChallenge")
	}
	tok := strings.Repeat("k", 43)
	pr := uiproof.Proof(tok, 4000, c)
	if !uiproof.Verify(tok, 4000, c, pr) || uiproof.Verify(tok, 4001, c, pr) || uiproof.Verify(tok, 4000, c, tamper(pr)) || uiproof.Verify("", 4000, c, pr) || uiproof.Verify(tok+"x", 4000, c, pr) {
		t.Fatal("Verify")
	}
}

// tamper changes the last character of a base64url proof to a different one.
func tamper(p string) string {
	last := p[len(p)-1]
	if last == 'A' {
		return p[:len(p)-1] + "B"
	}
	return p[:len(p)-1] + "A"
}
