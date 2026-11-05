//go:build unix

package uistate

import (
	"context"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Panda-Taps-LLC/watchdeck/internal/uiproof"
)

// TestRelayedProofFails: a relay on port P forwards the unauthenticated
// challenge to the real dashboard on port Q and hands back its proof. The
// proof covers Q, so a probe of P rejects it and the relay never receives
// the bearer.
func TestRelayedProofFails(t *testing.T) {
	tok := strings.Repeat("r", 43)
	var realSaw atomic.Int32
	q := fakeDashboard(t, tok, &realSaw)

	var relaySaw atomic.Int32
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := ln.Addr().(*net.TCPAddr).Port
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			relaySaw.Add(1)
			w.Write([]byte(`{"platform":"darwin"}`))
			return
		}
		req, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:"+strconv.Itoa(q)+"/api/status", nil)
		req.Header.Set(uiproof.ChallengeHeader, r.Header.Get(uiproof.ChallengeHeader))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			w.WriteHeader(502)
			return
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		for _, h := range []string{"Content-Security-Policy", uiproof.ProofHeader} {
			w.Header().Set(h, resp.Header.Get(h))
		}
		w.WriteHeader(resp.StatusCode)
	})}
	go srv.Serve(ln)
	defer srv.Close()

	if _, err := Probe(context.Background(), p, tok); err == nil {
		t.Fatal("Probe accepted a proof relayed from another port")
	}
	if relaySaw.Load() != 0 {
		t.Fatal("the relay received the bearer")
	}
	// the real dashboard on Q still passes
	if _, err := Probe(context.Background(), q, tok); err != nil {
		t.Fatalf("direct probe of Q: %v", err)
	}
}
