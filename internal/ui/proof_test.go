package ui

import (
	"strconv"
	"testing"

	"github.com/Panda-Taps-LLC/watchdeck/internal/uiproof"
)

// TestProbeProof: an unauthenticated GET /api/status with a well-formed
// challenge gets a 401 carrying HMAC(token, challenge); nothing else does.
func TestProbeProof(t *testing.T) {
	ts := startServer(t, emptyOptions(t))
	c, _ := uiproof.NewChallenge()
	resp, _ := ts.do(t, req{Path: "/api/status", Header: map[string]string{uiproof.ChallengeHeader: c}})
	if resp.StatusCode != 401 || !uiproof.Verify(ts.s.Token(), atoi(ts.port), c, resp.Header.Get(uiproof.ProofHeader)) {
		t.Fatalf("status %d, proof %q", resp.StatusCode, resp.Header.Get(uiproof.ProofHeader))
	}
	for _, q := range []req{
		{Path: "/api/status", Header: map[string]string{uiproof.ChallengeHeader: "short"}},
		{Path: "/api/status"},
		{Path: "/api/skills", Header: map[string]string{uiproof.ChallengeHeader: c}},
		{Path: "/api/status", Host: "evil.example:" + ts.port, Header: map[string]string{uiproof.ChallengeHeader: c}},
	} {
		resp, _ := ts.do(t, q)
		if resp.Header.Get(uiproof.ProofHeader) != "" {
			t.Errorf("%+v answered a proof", q)
		}
	}
}

func atoi(s string) int { n, _ := strconv.Atoi(s); return n }
