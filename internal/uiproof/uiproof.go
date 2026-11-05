// Package uiproof is the dashboard's proof of identity for health probes
// (M5.3). Before a client sends the bearer token to 127.0.0.1:<port>, it
// sends an unauthenticated request carrying a fresh random challenge; only
// a server that holds the token can answer with
// HMAC-SHA256(token, "watchdeck-probe|<port>|"+challenge), where port is
// the server's own listening port. Anything else on that
// port (a recycled port, a listener a sandboxed script bound while the
// dashboard was down) cannot produce the proof and never sees the bearer.
//
// The server and the client (internal/ui and internal/uistate) share this
// package so the two sides cannot drift. It is init-free.
package uiproof

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strconv"
)

// Header names.
const (
	ChallengeHeader = "X-Watchdeck-Challenge"
	ProofHeader     = "X-Watchdeck-Proof"
)

const (
	challengeBytes = 32
	challengeLen   = 43 // base64url, no padding
	label          = "watchdeck-probe|"
)

// NewChallenge is 32 random bytes, base64url.
func NewChallenge() (string, error) {
	b := make([]byte, challengeBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ValidChallenge reports whether c has the shape NewChallenge makes. A
// server answers only well-formed challenges.
func ValidChallenge(c string) bool {
	if len(c) != challengeLen {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(c)
	return err == nil
}

// Proof is base64url(HMAC-SHA256(token, "watchdeck-probe|<port>|"+challenge)).
// The port binds the proof to the listener that made it: a relay on another
// port that forwards the challenge to the real dashboard gets a proof for
// the dashboard's port, which fails a probe of the relay's port.
func Proof(token string, port int, challenge string) string {
	m := hmac.New(sha256.New, []byte(token))
	m.Write([]byte(label + strconv.Itoa(port) + "|" + challenge))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// Verify checks a proof in constant time. An empty token never verifies.
func Verify(token string, port int, challenge, proof string) bool {
	if token == "" || proof == "" {
		return false
	}
	return hmac.Equal([]byte(Proof(token, port, challenge)), []byte(proof))
}
