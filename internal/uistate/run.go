package uistate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
	"github.com/Panda-Taps-LLC/watchdeck/internal/uiproof"
	"github.com/Panda-Taps-LLC/watchdeck/internal/userconfig"
)

// Errors.
var (
	// ErrLocked: another process holds ui.lock (a server runs or starts).
	ErrLocked = errors.New("uistate: another watchdeck ui holds the lock")
	// ErrNotRunning: no process holds ui.lock.
	ErrNotRunning = errors.New("uistate: no dashboard is running")
	// ErrUnhealthy: ui.lock is held but the server did not answer an
	// authenticated GET /api/status within ProbeTimeout.
	ErrUnhealthy = errors.New("uistate: a dashboard holds the lock but does not answer")
)

// ProbeTimeout bounds one health probe (both requests).
const ProbeTimeout = 500 * time.Millisecond

// AutostartEnv turns EnsureRunning off when set to "off".
const AutostartEnv = "WATCHDECK_UI_AUTOSTART"

// Status is the part of GET /api/status a probe keeps.
type Status struct {
	Version       string `json:"version"`
	Platform      string `json:"platform"`
	Mode          string `json:"mode"`
	PID           int    `json:"pid"`
	NoTranscripts bool   `json:"noTranscripts"`
	IdleMinutes   int    `json:"idleMinutes"`
}

// Instance is a healthy running server.
type Instance struct {
	State  State
	Status Status
	Token  string
}

// URL is the instance's launch URL, token included.
func (i Instance) URL() string { return URL(i.State.Port, i.Token) }

// client never uses a proxy and never keeps a connection: the bearer goes
// to 127.0.0.1 only.
func client() *http.Client {
	return &http.Client{
		Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// Probe asks the server on 127.0.0.1:port whether it is a healthy
// watchdeck dashboard holding token. Whatever else listens on that port
// (a recycled port, a look-alike bound by a sandboxed script) must not
// receive the token, so the probe first sends an unauthenticated GET
// /api/status with a fresh random challenge (uiproof) and requires a 401
// with the dashboard's CSP and a valid HMAC(token, challenge) proof,
// checked in constant time. Only then does it repeat the request with the
// bearer and require 200 and a JSON body naming a
// platform. Both requests share ProbeTimeout.
func Probe(ctx context.Context, port int, token string) (Status, error) {
	if port <= 0 || port > 65535 {
		return Status{}, fmt.Errorf("uistate: port %d out of range", port)
	}
	ctx, cancel := context.WithTimeout(ctx, ProbeTimeout)
	defer cancel()
	c := client()
	url := "http://127.0.0.1:" + strconv.Itoa(port) + "/api/status"

	challenge, err := uiproof.NewChallenge()
	if err != nil {
		return Status{}, err
	}
	get := func(auth bool) (*http.Response, []byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, nil, err
		}
		if auth {
			req.Header.Set("Authorization", "Bearer "+token)
		} else {
			req.Header.Set(uiproof.ChallengeHeader, challenge)
		}
		resp, err := c.Do(req)
		if err != nil {
			return nil, nil, err
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return resp, b, err
	}

	resp, _, err := get(false)
	if err != nil {
		return Status{}, err
	}
	if resp.StatusCode != http.StatusUnauthorized || !strings.HasPrefix(resp.Header.Get("Content-Security-Policy"), "default-src 'none'") {
		return Status{}, fmt.Errorf("uistate: 127.0.0.1:%d is not a watchdeck dashboard", port)
	}
	// Only a server holding the token can answer the challenge; anything
	// else never receives the bearer.
	if !uiproof.Verify(token, port, challenge, resp.Header.Get(uiproof.ProofHeader)) {
		return Status{}, fmt.Errorf("uistate: 127.0.0.1:%d did not prove it holds the token", port)
	}
	resp, body, err := get(true)
	if err != nil {
		return Status{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return Status{}, fmt.Errorf("uistate: the dashboard on 127.0.0.1:%d refused the token (%d)", port, resp.StatusCode)
	}
	var st Status
	if err := json.Unmarshal(body, &st); err != nil || st.Platform == "" {
		return Status{}, fmt.Errorf("uistate: the dashboard on 127.0.0.1:%d sent an unexpected status", port)
	}
	return st, nil
}

// Locked reports whether a process holds ui.lock. It takes and drops the
// lock when free, so it must not be called by the process holding it.
func Locked(p paths.Paths) (bool, error) {
	// No lock file: nothing ever ran here, and nothing is created.
	if _, err := os.Lstat(Path(p, LockFile)); errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	l, err := TryLock(p)
	if errors.Is(err, ErrLocked) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	l.Release()
	return false, nil
}

// Running returns the healthy running instance: ui.lock held, ui.json and
// ui.token readable, and Probe passing. ErrNotRunning when the lock is
// free, ErrUnhealthy when it is held but the probe fails.
func Running(ctx context.Context, p paths.Paths) (Instance, error) {
	held, err := Locked(p)
	if err != nil {
		return Instance{}, err
	}
	if !held {
		return Instance{}, ErrNotRunning
	}
	return probeState(ctx, p)
}

// probeState probes the instance ui.json names, whoever holds the lock.
func probeState(ctx context.Context, p paths.Paths) (Instance, error) {
	st, ok, err := ReadState(p)
	if err != nil || !ok || st.PID == 0 || st.Port == 0 {
		return Instance{}, ErrUnhealthy
	}
	tok, err := ReadToken(p)
	if err != nil {
		return Instance{}, ErrUnhealthy
	}
	s, err := Probe(ctx, st.Port, tok)
	if err != nil {
		return Instance{}, ErrUnhealthy
	}
	return Instance{State: st, Status: s, Token: tok}, nil
}

// WaitRunning polls Running until it succeeds or timeout passes. A server
// that was just spawned holds the lock before it listens, so ErrUnhealthy
// and ErrNotRunning are retried; the last error is returned.
func WaitRunning(ctx context.Context, p paths.Paths, timeout time.Duration) (Instance, error) {
	deadline := time.Now().Add(timeout)
	for {
		inst, err := Running(ctx, p)
		if err == nil || time.Now().After(deadline) || ctx.Err() != nil {
			return inst, err
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// LockOrWait is the server's start: it takes ui.lock, retrying for up to
// wait while another process holds it (a Locked check holds it for a
// moment). ErrLocked after that means a server runs.
func LockOrWait(p paths.Paths, wait time.Duration) (*Lock, error) {
	deadline := time.Now().Add(wait)
	for {
		l, err := TryLock(p)
		if !errors.Is(err, ErrLocked) || time.Now().After(deadline) {
			return l, err
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// SpawnOptions are the flags of a background server started by Ensure.
type SpawnOptions struct {
	Mode          string // ModeAuto (default) or ModeManual
	NoTranscripts bool
	Env           []string // nil: this process's environment
}

// Args is the argv (after the binary) Ensure runs.
func (o SpawnOptions) Args() []string {
	mode := o.Mode
	if mode == "" {
		mode = ModeAuto
	}
	args := []string{"ui", "--mode", mode, "--no-open"}
	if o.NoTranscripts {
		args = append(args, "--no-transcripts")
	}
	return args
}

// Ensure starts a background server unless one holds ui.lock. It never
// waits for the server and never probes it: one flock attempt, then, when
// the lock was free, one fork/exec of binary (absolute) in its own session
// with stdio on /dev/null and "/" as its working directory. The spawned
// server takes the lock itself; of two racing spawns the loser exits 0.
// spawned is false when a server already held the lock.
func Ensure(p paths.Paths, binary string, o SpawnOptions) (spawned bool, pid int, err error) {
	if !filepath.IsAbs(binary) {
		return false, 0, fmt.Errorf("uistate: binary %q is not an absolute path", binary)
	}
	held, err := Locked(p)
	if err != nil {
		return false, 0, err
	}
	if held {
		return false, 0, nil
	}
	pid, err = spawn(binary, o.Args(), o.Env)
	if err != nil {
		return false, 0, err
	}
	return true, pid, nil
}

// AutostartOn reports whether the dashboard should start with each Claude
// Code session: not when WATCHDECK_UI_AUTOSTART=off (environ), and only
// when config.yaml says ui.autostart: true. The default, before `setup`
// asked, is off.
func AutostartOn(p paths.Paths, environ map[string]string) bool {
	if strings.EqualFold(strings.TrimSpace(environ[AutostartEnv]), "off") {
		return false
	}
	cfg, err := userconfig.Load(p.ConfigFile())
	if err != nil {
		return false
	}
	on, _ := cfg.AutostartUI()
	return on
}

// EnsureRunning is the SessionStart hook's entry point (cmd/watchdeck/hookcmd.go):
// when autostart is on (AutostartOn, with this process's environment) it
// calls Ensure in auto mode. It is fast and never blocks on the server: one
// config read, one flock attempt, at most one fork/exec. Autostart off is
// not an error.
func EnsureRunning(p paths.Paths, binary string) error {
	if !AutostartOn(p, paths.EnvMap(os.Environ())) {
		return nil
	}
	_, _, err := Ensure(p, binary, SpawnOptions{Mode: ModeAuto, Env: DaemonEnv(os.Environ())})
	return err
}

// DaemonEnv keeps only the variables a long-lived dashboard needs from the
// environment of the session that started it, so session-scoped values
// (API keys, CLAUDE_* session variables) do not outlive the session in a
// daemon.
func DaemonEnv(environ []string) []string {
	out := []string{} // never nil: a nil Env would make spawn inherit everything
	for _, kv := range environ {
		k, _, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		switch {
		case k == "PATH", k == "HOME", k == "USER", k == "LOGNAME", k == "SHELL",
			k == "TMPDIR", k == "LANG", k == "TZ", k == "BROWSER", k == "CLAUDE_CONFIG_DIR",
			strings.HasPrefix(k, "LC_"), strings.HasPrefix(k, "XDG_"), strings.HasPrefix(k, "WATCHDECK_"):
			out = append(out, kv)
		}
	}
	return out
}

// Stop asks the running server to shut down: GET /api/shutdown for a
// nonce, then POST it with the dashboard's own Origin, as the page would.
// It waits up to wait for ui.lock to be released. ErrNotRunning when none
// runs.
func Stop(ctx context.Context, p paths.Paths, wait time.Duration) (Instance, error) {
	inst, err := Running(ctx, p)
	if err != nil {
		return inst, err
	}
	base := "http://127.0.0.1:" + strconv.Itoa(inst.State.Port)
	c := client()
	c.Timeout = 5 * time.Second
	do := func(method, path string, body []byte) (int, []byte, error) {
		req, err := http.NewRequestWithContext(ctx, method, base+path, bytes.NewReader(body))
		if err != nil {
			return 0, nil, err
		}
		req.Header.Set("Authorization", "Bearer "+inst.Token)
		if method != http.MethodGet {
			req.Header.Set("Origin", base)
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := c.Do(req)
		if err != nil {
			return 0, nil, err
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return resp.StatusCode, b, nil
	}
	code, b, err := do(http.MethodGet, "/api/shutdown", nil)
	if err != nil {
		return inst, err
	}
	var v struct {
		Nonce string `json:"nonce"`
	}
	if code != http.StatusOK || json.Unmarshal(b, &v) != nil || v.Nonce == "" {
		return inst, fmt.Errorf("uistate: the dashboard refused GET /api/shutdown (%d)", code)
	}
	req, _ := json.Marshal(map[string]string{"nonce": v.Nonce})
	code, _, err = do(http.MethodPost, "/api/shutdown", req)
	if err != nil {
		return inst, err
	}
	if code != http.StatusAccepted {
		return inst, fmt.Errorf("uistate: the dashboard refused POST /api/shutdown (%d)", code)
	}
	deadline := time.Now().Add(wait)
	for {
		held, err := Locked(p)
		if err != nil {
			return inst, err
		}
		if !held {
			return inst, nil
		}
		if time.Now().After(deadline) {
			return inst, fmt.Errorf("uistate: pid %d accepted the shutdown but still holds the lock after %s", inst.State.PID, wait)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// TokenWatcher serves the current contents of ui.token to a running server
// (ui.Options.TokenSource). It re-reads the file only when it changed (a
// different file, size or mtime), so `ui --rotate-token` takes effect on the
// next request. When the file cannot be read it answers "", which refuses
// every request.
type TokenWatcher struct {
	p    paths.Paths
	mu   sync.Mutex
	tok  string
	last os.FileInfo
}

// NewTokenWatcher starts from the file as it is now.
func NewTokenWatcher(p paths.Paths) *TokenWatcher {
	w := &TokenWatcher{p: p}
	w.Token()
	return w
}

// Token is the current token, or "" when ui.token is unreadable.
func (w *TokenWatcher) Token() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	fi, err := os.Lstat(Path(w.p, TokenFile))
	if err != nil || !fi.Mode().IsRegular() {
		w.tok, w.last = "", nil
		return ""
	}
	if w.last != nil && os.SameFile(w.last, fi) && fi.Size() == w.last.Size() && fi.ModTime().Equal(w.last.ModTime()) {
		return w.tok
	}
	t, err := ReadToken(w.p)
	if err != nil {
		w.tok, w.last = "", nil
		return ""
	}
	w.tok, w.last = t, fi
	return t
}
