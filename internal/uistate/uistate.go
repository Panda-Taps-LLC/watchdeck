// Package uistate keeps the always-on dashboard's state on disk (M5.3):
//
//	<stateDir>/ui.json   0600  {v, pid, port, started, version, binary, mode, no_transcripts}
//	<stateDir>/ui.token  0600  32 random bytes, base64url; created once, reused, replaced by RotateToken
//	<stateDir>/ui.lock   0600  flock(LOCK_EX|LOCK_NB) held by the server for its lifetime
//
// The lock, not ui.json, says whether a server runs: the kernel drops a
// flock when its holder dies, so a stale ui.json naming a recycled pid
// never counts. Whether that server is healthy is decided by an
// authenticated GET /api/status (Probe), never by kill(pid, 0).
//
// The state dir is created 0700 (an existing looser one is tightened);
// every open of a file in it uses O_NOFOLLOW. The dir is also denied to
// sandboxed skill scripts by `run` (internal/runner), so a script cannot
// read the token.
//
// The package is init-free: nothing happens until a function is called.
package uistate

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"

	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
)

// File names under paths.Paths.StateDir.
const (
	StateFile = "ui.json"
	TokenFile = "ui.token"
	LockFile  = "ui.lock"
	LogFile   = "ui.log" // the service's stdout and stderr (internal/service)
)

// Modes a server runs in.
const (
	ModeManual  = "manual"  // `watchdeck ui` from a terminal: idle exit, the terminal's cwd
	ModeAuto    = "auto"    // started by `ui --ensure` or the SessionStart hook: no idle exit, no cwd
	ModeService = "service" // started by launchd or systemd (`ui --service`): no idle exit, no cwd
)

// ValidMode reports whether m is one of the three modes.
func ValidMode(m string) bool {
	return m == ModeManual || m == ModeAuto || m == ModeService
}

const (
	stateVersion  = 1
	tokenBytes    = 32
	tokenLen      = 43 // base64url of 32 bytes, no padding
	maxStateBytes = 64 << 10
)

// State is ui.json.
type State struct {
	V             int    `json:"v"`
	PID           int    `json:"pid"`
	Port          int    `json:"port"`
	Started       string `json:"started"` // RFC 3339
	Version       string `json:"version"`
	Binary        string `json:"binary"`
	Mode          string `json:"mode"`
	NoTranscripts bool   `json:"no_transcripts"`
	// LastPort is the port to try first on the next start. While a server
	// starts, ui.json says {pid: self, port: 0, last_port: N}, so no probe
	// goes to the old port before the new server listens (MarkStarting).
	LastPort int `json:"last_port,omitempty"`
}

// Path is the file name under the state dir.
func Path(p paths.Paths, name string) string { return filepath.Join(p.StateDir, name) }

// EnsureDir creates the state dir 0700, tightening an existing one.
func EnsureDir(p paths.Paths) error {
	dir := p.StateDir
	if dir == "" || !filepath.IsAbs(dir) {
		return fmt.Errorf("uistate: the state dir %q is not absolute", dir)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("uistate: %s is not a directory", dir)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return os.Chmod(dir, 0o700)
	}
	return nil
}

// readSmall reads a regular file without following a symlink at its last
// element, refusing anything over limit bytes.
func readSmall(path string, limit int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|oNoFollow, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("uistate: %s is not a regular file", path)
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("uistate: %s is over %d bytes", path, limit)
	}
	return b, nil
}

// writeAtomic writes b to a fresh 0600 temp file in the state dir and
// renames it over name. A rename replaces a symlink at name; it never
// writes through it.
func writeAtomic(p paths.Paths, name string, b []byte) error {
	if err := EnsureDir(p); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(p.StateDir, "."+name+"-*.tmp") // O_EXCL, 0600
	if err != nil {
		return err
	}
	tname := tmp.Name()
	_, werr := tmp.Write(b)
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Chmod(tname, 0o600)
	}
	if werr == nil {
		werr = os.Rename(tname, Path(p, name))
	}
	if werr != nil {
		os.Remove(tname)
	}
	return werr
}

// ReadState reads ui.json. ok is false when it does not exist.
func ReadState(p paths.Paths) (st State, ok bool, err error) {
	b, err := readSmall(Path(p, StateFile), maxStateBytes)
	if errors.Is(err, fs.ErrNotExist) {
		return State{}, false, nil
	}
	if err != nil {
		return State{}, false, err
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return State{}, false, fmt.Errorf("uistate: %s: %w", StateFile, err)
	}
	return st, true, nil
}

// WriteState writes ui.json atomically, 0600.
func WriteState(p paths.Paths, st State) error {
	st.V = stateVersion
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(p, StateFile, append(b, '\n'))
}

// MarkStarting is a starting server's first write, right after it took
// ui.lock and before it listens: pid is the server's, port is 0 (so nothing
// probes a port the server does not hold yet), and the previous port is kept
// in LastPort as the hint for Listen.
func MarkStarting(p paths.Paths, pid int, mode string) error {
	old, _, _ := ReadState(p) // unreadable: no hint
	return WriteState(p, State{PID: pid, Mode: mode, LastPort: HintPort(old)})
}

// Reassert rewrites ui.json with mine when it no longer names mine's pid
// and port (another process rewrote or removed it while mine holds the
// lock). It reports whether it wrote.
func Reassert(p paths.Paths, mine State) bool {
	cur, ok, err := ReadState(p)
	if err == nil && ok && cur.PID == mine.PID && cur.Port == mine.Port {
		return false
	}
	return WriteState(p, mine) == nil
}

// HintPort is the port a new server tries first: the recorded port, else
// the recorded LastPort, else 0.
func HintPort(st State) int {
	if st.Port > 0 {
		return st.Port
	}
	return st.LastPort
}

// ClearPID rewrites ui.json with pid 0 when it still names pid, keeping the
// port so the next start can reuse it. A server calls it on its way out.
func ClearPID(p paths.Paths, pid int) error {
	st, ok, err := ReadState(p)
	if err != nil || !ok || st.PID != pid {
		return err
	}
	st.PID = 0
	return WriteState(p, st)
}

// validToken reports whether t looks like a token this package made.
func validToken(t string) bool {
	if len(t) != tokenLen {
		return false
	}
	for i := 0; i < len(t); i++ {
		c := t[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func newToken() (string, error) {
	b := make([]byte, tokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("uistate: token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ReadToken reads ui.token. A missing file is fs.ErrNotExist; a file that
// does not hold a well-formed token is an error.
func ReadToken(p paths.Paths) (string, error) {
	b, err := readSmall(Path(p, TokenFile), 256)
	if err != nil {
		return "", err
	}
	t := string(b)
	if n := len(t); n > 0 && t[n-1] == '\n' {
		t = t[:n-1]
	}
	if !validToken(t) {
		return "", fmt.Errorf("uistate: %s does not hold a token", TokenFile)
	}
	return t, nil
}

// LoadOrCreateToken returns the token in ui.token, creating the file (0600,
// O_EXCL) when it does not exist. A file that holds no well-formed token is
// replaced with a new one.
func LoadOrCreateToken(p paths.Paths) (string, error) {
	t, err := ReadToken(p)
	if err == nil {
		return t, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return RotateToken(p)
	}
	if err := EnsureDir(p); err != nil {
		return "", err
	}
	t, err = newToken()
	if err != nil {
		return "", err
	}
	f, err := os.OpenFile(Path(p, TokenFile), os.O_WRONLY|os.O_CREATE|os.O_EXCL|oNoFollow, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return ReadToken(p) // another process created it first
	}
	if err != nil {
		return "", err
	}
	_, werr := f.WriteString(t + "\n")
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		os.Remove(Path(p, TokenFile))
		return "", werr
	}
	return t, nil
}

// RotateToken replaces ui.token with a new token and returns it. A running
// server picks it up through its TokenWatcher on the next request, so every
// open tab (and a remembered token) stops working.
func RotateToken(p paths.Paths) (string, error) {
	t, err := newToken()
	if err != nil {
		return "", err
	}
	if err := writeAtomic(p, TokenFile, []byte(t+"\n")); err != nil {
		return "", err
	}
	return t, nil
}

// URL is the launch URL for port and token.
func URL(port int, token string) string {
	return "http://127.0.0.1:" + strconv.Itoa(port) + "/#t=" + token
}

// BaseURL is the launch URL without the token.
func BaseURL(port int) string { return "http://127.0.0.1:" + strconv.Itoa(port) + "/" }
