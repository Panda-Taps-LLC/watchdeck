// Package lifecycle records when Claude Code sessions start, are in use and
// end, so the dashboard can say which sessions are live (M5.2).
//
// Two things live under the user's state dir (paths.Paths):
//
//   - sessions.jsonl: append-only JSONL, schema v1, mode 0600, one record per
//     SessionStart, SessionEnd and (at most once a minute per session)
//     UserPromptSubmit. Rotated to sessions.jsonl.1 past MaxBytes.
//   - live/<session_id>: a marker file (0600, dir 0700) created on start,
//     its mtime touched by every hook event the binary receives for that
//     session, removed on end. Its content is a small JSON object naming the
//     transcript, the cwd and when a record was last appended for it.
//
// The record never holds the prompt text UserPromptSubmit carries, nor
// anything else from the hook input beyond the fields of Record.
//
// The package does no work at init: the hook links it and runs on every tool
// call. A zero Store (both paths "") is off and never touches the disk; that
// is what WATCHDECK_LIFECYCLE=off resolves to.
package lifecycle

import (
	"bufio"
	"encoding/json"
	"errors"
	"github.com/Panda-Taps-LLC/watchdeck/internal/activity"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/Panda-Taps-LLC/watchdeck/internal/transcript"
)

// Version is the schema version written into every record.
const Version = 1

// Record kinds.
const (
	KindStart = "start" // SessionStart
	KindEnd   = "end"   // SessionEnd
	KindBeat  = "beat"  // UserPromptSubmit, at most once per BeatEvery per session
)

// Session states.
const (
	Live    = "live"    // marker present and touched within LiveWindow, or the transcript written within TranscriptWindow
	Idle    = "idle"    // marker present, older
	Ended   = "ended"   // the session's last record is an end record
	Unknown = "unknown" // no marker and no end record
)

// Timing rules. Variables so tests can shorten them; never changed at run time.
var (
	BeatEvery        = 60 * time.Second // a beat appends a record at most this often per session
	LiveWindow       = 10 * time.Minute // marker mtime younger than this: live
	TranscriptWindow = 30 * time.Second // transcript mtime younger than this: live
)

// MaxBytes is the size above which an append renames sessions.jsonl to
// sessions.jsonl.1 first (the previous .1 is replaced).
var MaxBytes int64 = 4 << 20

// maxMarker caps how much of a marker file is read.
const maxMarker = 64 << 10 // two capped fields fit even when JSON escaping grows them sixfold

// tmpPrefix starts the name of a marker being written; List skips it.
const tmpPrefix = ".tmp-"

// Bounds.
const (
	maxField   = 4 << 10              // transcript_path and cwd are cut to this many bytes
	futureSkew = time.Minute          // a marker mtime further in the future than this is not trusted as live
	tmpMaxAge  = time.Hour            // a leftover live/.tmp-* older than this is removed on Start
	lockTries  = 50                   // rotation lock: non-blocking attempts…
	lockWait   = 2 * time.Millisecond // …this far apart; then the append goes ahead without rotating
)

// OnSessionStart is the extension point M5.3 uses to start the dashboard
// when a session starts. The hook calls it, when non-nil, after the start
// record and marker are written, inside its panic guard. It is nil in M5.2
// and nothing sets it yet.
var OnSessionStart func(s Store, r Record)

// ErrInvalidID is returned for a session id that is not a safe file name.
var ErrInvalidID = errors.New("lifecycle: invalid session id")

// ErrSymlink is returned when the live dir or the log is a symlink.
var ErrSymlink = errors.New("lifecycle: refusing a symlink")

// ErrNotRegular is returned when a marker, the log or its lock is not a
// regular file (a FIFO, device, socket or directory planted there).
var ErrNotRegular = errors.New("lifecycle: refusing a file that is not regular")

// Record is one line of sessions.jsonl.
type Record struct {
	V          int    `json:"v"`
	Kind       string `json:"kind"` // start | end | beat
	TS         string `json:"ts"`   // RFC3339Nano, UTC
	Harness    string `json:"harness,omitempty"`
	SessionID  string `json:"session_id"`
	Transcript string `json:"transcript_path,omitempty"`
	Cwd        string `json:"cwd,omitempty"`
	Source     string `json:"source,omitempty"` // start: startup | resume | clear | compact
	Reason     string `json:"reason,omitempty"` // end: clear | logout | prompt_input_exit | other | …
}

// marker is the content of live/<session_id>.
type marker struct {
	Logged     string `json:"logged"` // RFC3339Nano of the last record appended for this session (start or beat)
	Transcript string `json:"transcript_path,omitempty"`
	Cwd        string `json:"cwd,omitempty"`
}

// Store names the two locations. Both "" (the zero value) means off.
type Store struct {
	Log  string // sessions.jsonl
	Live string // the live/ dir
	// Harness names the coding agent for new records; "" = claude-code.
	Harness string

	// Now is the clock; nil means time.Now. Tests inject a fake one.
	Now func() time.Time
	// NoTranscriptStat makes State and List ignore the transcript's mtime
	// (the 30 s rule); the marker alone decides live or idle.
	NoTranscriptStat bool
}

// Off reports whether the store writes nothing.
func (s Store) Off() bool { return s.Log == "" || s.Live == "" }

func (s Store) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// ValidID reports whether id can name a marker file: transcript.ValidID and
// not starting with a dot.
func ValidID(id string) bool {
	return transcript.ValidID(id) && id[0] != '.'
}

// Start records a SessionStart: a start record and a fresh marker.
func (s Store) Start(sessionID, transcriptPath, cwd, source string) (Record, error) {
	if s.Off() {
		return Record{}, nil
	}
	if !ValidID(sessionID) {
		return Record{}, ErrInvalidID
	}
	now := s.now()
	r := s.record(KindStart, sessionID, transcriptPath, cwd, now)
	r.Source = source
	aerr := s.append(r)
	if err := s.writeMarker(sessionID, marker{Logged: r.TS, Transcript: r.Transcript, Cwd: r.Cwd}, now); err != nil {
		return r, err
	}
	s.pruneTmp(now)
	return r, aerr
}

// pruneTmp removes live/.tmp-* files older than tmpMaxAge (left by a hook
// killed between create and rename). Best effort; only regular files.
func (s Store) pruneTmp(now time.Time) {
	ents, err := os.ReadDir(s.Live)
	if err != nil {
		return
	}
	for _, e := range ents {
		if !strings.HasPrefix(e.Name(), tmpPrefix) {
			continue
		}
		p := filepath.Join(s.Live, e.Name())
		if fi, err := os.Lstat(p); err == nil && fi.Mode().IsRegular() && now.Sub(fi.ModTime()) > tmpMaxAge {
			_ = os.Remove(p)
		}
	}
}

// Beat records a UserPromptSubmit. When a record was appended for the session
// less than BeatEvery ago it only touches the marker; otherwise it rewrites
// the marker and appends a beat record. A missing marker (the hook was
// installed mid-session) is created.
func (s Store) Beat(sessionID, transcriptPath, cwd string) error {
	if s.Off() {
		return nil
	}
	if !ValidID(sessionID) {
		return ErrInvalidID
	}
	now := s.now()
	if m, ok := s.readMarker(sessionID); ok {
		if t, err := time.Parse(time.RFC3339Nano, m.Logged); err == nil {
			if d := now.Sub(t); d >= 0 && d < BeatEvery {
				return s.chtimes(sessionID, now)
			}
		}
	}
	r := s.record(KindBeat, sessionID, transcriptPath, cwd, now)
	if err := s.writeMarker(sessionID, marker{Logged: r.TS, Transcript: r.Transcript, Cwd: r.Cwd}, now); err != nil {
		return err
	}
	return s.append(r)
}

// End records a SessionEnd: an end record, then the marker is removed.
func (s Store) End(sessionID, transcriptPath, cwd, reason string) error {
	if s.Off() {
		return nil
	}
	if !ValidID(sessionID) {
		return ErrInvalidID
	}
	r := s.record(KindEnd, sessionID, transcriptPath, cwd, s.now())
	r.Reason = reason
	aerr := s.append(r)
	if err := s.liveDirOK(); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return aerr // no live dir yet: no marker to remove
		}
		return err
	}
	if err := os.Remove(filepath.Join(s.Live, sessionID)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return aerr
}

// Touch sets the marker's mtime to now when the marker exists. It never
// creates anything and never appends; any other hook event calls it.
func (s Store) Touch(sessionID string) error {
	if s.Off() || !ValidID(sessionID) {
		return nil
	}
	return s.chtimes(sessionID, s.now())
}

func (s Store) record(kind, sessionID, transcriptPath, cwd string, now time.Time) Record {
	r := Record{V: Version, Harness: activity.DefaultHarness(s.Harness), Kind: kind, TS: now.UTC().Format(time.RFC3339Nano), SessionID: sessionID, Transcript: capField(transcriptPath)}
	if cwd != "" {
		r.Cwd = capField(filepath.Clean(cwd))
	}
	return r
}

// capField cuts s to at most maxField bytes on a UTF-8 boundary.
func capField(s string) string {
	if len(s) <= maxField {
		return s
	}
	cut := maxField
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// openRegular opens path with O_NOFOLLOW|O_NONBLOCK (so a FIFO or device
// planted at the path can never block the hook) and refuses anything that is
// not a regular file.
func openRegular(path string, flag int, perm os.FileMode) (*os.File, error) {
	f, err := os.OpenFile(path, flag|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, perm)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		f.Close()
		return nil, ErrNotRegular
	}
	return f, nil
}

// liveDirOK refuses a live dir that is a symlink (or not a directory).
func (s Store) liveDirOK() error {
	fi, err := os.Lstat(s.Live)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		return ErrSymlink
	}
	return nil
}

// chtimes touches an existing regular marker; a missing one is not an error.
func (s Store) chtimes(sessionID string, now time.Time) error {
	if err := s.liveDirOK(); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	p := filepath.Join(s.Live, sessionID)
	fi, err := os.Lstat(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if !fi.Mode().IsRegular() {
		return ErrSymlink
	}
	return os.Chtimes(p, now, now)
}

// writeMarker replaces live/<id> atomically (temp file + rename, so a planted
// symlink at the name is replaced, never followed) and sets its mtime to now.
func (s Store) writeMarker(sessionID string, m marker, now time.Time) error {
	if err := os.MkdirAll(filepath.Dir(s.Live), 0o700); err != nil {
		return err
	}
	if err := os.Mkdir(s.Live, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	if err := s.liveDirOK(); err != nil {
		return err
	}
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(s.Live, tmpPrefix+sessionID+"-")
	if err != nil {
		return err
	}
	name := tmp.Name()
	_, werr := tmp.Write(b)
	cerr := tmp.Close()
	if werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Chmod(name, 0o600) // CreateTemp makes 0600; keep it explicit
	}
	if werr == nil {
		werr = os.Chtimes(name, now, now)
	}
	if werr == nil {
		werr = os.Rename(name, filepath.Join(s.Live, sessionID))
	}
	if werr != nil {
		_ = os.Remove(name)
	}
	return werr
}

// readMarker reads live/<id> without following a symlink.
func (s Store) readMarker(sessionID string) (marker, bool) {
	if s.liveDirOK() != nil {
		return marker{}, false
	}
	f, err := openRegular(filepath.Join(s.Live, sessionID), os.O_RDONLY, 0)
	if err != nil {
		return marker{}, false
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxMarker))
	if err != nil {
		return marker{}, false
	}
	var m marker
	if json.Unmarshal(b, &m) != nil {
		return marker{}, false
	}
	return m, true
}

// append writes one record with a single write, rotating first when the log
// has grown past MaxBytes. O_NOFOLLOW refuses a symlink planted at the path.
func (s Store) append(r Record) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if err := os.MkdirAll(filepath.Dir(s.Log), 0o700); err != nil {
		return err
	}
	// Rotation happens only under an exclusive flock on <log>.lock, so two
	// hooks never both rename (the second would move the fresh file over the
	// rotated one). The append itself is one O_APPEND write and needs no lock;
	// when the lock is busy for ~100 ms the append goes ahead unrotated.
	if unlock, ok := s.lock(); ok {
		if fi, err := os.Lstat(s.Log); err == nil && fi.Mode().IsRegular() && fi.Size() > MaxBytes {
			_ = os.Rename(s.Log, s.Log+".1")
		}
		defer unlock()
	}
	f, err := openRegular(s.Log, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.Write(b)
	cerr := f.Close()
	if werr != nil {
		return werr
	}
	return cerr
}

// lock takes the rotation lock, <log>.lock, without ever blocking for long.
func (s Store) lock() (func(), bool) {
	f, err := openRegular(s.Log+".lock", os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, false
	}
	for i := 0; i < lockTries; i++ {
		if syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) == nil {
			return func() {
				_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
				f.Close()
			}, true
		}
		time.Sleep(lockWait)
	}
	f.Close()
	return nil, false
}

// Session is one session as the reader sees it.
type Session struct {
	SessionID  string    `json:"session_id"`
	State      string    `json:"state"` // live | idle | ended | unknown
	Transcript string    `json:"transcript_path,omitempty"`
	Cwd        string    `json:"cwd,omitempty"`
	Source     string    `json:"source,omitempty"` // of the last start record
	Reason     string    `json:"reason,omitempty"` // of the end record when ended
	Started    string    `json:"started,omitempty"`
	Ended      string    `json:"ended,omitempty"`
	LastSeen   time.Time `json:"last_seen,omitzero"` // marker mtime, else the last record's time
}

// readLog returns every record in sessions.jsonl.1 then sessions.jsonl, in
// file order. Missing files are empty; lines that do not parse are skipped.
func (s Store) readLog() ([]Record, error) {
	var out []Record
	for _, p := range []string{s.Log + ".1", s.Log} {
		f, err := openRegular(p, os.O_RDONLY, 0)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			var r Record
			if json.Unmarshal(sc.Bytes(), &r) != nil || r.SessionID == "" {
				continue
			}
			r.Harness = activity.DefaultHarness(r.Harness)
			out = append(out, r)
		}
		err = sc.Err()
		f.Close()
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// State returns one session's state: ended when its last record is an end
// record (a resumed session starts again with the same id, so only the last
// start/beat/end counts); otherwise live or idle from its marker; otherwise
// unknown.
func (s Store) State(sessionID string) (string, error) {
	if s.Off() {
		return Unknown, nil
	}
	if !ValidID(sessionID) {
		return Unknown, ErrInvalidID
	}
	recs, err := s.readLog()
	if err != nil {
		return Unknown, err
	}
	var last *Record
	for i := range recs {
		if recs[i].SessionID == sessionID {
			last = &recs[i]
		}
	}
	if last != nil && last.Kind == KindEnd {
		return Ended, nil
	}
	st, _, _ := s.markerState(sessionID, "")
	return st, nil
}

// markerState is live, idle or unknown from live/<id>, plus the marker's
// mtime and content. fallbackTranscript is used when the marker names none.
func (s Store) markerState(sessionID, fallbackTranscript string) (string, time.Time, marker) {
	if s.liveDirOK() != nil {
		return Unknown, time.Time{}, marker{}
	}
	fi, err := os.Lstat(filepath.Join(s.Live, sessionID))
	if err != nil || !fi.Mode().IsRegular() {
		return Unknown, time.Time{}, marker{}
	}
	m, _ := s.readMarker(sessionID)
	now := s.now()
	if age := now.Sub(fi.ModTime()); age < LiveWindow && age > -futureSkew {
		return Live, fi.ModTime(), m // an mtime set far into the future is not trusted
	}
	tp := m.Transcript
	if tp == "" {
		tp = fallbackTranscript
	}
	if !s.NoTranscriptStat && tp != "" {
		if ti, err := os.Stat(tp); err == nil && now.Sub(ti.ModTime()) < TranscriptWindow {
			return Live, fi.ModTime(), m
		}
	}
	return Idle, fi.ModTime(), m
}

// List returns every session named by the log or by a marker, newest first
// (by LastSeen). Ended sessions are included.
func (s Store) List() ([]Session, error) {
	if s.Off() {
		return nil, nil
	}
	recs, err := s.readLog()
	if err != nil {
		return nil, err
	}
	byID := map[string]*Session{}
	var lastKind = map[string]string{}
	get := func(id string) *Session {
		ss := byID[id]
		if ss == nil {
			ss = &Session{SessionID: id}
			byID[id] = ss
		}
		return ss
	}
	for _, r := range recs {
		if !ValidID(r.SessionID) {
			continue
		}
		ss := get(r.SessionID)
		if r.Transcript != "" {
			ss.Transcript = r.Transcript
		}
		if r.Cwd != "" {
			ss.Cwd = r.Cwd
		}
		switch r.Kind {
		case KindStart:
			ss.Started, ss.Source, ss.Ended, ss.Reason = r.TS, r.Source, "", ""
		case KindEnd:
			ss.Ended, ss.Reason = r.TS, r.Reason
		}
		if t, err := time.Parse(time.RFC3339Nano, r.TS); err == nil && t.After(ss.LastSeen) {
			ss.LastSeen = t
		}
		lastKind[r.SessionID] = r.Kind
	}
	if s.liveDirOK() == nil {
		if ents, err := os.ReadDir(s.Live); err == nil {
			for _, e := range ents {
				n := e.Name()
				if strings.HasPrefix(n, ".") || !ValidID(n) {
					continue
				}
				get(n)
			}
		}
	}
	out := make([]Session, 0, len(byID))
	for id, ss := range byID {
		if lastKind[id] == KindEnd {
			ss.State = Ended
		} else {
			ss.Ended, ss.Reason = "", ""
			st, mtime, m := s.markerState(id, ss.Transcript)
			ss.State = st
			if !mtime.IsZero() {
				ss.LastSeen = mtime
			}
			if m.Transcript != "" {
				ss.Transcript = m.Transcript
			}
			if m.Cwd != "" {
				ss.Cwd = m.Cwd
			}
		}
		out = append(out, *ss)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].LastSeen.Equal(out[j].LastSeen) {
			return out[i].LastSeen.After(out[j].LastSeen)
		}
		return out[i].SessionID < out[j].SessionID
	})
	return out, nil
}

// Counts tallies sessions by state.
func Counts(ss []Session) (live, idle, ended, unknown int) {
	for _, s := range ss {
		switch s.State {
		case Live:
			live++
		case Idle:
			idle++
		case Ended:
			ended++
		default:
			unknown++
		}
	}
	return
}
