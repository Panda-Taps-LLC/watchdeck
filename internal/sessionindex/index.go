// Package sessionindex keeps a derived index of every Claude Code session
// under the projects dir: per-session metadata plus a bounded, full-content
// search text. It is the M5.4 step of the 2026-10-13 plan and reverses two
// M4 decisions (the whole projects tree is now scanned; a derived copy of
// transcript text is now kept on disk).
//
// Layout under Options.Dir (paths.SessionIndexDir, <stateDir>/index):
//
//	meta.json        every entry; written to a temp file and renamed
//	text/<sha256(id)>.txt  the session's search text, one part per line
//	.lock            flock held by Update
//
// Directories are 0700 and files 0600. A rebuilt text file is written to a
// temp file and renamed into place. Growth is appended in place and
// meta.json records text_bytes; on the next Update a text file longer than
// text_bytes (a crash between the append and the meta save) is truncated
// back to it, and a shorter or missing one rebuilds the entry, so text is
// never duplicated.
//
// Bounds: lines over transcript.DefaultMaxLine (2 MiB) are skipped; a file
// over Options.MaxRead (32 MiB) is read as head metadata plus its last 32
// MiB (TailRead); a session's text stops at Options.TextCap (16 MiB,
// TextCapped). Options.NoTranscripts indexes nothing and writes nothing.
//
// The package does no init-time work: cmd/watchdeck links it and is also
// the hook binary.
package sessionindex

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Panda-Taps-LLC/watchdeck/internal/activity"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/transcript"
)

const (
	// DefaultTextCap is the per-session search text cap, 16 MiB.
	DefaultTextCap int64 = 16 << 20
	// DefaultHeadCap bounds the metadata scan at the start of a file that is
	// read from its tail.
	DefaultHeadCap int64 = 4 << 20

	metaFile    = "meta.json"
	textDir     = "text"
	lockFile    = ".lock"
	metaVersion = 4 // 4: leak watch findings; 3: harness on every entry; 2: text files named by sha256 of the id
	titleLen    = 240
)

var (
	// ErrNoDir is returned when Options.Dir is empty.
	ErrNoDir = errors.New("sessionindex: index dir not configured")
	// ErrDisabled is returned by operations that need transcripts when
	// Options.NoTranscripts is set.
	ErrDisabled = errors.New("sessionindex: transcripts are off (--no-transcripts)")

	errShrunk = errors.New("sessionindex: file shrank")
)

// Options configures an Index.
type Options struct {
	Dir           string // the index dir, paths.SessionIndexDir(); required
	ProjectsDir   string // Claude Code's projects dir; required for Update
	TextCap       int64  // per-session search text cap (default DefaultTextCap)
	MaxRead       int64  // per-file tail read (default transcript.DefaultMaxBytes, 32 MiB)
	MaxLine       int    // longest line (default transcript.DefaultMaxLine, 2 MiB)
	HeadCap       int64  // metadata scan of a tail-read file (default DefaultHeadCap)
	NoTranscripts bool   // index nothing, write nothing
}

// FileState is the resume state of one transcript file.
type FileState struct {
	Name   string    `json:"name"`
	Size   int64     `json:"size"`
	Mtime  time.Time `json:"mtime"`
	Offset int64     `json:"offset"` // byte position after the last complete line read
}

// Entry is one session in the index.
type Entry struct {
	ID         string    `json:"id"`
	Harness    string    `json:"harness"`
	ProjectDir string    `json:"project_dir"` // the escaped project dir name under projects/
	Path       string    `json:"path"`        // the main transcript as the projects dir names it
	Size       int64     `json:"size"`
	Mtime      time.Time `json:"mtime"`
	Offset     int64     `json:"offset"`
	Cwd        string    `json:"cwd"` // the first cwd a main-file row carries (real, not unescaped)
	GitBranch  string    `json:"git_branch"`
	Models     []string  `json:"models"`
	CCVersion  string    `json:"cc_version"`
	Entrypoint string    `json:"entrypoint"`
	FirstTS    time.Time `json:"first_ts"`
	LastTS     time.Time `json:"last_ts"`
	Title      string    `json:"title"` // first typed prompt of the main agent, at most 240 bytes
	Turns      int       `json:"turns"`
	ToolCalls  int       `json:"tool_calls"`
	Skills     []string  `json:"skills"` // from Skill tool_use input and watchdeck run rewrites
	Subagents  int       `json:"subagents"`
	// Truncated is TailRead || TextCapped: the index does not cover the whole session.
	Truncated     bool        `json:"truncated"`
	TailRead      bool        `json:"tail_read"`
	TextCapped    bool        `json:"text_capped"`
	TextBytes     int64       `json:"text_bytes"`
	SkippedLines  int         `json:"skipped_lines"`
	SubagentFiles []FileState `json:"subagent_files,omitempty"`
	// Findings are the secret-shaped strings leak watch found (DESIGN §14
	// "Leak watch"), in file order, at most MaxFindings; FindingsCapped is
	// set when more were found. A finding never holds the matched text.
	Findings       []Finding `json:"findings,omitempty"`
	FindingsCapped bool      `json:"findings_capped,omitempty"`
}

// MaxFindings is the most findings one entry keeps.
const MaxFindings = 50

// Where a finding was seen.
const (
	WhereResult = "result" // a tool result
	WhereReply  = "reply"  // a model reply's text
	WhereInput  = "input"  // a tool call's input
)

// Finding is one secret-shaped string leak watch found in a session. Ref is
// the tool use id for a result or input, the assistant row's uuid for a
// reply. Tool is the tool's name ("unknown" for a result whose tool use was
// read in an earlier pass; "" for a reply). Target names what the call
// touched, at most 120 bytes: the file path for the file tools, the path
// for Grep and Glob, the program for Bash, the host for WebFetch, else "".
// Agent is the subagent id for a finding in a subagent file. Nothing here
// holds the matched text.
type Finding struct {
	Pattern string `json:"pattern"`
	Label   string `json:"label"`
	Where   string `json:"where"`
	Tool    string `json:"tool,omitempty"`
	Target  string `json:"target,omitempty"`
	// TargetCut is true when Target is the first 120 bytes of a longer
	// one: a rule must not be built from it.
	TargetCut bool      `json:"target_cut,omitempty"`
	Ref       string    `json:"ref"`
	Agent     string    `json:"agent,omitempty"`
	TS        time.Time `json:"ts"`
}

type meta struct {
	Version  int               `json:"version"`
	Updated  time.Time         `json:"updated"`
	Sessions map[string]*Entry `json:"sessions"`
}

// Index is an opened session index. It is not safe for concurrent use by
// several goroutines; Update takes a file lock against other processes.
type Index struct {
	o Options
	m meta
}

// Stats reports what one Update did.
type Stats struct {
	Sessions   int  `json:"sessions"`   // entries after the update
	Rebuilt    int  `json:"rebuilt"`    // entries read from the start
	Appended   int  `json:"appended"`   // entries resumed at their offset
	Unchanged  int  `json:"unchanged"`  // size and mtime equal
	Pruned     int  `json:"pruned"`     // transcript gone, entry removed
	Duplicates int  `json:"duplicates"` // a session id seen in a second project dir (the newest wins)
	Errors     int  `json:"errors"`     // files that could not be read
	Disabled   bool `json:"disabled"`   // NoTranscripts: nothing was done
}

// Open loads meta.json when present. It creates nothing; an unreadable or
// older-version meta.json starts an empty index (rebuilt by Update).
func Open(o Options) (*Index, error) {
	if o.Dir == "" {
		return nil, ErrNoDir
	}
	if o.TextCap <= 0 {
		o.TextCap = DefaultTextCap
	}
	if o.MaxRead <= 0 {
		o.MaxRead = transcript.DefaultMaxBytes
	}
	if o.MaxLine <= 0 {
		o.MaxLine = transcript.DefaultMaxLine
	}
	if o.HeadCap <= 0 {
		o.HeadCap = DefaultHeadCap
	}
	ix := &Index{o: o, m: meta{Version: metaVersion, Sessions: map[string]*Entry{}}}
	if o.NoTranscripts {
		return ix, nil
	}
	if err := ix.load(); err != nil {
		return nil, err
	}
	return ix, nil
}

// load replaces the in-memory entries with meta.json. A missing file leaves
// them empty; an unreadable or older-version one starts an empty index.
func (ix *Index) load() error {
	ix.m = meta{Version: metaVersion, Sessions: map[string]*Entry{}}
	b, err := os.ReadFile(filepath.Join(ix.o.Dir, metaFile))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var m meta
	if json.Unmarshal(b, &m) == nil && m.Version == metaVersion && m.Sessions != nil {
		for id, e := range m.Sessions {
			if e == nil || !transcript.ValidID(id) || e.ID != id {
				delete(m.Sessions, id)
				continue
			}
			if e.Harness == "" {
				e.Harness = activity.HarnessClaudeCode
			}
		}
		ix.m = m
	}
	return nil
}

// Entries returns every entry, newest activity first (LastTS, then mtime,
// then id).
func (ix *Index) Entries() []Entry {
	out := make([]Entry, 0, len(ix.m.Sessions))
	for _, e := range ix.m.Sessions {
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool { return newer(&out[i], &out[j]) })
	return out
}

// Get returns the entry for a session id.
func (ix *Index) Get(id string) (Entry, bool) {
	e, ok := ix.m.Sessions[id]
	if !ok {
		return Entry{}, false
	}
	return *e, true
}

// Updated is when meta.json was last saved; zero for a new index.
func (ix *Index) Updated() time.Time { return ix.m.Updated }

func newer(a, b *Entry) bool {
	ta, tb := a.LastTS, b.LastTS
	if ta.IsZero() {
		ta = a.Mtime
	}
	if tb.IsZero() {
		tb = b.Mtime
	}
	if !ta.Equal(tb) {
		return ta.After(tb)
	}
	return a.ID < b.ID
}

// Update brings the index in line with the projects dir: new sessions are
// read, grown files are resumed at their stored offset, shrunk files (or an
// mtime that went backwards, or a vanished subagent file) rebuild their
// entry, unchanged files are skipped by size and mtime, and entries whose
// transcript is gone are pruned. With NoTranscripts it does nothing.
func (ix *Index) Update() (Stats, error) {
	return ix.update(false)
}

// Rebuild drops every entry and reads every session again.
func (ix *Index) Rebuild() (Stats, error) {
	return ix.update(true)
}

func (ix *Index) update(all bool) (st Stats, err error) {
	if ix.o.NoTranscripts {
		return Stats{Disabled: true}, nil
	}
	if ix.o.ProjectsDir == "" {
		return st, transcript.ErrNoProjectsDir
	}
	if err := ensureDir(ix.o.Dir); err != nil {
		return st, err
	}
	if err := ensureDir(filepath.Join(ix.o.Dir, textDir)); err != nil {
		return st, err
	}
	unlock, err := lock(filepath.Join(ix.o.Dir, lockFile))
	if err != nil {
		return st, err
	}
	defer unlock()
	// another process may have saved since Open: start from its meta.json
	if err := ix.load(); err != nil {
		return st, err
	}

	refs, err := transcript.DiscoverAll(ix.o.ProjectsDir)
	if err != nil {
		return st, err
	}
	if all {
		// saved empty first, for the same reason rebuild drops an entry
		// before renaming its text file into place
		ix.m.Sessions = map[string]*Entry{}
		if err := ix.save(); err != nil {
			return st, err
		}
	}
	seen := map[string]bool{}
	for i := range refs {
		ref := &refs[i]
		if seen[ref.ID] {
			st.Duplicates++ // refs are newest first: the first one wins
			continue
		}
		seen[ref.ID] = true
		switch ix.sync(ref) {
		case actRebuilt:
			st.Rebuilt++
		case actAppended:
			st.Appended++
		case actUnchanged:
			st.Unchanged++
		case actError:
			st.Errors++
		}
	}
	for id := range ix.m.Sessions {
		if !seen[id] {
			delete(ix.m.Sessions, id)
			os.Remove(ix.textPath(id))
			st.Pruned++
		}
	}
	// stray text files (a crash before a meta save, or a purge race)
	if ents, err := os.ReadDir(filepath.Join(ix.o.Dir, textDir)); err == nil {
		keep := make(map[string]bool, len(ix.m.Sessions))
		for id := range ix.m.Sessions {
			keep[textName(id)] = true
		}
		for _, de := range ents {
			if name := de.Name(); !keep[name] {
				os.Remove(filepath.Join(ix.o.Dir, textDir, name))
			}
		}
	}
	st.Sessions = len(ix.m.Sessions)
	ix.m.Version = metaVersion
	ix.m.Updated = time.Now().UTC()
	return st, ix.save()
}

type action int

const (
	actUnchanged action = iota
	actAppended
	actRebuilt
	actError
)

// textName is the text file of a session: the lowercase hex sha256 of its
// id. Ids that differ only in case ("AAAA", "aaaa") are distinct sessions,
// and on a case-insensitive filesystem (the macOS default) "<id>.txt" would
// make them share one file.
func textName(id string) string {
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:]) + ".txt"
}

func (ix *Index) textPath(id string) string {
	return filepath.Join(ix.o.Dir, textDir, textName(id))
}

// sync updates one session's entry.
func (ix *Index) sync(ref *transcript.SessionFiles) action {
	e := ix.m.Sessions[ref.ID]
	if e == nil || e.Path != ref.Path || needsRebuild(e, ref) || !ix.reconcileText(e) {
		if err := ix.rebuild(ref); err != nil {
			delete(ix.m.Sessions, ref.ID)
			os.Remove(ix.textPath(ref.ID))
			return actError
		}
		return actRebuilt
	}
	if unchanged(e, ref) {
		return actUnchanged
	}
	if err := ix.appendTo(e, ref); err != nil {
		if errors.Is(err, errShrunk) {
			if ix.rebuild(ref) == nil {
				return actRebuilt
			}
		}
		delete(ix.m.Sessions, ref.ID)
		os.Remove(ix.textPath(ref.ID))
		return actError
	}
	return actAppended
}

func needsRebuild(e *Entry, ref *transcript.SessionFiles) bool {
	if ref.Main.Size < e.Size || ref.Main.ModTime.Before(e.Mtime) || e.Offset > ref.Main.Size {
		return true
	}
	files := map[string]transcript.FileRef{}
	for _, f := range ref.SubagentFiles {
		files[f.Name] = f
	}
	for _, s := range e.SubagentFiles {
		f, ok := files[s.Name]
		if !ok || f.Size < s.Size || f.ModTime.Before(s.Mtime) || s.Offset > f.Size {
			return true
		}
	}
	return false
}

func unchanged(e *Entry, ref *transcript.SessionFiles) bool {
	if ref.Main.Size != e.Size || !ref.Main.ModTime.Equal(e.Mtime) || len(ref.SubagentFiles) != len(e.SubagentFiles) {
		return false
	}
	for i, f := range ref.SubagentFiles {
		s := e.SubagentFiles[i]
		if f.Name != s.Name || f.Size != s.Size || !f.ModTime.Equal(s.Mtime) {
			return false
		}
	}
	return true
}

// reconcileText makes the text file exactly TextBytes long: a longer file
// (a crash after an append, before the meta save) is truncated; a shorter or
// missing one returns false and the entry is rebuilt.
func (ix *Index) reconcileText(e *Entry) bool {
	p := ix.textPath(e.ID)
	st, err := os.Lstat(p)
	if err != nil {
		return false
	}
	if !st.Mode().IsRegular() {
		return false
	}
	switch {
	case st.Size() == e.TextBytes:
		return true
	case st.Size() > e.TextBytes:
		return os.Truncate(p, e.TextBytes) == nil
	default:
		return false
	}
}

func (ix *Index) newBuilder(e *Entry, s *sink) *builder {
	return &builder{e: e, s: s, maxLine: ix.o.MaxLine, maxRead: ix.o.MaxRead, headCap: ix.o.HeadCap, tools: map[string]toolRef{}}
}

// rebuild reads every file of a session from the start into a temp text
// file and renames it into place.
func (ix *Index) rebuild(ref *transcript.SessionFiles) error {
	dir := filepath.Join(ix.o.Dir, textDir)
	tmp, err := os.CreateTemp(dir, ".tmp-"+ref.ID+"-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // a no-op once it is renamed into place
	w := bufio.NewWriterSize(tmp, 64<<10)
	e := &Entry{
		ID:         ref.ID,
		Harness:    activity.HarnessClaudeCode,
		ProjectDir: filepath.Base(ref.ProjectDir),
		Path:       ref.Path,
		Size:       ref.Main.Size,
		Mtime:      ref.Main.ModTime,
	}
	s := &sink{w: w, cap: ix.o.TextCap}
	b := ix.newBuilder(e, s)
	off, err := b.readFile(ref.Main.Resolved, true, 0)
	if err != nil {
		tmp.Close()
		return err
	}
	e.Offset = off
	for _, f := range ref.SubagentFiles {
		b.agent = agentOf(f.Name)
		off, err := b.readFile(f.Resolved, false, 0)
		if err != nil {
			continue // a subagent file that vanished between listing and reading
		}
		e.SubagentFiles = append(e.SubagentFiles, FileState{Name: f.Name, Size: f.Size, Mtime: f.ModTime, Offset: off})
	}
	ix.finishEntry(e, s)
	if err := w.Flush(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// A session that already has an entry is first dropped from meta.json on
	// disk: if the process dies between the rename and the final meta save,
	// the next update finds no entry and reads the session afresh, instead of
	// reconciling the new text file against the old entry's text_bytes and
	// offsets.
	if _, had := ix.m.Sessions[ref.ID]; had {
		delete(ix.m.Sessions, ref.ID)
		if err := ix.save(); err != nil {
			return err
		}
	}
	if err := os.Rename(tmpName, ix.textPath(ref.ID)); err != nil {
		return err
	}
	if afterTextRename != nil {
		afterTextRename(ref.ID)
	}
	ix.m.Sessions[ref.ID] = e
	return nil
}

// afterTextRename is nil except in tests, which use it to simulate a crash
// between a rebuilt text file's rename and the meta save.
var afterTextRename func(id string)

// appendTo resumes a grown session at its stored offsets and appends the new
// text to its text file.
func (ix *Index) appendTo(e *Entry, ref *transcript.SessionFiles) error {
	f, err := os.OpenFile(ix.textPath(e.ID), os.O_WRONLY|os.O_APPEND|oNoFollow, 0o600)
	if err != nil {
		return err
	}
	w := bufio.NewWriterSize(f, 64<<10)
	ne := *e // work on a copy; commit only on success
	ne.Models = append([]string(nil), e.Models...)
	ne.Skills = append([]string(nil), e.Skills...)
	ne.Findings = append([]Finding(nil), e.Findings...)
	ne.SubagentFiles = nil
	s := &sink{w: w, n: e.TextBytes, cap: ix.o.TextCap, capped: e.TextCapped}
	b := ix.newBuilder(&ne, s)
	fail := func(err error) error {
		f.Close()
		return err // the text file is truncated back to TextBytes by the next reconcile
	}
	if ref.Main.Size != e.Size || !ref.Main.ModTime.Equal(e.Mtime) {
		off, err := b.readFile(ref.Main.Resolved, true, e.Offset)
		if err != nil {
			return fail(err)
		}
		ne.Offset = off
	}
	ne.Size, ne.Mtime = ref.Main.Size, ref.Main.ModTime
	old := map[string]FileState{}
	for _, s := range e.SubagentFiles {
		old[s.Name] = s
	}
	for _, sf := range ref.SubagentFiles {
		prev, had := old[sf.Name]
		if had && prev.Size == sf.Size && prev.Mtime.Equal(sf.ModTime) {
			ne.SubagentFiles = append(ne.SubagentFiles, prev)
			continue
		}
		b.agent = agentOf(sf.Name)
		off, err := b.readFile(sf.Resolved, false, prev.Offset) // prev.Offset is 0 for a new file
		if err != nil {
			return fail(err)
		}
		ne.SubagentFiles = append(ne.SubagentFiles, FileState{Name: sf.Name, Size: sf.Size, Mtime: sf.ModTime, Offset: off})
	}
	ix.finishEntry(&ne, s)
	if err := w.Flush(); err != nil {
		return fail(err)
	}
	if err := f.Close(); err != nil {
		return err
	}
	*e = ne
	return nil
}

func (ix *Index) finishEntry(e *Entry, s *sink) {
	e.TextBytes = s.n
	e.TextCapped = s.capped
	e.Subagents = len(e.SubagentFiles)
	e.Truncated = e.TailRead || e.TextCapped
	if e.Models == nil {
		e.Models = []string{}
	}
	if e.Skills == nil {
		e.Skills = []string{}
	}
}

// save writes meta.json through a temp file and a rename.
func (ix *Index) save() error {
	b, err := json.Marshal(&ix.m)
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(ix.o.Dir, metaFile), b)
}

func writeAtomic(path string, b []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-"+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// ensureDir creates dir 0700 and tightens an existing one to 0700. A
// symlink is refused.
func ensureDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	st, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !st.IsDir() {
		return fmt.Errorf("sessionindex: %s is not a directory", dir)
	}
	if st.Mode().Perm() != 0o700 {
		return os.Chmod(dir, 0o700)
	}
	return nil
}

// Purge removes the index dir and everything in it. Dir must be named
// "index", so a misconfigured path cannot remove anything else.
func Purge(o Options) error {
	if o.Dir == "" {
		return ErrNoDir
	}
	if filepath.Base(filepath.Clean(o.Dir)) != "index" {
		return fmt.Errorf("sessionindex: refusing to purge %s (not an index dir)", o.Dir)
	}
	return os.RemoveAll(o.Dir)
}
