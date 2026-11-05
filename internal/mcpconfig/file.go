package mcpconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/safeio"
)

// MaxConfigBytes caps the config read. Claude Code's .claude.json grows with
// per-project state; 64 MiB is far above anything seen and still bounded.
const MaxConfigBytes = 64 << 20

// KeepBackups is how many backups of the config WriteConfig keeps.
const KeepBackups = 10

// ReadConfig reads the config without blocking on a FIFO or a device. The
// path is resolved through symlinks first (a dotfiles setup may link it),
// so a later write replaces the real file, not the link. exists is false
// with no error when the file is absent.
func ReadConfig(path string) (data []byte, real string, exists bool, err error) {
	real = path
	if r, e := filepath.EvalSymlinks(path); e == nil {
		real = r
	}
	data, err = safeio.ReadRegular(real, MaxConfigBytes, false)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, real, false, nil
	}
	if err != nil {
		return nil, real, true, err
	}
	return data, real, true, nil
}

// beforeRename is a test hook run after the temp file is written and before
// the change check and rename.
var beforeRename = func() {}

// backupNow is the clock for backup names; tests replace it.
var backupNow = time.Now

// ErrChanged means the config changed between read and write (Claude Code
// rewrites it on its own schedule); nothing was written.
var ErrChanged = errors.New("the config changed while watchdeck was editing it (is Claude Code running?); nothing was written, try again")

// WriteConfig replaces the config at real (already symlink-resolved) with
// next, given old, the bytes it was computed from:
//
//  1. old is copied to <backupDir>/<base>.bak-<unix seconds>[-N], 0600,
//     created exclusively (backupDir 0700, inside watchdeck's state dir,
//     which every sandbox profile denies: the file holds server tokens);
//  2. next goes to a temp file beside real with real's permission bits
//     (0600 when unknown), fsynced;
//  3. the config is read again; if it is no longer old, the temp file is
//     removed and ErrChanged returned;
//  4. the temp file is renamed over real; old backups beyond KeepBackups
//     are removed.
//
// It returns the backup path.
func WriteConfig(real string, old, next []byte, backupDir string) (string, error) {
	mode := fs.FileMode(0o600)
	if fi, err := os.Stat(real); err == nil {
		mode = fi.Mode().Perm()
	}
	backup, err := writeBackup(backupDir, filepath.Base(real), old)
	if err != nil {
		return "", fmt.Errorf("backup: %w", err)
	}
	dir := filepath.Dir(real)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(real)+".watchdeck-*.tmp")
	if err != nil {
		return backup, err
	}
	name := tmp.Name()
	fail := func(err error) (string, error) {
		tmp.Close()
		os.Remove(name)
		return backup, err
	}
	if _, err := tmp.Write(next); err != nil {
		return fail(err)
	}
	if err := tmp.Chmod(mode); err != nil {
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return backup, err
	}
	beforeRename()
	cur, err := safeio.ReadRegular(real, MaxConfigBytes, false)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		os.Remove(name)
		return backup, err
	}
	if !bytes.Equal(cur, old) {
		os.Remove(name)
		return backup, ErrChanged
	}
	if err := os.Rename(name, real); err != nil {
		os.Remove(name)
		return backup, err
	}
	pruneBackups(backupDir, filepath.Base(real))
	return backup, nil
}

func writeBackup(dir, base string, data []byte) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	ts := strconv.FormatInt(backupNow().Unix(), 10)
	for n := 1; n < 10000; n++ {
		p := filepath.Join(dir, base+".bak-"+ts)
		if n > 1 {
			p += "-" + strconv.Itoa(n)
		}
		f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			return "", err
		}
		if _, err := f.Write(data); err != nil {
			f.Close()
			os.Remove(p)
			return "", err
		}
		if err := f.Sync(); err != nil {
			f.Close()
			return "", err
		}
		return p, f.Close()
	}
	return "", errors.New("too many backups in one second")
}

type bak struct {
	path  string
	ts, n int64
}

func pruneBackups(dir, base string) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	var bs []bak
	for _, e := range ents {
		rest, ok := strings.CutPrefix(e.Name(), base+".bak-")
		if !ok {
			continue
		}
		tsS, nS, _ := strings.Cut(rest, "-")
		ts, err := strconv.ParseInt(tsS, 10, 64)
		if err != nil {
			continue
		}
		n := int64(1)
		if nS != "" {
			if n, err = strconv.ParseInt(nS, 10, 64); err != nil {
				continue
			}
		}
		bs = append(bs, bak{filepath.Join(dir, e.Name()), ts, n})
	}
	sort.Slice(bs, func(i, j int) bool {
		if bs[i].ts != bs[j].ts {
			return bs[i].ts > bs[j].ts
		}
		return bs[i].n > bs[j].n
	})
	for i := KeepBackups; i < len(bs); i++ {
		os.Remove(bs[i].path)
	}
}

// Record is what wrap keeps for unwrap: the entry's bytes before and after.
// Original holds the server's env values (often tokens); the state file is
// 0600 in watchdeck's state dir, which every sandbox profile denies.
type Record struct {
	Config    string `json:"config"` // symlink-resolved config path
	Name      string `json:"name"`
	Original  string `json:"original"`
	Wrapped   string `json:"wrapped"`
	Binary    string `json:"binary"`
	WrappedAt string `json:"wrapped_at"`
}

// State is the wrap state file.
type State struct {
	Version int      `json:"version"`
	Servers []Record `json:"servers"`
}

// StateFile is the wrap state file's name in the state dir.
const StateFile = "mcp-wrapped.json"

// LoadState reads the state file; a missing file is an empty state.
func LoadState(path string) (State, error) {
	b, err := safeio.ReadRegular(path, 16<<20, true)
	if errors.Is(err, fs.ErrNotExist) {
		return State{Version: 1}, nil
	}
	if err != nil {
		return State{}, err
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return State{}, fmt.Errorf("%s: %w", StateFile, err)
	}
	if s.Version != 1 {
		return State{}, fmt.Errorf("%s: unknown version %d", StateFile, s.Version)
	}
	return s, nil
}

// Get returns the record for config and name.
func (s State) Get(config, name string) (Record, bool) {
	for _, r := range s.Servers {
		if r.Config == config && r.Name == name {
			return r, true
		}
	}
	return Record{}, false
}

// Put inserts or replaces r.
func (s *State) Put(r Record) {
	s.Delete(r.Config, r.Name)
	s.Servers = append(s.Servers, r)
	sort.Slice(s.Servers, func(i, j int) bool {
		if s.Servers[i].Config != s.Servers[j].Config {
			return s.Servers[i].Config < s.Servers[j].Config
		}
		return s.Servers[i].Name < s.Servers[j].Name
	})
}

// Delete removes the record for config and name.
func (s *State) Delete(config, name string) {
	out := s.Servers[:0]
	for _, r := range s.Servers {
		if r.Config != config || r.Name != name {
			out = append(out, r)
		}
	}
	s.Servers = out
}

// SaveState writes the state file atomically, 0600 (dir 0700).
func SaveState(path string, s State) error {
	s.Version = 1
	if s.Servers == nil {
		s.Servers = []Record{}
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".mcp-wrapped-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		os.Remove(name)
		return err
	}
	return nil
}
