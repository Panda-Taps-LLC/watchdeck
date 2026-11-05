package policy

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/manifest"
	"github.com/Panda-Taps-LLC/watchdeck/internal/safeio"
)

// The hook's policy cache (M6.3). Parsing the YAML files costs far more than
// a hook call may spend, so the hook keeps the two parsed files (or their
// parse errors) as JSON, keyed by each file's size and mtime, the way
// index.LoadOrBuild keys the skill index. A hook call stats the two policy
// files; when neither exists it opens nothing else. Otherwise it reads the
// cache (one small file) and rebuilds it only when a key changed.
//
// The cache lives in watchdeck's state dir, which the sandbox denies to
// skill scripts (read and write), so a sandboxed script cannot plant a cache
// that drops the user's gates. It is written 0600 through a temp file and a
// rename.

// CacheVersion is the on-disk format of the policy cache. 2: PolicyFile
// gained Mode (shadow mode); a version 1 doc from an older binary may hold
// a parse error for a file this binary reads. 3: PolicyFile gained
// Temporary (Plan 08); a version 2 doc may hold "unknown field" for a file
// with a temporary: list.
const CacheVersion = 3

// CacheFile is the cache's file name under the state dir.
const CacheFile = "policy-cache.json"

// maxCache caps the cache read (two files of at most 1 MiB of YAML each).
const maxCache = 8 << 20

type fileKey struct {
	Path   string `json:"path"`
	Exists bool   `json:"exists"`
	Size   int64  `json:"size,omitempty"`
	Mtime  int64  `json:"mtime,omitempty"` // unix nanos
	Mode   uint32 `json:"mode,omitempty"`
}

type cacheDoc struct {
	V           int                  `json:"v"`
	User        fileKey              `json:"user"`
	Project     fileKey              `json:"project"`
	UserFile    *manifest.PolicyFile `json:"user_file,omitempty"`
	ProjectFile *manifest.PolicyFile `json:"project_file,omitempty"`
	UserErr     string               `json:"user_err,omitempty"`
	ProjectErr  string               `json:"project_err,omitempty"`
}

// Loaded is LoadCached's result. A layer whose file is malformed is empty
// in Policy and its error is in UserErr or ProjectErr; the other layer
// still applies.
type Loaded struct {
	Policy     *Policy
	Warnings   []Warning
	UserErr    error
	ProjectErr error
	// Absent is true when neither file exists: Policy is empty and no file
	// was opened (two stats only).
	Absent bool
	// Rebuilt is true when the files were parsed in this call.
	Rebuilt bool
}

func keyOf(path string) fileKey {
	k := fileKey{Path: path}
	if path == "" {
		return k
	}
	fi, err := os.Stat(path)
	if err != nil {
		return k
	}
	k.Exists = true
	k.Size = fi.Size()
	k.Mtime = fi.ModTime().UnixNano()
	k.Mode = uint32(fi.Mode())
	return k
}

// LoadCached loads the user file (trusted) and the project file (untrusted)
// through the cache at cachePath ("" = no cache, parse every time). An
// empty file path skips that file. It never fails: a malformed file is
// reported in Loaded and contributes nothing.
//
// The cache holds the parsed files, expired temporaries included; NewAt
// runs on every load with the wall clock, so a temporary ends on the first
// call after its until, cache hit or not.
func LoadCached(cachePath, userPath, projectPath string) Loaded {
	return loadCachedAt(time.Now(), cachePath, userPath, projectPath)
}

func loadCachedAt(now time.Time, cachePath, userPath, projectPath string) Loaded {
	uk, pk := keyOf(userPath), keyOf(projectPath)
	if !uk.Exists && !pk.Exists {
		p, _ := NewAt(now, Layer{Path: userPath}, Layer{Path: projectPath})
		return Loaded{Policy: p, Absent: true}
	}
	if cachePath != "" {
		if doc, ok := readCache(cachePath); ok && doc.User == uk && doc.Project == pk {
			return fromDoc(now, doc, false)
		}
	}
	doc := cacheDoc{V: CacheVersion, User: uk, Project: pk}
	if uk.Exists {
		f, exists, err := LoadFile(userPath)
		switch {
		case err != nil:
			doc.UserErr = err.Error()
		case exists:
			doc.UserFile = &f
		}
	}
	if pk.Exists {
		f, exists, err := LoadProjectFile(projectPath)
		switch {
		case err != nil:
			doc.ProjectErr = err.Error()
		case exists:
			doc.ProjectFile = &f
		}
	}
	if cachePath != "" {
		writeCache(cachePath, doc)
	}
	return fromDoc(now, doc, true)
}

func fromDoc(now time.Time, doc cacheDoc, rebuilt bool) Loaded {
	var user, project Layer
	user.Path, project.Path = doc.User.Path, doc.Project.Path
	if doc.UserFile != nil {
		user.File, user.Exists = *doc.UserFile, true
	}
	if doc.ProjectFile != nil {
		project.File, project.Exists = *doc.ProjectFile, true
	}
	p, warns := NewAt(now, user, project)
	l := Loaded{Policy: p, Warnings: warns, Rebuilt: rebuilt}
	if doc.UserErr != "" {
		l.UserErr = errors.New(doc.UserErr)
	}
	if doc.ProjectErr != "" {
		l.ProjectErr = errors.New(doc.ProjectErr)
	}
	return l
}

func readCache(path string) (cacheDoc, bool) {
	if !cacheFileTrusted(path) {
		return cacheDoc{}, false // rebuilt and replaced (0600, ours) by the caller
	}
	b, err := safeio.ReadRegular(path, maxCache, true)
	if err != nil {
		return cacheDoc{}, false
	}
	var doc cacheDoc
	if json.Unmarshal(b, &doc) != nil || doc.V != CacheVersion {
		return cacheDoc{}, false
	}
	return doc, true
}

// cacheFileTrusted reports whether the cache file is a regular file, mode
// 0600 (no group or other bits) and owned by this user. Anything else is
// never read: the cache is rebuilt from the policy files.
func cacheFileTrusted(path string) bool {
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm()&0o077 != 0 {
		return false
	}
	return ownedByMe(fi)
}

// CacheMatchesFresh reports whether the cache at cachePath, read as the
// hook reads it, gives the same policy as parsing the files now (doctor).
// ok is false when there is no usable cache to compare.
func CacheMatchesFresh(cachePath, userPath, projectPath string) (same, ok bool) {
	doc, ok := readCache(cachePath)
	if !ok || doc.User != keyOf(userPath) || doc.Project != keyOf(projectPath) {
		return false, false
	}
	// One clock for both, so a temporary expiring between the two loads
	// cannot make them differ.
	now := time.Now()
	cached := fromDoc(now, doc, false)
	fresh := loadCachedAt(now, "", userPath, projectPath)
	return reflect.DeepEqual(cached.Policy, fresh.Policy) && reflect.DeepEqual(cached.Warnings, fresh.Warnings) &&
		(cached.UserErr == nil) == (fresh.UserErr == nil) && (cached.ProjectErr == nil) == (fresh.ProjectErr == nil), true
}

// writeCache saves doc atomically, 0600. Errors are ignored: the parsed
// result is still used for this call.
func writeCache(path string, doc cacheDoc) {
	b, err := json.Marshal(doc)
	if err != nil {
		return
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	tmp, err := os.CreateTemp(dir, ".policy-cache-*.tmp")
	if err != nil {
		return
	}
	name := tmp.Name()
	_, werr := tmp.Write(b)
	cerr := tmp.Close()
	if werr != nil || cerr != nil || os.Chmod(name, 0o600) != nil || os.Rename(name, path) != nil {
		_ = os.Remove(name)
	}
}
