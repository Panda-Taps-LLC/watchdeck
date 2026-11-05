package claudesettings

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"

	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
	"github.com/Panda-Taps-LLC/watchdeck/internal/safeio"
)

// The hook's native-rules cache (Plan 02 Task 7), modelled on the policy
// cache (internal/policy/cache.go). Reading and parsing up to five JSON
// settings files and listing the managed drop-in directory on every
// rewrite would cost more than a hook call may spend, so the Bash rules
// found in them are kept as JSON, keyed by the stat (size, mtime, mode,
// existence) of every candidate: the managed file, the managed drop-in
// directory itself (its mtime changes when a drop-in is added, removed or
// renamed), each drop-in, and the user, project and local files. A call
// stats those; when nothing changed it reads the cache (one small file),
// and when no candidate exists it reads and writes nothing.
//
// The cache lives in watchdeck's state dir, which the sandbox denies to
// skill scripts, so a sandboxed script cannot plant a cache that drops a
// deny rule. It is read only when it is a regular 0600 file owned by this
// user, and written 0600 through a temp file and a rename.

// RulesCacheVersion is the on-disk format of the native-rules cache.
const RulesCacheVersion = 1

// RulesCacheFile is the cache's file name under the state dir.
const RulesCacheFile = "claude-rules-cache.json"

const maxRulesCache = 4 << 20

type statKey struct {
	Path   string `json:"path"`
	Exists bool   `json:"exists,omitempty"`
	Size   int64  `json:"size,omitempty"`
	Mtime  int64  `json:"mtime,omitempty"` // unix nanos
	Mode   uint32 `json:"mode,omitempty"`
}

type rulesDoc struct {
	V     int        `json:"v"`
	Keys  []statKey  `json:"keys"` // every candidate, in a fixed order
	Rules []BashRule `json:"rules,omitempty"`
}

func statOf(path string) statKey {
	k := statKey{Path: path}
	fi, err := os.Stat(path)
	if err != nil {
		return k
	}
	k.Exists, k.Size, k.Mtime, k.Mode = true, fi.Size(), fi.ModTime().UnixNano(), uint32(fi.Mode())
	return k
}

// LoadCachedRules returns the Bash rules of the settings files at locs,
// through the cache at cachePath ("" = no cache). The key is the stat of
// each location; a caller that wants a new managed drop-in noticed without
// listing the directory on every call uses LoadCachedRulesFor.
func LoadCachedRules(cachePath string, locs []Location) []BashRule {
	keys := make([]statKey, len(locs))
	exists := false
	for i, l := range locs {
		keys[i] = statOf(l.Path)
		exists = exists || keys[i].Exists
	}
	if !exists {
		return nil
	}
	return cachedOrRead(cachePath, keys, func() []Location { return locs })
}

// LoadCachedRulesFor is LoadCachedRules for the files Locate lists for
// this OS, paths and project root, without listing the managed drop-in
// directory unless its stat changed since the cache was written.
func LoadCachedRulesFor(cachePath string, p paths.Paths, projectRoot string) []BashRule {
	return loadCachedRulesAt(cachePath, managedDir(runtime.GOOS), p, projectRoot)
}

// LoadCachedRulesAt is LoadCachedRulesFor with the managed directory as a
// parameter ("" for none), for callers whose tests must not read this
// machine's /Library or /etc.
func LoadCachedRulesAt(cachePath, managed string, p paths.Paths, projectRoot string) []BashRule {
	return loadCachedRulesAt(cachePath, managed, p, projectRoot)
}

func loadCachedRulesAt(cachePath, managed string, p paths.Paths, projectRoot string) []BashRule {
	// The fixed candidates: everything Locate lists but the drop-ins, plus
	// the drop-in directory itself.
	fixed := locate("", p, projectRoot)
	var keys []statKey
	if managed != "" {
		keys = append(keys, statOf(filepath.Join(managed, managedFile)), statOf(filepath.Join(managed, managedDropIns)))
	}
	for _, l := range fixed {
		keys = append(keys, statOf(l.Path))
	}
	exists := false
	for _, k := range keys {
		exists = exists || k.Exists
	}
	if !exists {
		return nil // nothing to read: stats only
	}
	if cachePath != "" {
		if doc, ok := readRulesCache(cachePath); ok && len(doc.Keys) >= len(keys) && keysEqual(doc.Keys[:len(keys)], keys) {
			// the drop-ins listed when the cache was written, unchanged?
			same := true
			for _, k := range doc.Keys[len(keys):] {
				if statOf(k.Path) != k {
					same = false
					break
				}
			}
			if same {
				return doc.Rules
			}
		}
	}
	locs := locate(managed, p, projectRoot)
	// the full key: the fixed candidates, then each drop-in Locate listed
	full := append([]statKey(nil), keys...)
	for _, l := range locs {
		if l.Scope == ScopeManaged && l.Path != filepath.Join(managed, managedFile) {
			full = append(full, statOf(l.Path))
		}
	}
	return readAndCache(cachePath, full, locs)
}

func keysEqual(a, b []statKey) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func cachedOrRead(cachePath string, keys []statKey, locs func() []Location) []BashRule {
	if cachePath != "" {
		if doc, ok := readRulesCache(cachePath); ok && keysEqual(doc.Keys, keys) {
			return doc.Rules
		}
	}
	return readAndCache(cachePath, keys, locs())
}

// readAndCache reads locs, extracts the Bash rules (an unreadable existing
// file becomes an Unreadable rule) and saves them under keys.
func readAndCache(cachePath string, keys []statKey, locs []Location) []BashRule {
	eff, _ := Read(locs, nil) // an all-failed Read still lists each file's error
	rules := BashRules(eff)
	for _, f := range eff.Files {
		if f.Exists && f.Err != nil {
			rules = append(rules, BashRule{Pattern: "*", Kind: KindAsk, Scope: f.Scope, Unreadable: true, Path: f.Path})
		}
	}
	if cachePath != "" {
		writeRulesCache(cachePath, rulesDoc{V: RulesCacheVersion, Keys: keys, Rules: rules})
	}
	return rules
}

func readRulesCache(path string) (rulesDoc, bool) {
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm()&0o077 != 0 || !ownedByMe(fi) {
		return rulesDoc{}, false // rebuilt and replaced (0600, ours)
	}
	b, err := safeio.ReadRegular(path, maxRulesCache, true)
	if err != nil {
		return rulesDoc{}, false
	}
	var doc rulesDoc
	if json.Unmarshal(b, &doc) != nil || doc.V != RulesCacheVersion {
		return rulesDoc{}, false
	}
	return doc, true
}

// writeRulesCache saves doc atomically, 0600. Errors are ignored: the
// rules just read are still used for this call.
func writeRulesCache(path string, doc rulesDoc) {
	b, err := json.Marshal(doc)
	if err != nil {
		return
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	tmp, err := os.CreateTemp(dir, ".claude-rules-*.tmp")
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
