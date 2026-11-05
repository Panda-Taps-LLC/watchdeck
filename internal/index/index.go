// Package index caches skill discovery so the PreToolUse hook can decide in
// a few milliseconds without walking directories or parsing YAML.
//
// The cache lives at <cacheDir>/watchdeck/index.json and records the mtimes
// of every input that can change the answer. Freshness is a handful of stats.
package index

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/manifest"
	"github.com/Panda-Taps-LLC/watchdeck/internal/match"
	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
	"github.com/Panda-Taps-LLC/watchdeck/internal/safeio"
	"github.com/Panda-Taps-LLC/watchdeck/internal/skills"
)

// Version of the on-disk format.
// 2 (M6.3): entries carry skillmd_irregular; a version-1 cache is rebuilt.
const Version = 2

// Entry is one indexed skill.
type Entry struct {
	Name          string   `json:"name"`
	Dir           string   `json:"dir"`               // real root (dedup key)
	Aliases       []string `json:"aliases,omitempty"` // other paths that reach the same root (symlinks)
	Source        string   `json:"source"`
	PluginID      string   `json:"plugin_id,omitempty"`
	Enabled       bool     `json:"enabled"`
	Scripts       []string `json:"scripts"`                  // globs governing which files are this skill's code
	Manifest      string   `json:"manifest,omitempty"`       // PERMISSIONS.yaml path when present
	ManifestMtime int64    `json:"manifest_mtime,omitempty"` // unix nanos
	ManifestError string   `json:"manifest_error,omitempty"`
	// SkillMDIrregular: SKILL.md is not a regular file (FIFO, directory,
	// device). The hook still sandboxes the scripts and always asks.
	SkillMDIrregular bool `json:"skillmd_irregular,omitempty"`
}

// Input is a path whose mtime invalidates the index when it changes. Mtime 0 = absent.
type Input struct {
	Path  string `json:"path"`
	Mtime int64  `json:"mtime"`
}

// Index is the cached discovery result.
type Index struct {
	Version     int       `json:"version"`
	BuiltAt     time.Time `json:"built_at"`
	Home        string    `json:"home"`
	ProjectRoot string    `json:"project_root,omitempty"`
	Inputs      []Input   `json:"inputs"`
	Entries     []Entry   `json:"skills"`
	NeedleList  []string  `json:"needles"`
}

// GenericNeedles are substrings that mean "parse this command" even when no
// absolute skill root appears in it.
var GenericNeedles = []string{".claude/skills", ".agents/skills", "scripts/", "CLAUDE_SKILL_DIR"}

// Path returns the index file location under a cache directory.
func Path(cacheDir string) string {
	return filepath.Join(cacheDir, paths.BinaryName, "index.json")
}

// Skills implements match.Index.
func (ix *Index) Skills() []match.IndexedSkill {
	out := make([]match.IndexedSkill, 0, len(ix.Entries))
	for _, e := range ix.Entries {
		if !e.Enabled {
			continue
		}
		out = append(out, match.IndexedSkill{Name: e.Name, Dir: e.Dir, Aliases: e.Aliases, Scripts: e.Scripts})
	}
	return out
}

// Needles implements match.Index.
func (ix *Index) Needles() []string { return ix.NeedleList }

// Lookup finds an entry by skill name.
func (ix *Index) Lookup(name string) (Entry, bool) {
	for _, e := range ix.Entries {
		if e.Name == name {
			return e, true
		}
	}
	return Entry{}, false
}

func mtime(p string) int64 {
	st, err := os.Stat(p)
	if err != nil {
		return 0
	}
	return st.ModTime().UnixNano()
}

// Fresh reports whether every recorded input still has the same mtime and the
// project root matches the caller's.
func (ix *Index) Fresh(projectRoot string) bool {
	if ix.Version != Version || ix.ProjectRoot != projectRoot {
		return false
	}
	for _, in := range ix.Inputs {
		if mtime(in.Path) != in.Mtime {
			return false
		}
	}
	return true
}

// ManifestStale reports whether a skill's PERMISSIONS.yaml changed or appeared
// since the index was built. Callers re-read the manifest when true.
func (ix *Index) ManifestStale(e Entry) bool {
	p := e.Manifest
	if p == "" {
		p = filepath.Join(e.Dir, "PERMISSIONS.yaml")
	}
	return mtime(p) != e.ManifestMtime
}

// ProjectRoot walks up from cwd to the nearest directory containing .git,
// stopping at home or the filesystem root. Returns "" when none. It is
// paths.ProjectRoot; kept here so existing callers need not change.
func ProjectRoot(cwd, home string) string { return paths.ProjectRoot(cwd, home) }

// Build runs discovery and records inputs. userCfgDir is where overrides.yaml lives.
func Build(roots skills.Roots, userCfgDir string) (*Index, error) {
	found, err := skills.Scan(roots)
	if err != nil {
		return nil, err
	}
	home := roots.Home
	project := ProjectRoot(roots.Cwd, home)
	ix := &Index{Version: Version, BuiltAt: time.Now().UTC(), Home: home, ProjectRoot: project}

	inputs := []string{
		filepath.Join(home, ".claude", "skills"),
		filepath.Join(home, ".claude", "skills", "synced"),
		filepath.Join(home, ".agents", "skills"),
		filepath.Join(home, ".claude", "plugins", "installed_plugins.json"),
		filepath.Join(home, ".claude", "settings.json"),
		filepath.Join(home, ".claude", "settings.local.json"),
		filepath.Join(userCfgDir, "overrides.yaml"),
	}
	if project != "" {
		inputs = append(inputs,
			filepath.Join(project, ".claude", "skills"),
			filepath.Join(project, ".claude", "settings.json"),
			filepath.Join(project, ".claude", "settings.local.json"),
			filepath.Join(project, manifest.ProjectOverridesFile),
		)
	}
	for _, p := range inputs {
		ix.Inputs = append(ix.Inputs, Input{Path: p, Mtime: mtime(p)})
	}

	for _, s := range found {
		e := Entry{
			Name:             s.Name,
			Dir:              s.RealRoot,
			Source:           s.Kind.String(),
			PluginID:         s.PluginID,
			Enabled:          s.Enabled,
			SkillMDIrregular: s.SkillMDIrregular,
			Scripts:          manifest.Default().Scripts,
		}
		if s.Root != s.RealRoot {
			e.Aliases = []string{s.Root}
		}
		mp := filepath.Join(s.RealRoot, "PERMISSIONS.yaml")
		if st, err := os.Stat(mp); err == nil {
			e.Manifest = mp
			e.ManifestMtime = st.ModTime().UnixNano()
			if m, err := manifest.Parse(mp); err != nil {
				e.ManifestError = err.Error()
			} else if len(m.Scripts) > 0 {
				e.Scripts = m.Scripts
			}
		}
		ix.Entries = append(ix.Entries, e)
	}
	// Needles: every enabled root and alias in absolute, ~/, $HOME/ and
	// ${HOME}/ spellings plus the generic markers. FastReject is purely
	// textual, so every spelling a command might use has to be present.
	ix.NeedleList = match.BuildNeedles(home, ix.Skills())
	ix.NeedleList = append(ix.NeedleList, GenericNeedles...)
	sort.Strings(ix.NeedleList)
	ix.NeedleList = dedupe(ix.NeedleList)
	return ix, nil
}

// Load reads an index file.
func Load(path string) (*Index, error) {
	b, err := safeio.ReadRegular(path, 4*safeio.MaxJSON, false)
	if err != nil {
		return nil, err
	}
	var ix Index
	if err := json.Unmarshal(b, &ix); err != nil {
		return nil, err
	}
	return &ix, nil
}

// Save writes the index atomically.
func (ix *Index) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(ix, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".index-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	return os.Rename(name, path)
}

// LoadOrBuild returns a fresh index, rebuilding and saving when the cached one
// is missing, unreadable, or stale. rebuilt reports which happened.
func LoadOrBuild(path string, roots skills.Roots, userCfgDir string) (ix *Index, rebuilt bool, err error) {
	project := ProjectRoot(roots.Cwd, roots.Home)
	if cached, lerr := Load(path); lerr == nil && cached.Fresh(project) {
		return cached, false, nil
	} else if lerr != nil && !errors.Is(lerr, os.ErrNotExist) {
		_ = lerr // unreadable cache: rebuild below
	}
	ix, err = Build(roots, userCfgDir)
	if err != nil {
		return nil, true, err
	}
	if serr := ix.Save(path); serr != nil {
		// A read-only cache dir must not break the hook; the in-memory index is still usable.
		return ix, true, nil
	}
	return ix, true, nil
}

func dedupe(xs []string) []string {
	out := xs[:0]
	for i, x := range xs {
		if i == 0 || x != xs[i-1] {
			out = append(out, x)
		}
	}
	return out
}
