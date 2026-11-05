// Package skills discovers installed Agent Skills the way Claude Code loads
// them: personal, project, nested, claude.ai-synced, plugin, enterprise, and
// explicitly supplied directories.
//
// Discovery never consults the process environment or the real home
// directory; every root comes in through Roots. Skills are deduplicated by
// their resolved directory (RealRoot), first source wins, and the result is
// sorted by Kind then Name.
package skills

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"github.com/Panda-Taps-LLC/watchdeck/internal/safeio"
	"github.com/Panda-Taps-LLC/watchdeck/internal/skillmd"
)

// Kind is where a skill was discovered. The order is the scan order and the
// primary sort key; it also decides which copy wins when two sources resolve
// to the same directory.
type Kind int

const (
	Personal   Kind = iota // $Home/.claude/skills/<name>
	Project                // <dir>/.claude/skills/<name>, for dir from Cwd up to the git root
	Nested                 // .claude/skills below Cwd (Deep)
	Synced                 // $Home/.claude/skills/synced/<accountId_orgId>/<name>
	Plugin                 // <installPath>/skills/<name> from installed_plugins.json
	Enterprise             // managed skills dir (macOS: /Library/Application Support/ClaudeCode/.claude/skills)
	Dir                    // ExtraDirs (--dir)
	Env                    // Env["CLAUDE_SKILL_DIR"]
)

// errNotRegular is the problem recorded for a SKILL.md that is not a regular file.
var errNotRegular = errors.New("not a regular file (not read; the directory is treated as a skill and its scripts are asked about)")

var kindNames = [...]string{"personal", "project", "nested", "claude.ai sync", "plugin", "enterprise", "dir", "env"}

func (k Kind) String() string {
	if k >= 0 && int(k) < len(kindNames) {
		return kindNames[k]
	}
	return fmt.Sprintf("Kind(%d)", int(k))
}

// Skill is one discovered SKILL.md directory.
type Skill struct {
	Name, DirName string
	Kind          Kind
	Root          string // as discovered (may be a symlink); for display
	RealRoot      string // EvalSymlinks(Root); the dedup key
	PluginID      string // "name@marketplace" for Plugin
	SyncID        string // "<accountId_orgId>" for Synced
	Enabled       bool   // plugins: enabledPlugins[id], default true; everything else true
	Frontmatter   skillmd.Frontmatter
	Problems      []string // discovery problems followed by the frontmatter's Problems
	// SkillMDIrregular is set when SKILL.md exists but is not a regular
	// file (a FIFO, a directory, a device): the directory still counts as a
	// skill, by its directory name, so its scripts are sandboxed and asked
	// about rather than run unconfined (fail closed, M6.3).
	SkillMDIrregular bool
}

// Roots is everything Scan needs; nothing is read from the environment.
type Roots struct {
	Home, Cwd       string
	Env             map[string]string // CLAUDE_SKILL_DIR is honoured
	ExtraDirs       []string          // --dir: a skill dir (contains SKILL.md) or a parent of skill dirs
	All             bool              // include skills of disabled plugins
	Deep            bool              // also find .claude/skills nested below Cwd
	ProjectSettings []string          // extra settings.json paths merged last for enabledPlugins
}

// enterpriseSkillsDir is the managed-skills location; tests point it elsewhere.
// It is initialised from a per-OS constant (enterprise_*.go), not a function
// call, so the package has no init work: it is linked into the hook binary.
var enterpriseSkillsDir = defaultEnterpriseDir

// skipDeepDir reports directory names never descended into by the Deep walk.
func skipDeepDir(name string) bool {
	switch name {
	case ".git", "node_modules", ".venv", "venv", "__pycache__", ".cache", "vendor":
		return true
	}
	return false
}

// Scan discovers skills from every source in r. It returns an error only when
// a root the user asked for is unusable (a missing --dir) or a registry it
// must trust is unreadable (installed_plugins.json, a settings file).
func Scan(r Roots) ([]Skill, error) {
	s := &scanner{roots: r, seen: map[string]bool{}}
	if r.Home != "" {
		s.home = absPath(r.Home)
		s.realHome = realPath(s.home)
	}
	if r.Cwd != "" {
		s.cwd = absPath(r.Cwd)
	}

	s.personal()
	projectRoot := s.project()
	if r.Deep {
		if err := s.nested(); err != nil {
			return nil, err
		}
	}
	s.synced()
	if err := s.plugins(projectRoot); err != nil {
		return nil, err
	}
	s.enterprise()
	if err := s.extraDirs(); err != nil {
		return nil, err
	}
	s.env()

	sort.SliceStable(s.out, func(i, j int) bool {
		a, b := s.out[i], s.out[j]
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.PluginID != b.PluginID {
			return a.PluginID < b.PluginID
		}
		return a.Root < b.Root
	})
	return s.out, nil
}

type scanner struct {
	roots          Roots
	home, realHome string
	cwd            string
	seen           map[string]bool
	out            []Skill
}

// add records the skill rooted at root if it has a SKILL.md and its real
// directory has not been seen. It returns whether a skill was added.
func (s *scanner) add(kind Kind, root string, problems []string, set func(*Skill)) bool {
	path := filepath.Join(root, "SKILL.md")
	fi, err := os.Stat(path)
	if err != nil {
		return false
	}
	irregular := !fi.Mode().IsRegular()
	real := realPath(root)
	if s.seen[real] {
		return false
	}
	s.seen[real] = true

	sk := Skill{
		DirName:  filepath.Base(root),
		Kind:     kind,
		Root:     root,
		RealRoot: real,
		Enabled:  true,
		Problems: problems,
	}
	var fm skillmd.Frontmatter
	if irregular {
		// Never opened: a FIFO or device could block. The name is the
		// directory's.
		err = errNotRegular
		sk.SkillMDIrregular = true
	} else {
		fm, err = skillmd.Parse(path)
	}
	switch {
	case errors.Is(err, skillmd.ErrNoFrontmatter):
		sk.Problems = append(sk.Problems, "SKILL.md: no frontmatter")
	case err != nil:
		sk.Problems = append(sk.Problems, "SKILL.md: "+err.Error())
	default:
		sk.Frontmatter = fm
		sk.Problems = append(sk.Problems, fm.Problems...)
	}
	sk.Name = fm.Name
	if sk.Name == "" {
		sk.Name = sk.DirName
	}
	if set != nil {
		set(&sk)
	}
	s.out = append(s.out, sk)
	return true
}

// addChildren adds every immediate child of dir that holds a SKILL.md.
func (s *scanner) addChildren(kind Kind, dir string, skip string, set func(*Skill)) {
	for _, name := range childDirs(dir) {
		if name == skip {
			continue
		}
		s.add(kind, filepath.Join(dir, name), nil, set)
	}
}

// childDirs lists non-hidden entries of dir in name order. Symlinked entries
// are kept (their type is resolved later by Stat on SKILL.md). A missing or
// unreadable dir yields nothing.
func childDirs(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range entries {
		n := e.Name()
		if n == "" || n[0] == '.' {
			continue
		}
		names = append(names, n)
	}
	return names
}

func (s *scanner) personal() {
	if s.home == "" {
		return
	}
	s.addChildren(Personal, filepath.Join(s.home, ".claude", "skills"), "synced", nil)
}

// project walks from Cwd upward, adding <dir>/.claude/skills at each level,
// and stops after the first directory containing .git, at Home (not scanned,
// that is the personal dir) or at the filesystem root. It returns the project
// root used for settings: the git root, or Cwd when there is none.
func (s *scanner) project() string {
	if s.cwd == "" {
		return ""
	}
	projectRoot := ""
	for d := s.cwd; ; {
		if s.realHome != "" && realPath(d) == s.realHome {
			break
		}
		s.addChildren(Project, filepath.Join(d, ".claude", "skills"), "", nil)
		if exists(filepath.Join(d, ".git")) {
			projectRoot = d
			break
		}
		parent := filepath.Dir(d)
		if parent == d {
			break
		}
		d = parent
	}
	if projectRoot == "" {
		projectRoot = s.cwd
	}
	return projectRoot
}

// nested finds .claude/skills directories below Cwd (Cwd's own is Project
// and already seen). Symlinks are not followed.
func (s *scanner) nested() error {
	if s.cwd == "" {
		return nil
	}
	return filepath.WalkDir(s.cwd, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if path == s.cwd {
				return err
			}
			return nil // unreadable subtree: skip
		}
		if !d.IsDir() || path == s.cwd {
			return nil
		}
		name := d.Name()
		if name == ".claude" {
			s.addChildren(Nested, filepath.Join(path, "skills"), "", nil)
			return fs.SkipDir
		}
		if skipDeepDir(name) || name[0] == '.' {
			return fs.SkipDir
		}
		return nil
	})
}

// syncManifest is the sibling manifest.json of a synced account dir.
type syncManifest struct {
	Skills []struct {
		SkillID string `json:"skillId"`
		Name    string `json:"name"`
	} `json:"skills"`
}

func (s *scanner) synced() {
	if s.home == "" {
		return
	}
	base := filepath.Join(s.home, ".claude", "skills", "synced")
	for _, id := range childDirs(base) {
		idDir := filepath.Join(base, id)
		listed, manifestProblem := readSyncManifest(filepath.Join(idDir, "manifest.json"))
		for _, name := range childDirs(idDir) {
			var problems []string
			if manifestProblem != "" {
				problems = append(problems, manifestProblem)
			} else if !listed[name] {
				problems = append(problems, "not listed in manifest.json")
			}
			s.add(Synced, filepath.Join(idDir, name), problems, func(sk *Skill) { sk.SyncID = id })
		}
	}
}

func readSyncManifest(path string) (listed map[string]bool, problem string) {
	b, err := safeio.ReadRegular(path, safeio.MaxJSON, false)
	if err != nil {
		return nil, "manifest.json: " + err.Error()
	}
	var m syncManifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, "manifest.json: " + err.Error()
	}
	listed = map[string]bool{}
	for _, sk := range m.Skills {
		listed[sk.SkillID] = true
		listed[sk.Name] = true
	}
	return listed, ""
}

// pluginRegistry is installed_plugins.json. Values are decoded leniently: v2
// stores a list of installs per plugin, v1 stored a single object.
type pluginRegistry struct {
	Version int                        `json:"version"`
	Plugins map[string]json.RawMessage `json:"plugins"`
}

type pluginInstall struct {
	Scope       string `json:"scope"`
	InstallPath string `json:"installPath"`
	Version     string `json:"version"`
}

func (s *scanner) plugins(projectRoot string) error {
	if s.home == "" {
		return nil
	}
	regPath := filepath.Join(s.home, ".claude", "plugins", "installed_plugins.json")
	b, err := safeio.ReadRegular(regPath, safeio.MaxJSON, false)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var reg pluginRegistry
	if err := json.Unmarshal(b, &reg); err != nil {
		return fmt.Errorf("%s: %w", regPath, err)
	}

	enabled, err := s.enabledPlugins(projectRoot)
	if err != nil {
		return err
	}

	ids := make([]string, 0, len(reg.Plugins))
	for id := range reg.Plugins {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		on, listed := enabled[id]
		on = on || !listed
		if !on && !s.roots.All {
			continue
		}
		installs, err := decodeInstalls(reg.Plugins[id])
		if err != nil {
			return fmt.Errorf("%s: plugin %q: %w", regPath, id, err)
		}
		for _, in := range installs {
			if in.InstallPath == "" {
				continue
			}
			s.addChildren(Plugin, filepath.Join(in.InstallPath, "skills"), "", func(sk *Skill) {
				sk.PluginID = id
				sk.Enabled = on
			})
		}
	}
	return nil
}

func decodeInstalls(raw json.RawMessage) ([]pluginInstall, error) {
	var list []pluginInstall
	if err := json.Unmarshal(raw, &list); err == nil {
		return list, nil
	}
	var one pluginInstall
	if err := json.Unmarshal(raw, &one); err != nil {
		return nil, err
	}
	return []pluginInstall{one}, nil
}

// enabledPlugins merges the enabledPlugins maps of user settings, project
// settings and ProjectSettings, later files winning. Missing files are fine;
// unparseable ones are errors because they decide what is enforced.
func (s *scanner) enabledPlugins(projectRoot string) (map[string]bool, error) {
	paths := []string{
		filepath.Join(s.home, ".claude", "settings.json"),
		filepath.Join(s.home, ".claude", "settings.local.json"),
	}
	if projectRoot != "" {
		paths = append(paths,
			filepath.Join(projectRoot, ".claude", "settings.json"),
			filepath.Join(projectRoot, ".claude", "settings.local.json"))
	}
	paths = append(paths, s.roots.ProjectSettings...)
	return mergeEnabled(paths)
}

// mergeEnabled merges the enabledPlugins maps of the given settings files,
// later files winning. Missing files are skipped; unreadable or unparseable
// ones are errors.
func mergeEnabled(paths []string) (map[string]bool, error) {
	merged := map[string]bool{}
	for _, p := range paths {
		b, err := safeio.ReadRegular(p, safeio.MaxJSON, false)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		var st struct {
			EnabledPlugins map[string]bool `json:"enabledPlugins"`
		}
		if err := json.Unmarshal(b, &st); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		for k, v := range st.EnabledPlugins {
			merged[k] = v
		}
	}
	return merged, nil
}

func (s *scanner) enterprise() {
	if enterpriseSkillsDir == "" {
		return
	}
	s.addChildren(Enterprise, enterpriseSkillsDir, "", nil)
}

// addDirOrChildren treats dir as a skill when it holds a SKILL.md, otherwise
// as a parent of skill dirs. It reports whether dir exists.
func (s *scanner) addDirOrChildren(kind Kind, dir string) bool {
	dir = absPath(dir)
	fi, err := os.Stat(dir)
	if err != nil || !fi.IsDir() {
		return false
	}
	if exists(filepath.Join(dir, "SKILL.md")) {
		s.add(kind, dir, nil, nil)
		return true
	}
	s.addChildren(kind, dir, "", nil)
	return true
}

func (s *scanner) extraDirs() error {
	for _, d := range s.roots.ExtraDirs {
		if !s.addDirOrChildren(Dir, d) {
			return fmt.Errorf("skills: --dir %s: not a directory", d)
		}
	}
	return nil
}

func (s *scanner) env() {
	if d := s.roots.Env["CLAUDE_SKILL_DIR"]; d != "" {
		s.addDirOrChildren(Env, d)
	}
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

func absPath(p string) string {
	if abs, err := filepath.Abs(p); err == nil {
		return abs
	}
	return filepath.Clean(p)
}

// realPath resolves symlinks; when that fails (dangling link) it falls back to
// the cleaned absolute path so dedup still has a stable key.
func realPath(p string) string {
	p = absPath(p)
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return p
}
