// Package demo backs `watchdeck demo`: an embedded copy of the
// canary-request test skill (testdata/skills/canary-request, kept equal by
// TestDemoEmbeddedMatchesTestdata) is written into a throwaway tree with its
// own HOME, XDG dirs, Claude Code config dir and activity log, and its
// network probe is run under the sandbox through the ordinary runner.
// Nothing of the user's own skills, overrides, settings or activity log is
// read or written.
package demo

import (
	"context"
	"embed"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/Panda-Taps-LLC/watchdeck/internal/runner"

	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
)

// Skill is the embedded skill's name.
const Skill = "canary-request"

//go:embed canary
var canary embed.FS

// Canary is the embedded skill tree, rooted at the skill directory.
func Canary() fs.FS {
	sub, err := fs.Sub(canary, "canary")
	if err != nil {
		panic(err) // the embed pattern above guarantees the directory
	}
	return sub
}

// Env is one demo tree.
type Env struct {
	Base      string // everything below lives here; Remove deletes it
	Home      string // fake HOME holding .claude/skills/canary-request
	Cwd       string // the project the probe runs in
	XDGConfig string // XDG_CONFIG_HOME for the demo
	XDGCache  string // XDG_CACHE_HOME
	XDGState  string // XDG_STATE_HOME
	ClaudeDir string // CLAUDE_CONFIG_DIR: Home/.claude
	Cfg       string // XDGConfig/watchdeck: empty, so no grants
	Activity  string // XDGState/watchdeck/activity.jsonl: the demo's own log
	SkillDir  string
}

// baseDir is where the tree goes. It must not lie under the per-user temp
// dir or /tmp: the profile always allows writes there, and the compiler
// refuses an allow on an ancestor of HOME. /var/tmp is user-writable and
// never allowed (the runner tests use it for the same reason).
func baseDir() string {
	if runtime.GOOS == "darwin" || runtime.GOOS == "linux" {
		if fi, err := os.Stat("/var/tmp"); err == nil && fi.IsDir() {
			return "/var/tmp"
		}
	}
	return ""
}

// Prepare writes the demo tree and returns it.
func Prepare() (*Env, error) {
	base, err := os.MkdirTemp(baseDir(), paths.BinaryName+"-demo-")
	if err != nil {
		return nil, err
	}
	if r, err := filepath.EvalSymlinks(base); err == nil {
		base = r
	}
	e := &Env{
		Base:      base,
		Home:      filepath.Join(base, "home"),
		Cwd:       filepath.Join(base, "proj"),
		XDGConfig: filepath.Join(base, "xdg", "config"),
		XDGCache:  filepath.Join(base, "xdg", "cache"),
		XDGState:  filepath.Join(base, "xdg", "state"),
	}
	e.ClaudeDir = filepath.Join(e.Home, ".claude")
	e.Cfg = filepath.Join(e.XDGConfig, paths.BinaryName)
	e.Activity = filepath.Join(e.XDGState, paths.BinaryName, "activity.jsonl")
	e.SkillDir = filepath.Join(e.ClaudeDir, "skills", Skill)
	for _, d := range []string{e.Cwd, e.Cfg, e.XDGCache, filepath.Dir(e.Activity), filepath.Dir(e.SkillDir)} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			e.Remove()
			return nil, err
		}
	}
	if err := WriteCanary(e.SkillDir); err != nil {
		e.Remove()
		return nil, err
	}
	return e, nil
}

// WriteCanary writes the embedded skill into dst; scripts get mode 0755
// (embed keeps no modes).
func WriteCanary(dst string) error {
	src := Canary()
	return fs.WalkDir(src, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		target := filepath.Join(dst, filepath.FromSlash(p))
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		b, err := fs.ReadFile(src, p)
		if err != nil {
			return err
		}
		mode := os.FileMode(0o644)
		if strings.HasPrefix(p, "scripts/") {
			mode = 0o755
		}
		return os.WriteFile(target, b, mode)
	})
}

// ProbeCommand is the shell text the demo runs: the network probe in strict
// mode, so a denial exits 1 and the runner prints its trailer.
func (e *Env) ProbeCommand(python string) string {
	return python + " " + filepath.Join(e.SkillDir, "scripts", "probe.py") + " net --strict"
}

// replacedEnv reports the variables Environ drops from the parent; those
// naming a location are set to the demo tree instead.
func replacedEnv(name string) bool {
	switch name {
	case "HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME", "CLAUDE_CONFIG_DIR",
		"WATCHDECK_ACTIVITY", runner.ProfileEnvVar, "CLAUDE_SKILL_DIR":
		return true
	}
	return false
}

// Environ is the parent environment pointed entirely at the demo tree: HOME,
// the three XDG dirs, CLAUDE_CONFIG_DIR and WATCHDECK_ACTIVITY name demo
// paths; WATCHDECK_PROFILE and CLAUDE_SKILL_DIR are dropped. A watchdeck
// process started with it (the probe's runner, the dashboard) resolves every
// location inside the demo tree, so it can neither read nor write the user's
// own skills, grants, settings or activity log.
func (e *Env) Environ(parent []string) []string {
	var env []string
	for _, kv := range parent {
		name, _, _ := strings.Cut(kv, "=")
		if replacedEnv(name) {
			continue
		}
		env = append(env, kv)
	}
	return append(env,
		"HOME="+e.Home,
		"XDG_CONFIG_HOME="+e.XDGConfig,
		"XDG_CACHE_HOME="+e.XDGCache,
		"XDG_STATE_HOME="+e.XDGState,
		"CLAUDE_CONFIG_DIR="+e.ClaudeDir,
		"WATCHDECK_ACTIVITY="+e.Activity,
	)
}

// Run executes the probe under the canary's sandbox, as `watchdeck run
// --skill canary-request -c '<ProbeCommand>'` would, and returns its exit
// code. environ is the parent environment; see Environ.
func (e *Env) Run(ctx context.Context, python string, environ []string, stdout, stderr io.Writer) int {
	return runner.Run(ctx, runner.Options{
		Skills:       []string{Skill},
		Command:      e.ProbeCommand(python),
		Env:          runner.Env{Home: e.Home, Cwd: e.Cwd, CacheDir: e.XDGCache, UserCfgDir: e.Cfg},
		Environ:      e.Environ(environ),
		Stdin:        strings.NewReader(""),
		Stdout:       stdout,
		Stderr:       stderr,
		ActivityPath: e.Activity,
	})
}

// Remove deletes the demo tree.
func (e *Env) Remove() error { return os.RemoveAll(e.Base) }
