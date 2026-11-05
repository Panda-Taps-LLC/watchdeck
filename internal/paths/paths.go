// Package paths resolves every file location watchdeck reads or writes from
// a home directory and an environment map, so no other package re-implements
// the XDG rules. It is pure: Resolve touches nothing on disk, ProjectRoot
// performs a handful of Stat calls, and the package has no init work, which
// keeps it free to link into the PreToolUse hook.
package paths

import (
	"os"
	"path/filepath"
	"strings"
)

// Paths is the resolved set of locations. Every field is absolute when Home
// and the XDG variables are; json tags match `watchdeck paths --json`.
type Paths struct {
	Home      string `json:"home"`      // required input
	ConfigDir string `json:"configDir"` // ${XDG_CONFIG_HOME:-$HOME/.config}/watchdeck: watchdeck's own config (overrides.yaml)
	CacheBase string `json:"cacheBase"` // ${XDG_CACHE_HOME:-$HOME/.cache}: index.Path appends watchdeck/index.json
	StateDir  string `json:"stateDir"`  // ${XDG_STATE_HOME:-$HOME/.local/state}/watchdeck
	Activity  string `json:"activity"`  // StateDir/activity.jsonl; WATCHDECK_ACTIVITY=<path> overrides, "off" yields ""
	ClaudeDir string `json:"claudeDir"` // ${CLAUDE_CONFIG_DIR:-$HOME/.claude}: Claude Code's settings.json and projects/ transcripts
	Sessions  string `json:"sessions"`  // StateDir/sessions.jsonl: session lifecycle records (M5.2); WATCHDECK_LIFECYCLE=off yields ""
	LiveDir   string `json:"liveDir"`   // StateDir/live: one marker file per open session (M5.2); WATCHDECK_LIFECYCLE=off yields ""
}

// File and directory names under the resolved roots.
const (
	// BinaryName is the executable and the word the hook rewrites commands to.
	BinaryName = "watchdeck"
	// Trailer prefixes every line the runner writes about a policy decision.
	Trailer = "[" + BinaryName + "] "

	appDir           = BinaryName
	overridesFile    = "overrides.yaml"
	configFile       = "config.yaml"
	indexFile        = "index.json"
	activityFile     = "activity.jsonl"
	sessionIndexDir  = "index"
	claudeSettings   = "settings.json"
	claudeProjects   = "projects"
	activityEnv      = "WATCHDECK_ACTIVITY"
	activityOffValue = "off"
	sessionsFile     = "sessions.jsonl"
	liveDir          = "live"
	lifecycleEnv     = "WATCHDECK_LIFECYCLE"
)

// Resolve computes every location from home and an environment map (see
// EnvMap). An absolute XDG_CONFIG_HOME, XDG_CACHE_HOME or XDG_STATE_HOME
// replaces the corresponding default under home; a relative one is ignored,
// as the XDG Base Directory spec requires. A non-empty CLAUDE_CONFIG_DIR
// replaces ~/.claude.
// WATCHDECK_ACTIVITY=<path> replaces the activity file; the value "off"
// (any case, surrounding space ignored) disables it and Activity is "".
// WATCHDECK_LIFECYCLE=off (same rule) disables the session lifecycle
// records: Sessions and LiveDir are "". Any other value is ignored.
func Resolve(home string, environ map[string]string) Paths {
	p := Paths{Home: home}
	p.ConfigDir = filepath.Join(xdgOrDefault(environ["XDG_CONFIG_HOME"], filepath.Join(home, ".config")), appDir)
	p.CacheBase = xdgOrDefault(environ["XDG_CACHE_HOME"], filepath.Join(home, ".cache"))
	p.StateDir = filepath.Join(xdgOrDefault(environ["XDG_STATE_HOME"], filepath.Join(home, ".local", "state")), appDir)
	p.ClaudeDir = orDefault(environ["CLAUDE_CONFIG_DIR"], filepath.Join(home, ".claude"))
	switch act := strings.TrimSpace(environ[activityEnv]); {
	case act == "":
		p.Activity = filepath.Join(p.StateDir, activityFile)
	case strings.EqualFold(act, activityOffValue):
		p.Activity = ""
	default:
		p.Activity = act
	}
	if !strings.EqualFold(strings.TrimSpace(environ[lifecycleEnv]), activityOffValue) {
		p.Sessions = filepath.Join(p.StateDir, sessionsFile)
		p.LiveDir = filepath.Join(p.StateDir, liveDir)
	}
	return p
}

// xdgOrDefault returns v when it is an absolute path, else def. The XDG Base
// Directory spec says relative values are invalid and must be ignored; using
// one would put state under whatever the current directory is.
func xdgOrDefault(v, def string) string {
	if v != "" && filepath.IsAbs(v) {
		return v
	}
	return def
}

func orDefault(v, def string) string {
	if v != "" {
		return v
	}
	return def
}

// EnvMap turns os.Environ()-style "KEY=value" pairs into a map. A pair without
// "=" or with an empty key is dropped; a later duplicate wins.
func EnvMap(environ []string) map[string]string {
	m := make(map[string]string, len(environ))
	for _, kv := range environ {
		if i := strings.IndexByte(kv, '='); i > 0 {
			m[kv[:i]] = kv[i+1:]
		}
	}
	return m
}

// OverridesFile is the user overrides file, ConfigDir/overrides.yaml.
func (p Paths) OverridesFile() string { return filepath.Join(p.ConfigDir, overridesFile) }

// ConfigFile is watchdeck's own settings, ConfigDir/config.yaml (written
// by `watchdeck setup`; see internal/userconfig).
func (p Paths) ConfigFile() string { return filepath.Join(p.ConfigDir, configFile) }

// IndexFile is the discovery cache, CacheBase/watchdeck/index.json. It equals
// index.Path(p.CacheBase).
func (p Paths) IndexFile() string { return filepath.Join(p.CacheBase, appDir, indexFile) }

// ClaudeSettings is Claude Code's user settings file, ClaudeDir/settings.json.
func (p Paths) ClaudeSettings() string { return filepath.Join(p.ClaudeDir, claudeSettings) }

// ClaudeProjectsDir is where Claude Code keeps session transcripts, ClaudeDir/projects.
func (p Paths) ClaudeProjectsDir() string { return filepath.Join(p.ClaudeDir, claudeProjects) }

// ProjectSettings is a project's Claude Code settings file, projectRoot/.claude/settings.json.
func ProjectSettings(projectRoot string) string {
	return filepath.Join(projectRoot, ".claude", claudeSettings)
}

// ProjectRoot walks up from cwd to the nearest directory containing .git,
// stopping at home or the filesystem root. It returns "" when there is none,
// so a stray repository above the home directory is never treated as the
// project. An empty cwd (a dashboard with no working directory) has none.
func ProjectRoot(cwd, home string) string {
	if cwd == "" {
		return ""
	}
	d := filepath.Clean(cwd)
	for {
		if _, err := os.Stat(filepath.Join(d, ".git")); err == nil {
			return d
		}
		if d == home || d == "/" || d == filepath.Dir(d) {
			return ""
		}
		d = filepath.Dir(d)
	}
}

// SessionIndexDir is the session index (M5.4), StateDir/index: meta.json and
// text/<sha256 of the session id>.txt, dirs 0700 and files 0600.
func (p Paths) SessionIndexDir() string { return filepath.Join(p.StateDir, sessionIndexDir) }

// HookCandidates are the install dirs plugin/bin/hook.sh tries after PATH, in order.
func HookCandidates(home string) []string {
	return []string{
		filepath.Join(home, ".local", "share", BinaryName, "bin", BinaryName),
		"/opt/homebrew/bin/" + BinaryName,
		"/usr/local/bin/" + BinaryName,
	}
}
