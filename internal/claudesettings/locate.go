package claudesettings

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
)

// Scope names a settings file's level.
type Scope string

// The four scopes Claude Code reads.
const (
	ScopeManaged Scope = "managed"
	ScopeUser    Scope = "user"
	ScopeProject Scope = "project"
	ScopeLocal   Scope = "local"
)

const (
	darwinManagedDir = "/Library/Application Support/ClaudeCode"
	linuxManagedDir  = "/etc/claude-code"
	managedFile      = "managed-settings.json"
	managedDropIns   = "managed-settings.d"
	settingsFile     = "settings.json"
	localFile        = "settings.local.json"
	projectDir       = ".claude"
)

// Location is one settings file Claude Code may read. ReadOnly marks the
// managed files, which an administrator owns.
type Location struct {
	Scope    Scope
	Path     string
	ReadOnly bool
}

// Locate lists the settings files for this OS and project root in
// precedence order (see the package doc). Missing files are still listed so
// a caller can show them; an empty projectRoot lists no project or local
// file. The only disk access is reading the managed-settings.d directory.
func Locate(p paths.Paths, projectRoot string) []Location {
	return locate(managedDir(runtime.GOOS), p, projectRoot)
}

// ManagedDirOverride, when non-nil, replaces the managed-settings directory
// for every OS. It is nil in production; tests in other packages set it to a
// temp dir so they never read the real /Library or /etc. It is deliberately
// not an environment variable: a person (or a model) could set one to route a
// managed deny around watchdeck's hook.
var ManagedDirOverride func() string

// managedDir is the managed-settings directory for goos, or "" when this
// package knows none for it.
func managedDir(goos string) string {
	if ManagedDirOverride != nil {
		return ManagedDirOverride()
	}
	switch goos {
	case "darwin":
		return darwinManagedDir
	case "linux":
		return linuxManagedDir
	}
	return ""
}

// locate is Locate with the managed directory as a parameter ("" for none),
// so tests never depend on this machine's /Library or /etc.
func locate(managed string, p paths.Paths, projectRoot string) []Location {
	var locs []Location
	if managed != "" {
		locs = append(locs, Location{Scope: ScopeManaged, Path: filepath.Join(managed, managedFile), ReadOnly: true})
		dir := filepath.Join(managed, managedDropIns)
		entries, _ := os.ReadDir(dir) // sorted by name; a missing dir lists nothing
		for _, e := range entries {
			name := e.Name()
			if strings.HasPrefix(name, ".") || !strings.HasSuffix(name, ".json") {
				continue
			}
			path := filepath.Join(dir, name)
			if e.IsDir() {
				continue
			}
			if e.Type()&os.ModeSymlink != 0 {
				if fi, err := os.Stat(path); err == nil && fi.IsDir() {
					continue
				}
			}
			locs = append(locs, Location{Scope: ScopeManaged, Path: path, ReadOnly: true})
		}
	}
	claudeDir := p.ClaudeDir
	if claudeDir == "" {
		claudeDir = filepath.Join(p.Home, ".claude")
	}
	locs = append(locs, Location{Scope: ScopeUser, Path: filepath.Join(claudeDir, settingsFile)})
	if projectRoot != "" {
		locs = append(locs,
			Location{Scope: ScopeProject, Path: filepath.Join(projectRoot, projectDir, settingsFile)},
			Location{Scope: ScopeLocal, Path: filepath.Join(projectRoot, projectDir, localFile)},
		)
	}
	return locs
}
