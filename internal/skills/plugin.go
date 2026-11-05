package skills

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Panda-Taps-LLC/watchdeck/internal/safeio"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
)

// PluginActive reports whether a plugin called name (any marketplace: the
// registry key is "<name>@<marketplace>") is installed in
// claudeDir/plugins/installed_plugins.json and enabled, by the same rule
// discovery uses: the enabledPlugins maps of claudeDir/settings.json,
// claudeDir/settings.local.json and, when projectRoot is set, the project's
// .claude/settings.json and settings.local.json, later files winning; a
// plugin no file lists counts as enabled. It returns the first active
// plugin id. A plugin loaded with `claude --plugin-dir` leaves no trace in
// either file and is not seen here.
func PluginActive(claudeDir, projectRoot, name string) (string, bool, error) {
	regPath := filepath.Join(claudeDir, "plugins", "installed_plugins.json")
	b, err := safeio.ReadRegular(regPath, safeio.MaxJSON, false)
	if errors.Is(err, fs.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	var reg pluginRegistry
	if err := json.Unmarshal(b, &reg); err != nil {
		return "", false, fmt.Errorf("%s: %w", regPath, err)
	}
	var ids []string
	for id := range reg.Plugins {
		if strings.HasPrefix(id, name+"@") || id == name {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return "", false, nil
	}
	sort.Strings(ids)
	settingsFiles := []string{
		filepath.Join(claudeDir, "settings.json"),
		filepath.Join(claudeDir, "settings.local.json"),
	}
	if projectRoot != "" {
		settingsFiles = append(settingsFiles,
			filepath.Join(projectRoot, ".claude", "settings.json"),
			filepath.Join(projectRoot, ".claude", "settings.local.json"))
	}
	enabled, err := mergeEnabled(settingsFiles)
	if err != nil {
		return "", false, err
	}
	for _, id := range ids {
		if on, listed := enabled[id]; on || !listed {
			return id, true, nil
		}
	}
	return "", false, nil
}
