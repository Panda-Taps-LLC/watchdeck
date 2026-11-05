// Package userconfig reads and writes watchdeck's own settings file,
// paths.Paths.ConfigFile() (ConfigDir/config.yaml, next to overrides.yaml).
// It is separate from overrides.yaml, which holds grants only.
//
//	ui:
//	  autostart: true   # start the dashboard with each Claude Code session
//	installed_at: "2026-10-19T08:30:15Z"   # first successful `setup` completion
//
// The package is init-free; it does nothing until called.
package userconfig

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/goccy/go-yaml"

	"github.com/Panda-Taps-LLC/watchdeck/internal/safeio"
)

// Config is the parsed file. A nil pointer means the key is absent, so a
// caller can tell "never asked" from "answered no".
type Config struct {
	UI UI `yaml:"ui"`
	// Installed is the raw installed_at text; read it through InstalledAt.
	Installed string `yaml:"installed_at"`
}

// UI holds the dashboard settings.
type UI struct {
	Autostart *bool `yaml:"autostart"`
}

// AutostartUI reports the ui.autostart answer and whether one was given.
func (c Config) AutostartUI() (on, set bool) {
	if c.UI.Autostart == nil {
		return false, false
	}
	return *c.UI.Autostart, true
}

// InstalledAt reports when the hooks were first installed and whether a
// valid RFC 3339 date is recorded. A value that does not parse counts as
// not recorded.
func (c Config) InstalledAt() (time.Time, bool) {
	if c.Installed == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, c.Installed)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

// Load reads the file at path. A missing or empty file is a zero Config and
// no error; a file that does not parse is an error.
func Load(path string) (Config, error) {
	var c Config
	b, err := readYAML(path)
	if errors.Is(err, fs.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	if err := yaml.Unmarshal(b, &c); err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

// SetAutostartUI writes ui.autostart into the file at path, keeping every
// other key (comments are not kept). The file is written atomically with
// mode 0600; its directory is created 0700 when missing.
func SetAutostartUI(path string, on bool) error {
	return update(path, func(raw map[string]any) bool {
		ui, _ := raw["ui"].(map[string]any)
		if ui == nil {
			ui = map[string]any{}
		}
		ui["autostart"] = on
		raw["ui"] = ui
		return true
	})
}

// SetInstalledAt records t (UTC, RFC 3339) as installed_at, keeping every
// other key (the rewrite drops comments and may reorder keys, as
// SetAutostartUI does). It never overwrites a date that is already
// recorded: the first successful setup wins, and a second call leaves the file untouched. A
// value that does not parse is not a date and is replaced.
func SetInstalledAt(path string, t time.Time) error {
	return update(path, func(raw map[string]any) bool {
		if s, ok := raw["installed_at"].(string); ok {
			if _, err := time.Parse(time.RFC3339, s); err == nil {
				return false
			}
		}
		raw["installed_at"] = t.UTC().Format(time.RFC3339)
		return true
	})
}

// update reads the file into a generic map, lets edit change it, and writes
// the result atomically (0600, directory 0700) when edit returns true.
func update(path string, edit func(raw map[string]any) bool) error {
	raw := map[string]any{}
	b, err := readYAML(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return err
	default:
		if err := yaml.Unmarshal(b, &raw); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if raw == nil {
			raw = map[string]any{}
		}
	}
	if !edit(raw) {
		return nil
	}
	out, err := yaml.Marshal(raw)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".config-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(out); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Chmod(name, 0o600); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		os.Remove(name)
		return err
	}
	return nil
}

// readYAML reads the config file without blocking (regular files only, at
// most 1 MiB) and refuses YAML nested deeper than safeio.CheckYAML allows.
func readYAML(path string) ([]byte, error) {
	b, err := safeio.ReadRegular(path, safeio.MaxUser, false)
	if err != nil {
		return nil, err
	}
	if err := safeio.CheckYAML(b); err != nil {
		return nil, err
	}
	return b, nil
}
