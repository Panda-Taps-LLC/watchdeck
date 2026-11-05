package skills

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPluginActive(t *testing.T) {
	claude := t.TempDir()
	proj := t.TempDir()
	write := func(p, s string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if _, ok, err := PluginActive(claude, proj, "watchdeck"); ok || err != nil {
		t.Fatalf("no registry: ok=%v err=%v", ok, err)
	}
	write(filepath.Join(claude, "plugins", "installed_plugins.json"),
		`{"version":2,"plugins":{"watchdeck@watchdeck":[{"scope":"user","installPath":"/fake/p","version":"0.1.0"}],"other@mkt":[]}}`)
	id, ok, err := PluginActive(claude, proj, "watchdeck")
	if !ok || err != nil || id != "watchdeck@watchdeck" {
		t.Fatalf("installed, unlisted: id=%q ok=%v err=%v", id, ok, err)
	}
	write(filepath.Join(claude, "settings.json"), `{"enabledPlugins":{"watchdeck@watchdeck":false}}`)
	if _, ok, _ := PluginActive(claude, proj, "watchdeck"); ok {
		t.Fatal("disabled in user settings but reported active")
	}
	write(filepath.Join(proj, ".claude", "settings.local.json"), `{"enabledPlugins":{"watchdeck@watchdeck":true}}`)
	if _, ok, _ := PluginActive(claude, proj, "watchdeck"); !ok {
		t.Fatal("re-enabled by the project's local settings but reported inactive")
	}
	if _, ok, _ := PluginActive(claude, proj, "skill"); ok {
		t.Fatal("a name prefix matched another plugin")
	}
	write(filepath.Join(claude, "settings.json"), `{`)
	if _, _, err := PluginActive(claude, proj, "watchdeck"); err == nil {
		t.Fatal("unparseable settings: want an error")
	}
}
