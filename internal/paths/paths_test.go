package paths

import (
	"os"
	"path/filepath"
	"testing"
)

// Every test builds its home under t.TempDir(); nothing here reads the
// developer's real home or environment.

func TestResolveDefaults(t *testing.T) {
	home := t.TempDir()
	p := Resolve(home, map[string]string{})
	want := Paths{
		Home:      home,
		ConfigDir: filepath.Join(home, ".config", "watchdeck"),
		CacheBase: filepath.Join(home, ".cache"),
		StateDir:  filepath.Join(home, ".local", "state", "watchdeck"),
		Activity:  filepath.Join(home, ".local", "state", "watchdeck", "activity.jsonl"),
		ClaudeDir: filepath.Join(home, ".claude"),
		Sessions:  filepath.Join(home, ".local", "state", "watchdeck", "sessions.jsonl"),
		LiveDir:   filepath.Join(home, ".local", "state", "watchdeck", "live"),
	}
	if p != want {
		t.Fatalf("Resolve defaults:\n got %+v\nwant %+v", p, want)
	}
	if got, want := p.OverridesFile(), filepath.Join(home, ".config", "watchdeck", "overrides.yaml"); got != want {
		t.Errorf("OverridesFile = %q, want %q", got, want)
	}
	if got, want := p.IndexFile(), filepath.Join(home, ".cache", "watchdeck", "index.json"); got != want {
		t.Errorf("IndexFile = %q, want %q", got, want)
	}
	if got, want := p.ClaudeSettings(), filepath.Join(home, ".claude", "settings.json"); got != want {
		t.Errorf("ClaudeSettings = %q, want %q", got, want)
	}
	if got, want := p.ClaudeProjectsDir(), filepath.Join(home, ".claude", "projects"); got != want {
		t.Errorf("ClaudeProjectsDir = %q, want %q", got, want)
	}
	if got, want := ProjectSettings(filepath.Join(home, "proj")), filepath.Join(home, "proj", ".claude", "settings.json"); got != want {
		t.Errorf("ProjectSettings = %q, want %q", got, want)
	}
}

func TestResolveXDG(t *testing.T) {
	home := t.TempDir()
	env := map[string]string{
		"XDG_CONFIG_HOME":   "/x/cfg",
		"XDG_CACHE_HOME":    "/x/cache",
		"XDG_STATE_HOME":    "/x/state",
		"CLAUDE_CONFIG_DIR": "/x/claude",
	}
	p := Resolve(home, env)
	want := Paths{
		Home:      home,
		ConfigDir: "/x/cfg/watchdeck",
		CacheBase: "/x/cache",
		StateDir:  "/x/state/watchdeck",
		Activity:  "/x/state/watchdeck/activity.jsonl",
		ClaudeDir: "/x/claude",
		Sessions:  "/x/state/watchdeck/sessions.jsonl",
		LiveDir:   "/x/state/watchdeck/live",
	}
	if p != want {
		t.Fatalf("Resolve XDG:\n got %+v\nwant %+v", p, want)
	}
	if got := p.OverridesFile(); got != "/x/cfg/watchdeck/overrides.yaml" {
		t.Errorf("OverridesFile = %q", got)
	}
	if got := p.IndexFile(); got != "/x/cache/watchdeck/index.json" {
		t.Errorf("IndexFile = %q", got)
	}
	if got := p.ClaudeSettings(); got != "/x/claude/settings.json" {
		t.Errorf("ClaudeSettings = %q", got)
	}
	// An empty variable means "unset", as for the shell.
	if q := Resolve(home, map[string]string{"XDG_CONFIG_HOME": ""}); q.ConfigDir != filepath.Join(home, ".config", "watchdeck") {
		t.Errorf("empty XDG_CONFIG_HOME should fall back, got %q", q.ConfigDir)
	}
}

// TestLifecycleOff: WATCHDECK_LIFECYCLE=off (any case, padded) empties
// Sessions and LiveDir; any other value leaves them; the activity log is
// independent of it.
func TestLifecycleOff(t *testing.T) {
	home := t.TempDir()
	for _, off := range []string{"off", "OFF", " Off "} {
		p := Resolve(home, map[string]string{"WATCHDECK_LIFECYCLE": off})
		if p.Sessions != "" || p.LiveDir != "" {
			t.Errorf("WATCHDECK_LIFECYCLE=%q: Sessions=%q LiveDir=%q, want empty", off, p.Sessions, p.LiveDir)
		}
		if p.Activity == "" {
			t.Errorf("WATCHDECK_LIFECYCLE=%q turned the activity log off", off)
		}
	}
	for _, on := range []string{"", "on", "1", "/x/y"} {
		if p := Resolve(home, map[string]string{"WATCHDECK_LIFECYCLE": on}); p.Sessions == "" || p.LiveDir == "" {
			t.Errorf("WATCHDECK_LIFECYCLE=%q disabled the lifecycle", on)
		}
	}
	if p := Resolve(home, map[string]string{"WATCHDECK_ACTIVITY": "off"}); p.Sessions == "" {
		t.Error("WATCHDECK_ACTIVITY=off disabled the lifecycle")
	}
}

func TestActivityOverride(t *testing.T) {
	home := t.TempDir()
	if p := Resolve(home, map[string]string{"WATCHDECK_ACTIVITY": "/x/y.jsonl"}); p.Activity != "/x/y.jsonl" {
		t.Errorf("Activity = %q, want /x/y.jsonl", p.Activity)
	}
	for _, off := range []string{"off", "OFF", " off "} {
		if p := Resolve(home, map[string]string{"WATCHDECK_ACTIVITY": off}); p.Activity != "" {
			t.Errorf("WATCHDECK_ACTIVITY=%q: Activity = %q, want \"\"", off, p.Activity)
		}
	}
	// The override does not move the state dir itself.
	p := Resolve(home, map[string]string{"WATCHDECK_ACTIVITY": "/x/y.jsonl", "XDG_STATE_HOME": "/s"})
	if p.StateDir != "/s/watchdeck" {
		t.Errorf("StateDir = %q", p.StateDir)
	}
}

func TestEnvMap(t *testing.T) {
	m := EnvMap([]string{"A=1", "B=x=y", "NOEQ", "=empty", "A=2"})
	if len(m) != 2 || m["A"] != "2" || m["B"] != "x=y" {
		t.Fatalf("EnvMap = %v", m)
	}
}

func TestProjectRootStopsAtHome(t *testing.T) {
	// above/.git exists, home is above/home: the walk from inside home must
	// never reach it.
	above := t.TempDir()
	if err := os.MkdirAll(filepath.Join(above, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(above, "home")
	proj := filepath.Join(home, "p")
	for _, d := range []string{filepath.Join(proj, ".git"), filepath.Join(proj, "a", "b"), filepath.Join(home, "plain", "sub")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if got := ProjectRoot(filepath.Join(proj, "a", "b"), home); got != proj {
		t.Errorf("ProjectRoot from below = %q, want %q", got, proj)
	}
	if got := ProjectRoot(proj, home); got != proj {
		t.Errorf("ProjectRoot at root = %q, want %q", got, proj)
	}
	if got := ProjectRoot(home, home); got != "" {
		t.Errorf("home itself (no .git) must not be a project: %q", got)
	}
	if got := ProjectRoot(filepath.Join(home, "plain", "sub"), home); got != "" {
		t.Errorf("walk must stop at home, not find %s: got %q", filepath.Join(above, ".git"), got)
	}
	// Without a home boundary the same walk does reach it.
	if got := ProjectRoot(filepath.Join(home, "plain", "sub"), ""); got != above {
		t.Errorf("unbounded walk = %q, want %q", got, above)
	}
}

// TestRelativeXDGIgnored: relative XDG_* values are invalid per the XDG Base
// Directory spec and fall back to the defaults, so state never lands under
// the current directory (and the run sandbox's state-dir deny stays absolute).
func TestRelativeXDGIgnored(t *testing.T) {
	p := Resolve("/h", map[string]string{"XDG_CONFIG_HOME": "cfg", "XDG_CACHE_HOME": "./cache", "XDG_STATE_HOME": "state"})
	if p.ConfigDir != "/h/.config/watchdeck" || p.CacheBase != "/h/.cache" || p.StateDir != "/h/.local/state/watchdeck" {
		t.Errorf("relative XDG used: %+v", p)
	}
	if p.Activity != "/h/.local/state/watchdeck/activity.jsonl" {
		t.Errorf("activity: %q", p.Activity)
	}
}
