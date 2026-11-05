package demo

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
)

// TestDemoEmbeddedMatchesTestdata: the embedded canary is byte-for-byte the
// test fixture, file set included. Edit testdata/skills/canary-request and
// copy it here, never the other way round.
func TestDemoEmbeddedMatchesTestdata(t *testing.T) {
	src := filepath.Join("..", "..", "testdata", "skills", Skill)
	want := map[string][]byte{}
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		b, err := os.ReadFile(p)
		want[filepath.ToSlash(rel)] = b
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]byte{}
	err = fs.WalkDir(Canary(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := fs.ReadFile(Canary(), p)
		got[p] = b
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("embedded files %v, testdata files %v", keys(got), keys(want))
	}
	for name, b := range want {
		if !bytes.Equal(got[name], b) {
			t.Errorf("%s differs from testdata (or is missing)", name)
		}
	}
}

func TestWriteCanaryModes(t *testing.T) {
	dst := t.TempDir()
	if err := WriteCanary(dst); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(dst, "scripts", "probe.py"))
	if err != nil || fi.Mode().Perm() != 0o755 {
		t.Fatalf("probe.py: %v, %v", fi, err)
	}
	if _, err := os.Stat(filepath.Join(dst, "PERMISSIONS.yaml")); err != nil {
		t.Fatal(err)
	}
}

// TestEnvironStaysInTheDemoTree: every location watchdeck resolves from the
// demo environment lies inside the demo tree, whatever the parent had.
func TestEnvironStaysInTheDemoTree(t *testing.T) {
	e, err := Prepare()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Remove() })
	parent := []string{"PATH=/usr/bin:/bin", "HOME=/Users/you", "XDG_CONFIG_HOME=/Users/you/.config",
		"XDG_CACHE_HOME=/Users/you/.cache", "XDG_STATE_HOME=/Users/you/.local/state", "CLAUDE_CONFIG_DIR=/Users/you/.claude",
		"WATCHDECK_ACTIVITY=/Users/you/act.jsonl", "WATCHDECK_PROFILE=abc", "CLAUDE_SKILL_DIR=/Users/you/skills/x", "LANG=C"}
	env := e.Environ(parent)
	m := paths.EnvMap(env)
	if m["PATH"] != "/usr/bin:/bin" || m["LANG"] != "C" {
		t.Errorf("unrelated variables lost: %v", env)
	}
	if _, ok := m["WATCHDECK_PROFILE"]; ok {
		t.Error("WATCHDECK_PROFILE kept")
	}
	if _, ok := m["CLAUDE_SKILL_DIR"]; ok {
		t.Error("CLAUDE_SKILL_DIR kept")
	}
	for _, kv := range env {
		if strings.Contains(kv, "/Users/you") {
			t.Errorf("parent location survived: %s", kv)
		}
	}
	p := paths.Resolve(m["HOME"], m)
	for name, v := range map[string]string{"home": p.Home, "config": p.ConfigDir, "cache": p.CacheBase, "state": p.StateDir,
		"activity": p.Activity, "claude": p.ClaudeDir, "overrides": p.OverridesFile(), "settings": p.ClaudeSettings()} {
		if !strings.HasPrefix(v, e.Base+"/") {
			t.Errorf("%s = %s, not under %s", name, v, e.Base)
		}
	}
	if p.Activity != e.Activity || p.ConfigDir != e.Cfg {
		t.Errorf("runner and resolver disagree: activity %s vs %s, config %s vs %s", p.Activity, e.Activity, p.ConfigDir, e.Cfg)
	}
}

func keys(m map[string][]byte) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
