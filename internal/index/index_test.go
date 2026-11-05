package index

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/skills"
)

func fakeHome(t *testing.T) (home string) {
	t.Helper()
	home = t.TempDir()
	write := func(rel, content string) {
		p := filepath.Join(home, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(".claude/skills/alpha/SKILL.md", "---\nname: alpha\ndescription: a\n---\n")
	write(".claude/skills/alpha/scripts/x.py", "print(1)\n")
	write(".claude/skills/beta/SKILL.md", "---\nname: beta\ndescription: b\n---\n")
	write(".claude/skills/beta/PERMISSIONS.yaml", "version: 1\nscripts: [\"bin/**\"]\nnetwork: none\n")
	write(".claude/skills/gamma/SKILL.md", "---\nname: gamma\ndescription: g\n---\n")
	write(".claude/skills/gamma/PERMISSIONS.yaml", "version: 1\nbogus: 1\n")
	return home
}

func TestBuildLoadFresh(t *testing.T) {
	home := fakeHome(t)
	cfg := filepath.Join(t.TempDir(), "cfg")
	roots := skills.Roots{Home: home, Cwd: home}
	ix, err := Build(roots, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(ix.Entries) != 3 {
		t.Fatalf("entries = %d", len(ix.Entries))
	}
	beta, ok := ix.Lookup("beta")
	if !ok || beta.Manifest == "" || len(beta.Scripts) != 1 || beta.Scripts[0] != "bin/**" {
		t.Fatalf("beta = %+v", beta)
	}
	gamma, _ := ix.Lookup("gamma")
	if gamma.ManifestError == "" {
		t.Fatal("invalid manifest not recorded")
	}
	alpha, _ := ix.Lookup("alpha")
	if alpha.Manifest != "" || alpha.Scripts[0] != "scripts/**" {
		t.Fatalf("alpha = %+v", alpha)
	}
	// needles include every root and the generic markers
	needles := map[string]bool{}
	for _, n := range ix.Needles() {
		needles[n] = true
	}
	if !needles[alpha.Dir] || !needles[".claude/skills"] || !needles["scripts/"] || !needles["~/.claude/skills/alpha"] {
		t.Fatalf("needles = %v", ix.Needles())
	}
	if len(ix.Skills()) != 3 {
		t.Fatalf("Skills() = %d", len(ix.Skills()))
	}

	path := Path(filepath.Join(t.TempDir(), "cache"))
	if err := ix.Save(path); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.Fresh("") {
		t.Fatal("freshly saved index reported stale")
	}
	if loaded.Fresh("/some/project") {
		t.Fatal("index for a different project root reported fresh")
	}

	// touching the skills dir (adding a skill) makes it stale
	time.Sleep(10 * time.Millisecond)
	os.MkdirAll(filepath.Join(home, ".claude", "skills", "delta"), 0o755)
	os.WriteFile(filepath.Join(home, ".claude", "skills", "delta", "SKILL.md"), []byte("---\nname: delta\ndescription: d\n---\n"), 0o644)
	if loaded.Fresh("") {
		t.Fatal("index not stale after a new skill dir was added")
	}
	ix2, rebuilt, err := LoadOrBuild(path, roots, cfg)
	if err != nil || !rebuilt || len(ix2.Entries) != 4 {
		t.Fatalf("LoadOrBuild: rebuilt=%v n=%d err=%v", rebuilt, len(ix2.Entries), err)
	}
	ix3, rebuilt, err := LoadOrBuild(path, roots, cfg)
	if err != nil || rebuilt || len(ix3.Entries) != 4 {
		t.Fatalf("second LoadOrBuild: rebuilt=%v n=%d err=%v", rebuilt, len(ix3.Entries), err)
	}

	// editing a manifest is detected lazily per entry
	time.Sleep(10 * time.Millisecond)
	os.WriteFile(filepath.Join(home, ".claude", "skills", "beta", "PERMISSIONS.yaml"), []byte("version: 1\nnetwork: localhost\n"), 0o644)
	b, _ := ix3.Lookup("beta")
	if !ix3.ManifestStale(b) {
		t.Fatal("manifest edit not detected")
	}
	a, _ := ix3.Lookup("alpha")
	if ix3.ManifestStale(a) {
		t.Fatal("alpha (no manifest) reported stale")
	}
}

func TestProjectRoot(t *testing.T) {
	home := t.TempDir()
	proj := filepath.Join(home, "p")
	os.MkdirAll(filepath.Join(proj, ".git"), 0o755)
	os.MkdirAll(filepath.Join(proj, "a", "b"), 0o755)
	if got := ProjectRoot(filepath.Join(proj, "a", "b"), home); got != proj {
		t.Fatalf("ProjectRoot = %q", got)
	}
	if got := ProjectRoot(home, home); got != "" {
		t.Fatalf("home should not be a project: %q", got)
	}
}
