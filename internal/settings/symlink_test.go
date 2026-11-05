package settings

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestInstallKeepsSymlinkedSettings: a settings.json linked into a dotfiles
// repo stays a link; the real file gets the change and the backup sits beside
// it, and uninstall edits the same real file.
func TestInstallKeepsSymlinkedSettings(t *testing.T) {
	dir := t.TempDir()
	dots := filepath.Join(dir, "dotfiles")
	if err := os.MkdirAll(dots, 0o755); err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(dots, "settings.json")
	orig := "{\n  \"theme\": \"dark\"\n}\n"
	if err := os.WriteFile(real, []byte(orig), 0o644); err != nil {
		t.Fatal(err)
	}
	claude := filepath.Join(dir, "claude")
	if err := os.MkdirAll(claude, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(claude, "settings.json")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	ch, err := Install(link, testBinary)
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("settings.json is no longer a link: %v %v", fi, err)
	}
	if b, _ := os.ReadFile(real); !strings.Contains(string(b), testBinary) {
		t.Fatalf("the real file did not get the hooks:\n%s", b)
	}
	if realDots, _ := filepath.EvalSymlinks(dots); filepath.Dir(ch.Backup) != realDots { // macOS: /var is /private/var
		t.Fatalf("backup %s not beside the real file", ch.Backup)
	}
	if st, err := Inspect(link); err != nil || !st.Complete {
		t.Fatalf("status through the link = %+v, %v", st, err)
	}
	if _, err := Uninstall(link); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("uninstall replaced the link: %v %v", fi, err)
	}
	if b, _ := os.ReadFile(real); string(b) != orig {
		t.Fatalf("uninstall did not restore the real file:\n%s", b)
	}
}
