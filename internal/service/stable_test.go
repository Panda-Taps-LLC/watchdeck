package service

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStableBinaryHomebrew(t *testing.T) {
	prefix, _ := filepath.EvalSymlinks(t.TempDir())
	cellar := filepath.Join(prefix, "Cellar", "watchdeck", "0.2.0", "bin")
	os.MkdirAll(cellar, 0o755)
	bin := filepath.Join(cellar, "watchdeck")
	os.WriteFile(bin, []byte("x"), 0o755)
	if got := StableBinary(bin); got != bin {
		t.Fatalf("no opt link: %s", got)
	}
	opt := filepath.Join(prefix, "opt", "watchdeck")
	os.MkdirAll(filepath.Dir(opt), 0o755)
	if err := os.Symlink(filepath.Join(prefix, "Cellar", "watchdeck", "0.2.0"), opt); err != nil {
		t.Fatal(err)
	}
	if got := StableBinary(bin); got != filepath.Join(opt, "bin", "watchdeck") {
		t.Fatalf("StableBinary = %s", got)
	}
	if got := StableBinary("/usr/local/bin/watchdeck"); got != "/usr/local/bin/watchdeck" {
		t.Fatalf("non-Cellar path changed: %s", got)
	}
}
