package settings

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// TestHookShSkipsPlantedBinary: plugin/bin/hook.sh never runs a watchdeck
// found on PATH under the project (cwd) or $TMPDIR, or by a relative PATH
// entry (review 2026-10-14). A sandboxed skill script may write the project,
// and PATH often holds a project dir (.venv/bin, node_modules/.bin), so a
// planted copy would answer every later hook event outside any sandbox.
func TestHookShSkipsPlantedBinary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sh")
	}
	script, err := filepath.Abs(filepath.Join("..", "..", "plugin", "bin", "hook.sh"))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	project := filepath.Join(root, "project")
	tmp := filepath.Join(root, "tmp")
	good := filepath.Join(root, "installed")
	home := filepath.Join(root, "home")
	marker := filepath.Join(root, "ran")
	plant := func(dir, name string) {
		t.Helper()
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		body := "#!/bin/sh\necho " + name + " >> '" + marker + "'\n"
		if err := os.WriteFile(filepath.Join(dir, "watchdeck"), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	plant(filepath.Join(project, ".venv", "bin"), "project")
	plant(filepath.Join(tmp, "bin"), "tmp")
	plant(good, "installed")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	run := func(path string) string {
		t.Helper()
		os.Remove(marker)
		cmd := exec.Command("/bin/sh", script)
		cmd.Dir = project
		cmd.Env = []string{"PATH=" + path, "HOME=" + home, "TMPDIR=" + tmp + "/", "PWD=" + project,
			"WATCHDECK_ACTIVITY=" + filepath.Join(root, "a.jsonl"), "XDG_STATE_HOME=" + filepath.Join(root, "state")}
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("hook.sh with PATH=%s: %v %s", path, err, out)
		}
		b, _ := os.ReadFile(marker)
		return string(b)
	}
	sys := "/usr/bin:/bin"
	for _, c := range []struct{ path, want string }{
		{filepath.Join(project, ".venv", "bin") + ":" + sys, ""},
		{filepath.Join(tmp, "bin") + ":" + sys, ""},
		{".venv/bin:" + sys, ""},
		{filepath.Join(project, ".venv", "bin") + ":" + good + ":" + sys, "installed\n"},
		{good + ":" + sys, "installed\n"},
	} {
		if got := run(c.path); got != c.want {
			t.Errorf("PATH=%s: ran %q, want %q", c.path, got, c.want)
		}
	}
}
