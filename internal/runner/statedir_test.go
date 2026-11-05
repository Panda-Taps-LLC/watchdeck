package runner

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/Panda-Taps-LLC/watchdeck/internal/manifest"
)

// TestStateDenyFollowsXDG: the state dir denied to scripts is the one
// paths.Resolve gives, default or XDG_STATE_HOME, and it is created 0700 so
// that bwrap (which hides only existing paths) always applies the deny.
func TestStateDenyFollowsXDG(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "h")
	got, err := stateDeny(Env{Home: home})
	if err != nil || len(got) != 1 || got[0] != filepath.Join(home, ".local", "state", "watchdeck") {
		t.Errorf("default: %q %v", got, err)
	}
	if st, err := os.Stat(got[0]); err != nil || !st.IsDir() || st.Mode().Perm()&0o077 != 0 {
		t.Errorf("state dir not created private: %v", err)
	}
	xdg := filepath.Join(root, "s")
	if got, err := stateDeny(Env{Home: home, Environ: map[string]string{"XDG_STATE_HOME": xdg}}); err != nil || len(got) != 1 || got[0] != filepath.Join(xdg, "watchdeck") {
		t.Errorf("XDG: %q %v", got, err)
	}
	// a relative XDG_STATE_HOME is ignored (paths.Resolve), not used
	if got, err := stateDeny(Env{Home: home, Environ: map[string]string{"XDG_STATE_HOME": "rel"}}); err != nil || got[0] != filepath.Join(home, ".local", "state", "watchdeck") {
		t.Errorf("relative XDG: %q %v", got, err)
	}
}

// TestStateDenyFailsClosed: no home means a relative state dir, which is a
// policy error, never a run without the deny.
func TestStateDenyFailsClosed(t *testing.T) {
	if got, err := stateDeny(Env{}); err == nil {
		t.Errorf("no home accepted: %q", got)
	}
	if _, _, _, err := toResolved(manifest.Default(), nil, "/h", "/p", "/t", []string{"rel/state"}); err == nil {
		t.Error("relative extra deny accepted")
	}
}

// TestToResolvedDeniesStateDir: the state dir becomes a deny path (read and
// write), and a write entry under it is dropped like one under ~/.ssh.
func TestToResolvedDeniesStateDir(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, "home")
	state := filepath.Join(root, "state", "watchdeck")
	eff := manifest.Default()
	eff.Write = append(eff.Write, state+"/index", "${CWD}/out")
	res, dropped, droppedWrites, err := toResolved(eff, nil, home, filepath.Join(root, "proj"), filepath.Join(root, "tmp"), []string{state})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(res.DenyPaths, state) {
		t.Errorf("DenyPaths lacks the state dir: %q", res.DenyPaths)
	}
	if len(droppedWrites) != 1 || droppedWrites[0] != state+"/index" || len(dropped) != 1 {
		t.Errorf("dropped %q %q", droppedWrites, dropped)
	}
	for _, w := range res.Write {
		if w == state+"/index" {
			t.Errorf("write under the state dir kept: %q", res.Write)
		}
	}
}
