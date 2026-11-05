//go:build unix

package mapapi

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/manifest"
	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
)

// TestDeclaredProjectFileReadSafely: the map reads a project's
// .watchdeck.yaml through manifest.LoadProjectOverridesFile, so a symlink
// resolving outside the project and a FIFO are ignored (the grant stays the
// default) and never block; a regular file inside the project applies.
func TestDeclaredProjectFileReadSafely(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	copyTree(t, fromRepo(t, "testdata", "skills", "canary-request"), filepath.Join(home, ".claude", "skills", "canary-request"))
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(filepath.Join(proj, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	a := &api{d: Deps{Paths: paths.Resolve(home, map[string]string{
		"XDG_CONFIG_HOME": filepath.Join(root, "cfg"),
		"XDG_CACHE_HOME":  filepath.Join(root, "cache"),
		"XDG_STATE_HOME":  filepath.Join(root, "state"),
	})}}
	grant := `version: 1
skills:
  canary-request:
    network: localhost
`
	pf := filepath.Join(proj, manifest.ProjectOverridesFile)
	network := func() manifest.Network {
		t.Helper()
		done := make(chan manifest.Network, 1)
		go func() {
			out, _, _ := a.declared([]string{"canary-request"}, proj, proj)
			done <- out["canary-request"].Granted.Network
		}()
		select {
		case n := <-done:
			return n
		case <-time.After(3 * time.Second):
			t.Fatal("declared blocked on the project file")
		}
		return 0
	}

	// Regular file inside the project: applies.
	if err := os.WriteFile(pf, []byte(grant), 0o644); err != nil {
		t.Fatal(err)
	}
	if n := network(); n != manifest.NetLocalhost {
		t.Fatalf("inside file: network = %s", n)
	}

	// Symlink to a file outside the project: ignored.
	outside := filepath.Join(root, "outside.yaml")
	if err := os.WriteFile(outside, []byte(grant), 0o644); err != nil {
		t.Fatal(err)
	}
	os.Remove(pf)
	if err := os.Symlink(outside, pf); err != nil {
		t.Fatal(err)
	}
	if n := network(); n != manifest.NetNone {
		t.Errorf("outside symlink honoured: network = %s", n)
	}

	// FIFO: ignored, promptly.
	os.Remove(pf)
	if err := syscall.Mkfifo(pf, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	if n := network(); n != manifest.NetNone {
		t.Errorf("fifo: network = %s", n)
	}
}
