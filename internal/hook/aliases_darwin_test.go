//go:build darwin

package hook

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/Panda-Taps-LLC/watchdeck/internal/policy"
)

// TestDarwinPathAliases (verifier finding): the same file named through a
// macOS alias root never gets past a path gate or a pack. The data volume
// spelling is mapped back and gated; /.vol, /.resolve and /.nofollow are
// not resolved and ask; a case-changed spelling is still caught.
func TestDarwinPathAliases(t *testing.T) {
	f := newFx(t)
	f.writeUser(t, "version: 2\nsubjects:\n  - {kind: tool, name: files, match: {tools: [Write, Edit, Read]}, paths: {deny: ['~/.zshrc']}}\n")
	home := policy.CanonicalPath(f.home) // /private/var/folders/… for a temp home
	rc := filepath.Join(home, ".zshrc")
	os.WriteFile(rc, []byte("# fake\n"), 0o600)
	os.MkdirAll(filepath.Join(home, ".ssh"), 0o700)
	key := filepath.Join(home, ".ssh", "id_ed25519")
	os.WriteFile(key, []byte("not a key\n"), 0o600)
	var st syscall.Stat_t
	if err := syscall.Stat(rc, &st); err != nil {
		t.Fatal(err)
	}
	vol := fmt.Sprintf("/.vol/%d/%d", st.Dev, st.Ino)
	cases := []struct {
		tool, path, want, reason string
	}{
		{"Write", "/System/Volumes/Data" + rc, Deny, "tool gate files"},
		{"Write", "/System/Volumes/Data" + strings.ToUpper(rc), Deny, "tool gate files"},
		{"Write", "/.nofollow" + rc, Ask, "could not be normalised"},
		{"Write", "/.resolve/1" + rc, Ask, "could not be normalised"},
		{"Edit", vol, Ask, "could not be normalised"},
		// packs see the same file: the SSH key read asks through the alias too
		{"Read", "/System/Volumes/Data" + key, Ask, "secrets-read/read-ssh-private-key"},
		{"Read", "/.nofollow" + key, Ask, "could not be normalised"},
		{"Read", "/.vol/1/2", Ask, "could not be normalised"},
	}
	for _, c := range cases {
		in := f.tool(c.tool, map[string]any{"file_path": c.path, "content": "x", "old_string": "a", "new_string": "b"})
		out := Decide(in, f.env)
		if decisionOf(out) != c.want || !strings.Contains(out.HookSpecificOutput.PermissionDecisionReason, c.reason) {
			t.Errorf("%s %s: %+v", c.tool, c.path, out)
		}
	}
}
