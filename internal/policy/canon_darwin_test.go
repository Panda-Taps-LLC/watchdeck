//go:build darwin

package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCanonicalPathDarwin: F_GETPATH gives the kernel's spelling (true case,
// /private for /var), the data volume prefix is dropped, and the alias
// roots are refused.
func TestCanonicalPathDarwin(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "Sub"), 0o700)
	want := CanonicalPath(filepath.Join(dir, "Sub"))
	if !strings.HasPrefix(want, "/private/") {
		t.Fatalf("temp dir not under /private: %s", want)
	}
	upper := strings.ToUpper(filepath.Join(dir, "Sub"))
	if got := CanonicalPath(upper); got != want {
		t.Fatalf("case: %s, want %s", got, want)
	}
	if got := CanonicalPath("/System/Volumes/Data" + want + "/new.txt"); got != want+"/new.txt" {
		t.Fatalf("data volume: %s", got)
	}
	for _, p := range []string{"/.vol/1/2", "/.nofollow/Users/x", "/.resolve/1/Users/x"} {
		if NormalizePath(p, "", "/Users/x").OK {
			t.Errorf("%s normalised", p)
		}
	}
}
