package claudesettings

import (
	"path/filepath"
	"runtime"
	"testing"
)

func TestLocatePerOS(t *testing.T) {
	p := tempPaths(t)
	root := filepath.Join(p.Home, "proj")
	cases := []struct {
		goos    string
		managed string
	}{
		{"darwin", "/Library/Application Support/ClaudeCode"},
		{"linux", "/etc/claude-code"},
		{"plan9", ""},
	}
	for _, c := range cases {
		t.Run(c.goos, func(t *testing.T) {
			if got := managedDir(c.goos); got != c.managed {
				t.Fatalf("managedDir(%s) = %q, want %q", c.goos, got, c.managed)
			}
			// Point the managed dir at an empty temp dir so the test never
			// depends on what this machine has under /Library or /etc.
			base := ""
			if c.managed != "" {
				base = t.TempDir()
			}
			locs := locate(base, p, root)
			var want []Location
			if base != "" {
				want = append(want, Location{Scope: ScopeManaged, Path: filepath.Join(base, "managed-settings.json"), ReadOnly: true})
			}
			want = append(want,
				Location{Scope: ScopeUser, Path: filepath.Join(p.ClaudeDir, "settings.json")},
				Location{Scope: ScopeProject, Path: filepath.Join(root, ".claude", "settings.json")},
				Location{Scope: ScopeLocal, Path: filepath.Join(root, ".claude", "settings.local.json")},
			)
			if len(locs) != len(want) {
				t.Fatalf("locate = %+v, want %+v", locs, want)
			}
			for i := range want {
				if locs[i] != want[i] {
					t.Fatalf("locate[%d] = %+v, want %+v", i, locs[i], want[i])
				}
			}
		})
	}

	// The exported Locate uses this OS's managed dir first (when it has one)
	// and the user file next; the count is not asserted, since a real drop-in
	// directory on this machine would change it.
	locs := Locate(p, root)
	if md := managedDir(runtime.GOOS); md != "" {
		if locs[0].Path != filepath.Join(md, "managed-settings.json") || !locs[0].ReadOnly || locs[0].Scope != ScopeManaged {
			t.Fatalf("Locate[0] = %+v", locs[0])
		}
	}
	if n := len(locs); locs[n-3].Scope != ScopeUser || locs[n-1].Scope != ScopeLocal {
		t.Fatalf("Locate tail = %+v", locs)
	}

	// No project root: user only (plus managed).
	locs = locate("", p, "")
	if len(locs) != 1 || locs[0].Scope != ScopeUser {
		t.Fatalf("no root: %+v", locs)
	}
}

// TestLocateManagedDropIns: the base file first, then managed-settings.d
// *.json in name order; hidden files, other extensions and directories skipped.
func TestLocateManagedDropIns(t *testing.T) {
	p := tempPaths(t)
	base := t.TempDir()
	d := filepath.Join(base, "managed-settings.d")
	for _, n := range []string{"20-b.json", "10-a.json", ".hidden.json", "notes.txt"} {
		writeFile(t, filepath.Join(d, n), "{}")
	}
	writeFile(t, filepath.Join(d, "30-dir.json", "x"), "")
	locs := locate(base, p, "")
	want := []string{
		filepath.Join(base, "managed-settings.json"),
		filepath.Join(d, "10-a.json"),
		filepath.Join(d, "20-b.json"),
		filepath.Join(p.ClaudeDir, "settings.json"),
	}
	if len(locs) != len(want) {
		t.Fatalf("locate = %+v", locs)
	}
	for i, w := range want {
		if locs[i].Path != w {
			t.Fatalf("locate[%d] = %s, want %s", i, locs[i].Path, w)
		}
		if (i < 3) != locs[i].ReadOnly {
			t.Fatalf("locate[%d] ReadOnly = %v", i, locs[i].ReadOnly)
		}
	}
}
