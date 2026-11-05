//go:build unix

package safeio

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestReadRegular(t *testing.T) {
	dir := t.TempDir()
	reg := filepath.Join(dir, "f")
	os.WriteFile(reg, []byte("hello"), 0o600)
	if b, err := ReadRegular(reg, 5, false); err != nil || string(b) != "hello" {
		t.Fatalf("regular = %q %v", b, err)
	}
	if _, err := ReadRegular(reg, 4, false); !errors.Is(err, ErrTooLarge) {
		t.Errorf("over cap = %v", err)
	}
	if _, err := ReadRegular(filepath.Join(dir, "none"), 5, false); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing = %v", err)
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	link := filepath.Join(dir, "link")
	os.Symlink(reg, link)
	for name, c := range map[string]struct {
		path     string
		nofollow bool
	}{
		"fifo": {fifo, false}, "dev-null": {"/dev/null", false}, "dir": {dir, false}, "symlink-nofollow": {link, true},
	} {
		done := make(chan error, 1)
		go func() { _, err := ReadRegular(c.path, 1<<10, c.nofollow); done <- err }()
		select {
		case err := <-done:
			if err == nil {
				t.Errorf("%s: no error", name)
			}
			if strings.Contains(err.Error(), dir) && name != "symlink-nofollow" && name != "dir" {
				// os errors carry the path; ErrNotRegular does not
				t.Errorf("%s: %v", name, err)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("%s: blocked", name)
		}
	}
	if b, err := ReadRegular(link, 5, false); err != nil || string(b) != "hello" {
		t.Errorf("symlink followed = %q %v", b, err)
	}
}

func TestScanYAMLLimits(t *testing.T) {
	nest := func(n int) string { return "x: " + strings.Repeat("[", n) + "a" + strings.Repeat("]", n) + "\n" }
	ok := []string{
		nest(MaxFlowDepth),
		"x: '" + strings.Repeat("[", 500) + "'\n",
		"x: \"" + strings.Repeat("{", 500) + "\"\n",
		"# " + strings.Repeat("[", 500) + "\nx: 1\n",
		"x:\n" + strings.Repeat(" ", MaxIndent) + "y\n",
		strings.Repeat("- ", MaxDashChain) + "x\n",
		"a: &a [x]\n" + strings.Repeat("b: *a\n", MaxAliases),
		"x: " + strings.Repeat("[a], ", 2000) + "\n",
	}
	for i, s := range ok {
		if err := CheckYAML([]byte(s)); err != nil {
			t.Errorf("ok[%d]: %v", i, err)
		}
	}
	bad := []string{
		nest(MaxFlowDepth + 1),
		"x: " + strings.Repeat("{a: ", 100) + "\n",
		"x: '" + strings.Repeat("]", 200) + "'\ny: " + strings.Repeat("[", 100) + "\n", // quoted closers cannot hide openers
		"x:\n" + strings.Repeat(" ", MaxIndent+1) + "y\n",
		strings.Repeat("- ", MaxDashChain+1) + "x\n",
		strings.Repeat("? ", MaxDashChain+1) + "x\n",
		"a: &a [x]\n" + strings.Repeat("b: *a\n", MaxAliases+1),
	}
	for i, s := range bad {
		if err := CheckYAML([]byte(s)); !errors.Is(err, ErrTooDeep) {
			t.Errorf("bad[%d]: %v", i, err)
		}
	}
	if ErrTooDeep.Error() != "malformed YAML (too deeply nested)" {
		t.Error(ErrTooDeep)
	}
}

func TestScanYAMLInfo(t *testing.T) {
	cases := []struct {
		src        string
		docs       int
		version    string
		has, isInt bool
	}{
		{"version: 2\n", 1, "2", true, true},
		{"%YAML 1.2\n---\nversion: 2\n", 1, "2", true, true},
		{"---\nversion: 2\n", 1, "2", true, true},
		{"version: 2\n---\n", 1, "2", true, true},
		{"version: 2\n...\n", 1, "2", true, true},
		{"version: 2\n---\nversion: 1\n", 2, "2", true, true},
		{"a: 1\n---\nb: 2\n", 2, "", false, false},
		{"version: 2.0\n", 1, "2.0", true, false},
		{"version: \"2\"\n", 1, "2", true, false},
		{"x:\n  version: 2\n", 1, "", false, false},
		{"{version: 2}\n", 1, "", false, false},
		{"# only a comment\n", 0, "", false, false},
	}
	for _, c := range cases {
		info, err := ScanYAML([]byte(c.src))
		if err != nil {
			t.Fatalf("%q: %v", c.src, err)
		}
		if info.Docs != c.docs || info.Version != c.version || info.HasVersion != c.has || info.VersionInt != c.isInt {
			t.Errorf("%q: %+v", c.src, info)
		}
	}
}

// TestScanYAMLLinear: the scan of a worst-case 1 MiB input stays fast.
func TestScanYAMLLinear(t *testing.T) {
	for _, s := range []string{
		strings.Repeat("[", 1<<20),
		strings.Repeat("k: v\n", (1<<20)/5),
		"x: '" + strings.Repeat("[", 1<<20) + "'\n",
	} {
		start := time.Now()
		CheckYAML([]byte(s))
		if el := time.Since(start); el > 2*time.Second {
			t.Errorf("scan took %v", el)
		}
	}
}
