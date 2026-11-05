package main

import (
	"bytes"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// outsideNames are the substrings no public file of this repository may
// contain, in lower case: products, apps, studies, standards and sources that
// are not this project, GitHub, Sigstore, Homebrew or Claude Code. They are
// stored hex-encoded so that this file does not spell them either; decode
// with fromHex. outsideWords are matched as whole words, the others as plain
// substrings.
var outsideNames = fromHex(
	"6b6172616e62313932",
	"656c69666572726573",
	"63757063616b65",
	"6167656e74732d6f627365727665",
	"6f77617370",
	"6c6974746c6520736e69746368",
	"7461696c7363616c65",
	"67686f73747479",
	"72617963617374",
	"3170617373776f7264",
	"73797374656d2073657474696e6773",
	"7266632d7065726d697373696f6e73",
)

// outsideWords are matched as whole words (no letter or digit on either side).
var outsideWords = fromHex(
	"7265696e73",
)

// fromHex decodes the lists above; a malformed entry is a programming error.
func fromHex(entries ...string) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		b, err := hex.DecodeString(e)
		if err != nil {
			panic("outsidenames: bad hex entry " + e)
		}
		out = append(out, string(b))
	}
	return out
}

// outsideNamesOwnFile is this file, excluded from the scan: it is the only
// tracked file that holds the list (hex-encoded).
const outsideNamesOwnFile = "cmd/watchdeck/outsidenames_test.go"

// TestNoOutsideNamesInTree walks every git-tracked text file of the repository
// and fails, naming file:line, on any outside name. Binary files are skipped
// by a NUL sniff; docs/images and this file are skipped by path. It reads
// nothing outside the repository. The planted subtest is the RED proof: a
// temporary tree with one planted line must be reported.
func TestNoOutsideNamesInTree(t *testing.T) {
	t.Run("planted", func(t *testing.T) {
		dir := t.TempDir()
		for _, c := range []struct{ rel, text string }{
			{"README.md", "clean line\nbuilt on " + outsideNames[6] + "\n"},
			{"docs/a.md", "the word " + strings.ToUpper(outsideWords[0][:1]) + outsideWords[0][1:] + " alone\n"},
			{"docs/b.md", "no hit: " + outsideWords[0] + "tall, oversight\n"},
			{"docs/images/c.md", "skipped: " + outsideNames[8] + "\n"},
			{"bin.dat", "skipped: " + outsideNames[4] + "\x00binary\n"},
			{outsideNamesOwnFile, "skipped: " + outsideNames[2] + "\n"},
		} {
			p := filepath.Join(dir, filepath.FromSlash(c.rel))
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte(c.text), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		files := []string{"README.md", "docs/a.md", "docs/b.md", "docs/images/c.md", "bin.dat", outsideNamesOwnFile}
		want := []string{
			"README.md:2: " + outsideNames[6],
			"docs/a.md:1: " + outsideWords[0],
		}
		got := scanForOutsideNames(t, dir, files)
		if strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Fatalf("planted tree: got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
		}
	})

	root := moduleRoot(t)
	files := trackedFiles(t, root)
	if len(files) < 100 {
		t.Fatalf("git ls-files listed only %d files under %s", len(files), root)
	}
	if hits := scanForOutsideNames(t, root, files); len(hits) > 0 {
		t.Errorf("%d outside names in tracked files (no public file names a product, app, study, standard or source other than this project):\n%s", len(hits), strings.Join(hits, "\n"))
	}
}

// scanForOutsideNames returns "rel:line: name" for every hit over files
// (slash-separated paths relative to root), in file then line order.
func scanForOutsideNames(t *testing.T, root string, files []string) []string {
	t.Helper()
	var hits []string
	for _, rel := range files {
		if rel == outsideNamesOwnFile || strings.HasPrefix(rel, "docs/images/") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatal(err)
		}
		head := b
		if len(head) > 8192 {
			head = head[:8192]
		}
		if bytes.IndexByte(head, 0) >= 0 {
			continue
		}
		for i, line := range strings.Split(strings.ToLower(string(b)), "\n") {
			for _, n := range outsideNames {
				if strings.Contains(line, n) {
					hits = append(hits, rel+":"+strconv.Itoa(i+1)+": "+n)
				}
			}
			for _, w := range outsideWords {
				if containsWord(line, w) {
					hits = append(hits, rel+":"+strconv.Itoa(i+1)+": "+w)
				}
			}
		}
	}
	return hits
}

// containsWord reports whether w occurs in s with no letter or digit on
// either side.
func containsWord(s, w string) bool {
	for off := 0; ; {
		i := strings.Index(s[off:], w)
		if i < 0 {
			return false
		}
		start, end := off+i, off+i+len(w)
		if (start == 0 || !isWordByte(s[start-1])) && (end == len(s) || !isWordByte(s[end])) {
			return true
		}
		off = start + 1
	}
}

func isWordByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_'
}

// moduleRoot walks up from the working directory to the directory holding
// go.mod.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found above the working directory")
		}
		dir = parent
	}
}

// trackedFiles lists the git-tracked regular files under root,
// slash-separated and relative to root; symlinks are not followed.
func trackedFiles(t *testing.T, root string) []string {
	t.Helper()
	cmd := exec.Command("git", "-C", root, "ls-files", "-z")
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git ls-files: %v", err)
	}
	var files []string
	for _, f := range bytes.Split(out, []byte{0}) {
		if len(f) == 0 {
			continue
		}
		fi, err := os.Lstat(filepath.Join(root, filepath.FromSlash(string(f))))
		if err != nil || !fi.Mode().IsRegular() {
			continue // deleted in the working tree, or a symlink
		}
		files = append(files, string(f))
	}
	return files
}
