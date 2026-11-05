package paths

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoStrayNameLiterals fails on any runtime literal of the project file
// name, the binary name used as a command or as a whole string (a bare
// "watchdeck" or "/watchdeck", as in a == or HasSuffix test), or the trailer
// prefix outside the packages that define them. Comment lines are ignored.
func TestNoStrayNameLiterals(t *testing.T) {
	needles := []string{`".watchdeck.yaml"`, `"watchdeck run`, `"[watchdeck]`, `"watchdeck"`, `"/watchdeck"`}
	root := filepath.Join("..", "..")
	var hits []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		if d.IsDir() {
			switch {
			case d.Name() == "testdata", d.Name() == ".git", d.Name() == ".claude", d.Name() == "node_modules":
				return filepath.SkipDir
			case rel == filepath.Join("internal", "paths"), rel == filepath.Join("internal", "manifest"):
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for i, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "//") {
				continue
			}
			for _, n := range needles {
				if strings.Contains(line, n) {
					hits = append(hits, rel+":"+itoa(i+1)+": "+strings.TrimSpace(line))
					break
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) > 0 {
		t.Errorf("%d stray name literals (use paths.BinaryName, paths.Trailer, manifest.ProjectOverridesFile):\n%s", len(hits), strings.Join(hits, "\n"))
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	for ; n > 0; n /= 10 {
		s = string(rune('0'+n%10)) + s
	}
	return s
}
