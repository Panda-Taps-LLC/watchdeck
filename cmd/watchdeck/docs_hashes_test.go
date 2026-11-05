package main

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestNoArchivedHashesInDocs keeps commit hashes out of the docs. Revisions
// are named by milestone ("the Plan 05 close"), never by SHA, and a CI run id
// is written only after the word "run". The pattern covers the spellings the
// docs used before: BEFORE=/AFTER= assignments, "at", "against", "commit" or
// "probed" followed by a short hash, and a seven-character table cell. The
// test deliberately names no hash.
func TestNoArchivedHashesInDocs(t *testing.T) {
	re := regexp.MustCompile(`\b(BEFORE|AFTER)=[0-9a-f]{7,}\b|\b(at|against|commit|probed) [0-9a-f]{7,}\b|\| [0-9a-f]{7} \|`)
	files := []string{
		filepath.Join("docs", "DESIGN.md"),
		filepath.Join("docs", "images", "README.md"),
		"README.md",
		filepath.Join("docs", "GUIDE.md"),
		"CHANGELOG.md",
		"CONTRIBUTING.md",
	}
	for _, f := range files {
		for i, line := range strings.Split(repoFile(t, f), "\n") {
			if m := re.FindString(line); m != "" {
				t.Errorf("%s:%d: a commit hash in the docs (%q); name the revision by milestone instead", f, i+1, m)
			}
		}
	}
}
