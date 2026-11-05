package scan

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestRequiredLiterals(t *testing.T) {
	cases := map[string][]string{
		`^\s*(import|from)\s+(requests|httpx)\b`: {"import", "from"},
		`\bfetch\(`:                              {"fetch("},
		`subprocess\.|os\.system\(`:              {"subprocess.", "os.system("},
		`(?i)do not tell`:                        nil,
		`[a-z]+`:                                 nil,
		`\bcurl\b|\bwget\b`:                      {"curl", "wget"},
		`x?y?`:                                   nil,
	}
	for expr, want := range cases {
		got := requiredLiterals(expr)
		if len(got) != len(want) {
			t.Errorf("%q: got %q, want %q", expr, got, want)
			continue
		}
		for i := range want {
			if string(got[i]) != want[i] {
				t.Errorf("%q: got %q, want %q", expr, got, want)
			}
		}
	}
}

// TestPrefilterSoundness brute-forces the invariant "regex matches the line
// ⇒ the literal filter accepts the line" over every line of every fixture
// under testdata and of the pattern tests themselves (their positive samples
// are string literals on their own lines). Any violation is a scanner bypass.
func TestPrefilterSoundness(t *testing.T) {
	var corpus [][]byte
	add := func(p string) {
		b, err := os.ReadFile(p)
		if err != nil {
			return
		}
		corpus = append(corpus, bytes.Split(b, []byte("\n"))...)
	}
	filepath.WalkDir("testdata", func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			add(p)
		}
		return nil
	})
	add("patterns_test.go")
	add("scan_test.go")
	if len(corpus) < 100 {
		t.Fatalf("corpus too small: %d lines", len(corpus))
	}
	filtered := 0
	for _, r := range allRules() {
		if r.lits != nil {
			filtered++
		}
		for _, line := range corpus {
			if r.re.Match(line) && r.lits != nil && !anyContains(line, r.lits) {
				t.Errorf("rule %s: pre-filter %q rejects a matching line %q", r.name, r.lits, line)
			}
		}
	}
	t.Logf("%d of %d rules have a literal pre-filter; corpus %d lines", filtered, len(allRules()), len(corpus))
}
