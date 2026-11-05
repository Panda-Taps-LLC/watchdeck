// Package scan is a precision-first static scanner for skill directories. It
// runs per-language regex tables over script files (Python, JavaScript /
// TypeScript, shell) and instruction-level patterns over SKILL.md prose, and
// reports which capability categories a skill appears to use.
//
// It is a helper for authors and auditors, not the trust anchor: the sandbox
// enforces, the scan only informs. Comments are stripped cheaply (whole-line
// `#` or `//` only). Each file is read up to 1 MiB; longer files are scanned
// on their first MiB only.
package scan

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/Panda-Taps-LLC/watchdeck/internal/inventory"
	"github.com/Panda-Taps-LLC/watchdeck/internal/safeio"
)

// Category is a capability class a hit belongs to.
type Category string

const (
	Network     Category = "net"
	Credential  Category = "cred"
	Exec        Category = "exec"
	Environment Category = "env"
	Encoding    Category = "enc"
	Filesystem  Category = "fs"
	Instruction Category = "instr"
)

// order is the canonical category order used by Flags and Summary.
var order = []Category{Network, Credential, Exec, Environment, Encoding, Filesystem, Instruction}

func rank(c Category) int {
	for i, o := range order {
		if o == c {
			return i
		}
	}
	return len(order)
}

// Hit is one matched line.
type Hit struct {
	Category Category `json:"category"`
	File     string   `json:"file"`    // slash-separated path relative to the skill root
	Line     int      `json:"line"`    // 1-based
	Pattern  string   `json:"pattern"` // stable rule name, e.g. "py-net-import"
	Snippet  string   `json:"snippet"` // trimmed line, truncated
}

// MaxFileBytes caps how much of each file is scanned.
const MaxFileBytes = 1 << 20

// maxSnippet caps Snippet length in bytes (cut on a rune boundary).
const maxSnippet = 120

// Dir scans the script files of root (as found by inventory.Scripts with the
// default globs, in or out of glob) for Python, JS/TS and shell, plus
// SKILL.md for instruction-level patterns. Hits are sorted by File, Line and
// category order; one hit per (file, line, category). root may be a symlink.
func Dir(root string) ([]Hit, error) {
	real, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, fmt.Errorf("scan: %w", err)
	}
	scripts, err := inventory.Scripts(real, nil)
	if err != nil {
		return nil, fmt.Errorf("scan: %w", err)
	}
	var hits []Hit
	for _, s := range scripts {
		if rulesFor(s.Lang) == nil {
			continue
		}
		content, err := readCapped(filepath.Join(real, filepath.FromSlash(s.Rel)))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) {
				continue
			}
			return nil, fmt.Errorf("scan: %s: %w", s.Rel, err)
		}
		hits = append(hits, scanContent(s.Lang, s.Rel, content)...)
	}
	if content, err := readCapped(filepath.Join(real, "SKILL.md")); err == nil {
		hits = append(hits, scanContent("skillmd", "SKILL.md", content)...)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("scan: SKILL.md: %w", err)
	}
	sortHits(hits)
	return hits, nil
}

// Flags returns the distinct categories present, in canonical order.
func Flags(hits []Hit) []Category {
	seen := map[Category]bool{}
	for _, h := range hits {
		seen[h.Category] = true
	}
	var out []Category
	for _, c := range order {
		if seen[c] {
			out = append(out, c)
		}
	}
	return out
}

// Summary joins Flags with spaces, or "-" when there are none.
func Summary(hits []Hit) string {
	flags := Flags(hits)
	if len(flags) == 0 {
		return "-"
	}
	parts := make([]string, len(flags))
	for i, f := range flags {
		parts[i] = string(f)
	}
	return strings.Join(parts, " ")
}

// scanContent runs the rule table for lang over content line by line.
// lang is an inventory language ("py", "js", "ts", "sh") or "skillmd".
func scanContent(lang, file string, content []byte) []Hit {
	rules := rulesFor(lang)
	if rules == nil {
		return nil
	}
	var hits []Hit
	lineNo := 0
	for len(content) > 0 {
		lineNo++
		var line []byte
		if i := bytes.IndexByte(content, '\n'); i >= 0 {
			line, content = content[:i], content[i+1:]
		} else {
			line, content = content, nil
		}
		line = bytes.TrimRight(line, "\r")
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) == 0 || isComment(lang, trimmed) {
			continue
		}
		var seen [8]bool
		for _, r := range rules {
			if seen[rank(r.cat)] || (r.lits != nil && !anyContains(line, r.lits)) || !r.match(line) {
				continue
			}
			seen[rank(r.cat)] = true
			hits = append(hits, Hit{
				Category: r.cat,
				File:     file,
				Line:     lineNo,
				Pattern:  r.name,
				Snippet:  snippet(trimmed),
			})
		}
	}
	return hits
}

// isComment reports whole-line comments for script languages. SKILL.md lines
// starting with `#` are headings and are kept.
func isComment(lang string, trimmed []byte) bool {
	switch lang {
	case "py", "sh":
		return trimmed[0] == '#'
	case "js", "ts":
		return bytes.HasPrefix(trimmed, []byte("//"))
	}
	return false
}

func snippet(b []byte) string {
	if len(b) <= maxSnippet {
		return string(b)
	}
	cut := maxSnippet
	for cut > 0 && !utf8.RuneStart(b[cut]) {
		cut--
	}
	return string(b[:cut]) + "..."
}

func readCapped(p string) ([]byte, error) {
	f, err := safeio.OpenRegular(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, MaxFileBytes))
}

func sortHits(hits []Hit) {
	sort.SliceStable(hits, func(i, j int) bool {
		a, b := hits[i], hits[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return rank(a.Category) < rank(b.Category)
	})
}
