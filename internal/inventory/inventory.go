// Package inventory lists the script files inside a skill directory and
// computes the vercel-labs/skills folder hash.
//
// Script detection is by file name first and content second: a known script
// extension decides immediately, data and credential-looking names are never
// opened, and only the remaining files are sniffed for a `#!` first line or an
// executable bit.
//
// Hash follows the computeSkillFolderHash scheme from vercel-labs/skills
// (src/local-lock.ts): walk the directory skipping `.git` and `node_modules`,
// take every regular file, sort relative paths, and feed one SHA-256 with
// `relpath` then `content` per file. Their sort is JavaScript localeCompare
// (ICU, case-insensitive at primary strength); ours is byte order. The two
// agree only on trees whose paths are all lowercase ASCII without competing
// punctuation, so a canonical skill (`SKILL.md` + `scripts/`) does not match
// the vercel lock hash. See hash_test.go for the recorded divergence.
package inventory

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
)

// Script is one script file inside a skill directory.
type Script struct {
	Rel    string `json:"rel"`    // slash-separated path relative to the skill root
	Lang   string `json:"lang"`   // py, sh, js, ts, rb, pl, php, go, rs, swift, applescript, other
	InGlob bool   `json:"inGlob"` // matches one of the script globs
}

// DefaultGlobs is used when Scripts receives nil globs.
var DefaultGlobs = []string{"scripts/**"}

// langForExt maps a lowercase extension (without dot) to a Lang value.
//
// The lookups below are switches, not package-level maps: a map literal is
// built at init, and this package is linked into the hook binary.
func langForExt(ext string) (string, bool) {
	switch ext {
	case "py":
		return "py", true
	case "sh", "bash", "zsh":
		return "sh", true
	case "js", "mjs", "cjs":
		return "js", true
	case "ts":
		return "ts", true
	case "rb", "pl", "php", "go", "rs", "swift", "applescript":
		return ext, true
	case "scpt":
		return "applescript", true
	}
	return "", false
}

// isDataExt reports documentation and data extensions that are never
// scripts, whatever their mode bits say. They are not opened.
func isDataExt(ext string) bool {
	switch ext {
	case "md", "txt", "json", "yaml", "yml", "toml",
		"lock", "csv", "tsv", "xml", "xsd", "html",
		"css", "svg", "png", "jpg", "jpeg", "gif",
		"webp", "ico", "pdf", "ttf", "otf", "woff",
		"woff2", "zip", "gz", "tar", "example", "sample",
		"cff", "rst", "ini", "cfg", "log":
		return true
	}
	return false
}

// skipDir reports directory names never descended into by Scripts.
func skipDir(name string) bool {
	switch name {
	case ".git", "node_modules", ".venv", "__pycache__":
		return true
	}
	return false
}

// Scripts walks root and returns its script files sorted by Rel.
//
// A file is a script if its extension is a known script extension, or its
// first line starts with `#!`, or it has an executable bit and is not a
// documentation/data file. Files named like credentials (`.env*`, `*.pem`,
// `*.key`, ...) are never opened and never scripts. `.git`, `node_modules`,
// `.venv`, `__pycache__` and `*.lock` are skipped.
//
// globs are doublestar patterns relative to root; nil means DefaultGlobs. A
// glob without meta characters is also accepted as a directory prefix, so
// `scripts` and `scripts/` behave like `scripts/**`. root may be a symlink.
// Unreadable subdirectories are skipped; only a bad root or a bad glob is an
// error.
func Scripts(root string, globs []string) ([]Script, error) {
	if globs == nil {
		globs = DefaultGlobs
	}
	for _, g := range globs {
		if !doublestar.ValidatePattern(g) {
			return nil, fmt.Errorf("inventory: bad script glob %q", g)
		}
	}
	real, err := realDir(root)
	if err != nil {
		return nil, err
	}
	var out []Script
	err = filepath.WalkDir(real, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if p == real {
				return walkErr
			}
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if p != real && skipDir(d.Name()) {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil // symlinks, sockets, devices
		}
		lang, ok := classify(p, d)
		if !ok {
			return nil
		}
		rel, err := filepath.Rel(real, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		out = append(out, Script{Rel: rel, Lang: lang, InGlob: inGlob(rel, globs)})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("inventory: %w", err)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Rel < out[j].Rel })
	return out, nil
}

// classify decides whether the regular file at p is a script and its Lang.
func classify(p string, d fs.DirEntry) (lang string, ok bool) {
	name := d.Name()
	ext := strings.ToLower(strings.TrimPrefix(path.Ext(name), "."))
	if ext == "lock" {
		return "", false
	}
	if l, known := langForExt(ext); known {
		return l, true
	}
	if sensitiveName(name) || isDataExt(ext) {
		return "", false
	}
	if l, has := shebangLang(p); has {
		return l, true
	}
	info, err := d.Info()
	if err != nil {
		return "", false
	}
	if info.Mode()&0o111 != 0 {
		return "other", true
	}
	return "", false
}

// sensitiveName reports files that look like credentials or key material.
// They are classified by name only and never opened.
func sensitiveName(name string) bool {
	lower := strings.ToLower(name)
	if strings.HasPrefix(lower, ".env") || lower == ".netrc" || lower == ".npmrc" || lower == ".pypirc" {
		return true
	}
	switch strings.TrimPrefix(path.Ext(lower), ".") {
	case "pem", "key", "p12", "pfx", "crt", "cer", "der", "jks", "keystore", "gpg", "asc":
		return true
	}
	return false
}

// shebangLang reads only the first line of p and maps a `#!` interpreter to a
// Lang. Unknown interpreters are "other".
func shebangLang(p string) (string, bool) {
	f, err := os.Open(p)
	if err != nil {
		return "", false
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 256)
	var prefix [2]byte
	if _, err := r.Read(prefix[:]); err != nil || prefix != [2]byte{'#', '!'} {
		return "", false
	}
	line, _ := r.ReadString('\n') // a line longer than the buffer is simply cut
	fields := strings.Fields(line)
	interp := ""
	if len(fields) > 0 {
		base := path.Base(fields[0])
		if base == "env" {
			// `#!/usr/bin/env -S python3 -u` or `#!/usr/bin/env python3`
			for _, next := range fields[1:] {
				if !strings.HasPrefix(next, "-") {
					interp = path.Base(next)
					break
				}
			}
		} else {
			interp = base
		}
	}
	return interpLang(interp), true
}

func interpLang(interp string) string {
	switch {
	case strings.HasPrefix(interp, "python"):
		return "py"
	case interp == "sh", interp == "bash", interp == "zsh", interp == "dash", interp == "ksh":
		return "sh"
	case interp == "node", interp == "nodejs", interp == "bun":
		return "js"
	case interp == "ts-node", interp == "tsx", interp == "deno":
		return "ts"
	case strings.HasPrefix(interp, "ruby"):
		return "rb"
	case strings.HasPrefix(interp, "perl"):
		return "pl"
	case strings.HasPrefix(interp, "php"):
		return "php"
	case interp == "osascript":
		return "applescript"
	}
	return "other"
}

// inGlob reports whether rel matches any glob, treating a meta-free glob as a
// directory prefix too.
func inGlob(rel string, globs []string) bool {
	for _, g := range globs {
		if ok, _ := doublestar.Match(g, rel); ok {
			return true
		}
		if !strings.ContainsAny(g, "*?[{\\") {
			dir := strings.TrimSuffix(g, "/")
			if dir != "" && strings.HasPrefix(rel, dir+"/") {
				return true
			}
		}
	}
	return false
}

// Summary renders counts per language for in-glob scripts, sorted by count
// descending then language, followed by the number of scripts outside the
// globs: "py(3) sh(2) +1 outside". It returns "-" when there are no scripts.
func Summary(s []Script) string {
	if len(s) == 0 {
		return "-"
	}
	counts := map[string]int{}
	outside := 0
	for _, sc := range s {
		if sc.InGlob {
			counts[sc.Lang]++
		} else {
			outside++
		}
	}
	langs := make([]string, 0, len(counts))
	for l := range counts {
		langs = append(langs, l)
	}
	sort.Slice(langs, func(i, j int) bool {
		if counts[langs[i]] != counts[langs[j]] {
			return counts[langs[i]] > counts[langs[j]]
		}
		return langs[i] < langs[j]
	})
	parts := make([]string, 0, len(langs)+1)
	for _, l := range langs {
		parts = append(parts, fmt.Sprintf("%s(%d)", l, counts[l]))
	}
	if outside > 0 {
		parts = append(parts, fmt.Sprintf("+%d outside", outside))
	}
	return strings.Join(parts, " ")
}

// realDir resolves symlinks in root and checks that it is a directory.
func realDir(root string) (string, error) {
	real, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", fmt.Errorf("inventory: %w", err)
	}
	info, err := os.Stat(real)
	if err != nil {
		return "", fmt.Errorf("inventory: %w", err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("inventory: %s: %w", root, errNotDir)
	}
	return real, nil
}

var errNotDir = errors.New("not a directory")
