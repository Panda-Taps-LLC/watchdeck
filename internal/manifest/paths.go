package manifest

import (
	"fmt"
	"path"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
)

// knownVars are the variables a path may start with. They stay symbolic in
// this package; `run` expands them.
var knownVars = []string{"${SKILL_DIR}", "${CWD}", "${TMP}", "${HOME}"}

// isGlob reports whether p contains glob metacharacters.
func isGlob(p string) bool { return strings.ContainsAny(p, "*?[") }

// normPath canonicalises a symbolic path for comparison: ${HOME} becomes ~,
// trailing slashes and duplicate separators go away. Globs are only trimmed.
// Variables are not expanded. Callers must have rejected ".." segments first
// (validatePath does), otherwise path.Clean could hop over a variable prefix.
func normPath(p string) string {
	p = strings.TrimSpace(p)
	if strings.HasPrefix(p, "${HOME}") {
		p = "~" + strings.TrimPrefix(p, "${HOME}")
	}
	if p == "" {
		return ""
	}
	if isGlob(p) {
		if len(p) > 1 {
			p = strings.TrimRight(p, "/")
		}
		return p
	}
	c := path.Clean(p)
	if c == "." {
		return ""
	}
	return c
}

// normAll returns normPath applied to every element (nil stays nil).
func normAll(ps []string) []string {
	if ps == nil {
		return nil
	}
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, normPath(p))
	}
	return out
}

// within reports whether normalised path p equals base or lies below it.
// "/" contains every path, including symbolic ones such as ~/x or ${CWD}/x.
func within(p, base string) bool {
	if p == "" || base == "" {
		return false
	}
	if base == "/" {
		return true
	}
	return p == base || strings.HasPrefix(p, base+"/")
}

// withinAny reports whether p lies within at least one of bases.
func withinAny(p string, bases []string) bool {
	for _, b := range bases {
		if within(p, normPath(b)) {
			return true
		}
	}
	return false
}

// underDeny reports whether normalised path p is denied by a deny path or a
// deny pattern.
func underDeny(p string, denyPaths, denyPatterns []string) bool {
	if withinAny(p, denyPaths) {
		return true
	}
	for _, pat := range denyPatterns {
		if ok, _ := doublestar.Match(pat, p); ok {
			return true
		}
	}
	return false
}

// splitDeny separates plain deny paths from ** patterns, normalising paths.
func splitDeny(entries []string) (paths, patterns []string) {
	for _, e := range entries {
		if isGlob(e) {
			patterns = appendUnique(patterns, normPath(e))
		} else {
			paths = appendUnique(paths, normPath(e))
		}
	}
	return paths, patterns
}

// validatePath checks one filesystem path entry. field names the YAML key
// for the error message (e.g. "filesystem.write[1]"). Globs are only
// accepted when allowGlob is set (deny lists).
func validatePath(field, p string, allowGlob bool) error {
	if strings.TrimSpace(p) == "" {
		return fmt.Errorf("%s: empty path", field)
	}
	if strings.ContainsAny(p, "\n\r\x00") {
		return fmt.Errorf("%s: control characters are not allowed", field)
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return fmt.Errorf("%s: '..' segments are not allowed", field)
		}
	}
	rest := p
	switch {
	case strings.HasPrefix(p, "${"):
		matched := ""
		for _, v := range knownVars {
			if strings.HasPrefix(p, v) {
				matched = v
				break
			}
		}
		if matched == "" || (len(p) > len(matched) && p[len(matched)] != '/') {
			return fmt.Errorf("%s: unknown variable (allowed: ${SKILL_DIR} ${CWD} ${TMP} ${HOME} ~)", field)
		}
		rest = p[len(matched):]
	case strings.HasPrefix(p, "~"):
		if p != "~" && !strings.HasPrefix(p, "~/") {
			return fmt.Errorf("%s: ~ must be followed by /", field)
		}
		rest = p[1:]
	case strings.HasPrefix(p, "/"):
	case allowGlob && isGlob(p):
		// relative pattern such as **/.env
	default:
		return fmt.Errorf("%s: must be absolute or start with ~ or a variable (${SKILL_DIR} ${CWD} ${TMP} ${HOME})", field)
	}
	if strings.Contains(rest, "$") {
		return fmt.Errorf("%s: variables are only allowed at the start of a path (${SKILL_DIR} ${CWD} ${TMP} ${HOME})", field)
	}
	if isGlob(p) {
		if !allowGlob {
			return fmt.Errorf("%s: globs are not supported here (only filesystem.deny takes patterns)", field)
		}
		if !doublestar.ValidatePattern(p) {
			return fmt.Errorf("%s: invalid glob", field)
		}
	}
	return nil
}

// The deny checks below compare case-insensitively, segment by segment, with
// strings.EqualFold (Unicode simple folding): APFS, the macOS default, is
// case-insensitive, so ~/.SSH, ~/.ſſh (U+017F) and ~/.docKer (Kelvin
// sign) name ~/.ssh and ~/.docker, and .ENV names .env. Refusing such a
// spelling on a case-sensitive filesystem only refuses a path that looks like
// a credential store. Their errors name the field and the rule, never the
// value: a manifest or override file is untrusted, and the error reaches the
// hook's permission reason, run's stderr and the activity records.

// UnderFold reports whether p equals root or lies under it, comparing each
// path segment with strings.EqualFold. "/" contains every path.
func UnderFold(p, root string) bool {
	if p == "" || root == "" {
		return false
	}
	if root == "/" {
		return true
	}
	ps, rs := strings.Split(p, "/"), strings.Split(root, "/")
	if len(ps) < len(rs) {
		return false
	}
	for i, r := range rs {
		if !strings.EqualFold(ps[i], r) {
			return false
		}
	}
	return true
}

// matchesDenyPattern reports whether normalised n matches the built-in deny
// pattern d. A "**/<name>" pattern matches any path whose last element
// equals name under strings.EqualFold; any other pattern falls back to
// doublestar.
func matchesDenyPattern(d, n string) bool {
	if last, ok := strings.CutPrefix(d, "**/"); ok && !isGlob(last) {
		return strings.EqualFold(path.Base(n), last)
	}
	ok, _ := doublestar.Match(d, n)
	return ok
}

// checkBuiltinDeny rejects a read/write entry that is a built-in deny path,
// lies under one, contains one, or matches a built-in deny pattern.
func checkBuiltinDeny(field, p string) error {
	n := normPath(p)
	for _, d := range BuiltinDeny {
		if isGlob(d) {
			if matchesDenyPattern(d, n) {
				return fmt.Errorf("%s: matches built-in deny pattern %s", field, d)
			}
			continue
		}
		dn := normPath(d)
		if UnderFold(n, dn) {
			return fmt.Errorf("%s: is a built-in deny path (%s)", field, d)
		}
		if UnderFold(dn, n) {
			return fmt.Errorf("%s: contains built-in deny path %s", field, d)
		}
	}
	return nil
}

// checkGrantsBuiltinDeny rejects an override entry that equals, lies under,
// or matches a built-in deny. Parents (e.g. "~") are fine in overrides: the
// profile's deny rules still win for the sensitive subtrees. Like Apply's
// real-path check (checkGrantsBuiltinDenyAt), the comparison is
// case-insensitive, so a hand-edited overrides file cannot grant ~/.SSH
// either.
func checkGrantsBuiltinDeny(field, p string) error {
	n := normPath(p)
	for _, d := range BuiltinDeny {
		if isGlob(d) {
			if matchesDenyPattern(d, n) {
				return fmt.Errorf("%s: cannot grant built-in deny pattern %s", field, d)
			}
			continue
		}
		if UnderFold(n, normPath(d)) {
			return fmt.Errorf("%s: cannot grant built-in deny path %s", field, d)
		}
	}
	return nil
}

// appendUnique appends s to list unless already present.
func appendUnique(list []string, s string) []string {
	for _, x := range list {
		if x == s {
			return list
		}
	}
	return append(list, s)
}

// contains reports whether list has s.
func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// containsPath reports whether list has a path equal to p after normalisation.
func containsPath(list []string, p string) bool {
	n := normPath(p)
	for _, x := range list {
		if normPath(x) == n {
			return true
		}
	}
	return false
}

// cloneStrings copies a slice (nil stays nil).
func cloneStrings(s []string) []string {
	if s == nil {
		return nil
	}
	out := make([]string, len(s))
	copy(out, s)
	return out
}

// dedupe removes repeated strings, keeping first occurrences in order.
func dedupe(s []string) []string {
	var out []string
	for _, x := range s {
		out = appendUnique(out, x)
	}
	return out
}
