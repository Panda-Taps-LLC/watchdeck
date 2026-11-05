// Package projectscope validates the ?project=<abs root> parameter that the
// dashboard's project-scoped routes take when the server has no working
// directory of its own (auto and service mode, M5.3). A project is accepted
// only when it is one the machine has already seen: the cwd, or the git root
// of the cwd, of a Claude Code session in the session index or of a record in
// the activity log. Anything else is refused, so a request cannot point the
// server at an arbitrary directory.
//
// The package is init-free and touches the disk only through the Known
// callback the caller provides and paths.ProjectRoot.
package projectscope

import (
	"errors"
	"path/filepath"
	"strings"

	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
)

// Param is the query parameter name.
const Param = "project"

// ErrUnknown is returned for a project that is not absolute, not clean, or
// not among the known roots. The message never echoes the value.
var ErrUnknown = errors.New("unknown project: pass the absolute root of a project with recorded sessions")

// Roots maps every cwd to itself and to its git root (paths.ProjectRoot,
// which stops at home), dropping empty and relative values and duplicates.
func Roots(cwds []string, home string) []string {
	seen := make(map[string]bool, len(cwds))
	var out []string
	add := func(p string) {
		if p == "" || !filepath.IsAbs(p) {
			return
		}
		p = filepath.Clean(p)
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, c := range cwds {
		add(c)
		add(paths.ProjectRoot(c, home))
	}
	return out
}

// Display is how the dashboard shows a project path (M5.5): "~" or "~/<rel>"
// under home, the path as recorded anywhere else. The JSON the dashboard
// serves carries this form, never the home dir itself, and Resolve takes it
// back.
func Display(p, home string) string {
	if p == "" || home == "" || !filepath.IsAbs(p) {
		return p
	}
	p = filepath.Clean(p)
	home = filepath.Clean(home)
	if p == home {
		return "~"
	}
	if rel, err := filepath.Rel(home, p); err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, "../") {
		return "~/" + filepath.ToSlash(rel)
	}
	return p
}

// Expand undoes Display: "~" is home and "~/<rel>" is home joined with rel
// (cleaned); any other value is returned unchanged. A "~/" value whose rel
// climbs out of home ("~/../x") is returned unchanged, so Resolve refuses it
// as not absolute.
func Expand(v, home string) string {
	if home == "" || !filepath.IsAbs(home) {
		return v
	}
	if v == "~" {
		return filepath.Clean(home)
	}
	rest, ok := strings.CutPrefix(v, "~/")
	if !ok || rest == "" {
		return v
	}
	for _, seg := range strings.Split(rest, "/") {
		if seg == ".." {
			return v
		}
	}
	return filepath.Join(home, rest)
}

// Resolve returns the working directory a request should use. With no
// project value it is def (the server's own cwd, possibly ""). A "~/<rel>"
// value is first expanded against home (Expand; M5.5, so the page can send
// back the Display form it was given). A value must then be absolute,
// already clean, free of NUL and "..", and equal to one of the
// roots known() returns (or to def, or to def's git root); otherwise it is
// ErrUnknown.
func Resolve(value, def, home string, known func() []string) (string, error) {
	if value == "" {
		return def, nil
	}
	value = Expand(value, home)
	if !filepath.IsAbs(value) || filepath.Clean(value) != value || strings.ContainsRune(value, 0) {
		return "", ErrUnknown
	}
	if def != "" && (value == filepath.Clean(def) || value == paths.ProjectRoot(def, home)) {
		return value, nil
	}
	if known == nil {
		return "", ErrUnknown
	}
	for _, k := range known() {
		if k == value {
			return value, nil
		}
	}
	return "", ErrUnknown
}
