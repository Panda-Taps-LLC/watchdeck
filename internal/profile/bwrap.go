package profile

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Panda-Taps-LLC/watchdeck/internal/manifest"
)

// BwrapArgs compiles a Resolved policy to a bubblewrap argument vector, one
// argument per line (the Linux "profile" text internal/sandbox splits).
//
// Designed 2026-10-12, CI-tested only. Order matters: bwrap applies mounts in
// argument order, so writable binds come first and the deny tmpfs mounts
// after them (a deny always shadows a bind), then the skill directories are
// re-exposed read-only (a skill under ~/.claude must stay readable), then
// namespaces are unshared.
//
//	--ro-bind / /  --dev /dev  --proc /proc
//	--bind <p> <p>                 for each writable path (cwd, tmp, extras)
//	--tmpfs <deny path>            for each existing deny directory (hides it)
//	--ro-bind /dev/null <file>     for each existing deny file or socket (a tmpfs needs a directory)
//	--ro-bind <skill dir> <same>   re-expose the skill's own code
//	--unshare-all [--share-net]    pid, ipc, uts, cgroup, user, net (net kept only for network=all)
//	--clearenv  --die-with-parent  --new-session
//	--setenv K V ...               appended by internal/sandbox for each variable the runner kept
//
// Not expressible with bwrap and therefore documented limits on Linux:
// exec allow-lists (warning only), network=localhost (treated as none: a
// fresh network namespace has no usable loopback without privileges), and
// ** deny patterns such as **/.env (only literal paths can be hidden).
func BwrapArgs(r Resolved) (string, []string, error) {
	var args []string
	var warnings []string
	add := func(a ...string) { args = append(args, a...) }
	add("--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc")

	deny := append([]string(nil), r.DenyPaths...)
	sort.Strings(deny)
	for _, d := range deny {
		d = filepath.Clean(d)
		if d == "" || d == "/" {
			return "", nil, fmt.Errorf("refusing to hide %q", d)
		}
	}

	writes := map[string]bool{}
	for _, w := range append([]string{r.CWD, r.Tmp}, r.Write...) {
		w = filepath.Clean(w)
		if w == "/" {
			return "", nil, fmt.Errorf("refusing to make / writable")
		}
		writes[w] = true
	}
	var wl []string
	for w := range writes {
		wl = append(wl, w)
	}
	sort.Strings(wl)
	for _, w := range wl {
		for _, d := range deny {
			if under(w, d) {
				warnings = append(warnings, fmt.Sprintf("writable path %s lies under denied %s and will be hidden", w, d))
			}
		}
		add("--bind", w, w)
	}
	for _, d := range deny {
		add("--tmpfs", filepath.Clean(d))
	}
	files := append([]string(nil), r.DenyFiles...)
	sort.Strings(files)
	for i, f := range files {
		f = filepath.Clean(f)
		if f == "" || f == "/" || f == "/dev/null" {
			return "", nil, fmt.Errorf("refusing to hide %q", f)
		}
		files[i] = f
		add("--ro-bind", "/dev/null", f)
	}
	for _, s := range r.SkillDirs {
		s = filepath.Clean(s)
		for _, d := range append(append([]string(nil), deny...), files...) {
			if under(d, s) {
				return "", nil, fmt.Errorf("skill dir %s covers denied path %s", s, d)
			}
		}
		add("--ro-bind", s, s)
	}
	if len(r.DenyPatterns) > 0 {
		warnings = append(warnings, "deny patterns are not enforced on Linux: "+strings.Join(r.DenyPatterns, ", "))
	}

	add("--unshare-all")
	switch r.Network {
	case manifest.NetAll:
		add("--share-net")
	case manifest.NetLocalhost:
		warnings = append(warnings, "network=localhost is treated as none on Linux (no loopback in an unprivileged network namespace)")
	}
	if !r.ExecAny {
		warnings = append(warnings, "exec allow-lists are not enforced on Linux")
	}
	add("--clearenv", "--die-with-parent", "--new-session")
	return strings.Join(args, "\n"), warnings, nil
}

// under reports whether p equals or lies below dir.
func under(p, dir string) bool {
	return p == dir || strings.HasPrefix(p, dir+"/")
}
