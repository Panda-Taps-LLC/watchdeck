// Package profile compiles a fully resolved skill policy into a macOS
// Seatbelt profile string.
//
// The package is pure: it never touches the filesystem or the environment.
// Every path in a Resolved is expected to be absolute and already passed
// through filepath.EvalSymlinks, because Seatbelt matches real paths only
// (a deny spelled /var/folders/... never matches /private/var/folders/...;
// see spikes/seatbelt/README.md, Spike 2 (b)).
//
// Rule order, later rules win in Seatbelt:
//
//	(version 1) (allow default)
//	network: none → (deny network*); localhost → deny + bind/inbound/outbound on localhost; all → nothing
//	(deny file-write*)                        when DenyAllWrites
//	(deny file-write* (subpath Home))         otherwise
//	(allow file-write* (subpath Tmp) (subpath "/private/tmp") (subpath CWD) (subpath Write...))
//	(allow file-write* /dev/null /dev/ptmx ^/dev/fd/ ^/dev/tty)   when DenyAllWrites
//	(deny file-read* (subpath DenyPaths...))
//	(deny file-read* (regex #"..."))          one per DenyPattern
//	(allow file-read* (subpath SkillDirs...))
//	(deny file-write* (subpath DenyPaths...))
//	(deny file-write-unlink (literal A...))   every writable ancestor of a DenyPath or an absolute DenyPattern
//	(deny file-write* (regex #"..."))         one per DenyPattern
//	(deny process-exec*) (allow process-exec (literal ExecAllow...))   when !ExecAny
//
// Consequences of that order, both deliberate: a cwd inside ~/.claude still
// cannot write there, and a file matching a DenyPattern that lives inside a
// SkillDir is readable (but never writable, renamable or removable).
package profile

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/Panda-Taps-LLC/watchdeck/internal/manifest"
)

// Resolved is the input to Compile: every path absolute and already through
// EvalSymlinks; no ${VAR} or ~ left.
type Resolved struct {
	SkillDirs []string
	CWD, Tmp  string // Tmp = real per-user temp dir; /private/tmp is always added too
	Write     []string
	DenyPaths []string
	// DenyFiles are existing deny paths that are not directories (files,
	// sockets). Linux hides each by binding /dev/null over it, since a tmpfs
	// needs a directory mount point. The macOS compiler ignores this field;
	// there DenyPaths carries files too.
	DenyFiles []string
	// DenyPatterns are ** globs such as "**/.env" or "/abs/dir/**".
	// Supported: a pattern starting with "**/" or "/", segments made of
	// literal characters, "*" and "?", and "**" as a whole segment.
	DenyPatterns  []string
	ExecAllow     []string
	ExecAny       bool
	Network       manifest.Network
	DenyAllWrites bool   // true → (deny file-write*) + allows; false → deny only under Home
	Home          string // required unless DenyAllWrites
}

// Device nodes an interpreter needs to open for writing once every write is
// denied. Each one was found by removing it in Spike 2 (a):
// /dev/null (subprocess DEVNULL, `> /dev/null`), /dev/ptmx (pty allocation),
// /dev/fd/* (`> /dev/stderr`, /dev/stdout resolve there), /dev/tty* (reopening
// the controlling terminal and pty slaves).
const denyAllDeviceAllows = `(allow file-write* (literal "/dev/null") (literal "/dev/ptmx") (regex #"^/dev/fd/") (regex #"^/dev/tty"))`

// Compile renders r as a Seatbelt profile. It returns an error for input the
// profile language cannot express (newlines, a double quote inside a regex),
// for unsupported globs, and for inputs that would silently nullify a deny
// (a root path, an allow on an ancestor of Home, a skill dir covering a deny
// path, an empty exec allow-list).
func Compile(r Resolved) (string, error) {
	var errs []error
	cwd := cleanPath("CWD", r.CWD, &errs)
	tmp := cleanPath("Tmp", r.Tmp, &errs)
	home := ""
	if r.Home != "" || !r.DenyAllWrites {
		home = cleanPath("Home", r.Home, &errs)
	}
	skillDirs := cleanList("SkillDirs", r.SkillDirs, &errs)
	writes := cleanList("Write", r.Write, &errs)
	denyPaths := cleanList("DenyPaths", r.DenyPaths, &errs)
	execAllow := cleanList("ExecAllow", r.ExecAllow, &errs)

	patterns := uniqSorted(r.DenyPatterns)
	regexes := make([]string, 0, len(patterns))
	for _, g := range patterns {
		re, err := globToRegex(g)
		if err != nil {
			errs = append(errs, fmt.Errorf("DenyPatterns %q: %w", g, err))
			continue
		}
		regexes = append(regexes, re)
	}

	if r.Network < manifest.NetNone || r.Network > manifest.NetAll {
		//lint:ignore ST1005 the prefix is the struct field
		errs = append(errs, fmt.Errorf("Network: unknown value %d", int(r.Network)))
	}
	if !r.ExecAny && len(execAllow) == 0 {
		errs = append(errs, errors.New("ExecAllow: empty allow-list with ExecAny=false would deny every exec, including the shell"))
	}
	if home != "" {
		for _, p := range append(append([]string{cwd, tmp}, writes...), skillDirs...) {
			if p != "" && isStrictAncestor(p, home) {
				errs = append(errs, fmt.Errorf("%q is an ancestor of Home %q: an allow there would nullify the home deny", p, home))
			}
		}
	}
	for _, s := range skillDirs {
		for _, d := range denyPaths {
			if s == d || isStrictAncestor(s, d) {
				errs = append(errs, fmt.Errorf("SkillDirs %q covers DenyPaths %q: the read allow would nullify the deny", s, d))
			}
		}
	}
	if len(errs) > 0 {
		return "", errors.Join(errs...)
	}

	var b strings.Builder
	line := func(s string) { b.WriteString(s); b.WriteByte('\n') }

	line("(version 1)")
	line("(allow default)")

	switch r.Network {
	case manifest.NetNone:
		line("(deny network*)")
	case manifest.NetLocalhost:
		// Not the contract's `(allow network* (local ip "localhost:*"))`:
		// that form re-allows every outbound connection (Spike 2 (e)).
		line("(deny network*)")
		line(`(allow network-bind (local ip "localhost:*"))`)
		line(`(allow network-inbound (local ip "localhost:*"))`)
		line(`(allow network-outbound (remote ip "localhost:*"))`)
	case manifest.NetAll:
	}

	if r.DenyAllWrites {
		line("(deny file-write*)")
	} else {
		line("(deny file-write* " + subpath(home) + ")")
	}
	writeAllows := uniqSorted(append([]string{tmp, "/private/tmp", cwd}, writes...))
	line("(allow file-write* " + subpaths(writeAllows) + ")")
	if r.DenyAllWrites {
		line(denyAllDeviceAllows)
	}

	if len(denyPaths) > 0 {
		line("(deny file-read* " + subpaths(denyPaths) + ")")
	}
	for _, re := range regexes {
		line(`(deny file-read* (regex #"` + re + `"))`)
	}
	if len(skillDirs) > 0 {
		line("(allow file-read* " + subpaths(skillDirs) + ")")
	}
	if len(denyPaths) > 0 {
		line("(deny file-write* " + subpaths(denyPaths) + ")")
	}
	// A subpath deny covers the path and what is under it, not its parents:
	// from a writable ancestor (cwd = home) `mv ~/.config ~/c` moves gcloud
	// out from under the deny. Refuse renaming or removing every writable
	// ancestor (review 2026-10-14).
	if anc := writableAncestors(denyPaths, patterns, writeAllows, home, r.DenyAllWrites); len(anc) > 0 {
		lits := make([]string, len(anc))
		for i, a := range anc {
			lits[i] = `(literal "` + escape(a) + `")`
		}
		line("(deny file-write-unlink " + strings.Join(lits, " ") + ")")
	}
	// Seatbelt checks the path at open time, so a read deny alone lets a
	// script rename a matching file in a writable dir (mv .env x) and read
	// the copy. Denying writes refuses the rename and the unlink (review
	// 2026-10-14).
	for _, re := range regexes {
		line(`(deny file-write* (regex #"` + re + `"))`)
	}

	if !r.ExecAny {
		line("(deny process-exec*)")
		lits := make([]string, len(execAllow))
		for i, p := range execAllow {
			lits[i] = `(literal "` + escape(p) + `")`
		}
		line("(allow process-exec " + strings.Join(lits, " ") + ")")
	}
	return b.String(), nil
}

// writableAncestors returns the sorted strict ancestors (never "/") of each
// deny path, and of the literal prefix of each absolute deny pattern, that
// the profile leaves writable: at or under a write allow, or outside Home
// when only Home is write-denied. Renaming one would move the protected
// path to a spelling no deny matches.
func writableAncestors(denyPaths, patterns, writeAllows []string, home string, denyAll bool) []string {
	writable := func(a string) bool {
		for _, w := range writeAllows {
			if a == w || isStrictAncestor(w, a) {
				return true
			}
		}
		return !denyAll && home != "" && a != home && !isStrictAncestor(home, a)
	}
	targets := append([]string(nil), denyPaths...)
	for _, g := range patterns {
		if !strings.HasPrefix(g, "/") {
			continue // "**/..." matches under any parent, so a move keeps it matched
		}
		segs := strings.Split(g, "/")
		n := 1
		for n < len(segs) && !strings.ContainsAny(segs[n], "*?") {
			n++
		}
		if n == len(segs) {
			targets = append(targets, g) // a literal path: its parents
		} else {
			// The literal prefix itself is not matched (/abs/**/key does not
			// match /abs), so protect it too: add a pseudo child.
			targets = append(targets, path.Join(strings.Join(segs[:n], "/"), "*"))
		}
	}
	var out []string
	for _, t := range targets {
		for a := path.Dir(t); a != "/" && a != "."; a = path.Dir(a) {
			if writable(a) {
				out = append(out, a)
			}
		}
	}
	return uniqSorted(out)
}

// Hash returns the first 8 hex characters of sha256(profile), for display
// in trailers and as a cache key.
func Hash(profile string) string {
	sum := sha256.Sum256([]byte(profile))
	return hex.EncodeToString(sum[:])[:8]
}

// cleanPath validates one path and returns it cleaned ("" on error).
func cleanPath(field, p string, errs *[]error) string {
	switch {
	case p == "":
		*errs = append(*errs, fmt.Errorf("%s: empty path", field))
		return ""
	case strings.ContainsAny(p, "\n\r\x00"):
		*errs = append(*errs, fmt.Errorf("%s: path %q contains a newline or NUL", field, p))
		return ""
	case !strings.HasPrefix(p, "/"):
		*errs = append(*errs, fmt.Errorf("%s: path %q is not absolute", field, p))
		return ""
	}
	c := path.Clean(p)
	if c == "/" {
		*errs = append(*errs, fmt.Errorf("%s: refusing the root path", field))
		return ""
	}
	return c
}

// cleanList validates every entry and returns the sorted, deduplicated list.
func cleanList(field string, ps []string, errs *[]error) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		if c := cleanPath(field, p, errs); c != "" {
			out = append(out, c)
		}
	}
	return uniqSorted(out)
}

func uniqSorted(ss []string) []string {
	out := make([]string, 0, len(ss))
	seen := make(map[string]bool, len(ss))
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// isStrictAncestor reports whether dir is a proper ancestor of p
// (both cleaned, absolute).
func isStrictAncestor(dir, p string) bool {
	return dir != p && strings.HasPrefix(p, dir+"/")
}

// escape makes s safe inside a Seatbelt "..." string: \ → \\ and " → \".
// Both forms were verified against directories named odd"q and odd\b.
func escape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s)
}

func subpath(p string) string { return `(subpath "` + escape(p) + `")` }

func subpaths(ps []string) string {
	parts := make([]string, len(ps))
	for i, p := range ps {
		parts[i] = subpath(p)
	}
	return strings.Join(parts, " ")
}

// globToRegex converts a ** glob into a Seatbelt regex. Only POSIX ERE
// constructs are emitted ((^|/), (.*/)?, (/|$), [^/]*, [^/], \-escapes).
//
//	**/.env        → (^|/)\.env$
//	**/*.pem       → (^|/)[^/]*\.pem$
//	**/foo/**      → (^|/)foo(/|$)
//	/abs/dir/**    → ^/abs/dir(/|$)
//	/abs/**/key    → ^/abs/(.*/)?key$
//	/abs/file      → ^/abs/file$        (the file only, not a directory's contents)
func globToRegex(g string) (string, error) {
	switch {
	case g == "":
		return "", errors.New("empty pattern")
	case strings.ContainsAny(g, "\n\r\x00"):
		return "", errors.New("pattern contains a newline or NUL")
	case strings.Contains(g, `"`):
		return "", errors.New(`a double quote cannot be expressed inside a Seatbelt regex literal`)
	case strings.ContainsAny(g, `[]{}\`):
		return "", errors.New("character classes, brace alternation and backslash escapes are not supported")
	case !strings.HasPrefix(g, "**/") && !strings.HasPrefix(g, "/"):
		return "", errors.New(`pattern must start with "**/" or "/"`)
	}
	segs := strings.Split(g, "/")
	for i := 1; i < len(segs); i++ {
		if segs[i] == "**" && segs[i-1] == "**" {
			return "", errors.New("consecutive ** segments")
		}
	}
	var b strings.Builder
	needSep := false
	if segs[0] == "" { // absolute
		b.WriteString("^")
		segs = segs[1:]
		needSep = true
	} else { // "**/..."
		b.WriteString("(^|/)")
		segs = segs[1:]
	}
	allStars := true
	for i, s := range segs {
		last := i == len(segs)-1
		switch {
		case s == "":
			return "", errors.New("empty path segment (doubled or trailing slash)")
		case s == "**":
			if last {
				b.WriteString("(/|$)")
				continue
			}
			if needSep {
				b.WriteString("/")
			}
			b.WriteString("(.*/)?")
			needSep = false
		case strings.Contains(s, "**"):
			return "", fmt.Errorf("** must be a whole path segment (got %q)", s)
		default:
			allStars = false
			if needSep {
				b.WriteString("/")
			}
			for _, r := range s {
				switch r {
				case '*':
					b.WriteString("[^/]*")
				case '?':
					b.WriteString("[^/]")
				default:
					b.WriteString(regexp.QuoteMeta(string(r)))
				}
			}
			needSep = true
			if last {
				b.WriteString("$")
			}
		}
	}
	if allStars {
		return "", errors.New("pattern would match every path")
	}
	re := b.String()
	if _, err := regexp.Compile(re); err != nil {
		return "", fmt.Errorf("internal: produced invalid regex %q: %w", re, err)
	}
	return re, nil
}
