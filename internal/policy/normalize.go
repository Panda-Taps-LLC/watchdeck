package policy

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// Gate input normalisation (M6.3). The hook normalises a tool call's target
// before any gate looks at it, so one file or host has one spelling.
//
// Paths:
//   - "~" and "~/…" expand against the home directory; "~user/…" is not
//     resolved (no os/user lookup in the hook) and is reported as not
//     normalisable, so a gate answers ask for it;
//   - a relative path is joined to the call's cwd (no cwd: not normalisable);
//   - filepath.Clean removes "//", "/./" and "..";
//   - the real spelling resolves symlinks on the longest existing prefix
//     (a file that does not exist yet still has its parent resolved), and
//     gates check both the lexical and the real spelling;
//   - comparisons are case-folded on every OS (ToolGate). That is exact on
//     the macOS default (APFS, case-insensitive) and errs towards matching
//     more on a case-sensitive filesystem, which for a deny-or-ask gate is
//     the safe direction;
//   - Unicode normalisation (NFC/NFD) is not applied: the standard library
//     has none and the repo takes no new dependency. APFS looks names up
//     normalisation-insensitively, so a decomposed spelling of a non-ASCII
//     name in a gate entry or a target does not match the other form.
//     Documented gap; ASCII paths are unaffected.
//
// Hosts:
//   - net/url parses "scheme://…", "//host…" and a bare "user@host:port/…";
//     Hostname() drops userinfo, the port and IPv6 brackets;
//   - percent-encoding in the host is decoded by net/url;
//   - lower case, trailing dots trimmed;
//   - IDNA is not applied (golang.org/x/net/idna is not a dependency): a
//     host with non-ASCII characters is reported as not normalisable, so a
//     domain gate answers ask for it; an "xn--" host compares as written.
//   - IP literals compare as written (no decimal or octal IPv4 forms).

// Target is a normalised gate target.
type Target struct {
	// Lexical is the absolute, cleaned path (or the host).
	Lexical string
	// Real is the path with symlinks resolved on its longest existing
	// prefix; "" when equal to Lexical or for a host.
	Real string
	// OK is false when the target could not be normalised (~user, a
	// relative path without a cwd, an empty or non-ASCII host). Gates treat
	// such a target as unknown and answer ask when they have entries for
	// the tool.
	OK bool
}

// NormalizePath normalises a tool's file path against cwd and home.
func NormalizePath(p, cwd, home string) Target {
	p = strings.TrimSpace(p)
	if p == "" || strings.ContainsRune(p, 0) {
		return Target{}
	}
	switch {
	case p == "~" || strings.HasPrefix(p, "~/"):
		if home == "" {
			return Target{Lexical: p}
		}
		p = home + p[1:]
	case strings.HasPrefix(p, "~"):
		return Target{Lexical: p} // ~user: not resolved
	case !filepath.IsAbs(p):
		if cwd == "" || !filepath.IsAbs(cwd) {
			return Target{Lexical: p}
		}
		p = filepath.Join(cwd, p)
	}
	lex := filepath.Clean(p)
	if aliasPrefix(lex) {
		return Target{Lexical: lex} // /.vol, /.resolve, /.nofollow (macOS): not resolved, gates ask
	}
	lex = stripDataVolume(lex)
	t := Target{Lexical: lex, OK: true}
	if r := canonical(ResolveExisting(lex)); r != lex {
		t.Real = r
	}
	return t
}

// CanonicalPath is the real spelling of an absolute path: symlinks resolved
// on the longest existing prefix, and on macOS the kernel's path for the
// longest existing directory (true case, firmlinks).
func CanonicalPath(p string) string {
	if p == "" || !filepath.IsAbs(p) {
		return p
	}
	return canonical(ResolveExisting(stripDataVolume(filepath.Clean(p))))
}

// canonical replaces the longest existing directory of p with the
// kernel's own path for it (macOS: fcntl F_GETPATH; elsewhere unchanged).
func canonical(p string) string {
	dir, rest := p, ""
	for i := 0; i < 256; i++ {
		if fi, err := os.Stat(dir); err == nil && fi.IsDir() {
			c := canonicalDir(dir)
			if rest == "" {
				return c
			}
			return filepath.Join(c, rest)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return p
		}
		if rest == "" {
			rest = filepath.Base(dir)
		} else {
			rest = filepath.Join(filepath.Base(dir), rest)
		}
		dir = parent
	}
	return p
}

// ResolveExisting follows symlinks on the longest existing prefix of an
// absolute path, keeping the rest as written.
func ResolveExisting(p string) string {
	p = filepath.Clean(p)
	rest := ""
	for i := 0; i < 256; i++ {
		if r, err := filepath.EvalSymlinks(p); err == nil {
			if rest == "" {
				return r
			}
			return filepath.Join(r, rest)
		}
		parent := filepath.Dir(p)
		if parent == p {
			return filepath.Join(p, rest)
		}
		if rest == "" {
			rest = filepath.Base(p)
		} else {
			rest = filepath.Join(filepath.Base(p), rest)
		}
		p = parent
	}
	return p
}

// NormalizeHost returns the host a URL (or a bare host) names, normalised.
func NormalizeHost(raw string) Target {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 8<<10 {
		return Target{}
	}
	var u *url.URL
	var err error
	scheme, rest, hasScheme := splitScheme(raw)
	switch {
	case hasScheme && specialScheme(scheme):
		// WHATWG URL parsing for http, https, ws, wss, ftp: a backslash is
		// a slash, and any number of slashes (none included) may follow
		// the colon (http:/evil.com, http:evil.com, https:\\evil.com all
		// name evil.com).
		rest = strings.ReplaceAll(rest, `\`, "/")
		u, err = url.Parse(scheme + "://" + strings.TrimLeft(rest, "/"))
	case hasScheme && strings.HasPrefix(rest, "//"):
		u, err = url.Parse(raw)
	case hasScheme:
		// another scheme without an authority (javascript:, data:, file:x):
		// no host to compare, so not normalisable
		return Target{}
	case strings.HasPrefix(raw, "//"):
		u, err = url.Parse(raw)
	default:
		u, err = url.Parse("//" + raw)
	}
	if err != nil || u == nil {
		return Target{}
	}
	h := strings.TrimRight(strings.ToLower(u.Hostname()), ".")
	if h == "" {
		return Target{}
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		if c >= 0x80 || c <= ' ' || c == '/' || c == '\\' || c == '@' || c == '%' {
			return Target{Lexical: h}
		}
	}
	return Target{Lexical: h, OK: true}
}

// splitScheme splits "scheme:rest" when raw starts with a URL scheme
// (a letter, then letters, digits, + - .) followed by ':' that is not a
// host:port (a scheme has no '.', and a port is digits).
func splitScheme(raw string) (scheme, rest string, ok bool) {
	i := strings.IndexByte(raw, ':')
	if i <= 0 {
		return "", "", false
	}
	s := raw[:i]
	for j := 0; j < len(s); j++ {
		c := s[j]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		case j > 0 && (c >= '0' && c <= '9' || c == '+' || c == '-'):
		default:
			return "", "", false // '.', '@', '/' or a leading digit: a host or userinfo
		}
	}
	rest = raw[i+1:]
	if port := strings.SplitN(rest, "/", 2)[0]; port != "" && strings.Trim(port, "0123456789") == "" && !specialScheme(s) {
		return "", "", false // host:port ("localhost:8080/x")
	}
	return strings.ToLower(s), rest, true
}

// specialScheme reports the WHATWG special schemes with a host.
func specialScheme(s string) bool {
	switch strings.ToLower(s) {
	case "http", "https", "ws", "wss", "ftp":
		return true
	}
	return false
}

// SplitMCPTool returns every (server, tool) reading of a tool name
// mcp__<server>__<tool>. A server or tool name may itself contain "__"
// (Claude Code replaces characters outside [A-Za-z0-9_-] with "_"), so the
// split is ambiguous; callers check every reading and take the strongest
// gate. ok is false for a name that is not an MCP tool.
func SplitMCPTool(name string) (splits [][2]string, ok bool) {
	rest, isMCP := strings.CutPrefix(name, "mcp__")
	if !isMCP || rest == "" {
		return nil, false
	}
	for i := 0; i+2 < len(rest); i++ {
		if rest[i] == '_' && rest[i+1] == '_' && i > 0 {
			splits = append(splits, [2]string{rest[:i], rest[i+2:]})
		}
	}
	return splits, len(splits) > 0
}
