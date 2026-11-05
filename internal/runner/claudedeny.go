package runner

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/Panda-Taps-LLC/watchdeck/internal/manifest"

	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
)

// extraDeny is what `run` denies outside the manifest, for every sandboxed
// run (skill, command subject, MCP launch).
type extraDeny struct {
	// Paths are absolute deny paths (read and write) for toResolved; a write
	// entry under one is dropped like one under ~/.ssh.
	Paths []string
	// Patterns are absolute deny globs (Seatbelt read regexes), e.g.
	// "/Users/x/.claude.json*". Linux cannot enforce patterns, so they are
	// only set on darwin; there every existing match is in Paths instead.
	Patterns []string
}

// accountHome is the home directory of the account running this process,
// from the user database (getpwuid through libc on darwin, also with
// CGO_ENABLED=0; /etc/passwd on Linux without cgo). It never reads $HOME,
// which a command line can set (`HOME=/x watchdeck run …`). Tests replace
// it.
var accountHome = func() (string, error) {
	u, err := user.LookupId(strconv.Itoa(os.Getuid()))
	if err != nil {
		return "", err
	}
	if u.HomeDir == "" || !filepath.IsAbs(u.HomeDir) {
		return "", errors.New("the user database has no absolute home directory for this account")
	}
	return filepath.Clean(u.HomeDir), nil
}

// runDeny computes extraDeny. It fails closed (the run exits 125):
//   - when the account's home cannot be read from the user database: the
//     home-relative denies could otherwise be moved by setting $HOME;
//   - when CLAUDE_CONFIG_DIR is set but not absolute;
//   - when the state dir cannot be resolved (stateDeny).
//
// What it denies:
//   - watchdeck's state dir (stateDeny), and when $HOME is not the account
//     home also the account home's default state dir;
//   - for $HOME and the account home: <home>/.claude.json and every existing
//     sibling starting with .claude.json (.claude.json.backup, temp files),
//     plus the pattern <home>/.claude.json* on darwin;
//   - for the account home, when it differs from $HOME: every literal
//     built-in deny (~/.ssh, ~/.aws, ~/.claude, …) expanded there;
//   - $CLAUDE_CONFIG_DIR/.claude.json (and siblings), and $CLAUDE_CONFIG_DIR
//     itself when it is not <home>/.claude for either home. The directory is
//     skipped when it is, or contains, a home or the working directory
//     (denying it would deny the whole run); its .claude.json still is not.
func runDeny(env Env) (extraDeny, error) {
	var x extraDeny
	state, err := stateDeny(env)
	if err != nil {
		return x, err
	}
	x.Paths = append(x.Paths, state...)
	real, err := accountHome()
	if err != nil {
		return x, fmt.Errorf("cannot read this account's home directory from the user database (%v); refusing to run, since $HOME alone can be redirected", err)
	}
	environ := env.Environ
	if environ == nil {
		environ = map[string]string{}
	}
	homes := []string{filepath.Clean(env.Home)}
	if !sameDir(real, env.Home) {
		homes = append(homes, real)
		for _, d := range manifest.BuiltinDeny {
			if rest, ok := strings.CutPrefix(d, "~/"); ok && !strings.ContainsAny(rest, "*?[{") {
				x.Paths = append(x.Paths, filepath.Join(real, rest))
			}
		}
		x.Paths = append(x.Paths, filepath.Join(real, ".local", "state", paths.BinaryName))
	}
	for _, h := range homes {
		x.addClaudeJSON(h)
	}
	if cd, set := environ["CLAUDE_CONFIG_DIR"]; set && cd != "" {
		if !filepath.IsAbs(cd) {
			return x, errors.New("CLAUDE_CONFIG_DIR is not an absolute path; refusing to run (the deny for Claude Code's config could not be placed)")
		}
		cd = filepath.Clean(cd)
		x.addClaudeJSON(cd)
		relocated := true
		for _, h := range homes {
			if sameDir(cd, filepath.Join(h, ".claude")) {
				relocated = false
			}
		}
		for _, p := range append(append([]string(nil), homes...), env.Cwd) {
			if p != "" && (manifest.UnderFold(p, cd) || manifest.UnderFold(realPath(p), realPath(cd))) {
				relocated = false
			}
		}
		if relocated {
			x.Paths = append(x.Paths, cd)
		}
	}
	x.Paths = dedupe(x.Paths)
	x.Patterns = dedupe(x.Patterns)
	return x, nil
}

// addClaudeJSON denies dir/.claude.json, every existing dir/.claude.json*
// sibling, and (darwin) the pattern dir/.claude.json*, spelled on the real
// path because Seatbelt matches real paths.
func (x *extraDeny) addClaudeJSON(dir string) {
	x.Paths = append(x.Paths, filepath.Join(dir, ".claude.json"))
	if ms, err := filepath.Glob(filepath.Join(globEscape(dir), ".claude.json*")); err == nil {
		x.Paths = append(x.Paths, ms...)
	}
	if runtime.GOOS == "darwin" {
		rd := resolveExisting(dir)
		if !strings.ContainsAny(rd, "*?[]{}\\\"\n") {
			x.Patterns = append(x.Patterns, rd+"/.claude.json*")
		}
	}
}

func sameDir(a, b string) bool {
	return filepath.Clean(a) == filepath.Clean(b) || realPath(a) == realPath(b)
}

func globEscape(p string) string {
	r := strings.NewReplacer(`\`, `\\`, `*`, `\*`, `?`, `\?`, `[`, `\[`)
	return r.Replace(p)
}

func dedupe(xs []string) []string {
	seen := map[string]bool{}
	out := xs[:0]
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}
