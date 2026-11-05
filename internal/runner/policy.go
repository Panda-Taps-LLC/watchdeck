// Package runner implements `watchdeck run`: resolve the effective policy
// for one or more skills, compile the OS sandbox profile, execute the command
// under it, and explain denials.
package runner

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"

	"github.com/Panda-Taps-LLC/watchdeck/internal/index"
	"github.com/Panda-Taps-LLC/watchdeck/internal/manifest"
	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
	"github.com/Panda-Taps-LLC/watchdeck/internal/profile"
	"github.com/Panda-Taps-LLC/watchdeck/internal/skills"
)

// Policy is the fully resolved decision for a run.
type Policy struct {
	Skills    []string
	Subject   string   // "command:<name>" for a command subject run (M6.3); "" for skills
	SkillDirs []string // real roots
	Effective manifest.Effective
	Ungranted []string // request items beyond the grant, per skill: "<skill>: network: all"
	Ignored   []string // project override entries dropped
	Resolved  profile.Resolved
	Profile   string
	Warnings  []string // backend limits (Linux: exec allow-lists, localhost, deny patterns)
	Hash      string
	// ExtraDeny is what run denies outside the manifest (runDeny: state
	// dir, Claude Code's config, the account home's built-in denies when
	// $HOME differs); the run record lists it with the effective deny list.
	ExtraDeny []string

	cwdIsHome bool // MCP launches: the working directory is a home directory
}

// Env is everything Resolve needs from the host.
type Env struct {
	Home       string
	Cwd        string
	CacheDir   string // XDG cache dir (index lives under <CacheDir>/watchdeck)
	UserCfgDir string // where overrides.yaml lives
	Environ    map[string]string
}

// ErrUnknownSkill is returned when a requested skill is not in the index.
type ErrUnknownSkill struct{ Name string }

func (e ErrUnknownSkill) Error() string {
	return "unknown skill " + e.Name + " (not found by discovery; run `watchdeck audit`)"
}

// ErrManifest is a malformed PERMISSIONS.yaml (exit 125 territory).
type ErrManifest struct {
	Skill string
	Err   error
}

func (e ErrManifest) Error() string { return e.Skill + ": " + e.Err.Error() }

// Resolve computes the policy for the named skills. needShell is true when
// the command will be run through /bin/bash -c (the -c form): a restricted
// exec allow-list then also admits /bin/bash, which the wrapper itself needs.
// Bash under an exec allow-list can only run builtins and the listed binaries.
func Resolve(names []string, env Env, needShell bool) (*Policy, error) {
	if len(names) == 0 {
		return nil, fmt.Errorf("no skill given")
	}
	roots := skills.Roots{Home: env.Home, Cwd: env.Cwd, Env: map[string]string{}}
	if v := env.Environ["CLAUDE_SKILL_DIR"]; v != "" {
		roots.Env["CLAUDE_SKILL_DIR"] = v
	}
	ix, _, err := index.LoadOrBuild(index.Path(env.CacheDir), roots, env.UserCfgDir)
	if err != nil {
		return nil, fmt.Errorf("index: %w", err)
	}
	projectRoot := index.ProjectRoot(env.Cwd, env.Home)
	user, project, err := manifest.LoadOverrides(env.UserCfgDir, projectRoot)
	if err != nil {
		// "overrides: <file>: <field>: <rule>", the hook's wording; the
		// parser never puts a value from the file into the error.
		return nil, fmt.Errorf("overrides: %w", err)
	}

	pol := &Policy{}
	var eff manifest.Effective
	for i, name := range names {
		entry, ok := ix.Lookup(name)
		if !ok {
			return nil, ErrUnknownSkill{name}
		}
		grant, ignored := manifest.Grant(name, user, project)
		for _, ig := range ignored {
			pol.Ignored = append(pol.Ignored, name+": "+ig)
		}
		one := grant
		mp := entry.Manifest
		if mp == "" {
			mp = filepath.Join(entry.Dir, "PERMISSIONS.yaml")
		}
		if _, statErr := os.Stat(mp); statErr == nil {
			req, perr := manifest.Parse(mp)
			if perr != nil {
				return nil, ErrManifest{name, perr}
			}
			var ung []string
			one, ung = manifest.Clip(req, grant)
			for _, u := range ung {
				pol.Ungranted = append(pol.Ungranted, name+": "+u)
			}
		}
		if i == 0 {
			eff = one
		} else {
			eff = manifest.Intersect(eff, one)
		}
		pol.Skills = append(pol.Skills, name)
		pol.SkillDirs = append(pol.SkillDirs, entry.Dir)
	}

	realCWD := realPath(env.Cwd)
	realTMP := userTempDir(env.Environ)
	var more []string
	eff, more = manifest.ResolveProjectScoped(eff, realCWD, realTMP)
	pol.Ignored = append(pol.Ignored, more...)

	extra, err := runDeny(env) // state dir, Claude Code's config, account home (claudedeny.go)
	if err != nil {
		return nil, err
	}
	res, dropped, droppedWrites, err := toResolved(eff, pol.SkillDirs, env.Home, realCWD, realTMP, extra.Paths)
	if err != nil {
		return nil, err
	}
	res.DenyPatterns = append(res.DenyPatterns, extra.Patterns...)
	pol.ExtraDeny = append(append([]string(nil), extra.Paths...), extra.Patterns...)
	// A write the profile does not carry must not be reported as granted
	// (run record, trailer, dashboard): take it out of the effective policy.
	for _, w := range droppedWrites {
		eff.Write = removeEntry(eff.Write, w)
	}
	pol.Effective = eff
	if needShell && !res.ExecAny {
		res.ExecAllow = append(res.ExecAllow, "/bin/bash")
		sort.Strings(res.ExecAllow)
	}
	pol.Resolved = res
	p, warnings, err := compile(res)
	if err != nil {
		return nil, fmt.Errorf("profile: %w", err)
	}
	pol.Profile = p
	pol.Warnings = append(dropped, warnings...)
	if realCWD == realPath(env.Home) {
		pol.Warnings = append(pol.Warnings, "working directory is your home directory: the script may write anywhere under it except the protected paths; run from a project directory for a tighter sandbox")
	}
	pol.Hash = profile.Hash(p)
	return pol, nil
}

// compile picks the backend: Seatbelt text on macOS, a bwrap argv on Linux.
func compile(res profile.Resolved) (string, []string, error) {
	if runtime.GOOS == "linux" {
		// Hide user runtime sockets too (ssh-agent, docker, session bus): the
		// ro-bind of / would otherwise expose them. Keep only paths that exist,
		// since bwrap cannot mount over a missing one, and split them by type:
		// a tmpfs needs a directory mount point, so files and sockets are hidden
		// with /dev/null instead (the first CI run, 2026-10-12, failed on
		// "--tmpfs /run/docker.sock: Not a directory").
		candidates := append([]string(nil), res.DenyPaths...)
		candidates = append(candidates, fmt.Sprintf("/run/user/%d", os.Getuid()), "/var/run/docker.sock", "/run/docker.sock")
		if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
			candidates = append(candidates, filepath.Dir(sock))
		}
		var existing, files []string
		seen := map[string]bool{}
		for _, d := range candidates {
			// Real path first: /var/run/docker.sock and /run/docker.sock are one
			// inode, and bwrap fails when the same target is mounted twice under
			// two spellings (second CI run, 2026-10-12).
			d = resolveExisting(filepath.Clean(d))
			if seen[d] {
				continue
			}
			if fi, err := os.Stat(d); err == nil {
				seen[d] = true
				if fi.IsDir() {
					existing = append(existing, d)
				} else {
					files = append(files, d)
				}
			}
		}
		res.DenyPaths = existing
		res.DenyFiles = files
		return profile.BwrapArgs(res)
	}
	p, err := profile.Compile(res)
	return p, nil, err
}

// stateDeny returns watchdeck's own state dir (paths.Resolve, so
// XDG_STATE_HOME is honoured), which a sandboxed script may neither read nor
// write: it holds the activity log and the session index, a derived copy of
// transcript text (M5.4). run appends its record from the parent process
// after the child exits, so the deny does not affect logging.
//
// It fails closed: a state dir that is not absolute is an error (exit 125),
// never a silently dropped deny. The dir is created (0700) before the
// profile is compiled, because bwrap can only hide a path that exists; a
// missing one could otherwise be created and planted by the child when its
// cwd or a write grant covers it.
func stateDeny(env Env) ([]string, error) {
	dir := paths.Resolve(env.Home, env.Environ).StateDir
	if !filepath.IsAbs(dir) {
		return nil, fmt.Errorf("state dir %q is not absolute; refusing to run without its sandbox deny", dir)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("state dir: %w", err)
	}
	return []string{dir}, nil
}

// toResolved expands variables and symlinks for the profile compiler. A
// write entry whose real path is, or lies under, a built-in deny path, or
// whose last element is a built-in deny name (**/.env), compared
// case-folded, is dropped with a warning ("write <p> ignored: under a protected path"): a
// symlink in the project or an override must never turn into a write allow
// on ~/.ssh and friends, whatever the backend's rule order does with it.
// droppedWrites lists the symbolic eff.Write entries that were dropped, so
// the caller can take them out of the effective policy.
//
// extraDeny are absolute paths treated like built-in deny paths (read and
// write denied, write entries under them dropped): watchdeck's state dir.
func toResolved(eff manifest.Effective, skillDirs []string, home, realCWD, realTMP string, extraDeny []string) (res profile.Resolved, dropped, droppedWrites []string, err error) {
	res = profile.Resolved{
		CWD: realCWD, Tmp: realTMP, Home: realPath(home),
		Network: eff.Network, ExecAny: eff.ExecAny, DenyAllWrites: true,
	}
	for _, d := range skillDirs {
		res.SkillDirs = append(res.SkillDirs, realPath(d))
	}
	expand := func(p string) []string {
		var outs []string
		if strings.Contains(p, "${SKILL_DIR}") {
			for _, d := range skillDirs {
				outs = append(outs, strings.Replace(p, "${SKILL_DIR}", realPath(d), 1))
			}
		} else {
			outs = []string{p}
		}
		for i, o := range outs {
			o = strings.Replace(o, "${CWD}", realCWD, 1)
			o = strings.Replace(o, "${TMP}", realTMP, 1)
			if o == "~" || strings.HasPrefix(o, "~/") {
				o = home + strings.TrimPrefix(o, "~")
			}
			outs[i] = resolveExisting(o)
		}
		return outs
	}
	var protected, protectedNames []string
	for _, d := range manifest.BuiltinDeny {
		if strings.Contains(d, "*") {
			// "**/.env": a write entry whose last element is the name
			if last, ok := strings.CutPrefix(d, "**/"); ok && !strings.ContainsAny(last, "*?[{") {
				protectedNames = append(protectedNames, last)
			}
			continue
		}
		protected = append(protected, expand(d)...)
	}
	var extra []string
	for _, d := range extraDeny {
		if !filepath.IsAbs(d) {
			return res, nil, nil, fmt.Errorf("deny path %q is not absolute", d)
		}
		x := resolveExisting(filepath.Clean(d))
		protected = append(protected, x)
		extra = append(extra, x)
	}
	seen := map[string]bool{}
	for _, w := range eff.Write {
		wDropped := false
		for _, x := range expand(w) {
			// Protected first: a second spelling of an already-dropped real
			// path must be dropped (and reported) too, not skipped as seen.
			if underAny(x, protected) || namedAny(x, protectedNames) {
				wDropped = true
				continue
			}
			if seen[x] {
				continue
			}
			seen[x] = true
			res.Write = append(res.Write, x)
		}
		if wDropped {
			// w may come from the project file: the warning is display
			// text, droppedWrites keeps the raw entry.
			dropped = append(dropped, "write "+manifest.DisplayPath(w)+" ignored: under a protected path")
			droppedWrites = append(droppedWrites, w)
		}
	}
	for _, d := range eff.Deny {
		res.DenyPaths = append(res.DenyPaths, expand(d)...)
	}
	for _, x := range extra {
		if !slices.Contains(res.DenyPaths, x) {
			res.DenyPaths = append(res.DenyPaths, x)
		}
	}
	for _, p := range eff.DenyPatterns {
		if strings.HasPrefix(p, "~/") {
			p = home + p[1:]
		}
		res.DenyPatterns = append(res.DenyPatterns, p)
	}
	if !eff.ExecAny {
		for _, e := range eff.Exec {
			res.ExecAllow = append(res.ExecAllow, realPath(e))
		}
		sort.Strings(res.ExecAllow)
	}
	return res, dropped, droppedWrites, nil
}

// removeEntry returns xs without s, keeping nil as nil.
func removeEntry(xs []string, s string) []string {
	if xs == nil {
		return nil
	}
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		if x != s {
			out = append(out, x)
		}
	}
	return out
}

// underAny reports whether p equals or lies under one of dirs (real paths),
// case-folded on every OS: on a case-insensitive filesystem (the macOS
// default) ~/.SSH is ~/.ssh, and on a case-sensitive one dropping a case
// variant of a protected path costs nothing.
func underAny(p string, dirs []string) bool {
	for _, d := range dirs {
		if manifest.UnderFold(p, d) {
			return true
		}
	}
	return false
}

// namedAny reports whether p's last element is one of names, case-folded
// (".ENV" is ".env").
func namedAny(p string, names []string) bool {
	base := filepath.Base(p)
	for _, n := range names {
		if strings.EqualFold(base, n) {
			return true
		}
	}
	return false
}

// realPath resolves symlinks when the path exists, else cleans it.
func realPath(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return filepath.Clean(p)
}

// resolveExisting follows symlinks on the longest existing prefix.
func resolveExisting(p string) string {
	p = filepath.Clean(p)
	rest := ""
	for {
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
}

// userTempDir is the real per-user temp dir. On macOS that is
// confstr(_CS_DARWIN_USER_TEMP_DIR) (/private/var/folders/<x>/<y>/T), which
// the Xcode python3 shim writes to regardless of TMPDIR; getconf exposes it.
func userTempDir(environ map[string]string) string {
	if runtime.GOOS == "darwin" {
		if out, err := exec.Command("/usr/bin/getconf", "DARWIN_USER_TEMP_DIR").Output(); err == nil {
			if d := strings.TrimRight(strings.TrimSpace(string(out)), "/"); d != "" {
				return realPath(d)
			}
		}
	}
	if t := environ["TMPDIR"]; t != "" {
		return realPath(strings.TrimRight(t, "/"))
	}
	return realPath(os.TempDir())
}
