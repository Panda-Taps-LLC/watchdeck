package manifest

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/bmatcuk/doublestar/v4"

	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
)

// Edit is one change to a skill's block in the user overrides file. Every
// field is optional; Empty reports an edit that does nothing. The CLI
// (`watchdeck allow`) and the dashboard both build an Edit and go through
// policy.Apply (which applies it with Apply below) and policy.Save, so the
// file has one writer path.
type Edit struct {
	Network               *Network // set network (NetNone revokes; grants only widen, so none == default)
	ClearNetwork          bool     // remove the network key
	AddWrite, RemoveWrite []string // write paths; relative entries are rooted at ${CWD}
	AddRead, RemoveRead   []string // accepted by the API, not exposed in the UI or CLI
	AddEnv, RemoveEnv     []string // same
	Caches                *bool    // caches: true | false
	AutoAllow             *bool    // auto_allow: true | false
	ClearAutoAllow        bool     // remove the auto_allow key
	Reset                 bool     // delete the whole block for this skill (applied before the other fields)

	// Home, when set, is the user's real home directory. Apply then also
	// refuses a write/read entry that reaches a built-in deny path through
	// its absolute spelling (/Users/me/.ssh) or a symlink, not only through
	// ~/.ssh. Not an edit field: Empty ignores it. "" skips the check.
	Home string
}

// Empty reports whether the edit changes nothing.
func (e Edit) Empty() bool {
	return e.Network == nil && !e.ClearNetwork &&
		len(e.AddWrite) == 0 && len(e.RemoveWrite) == 0 &&
		len(e.AddRead) == 0 && len(e.RemoveRead) == 0 &&
		len(e.AddEnv) == 0 && len(e.RemoveEnv) == 0 &&
		e.Caches == nil && e.AutoAllow == nil && !e.ClearAutoAllow && !e.Reset
}

// MaxSkillNameLen bounds a skill name in an overrides file or on the CLI.
const MaxSkillNameLen = 128

// SkillNameRule describes ValidSkillName for error messages.
const SkillNameRule = `letters, digits, '.', '_', '-' (not first), at most 128 characters, not "." or ".."; or "*"`

// ValidSkillName reports whether name is "*" or matches
// ^[A-Za-z0-9._][A-Za-z0-9._-]{0,127}$ and is not "." or "..". Skill names
// end up on shell lines (`watchdeck allow <name> ...`), in YAML keys and in
// the hook's reason text, so anything else is refused before it reaches a
// file or a command. The rule matches the in-session mod's.
func ValidSkillName(name string) bool {
	if name == "*" {
		return true
	}
	// A leading "-" would be read as a flag by `watchdeck allow`.
	if name == "" || len(name) > MaxSkillNameLen || name[0] == '-' || name == "." || name == ".." {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}

// Apply returns o with e applied to the block for skill ("*" edits Defaults).
// The input is not modified. Reset empties the block first; then network,
// write, read, env, caches and auto_allow are set or removed; a block left
// with nothing in it is deleted. Removing an absent entry is a no-op and
// changed stays false. The result is validated by rendering it and parsing
// it back strictly, so a built-in deny path, a bad env name or an empty path
// is an error and nothing changes. An invalid skill name is an error too.
func Apply(o Overrides, skill string, e Edit) (out Overrides, changed bool, err error) {
	if !ValidSkillName(skill) {
		return o, false, fmt.Errorf("invalid skill name %q (%s)", skill, SkillNameRule)
	}
	if e.Network != nil && e.ClearNetwork {
		return o, false, errors.New("edit: network and clearNetwork are exclusive")
	}
	if e.AutoAllow != nil && e.ClearAutoAllow {
		return o, false, errors.New("edit: autoAllow and clearAutoAllow are exclusive")
	}
	out = o.clone()
	var blk Override
	existed := false
	if skill == "*" {
		blk = out.Defaults
		existed = !emptyOverride(blk)
	} else {
		blk, existed = out.Skills[skill]
	}

	if e.Reset {
		if existed {
			changed = true
		}
		blk = Override{}
	}
	if e.ClearNetwork && blk.Network != nil {
		blk.Network = nil
		changed = true
	}
	if e.Network != nil && (blk.Network == nil || *blk.Network != *e.Network) {
		n := *e.Network
		blk.Network = &n
		changed = true
	}
	blk.Write, changed = addPaths(blk.Write, e.AddWrite, changed)
	blk.Write, changed = removePaths(blk.Write, e.RemoveWrite, changed)
	blk.Read, changed = addPaths(blk.Read, e.AddRead, changed)
	blk.Read, changed = removePaths(blk.Read, e.RemoveRead, changed)
	for _, name := range e.AddEnv {
		if !contains(blk.Env, name) {
			blk.Env = append(blk.Env, name)
			changed = true
		}
	}
	for _, name := range e.RemoveEnv {
		if contains(blk.Env, name) {
			blk.Env = removeString(blk.Env, name)
			changed = true
		}
	}
	if len(blk.Env) == 0 {
		blk.Env = nil
	}
	if e.Caches != nil && blk.Caches != *e.Caches {
		blk.Caches = *e.Caches
		changed = true
	}
	if e.ClearAutoAllow && blk.AutoAllow != nil {
		blk.AutoAllow = nil
		changed = true
	}
	if e.AutoAllow != nil && (blk.AutoAllow == nil || *blk.AutoAllow != *e.AutoAllow) {
		v := *e.AutoAllow
		blk.AutoAllow = &v
		changed = true
	}
	if !changed {
		return o, false, nil
	}

	if skill == "*" {
		out.Defaults = blk
	} else if emptyOverride(blk) {
		delete(out.Skills, skill)
	} else {
		if out.Skills == nil {
			out.Skills = map[string]Override{}
		}
		out.Skills[skill] = blk
	}
	if len(out.Skills) == 0 {
		out.Skills = nil
	}
	if _, perr := ParseOverrides([]byte(RenderOverrides(out))); perr != nil {
		return o, false, perr
	}
	if e.Home != "" {
		field := "skills." + skill
		if skill == "*" {
			field = "defaults"
		}
		for _, l := range []struct {
			key   string
			paths []string
		}{{"write", blk.Write}, {"read", blk.Read}} {
			for i, p := range l.paths {
				if err := checkGrantsBuiltinDenyAt(fmt.Sprintf("%s.%s[%d]", field, l.key, i), p, e.Home); err != nil {
					return o, false, err
				}
			}
		}
	}
	return out, true, nil
}

// checkGrantsBuiltinDenyAt is checkGrantsBuiltinDeny on real paths: p is
// expanded against home (~ and ${HOME}; absolute paths as given; other
// variables are left to run's own check), cleaned, and also resolved through
// symlinks on its longest existing prefix. The deny paths are expanded and
// resolved the same way (a home under /var is /private/var on macOS). The
// message matches the symbolic check's, so `allow x --write /Users/me/.ssh`
// and `allow x --write ~/.ssh` read the same.
//
// Every comparison is case-folded, on every OS: on a case-insensitive
// filesystem (the macOS default) ~/.SSH and ~/.Ssh/x are ~/.ssh, and a .ENV
// is a .env. Refusing a case variant on a case-sensitive filesystem only
// refuses a path that looks like a credential store.
func checkGrantsBuiltinDenyAt(field, p, home string) error {
	// "**/.env" and friends: any entry whose last element is the name, in any
	// spelling (${CWD}/.ENV included, which has no real path here).
	for _, d := range BuiltinDeny {
		if last, ok := strings.CutPrefix(d, "**/"); ok && !isGlob(last) && strings.EqualFold(path.Base(normPath(p)), last) {
			return fmt.Errorf("%s: cannot grant built-in deny pattern %s", field, d)
		}
	}
	abs := ""
	switch {
	case p == "~" || strings.HasPrefix(p, "~/"):
		abs = home + p[1:]
	case p == "${HOME}" || strings.HasPrefix(p, "${HOME}/"):
		abs = home + strings.TrimPrefix(p, "${HOME}")
	case strings.HasPrefix(p, "/"):
		abs = p
	default:
		return nil
	}
	cands := []string{filepath.Clean(abs), resolveExisting(abs)}
	for _, d := range BuiltinDeny {
		if isGlob(d) {
			for _, c := range cands {
				// "**/.env": any path whose last element is .env
				last, ok := strings.CutPrefix(d, "**/")
				hit := ok && !isGlob(last) && strings.EqualFold(filepath.Base(c), last)
				if !hit {
					hit, _ = doublestar.Match(d, strings.TrimPrefix(c, "/"))
				}
				if hit {
					return fmt.Errorf("%s: cannot grant built-in deny pattern %s", field, d)
				}
			}
			continue
		}
		dAbs := home + strings.TrimPrefix(d, "~")
		for _, root := range []string{filepath.Clean(dAbs), resolveExisting(dAbs)} {
			for _, c := range cands {
				if UnderFold(c, root) {
					return fmt.Errorf("%s: cannot grant built-in deny path %s", field, d)
				}
			}
		}
	}
	return nil
}

// addPaths appends each new path (rooted at ${CWD} when relative) unless an
// equal path, compared after normalisation, is already present.
func addPaths(list, add []string, changed bool) ([]string, bool) {
	for _, p := range add {
		p = rootRelative(p)
		if !containsPath(list, p) {
			list = append(list, p)
			changed = true
		}
	}
	return list, changed
}

// removePaths drops every entry equal to one of rm after normalisation. An
// emptied list becomes nil.
func removePaths(list, rm []string, changed bool) ([]string, bool) {
	for _, p := range rm {
		n := normPath(rootRelative(p))
		kept := list[:0:0]
		for _, x := range list {
			if normPath(x) == n {
				changed = true
				continue
			}
			kept = append(kept, x)
		}
		list = kept
	}
	if len(list) == 0 {
		return nil, changed
	}
	return list, changed
}

// clone deep-copies an Overrides.
func (o Overrides) clone() Overrides {
	out := Overrides{Defaults: o.Defaults.clone()}
	if o.Skills != nil {
		out.Skills = make(map[string]Override, len(o.Skills))
		for k, v := range o.Skills {
			out.Skills[k] = v.clone()
		}
	}
	return out
}

func (o Override) clone() Override {
	o.Write = cloneStrings(o.Write)
	o.Read = cloneStrings(o.Read)
	o.Env = cloneStrings(o.Env)
	if o.Network != nil {
		n := *o.Network
		o.Network = &n
	}
	if o.AutoAllow != nil {
		v := *o.AutoAllow
		o.AutoAllow = &v
	}
	return o
}

// emptyOverride reports whether a block has nothing set.
func emptyOverride(o Override) bool {
	return o.Network == nil && len(o.Write) == 0 && len(o.Read) == 0 && len(o.Env) == 0 && !o.Caches && o.AutoAllow == nil
}

// RenderOverrides writes an Overrides as the YAML `watchdeck allow`
// produces: a header comment, version: 1, a defaults block when it has
// content, then skills sorted by name with quoted names. RenderOverrides and
// ParseOverrides round-trip byte for byte.
func RenderOverrides(o Overrides) string {
	var b strings.Builder
	b.WriteString("# watchdeck user overrides. Edited by `watchdeck allow`; hand edits are fine.\n")
	b.WriteString("version: 1\n")
	if !emptyOverride(o.Defaults) {
		b.WriteString("defaults:\n")
		renderOverride(&b, o.Defaults)
	}
	if len(o.Skills) > 0 {
		names := make([]string, 0, len(o.Skills))
		for n := range o.Skills {
			names = append(names, n)
		}
		sort.Strings(names)
		b.WriteString("skills:\n")
		for _, n := range names {
			fmt.Fprintf(&b, "  %q:\n", n)
			renderOverride(&b, o.Skills[n])
		}
	}
	return b.String()
}

func renderOverride(b *strings.Builder, o Override) {
	indent := "    "
	if o.Network != nil {
		fmt.Fprintf(b, "%snetwork: %s\n", indent, o.Network.String())
	}
	if len(o.Write) > 0 {
		fmt.Fprintf(b, "%swrite: [%s]\n", indent, quoteList(dedupe(o.Write)))
	}
	if len(o.Read) > 0 {
		fmt.Fprintf(b, "%sread: [%s]\n", indent, quoteList(dedupe(o.Read)))
	}
	if len(o.Env) > 0 {
		fmt.Fprintf(b, "%senv: [%s]\n", indent, quoteList(dedupe(o.Env)))
	}
	if o.Caches {
		fmt.Fprintf(b, "%scaches: true\n", indent)
	}
	if o.AutoAllow != nil {
		fmt.Fprintf(b, "%sauto_allow: %v\n", indent, *o.AutoAllow)
	}
}

func quoteList(xs []string) string {
	q := make([]string, len(xs))
	for i, x := range xs {
		q[i] = fmt.Sprintf("%q", x)
	}
	return strings.Join(q, ", ")
}

// SaveOverrides writes o to path atomically: render, parse the text back
// strictly (an invalid file is never written), create the directory, write a
// temp file beside the target with mode 0600, fsync, then rename over path.
// A reader never sees a partial file and a failed write leaves the old one.
//
// Legacy, skill-only: it writes version 1, so saving over a v2 file this way
// drops every non-skill subject, pack and rule. The CLI and the dashboard
// write through policy.Apply + policy.Save; use those.
func SaveOverrides(path string, o Overrides) error {
	text := RenderOverrides(o)
	if _, err := ParseOverrides([]byte(text)); err != nil {
		return fmt.Errorf("refusing to write an invalid overrides file: %w", err)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".overrides-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	fail := func(err error) error {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if _, err := tmp.WriteString(text); err != nil {
		return fail(err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		os.Remove(name)
		return err
	}
	return nil
}

// LoadOverridesFile reads and strictly parses one overrides file: the
// exported form of loadOverridesFile with an exists flag. exists is false
// (with no error) when the file is absent; a malformed or unreadable file is
// an error naming the path.
func LoadOverridesFile(path string) (o Overrides, exists bool, err error) {
	if _, serr := os.Stat(path); errors.Is(serr, fs.ErrNotExist) {
		return Overrides{}, false, nil
	}
	o, err = loadOverridesFile(path, "")
	if err != nil {
		return Overrides{}, true, err
	}
	return o, true, nil
}

// LoadProjectOverridesFile is LoadOverridesFile for a project's
// .watchdeck.yaml: read with ReadProjectPolicyFile, so the file must be
// regular and resolve inside its own directory (filepath.Dir(path)).
func LoadProjectOverridesFile(path string) (o Overrides, exists bool, err error) {
	if _, serr := os.Lstat(path); errors.Is(serr, fs.ErrNotExist) {
		return Overrides{}, false, nil
	}
	o, err = loadOverridesFile(path, filepath.Dir(path))
	if err != nil {
		return Overrides{}, true, err
	}
	return o, true, nil
}

// AllowCommand renders e as the one `watchdeck allow` line that applies it,
// flags in the order network, --write, --remove-write, --caches/--no-caches,
// --auto/--no-auto, --reset; "*" renders as '*'. ok is false when the edit
// has no CLI form: ClearNetwork, ClearAutoAllow, read or env changes (edit
// overrides.yaml by hand), an empty edit, or an invalid skill name.
func AllowCommand(skill string, e Edit) (cmd string, ok bool) {
	if !ValidSkillName(skill) || e.Empty() {
		return "", false
	}
	if e.ClearNetwork || e.ClearAutoAllow || len(e.AddRead)+len(e.RemoveRead)+len(e.AddEnv)+len(e.RemoveEnv) > 0 {
		return "", false
	}
	args := []string{paths.BinaryName, "allow", shellArg(skill)}
	if e.Network != nil {
		args = append(args, "--network", e.Network.String())
	}
	for _, p := range e.AddWrite {
		args = append(args, "--write", shellArg(p))
	}
	for _, p := range e.RemoveWrite {
		args = append(args, "--remove-write", shellArg(p))
	}
	if e.Caches != nil {
		if *e.Caches {
			args = append(args, "--caches")
		} else {
			args = append(args, "--no-caches")
		}
	}
	if e.AutoAllow != nil {
		if *e.AutoAllow {
			args = append(args, "--auto")
		} else {
			args = append(args, "--no-auto")
		}
	}
	if e.Reset {
		args = append(args, "--reset")
	}
	return strings.Join(args, " "), true
}

// shellArg single-quotes s unless every byte is shell-neutral, so "*",
// "~/x", "${CWD}/build" and paths with spaces survive a POSIX shell intact.
func shellArg(s string) string {
	safe := s != ""
	for i := 0; i < len(s) && safe; i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.', c == '_', c == '-', c == '/', c == ':', c == '@', c == '%', c == '+', c == ',', c == '=':
		default:
			safe = false
		}
	}
	if safe {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
