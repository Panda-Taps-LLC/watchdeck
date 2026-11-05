package manifest

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/goccy/go-yaml"

	"github.com/Panda-Taps-LLC/watchdeck/internal/lazyre"
	"github.com/Panda-Taps-LLC/watchdeck/internal/safeio"

	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
)

// File names of the two override files. The user file lives under the
// watchdeck config dir (XDG_CONFIG_HOME/watchdeck by default); the
// project file lives at the project root.
const (
	UserOverridesFile    = "overrides.yaml"
	ProjectOverridesFile = "." + paths.BinaryName + ".yaml"
)

// CacheDirs are appended to Write by the `caches: true` override.
var CacheDirs = []string{"~/Library/Caches", "~/.cache", "~/.npm/_cacache"}

// Source says where an override block came from. The project file ships
// with a cloned repository, so it is untrusted and may only widen within the
// project's own sandbox (see Widen). The user file may widen anything.
type Source int

const (
	SourceProject Source = iota
	SourceUser
)

// String returns project | user.
func (s Source) String() string {
	switch s {
	case SourceProject:
		return "project"
	case SourceUser:
		return "user"
	}
	return fmt.Sprintf("Source(%d)", int(s))
}

// Override is one widening block from an overrides file. nil pointers and
// empty slices mean "not set". Relative write/read entries ("build",
// "./build") are stored as ${CWD}/build.
type Override struct {
	Network          *Network
	Write, Read, Env []string
	Caches           bool
	AutoAllow        *bool
}

// Overrides is a parsed overrides file: a defaults block that applies to
// every skill plus per-skill blocks. The key "*" under skills is accepted as
// a synonym for defaults.
type Overrides struct {
	Defaults Override
	Skills   map[string]Override
}

type rawOverrides struct {
	Version  *int                    `yaml:"version"`
	Defaults *rawOverride            `yaml:"defaults"`
	Skills   map[string]*rawOverride `yaml:"skills"`
}

// rawOverride.Network is a plain string (not *Network with its
// UnmarshalYAML): go-yaml re-formats the node for every custom unmarshaler,
// which made a file with many blocks quadratic to parse.
type rawOverride struct {
	Network   *string  `yaml:"network"`
	Write     []string `yaml:"write"`
	Read      []string `yaml:"read"`
	Env       []string `yaml:"env"`
	Caches    *bool    `yaml:"caches"`
	AutoAllow *bool    `yaml:"auto_allow"`
}

// ParseOverrides parses an overrides file strictly (unknown fields are
// errors, version must be 1 or 2). Paths are validated like manifest paths,
// relative entries are rooted at ${CWD}, no entry may grant a built-in deny
// path, env names must match the env regex, and skill keys must pass
// ValidSkillName.
//
// Errors name the field path and the rule, never the offending value: the
// project file ships with a cloned repository, and the error text reaches
// the hook's permission reason and the run's stderr, so a value echoed there
// could imitate watchdeck's own wording ("requested but not granted: …").
//
// A version 2 file (see ParsePolicyFile) is accepted too and projected onto
// the skill view: its defaults block and its skill subjects. Every other part
// of a v2 file is validated here as well, so a file this function accepts is
// one internal/policy accepts, but only skills are returned.
//
// The skill view includes the file's grant temporaries in force now
// (SkillOverrides).
func ParseOverrides(b []byte) (Overrides, error) { return parseOverrides(b, false) }

// parseOverrides is ParseOverrides; project refuses a temporary: list.
func parseOverrides(b []byte, project bool) (Overrides, error) {
	v, err := precheck(b)
	if err != nil {
		return Overrides{}, err
	}
	if v == 2 {
		f, err := parsePolicyV2(b)
		if err != nil {
			return Overrides{}, err
		}
		if project && len(f.Temporary) > 0 {
			return Overrides{}, errProjectTemporary()
		}
		return f.SkillOverrides(), nil
	}
	return parseOverridesV1(b)
}

// ParseProjectPolicyFile is ParsePolicyFile for a project's
// .watchdeck.yaml: a temporary: list is refused (only the user file may
// loosen anything for a while).
func ParseProjectPolicyFile(b []byte) (PolicyFile, error) {
	f, err := ParsePolicyFile(b)
	if err != nil {
		return PolicyFile{}, err
	}
	if len(f.Temporary) > 0 {
		return PolicyFile{}, errProjectTemporary()
	}
	return f, nil
}

// parseOverridesV1 is the version 1 parser (ParseOverrides before v2).
func parseOverridesV1(b []byte) (Overrides, error) {
	var raw rawOverrides
	if err := safeUnmarshal(b, &raw, yaml.Strict()); err != nil {
		return Overrides{}, fmt.Errorf("invalid overrides: %s", valueFreeYAMLErr(err))
	}
	if raw.Version == nil {
		return Overrides{}, errors.New("version: required (must be 1 or 2)")
	}
	if *raw.Version != 1 {
		return Overrides{}, fmt.Errorf("version: must be 1 or 2 (got %d)", *raw.Version)
	}
	var out Overrides
	var err error
	if out.Defaults, err = convertOverride("defaults", raw.Defaults); err != nil {
		return Overrides{}, err
	}
	if len(raw.Skills) > 0 {
		out.Skills = make(map[string]Override, len(raw.Skills))
		names := make([]string, 0, len(raw.Skills))
		for name := range raw.Skills {
			names = append(names, name)
		}
		sort.Strings(names) // deterministic error reporting
		for _, name := range names {
			if name == "" {
				return Overrides{}, errors.New("skills: empty skill name")
			}
			if !ValidSkillName(name) {
				return Overrides{}, errors.New("skills: invalid skill name (" + SkillNameRule + ")")
			}
			o, err := convertOverride("skills."+name, raw.Skills[name])
			if err != nil {
				return Overrides{}, err
			}
			out.Skills[name] = o
		}
	}
	return out, nil
}

func convertOverride(field string, r *rawOverride) (Override, error) {
	if r == nil {
		return Override{}, nil
	}
	o := Override{Env: r.Env, AutoAllow: r.AutoAllow}
	if r.Network != nil {
		n := NetNone
		if strings.TrimSpace(*r.Network) != "" {
			var err error
			if n, err = ParseNetwork(*r.Network); err != nil {
				return Override{}, errors.New(field + ".network: must be one of none, localhost, all")
			}
		}
		o.Network = &n
	}
	if r.Caches != nil {
		o.Caches = *r.Caches
	}
	var err error
	if o.Write, err = convertOverridePaths(field+".write", r.Write); err != nil {
		return Override{}, err
	}
	if o.Read, err = convertOverridePaths(field+".read", r.Read); err != nil {
		return Override{}, err
	}
	for i, e := range o.Env {
		if !envNameRe.MatchString(e) {
			return Override{}, fmt.Errorf("%s.env[%d]: invalid name (must match ^[A-Z_][A-Z0-9_]*$)", field, i)
		}
	}
	return o, nil
}

// convertOverridePaths roots relative entries at ${CWD}, then validates
// each entry like a manifest path and refuses built-in deny paths.
func convertOverridePaths(field string, ps []string) ([]string, error) {
	if ps == nil {
		return nil, nil
	}
	out := make([]string, 0, len(ps))
	for i, p := range ps {
		f := fmt.Sprintf("%s[%d]", field, i)
		p = rootRelative(p)
		if err := validatePath(f, p, false); err != nil {
			return nil, withoutValue(err, f)
		}
		if err := checkGrantsBuiltinDeny(f, p); err != nil {
			return nil, withoutValue(err, f)
		}
		out = append(out, p)
	}
	return out, nil
}

// withoutValue keeps a path error of the form `<field>: <rule>` (validatePath
// and checkGrantsBuiltinDeny name the field and the rule, never the value).
// Anything else, including a rule with a double quote in it, becomes
// `<field>: invalid path`, so a change in the helpers' wording can never
// start echoing the value.
func withoutValue(err error, field string) error {
	msg := err.Error()
	rule, ok := strings.CutPrefix(msg, field+": ")
	if ok && rule != "" && !strings.ContainsAny(rule, "\"|`") {
		return err
	}
	return errors.New(field + ": invalid path")
}

// yamlQuoted matches a double-quoted span as go-yaml prints a key or value.
var yamlQuoted = lazyre.Regexp{Expr: `"(?:[^"\\]|\\.)*"`}

// valueFreeYAMLErr renders a decode error without any text taken from the
// file, for override files and manifests alike. go-yaml quotes the offending
// key or value (`[4:5] unknown field "<key>"`, `mapping key "<key>" already
// defined`); each quoted span becomes "…", keeping the position and the kind
// of error. Anything left after a stray quote, a '|' or a backquote is cut,
// in case an unquoted token is ever echoed.
func valueFreeYAMLErr(err error) string {
	msg := yamlQuoted.ReplaceAllString(yamlErr(err), "…")
	if i := strings.IndexAny(msg, "\"|`'"); i >= 0 {
		msg = msg[:i]
	}
	msg = strings.TrimSpace(msg)
	msg = strings.TrimSpace(strings.TrimSuffix(msg, "(got"))
	if msg == "" {
		return "malformed YAML"
	}
	return msg
}

// rootRelative turns a relative entry ("build", "./build", ".") into a
// ${CWD}-rooted one. Absolute, ~ and ${VAR} entries are returned unchanged.
func rootRelative(p string) string {
	t := strings.TrimSpace(p)
	if t == "" || strings.HasPrefix(t, "/") || strings.HasPrefix(t, "~") || strings.HasPrefix(t, "${") {
		return p
	}
	for strings.HasPrefix(t, "./") {
		t = strings.TrimPrefix(t, "./")
	}
	if t == "" || t == "." {
		return "${CWD}"
	}
	return "${CWD}/" + t
}

// LoadOverrides reads <userCfgDir>/overrides.yaml and
// <projectDir>/.watchdeck.yaml. A missing file (or an empty dir argument)
// yields empty Overrides; a malformed file is an error naming the path.
func LoadOverrides(userCfgDir, projectDir string) (user, project Overrides, err error) {
	if userCfgDir != "" {
		user, err = loadOverridesFile(filepath.Join(userCfgDir, UserOverridesFile), "")
		if err != nil {
			return Overrides{}, Overrides{}, err
		}
	}
	if projectDir != "" {
		project, err = loadOverridesFile(filepath.Join(projectDir, ProjectOverridesFile), projectDir)
		if err != nil {
			return Overrides{}, Overrides{}, err
		}
	}
	return user, project, nil
}

// loadOverridesFile reads one file; projectRoot != "" marks the project
// file (ReadProjectPolicyFile).
func loadOverridesFile(path, projectRoot string) (Overrides, error) {
	var b []byte
	var err error
	if projectRoot != "" {
		b, err = ReadProjectPolicyFile(path, projectRoot)
	} else {
		b, err = ReadPolicyFile(path)
	}
	if errors.Is(err, fs.ErrNotExist) {
		return Overrides{}, nil
	}
	// The path names the project directory, which comes from the cloned
	// repository: it is display text in these errors (they reach the hook's
	// permission reason and the run's stderr). A *fs.PathError would repeat
	// the raw path, so only its cause is kept.
	if err != nil {
		var pe *fs.PathError
		if errors.As(err, &pe) {
			err = pe.Err
		}
		return Overrides{}, fmt.Errorf("%s: %w", DisplayPath(path), err)
	}
	o, err := parseOverrides(b, projectRoot != "")
	if err != nil {
		return Overrides{}, fmt.Errorf("%s: %w", DisplayPath(path), err)
	}
	return o, nil
}

// ReadPolicyFile reads the user overrides file (trusted; symlinks are
// followed) without ever blocking (safeio.ReadRegular): anything but a
// regular file (a FIFO, /dev/tty, a directory) is an error, and so is a
// file over 1 MiB.
func ReadPolicyFile(path string) ([]byte, error) {
	return readRegular(path, false)
}

// ReadProjectPolicyFile reads a project's .watchdeck.yaml (untrusted, it
// ships with a cloned repository) like ReadPolicyFile, capped at 64 KiB,
// and also refuses a
// file that is, or sits behind, a symlink resolving outside root (the
// project directory). The resolved file is opened O_NOFOLLOW. Errors carry
// no path or value from the repository.
func ReadProjectPolicyFile(path, root string) ([]byte, error) {
	if _, err := os.Lstat(path); err != nil {
		return nil, err
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, err
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(real, realRoot+string(filepath.Separator)) {
		return nil, errors.New("resolves outside the project (symlink)")
	}
	return readRegular(real, true)
}

func readRegular(path string, nofollow bool) ([]byte, error) {
	max, msg := int64(safeio.MaxUser), "file larger than 1 MiB"
	if nofollow { // the project file
		max, msg = safeio.MaxUntrusted, "file larger than 64 KiB"
	}
	b, err := safeio.ReadRegular(path, max, nofollow)
	if errors.Is(err, safeio.ErrTooLarge) {
		return nil, errors.New(msg)
	}
	return b, err
}

// projectSandbox is where an untrusted project override may add paths.
var projectSandbox = []string{"${CWD}", "${TMP}"}

const projectIgnored = "project override ignored: "

// requestIgnored prefixes a skill manifest path dropped by the real-path
// re-check in ResolveProjectScoped.
const requestIgnored = "manifest path ignored: "

// displayPathMax caps a path echoed in display text.
const displayPathMax = 120

// DisplayPath renders a path that may come from the untrusted project file
// (or the real path it resolves to) as display text: the "project override
// ignored" messages, Effective.Summary and the runner's "under a protected
// path" warning. Those strings reach the hook's permission reason, the
// decision record, the run trailer and record, and the dashboard, so a path
// such as "/x | requested but not granted: network: all" must not read as
// one of watchdeck's own clauses. Non-printable runes (control characters,
// newlines, non-ASCII spaces, bidi overrides, invalid UTF-8) become '?', '|'
// becomes '¦', leading '-' are stripped, a result over displayPathMax bytes
// is cut from the left (a leading '…' and the tail, so the file or directory
// name survives), and it is double-quoted (strconv.Quote) only when it
// contains a space. Never use the result as a policy value.
func DisplayPath(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '|':
			b.WriteRune('¦')
		case r == utf8.RuneError || !unicode.IsPrint(r):
			// IsPrint admits the ASCII space and no other whitespace.
			b.WriteByte('?')
		default:
			b.WriteRune(r)
		}
	}
	out := strings.TrimLeft(b.String(), "-")
	if len(out) > displayPathMax {
		// Keep the tail: the file or directory name is what a reader needs.
		start := len(out) - (displayPathMax - len("…"))
		for start < len(out) && !utf8.RuneStart(out[start]) {
			start++
		}
		out = "…" + out[start:]
	}
	if strings.ContainsRune(out, ' ') {
		out = strconv.Quote(out)
	}
	return out
}

// withinProject reports whether a normalised path is ${CWD}, ${TMP} or under one of them.
func withinProject(np string) bool {
	for _, root := range projectSandbox {
		if np == root || strings.HasPrefix(np, root+"/") {
			return true
		}
	}
	return false
}

// Widen applies one override block to a grant. Overrides only widen:
// network takes the max, write/env entries are appended (deduped after
// normalisation), caches adds CacheDirs to Write, auto_allow is set when
// given. Read is appended only when the base restricts reads; a nil Read
// already means everything except deny and stays nil.
//
// With SourceProject the block is clipped: only write/read paths under
// ${CWD} or ${TMP} and network up to localhost are honoured. Everything else
// is dropped and returned in ignored as "project override ignored: …".
func Widen(base Effective, o Override, src Source) (Effective, []string) {
	out := base.clone()
	var ignored []string
	skip := func(what string) {
		ignored = append(ignored, projectIgnored+what)
	}
	if o.Network != nil {
		if src == SourceProject && *o.Network > NetLocalhost {
			skip("network: " + o.Network.String() + " (only the user override can grant this)")
		} else {
			out.Network = maxNetwork(out.Network, *o.Network)
		}
	}
	for _, p := range o.Write {
		np := normPath(rootRelative(p))
		if src == SourceProject && !withinProject(np) {
			skip("write: " + DisplayPath(np) + " (outside ${CWD})")
			continue
		}
		if src == SourceProject {
			out.ProjectScoped = appendUnique(out.ProjectScoped, np)
		}
		out.Write = appendUnique(out.Write, np)
	}
	if o.Caches {
		if src == SourceProject {
			skip("caches")
		} else {
			for _, c := range CacheDirs {
				out.Write = appendUnique(out.Write, c)
			}
		}
	}
	for _, p := range o.Read {
		np := normPath(rootRelative(p))
		if src == SourceProject && !withinProject(np) {
			skip("read: " + DisplayPath(np) + " (outside ${CWD})")
			continue
		}
		if src == SourceProject {
			out.ProjectScoped = appendUnique(out.ProjectScoped, np)
		}
		if out.Read != nil {
			out.Read = appendUnique(out.Read, np)
		}
	}
	for _, e := range o.Env {
		if src == SourceProject {
			skip("env: " + e)
			continue
		}
		out.Env = appendUnique(out.Env, e)
	}
	if o.AutoAllow != nil {
		if src == SourceProject {
			skip("auto_allow")
		} else {
			out.AutoAllow = *o.AutoAllow
		}
	}
	return out, ignored
}

// Grant resolves the grant for one skill:
// Default() → project.Defaults → project.Skills["*"] → project.Skills[skill]
// → user.Defaults → user.Skills["*"] → user.Skills[skill].
// The project layer is applied with SourceProject (clipped, see Widen); the
// user layer with SourceUser. Every step only widens, so order matters only
// for AutoAllow, where the most specific per-skill user block wins. The
// returned list names every project entry that was ignored.
func Grant(skill string, user, project Overrides) (Effective, []string) {
	eff := Default()
	var ignored []string
	apply := func(o Override, src Source) {
		var ig []string
		eff, ig = Widen(eff, o, src)
		ignored = append(ignored, ig...)
	}
	for _, layer := range []struct {
		o   Overrides
		src Source
	}{{project, SourceProject}, {user, SourceUser}} {
		apply(layer.o.Defaults, layer.src)
		if star, ok := layer.o.Skills["*"]; ok {
			apply(star, layer.src)
		}
		if skill != "*" {
			if s, ok := layer.o.Skills[skill]; ok {
				apply(s, layer.src)
			}
		}
	}
	return eff, ignored
}

// ResolveProjectScoped re-checks every project-sourced Read/Write entry, and
// every entry a skill manifest narrowed to below ${CWD} or ${TMP}
// (RequestScoped), on real paths. realCWD and realTMP must already be
// symlink-resolved. An entry whose resolved path (following symlinks,
// including a symlinked ancestor of a not-yet-existing path) is not under
// realCWD or realTMP is removed from Read and Write and reported. The lexical
// checks in Widen and Clip are not enough: a repository can contain
// `build -> /somewhere/else`.
func ResolveProjectScoped(eff Effective, realCWD, realTMP string) (Effective, []string) {
	out := eff.clone()
	if len(out.ProjectScoped) == 0 && len(out.RequestScoped) == 0 {
		return out, nil
	}
	roots := []string{filepath.Clean(realCWD), filepath.Clean(realTMP)}
	var ignored []string
	check := func(entry, prefix string) {
		expanded := entry
		expanded = strings.Replace(expanded, "${CWD}", roots[0], 1)
		expanded = strings.Replace(expanded, "${TMP}", roots[1], 1)
		real := resolveExisting(expanded)
		for _, r := range roots {
			if real == r || strings.HasPrefix(real, r+"/") {
				return
			}
		}
		out.Write = removeString(out.Write, entry)
		out.Read = removeString(out.Read, entry)
		ignored = append(ignored, prefix+DisplayPath(entry)+" (resolves to "+DisplayPath(real)+", outside the project)")
	}
	for _, entry := range out.ProjectScoped {
		check(entry, projectIgnored)
	}
	for _, entry := range out.RequestScoped {
		if !contains(out.ProjectScoped, entry) {
			check(entry, requestIgnored)
		}
	}
	return out, ignored
}

// resolveExisting follows symlinks on the longest existing prefix of p and
// re-joins the rest, so a path that does not exist yet still resolves through
// any symlinked ancestor.
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

func removeString(xs []string, s string) []string {
	if xs == nil {
		return nil
	}
	out := xs[:0:0]
	for _, x := range xs {
		if x != s {
			out = append(out, x)
		}
	}
	return out
}
