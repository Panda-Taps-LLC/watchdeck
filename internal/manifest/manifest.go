package manifest

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/goccy/go-yaml"

	"github.com/Panda-Taps-LLC/watchdeck/internal/lazyre"
	"github.com/Panda-Taps-LLC/watchdeck/internal/safeio"
)

// Network is the network policy. Ordered so that a larger value is wider.
type Network int

const (
	NetNone Network = iota
	NetLocalhost
	NetAll
)

// String returns none | localhost | all.
func (n Network) String() string {
	switch n {
	case NetNone:
		return "none"
	case NetLocalhost:
		return "localhost"
	case NetAll:
		return "all"
	}
	return fmt.Sprintf("Network(%d)", int(n))
}

// ParseNetwork parses "none", "localhost" or "all".
func ParseNetwork(s string) (Network, error) {
	switch strings.TrimSpace(s) {
	case "none":
		return NetNone, nil
	case "localhost":
		return NetLocalhost, nil
	case "all":
		return NetAll, nil
	}
	return NetNone, errors.New("network: must be one of none, localhost, all")
}

// UnmarshalYAML implements yaml.BytesUnmarshaler so `network:` is checked
// against the enum while decoding. An empty value means none.
func (n *Network) UnmarshalYAML(b []byte) error {
	var s string
	if err := yaml.Unmarshal(b, &s); err != nil {
		return errors.New("network: must be one of none, localhost, all")
	}
	if strings.TrimSpace(s) == "" {
		*n = NetNone
		return nil
	}
	v, err := ParseNetwork(s)
	if err != nil {
		return err
	}
	*n = v
	return nil
}

// Manifest is a skill's PERMISSIONS.yaml: a REQUEST, not a grant. Omitted
// fields are nil (or ExecAny true) and inherit the grant in Clip.
type Manifest struct {
	Version    int
	Scripts    []string
	Filesystem struct{ Read, Write, Deny []string }
	Network    Network
	ExecAny    bool
	Exec       []string // exec: any | [paths]
	Env        []string
	Tools      []string
	Notes      string
}

// BuiltinDeny is always denied, whatever any manifest or override says. The
// ** entry is a pattern; the rest are paths.
var BuiltinDeny = []string{"~/.ssh", "~/.aws", "~/.gnupg", "~/.claude", "~/.config/gcloud", "~/.netrc", "~/.docker/config.json", "**/.env"}

var envNameRe = lazyre.Regexp{Expr: `^[A-Z_][A-Z0-9_]*$`}

// rawManifest is the strict YAML shape; it is converted into Manifest.
type rawManifest struct {
	Version    *int     `yaml:"version"`
	Scripts    []string `yaml:"scripts"`
	Filesystem struct {
		Read  []string `yaml:"read"`
		Write []string `yaml:"write"`
		Deny  []string `yaml:"deny"`
	} `yaml:"filesystem"`
	Network *Network  `yaml:"network"`
	Exec    *execSpec `yaml:"exec"`
	Env     []string  `yaml:"env"`
	Tools   []string  `yaml:"tools"`
	Notes   string    `yaml:"notes"`
}

// execSpec decodes `exec: any` or `exec: [paths]`.
type execSpec struct {
	any   bool
	paths []string
}

// UnmarshalYAML implements yaml.BytesUnmarshaler. The decoder hands over the
// YAML text of the node, so it is re-decoded as a string, then as a list.
func (e *execSpec) UnmarshalYAML(b []byte) error {
	var s string
	if err := yaml.Unmarshal(b, &s); err == nil {
		if s == "any" {
			e.any = true
			e.paths = nil
			return nil
		}
		return errors.New("exec: must be any or a list of absolute paths")
	}
	var list []string
	if err := yaml.Unmarshal(b, &list); err == nil {
		if list == nil {
			list = []string{}
		}
		e.any = false
		e.paths = list
		return nil
	}
	return errors.New("exec: must be any or a list of absolute paths")
}

// Parse reads and parses a PERMISSIONS.yaml. Errors carry the path, shown
// through DisplayPath: the skill's directory name comes from whoever ships
// the skill, and the error reaches the hook's permission reason and run's
// stderr. A *fs.PathError would repeat the raw path, so only its cause is
// kept.
func Parse(path string) (Manifest, error) {
	b, err := safeio.ReadRegular(path, safeio.MaxUntrusted, false)
	if errors.Is(err, safeio.ErrTooLarge) {
		err = errors.New("file larger than 64 KiB")
	}
	if err != nil {
		var pe *fs.PathError
		if errors.As(err, &pe) {
			err = pe.Err
		}
		return Manifest{}, fmt.Errorf("%s: %w", DisplayPath(path), err)
	}
	m, err := ParseBytes(b)
	if err != nil {
		return Manifest{}, fmt.Errorf("%s: %w", DisplayPath(path), err)
	}
	return m, nil
}

// ParseBytes parses a manifest strictly: unknown fields (at any level) are
// errors, version must be 1, duplicate keys are errors. The result is also
// run through Validate, so a manifest that parses is one `run` may use.
//
// Text over 64 KiB, or nested deeper than safeio.CheckYAML allows, is
// refused before go-yaml sees it.
func ParseBytes(b []byte) (Manifest, error) {
	if len(b) > safeio.MaxUntrusted {
		return Manifest{}, errors.New("file larger than 64 KiB")
	}
	if err := safeio.CheckYAML(b); err != nil {
		return Manifest{}, err
	}
	var raw rawManifest
	if err := safeUnmarshal(b, &raw, yaml.Strict()); err != nil {
		return Manifest{}, fmt.Errorf("invalid manifest: %s", valueFreeYAMLErr(err))
	}
	if raw.Version == nil {
		return Manifest{}, errors.New("version: required (must be 1)")
	}
	if *raw.Version != 1 {
		return Manifest{}, fmt.Errorf("version: must be 1 (got %d)", *raw.Version)
	}
	m := Manifest{
		Version: 1,
		Scripts: raw.Scripts,
		Env:     raw.Env,
		Tools:   raw.Tools,
		Notes:   raw.Notes,
	}
	m.Filesystem.Read = raw.Filesystem.Read
	m.Filesystem.Write = raw.Filesystem.Write
	m.Filesystem.Deny = raw.Filesystem.Deny
	if raw.Network != nil {
		m.Network = *raw.Network
	}
	if raw.Exec == nil {
		m.ExecAny = true
	} else {
		m.ExecAny = raw.Exec.any
		m.Exec = raw.Exec.paths
	}
	if err := Validate(m); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

// yamlErr renders a go-yaml error as a single line without the source excerpt.
func yamlErr(err error) string {
	msg := yaml.FormatError(err, false, false)
	if i := strings.IndexByte(msg, '\n'); i >= 0 {
		msg = msg[:i]
	}
	return strings.TrimSpace(msg)
}

// Validate checks a Manifest built by ParseBytes or by hand: version is 1,
// script globs parse and are relative, network is in the enum, exec paths are
// absolute, env names match ^[A-Z_][A-Z0-9_]*$, filesystem entries are
// absolute or variable-rooted, no read/write entry touches a built-in deny
// path (equal, below, or above it), and a deny list, when present, still
// contains every built-in entry.
func Validate(m Manifest) error {
	if m.Version != 1 {
		return fmt.Errorf("version: must be 1 (got %d)", m.Version)
	}
	for i, g := range m.Scripts {
		field := fmt.Sprintf("scripts[%d]", i)
		if strings.TrimSpace(g) == "" {
			return fmt.Errorf("%s: empty glob", field)
		}
		if strings.HasPrefix(g, "/") {
			return fmt.Errorf("%s: must be relative to the skill directory", field)
		}
		if !doublestar.ValidatePattern(g) {
			return fmt.Errorf("%s: invalid glob", field)
		}
	}
	if m.Network < NetNone || m.Network > NetAll {
		return fmt.Errorf("network: must be one of none, localhost, all (got %d)", int(m.Network))
	}
	if m.ExecAny && len(m.Exec) > 0 {
		return errors.New("exec: cannot be both \"any\" and a path list")
	}
	if !m.ExecAny {
		for i, p := range m.Exec {
			field := fmt.Sprintf("exec[%d]", i)
			if !strings.HasPrefix(p, "/") {
				return fmt.Errorf("%s: must be an absolute path", field)
			}
			if err := validatePath(field, p, false); err != nil {
				return err
			}
		}
	}
	for i, e := range m.Env {
		if !envNameRe.MatchString(e) {
			return fmt.Errorf("env[%d]: must match ^[A-Z_][A-Z0-9_]*$", i)
		}
	}
	for i, p := range m.Filesystem.Read {
		field := fmt.Sprintf("filesystem.read[%d]", i)
		if err := validatePath(field, p, false); err != nil {
			return err
		}
		if err := checkBuiltinDeny(field, p); err != nil {
			return err
		}
	}
	for i, p := range m.Filesystem.Write {
		field := fmt.Sprintf("filesystem.write[%d]", i)
		if err := validatePath(field, p, false); err != nil {
			return err
		}
		if err := checkBuiltinDeny(field, p); err != nil {
			return err
		}
	}
	for i, p := range m.Filesystem.Deny {
		if err := validatePath(fmt.Sprintf("filesystem.deny[%d]", i), p, true); err != nil {
			return err
		}
	}
	if m.Filesystem.Deny != nil {
		var missing []string
		for _, d := range BuiltinDeny {
			if !containsPath(m.Filesystem.Deny, d) {
				missing = append(missing, d)
			}
		}
		if len(missing) > 0 {
			return fmt.Errorf("filesystem.deny: cannot remove built-in deny %s", strings.Join(missing, ", "))
		}
	}
	return nil
}
