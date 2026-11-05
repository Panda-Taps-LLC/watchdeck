// Package skillmd parses the YAML frontmatter of an Agent Skills SKILL.md.
//
// The parser is tolerant: anything short of "no frontmatter at all" yields a
// Frontmatter value, and every deviation from the agentskills.io spec (bad
// YAML, invalid or mismatched name, non-string metadata values, ...) is
// recorded in Frontmatter.Problems instead of failing the parse. When the YAML
// itself cannot be parsed, name and description are recovered line by line.
package skillmd

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/goccy/go-yaml"

	"github.com/Panda-Taps-LLC/watchdeck/internal/lazyre"
	"github.com/Panda-Taps-LLC/watchdeck/internal/safeio"
)

// ErrNoFrontmatter is returned when the file does not start with a `---` line.
var ErrNoFrontmatter = errors.New("skillmd: no frontmatter")

const (
	// MaxNameLen is the spec limit on the name field.
	MaxNameLen = 64
	// MaxDescriptionLen is the spec limit on the description field (in runes).
	MaxDescriptionLen = 1024
)

// Frontmatter is the parsed SKILL.md header.
type Frontmatter struct {
	Name, Description      string
	License, Compatibility string
	AllowedTools           []string          // "allowed-tools": string (space- or comma-separated) or list
	Metadata               map[string]string // non-string values dropped + Problem recorded
	Raw                    map[string]any    // whole frontmatter as parsed (nil on regex fallback)
	Problems               []string          // malformed YAML, name≠dir, invalid name, non-string metadata, ...
}

func (fm *Frontmatter) problem(format string, args ...any) {
	fm.Problems = append(fm.Problems, fmt.Sprintf(format, args...))
}

// Parse reads a SKILL.md and parses its frontmatter. The expected skill name is
// the name of the directory containing the file.
func Parse(path string) (Frontmatter, error) {
	b, err := safeio.ReadRegular(path, safeio.MaxDocument, false)
	if err != nil {
		return Frontmatter{}, err
	}
	dirName := ""
	if abs, aerr := filepath.Abs(path); aerr == nil {
		dirName = filepath.Base(filepath.Dir(abs))
	}
	return ParseBytes(b, dirName)
}

// ParseBytes parses SKILL.md content. dirName is the skill directory's name and
// is compared against the frontmatter name; pass "" to skip that check.
//
// The only error is ErrNoFrontmatter. Everything else is reported in Problems.
func ParseBytes(b []byte, dirName string) (Frontmatter, error) {
	block, closed, ok := split(b)
	if !ok {
		return Frontmatter{}, ErrNoFrontmatter
	}
	var fm Frontmatter
	if !closed {
		fm.problem("frontmatter: closing '---' not found; parsed to end of file")
	}

	raw, probs, parsed := decode(block)
	fm.Problems = append(fm.Problems, probs...)
	if parsed {
		fm.Raw = raw
		fm.Name = fm.stringField(raw, "name")
		fm.Description = fm.stringField(raw, "description")
		fm.License = fm.stringField(raw, "license")
		fm.Compatibility = fm.stringField(raw, "compatibility")
		fm.AllowedTools = fm.toolsField(raw["allowed-tools"])
		fm.Metadata = fm.metadataField(raw["metadata"])
	} else {
		fm.Name = scalarByRegex(block, "name")
		fm.Description = scalarByRegex(block, "description")
	}

	fm.validate(dirName)
	return fm, nil
}

// ValidName checks the spec rules for a skill name: lowercase letters, digits
// and single hyphens, no leading or trailing hyphen, at most 64 characters.
func ValidName(name string) error {
	if name == "" {
		return errors.New("empty")
	}
	if len(name) > MaxNameLen {
		return fmt.Errorf("%d characters, max %d", len(name), MaxNameLen)
	}
	if !nameRe.MatchString(name) {
		return errors.New("must match ^[a-z0-9]+(-[a-z0-9]+)*$ (lowercase letters, digits, single hyphens)")
	}
	return nil
}

var nameRe = lazyre.Regexp{Expr: `^[a-z0-9]+(-[a-z0-9]+)*$`}

func (fm *Frontmatter) validate(dirName string) {
	if fm.Name == "" {
		fm.problem("name: missing")
	} else {
		if err := ValidName(fm.Name); err != nil {
			fm.problem("name %q: %v", fm.Name, err)
		}
		if dirName != "" && fm.Name != dirName {
			fm.problem("name %q does not match directory name %q", fm.Name, dirName)
		}
	}
	if fm.Description == "" {
		fm.problem("description: missing")
	} else if n := utf8.RuneCountInString(fm.Description); n > MaxDescriptionLen {
		fm.problem("description: %d characters, max %d", n, MaxDescriptionLen)
	}
}

// split isolates the frontmatter block. ok is false when the file does not
// start with a `---` line; closed is false when no closing `---`/`...` line
// was found (the rest of the file is then returned as the block).
func split(b []byte) (block []byte, closed, ok bool) {
	b = bytes.TrimPrefix(b, []byte("\xef\xbb\xbf")) // UTF-8 BOM
	b = bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
	lines := bytes.Split(b, []byte("\n"))

	start := -1
	for i, l := range lines {
		if len(bytes.TrimSpace(l)) == 0 {
			continue // tolerate leading blank lines
		}
		if string(bytes.TrimRight(l, " \t")) == "---" {
			start = i
		}
		break
	}
	if start < 0 {
		return nil, false, false
	}
	for i := start + 1; i < len(lines); i++ {
		t := string(bytes.TrimRight(lines[i], " \t"))
		if t == "---" || t == "..." {
			return bytes.Join(lines[start+1:i], []byte("\n")), true, true
		}
	}
	return bytes.Join(lines[start+1:], []byte("\n")), false, true
}

// decode parses the YAML block into a map. On a duplicate-key error it retries
// permissively so the rest of the structure survives; on any other error it
// reports failure so the caller falls back to regex recovery.
func decode(block []byte) (raw map[string]any, problems []string, ok bool) {
	// go-yaml v1.19.2 panics on some malformed input (found by
	// internal/policy's fuzz test); a SKILL.md from any installed skill must
	// not crash the hook, so a panic is a parse error.
	defer func() {
		if r := recover(); r != nil {
			raw, ok = nil, false
			problems = []string{"frontmatter: YAML parse error: malformed YAML; name/description recovered line by line"}
		}
	}()
	if len(bytes.TrimSpace(block)) == 0 {
		return map[string]any{}, nil, true
	}
	if len(block) > safeio.MaxUntrusted {
		return nil, []string{"frontmatter: larger than 64 KiB; name/description recovered line by line"}, false
	}
	if err := safeio.CheckYAML(block); err != nil {
		return nil, []string{"frontmatter: " + err.Error() + "; name/description recovered line by line"}, false
	}
	err := yaml.Unmarshal(block, &raw)
	if err == nil {
		if raw == nil {
			raw = map[string]any{}
		}
		return raw, nil, true
	}
	msg := firstLine(err.Error())

	// go-yaml's AllowDuplicateMapKey decode is quadratic in the number of
	// repeated keys (~115 ms for a 64 KiB block of them), so only a block
	// of a realistic size gets the permissive retry.
	if len(block) > maxRetryBlock {
		return nil, []string{"frontmatter: YAML parse error: " + msg + "; name/description recovered line by line"}, false
	}
	var retry map[string]any
	if rerr := yaml.UnmarshalWithOptions(block, &retry, yaml.AllowDuplicateMapKey()); rerr == nil && retry != nil {
		return retry, []string{"frontmatter: " + msg + " (last value kept)"}, true
	}
	return nil, []string{"frontmatter: YAML parse error: " + msg + "; name/description recovered line by line"}, false
}

// maxRetryBlock bounds the frontmatter size that gets the duplicate-key
// retry in decode.
const maxRetryBlock = 8 << 10

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// stringField returns raw[key] as a trimmed string. Non-string scalars are
// stringified with a Problem; maps and lists yield "" with a Problem.
func (fm *Frontmatter) stringField(raw map[string]any, key string) string {
	v, present := raw[key]
	if !present || v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case map[string]any, []any:
		fm.problem("%s: expected a string, got a %s", key, yamlKind(v))
		return ""
	default:
		fm.problem("%s: expected a string, got %s %v", key, yamlKind(v), v)
		return strings.TrimSpace(fmt.Sprint(v))
	}
}

func yamlKind(v any) string {
	switch v.(type) {
	case map[string]any:
		return "mapping"
	case []any:
		return "list"
	case bool:
		return "boolean"
	case string:
		return "string"
	case nil:
		return "null"
	default:
		return "number"
	}
}

// toolsField parses allowed-tools from a string or a list of strings.
func (fm *Frontmatter) toolsField(v any) []string {
	switch t := v.(type) {
	case nil:
		return nil
	case string:
		return splitTools(t)
	case []any:
		var out []string
		for i, e := range t {
			s, isStr := e.(string)
			if !isStr {
				fm.problem("allowed-tools[%d]: expected a string, got %s", i, yamlKind(e))
				continue
			}
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		fm.problem("allowed-tools: expected a string or a list, got %s", yamlKind(v))
		return nil
	}
}

// splitTools splits a tool list on whitespace and commas outside parentheses,
// so `Bash(git add:*), Bash(npm run *)` stays two entries.
func splitTools(s string) []string {
	var out []string
	var cur strings.Builder
	depth := 0
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	for _, r := range s {
		switch {
		case r == '(':
			depth++
			cur.WriteRune(r)
		case r == ')':
			if depth > 0 {
				depth--
			}
			cur.WriteRune(r)
		case depth == 0 && (r == ',' || unicode.IsSpace(r)):
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return out
}

// metadataField keeps only string values of the metadata mapping.
func (fm *Frontmatter) metadataField(v any) map[string]string {
	if v == nil {
		return nil
	}
	m, isMap := v.(map[string]any)
	if !isMap {
		fm.problem("metadata: expected a mapping, got %s", yamlKind(v))
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make(map[string]string, len(m))
	for _, k := range keys {
		s, isStr := m[k].(string)
		if !isStr {
			fm.problem("metadata.%s: expected a string, got %s; dropped", k, yamlKind(m[k]))
			continue
		}
		out[k] = s
	}
	return out
}

// scalarByRegex recovers `key: value` from unparseable YAML. It handles quoted
// values and `>`/`|` block scalars well enough for display purposes.
func scalarByRegex(block []byte, key string) string {
	re := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(key) + `:[ \t]*(.*)$`)
	loc := re.FindSubmatchIndex(block)
	if loc == nil {
		return ""
	}
	val := strings.TrimSpace(string(block[loc[2]:loc[3]]))
	if val != "" && val[0] != '>' && val[0] != '|' {
		return unquote(val)
	}
	// Block scalar (or value on following indented lines): gather indented lines.
	fold := val == "" || val[0] == '>'
	rest := string(block[loc[1]:])
	var parts []string
	for _, l := range strings.Split(rest, "\n")[1:] {
		if strings.TrimSpace(l) == "" {
			if len(parts) > 0 {
				parts = append(parts, "")
			}
			continue
		}
		if l[0] != ' ' && l[0] != '\t' {
			break
		}
		parts = append(parts, strings.TrimSpace(l))
	}
	for len(parts) > 0 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	if fold {
		var sb strings.Builder
		for i, p := range parts {
			switch {
			case p == "":
				sb.WriteString("\n")
			case i > 0 && parts[i-1] != "":
				sb.WriteString(" " + p)
			default:
				sb.WriteString(p)
			}
		}
		return strings.TrimSpace(sb.String())
	}
	return strings.TrimSpace(strings.Join(parts, "\n"))
}

// unquote strips matching quotes, or a lone leading quote (the unterminated
// string that usually caused the YAML error in the first place).
func unquote(s string) string {
	if s == "" || (s[0] != '"' && s[0] != '\'') {
		return s
	}
	if len(s) >= 2 && s[len(s)-1] == s[0] {
		return strings.TrimSpace(s[1 : len(s)-1])
	}
	return strings.TrimSpace(s[1:])
}
