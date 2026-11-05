// Package mcpconfig reads and rewrites the user-scope stdio MCP server
// definitions in Claude Code's user config (~/.claude.json, or
// $CLAUDE_CONFIG_DIR/.claude.json), for `watchdeck mcp wrap|unwrap|status`
// (M6.7, experimental).
//
// That file is Claude Code's live state file, not only a config file: it
// carries trust flags, per-project state and more, and Claude Code rewrites
// it on its own schedule. This package therefore never re-serialises the
// file. It splices the bytes of one value, the top-level
// mcpServers.<name> entry, and leaves every other byte alone; a test checks
// that the only semantic difference after a splice is at that one path.
//
// Pure functions here take and return bytes; the file operations (backup,
// atomic write with a change check) are in file.go.
package mcpconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
)

// UserConfigPath is Claude Code's user config file: $CLAUDE_CONFIG_DIR/.claude.json
// when CLAUDE_CONFIG_DIR is set, else ~/.claude.json. Verified with Claude
// Code 2.1.296 on 2026-10-14: `claude mcp add -s user` with CLAUDE_CONFIG_DIR
// set wrote $CLAUDE_CONFIG_DIR/.claude.json.
func UserConfigPath(home string, environ map[string]string) string {
	if d := environ["CLAUDE_CONFIG_DIR"]; d != "" {
		return filepath.Join(d, ".claude.json")
	}
	return filepath.Join(home, ".claude.json")
}

// Server is one MCP server entry as found in the config.
type Server struct {
	Name    string
	Raw     []byte // the entry's bytes exactly as in the file
	Type    string // "" when the entry has no type (Claude Code reads that as stdio)
	Command string
	Args    []string
	EnvKeys []string // names under env, in file order; values are never kept here
	URL     string
}

// Stdio reports whether Claude Code launches this entry as a local process:
// type stdio, or no type and no url (docs, 2026-10-14: "Claude Code reads an
// entry with no type as a stdio server").
func (s Server) Stdio() bool {
	return (s.Type == "stdio" || s.Type == "") && s.URL == ""
}

// Wrapped reports whether the entry already runs through `watchdeck run
// --subject mcp:…`: its command's base name starts with "watchdeck" and
// its args start with run --subject mcp:<x> --.
func (s Server) Wrapped() bool {
	_, ok := WrappedSubject(s)
	return ok
}

// WrappedSubject returns the server name in a wrapped entry's
// "--subject mcp:<name>".
func WrappedSubject(s Server) (string, bool) {
	name, _, _, ok := wrappedSplit(s)
	return name, ok
}

// AllowHomeCwdFlag is the run flag that lets a wrapped server start with
// the home directory as its working directory.
const AllowHomeCwdFlag = "--allow-home-cwd"

// wrappedSplit parses run --subject mcp:<name> [--allow-home-cwd] -- argv:
// the name, the index of "--", and whether the flag is there.
func wrappedSplit(s Server) (name string, sep int, allowHome, ok bool) {
	if base := filepath.Base(s.Command); !strings.HasPrefix(base, paths.BinaryName) {
		return "", 0, false, false
	}
	a := s.Args
	if len(a) < 4 || a[0] != "run" || a[1] != "--subject" {
		return "", 0, false, false
	}
	sep = 3
	if a[3] == AllowHomeCwdFlag {
		allowHome, sep = true, 4
	}
	if len(a) <= sep || a[sep] != "--" {
		return "", 0, false, false
	}
	name, ok = strings.CutPrefix(a[2], "mcp:")
	return name, sep, allowHome, ok
}

// OriginalArgv is the wrapped entry's original command and args (everything
// after "--"), or nil when s is not wrapped.
func OriginalArgv(s Server) []string {
	_, sep, _, ok := wrappedSplit(s)
	if !ok {
		return nil
	}
	return append([]string(nil), s.Args[sep+1:]...)
}

// ErrNotFound means the name is not under the top-level mcpServers.
var ErrNotFound = errors.New("not found")

// span is a value's byte range in the file.
type span struct {
	keyStart   int // offset of the key's opening quote
	start, end int // the value
}

// entry is one key of a JSON object with the byte range of its value.
type entry struct {
	key string
	span
}

// objectEntries walks the JSON object that starts at data[base:] (after
// optional whitespace) and returns its keys with their value spans
// (absolute offsets). It refuses a value that is not an object.
func objectEntries(data []byte, base int) ([]entry, int, error) {
	dec := json.NewDecoder(bytes.NewReader(data[base:]))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return nil, 0, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, 0, errors.New("not a JSON object")
	}
	var out []entry
	for dec.More() {
		before := int(dec.InputOffset())
		tok, err := dec.Token()
		if err != nil {
			return nil, 0, err
		}
		key, ok := tok.(string)
		if !ok {
			return nil, 0, errors.New("object key is not a string")
		}
		afterKey := int(dec.InputOffset())
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, 0, err
		}
		end := int(dec.InputOffset())
		start := end - len(raw)
		// the key's opening quote: first '"' after the previous token
		ks := bytes.IndexByte(data[base+before:base+afterKey], '"')
		if ks < 0 {
			return nil, 0, errors.New("internal: key quote not found")
		}
		e := entry{key: key, span: span{keyStart: base + before + ks, start: base + start, end: base + end}}
		if !bytes.Equal(data[e.start:e.end], raw) {
			return nil, 0, errors.New("internal: value span mismatch")
		}
		out = append(out, e)
	}
	if _, err := dec.Token(); err != nil { // closing '}'
		return nil, 0, err
	}
	return out, base + int(dec.InputOffset()), nil
}

// topLevel parses the whole file as one JSON object and returns its
// entries; trailing non-space data is an error.
func topLevel(data []byte) ([]entry, error) {
	es, end, err := objectEntries(data, 0)
	if err != nil {
		return nil, fmt.Errorf("config is not a JSON object: %w", err)
	}
	if len(bytes.TrimSpace(data[end:])) != 0 {
		return nil, errors.New("config has data after the top-level object")
	}
	return es, nil
}

// unique returns the one entry named key; more than one is an error (Go and
// JavaScript would disagree on which one counts).
func unique(es []entry, key, where string) (entry, bool, error) {
	var found []entry
	for _, e := range es {
		if e.key == key {
			found = append(found, e)
		}
	}
	switch len(found) {
	case 0:
		return entry{}, false, nil
	case 1:
		return found[0], true, nil
	}
	return entry{}, false, fmt.Errorf("%s: duplicate key %q; refusing to edit", where, key)
}

// servers returns the entries of the top-level mcpServers object (nil when
// there is none).
func servers(data []byte) ([]entry, error) {
	top, err := topLevel(data)
	if err != nil {
		return nil, err
	}
	ms, ok, err := unique(top, "mcpServers", "config")
	if err != nil || !ok {
		return nil, err
	}
	if bytes.Equal(data[ms.start:ms.end], []byte("null")) {
		return nil, nil
	}
	es, _, err := objectEntries(data, ms.start)
	if err != nil {
		return nil, fmt.Errorf("mcpServers: %w", err)
	}
	return es, nil
}

// List returns every user-scope server, in file order.
func List(data []byte) ([]Server, error) {
	es, err := servers(data)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []Server
	for _, e := range es {
		if seen[e.key] {
			return nil, fmt.Errorf("mcpServers: duplicate key %q", e.key)
		}
		seen[e.key] = true
		s, err := parseServer(e.key, data[e.start:e.end])
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

// Find returns the user-scope server name, or ErrNotFound.
func Find(data []byte, name string) (Server, error) {
	s, _, err := find(data, name)
	return s, err
}

func find(data []byte, name string) (Server, entry, error) {
	es, err := servers(data)
	if err != nil {
		return Server{}, entry{}, err
	}
	e, ok, err := unique(es, name, "mcpServers")
	if err != nil {
		return Server{}, entry{}, err
	}
	if !ok {
		return Server{}, entry{}, ErrNotFound
	}
	s, err := parseServer(name, data[e.start:e.end])
	return s, e, err
}

// LocalScopeProjects returns the project paths whose local-scope
// mcpServers (projects.<path>.mcpServers) define name. Used only to explain
// a refusal: local scope is not wrapped.
func LocalScopeProjects(data []byte, name string) []string {
	top, err := topLevel(data)
	if err != nil {
		return nil
	}
	pr, ok, err := unique(top, "projects", "config")
	if err != nil || !ok {
		return nil
	}
	projects, _, err := objectEntries(data, pr.start)
	if err != nil {
		return nil
	}
	var out []string
	for _, p := range projects {
		inner, _, err := objectEntries(data, p.start)
		if err != nil {
			continue
		}
		ms, ok, err := unique(inner, "mcpServers", "project")
		if err != nil || !ok {
			continue
		}
		srv, _, err := objectEntries(data, ms.start)
		if err != nil {
			continue
		}
		for _, s := range srv {
			if s.key == name {
				out = append(out, p.key)
				break
			}
		}
	}
	return out
}

func parseServer(name string, raw []byte) (Server, error) {
	s := Server{Name: name, Raw: append([]byte(nil), raw...)}
	es, _, err := objectEntries(raw, 0)
	if err != nil {
		return s, fmt.Errorf("mcpServers.%s: %w", name, err)
	}
	if k, dup := duplicateKey(es); dup {
		return s, fmt.Errorf("mcpServers.%s: duplicate key %q; refusing to edit", name, k)
	}
	for _, e := range es {
		v := raw[e.start:e.end]
		switch e.key {
		case "type":
			if err := json.Unmarshal(v, &s.Type); err != nil {
				return s, fmt.Errorf("mcpServers.%s.type: not a string", name)
			}
		case "command":
			if err := json.Unmarshal(v, &s.Command); err != nil {
				return s, fmt.Errorf("mcpServers.%s.command: not a string", name)
			}
		case "args":
			if err := json.Unmarshal(v, &s.Args); err != nil {
				return s, fmt.Errorf("mcpServers.%s.args: not a list of strings", name)
			}
		case "url":
			if err := json.Unmarshal(v, &s.URL); err != nil {
				return s, fmt.Errorf("mcpServers.%s.url: not a string", name)
			}
		case "env":
			if bytes.Equal(v, []byte("null")) {
				continue
			}
			envs, _, err := objectEntries(raw, e.start)
			if err != nil {
				return s, fmt.Errorf("mcpServers.%s.env: not an object", name)
			}
			if k, dup := duplicateKey(envs); dup {
				return s, fmt.Errorf("mcpServers.%s.env: duplicate key %q; refusing to edit", name, k)
			}
			for _, x := range envs {
				s.EnvKeys = append(s.EnvKeys, x.key)
			}
		}
	}
	return s, nil
}

// WrapArgs is the wrapped entry's args: run --subject mcp:<name>
// [--allow-home-cwd] -- <command> <args…>.
func WrapArgs(name, command string, args []string, allowHome bool) []string {
	out := []string{"run", "--subject", "mcp:" + name}
	if allowHome {
		out = append(out, AllowHomeCwdFlag)
	}
	return append(append(out, "--", command), args...)
}

// Wrap returns data with the user-scope server name rewritten to run
// through binary (absolute), plus the original and the new entry bytes.
// Every other byte of data is unchanged. It refuses an entry that is
// missing, not stdio, without a command, or already wrapped.
func Wrap(data []byte, name, binary string, allowHome bool) (out, original, wrapped []byte, err error) {
	if !filepath.IsAbs(binary) {
		return nil, nil, nil, errors.New("the watchdeck binary path must be absolute")
	}
	s, e, err := find(data, name)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := Wrappable(s); err != nil {
		return nil, nil, nil, err
	}
	nv, err := rewriteEntry(data, e, binary, WrapArgs(name, s.Command, s.Args, allowHome))
	if err != nil {
		return nil, nil, nil, err
	}
	return splice(data, e.span, nv), s.Raw, nv, nil
}

// Wrappable explains why s cannot be wrapped, or returns nil.
func Wrappable(s Server) error {
	switch {
	case s.Wrapped():
		return errors.New("already wrapped (its command is watchdeck run)")
	case !s.Stdio():
		t := s.Type
		if t == "" {
			t = "url"
		}
		return fmt.Errorf("not a stdio server (type %s): only local processes can be sandboxed", t)
	case s.Command == "":
		return errors.New("has no command")
	}
	return nil
}

// Unwrap restores the server name. When the current entry is still exactly
// the wrapped bytes wrap wrote (compared as JSON values, so a re-indent by
// Claude Code does not count as a change), original is spliced back byte
// for byte (exact = true). When the entry was edited since but is still a
// wrapper for name, only its command and args are put back from the args
// after "--" (exact = false). Anything else is refused.
func Unwrap(data []byte, name string, original, wrapped []byte) (out []byte, exact bool, err error) {
	s, e, err := find(data, name)
	if err != nil {
		return nil, false, err
	}
	sub, ok := WrappedSubject(s)
	if !ok || sub != name {
		return nil, false, errors.New("the entry is not wrapped by watchdeck (nothing to restore)")
	}
	if len(original) > 0 && sameJSON(s.Raw, wrapped) {
		if _, err := parseServer(name, original); err != nil {
			return nil, false, fmt.Errorf("stored original: %w", err)
		}
		return splice(data, e.span, original), true, nil
	}
	argv := OriginalArgv(s)
	if len(argv) == 0 {
		return nil, false, errors.New("wrapped entry has no command after --")
	}
	nv, err := rewriteEntry(data, e, argv[0], argv[1:])
	if err != nil {
		return nil, false, err
	}
	return splice(data, e.span, nv), false, nil
}

func sameJSON(a, b []byte) bool {
	var ca, cb bytes.Buffer
	if json.Compact(&ca, a) != nil || json.Compact(&cb, b) != nil {
		return false
	}
	return bytes.Equal(ca.Bytes(), cb.Bytes())
}

func splice(data []byte, sp span, v []byte) []byte {
	out := make([]byte, 0, len(data)-(sp.end-sp.start)+len(v))
	out = append(out, data[:sp.start]...)
	out = append(out, v...)
	return append(out, data[sp.end:]...)
}

// rewriteEntry renders the entry at e with command and args replaced,
// keeping every other key, the key order and the values' bytes. A missing
// args key is added right after command. The result is indented the way
// the entry was: compact when it had no newline, else like Claude Code's
// JSON.stringify(…, null, 2) at the entry's depth (prefix = the key line's
// leading whitespace, unit = the entry's first indent step).
func rewriteEntry(data []byte, e entry, command string, args []string) ([]byte, error) {
	raw := data[e.start:e.end]
	es, _, err := objectEntries(raw, 0)
	if err != nil {
		return nil, err
	}
	cmdJSON, err := marshal(command)
	if err != nil {
		return nil, err
	}
	if args == nil {
		args = []string{}
	}
	argsJSON, err := marshal(args)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	b.WriteByte('{')
	n := 0
	put := func(k string, v []byte) {
		if n > 0 {
			b.WriteByte(',')
		}
		n++
		kj, _ := marshal(k)
		b.Write(kj)
		b.WriteByte(':')
		var c bytes.Buffer
		if json.Compact(&c, v) != nil {
			b.Write(v)
			return
		}
		b.Write(c.Bytes())
	}
	hasArgs := false
	for _, x := range es {
		if x.key == "args" {
			hasArgs = true
		}
	}
	for _, x := range es {
		switch x.key {
		case "command":
			put("command", cmdJSON)
			if !hasArgs {
				put("args", argsJSON)
			}
		case "args":
			put("args", argsJSON)
		default:
			put(x.key, raw[x.start:x.end])
		}
	}
	b.WriteByte('}')
	if !bytes.Contains(raw, []byte("\n")) {
		return b.Bytes(), nil
	}
	prefix := lineIndent(data, e.keyStart)
	unit := "  "
	if i := bytes.IndexByte(raw, '\n'); i >= 0 {
		rest := raw[i+1:]
		j := 0
		for j < len(rest) && (rest[j] == ' ' || rest[j] == '\t') {
			j++
		}
		if ws := string(rest[:j]); strings.HasPrefix(ws, prefix) && len(ws) > len(prefix) {
			unit = ws[len(prefix):]
		}
	}
	var out bytes.Buffer
	if err := json.Indent(&out, b.Bytes(), prefix, unit); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// lineIndent is the leading whitespace of the line holding offset off.
func lineIndent(data []byte, off int) string {
	ls := bytes.LastIndexByte(data[:off], '\n') + 1
	j := ls
	for j < off && (data[j] == ' ' || data[j] == '\t') {
		j++
	}
	return string(data[ls:j])
}

// marshal is json.Marshal without HTML escaping (JSON.stringify does not
// escape <, > or &).
func marshal(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(b.Bytes(), "\n"), nil
}

// RedactedEntry renders an entry for display with every env value replaced
// by "***": the values are often tokens.
func RedactedEntry(raw []byte) string {
	es, _, err := objectEntries(raw, 0)
	if err != nil {
		return "(unreadable entry)"
	}
	out := append([]byte(nil), raw...)
	for i := len(es) - 1; i >= 0; i-- {
		x := es[i]
		if x.key != "env" {
			continue
		}
		envs, _, err := objectEntries(raw, x.start)
		if err != nil {
			continue
		}
		for j := len(envs) - 1; j >= 0; j-- {
			v := envs[j]
			out = append(append(append([]byte(nil), out[:v.start]...), `"***"`...), out[v.end:]...)
		}
	}
	return string(out)
}

// LocalScopeServers returns the local-scope servers of project (the
// projects.<project>.mcpServers entries), for display only.
func LocalScopeServers(data []byte, project string) []Server {
	top, err := topLevel(data)
	if err != nil {
		return nil
	}
	pr, ok, err := unique(top, "projects", "config")
	if err != nil || !ok {
		return nil
	}
	projects, _, err := objectEntries(data, pr.start)
	if err != nil {
		return nil
	}
	p, ok, err := unique(projects, project, "projects")
	if err != nil || !ok {
		return nil
	}
	inner, _, err := objectEntries(data, p.start)
	if err != nil {
		return nil
	}
	ms, ok, err := unique(inner, "mcpServers", "project")
	if err != nil || !ok {
		return nil
	}
	srv, _, err := objectEntries(data, ms.start)
	if err != nil {
		return nil
	}
	var out []Server
	for _, e := range srv {
		if s, err := parseServer(e.key, data[e.start:e.end]); err == nil {
			out = append(out, s)
		}
	}
	return out
}

// duplicateKey reports the first key that appears twice (Go and JavaScript
// would disagree on which value counts).
func duplicateKey(es []entry) (string, bool) {
	seen := map[string]bool{}
	for _, e := range es {
		if seen[e.key] {
			return e.key, true
		}
		seen[e.key] = true
	}
	return "", false
}
