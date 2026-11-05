// Package safeio reads files the hook depends on without ever blocking, and
// checks YAML text before go-yaml parses it.
//
// The hook runs on every Bash call; Claude Code treats a hook that times out
// as no opinion, so a read that hangs (a FIFO or /dev/tty planted where a
// SKILL.md, PERMISSIONS.yaml, .watchdeck.yaml or .claude/settings.json is
// expected) or a parse that takes seconds (go-yaml is roughly quadratic in
// flow-collection nesting before its own depth check) would let a command
// run unsandboxed. ReadRegular opens O_NONBLOCK and refuses anything but a
// regular file; CheckYAML rejects deeply nested YAML using go-yaml's lexer,
// which is linear, before any decode.
//
// Errors carry no path and no text from the file.
package safeio

import (
	"errors"
	"io"
	"os"
	"syscall"

	"github.com/goccy/go-yaml/lexer"
	"github.com/goccy/go-yaml/token"
)

// Caps for files the hook reads.
const (
	// MaxUntrusted caps a file that ships with a skill or a repository:
	// PERMISSIONS.yaml, a project .watchdeck.yaml, SKILL.md frontmatter.
	MaxUntrusted = 64 << 10
	// MaxUser caps the user's own YAML files (overrides.yaml, config.yaml).
	MaxUser = 1 << 20
	// MaxDocument caps a SKILL.md as a whole (body included).
	MaxDocument = 1 << 20
	// MaxJSON caps JSON state files (settings, plugin registry, index).
	MaxJSON = 16 << 20
)

// Limits on YAML structure (CheckYAML).
const (
	MaxFlowDepth  = 64  // nested [ { }
	MaxIndent     = 256 // columns of block indentation
	MaxDashChain  = 64  // "- - - x" entries or "? ? x" keys opened on one line
	MaxAliases    = 16  // *alias references (none of watchdeck's files need one)
	MaxYAMLTokens = 1 << 20
)

var (
	// ErrNotRegular: the path is a FIFO, a device, a socket or a directory.
	ErrNotRegular = errors.New("not a regular file")
	// ErrTooLarge: the file is over its cap.
	ErrTooLarge = errors.New("file too large")
	// ErrTooDeep: the YAML nests deeper than the limits.
	ErrTooDeep = errors.New("malformed YAML (too deeply nested)")
)

// ReadRegular reads at most max bytes of path without blocking: the file is
// opened O_RDONLY|O_NONBLOCK (and O_NOFOLLOW with nofollow), must be a
// regular file, and a file larger than max is ErrTooLarge. A missing file
// is an error satisfying errors.Is(err, fs.ErrNotExist).
func ReadRegular(path string, max int64, nofollow bool) ([]byte, error) {
	f, err := openRegular(path, nofollow)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, ErrTooLarge
	}
	return b, nil
}

// OpenRegular opens path for reading without blocking (O_NONBLOCK, symlinks
// followed) and returns ErrNotRegular unless it is a regular file. The
// caller closes the file and bounds its own reads.
func OpenRegular(path string) (*os.File, error) { return openRegular(path, false) }

func openRegular(path string, nofollow bool) (*os.File, error) {
	flag := os.O_RDONLY | syscall.O_NONBLOCK
	if nofollow {
		flag |= syscall.O_NOFOLLOW
	}
	f, err := os.OpenFile(path, flag, 0)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		f.Close()
		return nil, ErrNotRegular
	}
	return f, nil
}

// CheckYAML is ScanYAML without the result.
func CheckYAML(b []byte) error {
	_, err := ScanYAML(b)
	return err
}

// YAMLInfo is what ScanYAML learns from the tokens.
type YAMLInfo struct {
	// Docs counts documents with content. A %YAML or %TAG directive and
	// the --- that ends it do not start a second document.
	Docs int
	// Version is the token after a top-level "version:" key of the first
	// document ("" when there is none); VersionInt says whether the lexer
	// read it as a plain decimal integer.
	Version    string
	HasVersion bool
	VersionInt bool
}

// ScanYAML lexes b once (go-yaml's lexer, linear in len(b)) and returns
// ErrTooDeep when b nests flow collections deeper than MaxFlowDepth,
// indents a line more than MaxIndent columns, opens more than MaxDashChain
// sequence entries or complex keys on one line, uses more than MaxAliases
// aliases (alias expansion is the "billion laughs" blow-up), or lexes to more
// than MaxYAMLTokens tokens. Brackets inside quoted scalars and comments are
// text to the lexer and are not counted. A lexer panic is ErrTooDeep too.
func ScanYAML(b []byte) (info YAMLInfo, err error) {
	defer func() {
		if recover() != nil {
			info, err = YAMLInfo{}, ErrTooDeep
		}
	}()
	toks := lexer.Tokenize(string(b))
	if len(toks) > MaxYAMLTokens {
		return YAMLInfo{}, ErrTooDeep
	}
	depth, line, chain, aliases := 0, -1, 0, 0
	inDirective, docHasContent := false, false
	for i, tk := range toks {
		if tk == nil {
			continue
		}
		if p := tk.Position; p != nil && p.Line != line {
			line, chain = p.Line, 0
			if p.Column-1 > MaxIndent {
				return YAMLInfo{}, ErrTooDeep
			}
		}
		switch tk.Type {
		case token.SequenceStartType, token.MappingStartType:
			depth++
			if depth > MaxFlowDepth {
				return YAMLInfo{}, ErrTooDeep
			}
		case token.SequenceEndType, token.MappingEndType:
			if depth > 0 {
				depth--
			}
		case token.SequenceEntryType, token.MappingKeyType:
			chain++
			if chain > MaxDashChain {
				return YAMLInfo{}, ErrTooDeep
			}
		case token.AliasType:
			aliases++
			if aliases > MaxAliases {
				return YAMLInfo{}, ErrTooDeep
			}
		}
		switch tk.Type {
		case token.DirectiveType:
			inDirective = true
			continue
		case token.DocumentHeaderType:
			if docHasContent {
				docHasContent = false
			}
			inDirective = false
			continue
		case token.DocumentEndType:
			docHasContent = false
			continue
		case token.CommentType, token.SpaceType:
			continue
		}
		if inDirective {
			continue
		}
		if !docHasContent {
			docHasContent = true
			info.Docs++
		}
		if info.Docs == 1 && !info.HasVersion && depth == 0 && tk.Type == token.StringType && tk.Value == "version" &&
			tk.Position != nil && tk.Position.Column == 1 && i+2 < len(toks) && toks[i+1] != nil && toks[i+1].Type == token.MappingValueType && toks[i+2] != nil {
			v := toks[i+2]
			info.HasVersion, info.Version, info.VersionInt = true, v.Value, v.Type == token.IntegerType
		}
	}
	return info, nil
}
