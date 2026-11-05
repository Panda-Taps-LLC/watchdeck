package transcript

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// PathsDeps is what Discover needs from the paths resolver and the activity
// log. The caller passes the distinct transcript_path values its decision
// records carry; this package does not read the activity log itself.
type PathsDeps struct {
	ClaudeProjectsDir string   // ~/.claude/projects or $CLAUDE_CONFIG_DIR/projects
	Cwd               string   // the project whose sessions are listed; "" lists none by cwd
	TranscriptPaths   []string // transcript_path values from activity records, checked for path safety before use
}

// Discover lists the sessions of the current project plus every transcript
// the activity log names. It reads directory entries and Stat only; no file
// is opened. The whole projects tree is never scanned. Results are newest
// first. A missing projects dir yields no sessions and no error.
func Discover(deps PathsDeps) ([]SessionRef, error) {
	if deps.ClaudeProjectsDir == "" {
		return nil, ErrNoProjectsDir
	}
	root, err := resolveRoot(deps.ClaudeProjectsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	byPath := map[string]*SessionRef{}
	var refs []*SessionRef

	if dir := projectDirFor(deps.ClaudeProjectsDir, deps.Cwd); dir != "" {
		// The project dir must resolve to a direct child of the projects dir
		// before it is listed: a symlinked project dir could lead anywhere.
		if rdir, ok := underRoot(root, dir); ok && filepath.Dir(rdir) == root {
			if entries, err := os.ReadDir(rdir); err == nil {
				for _, e := range entries {
					name := e.Name()
					if e.IsDir() || !strings.HasSuffix(name, ".jsonl") || !ValidID(strings.TrimSuffix(name, ".jsonl")) {
						continue
					}
					p := filepath.Join(dir, name)
					resolved, err := resolveSessionPath(root, p)
					if err != nil {
						continue
					}
					ref := refFor(root, p, resolved, deps.Cwd, "cwd")
					if ref == nil {
						continue
					}
					byPath[resolved] = ref
					refs = append(refs, ref)
				}
			}
		}
	}

	for _, p := range deps.TranscriptPaths {
		if p == "" {
			continue
		}
		resolved, err := resolveSessionPath(root, p)
		if err != nil {
			continue
		}
		if ref, ok := byPath[resolved]; ok {
			if ref.Source == "cwd" {
				ref.Source = "cwd+activity"
			}
			continue
		}
		ref := refFor(root, p, resolved, UnescapeProjectDirGuess(filepath.Base(filepath.Dir(p))), "activity")
		if ref == nil {
			continue
		}
		byPath[resolved] = ref
		refs = append(refs, ref)
	}

	sort.SliceStable(refs, func(i, j int) bool {
		if !refs[i].ModTime.Equal(refs[j].ModTime) {
			return refs[i].ModTime.After(refs[j].ModTime)
		}
		return refs[i].ID < refs[j].ID
	})
	out := make([]SessionRef, 0, len(refs))
	for _, r := range refs {
		out = append(out, *r)
	}
	return out, nil
}

// projectDirFor returns <projects>/<escaped cwd>, or "" when cwd is empty.
// When the escaped name is longer than ProjectDirMaxLen, Claude Code writes
// <first 200 characters>-<hash>; the projects dir is listed (names only) and
// the single directory with that prefix and an alphanumeric suffix is used.
// Zero or several matches give "": the cwd's sessions are then found only
// through activity transcript paths.
func projectDirFor(projects, cwd string) string {
	if cwd == "" {
		return ""
	}
	esc := EscapeProjectDir(cwd)
	if len(esc) <= ProjectDirMaxLen {
		return filepath.Join(projects, esc)
	}
	prefix := esc[:ProjectDirMaxLen] + "-"
	entries, err := os.ReadDir(projects)
	if err != nil {
		return ""
	}
	found := ""
	for _, e := range entries {
		name := e.Name()
		if !e.IsDir() || !strings.HasPrefix(name, prefix) || len(name) == len(prefix) || !alnum(name[len(prefix):]) {
			continue
		}
		if found != "" {
			return "" // ambiguous
		}
		found = name
	}
	if found == "" {
		return ""
	}
	return filepath.Join(projects, found)
}

func alnum(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

// refFor builds a SessionRef from Stat and one directory listing. p is the
// path as the caller named it, resolved the result of resolveSessionPath.
func refFor(root, p, resolved, cwdGuess, source string) *SessionRef {
	st, err := os.Stat(resolved)
	if err != nil || !st.Mode().IsRegular() {
		return nil
	}
	id := strings.TrimSuffix(filepath.Base(p), ".jsonl")
	return &SessionRef{
		ID:         id,
		Path:       p,
		CwdGuess:   cwdGuess,
		ProjectDir: filepath.Dir(p),
		Size:       st.Size(),
		ModTime:    st.ModTime(),
		Subagents:  countSubagentFiles(root, filepath.Join(filepath.Dir(resolved), id, "subagents")),
		Source:     source,
	}
}

// countSubagentFiles counts agent-*.jsonl entries; 0 when the dir is missing
// or resolves outside the projects dir (it is not listed then).
func countSubagentFiles(root, dir string) int {
	rdir, ok := underRoot(root, dir)
	if !ok {
		return 0
	}
	entries, err := os.ReadDir(rdir)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if _, ok := subagentID(e.Name()); ok && !e.IsDir() {
			n++
		}
	}
	return n
}

// subagentID extracts <id> from "agent-<id>.jsonl" and checks it with ValidID.
func subagentID(name string) (string, bool) {
	if !strings.HasPrefix(name, "agent-") || !strings.HasSuffix(name, ".jsonl") {
		return "", false
	}
	id := strings.TrimSuffix(strings.TrimPrefix(name, "agent-"), ".jsonl")
	if !ValidID(id) {
		return "", false
	}
	return id, true
}

// underRoot resolves p through EvalSymlinks and reports whether the result
// sits under root (which must come from resolveRoot). A missing p is not under.
func underRoot(root, p string) (string, bool) {
	r, err := filepath.EvalSymlinks(p)
	if err != nil || !strings.HasPrefix(r, root+string(filepath.Separator)) {
		return "", false
	}
	return r, true
}

// resolveRoot makes the projects dir absolute and resolves its symlinks.
func resolveRoot(dir string) (string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(abs)
}

// resolveSessionPath checks that p is <root>/<escaped cwd>/<id>.jsonl after
// symlink resolution, with <id> passing ValidID both before and after the
// resolution, and returns the resolved path. root must come from resolveRoot.
func resolveSessionPath(root, p string) (string, error) {
	if !strings.HasSuffix(p, ".jsonl") || !ValidID(strings.TrimSuffix(filepath.Base(p), ".jsonl")) {
		return "", ErrBadID
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	r, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", err
	}
	prefix := root + string(filepath.Separator)
	if !strings.HasPrefix(r, prefix) {
		return "", ErrOutsideProjects
	}
	rel := r[len(prefix):]
	parts := strings.Split(rel, string(filepath.Separator))
	if len(parts) != 2 || parts[0] == "" || !strings.HasSuffix(parts[1], ".jsonl") || !ValidID(strings.TrimSuffix(parts[1], ".jsonl")) {
		return "", ErrOutsideProjects
	}
	return r, nil
}
