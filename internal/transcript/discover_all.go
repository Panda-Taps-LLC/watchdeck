package transcript

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// FileRef is one transcript file found by DiscoverAll, from Stat only.
type FileRef struct {
	Name     string    // file name as listed (<id>.jsonl or agent-<id>.jsonl)
	Path     string    // as the caller's projects dir names it
	Resolved string    // after EvalSymlinks; checked to sit under the projects dir. Open this one.
	Size     int64     // of the resolved file
	ModTime  time.Time // of the resolved file
}

// SessionFiles is one session found by DiscoverAll: the main file (as a
// SessionRef with Source "all") and its subagent files.
type SessionFiles struct {
	SessionRef
	Main          FileRef
	SubagentFiles []FileRef // agent-<id>.jsonl under <id>/subagents/, sorted by name
}

// DiscoverAll lists every session under projectsDir: <projects>/*/<id>.jsonl
// plus each session's <id>/subagents/agent-<id>.jsonl. Unlike Discover it
// walks the whole projects tree (M5.4, reversed decision 1, 2026-10-13); it
// still opens no file, only directory listings and Stat.
//
// The same checks as Discover apply: a project dir must resolve to a direct
// child of the resolved projects dir (a symlinked project dir leading
// elsewhere is skipped), a session file must pass resolveSessionPath (ValidID
// stem before and after resolution, exactly <root>/<dir>/<id>.jsonl), and a
// subagent dir and file must resolve under the projects dir with a ValidID
// agent id. Two names that resolve to the same file yield one session.
// Results are newest first, then by id. A missing projects dir yields no
// sessions and no error.
func DiscoverAll(projectsDir string) ([]SessionFiles, error) {
	if projectsDir == "" {
		return nil, ErrNoProjectsDir
	}
	root, err := resolveRoot(projectsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	dirs, err := os.ReadDir(projectsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	seen := map[string]bool{}
	var out []SessionFiles
	for _, d := range dirs {
		dir := filepath.Join(projectsDir, d.Name())
		rdir, ok := underRoot(root, dir)
		if !ok || filepath.Dir(rdir) != root {
			continue
		}
		if st, err := os.Stat(rdir); err != nil || !st.IsDir() {
			continue
		}
		entries, err := os.ReadDir(rdir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || !strings.HasSuffix(name, ".jsonl") || !ValidID(strings.TrimSuffix(name, ".jsonl")) {
				continue
			}
			p := filepath.Join(dir, name)
			resolved, err := resolveSessionPath(root, p)
			if err != nil || seen[resolved] {
				continue
			}
			st, err := os.Stat(resolved)
			if err != nil || !st.Mode().IsRegular() {
				continue
			}
			seen[resolved] = true
			// the id is the resolved file's stem: a second name for a session
			// file must not invent a second session id
			id := strings.TrimSuffix(filepath.Base(resolved), ".jsonl")
			sf := SessionFiles{
				SessionRef: SessionRef{
					ID:         id,
					Path:       p,
					CwdGuess:   UnescapeProjectDirGuess(d.Name()),
					ProjectDir: dir,
					Size:       st.Size(),
					ModTime:    st.ModTime(),
					Source:     "all",
				},
				Main: FileRef{Name: name, Path: p, Resolved: resolved, Size: st.Size(), ModTime: st.ModTime()},
			}
			sf.SubagentFiles = listSubagentFiles(root, filepath.Join(dir, id, "subagents"))
			sf.Subagents = len(sf.SubagentFiles)
			out = append(out, sf)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].ModTime.Equal(out[j].ModTime) {
			return out[i].ModTime.After(out[j].ModTime)
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// listSubagentFiles returns the agent-<id>.jsonl files of one session whose
// dir and file both resolve under root; nil when the dir is missing or leads
// outside.
func listSubagentFiles(root, dir string) []FileRef {
	rdir, ok := underRoot(root, dir)
	if !ok {
		return nil
	}
	entries, err := os.ReadDir(rdir)
	if err != nil {
		return nil
	}
	var out []FileRef
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if _, ok := subagentID(e.Name()); !ok {
			continue
		}
		p := filepath.Join(dir, e.Name())
		r, ok := underRoot(root, filepath.Join(rdir, e.Name()))
		if !ok {
			continue
		}
		st, err := os.Stat(r)
		if err != nil || !st.Mode().IsRegular() {
			continue
		}
		out = append(out, FileRef{Name: e.Name(), Path: p, Resolved: r, Size: st.Size(), ModTime: st.ModTime()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
