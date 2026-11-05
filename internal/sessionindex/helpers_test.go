package sessionindex

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// All tests work on temp projects dirs and temp index dirs; nothing reads a
// real home. Fixture A is copied from ../transcript/testdata.

type env struct {
	root, projects, dir string
}

func newEnv(t testing.TB) env {
	t.Helper()
	root := t.TempDir()
	e := env{root: root, projects: filepath.Join(root, "projects"), dir: filepath.Join(root, "state", "watchdeck", "index")}
	if err := os.MkdirAll(e.projects, 0o700); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e env) open(t testing.TB, mod ...func(*Options)) *Index {
	t.Helper()
	o := Options{Dir: e.dir, ProjectsDir: e.projects}
	for _, f := range mod {
		f(&o)
	}
	ix, err := Open(o)
	if err != nil {
		t.Fatal(err)
	}
	return ix
}

func (e env) update(t testing.TB, mod ...func(*Options)) (*Index, Stats) {
	t.Helper()
	ix := e.open(t, mod...)
	st, err := ix.Update()
	if err != nil {
		t.Fatal(err)
	}
	return ix, st
}

var tsBase = time.Date(2026, 10, 13, 9, 0, 0, 0, time.UTC)

func ts(i int) string { return tsBase.Add(time.Duration(i) * time.Second).Format(time.RFC3339Nano) }

func jsonLine(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b) + "\n"
}

func userPrompt(i int, cwd, text string) string {
	return jsonLine(map[string]any{
		"type": "user", "timestamp": ts(i), "cwd": cwd, "gitBranch": "main", "version": "2.1.296", "entrypoint": "cli",
		"message": map[string]any{"role": "user", "content": text},
	})
}

func assistantText(i int, model, text string) string {
	return jsonLine(map[string]any{
		"type": "assistant", "timestamp": ts(i),
		"message": map[string]any{"role": "assistant", "model": model, "content": []any{
			map[string]any{"type": "thinking", "thinking": "pondering " + text},
			map[string]any{"type": "text", "text": text},
		}},
	})
}

func assistantTool(i int, model, id, name string, input map[string]any) string {
	return jsonLine(map[string]any{
		"type": "assistant", "timestamp": ts(i),
		"message": map[string]any{"role": "assistant", "model": model, "content": []any{
			map[string]any{"type": "tool_use", "id": id, "name": name, "input": input},
		}},
	})
}

func toolResult(i int, id, text string) string {
	return jsonLine(map[string]any{
		"type": "user", "timestamp": ts(i),
		"message": map[string]any{"role": "user", "content": []any{
			map[string]any{"type": "tool_result", "tool_use_id": id, "content": text},
		}},
	})
}

// session builds a small synthetic transcript with a distinct word.
func session(cwd, word string) string {
	return userPrompt(0, cwd, "please look for "+word) +
		assistantText(1, "claude-test-1", "looking for "+word) +
		assistantTool(2, "claude-test-1", "toolu_"+word, "Bash", map[string]any{"command": "grep -r " + word + " ."}) +
		toolResult(3, "toolu_"+word, "found "+word+" twice")
}

func writeSession(t testing.TB, projects, projDir, id, content string) string {
	t.Helper()
	d := filepath.Join(projects, projDir)
	if err := os.MkdirAll(d, 0o700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(d, id+".jsonl")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func appendFile(t testing.TB, p, data string) {
	t.Helper()
	f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(data); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

// bumpMtime moves a file's mtime forward so a same-second rewrite is seen.
func bumpMtime(t testing.TB, p string, d time.Duration) {
	t.Helper()
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	m := st.ModTime().Add(d)
	if err := os.Chtimes(p, m, m); err != nil {
		t.Fatal(err)
	}
}

func readText(t testing.TB, e env, id string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(e.dir, "text", textName(id)))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func copyTree(t testing.TB, src, dst string) {
	t.Helper()
	err := filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		in, err := os.Open(p)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.Create(target)
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, in); err != nil {
			out.Close()
			return err
		}
		return out.Close()
	})
	if err != nil {
		t.Fatal(err)
	}
}

func sid(i int) string { return fmt.Sprintf("00000000-0000-4000-8000-%012d", i) }

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func countOccur(s, sub string) int { return strings.Count(s, sub) }
