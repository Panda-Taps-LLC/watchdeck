package transcript

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

const (
	sessionA  = "a9896c55-0b77-4f85-a0e0-9be2948b8aa6"
	subagentA = "a3033ade8c1d9c1a5"
	bashA     = "toolu_012ZTzbEFwgsQu4H4Zv1Sk2m" // main agent's probe call
	readA     = "toolu_01PEzFa65hdCYERmSZVb9Yej"
	agentA    = "toolu_01FZL82cF5JL9ZMVa4U5Psu4" // the Agent spawn
	grepA     = "toolu_01ArKPuK8AHT3nxPPygzf3GY" // subagent's Grep
	subBashA  = "toolu_01FfekpxjThEQTpTcNXLWp5S" // subagent's Bash
	handbackA = "toolu_01H9WTdMTLtDoVTWanw2vecL"

	sessionB = "b0000000-0000-4000-8000-00000000000b"
)

// fixtureProjects returns the absolute projects dir of a committed fixture.
func fixtureProjects(t *testing.T, name string) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join("testdata", name, "projects"))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func mainPath(projects, escaped, id string) string {
	return filepath.Join(projects, escaped, id+".jsonl")
}

func loadA(t *testing.T) *Session {
	t.Helper()
	projects := fixtureProjects(t, "e2e-canary")
	s, err := Load(mainPath(projects, "-Users-you-proj", sessionA), Options{ProjectsDir: projects})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func loadB(t *testing.T) *Session {
	t.Helper()
	projects := fixtureProjects(t, "synthetic-subagents")
	s, err := Load(mainPath(projects, "-Users-you-proj-b", sessionB), Options{ProjectsDir: projects})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// copyTree copies every regular file under src to the same relative path under dst.
func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
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

// tempCopyOfA copies fixture A into a temp projects dir and returns (projects, main path).
func tempCopyOfA(t *testing.T) (string, string) {
	t.Helper()
	projects := filepath.Join(t.TempDir(), "projects")
	copyTree(t, fixtureProjects(t, "e2e-canary"), projects)
	return projects, mainPath(projects, "-Users-you-proj", sessionA)
}

func appendTo(t *testing.T, path string, data []byte) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func countKind(s *Session, kind string) int {
	n := 0
	for _, e := range s.Events {
		if e.Kind == kind {
			n++
		}
	}
	return n
}

func toolNames(s *Session) map[string]int {
	m := map[string]int{}
	for _, e := range s.Events {
		if e.IsCall() {
			m[e.ToolCall.Name]++
		}
	}
	return m
}
