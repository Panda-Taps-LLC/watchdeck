package mapmodel

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/activity"
	"github.com/Panda-Taps-LLC/watchdeck/internal/manifest"
	"github.com/Panda-Taps-LLC/watchdeck/internal/transcript"
)

const (
	sidA = "a9896c55-0b77-4f85-a0e0-9be2948b8aa6"
	sidB = "b0000000-0000-4000-8000-00000000000b"
	// fixture A's two hook-stdin ids
	idMainProbe = "toolu_012ZTzbEFwgsQu4H4Zv1Sk2m"
	idSubGrep   = "toolu_01FfekpxjThEQTpTcNXLWp5S"
)

// loadFixture loads a session from internal/transcript/testdata through
// transcript.Load with Options.ProjectsDir, as the API layer does.
func loadFixture(t *testing.T, dir, project, sid string) *transcript.Session {
	t.Helper()
	projects, err := filepath.Abs(filepath.Join("..", "transcript", "testdata", dir, "projects"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := transcript.Load(filepath.Join(projects, project, sid+".jsonl"), transcript.Options{ProjectsDir: projects})
	if err != nil {
		t.Fatalf("load %s: %v", dir, err)
	}
	return s
}

func loadA(t *testing.T) *transcript.Session {
	return loadFixture(t, "e2e-canary", "-Users-you-proj", sidA)
}

func loadB(t *testing.T) *transcript.Session {
	return loadFixture(t, "synthetic-subagents", "-Users-you-proj-b", sidB)
}

// readRecs parses a JSONL activity file.
func readRecs(t *testing.T, path string) []activity.Record {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []activity.Record
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var r activity.Record
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		out = append(out, r)
	}
	return out
}

func recsA(t *testing.T) []activity.Record {
	return readRecs(t, filepath.Join("testdata", "activity-a.jsonl"))
}

// canaryRequest parses the repo's canary-request manifest.
func canaryRequest(t *testing.T) manifest.Manifest {
	t.Helper()
	m, err := manifest.Parse(filepath.Join("..", "..", "testdata", "skills", "canary-request", "PERMISSIONS.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// declaredWith builds Declared for the two canaries under a grant, with
// Ungranted computed by manifest.Clip so the test cannot drift from the
// real clipping rules.
func declaredWith(t *testing.T, requestGrant manifest.Effective) map[string]Declared {
	t.Helper()
	req := canaryRequest(t)
	_, ung := manifest.Clip(req, requestGrant)
	return map[string]Declared{
		"canary-request": {Skill: "canary-request", HasManifest: true, Request: req, Granted: requestGrant, Ungranted: ung},
		"canary-basic":   {Skill: "canary-basic", HasManifest: false, Granted: manifest.Default()},
	}
}

func declaredA(t *testing.T) map[string]Declared { return declaredWith(t, manifest.Default()) }

// optsA are the golden options: not live (Now is an hour after the session).
func optsA(s *transcript.Session, view string, hide bool) Options {
	return Options{View: view, HideNone: hide, Now: s.LastEvent.Add(time.Hour), Cwd: "/Users/you/proj"}
}

func mustJSON(t *testing.T, g Graph) []byte {
	t.Helper()
	b, err := json.MarshalIndent(g, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	return append(b, '\n')
}

func node(g Graph, id string) *Node {
	for i := range g.Nodes {
		if g.Nodes[i].ID == id {
			return &g.Nodes[i]
		}
	}
	return nil
}

func edge(g Graph, id string) *Edge {
	for i := range g.Edges {
		if g.Edges[i].ID == id {
			return &g.Edges[i]
		}
	}
	return nil
}

func skillDetail(t *testing.T, g Graph, id string) *SkillDetail {
	t.Helper()
	n := node(g, id)
	if n == nil {
		t.Fatalf("no node %s", id)
	}
	d, ok := n.Detail.(*SkillDetail)
	if !ok {
		t.Fatalf("%s detail is %T", id, n.Detail)
	}
	return d
}

func intp(n int) *int { return &n }
