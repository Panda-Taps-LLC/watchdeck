package sessionindex

import (
	"fmt"
	"strings"
	"testing"
)

// benchProjects writes 1000 small synthetic sessions (about 40 rows, ~10 KB
// each) over 10 project dirs in a temp dir. One session in 100 carries the
// word "rarekeyword".
func benchProjects(b *testing.B) env {
	b.Helper()
	e := newEnv(b)
	filler := strings.Repeat("some ordinary tool output line ", 8)
	for i := 0; i < 1000; i++ {
		var sb strings.Builder
		cwd := fmt.Sprintf("/Users/you/proj%d", i%10)
		sb.WriteString(userPrompt(0, cwd, fmt.Sprintf("task number %d", i)))
		for j := 0; j < 13; j++ {
			id := fmt.Sprintf("toolu_%d_%d", i, j)
			sb.WriteString(assistantText(3*j+1, modelTest, "working on step "+fmt.Sprint(j)))
			sb.WriteString(assistantTool(3*j+2, modelTest, id, "Bash", map[string]any{"command": "ls -la src/" + fmt.Sprint(j)}))
			sb.WriteString(toolResult(3*j+3, id, filler))
		}
		if i%100 == 0 {
			sb.WriteString(assistantText(99, modelTest, "found the rarekeyword here"))
		}
		writeSession(b, e.projects, fmt.Sprintf("-Users-you-proj%d", i%10), sid(i), sb.String())
	}
	return e
}

func BenchmarkIndex1000Sessions(b *testing.B) {
	e := benchProjects(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		if err := Purge(Options{Dir: e.dir}); err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
		ix, err := Open(Options{Dir: e.dir, ProjectsDir: e.projects})
		if err != nil {
			b.Fatal(err)
		}
		st, err := ix.Update()
		if err != nil || st.Sessions != 1000 {
			b.Fatalf("%v %+v", err, st)
		}
	}
}

func BenchmarkUpdateUnchanged1000Sessions(b *testing.B) {
	e := benchProjects(b)
	if _, err := e.open(b).Update(); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ix := e.open(b)
		if st, err := ix.Update(); err != nil || st.Unchanged != 1000 {
			b.Fatalf("%v %+v", err, st)
		}
	}
}

func BenchmarkSearch1000Sessions(b *testing.B) {
	e := benchProjects(b)
	ix := e.open(b)
	if _, err := ix.Update(); err != nil {
		b.Fatal(err)
	}
	for _, q := range []string{"rarekeyword", "absent-term", "Über"} {
		b.Run(q, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if _, err := ix.Search(q, 50); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
