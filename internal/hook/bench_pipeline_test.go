package hook

import "testing"

// BenchmarkDecideRead is one Read call with the default packs and no policy
// file: the path is normalised and the Read rules run. In real use every
// call is a fresh process; this measures the warm in-process part.
func BenchmarkDecideRead(b *testing.B) {
	f := newFx(b)
	in := f.tool("Read", map[string]any{"file_path": f.cwd + "/README.md"})
	for i := 0; i < b.N; i++ {
		Decide(in, f.env)
	}
}

// BenchmarkDecideBashNoOpinion is `git status` with the default packs.
func BenchmarkDecideBashNoOpinion(b *testing.B) {
	f := newFx(b)
	in := f.in("git status")
	for i := 0; i < b.N; i++ {
		Decide(in, f.env)
	}
}
