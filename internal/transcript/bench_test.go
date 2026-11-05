package transcript

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// BenchmarkLoad32MiB is the V13 check (Spec B §10): a 32 MiB main file with
// realistic rows must load well under 300 ms. Not run by default:
//
//	go test ./internal/transcript -run '^$' -bench Load32MiB -benchtime 3x
func BenchmarkLoad32MiB(b *testing.B) {
	projects := filepath.Join(b.TempDir(), "projects")
	dir := filepath.Join(projects, "-Users-you-proj")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		b.Fatal(err)
	}
	path := filepath.Join(dir, "bench.jsonl")
	f, err := os.Create(path)
	if err != nil {
		b.Fatal(err)
	}
	w := bufio.NewWriterSize(f, 1<<20)
	filler := strings.Repeat("x", 1500)
	var size int64
	for i := 0; size < DefaultMaxBytes+1<<20; i++ {
		ts := fmt.Sprintf("2026-10-12T10:%02d:%02d.000Z", (i/60)%60, i%60)
		var row string
		switch i % 4 {
		case 0:
			row = fmt.Sprintf(`{"type":"assistant","isSidechain":false,"message":{"model":"claude-opus-5-5","role":"assistant","content":[{"type":"tool_use","id":"toolu_%08d","name":"Bash","input":{"command":"python3 probe.py net","description":"%s"}}]},"uuid":"u%d","timestamp":"%s","cwd":"/Users/you/proj"}`, i, filler[:200], i, ts)
		case 1:
			row = fmt.Sprintf(`{"type":"user","isSidechain":false,"message":{"role":"user","content":[{"tool_use_id":"toolu_%08d","type":"tool_result","content":"net: DENIED(1)\n%s","is_error":false}]},"uuid":"u%d","timestamp":"%s","toolUseResult":{"stdout":"%s"}}`, i-1, filler, i, ts, filler)
		case 2:
			row = fmt.Sprintf(`{"type":"assistant","isSidechain":false,"message":{"model":"claude-opus-5-5","role":"assistant","content":[{"type":"tool_use","id":"toolu_%08d","name":"Read","input":{"file_path":"/Users/you/proj/%d.txt"}}]},"uuid":"u%d","timestamp":"%s"}`, i, i, i, ts)
		default:
			row = fmt.Sprintf(`{"type":"user","isSidechain":false,"message":{"role":"user","content":[{"tool_use_id":"toolu_%08d","type":"tool_result","content":"%s"}]},"uuid":"u%d","timestamp":"%s"}`, i-1, filler, i, ts)
		}
		n, err := w.WriteString(row + "\n")
		if err != nil {
			b.Fatal(err)
		}
		size += int64(n)
	}
	if err := w.Flush(); err != nil {
		b.Fatal(err)
	}
	if err := f.Close(); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s, err := Load(path, Options{ProjectsDir: projects})
		if err != nil {
			b.Fatal(err)
		}
		if !s.Truncated || len(s.Events) < 1000 {
			b.Fatalf("unexpected session: truncated %v events %d", s.Truncated, len(s.Events))
		}
	}
}
