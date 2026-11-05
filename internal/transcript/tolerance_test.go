package transcript

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func removeFile(p string) error { return os.Remove(p) }

func TestUnknownFieldsAndTypesIgnored(t *testing.T) {
	projects, main := tempCopyOfA(t)
	base := loadA(t)
	appendTo(t, main, []byte(
		`{"type":"future-kind","zzz":{"a":[1,2,{"b":null}]},"timestamp":"2026-10-13T02:19:00.000Z"}`+"\n"+
			`{"type":"file-history-snapshot","snapshot":{"files":[]}}`+"\n"+
			`{"type":"summary","summary":"x","leafUuid":"y"}`+"\n"+
			`{"type":"user","zzz":{"nested":true},"isSidechain":false,"message":{"role":"user","content":"a second prompt","extra":1},"uuid":"u-x","timestamp":"2026-10-13T02:19:01.000Z","cwd":"/Users/you/proj"}`+"\n"+
			`{"type":"assistant","isSidechain":false,"message":{"role":"assistant","model":"claude-future-9","content":[{"type":"tool_use","id":"toolu_future","name":"FutureTool","input":{"what":["ever"]},"zzz":1},{"type":"server_tool_use","id":"srv"},{"type":"thinking","thinking":"hidden"}]},"uuid":"a-x","timestamp":"2026-10-13T02:19:02.000Z"}`+"\n"))
	s, err := Load(main, Options{ProjectsDir: projects})
	if err != nil {
		t.Fatal(err)
	}
	if s.SkippedLines != 0 {
		t.Errorf("unknown rows must be ignored, not counted: %d", s.SkippedLines)
	}
	if len(s.Prompts) != len(base.Prompts)+1 || len(s.Events) != len(base.Events)+2 {
		t.Errorf("prompts %d events %d (base %d/%d)", len(s.Prompts), len(s.Events), len(base.Prompts), len(base.Events))
	}
	if c := s.Call("toolu_future"); c == nil || c.ToolCall.Name != "FutureTool" {
		t.Errorf("future tool: %+v", c)
	}
	if s.Agents[0].Model != "claude-future-9" {
		t.Errorf("last model wins: %q", s.Agents[0].Model)
	}
	if !s.LastEvent.Equal(mustTS("2026-10-13T02:19:02.000Z")) {
		t.Errorf("last event %v", s.LastEvent)
	}
}

func TestTruncatedLastLine(t *testing.T) {
	projects, main := tempCopyOfA(t)
	b, err := os.ReadFile(main)
	if err != nil {
		t.Fatal(err)
	}
	// cut the final row in the middle of its JSON, no trailing newline (a write in progress)
	cut := b[:len(b)-40]
	if err := os.WriteFile(main, cut, 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := Load(main, Options{ProjectsDir: projects})
	if err != nil {
		t.Fatal(err)
	}
	if s.SkippedLines != 1 {
		t.Errorf("skipped %d", s.SkippedLines)
	}
	base := loadA(t)
	if len(s.Events) != len(base.Events) { // the last row is the final assistant text, no event
		t.Errorf("events %d want %d", len(s.Events), len(base.Events))
	}
	if s.Truncated {
		t.Error("a cut last line is not a tail read")
	}
}

func TestCompleteLastLineWithoutNewlineIsSkipped(t *testing.T) {
	// Documented rule: a final line without "\n" is treated as in progress and skipped.
	projects, main := tempCopyOfA(t)
	appendTo(t, main, []byte(`{"type":"user","isSidechain":false,"message":{"role":"user","content":"tail"},"uuid":"u-t","timestamp":"2026-10-13T02:19:01.000Z"}`))
	s, err := Load(main, Options{ProjectsDir: projects})
	if err != nil {
		t.Fatal(err)
	}
	if s.SkippedLines != 1 || len(s.Prompts) != 1 {
		t.Errorf("skipped %d prompts %d", s.SkippedLines, len(s.Prompts))
	}
}

func TestNotJSONLineSkipped(t *testing.T) {
	projects, main := tempCopyOfA(t)
	appendTo(t, main, []byte("this is not json\n{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"ok\"},\"timestamp\":\"2026-10-13T02:19:01.000Z\"}\n\n"))
	s, err := Load(main, Options{ProjectsDir: projects})
	if err != nil {
		t.Fatal(err)
	}
	if s.SkippedLines != 1 || len(s.Prompts) != 2 {
		t.Errorf("skipped %d prompts %d", s.SkippedLines, len(s.Prompts))
	}
}

func TestOverLongLineSkipped(t *testing.T) {
	projects, main := tempCopyOfA(t)
	b, err := os.ReadFile(main)
	if err != nil {
		t.Fatal(err)
	}
	big := []byte(`{"type":"user","isSidechain":false,"message":{"role":"user","content":"` + strings.Repeat("x", 3<<20) + `"},"uuid":"u-big","timestamp":"2026-10-13T02:18:30.000Z"}` + "\n")
	if err := os.WriteFile(main, append(big, b...), 0o644); err != nil {
		t.Fatal(err)
	}
	base := loadA(t)
	s, err := Load(main, Options{ProjectsDir: projects}) // default MaxLine 2 MiB
	if err != nil {
		t.Fatal(err)
	}
	if s.SkippedLines != 1 || len(s.Prompts) != len(base.Prompts) || len(s.Events) != len(base.Events) {
		t.Errorf("3 MB line: skipped %d prompts %d events %d", s.SkippedLines, len(s.Prompts), len(s.Events))
	}
	s2, err := Load(main, Options{ProjectsDir: projects, MaxLine: 4 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if s2.SkippedLines != 0 || len(s2.Prompts) != len(base.Prompts)+1 {
		t.Errorf("with MaxLine 4 MiB: skipped %d prompts %d", s2.SkippedLines, len(s2.Prompts))
	}
}

func TestTailRead(t *testing.T) {
	projects := fixtureProjects(t, "e2e-canary")
	main := mainPath(projects, "-Users-you-proj", sessionA)
	sub := filepath.Join(projects, "-Users-you-proj", sessionA, "subagents", "agent-"+subagentA+".jsonl")
	full := loadA(t)

	// Cut the main file inside its Agent call row: the prompt, the Bash and
	// Read calls and the spawn itself are gone while the Agent result
	// survives. The cut is derived from the fixture's row offsets so the test
	// does not depend on exact file sizes.
	mainBytes, err := os.ReadFile(main)
	if err != nil {
		t.Fatal(err)
	}
	agentRow := bytes.Index(mainBytes, []byte(`"id":"`+agentA+`","name":"Agent"`))
	if agentRow < 0 {
		t.Fatal("fixture A has no Agent call row")
	}
	maxBytes := int64(len(mainBytes) - agentRow)
	subBytes, err := os.ReadFile(sub)
	if err != nil {
		t.Fatal(err)
	}
	// The subagent file is read with the same cap; the test needs its first
	// tool call (the Grep) to stay inside the tail.
	if grepRow := bytes.LastIndexByte(subBytes[:bytes.Index(subBytes, []byte(`"id":"`+grepA+`"`))], '\n'); int64(len(subBytes)) > maxBytes && int64(len(subBytes))-maxBytes > int64(grepRow) {
		t.Fatalf("fixture changed: a %d-byte tail of the subagent file drops its Grep row", maxBytes)
	}

	s, err := Load(main, Options{ProjectsDir: projects, MaxBytes: maxBytes})
	if err != nil {
		t.Fatal(err)
	}
	if !s.Truncated {
		t.Fatal("expected Truncated")
	}
	if len(s.Prompts) != 0 || s.Call(bashA) != nil || s.Call(readA) != nil || s.Call(agentA) != nil {
		t.Errorf("early rows should be missing: prompts %d bash %v read %v agent %v", len(s.Prompts), s.Call(bashA) != nil, s.Call(readA) != nil, s.Call(agentA) != nil)
	}
	// the result row's toolUseResult.agentId still marks it as the Agent return
	if r := s.Result(agentA); r == nil || r.Kind != "return" {
		t.Errorf("late rows must be intact: %+v", r)
	}
	if !s.LastEvent.Equal(full.LastEvent) {
		t.Errorf("last event %v want %v", s.LastEvent, full.LastEvent)
	}
	a := s.AgentByID(subagentA)
	if a == nil || a.Calls != 3 || s.Call(grepA) == nil {
		t.Fatalf("subagent calls inside the tail must load: %+v", a)
	}
	if fullSub := full.AgentByID(subagentA); int64(len(subBytes)) > maxBytes && !a.SpawnTS.After(fullSub.SpawnTS) {
		t.Errorf("a cut subagent file loses its first row: SpawnTS %v, full %v", a.SpawnTS, fullSub.SpawnTS)
	}
	// The spawn call itself is gone, so the subagent keeps its meta type but no link.
	if a.SpawnLink != "" || a.SpawnedBy != "" || a.Type != "Explore" {
		t.Errorf("spawn not seen must not be fabricated: %+v", a)
	}
	if s.SkippedLines != 0 {
		t.Errorf("the discarded partial first line is not counted: %d", s.SkippedLines)
	}
}

func TestSubagentsDirMissing(t *testing.T) {
	projects := t.TempDir() + "/projects"
	src := fixtureProjects(t, "e2e-canary")
	dir := projects + "/-Users-you-proj"
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(mainPath(src, "-Users-you-proj", sessionA))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mainPath(projects, "-Users-you-proj", sessionA), b, 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := Load(mainPath(projects, "-Users-you-proj", sessionA), Options{ProjectsDir: projects})
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Agents) != 1 || s.SkippedFiles != 0 {
		t.Errorf("agents %d skipped files %d", len(s.Agents), s.SkippedFiles)
	}
	sp := s.Call(agentA).ToolCall.Spawn
	if sp.AgentID != "" || sp.Confidence != "" {
		t.Errorf("no subagent file: spawn must stay unlinked: %+v", sp)
	}
	s2, err := Load(mainPath(src, "-Users-you-proj", sessionA), Options{ProjectsDir: src, SkipSubagents: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(s2.Agents) != 1 {
		t.Errorf("SkipSubagents: agents %d", len(s2.Agents))
	}
}

func TestBadSubagentFilesSkipped(t *testing.T) {
	projects, main := tempCopyOfA(t)
	subdir := projects + "/-Users-you-proj/" + sessionA + "/subagents"
	for _, name := range []string{"agent-bad id.jsonl", "agent-.jsonl", "agent-..jsonl", "notes.txt", "agent-ok.meta.json"} {
		p := subdir + "/" + name
		if err := os.WriteFile(p, []byte("{}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	s, err := Load(main, Options{ProjectsDir: projects})
	if err != nil {
		t.Fatal(err)
	}
	// the three agent-*.jsonl names fail ValidID (space, empty, ".") and are counted;
	// notes.txt and a meta file without a transcript are not transcripts at all.
	if len(s.Agents) != 2 || s.SkippedFiles != 3 {
		t.Errorf("agents %d skipped files %d", len(s.Agents), s.SkippedFiles)
	}
}

func TestMissingTimestampsSortLast(t *testing.T) {
	projects, main := tempCopyOfA(t)
	appendTo(t, main, []byte(`{"type":"assistant","isSidechain":false,"message":{"role":"assistant","content":[{"type":"tool_use","id":"toolu_nots","name":"Bash","input":{"command":"true"}}]},"uuid":"a-nots"}`+"\n"+
		`{"type":"assistant","isSidechain":false,"message":{"role":"assistant","content":[{"type":"tool_use","id":"toolu_late","name":"Bash","input":{"command":"true"}}]},"uuid":"a-late","timestamp":"2026-10-13T02:19:02.000Z"}`+"\n"))
	s, err := Load(main, Options{ProjectsDir: projects})
	if err != nil {
		t.Fatal(err)
	}
	last := s.Events[len(s.Events)-1]
	if last.ToolCall == nil || last.ToolCall.ID != "toolu_nots" || !last.TS.IsZero() {
		t.Errorf("row without timestamp must sort last: %+v", last)
	}
	if prev := s.Events[len(s.Events)-2]; prev.ToolCall == nil || prev.ToolCall.ID != "toolu_late" {
		t.Errorf("timed row before it: %+v", prev)
	}
}

func TestContentShapes(t *testing.T) {
	// string content, text-block content, tool_result as string and as block array, is_error absent and true
	projects, main := tempCopyOfA(t)
	appendTo(t, main, []byte(strings.Join([]string{
		`{"type":"user","isSidechain":false,"message":{"role":"user","content":[{"type":"text","text":"block "},{"type":"text","text":"prompt"}]},"uuid":"u1","timestamp":"2026-10-13T02:19:01.000Z"}`,
		`{"type":"assistant","isSidechain":false,"message":{"role":"assistant","content":[{"type":"tool_use","id":"toolu_s1","name":"Bash","input":{"command":"false"}}]},"uuid":"a1","timestamp":"2026-10-13T02:19:02.000Z"}`,
		`{"type":"user","isSidechain":false,"message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_s1","is_error":true,"content":[{"type":"text","text":"Exit code 1"},{"type":"text","text":"Operation not permitted"}]}]},"uuid":"u2","timestamp":"2026-10-13T02:19:03.000Z"}`,
		`{"type":"user","isSidechain":false,"isMeta":true,"message":{"role":"user","content":"<system-reminder>not a prompt</system-reminder>"},"uuid":"u3","timestamp":"2026-10-13T02:19:04.000Z"}`,
		`{"type":"user","isSidechain":false,"message":{"role":"user","content":""},"uuid":"u4","timestamp":"2026-10-13T02:19:05.000Z"}`,
	}, "\n")+"\n"))
	s, err := Load(main, Options{ProjectsDir: projects})
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Prompts) != 2 || s.Prompts[1].Summary != "block \nprompt" {
		t.Errorf("prompts: %+v", s.Prompts)
	}
	r := s.Result("toolu_s1")
	if r == nil || !r.IsError || r.Snippet != "Exit code 1\nOperation not permitted" {
		t.Errorf("block-array result: %+v", r)
	}
}

func TestLongCommandAndSnippetTruncatedOnRuneBoundary(t *testing.T) {
	projects, main := tempCopyOfA(t)
	cmd := strings.Repeat("é", 600) // 1200 bytes
	appendTo(t, main, []byte(`{"type":"assistant","isSidechain":false,"message":{"role":"assistant","content":[{"type":"tool_use","id":"toolu_long","name":"Bash","input":{"command":"`+cmd+`"}}]},"uuid":"al","timestamp":"2026-10-13T02:19:02.000Z"}`+"\n"+
		`{"type":"user","isSidechain":false,"message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_long","content":"`+cmd+`"}]},"uuid":"ul","timestamp":"2026-10-13T02:19:03.000Z"}`+"\n"))
	s, err := Load(main, Options{ProjectsDir: projects})
	if err != nil {
		t.Fatal(err)
	}
	c := s.Call("toolu_long").ToolCall.Command
	if len(c) != 512 || !strings.HasSuffix(c, "é") || !bytes.Equal([]byte(c), []byte(strings.Repeat("é", 256))) {
		t.Errorf("command truncation: len %d", len(c))
	}
	if sn := s.Result("toolu_long").Snippet; len(sn) != 240 || sn != strings.Repeat("é", 120) {
		t.Errorf("snippet truncation: len %d", len(sn))
	}
}

func TestBlankLinesIgnored(t *testing.T) {
	projects, main := tempCopyOfA(t)
	appendTo(t, main, []byte("\n  \n\r\n"))
	s, err := Load(main, Options{ProjectsDir: projects})
	if err != nil {
		t.Fatal(err)
	}
	if s.SkippedLines != 0 {
		t.Errorf("blank lines must not count as skipped: %d", s.SkippedLines)
	}
}

func TestMaxLineBelowReaderBuffer(t *testing.T) {
	// MaxLine must hold for lines that fit in one read, not only for lines
	// longer than the reader's internal buffer.
	projects, main := tempCopyOfA(t)
	appendTo(t, main, []byte(`{"type":"user","isSidechain":false,"message":{"role":"user","content":"`+strings.Repeat("y", 2048)+`"},"uuid":"u-mid","timestamp":"2026-10-13T02:19:01.000Z"}`+"\n"))
	s, err := Load(main, Options{ProjectsDir: projects, MaxLine: 1024})
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Prompts) != 1 || s.SkippedLines == 0 {
		t.Errorf("2 KB line with MaxLine 1 KiB: prompts %d skipped %d", len(s.Prompts), s.SkippedLines)
	}
}

func TestSubagentSymlinkOutsideRefused(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(root, "outside")
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(outside, "secret.jsonl")
	if err := os.WriteFile(secret, []byte(`{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","id":"toolu_secret","name":"Bash","input":{"command":"secret"}}]},"timestamp":"2026-10-13T02:19:01.000Z"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// a symlinked agent file inside a real subagents dir
	projects, main := tempCopyOfA(t)
	subdir := filepath.Join(projects, "-Users-you-proj", sessionA, "subagents")
	if err := os.Symlink(secret, filepath.Join(subdir, "agent-evil.jsonl")); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	s, err := Load(main, Options{ProjectsDir: projects})
	if err != nil {
		t.Fatal(err)
	}
	if s.SkippedFiles != 1 || s.AgentByID("evil") != nil || s.Call("toolu_secret") != nil || len(s.Agents) != 2 {
		t.Errorf("symlinked agent file: skipped %d agents %d secret call %v", s.SkippedFiles, len(s.Agents), s.Call("toolu_secret") != nil)
	}

	// a symlinked meta file next to a real agent file is ignored, not read
	projects2, main2 := tempCopyOfA(t)
	sub2 := filepath.Join(projects2, "-Users-you-proj", sessionA, "subagents")
	metaPath := filepath.Join(sub2, "agent-"+subagentA+".meta.json")
	evilMeta := filepath.Join(outside, "meta.json")
	if err := os.WriteFile(evilMeta, []byte(`{"agentType":"Evil","description":"from outside","toolUseId":"`+agentA+`"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(metaPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(evilMeta, metaPath); err != nil {
		t.Fatal(err)
	}
	s2, err := Load(main2, Options{ProjectsDir: projects2})
	if err != nil {
		t.Fatal(err)
	}
	if a := s2.AgentByID(subagentA); a == nil || a.Type == "Evil" || a.SpawnLink == "meta" {
		t.Errorf("symlinked meta must not be read: %+v", a)
	}

	// a subagents dir that is itself a symlink to outside
	projects3, main3 := tempCopyOfA(t)
	sessDir := filepath.Join(projects3, "-Users-you-proj", sessionA)
	if err := os.RemoveAll(sessDir); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(sessDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(secret, filepath.Join(outside, "agent-evil.jsonl")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(sessDir, "subagents")); err != nil {
		t.Fatal(err)
	}
	s3, err := Load(main3, Options{ProjectsDir: projects3})
	if err != nil {
		t.Fatal(err)
	}
	if len(s3.Agents) != 1 || s3.SkippedFiles != 1 || s3.Call("toolu_secret") != nil {
		t.Errorf("symlinked subagents dir: agents %d skipped %d", len(s3.Agents), s3.SkippedFiles)
	}
}
