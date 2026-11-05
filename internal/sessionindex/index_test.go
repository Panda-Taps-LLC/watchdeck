package sessionindex

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	sessionA  = "a9896c55-0b77-4f85-a0e0-9be2948b8aa6"
	projDirA  = "-Users-you-proj"
	modelTest = "claude-test-1"
)

func TestFixtureATitleAndMetadata(t *testing.T) {
	e := newEnv(t)
	src, err := filepath.Abs(filepath.Join("..", "transcript", "testdata", "e2e-canary", "projects"))
	if err != nil {
		t.Fatal(err)
	}
	copyTree(t, src, e.projects)
	ix, st := e.update(t)
	if st.Rebuilt != 1 || st.Sessions != 1 || st.Errors != 0 {
		t.Fatalf("stats: %+v", st)
	}
	en, ok := ix.Get(sessionA)
	if !ok {
		t.Fatal("fixture A not indexed")
	}
	if !strings.HasPrefix(en.Title, "Do exactly three things, nothing else") || len(en.Title) > titleLen {
		t.Errorf("title: %q", en.Title)
	}
	if en.Cwd != "/Users/you/proj" || en.GitBranch != "master" || en.CCVersion != "2.1.296" || en.Entrypoint != "sdk-cli" || en.ProjectDir != projDirA {
		t.Errorf("metadata: %+v", en)
	}
	if en.Harness != "claude-code" {
		t.Errorf("harness: %q", en.Harness)
	}
	if len(en.Models) != 1 || en.Models[0] != "claude-opus-5-5" {
		t.Errorf("models: %v", en.Models)
	}
	// main: Bash, Read, Agent; subagent: Grep, Bash, SubagentHandback
	if en.Turns != 1 || en.ToolCalls != 6 || en.Subagents != 1 || len(en.SubagentFiles) != 1 {
		t.Errorf("turns %d tool_calls %d subagents %d", en.Turns, en.ToolCalls, en.Subagents)
	}
	if !contains(en.Skills, "canary-basic") {
		t.Errorf("skills from the hook rewrite: %v", en.Skills)
	}
	if en.Truncated || en.TailRead || en.TextCapped || en.SkippedLines != 0 {
		t.Errorf("flags: %+v", en)
	}
	if en.FirstTS.IsZero() || !en.LastTS.After(en.FirstTS) {
		t.Errorf("timestamps: %v %v", en.FirstTS, en.LastTS)
	}
	fi, _ := os.Stat(filepath.Join(e.projects, projDirA, sessionA+".jsonl"))
	if en.Offset != fi.Size() || en.Size != fi.Size() {
		t.Errorf("offset %d size %d file %d", en.Offset, en.Size, fi.Size())
	}
	text := readText(t, e, sessionA)
	if int64(len(text)) != en.TextBytes {
		t.Errorf("text_bytes %d, file %d", en.TextBytes, len(text))
	}
	for _, want := range []string{"Do exactly three things", "probe.py net", "net: DENIED(1)", "Count 'canary' occurrences"} {
		if !strings.Contains(text, want) {
			t.Errorf("text lacks %q", want)
		}
	}
	hits, err := ix.Search("DENIED(1)", 10)
	if err != nil || len(hits) != 1 || hits[0].SessionID != sessionA {
		t.Fatalf("search: %v %+v", err, hits)
	}
}

func TestIncrementalAppend(t *testing.T) {
	e := newEnv(t)
	p := writeSession(t, e.projects, "-tmp-p1", sid(1), session("/tmp/p1", "alpha"))
	_, st := e.update(t)
	if st.Rebuilt != 1 {
		t.Fatalf("first: %+v", st)
	}
	_, st = e.update(t)
	if st.Unchanged != 1 || st.Rebuilt+st.Appended != 0 {
		t.Fatalf("unchanged: %+v", st)
	}
	before := readText(t, e, sid(1))

	// a write in progress: the final line has no newline and is not consumed
	line := userPrompt(10, "/tmp/p1", "second question about bravo")
	appendFile(t, p, line[:len(line)-10])
	bumpMtime(t, p, time.Second)
	ix, st := e.update(t)
	if st.Appended != 1 {
		t.Fatalf("partial append: %+v", st)
	}
	en, _ := ix.Get(sid(1))
	if en.Turns != 1 || strings.Contains(readText(t, e, sid(1)), "bravo") {
		t.Fatalf("partial line was indexed: turns %d", en.Turns)
	}
	appendFile(t, p, line[len(line)-10:]+assistantTool(11, "claude-test-2", "toolu_s", "Skill", map[string]any{"skill": "pdf"}))
	bumpMtime(t, p, 2*time.Second)
	ix, st = e.update(t)
	if st.Appended != 1 {
		t.Fatalf("append: %+v", st)
	}
	en, _ = ix.Get(sid(1))
	fi, _ := os.Stat(p)
	if en.Turns != 2 || en.ToolCalls != 2 || en.Offset != fi.Size() || en.Title != "please look for alpha" {
		t.Errorf("after append: %+v", en)
	}
	if !contains(en.Models, modelTest) || !contains(en.Models, "claude-test-2") || !contains(en.Skills, "pdf") {
		t.Errorf("models %v skills %v", en.Models, en.Skills)
	}
	after := readText(t, e, sid(1))
	if !strings.HasPrefix(after, before) || countOccur(after, "bravo") != 1 || countOccur(after, "please look for alpha") != 1 {
		t.Errorf("text not appended exactly once:\n%s", after)
	}
	if int64(len(after)) != en.TextBytes {
		t.Errorf("text_bytes %d file %d", en.TextBytes, len(after))
	}
}

func TestShrinkRebuilds(t *testing.T) {
	e := newEnv(t)
	p := writeSession(t, e.projects, "-tmp-p1", sid(1), session("/tmp/p1", "alpha")+session("/tmp/p1", "bravo"))
	e.update(t)
	if err := os.WriteFile(p, []byte(session("/tmp/p1", "charlie")), 0o600); err != nil {
		t.Fatal(err)
	}
	bumpMtime(t, p, time.Second)
	ix, st := e.update(t)
	if st.Rebuilt != 1 {
		t.Fatalf("stats: %+v", st)
	}
	text := readText(t, e, sid(1))
	if strings.Contains(text, "alpha") || !strings.Contains(text, "charlie") {
		t.Errorf("text after shrink: %s", text)
	}
	en, _ := ix.Get(sid(1))
	if en.Turns != 1 || en.Title != "please look for charlie" {
		t.Errorf("entry: %+v", en)
	}
}

func TestMtimeBackwardsRebuilds(t *testing.T) {
	e := newEnv(t)
	p := writeSession(t, e.projects, "-tmp-p1", sid(1), session("/tmp/p1", "alpha"))
	e.update(t)
	appendFile(t, p, session("/tmp/p1", "bravo"))
	bumpMtime(t, p, -time.Hour)
	_, st := e.update(t)
	if st.Rebuilt != 1 {
		t.Fatalf("stats: %+v", st)
	}
}

func TestSparseLargeFileHeadAndTail(t *testing.T) {
	e := newEnv(t)
	p := writeSession(t, e.projects, "-tmp-big", sid(7), userPrompt(0, "/tmp/big", "the head prompt"))
	big := int64(33 << 20)
	if err := os.Truncate(p, big); err != nil { // sparse: a 33 MiB run of zero bytes
		t.Fatal(err)
	}
	appendFile(t, p, "\n"+session("/tmp/big", "tailword"))
	ix, st := e.update(t)
	if st.Rebuilt != 1 || st.Errors != 0 {
		t.Fatalf("stats: %+v", st)
	}
	en, _ := ix.Get(sid(7))
	fi, _ := os.Stat(p)
	if !en.TailRead || !en.Truncated || en.TextCapped {
		t.Errorf("flags: %+v", en)
	}
	if en.Title != "the head prompt" || en.Cwd != "/tmp/big" {
		t.Errorf("head metadata: title %q cwd %q", en.Title, en.Cwd)
	}
	if en.Offset != fi.Size() || en.ToolCalls != 1 || en.Turns != 1 {
		t.Errorf("tail: offset %d size %d calls %d turns %d", en.Offset, fi.Size(), en.ToolCalls, en.Turns)
	}
	text := readText(t, e, sid(7))
	if strings.Contains(text, "the head prompt") || !strings.Contains(text, "tailword") {
		t.Errorf("text: %q", text)
	}
	if _, st = e.update(t); st.Unchanged != 1 {
		t.Errorf("second update: %+v", st)
	}
}

func TestPerSessionCap(t *testing.T) {
	e := newEnv(t)
	long := strings.Repeat("lorem ipsum ", 400) // ~4.8 KB
	p := writeSession(t, e.projects, "-tmp-cap", sid(3), session("/tmp/cap", "alpha")+toolResult(5, "toolu_alpha", long))
	capOpt := func(o *Options) { o.TextCap = 1000 }
	ix, _ := e.update(t, capOpt)
	en, _ := ix.Get(sid(3))
	text := readText(t, e, sid(3))
	if !en.TextCapped || !en.Truncated || en.TailRead {
		t.Errorf("flags: %+v", en)
	}
	if int64(len(text)) > 1000 || int64(len(text)) != en.TextBytes {
		t.Errorf("text %d bytes, text_bytes %d", len(text), en.TextBytes)
	}
	appendFile(t, p, session("/tmp/cap", "zulu"))
	bumpMtime(t, p, time.Second)
	ix, st := e.update(t, capOpt)
	en, _ = ix.Get(sid(3))
	if st.Appended != 1 || readText(t, e, sid(3)) != text || en.Turns != 2 {
		t.Errorf("capped append: %+v turns %d", st, en.Turns)
	}
}

func TestPermissions(t *testing.T) {
	e := newEnv(t)
	writeSession(t, e.projects, "-tmp-p1", sid(1), session("/tmp/p1", "alpha"))
	old := syscallUmask(0)
	defer syscallUmask(old)
	e.update(t)
	for p, want := range map[string]os.FileMode{
		e.dir:                                          0o700,
		filepath.Join(e.dir, "text"):                   0o700,
		filepath.Join(e.dir, "meta.json"):              0o600,
		filepath.Join(e.dir, ".lock"):                  0o600,
		filepath.Join(e.dir, "text", textName(sid(1))): 0o600,
	} {
		st, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != want {
			t.Errorf("%s: %v, want %v", p, st.Mode().Perm(), want)
		}
	}
	// a loose pre-existing dir is tightened
	if err := os.Chmod(e.dir, 0o755); err != nil {
		t.Fatal(err)
	}
	e.update(t)
	if st, _ := os.Stat(e.dir); st.Mode().Perm() != 0o700 {
		t.Errorf("dir not tightened: %v", st.Mode().Perm())
	}
}

func TestSymlinkOutsideProjectsRefused(t *testing.T) {
	e := newEnv(t)
	outside := filepath.Join(e.root, "outside")
	writeSession(t, outside, "-elsewhere", sid(1), session("/x", "secretword"))
	// a project dir that is a symlink leading outside
	if err := os.Symlink(filepath.Join(outside, "-elsewhere"), filepath.Join(e.projects, "-linked")); err != nil {
		t.Fatal(err)
	}
	// a session file that is a symlink leading outside
	if err := os.MkdirAll(filepath.Join(e.projects, "-real"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "-elsewhere", sid(1)+".jsonl"), filepath.Join(e.projects, "-real", sid(2)+".jsonl")); err != nil {
		t.Fatal(err)
	}
	// a subagents dir that is a symlink leading outside
	writeSession(t, e.projects, "-real", sid(3), session("/real", "insideword"))
	if err := os.MkdirAll(filepath.Join(e.projects, "-real", sid(3)), 0o700); err != nil {
		t.Fatal(err)
	}
	subOut := filepath.Join(outside, "subs")
	if err := os.MkdirAll(subOut, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subOut, "agent-a1.jsonl"), []byte(session("/x", "subsecret")), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(subOut, filepath.Join(e.projects, "-real", sid(3), "subagents")); err != nil {
		t.Fatal(err)
	}
	ix, st := e.update(t)
	if st.Sessions != 1 {
		t.Fatalf("sessions: %+v %+v", st, ix.Entries())
	}
	en, ok := ix.Get(sid(3))
	if !ok || en.Subagents != 0 {
		t.Fatalf("entry: %+v", en)
	}
	for _, q := range []string{"secretword", "subsecret"} {
		if hits, _ := ix.Search(q, 10); len(hits) != 0 {
			t.Errorf("%s found: %+v", q, hits)
		}
	}
}

func TestNoTranscriptsWritesNothing(t *testing.T) {
	e := newEnv(t)
	writeSession(t, e.projects, "-tmp-p1", sid(1), session("/tmp/p1", "alpha"))
	off := func(o *Options) { o.NoTranscripts = true }
	ix, st := e.update(t, off)
	if !st.Disabled || len(ix.Entries()) != 0 {
		t.Errorf("stats %+v", st)
	}
	if _, err := ix.Search("alpha", 5); err != ErrDisabled {
		t.Errorf("search: %v", err)
	}
	if _, err := ix.Rebuild(); err != nil {
		t.Error(err)
	}
	if _, err := os.Stat(filepath.Join(e.root, "state")); !os.IsNotExist(err) {
		t.Errorf("state dir created: %v", err)
	}
}

func TestPrune(t *testing.T) {
	e := newEnv(t)
	writeSession(t, e.projects, "-tmp-p1", sid(1), session("/tmp/p1", "alpha"))
	p2 := writeSession(t, e.projects, "-tmp-p1", sid(2), session("/tmp/p1", "bravo"))
	e.update(t)
	if err := os.Remove(p2); err != nil {
		t.Fatal(err)
	}
	ix, st := e.update(t)
	if st.Pruned != 1 || st.Sessions != 1 {
		t.Fatalf("stats: %+v", st)
	}
	if _, ok := ix.Get(sid(2)); ok {
		t.Error("pruned entry still present")
	}
	if _, err := os.Stat(filepath.Join(e.dir, "text", textName(sid(2)))); !os.IsNotExist(err) {
		t.Errorf("text file left: %v", err)
	}
	// reopened from disk, the prune holds
	if _, ok := e.open(t).Get(sid(2)); ok {
		t.Error("pruned entry in meta.json")
	}
}

func TestCrossProjectListing(t *testing.T) {
	e := newEnv(t)
	for i, d := range []string{"-Users-you-a", "-Users-you-b", "-Users-you-c"} {
		cwd := "/Users/you/" + string(rune('a'+i))
		writeSession(t, e.projects, d, sid(10+i), session(cwd, "w"+d))
		writeSession(t, e.projects, d, sid(20+i), session(cwd, "x"+d))
	}
	ix, st := e.update(t)
	if st.Sessions != 6 {
		t.Fatalf("stats: %+v", st)
	}
	byProj := map[string]int{}
	for _, en := range ix.Entries() {
		byProj[en.ProjectDir]++
		if en.Cwd != "/Users/you/"+en.ProjectDir[len(en.ProjectDir)-1:] {
			t.Errorf("cwd %q for %s", en.Cwd, en.ProjectDir)
		}
	}
	if len(byProj) != 3 || byProj["-Users-you-b"] != 2 {
		t.Errorf("projects: %v", byProj)
	}
	// reopening from meta.json gives the same listing
	if got := len(e.open(t).Entries()); got != 6 {
		t.Errorf("reopened: %d", got)
	}
}

func TestDuplicateIDNewestWins(t *testing.T) {
	e := newEnv(t)
	p1 := writeSession(t, e.projects, "-a", sid(1), session("/a", "older"))
	p2 := writeSession(t, e.projects, "-b", sid(1), session("/b", "newer"))
	bumpMtime(t, p1, -time.Hour)
	bumpMtime(t, p2, time.Hour)
	ix, st := e.update(t)
	if st.Sessions != 1 || st.Duplicates != 1 {
		t.Fatalf("stats: %+v", st)
	}
	if en, _ := ix.Get(sid(1)); en.ProjectDir != "-b" {
		t.Errorf("winner: %s", en.ProjectDir)
	}
}

func TestCrashAfterAppendReconciled(t *testing.T) {
	e := newEnv(t)
	writeSession(t, e.projects, "-tmp-p1", sid(1), session("/tmp/p1", "alpha"))
	e.update(t)
	tp := filepath.Join(e.dir, "text", textName(sid(1)))
	appendFile(t, tp, "duplicated text from a crashed append\n")
	_, st := e.update(t)
	if st.Unchanged != 1 {
		t.Fatalf("stats: %+v", st)
	}
	if strings.Contains(readText(t, e, sid(1)), "crashed") {
		t.Error("text not truncated back to text_bytes")
	}
	// a text file shorter than text_bytes rebuilds
	if err := os.Truncate(tp, 3); err != nil {
		t.Fatal(err)
	}
	if _, st = e.update(t); st.Rebuilt != 1 {
		t.Errorf("short text: %+v", st)
	}
}

func TestSubagentGrowthAndRemoval(t *testing.T) {
	e := newEnv(t)
	writeSession(t, e.projects, "-p", sid(1), session("/p", "alpha"))
	sub := filepath.Join(e.projects, "-p", sid(1), "subagents")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	sp := filepath.Join(sub, "agent-a1.jsonl")
	if err := os.WriteFile(sp, []byte(assistantTool(5, modelTest, "toolu_x", "Grep", map[string]any{"pattern": "subword"})), 0o600); err != nil {
		t.Fatal(err)
	}
	ix, _ := e.update(t)
	en, _ := ix.Get(sid(1))
	if en.Subagents != 1 || en.ToolCalls != 2 || en.Turns != 1 {
		t.Fatalf("entry: %+v", en)
	}
	appendFile(t, sp, assistantTool(6, modelTest, "toolu_y", "Read", map[string]any{"file_path": "/p/x"}))
	bumpMtime(t, sp, time.Second)
	ix, st := e.update(t)
	en, _ = ix.Get(sid(1))
	if st.Appended != 1 || en.ToolCalls != 3 {
		t.Fatalf("growth: %+v %+v", st, en)
	}
	if err := os.Remove(sp); err != nil {
		t.Fatal(err)
	}
	ix, st = e.update(t)
	en, _ = ix.Get(sid(1))
	if st.Rebuilt != 1 || en.Subagents != 0 || en.ToolCalls != 1 {
		t.Fatalf("removal: %+v %+v", st, en)
	}
}

func TestPurge(t *testing.T) {
	e := newEnv(t)
	writeSession(t, e.projects, "-p", sid(1), session("/p", "alpha"))
	e.update(t)
	if err := Purge(Options{Dir: filepath.Join(e.root, "state")}); err == nil {
		t.Error("purge of a non-index dir accepted")
	}
	if err := Purge(Options{Dir: e.dir}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(e.dir); !os.IsNotExist(err) {
		t.Errorf("index dir left: %v", err)
	}
}

func TestTitleSkipsCommandAndMetaRows(t *testing.T) {
	e := newEnv(t)
	content := jsonLine(map[string]any{"type": "user", "timestamp": ts(0), "message": map[string]any{"role": "user", "content": "<command-name>/pdf</command-name>\n<command-message>pdf</command-message>"}}) +
		jsonLine(map[string]any{"type": "user", "isMeta": true, "timestamp": ts(1), "message": map[string]any{"role": "user", "content": []any{map[string]any{"type": "text", "text": "Base directory for this skill: /x"}}}}) +
		toolResult(2, "toolu_1", "a result, not a prompt") +
		userPrompt(3, "/p", "  the   real\nprompt  ")
	writeSession(t, e.projects, "-p", sid(1), content)
	ix, _ := e.update(t)
	en, _ := ix.Get(sid(1))
	if en.Title != "the real prompt" || en.Turns != 1 {
		t.Errorf("title %q turns %d", en.Title, en.Turns)
	}
}

func TestRewriteSkills(t *testing.T) {
	for cmd, want := range map[string]string{
		"watchdeck run --skill pdf -c 'python3 x.py'":                           "pdf",
		"/opt/bin/watchdeck run --skill a --skill b -c 'x --skill nope'":        "a,b",
		"watchdeck run --skill=xlsx -c 'x'":                                     "xlsx",
		"echo watchdeck --skill nope":                                           "",
		"python3 .claude/skills/canary-basic/scripts/probe.py net --skill nope": "",
	} {
		if got := strings.Join(rewriteSkills(cmd), ","); got != want {
			t.Errorf("%q: got %q want %q", cmd, got, want)
		}
	}
}
