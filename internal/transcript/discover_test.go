package transcript

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeFile(t *testing.T, p, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestEscapeProjectDir(t *testing.T) {
	// Observed on Claude Code 2.1.296, 2026-10-12 (zero-cost unauthenticated runs
	// under a temporary CLAUDE_CONFIG_DIR; see EscapeProjectDir).
	cases := map[string]string{
		"/Users/you/proj": "-Users-you-proj",
		// digits and existing dashes are kept; a leading "/" gives a leading "-"
		"/private/tmp/x-501/-Users-x-repo/0f1e2d3c-aaaa-4bbb-8ccc-000000000001/proj": "-private-tmp-x-501--Users-x-repo-0f1e2d3c-aaaa-4bbb-8ccc-000000000001-proj",
		// ".", "_", " ", "+" and "~" each become "-"
		"/p/a.b_c d+e~f": "-p-a-b-c-d-e-f",
		// one "-" per UTF-16 code unit: "é" one, an emoji two
		"/p/é😀x":                       "-p----x",
		"/Users/you/repo/.claude/wt/x": "-Users-you-repo--claude-wt-x",
		"":                             "",
	}
	for in, want := range cases {
		if got := EscapeProjectDir(in); got != want {
			t.Errorf("EscapeProjectDir(%q) = %q want %q", in, got, want)
		}
	}
	if UnescapeProjectDirGuess("-Users-you-proj") != "/Users/you/proj" {
		t.Error("UnescapeProjectDirGuess")
	}
	if UnescapeProjectDirGuess(EscapeProjectDir("/Users/you/my-proj")) != "/Users/you/my/proj" {
		t.Error("the unescape is documented as lossy on dashes")
	}
}

func TestValidID(t *testing.T) {
	for _, ok := range []string{sessionA, subagentA, "a", "A_b.c-d", "agent-x"} {
		if !ValidID(ok) {
			t.Errorf("%q should be valid", ok)
		}
	}
	for _, bad := range []string{"", ".", "..", "a/b", "../x", "a b", "a\x00", "é", "x" + string(make([]byte, 96))} {
		if ValidID(bad) {
			t.Errorf("%q should be invalid", bad)
		}
	}
	long := ""
	for i := 0; i < 96; i++ {
		long += "a"
	}
	if !ValidID(long) || ValidID(long+"a") {
		t.Error("length bound is 96")
	}
}

func TestDiscover(t *testing.T) {
	root := t.TempDir()
	projects := filepath.Join(root, "projects")
	cwd := "/Users/you/proj"
	esc := EscapeProjectDir(cwd)
	row := `{"type":"user","message":{"role":"user","content":"x"}}` + "\n"
	writeFile(t, filepath.Join(projects, esc, "s1.jsonl"), row)
	writeFile(t, filepath.Join(projects, esc, "s2.jsonl"), row+row)
	writeFile(t, filepath.Join(projects, esc, "notes.txt"), "no")
	writeFile(t, filepath.Join(projects, esc, "bad id.jsonl"), row)
	writeFile(t, filepath.Join(projects, esc, "s1", "subagents", "agent-a1.jsonl"), row)
	writeFile(t, filepath.Join(projects, esc, "s1", "subagents", "agent-a1.meta.json"), "{}")
	writeFile(t, filepath.Join(projects, esc, "s1", "subagents", "agent-a2.jsonl"), row)
	writeFile(t, filepath.Join(projects, esc, "s1", "subagents", "junk.jsonl"), row)
	if err := os.MkdirAll(filepath.Join(projects, esc, "adir.jsonl"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(projects, "-Users-you-other", "s3.jsonl"), row)
	writeFile(t, filepath.Join(projects, "-Users-you-other", "s4.jsonl"), row)
	outside := filepath.Join(root, "outside.jsonl")
	writeFile(t, outside, row)
	writeFile(t, filepath.Join(projects, "deep", "x", "s5.jsonl"), row)
	// distinct mtimes: s3 newest, then s1, then s2
	base := time.Date(2026, 10, 12, 10, 0, 0, 0, time.UTC)
	for i, name := range []string{"s2", "s1"} {
		if err := os.Chtimes(filepath.Join(projects, esc, name+".jsonl"), base, base.Add(time.Duration(i+1)*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chtimes(filepath.Join(projects, "-Users-you-other", "s3.jsonl"), base, base.Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}

	refs, err := Discover(PathsDeps{ClaudeProjectsDir: projects, Cwd: cwd, TranscriptPaths: []string{
		filepath.Join(projects, "-Users-you-other", "s3.jsonl"),
		filepath.Join(projects, esc, "s2.jsonl"), // also under cwd
		outside,
		filepath.Join(projects, esc, "..", "..", "outside.jsonl"),
		filepath.Join(projects, "deep", "x", "s5.jsonl"),
		filepath.Join(projects, esc, "s1", "subagents", "agent-a1.jsonl"),
		"",
	}})
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, r := range refs {
		ids = append(ids, r.ID)
	}
	if len(refs) != 3 || ids[0] != "s3" || ids[1] != "s1" || ids[2] != "s2" {
		t.Fatalf("refs: %v (%+v)", ids, refs)
	}
	s3, s1, s2 := refs[0], refs[1], refs[2]
	if s3.Source != "activity" || s3.CwdGuess != "/Users/you/other" || s3.ProjectDir != filepath.Join(projects, "-Users-you-other") {
		t.Errorf("s3: %+v", s3)
	}
	if s1.Source != "cwd" || s1.CwdGuess != cwd || s1.Subagents != 2 || s1.Size != int64(len(row)) || s1.Path != filepath.Join(projects, esc, "s1.jsonl") {
		t.Errorf("s1: %+v", s1)
	}
	if s2.Source != "cwd+activity" || s2.Subagents != 0 || s2.Size != int64(2*len(row)) {
		t.Errorf("s2: %+v", s2)
	}
}

func TestDiscoverDoesNotOpenFiles(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read mode-000 files")
	}
	projects := filepath.Join(t.TempDir(), "projects")
	p := filepath.Join(projects, "-Users-you-proj", "s1.jsonl")
	writeFile(t, p, "{}\n")
	if err := os.Chmod(p, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(p, 0o644) })
	refs, err := Discover(PathsDeps{ClaudeProjectsDir: projects, Cwd: "/Users/you/proj", TranscriptPaths: []string{p}})
	if err != nil || len(refs) != 1 || refs[0].Size != 3 || refs[0].Source != "cwd+activity" {
		t.Fatalf("refs %+v err %v", refs, err)
	}
	if _, err := Load(p, Options{ProjectsDir: projects}); err == nil {
		t.Error("Load must fail on an unreadable file (so the test proves Discover never opened it)")
	}
}

func TestDiscoverEdgeCases(t *testing.T) {
	if _, err := Discover(PathsDeps{}); !errors.Is(err, ErrNoProjectsDir) {
		t.Errorf("empty projects dir: %v", err)
	}
	refs, err := Discover(PathsDeps{ClaudeProjectsDir: filepath.Join(t.TempDir(), "missing"), Cwd: "/x"})
	if err != nil || len(refs) != 0 {
		t.Errorf("missing dir: %v %v", refs, err)
	}
	projects := filepath.Join(t.TempDir(), "projects")
	if err := os.MkdirAll(projects, 0o755); err != nil {
		t.Fatal(err)
	}
	refs, err = Discover(PathsDeps{ClaudeProjectsDir: projects})
	if err != nil || len(refs) != 0 {
		t.Errorf("no cwd, no paths: %v %v", refs, err)
	}
}

func TestDiscoverFixtures(t *testing.T) {
	projects := fixtureProjects(t, "e2e-canary")
	refs, err := Discover(PathsDeps{ClaudeProjectsDir: projects, Cwd: "/Users/you/proj"})
	if err != nil || len(refs) != 1 || refs[0].ID != sessionA || refs[0].Subagents != 1 || refs[0].Source != "cwd" {
		t.Fatalf("fixture A: %+v %v", refs, err)
	}
	// the hook's transcript_path, rebased from /Users/you/.claude/projects onto the fixture root
	rebased := filepath.Join(projects, "-Users-you-proj", sessionA+".jsonl")
	refs, err = Discover(PathsDeps{ClaudeProjectsDir: projects, TranscriptPaths: []string{rebased}})
	if err != nil || len(refs) != 1 || refs[0].Source != "activity" || refs[0].CwdGuess != "/Users/you/proj" {
		t.Fatalf("by transcript_path: %+v %v", refs, err)
	}
}

func TestPathSafety(t *testing.T) {
	root := t.TempDir()
	projects := filepath.Join(root, "projects")
	esc := "-Users-you-proj"
	good := filepath.Join(projects, esc, "ok.jsonl")
	writeFile(t, good, `{"type":"user","message":{"role":"user","content":"x"}}`+"\n")
	secret := filepath.Join(root, "secret.jsonl")
	writeFile(t, secret, `{"type":"user","message":{"role":"user","content":"secret"}}`+"\n")

	if _, err := Load(good, Options{}); !errors.Is(err, ErrNoProjectsDir) {
		t.Errorf("no projects dir: %v", err)
	}
	if _, err := Load(good, Options{ProjectsDir: projects}); err != nil {
		t.Errorf("good path: %v", err)
	}
	// a symlink from inside projects/ to a file outside is refused
	link := filepath.Join(projects, esc, "evil.jsonl")
	if err := os.Symlink(secret, link); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	if _, err := Load(link, Options{ProjectsDir: projects}); !errors.Is(err, ErrOutsideProjects) {
		t.Errorf("symlink out: %v", err)
	}
	// a symlinked directory inside projects/ pointing outside is refused too
	if err := os.Symlink(root, filepath.Join(projects, "-Users-evil")); err == nil {
		if _, err := Load(filepath.Join(projects, "-Users-evil", "secret.jsonl"), Options{ProjectsDir: projects}); !errors.Is(err, ErrOutsideProjects) {
			t.Errorf("symlinked dir out: %v", err)
		}
	}
	// "../" in the id, an id with a space, and a wrong depth
	for _, p := range []string{
		filepath.Join(projects, esc, "..", "..", "secret.jsonl"),
		projects + "/" + esc + "/../../secret.jsonl",
		filepath.Join(projects, esc, "bad id.jsonl"),
		filepath.Join(projects, esc, "ok.txt"),
		filepath.Join(projects, "ok.jsonl"),
		filepath.Join(projects, esc, "deeper", "ok.jsonl"),
		secret,
	} {
		_, err := Load(p, Options{ProjectsDir: projects})
		if err == nil {
			t.Errorf("%s: expected refusal", p)
		} else if !errors.Is(err, ErrBadID) && !errors.Is(err, ErrOutsideProjects) && !os.IsNotExist(err) {
			t.Errorf("%s: unexpected error %v", p, err)
		}
	}
	// the projects dir itself may be reached through a symlink (macOS /var -> /private/var)
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(projects, alias); err == nil {
		if _, err := Load(filepath.Join(alias, esc, "ok.jsonl"), Options{ProjectsDir: alias}); err != nil {
			t.Errorf("projects dir via symlink: %v", err)
		}
		if _, err := Load(filepath.Join(alias, esc, "ok.jsonl"), Options{ProjectsDir: projects}); err != nil {
			t.Errorf("path via symlink, dir direct: %v", err)
		}
	}
	// Discover applies the same rule to transcript paths
	refs, err := Discover(PathsDeps{ClaudeProjectsDir: projects, TranscriptPaths: []string{link, secret, good}})
	if err != nil || len(refs) != 1 || refs[0].ID != "ok" {
		t.Errorf("Discover safety: %+v %v", refs, err)
	}
}

func TestDiscoverLongCwd(t *testing.T) {
	// Claude Code cuts an escaped name over 200 characters and appends "-<hash>"
	// (observed 2026-10-12: "-" plus 6 characters). Discover finds it by prefix.
	projects := filepath.Join(t.TempDir(), "projects")
	long := "/Users/you/" + strings.Repeat("x", 120) + "/" + strings.Repeat("y", 120)
	esc := EscapeProjectDir(long)
	if len(esc) <= ProjectDirMaxLen {
		t.Fatalf("test cwd too short: %d", len(esc))
	}
	row := `{"type":"user","message":{"role":"user","content":"x"}}` + "\n"
	writeFile(t, filepath.Join(projects, esc[:ProjectDirMaxLen]+"-rgnak9", "s1.jsonl"), row)
	writeFile(t, filepath.Join(projects, esc[:ProjectDirMaxLen]+"-not.alnum", "s9.jsonl"), row)
	refs, err := Discover(PathsDeps{ClaudeProjectsDir: projects, Cwd: long})
	if err != nil || len(refs) != 1 || refs[0].ID != "s1" || refs[0].CwdGuess != long {
		t.Fatalf("long cwd: %+v %v", refs, err)
	}
	// a second candidate with the same prefix makes the cwd ambiguous: nothing by cwd
	writeFile(t, filepath.Join(projects, esc[:ProjectDirMaxLen]+"-abc123", "s2.jsonl"), row)
	refs, err = Discover(PathsDeps{ClaudeProjectsDir: projects, Cwd: long})
	if err != nil || len(refs) != 0 {
		t.Fatalf("ambiguous long cwd must list nothing: %+v %v", refs, err)
	}
	// the activity log's transcript_path still finds it
	refs, err = Discover(PathsDeps{ClaudeProjectsDir: projects, Cwd: long, TranscriptPaths: []string{filepath.Join(projects, esc[:ProjectDirMaxLen]+"-abc123", "s2.jsonl")}})
	if err != nil || len(refs) != 1 || refs[0].ID != "s2" || refs[0].Source != "activity" {
		t.Fatalf("by transcript_path: %+v %v", refs, err)
	}
}

func TestDiscoverSymlinkedDirsOutside(t *testing.T) {
	root := t.TempDir()
	projects := filepath.Join(root, "projects")
	outside := filepath.Join(root, "outside")
	row := `{"type":"user","message":{"role":"user","content":"x"}}` + "\n"
	writeFile(t, filepath.Join(outside, "s1.jsonl"), row)
	writeFile(t, filepath.Join(outside, "s1", "subagents", "agent-o1.jsonl"), row)
	writeFile(t, filepath.Join(outside, "subs", "agent-o2.jsonl"), row)
	writeFile(t, filepath.Join(outside, "subs", "agent-o3.jsonl"), row)
	if err := os.MkdirAll(projects, 0o755); err != nil {
		t.Fatal(err)
	}

	// a project dir that is a symlink to a directory outside projects/ is not listed
	if err := os.Symlink(outside, filepath.Join(projects, "-Users-you-proj")); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	refs, err := Discover(PathsDeps{ClaudeProjectsDir: projects, Cwd: "/Users/you/proj"})
	if err != nil || len(refs) != 0 {
		t.Errorf("symlinked project dir outside: %+v %v", refs, err)
	}

	// a real session whose subagents dir is a symlink to outside counts no subagents
	writeFile(t, filepath.Join(projects, "-Users-you-real", "s2.jsonl"), row)
	if err := os.MkdirAll(filepath.Join(projects, "-Users-you-real", "s2"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "subs"), filepath.Join(projects, "-Users-you-real", "s2", "subagents")); err != nil {
		t.Fatal(err)
	}
	refs, err = Discover(PathsDeps{ClaudeProjectsDir: projects, Cwd: "/Users/you/real"})
	if err != nil || len(refs) != 1 || refs[0].ID != "s2" || refs[0].Subagents != 0 {
		t.Errorf("symlinked subagents dir outside: %+v %v", refs, err)
	}

	// a project dir symlinked to another project dir inside projects/ is still listed
	if err := os.Symlink(filepath.Join(projects, "-Users-you-real"), filepath.Join(projects, "-Users-you-alias")); err != nil {
		t.Fatal(err)
	}
	refs, err = Discover(PathsDeps{ClaudeProjectsDir: projects, Cwd: "/Users/you/alias"})
	if err != nil || len(refs) != 1 || refs[0].ID != "s2" {
		t.Errorf("symlinked project dir inside: %+v %v", refs, err)
	}
}
