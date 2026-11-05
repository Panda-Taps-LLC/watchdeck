package match

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Panda-Taps-LLC/watchdeck/internal/shellparse"
)

// fixture is a fake home with three skills under ~/.claude/skills (S, S1,
// S2) and one skill whose real root is ~/.agents/skills/pdf reached through
// the symlink alias ~/.claude/skills/pdf. Every skill has scripts/{x.py,
// x.sh, x.js, a.py, b.py}, references/doc.md and SKILL.md.
type fixture struct {
	home, work      string
	S, S1, S2       string
	pdfReal, pdfAli string
	idx             *StaticIndex
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{home: t.TempDir(), work: t.TempDir()}
	mk := func(dir string) {
		for _, p := range []string{"scripts/x.py", "scripts/x.sh", "scripts/x.js", "scripts/a.py", "scripts/b.py", "references/doc.md", "SKILL.md"} {
			full := filepath.Join(dir, p)
			if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(full, []byte("# fixture\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	f.S = filepath.Join(f.home, ".claude", "skills", "S")
	f.S1 = filepath.Join(f.home, ".claude", "skills", "S1")
	f.S2 = filepath.Join(f.home, ".claude", "skills", "S2")
	f.pdfReal = filepath.Join(f.home, ".agents", "skills", "pdf")
	f.pdfAli = filepath.Join(f.home, ".claude", "skills", "pdf")
	for _, d := range []string{f.S, f.S1, f.S2, f.pdfReal} {
		mk(d)
	}
	if err := os.Symlink(f.pdfReal, f.pdfAli); err != nil {
		t.Fatal(err)
	}
	f.idx = NewStaticIndex(f.home,
		IndexedSkill{Name: "S", Dir: f.S},
		IndexedSkill{Name: "S1", Dir: f.S1},
		IndexedSkill{Name: "S2", Dir: f.S2},
		IndexedSkill{Name: "pdf", Dir: f.pdfReal, Aliases: []string{f.pdfAli}},
	)
	return f
}

// expand replaces @S@ @S1@ @S2@ @HOME@ @WORK@ placeholders.
func (f *fixture) expand(s string) string {
	r := strings.NewReplacer("@S1@", f.S1, "@S2@", f.S2, "@S@", f.S, "@HOME@", f.home, "@WORK@", f.work)
	return r.Replace(s)
}

type row struct {
	name   string
	cmd    string
	cwd    string            // placeholder form; "" means the neutral work dir
	env    map[string]string // nil means {HOME: home}
	skills []string
	conf   shellparse.Confidence
	reject bool   // FastReject must return true
	reason string // substring expected in Result.Reason (Low rows)
	needle *bool  // optional HasNeedle assertion
	single *bool  // optional IsSingleWatchdeckRun assertion
}

func bp(b bool) *bool { return &b }

func corpus() []row {
	return []row{
		// Command-recognition corpus from DESIGN.md §4, in order.
		{name: "abs python", cmd: "python3 @S@/scripts/x.py", skills: []string{"S"}, conf: shellparse.High},
		{name: "abs script", cmd: "@S@/scripts/x.sh", skills: []string{"S"}, conf: shellparse.High},
		{name: "dot-slash in skill cwd", cmd: "./scripts/x.sh", cwd: "@S@", skills: []string{"S"}, conf: shellparse.High},
		{name: "bash relative in skill cwd", cmd: "bash scripts/x.sh", cwd: "@S@", skills: []string{"S"}, conf: shellparse.High},
		{name: "cd then relative", cmd: "cd @S@ && python3 scripts/x.py", skills: []string{"S"}, conf: shellparse.High},
		{name: "$HOME double-quoted alias", cmd: `python3 "$HOME/.claude/skills/pdf/scripts/x.py"`, skills: []string{"pdf"}, conf: shellparse.High},
		{name: "tilde alias", cmd: "python3 ~/.claude/skills/pdf/scripts/x.py", skills: []string{"pdf"}, conf: shellparse.High},
		{name: "CLAUDE_SKILL_DIR", cmd: "python3 ${CLAUDE_SKILL_DIR}/scripts/x.py", env: map[string]string{"CLAUDE_SKILL_DIR": "@S@"}, skills: []string{"S"}, conf: shellparse.High},
		{name: "uv run", cmd: "uv run @S@/scripts/x.py", skills: []string{"S"}, conf: shellparse.High},
		{name: "node pipe tee", cmd: "node @S@/scripts/x.js | tee out.txt", skills: []string{"S"}, conf: shellparse.High},
		{name: "env prefix assign", cmd: "FOO=1 python3 @S@/scripts/x.py", skills: []string{"S"}, conf: shellparse.High},
		{name: "and-then git", cmd: "python3 @S@/scripts/x.py && git status", skills: []string{"S"}, conf: shellparse.High},
		{name: "two skills", cmd: "python3 @S1@/scripts/a.py; python3 @S2@/scripts/b.py", skills: []string{"S1", "S2"}, conf: shellparse.High},
		{name: "cat SKILL.md", cmd: "cat @S@/SKILL.md", conf: shellparse.None, needle: bp(true)},
		{name: "grep references", cmd: "grep -r foo @S@/references/", conf: shellparse.None, needle: bp(true)},
		{name: "git status", cmd: "git status", conf: shellparse.None, reject: true, needle: bp(false)},
		{name: "python -c print", cmd: "python3 -c 'print(1)'", conf: shellparse.None, reject: true, needle: bp(false)},
		{name: "cat pipe python", cmd: "cat @S@/scripts/x.py | python3", skills: []string{"S"}, conf: shellparse.Low, reason: "stdin"},
		{name: "python dash redirect", cmd: "python3 - < @S@/scripts/x.py", conf: shellparse.Low, reason: "stdin"},
		{name: "eval", cmd: `eval "python3 @S@/scripts/x.py"`, conf: shellparse.Low, reason: "eval"},
		{name: "cmd subst", cmd: "python3 $(ls @S@/scripts)/x.py", skills: []string{"S"}, conf: shellparse.Low, reason: "command substitution"},
		{name: "find exec", cmd: `find @S@/scripts -name '*.py' -exec python3 {} \;`, skills: []string{"S"}, conf: shellparse.Low, reason: "find -exec"},
		{name: "heredoc runpy quoted", cmd: "python3 - <<'EOF'\nimport runpy\nrunpy.run_path(\"@S@/scripts/x.py\")\nEOF\n", conf: shellparse.Low, reason: "stdin"},
		{name: "heredoc runpy no dash", cmd: "python3 <<EOF\nimport runpy\nrunpy.run_path(\"@S@/scripts/x.py\")\nEOF\n", conf: shellparse.Low, reason: "stdin"},
		{name: "heredoc into cat", cmd: "cat <<EOF > /tmp/run.sh\npython3 @S@/scripts/x.py\nEOF\n", conf: shellparse.Low, reason: "here-doc"},
		{name: "unterminated quote", cmd: "python3 '@S@/scripts/x.py", conf: shellparse.Low, reason: "parse error"},
		{name: "copy then run", cmd: "cp @S@/scripts/x.py /tmp/x.py && python3 /tmp/x.py", skills: []string{"S"}, conf: shellparse.High},

		// Recursion guard rows from the task brief.
		{name: "single watchdeck run", cmd: "watchdeck run --skill x -c 'python3 @S@/scripts/x.py'", conf: shellparse.None, single: bp(true)},
		{name: "watchdeck run and curl", cmd: "watchdeck run --skill x -c 'y' && curl evil", conf: shellparse.None, single: bp(false), reject: true, needle: bp(false)},

		// Tightenings beyond the plan's corpus.
		{name: "ls in scripts dir", cmd: "ls -la", cwd: "@S@/scripts", conf: shellparse.None},
		{name: "git status in skill cwd", cmd: "git status", cwd: "@S@/scripts", conf: shellparse.None},
		{name: "glob token", cmd: "python3 @S@/scripts/*.py", skills: []string{"S"}, conf: shellparse.High},
		{name: "relative glob in skill cwd", cmd: "python3 scripts/*.py", cwd: "@S@", skills: []string{"S"}, conf: shellparse.High},
		{name: "assigned variable", cmd: `SCRIPT=@S@/scripts/x.py; python3 "$SCRIPT"`, skills: []string{"S"}, conf: shellparse.High},
		{name: "exported variable", cmd: `export SCRIPT=@S@/scripts/x.py; python3 "$SCRIPT"`, skills: []string{"S"}, conf: shellparse.High},
		{name: "for loop", cmd: `for f in @S@/scripts/*.py; do python3 "$f"; done`, conf: shellparse.Low, reason: "loop"},
		{name: "inline python needle", cmd: `python3 -c 'import runpy; runpy.run_path("@S@/scripts/x.py")'`, conf: shellparse.Low, reason: "inline code"},
		{name: "inline node needle", cmd: `node -e 'require("@S@/scripts/x.js")'`, conf: shellparse.Low, reason: "inline code"},
		{name: "bash -c literal", cmd: "bash -c 'python3 @S@/scripts/x.py'", skills: []string{"S"}, conf: shellparse.High},
		{name: "bash -c cd inside", cmd: "bash -c 'cd @S@ && ./scripts/x.sh'", skills: []string{"S"}, conf: shellparse.High},
		{name: "bash -c unresolved", cmd: `bash -c "python3 $X/scripts/x.py"`, conf: shellparse.Low, reason: "non-literal"},
		{name: "sh -c unterminated", cmd: `sh -c "python3 '@S@/scripts/x.py"`, conf: shellparse.Low, reason: "parse error"},
		{name: "unresolved non-path arg", cmd: "python3 @S@/scripts/x.py --out $OUT", skills: []string{"S"}, conf: shellparse.High},
		{name: "unresolved path var", cmd: "python3 $DIR/scripts/x.py", conf: shellparse.Low, reason: "unresolved"},
		{name: "unresolved argv0", cmd: "$PY @S@/scripts/x.py", skills: []string{"S"}, conf: shellparse.Low, reason: "unresolved"},
		{name: "exec builtin", cmd: "exec python3 @S@/scripts/x.py", skills: []string{"S"}, conf: shellparse.Low, reason: "exec"},
		{name: "source", cmd: "source @S@/scripts/x.sh", skills: []string{"S"}, conf: shellparse.Low, reason: "source"},
		{name: "dot source", cmd: ". @S@/scripts/x.sh", skills: []string{"S"}, conf: shellparse.Low, reason: "source"},
		{name: "xargs", cmd: "echo a | xargs python3 @S@/scripts/x.py", skills: []string{"S"}, conf: shellparse.Low, reason: "xargs"},
		{name: "process subst", cmd: "python3 <(cat @S@/scripts/x.py)", skills: []string{"S"}, conf: shellparse.Low, reason: "process substitution"},
		{name: "backticks", cmd: "python3 `ls @S@/scripts`/x.py", skills: []string{"S"}, conf: shellparse.Low, reason: "backtick"},
		{name: "cd into scripts", cmd: "cd @S@/scripts && python3 x.py", skills: []string{"S"}, conf: shellparse.High},
		{name: "two cds", cmd: "cd @S@ && cd scripts && ./x.sh", skills: []string{"S"}, conf: shellparse.High},
		{name: "subshell cd does not leak", cmd: "(cd @S@ && python3 scripts/x.py) && python3 scripts/x.py", skills: []string{"S"}, conf: shellparse.High},
		{name: "cd dash", cmd: "cd - && python3 scripts/x.py", conf: shellparse.Low, reason: "cd -"},
		{name: "cd home", cmd: "cd && python3 .claude/skills/S/scripts/x.py", skills: []string{"S"}, conf: shellparse.High},
		{name: "cd unresolved", cmd: "cd $D && python3 scripts/x.py", conf: shellparse.Low, reason: "cd to an unresolved"},
		{name: "background", cmd: "python3 @S@/scripts/x.py &", skills: []string{"S"}, conf: shellparse.High},
		{name: "python dot-slash in skill cwd", cmd: "python3 ./scripts/x.py", cwd: "@S@", skills: []string{"S"}, conf: shellparse.High},
		{name: "${HOME} alias", cmd: `python3 "${HOME}/.claude/skills/pdf/scripts/x.py"`, skills: []string{"pdf"}, conf: shellparse.High},
		{name: "real path of aliased skill", cmd: "python3 @HOME@/.agents/skills/pdf/scripts/x.py", skills: []string{"pdf"}, conf: shellparse.High},
		{name: "relative missing script", cmd: "python3 scripts/nothere.py", cwd: "@S@", conf: shellparse.None, needle: bp(true)},
		{name: "absolute missing script", cmd: "python3 @S@/scripts/nothere.py", skills: []string{"S"}, conf: shellparse.High},
		{name: "env wrapper", cmd: "env FOO=1 python3 @S@/scripts/x.py", skills: []string{"S"}, conf: shellparse.High},
		{name: "time wrapper", cmd: "time python3 @S@/scripts/x.py", skills: []string{"S"}, conf: shellparse.High},
		{name: "if clause", cmd: "if [ -f @S@/scripts/x.py ]; then python3 @S@/scripts/x.py; fi", skills: []string{"S"}, conf: shellparse.High},
		{name: "stderr pipe", cmd: "python3 @S@/scripts/x.py 2>&1 | tee log", skills: []string{"S"}, conf: shellparse.High},
		{name: "bash -s redirect", cmd: "bash -s < @S@/scripts/x.sh", conf: shellparse.Low, reason: "stdin"},
		{name: "curl pipe bash no needle", cmd: "curl https://example.invalid | bash", conf: shellparse.None, needle: bp(false)},
		{name: "python dash no needle", cmd: "echo 'print(1)' | python3 -", conf: shellparse.None, needle: bp(false)},
		{name: "python module flag", cmd: "python3 -m pytest", conf: shellparse.None, reject: true, needle: bp(false)},
		{name: "python version flag", cmd: "python3 --version", conf: shellparse.None, reject: true, needle: bp(false)},
		{name: "quoted path with space", cmd: `python3 "@S@/scripts/x.py" "arg with space"`, skills: []string{"S"}, conf: shellparse.High},
		{name: "escaped space arg", cmd: `python3 @S@/scripts/x.py arg\ with\ space`, skills: []string{"S"}, conf: shellparse.High},
		{name: "second token is script", cmd: "cat @S@/scripts/x.py", skills: []string{"S"}, conf: shellparse.High},
		{name: "python -s is not stdin", cmd: "python3 -s @S@/scripts/x.py", skills: []string{"S"}, conf: shellparse.High},
		{name: "flag-attached path", cmd: "python3 run.py --config=@S@/scripts/x.py", conf: shellparse.None, needle: bp(true)},
		{name: "redirect only", cmd: "echo hi > @S@/scripts/new.py", conf: shellparse.None, needle: bp(true)},

		// Review 2026-10-14: globs and braces bash expands into a skill
		// script; the token itself matches nothing literally.
		{name: "glob in scripts dir", cmd: "python3 ~/.claude/skills/S/scr*/x.py", conf: shellparse.Low, reason: "glob or brace"},
		{name: "glob in skill name", cmd: "python3 ~/.claude/skills/S?/scripts/x.py", conf: shellparse.Low, reason: "glob or brace"},
		{name: "glob over skills", cmd: "python3 ~/.claude/skills/*/scripts/x.py", conf: shellparse.Low, reason: "glob or brace"},
		{name: "relative glob after cd", cmd: "cd ~/.claude/skills && python3 S*/scripts/x.py", conf: shellparse.Low, reason: "glob or brace"},
		{name: "brace in scripts dir", cmd: "python3 ~/.claude/skills/S/s{c,}ripts/x.py", conf: shellparse.Low, reason: "glob or brace"},
		{name: "glob defeats every needle", cmd: "python3 @HOME@/.cl*/sk*/S/scr*/x.py", conf: shellparse.Low, reason: "glob or brace"},
		{name: "glob outside skills", cmd: "ls /tmp/*.log", conf: shellparse.None},

		// Review 2026-10-14: empty quotes or a backslash inside the path
		// break every raw-text needle; the parser unquotes them.
		{name: "empty quotes in path", cmd: "python3 ~/.claude/sk''ills/S/scr''ipts/x.py", skills: []string{"S"}, conf: shellparse.High, needle: bp(true)},
		{name: "backslash in path", cmd: `python3 ~/.cl\aude/sk\ills/S/scr\ipts/x.py`, skills: []string{"S"}, conf: shellparse.High, needle: bp(true)},
		{name: "empty quotes in cd", cmd: "cd ~/.claude/sk''ills/S/scr''ipts && python3 x.py", skills: []string{"S"}, conf: shellparse.High, needle: bp(true)},

		// Review 2026-10-14: directory changes besides plain cd and pushd.
		{name: "builtin cd", cmd: "builtin cd ~/.claude/skills/S && python3 scripts/x.py", skills: []string{"S"}, conf: shellparse.High},
		{name: "env -C", cmd: "env -C ~/.claude/skills/S python3 scripts/x.py", skills: []string{"S"}, conf: shellparse.High},
		{name: "env --chdir=", cmd: "env --chdir=@S@ python3 scripts/x.py", skills: []string{"S"}, conf: shellparse.High},
		{name: "env -C relative", cmd: "cd ~/.claude/skills && env -C S python3 scripts/x.py", skills: []string{"S"}, conf: shellparse.High},
		{name: "CDPATH prefix", cmd: "CDPATH=~/.claude/skills cd S && python3 scripts/x.py", conf: shellparse.Low, reason: "CDPATH"},
		{name: "CDPATH assigned", cmd: "CDPATH=~/.claude/skills; cd S && python3 scripts/x.py", conf: shellparse.Low, reason: "CDPATH"},
		{name: "CDPATH in env, absolute script", cmd: "cd S && python3 ~/.claude/skills/S/scripts/x.py", env: map[string]string{"CDPATH": "@HOME@/.claude/skills"}, skills: []string{"S"}, conf: shellparse.High},
		{name: "CDPATH dot-relative ok", cmd: "cd ./sub && python3 @S@/scripts/x.py", env: map[string]string{"CDPATH": "@HOME@"}, skills: []string{"S"}, conf: shellparse.High},
		{name: "find exec tilde", cmd: `find ~/.claude/skills/S/scripts -name x.py -exec python3 {} \;`, skills: []string{"S"}, conf: shellparse.Low, reason: "find -exec"},
	}
}

func TestCorpus(t *testing.T) {
	f := newFixture(t)
	for _, r := range corpus() {
		t.Run(r.name, func(t *testing.T) {
			cmd := f.expand(r.cmd)
			cwd := f.work
			if r.cwd != "" {
				cwd = f.expand(r.cwd)
			}
			env := map[string]string{"HOME": f.home}
			for k, v := range r.env {
				env[k] = f.expand(v)
			}
			if got := FastReject(cmd, cwd, f.idx); got != r.reject {
				t.Errorf("FastReject(%q, cwd=%q) = %v, want %v", cmd, cwd, got, r.reject)
			}
			res := Resolve(cmd, cwd, env, f.idx)
			if !reflect.DeepEqual(res.Skills, r.skills) {
				t.Errorf("Skills = %v, want %v (reason %q)", res.Skills, r.skills, res.Reason)
			}
			if res.Confidence != r.conf {
				t.Errorf("Confidence = %v, want %v (reason %q)", res.Confidence, r.conf, res.Reason)
			}
			if r.reason != "" && !strings.Contains(res.Reason, r.reason) {
				t.Errorf("Reason = %q, want it to contain %q", res.Reason, r.reason)
			}
			if r.conf == shellparse.High && res.Reason != "" {
				t.Errorf("High result carries a reason: %q", res.Reason)
			}
			if r.needle != nil && res.HasNeedle != *r.needle {
				t.Errorf("HasNeedle = %v, want %v", res.HasNeedle, *r.needle)
			}
			if r.conf != shellparse.None && r.reject {
				t.Errorf("row expects %v but also fast-reject; the hook would never reach Resolve", r.conf)
			}
			if r.single != nil {
				if got := shellparse.IsSingleWatchdeckRun(cmd); got != *r.single {
					t.Errorf("IsSingleWatchdeckRun = %v, want %v", got, *r.single)
				}
			}
		})
	}
}

func TestResolveTokenFromSymlinkedCwd(t *testing.T) {
	// cwd given through the alias; the script resolves to the real root.
	f := newFixture(t)
	res := Resolve("python3 scripts/x.py", f.pdfAli, map[string]string{"HOME": f.home}, f.idx)
	if !reflect.DeepEqual(res.Skills, []string{"pdf"}) || res.Confidence != shellparse.High {
		t.Fatalf("got %+v", res)
	}
	if FastReject("python3 scripts/x.py", f.pdfAli, f.idx) {
		t.Fatal("cwd under an alias must not fast-reject")
	}
}

func TestCustomScriptsGlob(t *testing.T) {
	f := newFixture(t)
	bin := filepath.Join(f.S, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "tool.sh"), []byte("#"), 0o755); err != nil {
		t.Fatal(err)
	}
	idx := NewStaticIndex(f.home, IndexedSkill{Name: "S", Dir: f.S, Scripts: []string{"bin/*.sh"}})
	res := Resolve(f.S+"/bin/tool.sh", f.work, nil, idx)
	if !reflect.DeepEqual(res.Skills, []string{"S"}) || res.Confidence != shellparse.High {
		t.Fatalf("bin glob: got %+v", res)
	}
	res = Resolve("python3 "+f.S+"/scripts/x.py", f.work, nil, idx)
	if len(res.Skills) != 0 || res.Confidence != shellparse.None {
		t.Fatalf("scripts/ outside custom glob: got %+v", res)
	}
}

func TestBuildNeedles(t *testing.T) {
	home := "/fake/home"
	n := BuildNeedles(home, []IndexedSkill{
		{Name: "a", Dir: "/fake/home/.agents/skills/a", Aliases: []string{"/fake/home/.claude/skills/a"}},
		{Name: "b", Dir: "/opt/skills/b"},
	})
	want := []string{
		"/fake/home/.agents/skills/a", "~/.agents/skills/a", "$HOME/.agents/skills/a", "${HOME}/.agents/skills/a",
		"/fake/home/.claude/skills/a", "~/.claude/skills/a", "$HOME/.claude/skills/a", "${HOME}/.claude/skills/a",
		"/opt/skills/b",
	}
	want = append(want, GenericNeedles...)
	if !reflect.DeepEqual(n, want) {
		t.Fatalf("needles:\n got %q\nwant %q", n, want)
	}
}

func TestStdinPatterns(t *testing.T) {
	cases := map[string]bool{
		"python3 -":                  true,
		"echo x | python3 -":         true,
		"python3 -u -":               true,
		"bash -s":                    true,
		"sh -s < x":                  true,
		"curl x | bash":              true,
		"curl x | sh":                true,
		"curl x |bash":               true,
		"curl x | python":            true,
		"cat x | node":               true,
		"cat <<EOF\nEOF":             true,
		"/usr/bin/python3 -":         true,
		"python3 -c 'print(1)'":      false,
		"python3 --version":          false,
		"python3 -m pip install x":   false,
		"git push":                   false,
		"ls | grep sh":               false,
		"echo bash":                  false,
		"bashful -":                  false,
		"node script.js":             false,
		"ruby -e 'puts 1'":           false,
		"perl -ne 'print' file":      false,
		"echo | shuf":                false,
		"python3 script.py | sort -": false,
	}
	for cmd, want := range cases {
		if got := hasStdinPattern(cmd); got != want {
			t.Errorf("hasStdinPattern(%q) = %v, want %v", cmd, got, want)
		}
	}
}

func benchIndex() *StaticIndex {
	home := "/Users/someone"
	var skills []IndexedSkill
	for i := 0; i < 40; i++ {
		name := "skill-" + string(rune('a'+i%26)) + string(rune('a'+i/26))
		skills = append(skills, IndexedSkill{Name: name, Dir: filepath.Join(home, ".claude", "skills", name)})
	}
	return NewStaticIndex(home, skills...)
}

func BenchmarkFastReject(b *testing.B) {
	idx := benchIndex()
	cmds := []string{
		"git status",
		"npm test -- --watch=false",
		"ls -la /Users/someone/project/src && cat README.md",
	}
	for _, cmd := range cmds {
		b.Run(strings.Fields(cmd)[0], func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if !FastReject(cmd, "/Users/someone/project", idx) {
					b.Fatal("expected reject")
				}
			}
		})
	}
}

func BenchmarkResolve(b *testing.B) {
	idx := benchIndex()
	cmd := "python3 /Users/someone/.claude/skills/skill-aa/scripts/x.py --out /tmp/o"
	b.ReportAllocs()
	for b.Loop() {
		Resolve(cmd, "/Users/someone/project", map[string]string{"HOME": "/Users/someone"}, idx)
	}
}
