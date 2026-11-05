package shellparse

import (
	"math/rand/v2"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

var env = map[string]string{"HOME": "/h", "CLAUDE_SKILL_DIR": "/h/.claude/skills/s"}

func mustParse(t *testing.T, cmd, cwd string) *Program {
	t.Helper()
	p, err := Parse(cmd, cwd, env)
	if err != nil {
		t.Fatalf("Parse(%q): %v", cmd, err)
	}
	return p
}

func TestCwdTracking(t *testing.T) {
	cases := []struct {
		cmd  string
		want []Call
	}{
		{"cd /a && python3 x.py", []Call{{Argv: []string{"cd", "/a"}, Cwd: "/w"}, {Argv: []string{"python3", "x.py"}, Cwd: "/a"}}},
		{"cd a; cd b; ls", []Call{{Argv: []string{"cd", "a"}, Cwd: "/w"}, {Argv: []string{"cd", "b"}, Cwd: "/w/a"}, {Argv: []string{"ls"}, Cwd: "/w/a/b"}}},
		{"cd .. || ls", []Call{{Argv: []string{"cd", ".."}, Cwd: "/w"}, {Argv: []string{"ls"}, Cwd: "/"}}},
		{"cd /a | ls", []Call{{Argv: []string{"cd", "/a"}, Cwd: "/w"}, {Argv: []string{"ls"}, Cwd: "/a"}}},
		{"cd && ls", []Call{{Argv: []string{"cd"}, Cwd: "/w"}, {Argv: []string{"ls"}, Cwd: "/h"}}},
		{"cd -P /a && ls", []Call{{Argv: []string{"cd", "-P", "/a"}, Cwd: "/w"}, {Argv: []string{"ls"}, Cwd: "/a"}}},
		{"cd ~/x && ls", []Call{{Argv: []string{"cd", "/h/x"}, Cwd: "/w"}, {Argv: []string{"ls"}, Cwd: "/h/x"}}},
		{"(cd /a && ls) && ls", []Call{{Argv: []string{"cd", "/a"}, Cwd: "/w"}, {Argv: []string{"ls"}, Cwd: "/a"}, {Argv: []string{"ls"}, Cwd: "/w"}}},
		{"{ cd /a && ls; }; ls", []Call{{Argv: []string{"cd", "/a"}, Cwd: "/w"}, {Argv: []string{"ls"}, Cwd: "/a"}, {Argv: []string{"ls"}, Cwd: "/a"}}},
		{"pushd /a && ls", []Call{{Argv: []string{"pushd", "/a"}, Cwd: "/w"}, {Argv: []string{"ls"}, Cwd: "/a"}}},
		{"cd /a && echo $PWD", []Call{{Argv: []string{"cd", "/a"}, Cwd: "/w"}, {Argv: []string{"echo", "/a"}, Cwd: "/a"}}},
	}
	for _, c := range cases {
		p := mustParse(t, c.cmd, "/w")
		if !reflect.DeepEqual(p.Calls, c.want) {
			t.Errorf("%q:\n got %+v\nwant %+v", c.cmd, p.Calls, c.want)
		}
		if p.Confidence != High {
			t.Errorf("%q: confidence %v (%s)", c.cmd, p.Confidence, p.Reason)
		}
	}
}

func TestExpansion(t *testing.T) {
	cases := []struct {
		cmd  string
		want []string
	}{
		{`echo ~ ~/x "~/y" '~/z'`, []string{"echo", "/h", "/h/x", "~/y", "~/z"}},
		{`echo $HOME ${HOME} "$HOME/a" "${HOME}b"`, []string{"echo", "/h", "/h", "/h/a", "/hb"}},
		{`echo ${CLAUDE_SKILL_DIR}/s $CLAUDE_SKILL_DIR`, []string{"echo", "/h/.claude/skills/s/s", "/h/.claude/skills/s"}},
		{`echo $PWD "$PWD/x"`, []string{"echo", "/w", "/w/x"}},
		{`echo a\ b "c\"d" 'e'"f" $'g\th'`, []string{"echo", "a b", `c"d`, "ef", "g\th"}},
		{`echo "a\$b" "\\" "x\y"`, []string{"echo", "a$b", `\`, `x\y`}},
		{`X=/p/q; echo $X "$X/r"`, []string{"echo", "/p/q", "/p/q/r"}},
		{`X=/p Y=$X/q; echo $Y`, []string{"echo", "/p/q"}},
		{`echo --flag=~/x`, []string{"echo", "--flag=~/x"}},
		{`echo \~/x`, []string{"echo", "~/x"}},
		{`FOO=1 echo $FOO`, []string{"echo", "$FOO"}}, // prefix assignment is not recorded
	}
	for _, c := range cases {
		p := mustParse(t, c.cmd, "/w")
		if len(p.Calls) == 0 {
			t.Errorf("%q: no calls", c.cmd)
			continue
		}
		got := p.Calls[len(p.Calls)-1].Argv
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%q:\n got %q\nwant %q", c.cmd, got, c.want)
		}
	}
}

func TestLowReasons(t *testing.T) {
	cases := []struct{ cmd, reason string }{
		{"echo $(ls)", "command substitution"},
		{"echo `ls`", "backtick"},
		{"cat <(ls)", "process substitution"},
		{"eval ls", "eval"},
		{"source x.sh", "source"},
		{". x.sh", "source"},
		{"exec ls", "exec builtin"},
		{"ls | xargs rm", "xargs"},
		{`find . -exec rm {} \;`, "find -exec"},
		{`find . -execdir rm {} \;`, "find -exec"},
		{"echo $X/y", "unresolved expansion in path position: $X/y"},
		{"$X y", "unresolved expansion in path position: $X"},
		{"echo ${HOME:-/x}/y", "unresolved"},
		{"echo ~bob/x", "unresolved"},
		{"cd - && ls", "cd -"},
		{"cd $X && ls", "cd to an unresolved"},
		{"popd && ls", "popd"},
		{"for f in a b; do echo $f; done", "loop"},
		{"while true; do ls; done", "loop"},
		{"echo 'unterminated", "parse error"},
		{`bash -c "ls $X"`, "non-literal"},
		{"bash -c 'eval ls'", "nested bash -c: eval"},
		{"bash -c 'echo \"unterminated'", "parse error"},
		{"ls > $(x)", "command substitution"},
		{"X=$(ls); echo $X", "command substitution"},
		{"cat <<EOF\n$(ls)\nEOF\n", "command substitution"},
	}
	for _, c := range cases {
		p, _ := Parse(c.cmd, "/w", env)
		if p.Confidence != Low {
			t.Errorf("%q: confidence %v, want low", c.cmd, p.Confidence)
			continue
		}
		if !strings.Contains(p.Reason, c.reason) {
			t.Errorf("%q: reason %q, want it to contain %q", c.cmd, p.Reason, c.reason)
		}
	}
	highs := []string{
		"echo $X",                        // unresolved, not a path position
		"python3 /s/x.py --out $OUT",     // same
		"echo ${#X}",                     // same
		"FOO=$BAR ls",                    // assignment value, not argv
		"if [ -f x ]; then ls; fi",       // control flow without loops
		"case $x in a) ls;; esac",        // same
		"f() { ls; }; f",                 // function body
		"ls &",                           // background
		"time ls",                        // time wrapper
		"python3 x.py <<EOF\ninput\nEOF", // here-doc alone is not Low
		"bash -c 'cd /a && ls'",          // literal nested program
		"bash -lc 'ls'",                  // combined flag
	}
	for _, cmd := range highs {
		p, err := Parse(cmd, "/w", env)
		if err != nil || p.Confidence != High {
			t.Errorf("%q: confidence %v (%s) err=%v, want high", cmd, p.Confidence, p.Reason, err)
		}
	}
}

func TestParseError(t *testing.T) {
	p, err := Parse("echo 'x", "/w", env)
	if err == nil {
		t.Fatal("expected an error")
	}
	if p == nil || p.Confidence != Low || !strings.HasPrefix(p.Reason, "parse error: ") {
		t.Fatalf("got %+v", p)
	}
}

func TestStdinInterpreter(t *testing.T) {
	cases := map[string]bool{
		"python3 -":                        true,
		"python3 -u - < x.py":              true,
		"cat x.py | python3":               true,
		"cat x.py | python":                true,
		"cat x.py | python3 -u":            true,
		"python3 < x.py":                   true,
		"python3 <<EOF\nprint(1)\nEOF\n":   true,
		"python3 <<< 'print(1)'":           true,
		"node -":                           true,
		"curl x | node":                    true,
		"curl x | bash":                    true,
		"curl x | sh":                      true,
		"bash -s":                          true,
		"bash -s < x.sh":                   true,
		"bash -es":                         true,
		"ruby - < x.rb":                    true,
		"cat x.pl | perl":                  true,
		"env python3 -":                    true,
		"uv run python3 -":                 true,
		"cat x | bash -c 'python3 -'":      true,
		"a | b | python3":                  true,
		"cat x | python3 | sort":           true,
		"python3 x.py":                     false,
		"python3 -c 'print(1)'":            false,
		"python3 -m mod":                   false,
		"python3 -s x.py":                  false,
		"python3 -W ignore x.py":           false,
		"cat x.py | python3 y.py":          false,
		"python3 x.py < input.txt":         false,
		"python3 x.py 2< err":              false,
		"node -e 'x'":                      false,
		"node -r mod x.js":                 false,
		"node --eval=1":                    false,
		"bash x.sh":                        false,
		"bash -c 'ls'":                     false,
		"bash -- x.sh":                     false,
		"ruby -e 'puts 1'":                 false,
		"ruby -rjson x.rb":                 false,
		"perl -ne 'print' file":            false,
		"perl -e'print 1'":                 false,
		"cat x | grep y":                   false,
		"cat x | python3 x.py | sort":      false,
		"ls && python3 x.py":               false,
		"python3":                          false,
		"ls | tee out > /dev/null":         false,
		"python3 x.py <<EOF\ninput\nEOF\n": false,
	}
	for cmd, want := range cases {
		p, err := Parse(cmd, "/w", env)
		if err != nil {
			t.Errorf("%q: %v", cmd, err)
			continue
		}
		if p.StdinInterpreter != want {
			t.Errorf("%q: StdinInterpreter = %v, want %v", cmd, p.StdinInterpreter, want)
		}
	}
}

func TestHereDocs(t *testing.T) {
	cases := []struct {
		cmd  string
		want []string
	}{
		{"cat <<EOF\nline one\nline $x two\nEOF\n", []string{"line one\nline $x two\n"}},
		{"cat <<'EOF'\nquoted $x\nEOF\n", []string{"quoted $x\n"}},
		{"cat <<-EOF\n\tindented\n\tEOF\n", []string{"indented\n"}},
		{"cat <<<'here string'", []string{"here string"}},
		{"cat <<<\"$HOME/x\"", []string{"/h/x"}},
		{"python3 -c 'print(1)'", []string{"print(1)"}},
		{"node -e 'require(\"x\")'", []string{`require("x")`}},
		{"node --eval='1+1'", []string{"1+1"}},
		{"ruby -e 'puts 1'", []string{"puts 1"}},
		{"perl -e'print 1'", []string{"print 1"}},
		{"bash -c 'python3 -c \"import x\"'", []string{"import x"}},
		{"cat <<A\na\nA\ncat <<B\nb\nB\n", []string{"a\n", "b\n"}},
		{"ls", nil},
		{"bash -c 'ls'", nil},
	}
	for _, c := range cases {
		p, err := Parse(c.cmd, "/w", env)
		if err != nil {
			t.Errorf("%q: %v", c.cmd, err)
			continue
		}
		if !reflect.DeepEqual(p.HereDocs, c.want) {
			t.Errorf("%q: HereDocs = %q, want %q", c.cmd, p.HereDocs, c.want)
		}
	}
}

func TestNestedShell(t *testing.T) {
	p := mustParse(t, "cd /a && bash -c 'cd b && python3 x.py' && ls", "/w")
	want := []Call{
		{Argv: []string{"cd", "/a"}, Cwd: "/w"},
		{Argv: []string{"bash", "-c", "cd b && python3 x.py"}, Cwd: "/a"},
		{Argv: []string{"cd", "b"}, Cwd: "/a"},
		{Argv: []string{"python3", "x.py"}, Cwd: "/a/b"},
		{Argv: []string{"ls"}, Cwd: "/a"},
	}
	if !reflect.DeepEqual(p.Calls, want) {
		t.Fatalf("got %+v\nwant %+v", p.Calls, want)
	}
	// Depth guard: deeply nested bash -c strings stop at maxNestDepth.
	cmd := "ls"
	for i := 0; i < maxNestDepth+2; i++ {
		cmd = "bash -c " + Quote(cmd)
	}
	p, _ = Parse(cmd, "/w", env)
	if p.Confidence != Low || !strings.Contains(p.Reason, "nested too deeply") {
		t.Fatalf("depth guard: %v %q", p.Confidence, p.Reason)
	}
}

func TestSubstitutionCallsAreCollected(t *testing.T) {
	p, _ := Parse("python3 $(cat /s/scripts/x.py)", "/w", env)
	if p.Confidence != Low {
		t.Fatal("expected low")
	}
	var found bool
	for _, c := range p.Calls {
		if reflect.DeepEqual(c.Argv, []string{"cat", "/s/scripts/x.py"}) {
			found = true
		}
	}
	if !found {
		t.Fatalf("inner call not collected: %+v", p.Calls)
	}
}

func TestUnescapeAndAnsiC(t *testing.T) {
	if got := unescapeLit(`a\ b\\c\`, false); got != `a b\c\` {
		t.Errorf("unescapeLit plain: %q", got)
	}
	if got := unescapeLit(`a\$b\"c\\d\ne`+"\\\n"+`f`, true); got != `a$b"c\d\nef` {
		t.Errorf("unescapeLit double: %q", got)
	}
	cases := map[string]string{
		`a\nb`:       "a\nb",
		`\t\\\'`:     "\t\\'",
		`\x41\x4`:    "A\x04",
		`\u00e9`:     "é",
		`\U0001f600`: "😀",
		`\101`:       "A",
		`\e[0m`:      "\x1b[0m",
		`\q`:         `\q`,
		`no escapes`: "no escapes",
		`trailing\`:  `trailing\`,
	}
	for in, want := range cases {
		if got := ansiC(in); got != want {
			t.Errorf("ansiC(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIsSingleWatchdeckRun(t *testing.T) {
	cases := map[string]bool{
		"watchdeck run --skill x -c 'python3 /s/scripts/x.py'":         true,
		"/opt/homebrew/bin/watchdeck run --skill a --skill b -c \"y\"": true,
		"watchdeck run --skill x -c $'a\\nb'":                          true,
		"watchdeck run --skill x -c 'y' 2>/dev/null":                   false, // M6.3: no redirection
		"watchdeck run --skill x -c 'y' > out.txt":                     false,
		"watchdeck run --skill x -c \"$CMD\"":                          true,
		"  watchdeck   run  --skill x -c y  ":                          true,
		"watchdeck run":                                                true,
		"watchdeck run --skill x -c 'y' && curl evil":                  false,
		"watchdeck run --skill x -c 'y'; ls":                           false,
		"watchdeck run --skill x -c 'y' | cat":                         false,
		"watchdeck run --skill x -c 'y' || true":                       false,
		"watchdeck run --skill x -c 'y' &":                             false,
		"! watchdeck run --skill x -c 'y'":                             false,
		"watchdeck run --skill x -c \"$(cat f)\"":                      false,
		"watchdeck run --skill x -c `cat f`":                           false,
		"watchdeck run --skill x -c 'y' < <(ls)":                       false,
		"watchdeck run --skill x -c 'y'\nls":                           false,
		"(watchdeck run --skill x -c 'y')":                             false,
		"{ watchdeck run --skill x -c 'y'; }":                          false,
		"watchdeck audit":                                              false,
		"watchdeck":                                                    false,
		"echo watchdeck run":                                           false,
		"FOO=1 watchdeck run --skill x -c y":                           false, // M6.3: an assignment moves HOME-relative denies
		"HOME=/elsewhere watchdeck run --skill x -c y":                 false,
		"CLAUDE_CONFIG_DIR=/x watchdeck run --skill x -c y":            false,
		"env HOME=/x watchdeck run --skill x -c y":                     false,
		"nice watchdeck run --skill x -c y":                            false,
		"$BIN run --skill x -c y":                                      false,
		"watchdeck $CMD --skill x":                                     false,
		"~/bin/watchdeck run":                                          false,
		"watchdeck 'run' -c y":                                         true,
		"watchdeck run --skill x -c 'y":                                false,
		"":                                                             false,
	}
	for cmd, want := range cases {
		if got := IsSingleWatchdeckRun(cmd); got != want {
			t.Errorf("IsSingleWatchdeckRun(%q) = %v, want %v", cmd, got, want)
		}
	}
}

func TestQuoteBasics(t *testing.T) {
	cases := map[string]string{
		"":         "''",
		"abc":      "abc",
		"a b":      "'a b'",
		"it's":     `"it's"`,
		"$x":       "'$x'",
		"a\nb":     `$'a\nb'`,
		"nul\x00x": "nulx",
		"\x00":     "''",
	}
	for in, want := range cases {
		if got := Quote(in); got != want {
			t.Errorf("Quote(%q) = %q, want %q", in, got, want)
		}
	}
}

// randomStrings builds deterministic command-like strings from an alphabet
// heavy in shell metacharacters.
func randomStrings(n int) []string {
	alphabet := []string{
		"a", "b", "Z", "0", "9", " ", " ", "\t", "\n", "'", "\"", "$", "\\", "`", "~", "*", "?", "[", "]",
		"{", "}", "(", ")", ";", "|", "&", "<", ">", "#", "=", "!", "/", ".", "-", "é", "日", "\x01", "\x7f",
		"$(", "${", "'\"", "\\'", "\\\\", "$'", "<<", "&&", "||",
	}
	r := rand.New(rand.NewPCG(20261011, 42))
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		var b strings.Builder
		for l := r.IntN(24); l > 0; l-- {
			b.WriteString(alphabet[r.IntN(len(alphabet))])
		}
		out = append(out, b.String())
	}
	return out
}

func TestQuoteRoundTrip(t *testing.T) {
	samples := append(randomStrings(200), "", "'", `"`, "\\", "$", "`", "~", "a'b\"c", "x\ny\tz", "\x00mid\x00")
	for _, s := range samples {
		want := strings.ReplaceAll(s, "\x00", "")
		q := Quote(s)
		p, err := Parse("echo "+q, "/w", env)
		if err != nil {
			t.Errorf("Quote(%q) = %s: parse error %v", s, q, err)
			continue
		}
		if p.Confidence != High || len(p.Calls) != 1 || len(p.HereDocs) != 0 {
			t.Errorf("Quote(%q) = %s: confidence %v (%s), calls %d", s, q, p.Confidence, p.Reason, len(p.Calls))
			continue
		}
		if got := p.Calls[0].Argv; len(got) != 2 || got[1] != want {
			t.Errorf("Quote(%q) = %s: argv %q", s, q, got)
		}
	}
}

// TestQuoteRoundTripBash checks the quoting against the real shell for a
// subset of the samples. It skips when bash is not installed.
func TestQuoteRoundTripBash(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not installed")
	}
	if testing.Short() {
		t.Skip("spawns processes")
	}
	samples := append(randomStrings(60), "", "'", `"`, "it's", "a\nb", "$HOME", "`ls`", "~", "*.py", "x\x01y")
	for _, s := range samples {
		if strings.Contains(s, "\x00") {
			continue
		}
		q := Quote(s)
		out, err := exec.Command(bash, "-c", "printf '%s' "+q).CombinedOutput()
		if err != nil {
			t.Errorf("Quote(%q) = %s: bash error %v: %s", s, q, err, out)
			continue
		}
		if string(out) != s {
			t.Errorf("Quote(%q) = %s: bash printed %q", s, q, out)
		}
	}
}

func TestMain(m *testing.M) {
	// Expansion must never consult the developer's real HOME.
	os.Setenv("HOME", "/nonexistent-home-for-shellparse-tests")
	os.Exit(m.Run())
}

func TestPrefixAssignsRecorded(t *testing.T) {
	prog, err := Parse("FOO=1 BAR=x python3 /s/scripts/x.py", "/", nil)
	if err != nil || len(prog.Calls) != 1 {
		t.Fatalf("prog=%+v err=%v", prog, err)
	}
	if got := prog.Calls[0].Assigns; len(got) != 2 || got[0] != "FOO" || got[1] != "BAR" {
		t.Fatalf("Assigns = %q", got)
	}
	if prog.Calls[0].Argv[0] != "python3" {
		t.Fatalf("argv = %q", prog.Calls[0].Argv)
	}
	prog, _ = Parse("python3 /s/scripts/x.py", "/", nil)
	if len(prog.Calls[0].Assigns) != 0 {
		t.Fatalf("unexpected assigns %q", prog.Calls[0].Assigns)
	}
}

func TestUnquoteReversesQuote(t *testing.T) {
	for _, s := range []string{"python3 probe.py net --strict", "", "it's", "a\tb\nc", "$HOME `x`", "é ü", "\x01ctl"} {
		got, ok := Unquote(Quote(s))
		if !ok || got != s {
			t.Fatalf("Unquote(Quote(%q)) = %q, %v", s, got, ok)
		}
	}
	for _, q := range []string{"'a' 'b'", "'a'; true", "'a' >x", "\"$HOME\"", "$(true)", "'a' &", "x=1", "'a' | cat", "'unterminated"} {
		if got, ok := Unquote(q); ok {
			t.Fatalf("Unquote(%q) = %q, true; want not a single literal word", q, got)
		}
	}
}
