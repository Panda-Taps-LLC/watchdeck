package copylint

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestBannedWords(t *testing.T) {
	want := []string{"no opinion", "ungranted", "subject", "gate", "matcher", "profile hash", "hook", "PreToolUse", "classifier", "nonce"}
	if got := Banned(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Banned() = %q, want %q", got, want)
	}
	// Each call returns a fresh slice: a caller that edits it changes nothing.
	b := Banned()
	b[0] = "x"
	if Banned()[0] != "no opinion" {
		t.Fatal("Banned() shares its backing array")
	}
}

// TestScanJS runs Scan over testdata/tricky.js, whose lines each name the
// words Scan must report on that line in a trailing "// want: ..." note.
func TestScanJS(t *testing.T) {
	src, err := os.ReadFile("testdata/tricky.js")
	if err != nil {
		t.Fatal(err)
	}
	got := map[int][]string{}
	for _, h := range Scan("tricky.js", src) {
		if h.File != "tricky.js" {
			t.Errorf("hit file = %q", h.File)
		}
		got[h.Line] = append(got[h.Line], h.Word)
	}
	checked := 0
	for i, line := range strings.Split(string(src), "\n") {
		n := i + 1
		k := strings.LastIndex(line, "// want: ")
		if k < 0 || n <= 3 {
			if len(got[n]) > 0 {
				t.Errorf("line %d: unexpected hits %q", n, got[n])
			}
			continue
		}
		checked++
		spec := strings.TrimSpace(line[k+len("// want: "):])
		var want []string
		if spec != "none" {
			want = splitWant(spec)
		}
		if !reflect.DeepEqual(got[n], want) {
			t.Errorf("line %d %q: hits %q, want %q", n, strings.TrimSpace(line[:k]), got[n], want)
		}
	}
	if checked < 20 {
		t.Fatalf("only %d lines checked; the fixture lost its notes", checked)
	}
}

// splitWant splits "hook gate" into words but keeps the two-word banned
// phrases together.
func splitWant(spec string) []string {
	for _, p := range []string{"no opinion", "profile hash"} {
		if strings.EqualFold(spec, p) {
			return []string{spec}
		}
	}
	return strings.Fields(spec)
}

func TestScanJSHitFields(t *testing.T) {
	src := []byte("const x = 1;\nconst y = \"Turn the hook on\";\n")
	hits := Scan("a.js", src)
	if len(hits) != 1 {
		t.Fatalf("hits = %+v", hits)
	}
	h := hits[0]
	if h.File != "a.js" || h.Line != 2 || h.Word != "hook" || h.Text != "Turn the hook on" {
		t.Fatalf("hit = %+v", h)
	}
}

func TestScanJSMultilineTemplate(t *testing.T) {
	src := []byte("const t = `first line\nsecond with a gate\n`;\n")
	hits := Scan("t.js", src)
	if len(hits) != 1 || hits[0].Line != 2 || hits[0].Word != "gate" {
		t.Fatalf("hits = %+v", hits)
	}
}

func TestScanHTML(t *testing.T) {
	src := []byte(`<!doctype html>
<html><head><title>The hook page</title>
<link rel="stylesheet" href="/hook.css">
<script type="module" src="/hooks.js"></script>
<script>const s = "gate";</script>
<style>.hook { color: red; }</style>
</head><body>
<!-- a comment about the matcher -->
<a class="hook" data-page="hook" href="#/hook">Home</a>
<button title="Install hooks" aria-label="Turn on">x</button>
<input placeholder="Search by subject">
<p>Your nonce is old</p>
<span aria-label='single quoted classifier'></span>
</body></html>
`)
	var got []string
	for _, h := range Scan("index.html", src) {
		got = append(got, h.Word)
		if h.File != "index.html" || h.Line == 0 {
			t.Errorf("bad hit %+v", h)
		}
	}
	want := []string{"hook", "hooks", "subject", "nonce", "classifier"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("words = %q, want %q", got, want)
	}
	lines := map[string]int{}
	for _, h := range Scan("index.html", src) {
		lines[h.Word] = h.Line
	}
	if lines["hook"] != 2 || lines["hooks"] != 10 || lines["subject"] != 11 || lines["nonce"] != 12 || lines["classifier"] != 13 {
		t.Fatalf("lines = %v", lines)
	}
}

func TestScanMarkdown(t *testing.T) {
	src := []byte("# Title\n\nPlain text about a hook.\n\nRun `watchdeck gate` now.\n\n```sh\nwatchdeck hook --harness x\n```\n\n~~~\nmatcher inside tilde fence\n~~~\nAfter the fence: nonce.\n")
	var got []string
	var lines []int
	for _, h := range Scan("SKILL.md", src) {
		got = append(got, h.Word)
		lines = append(lines, h.Line)
	}
	if !reflect.DeepEqual(got, []string{"hook", "gate", "nonce"}) || !reflect.DeepEqual(lines, []int{3, 5, 14}) {
		t.Fatalf("words = %q lines = %v", got, lines)
	}
	if hits := Scan("usage.txt", []byte("usage: watchdeck classifier\n")); len(hits) != 1 || hits[0].Word != "classifier" {
		t.Fatalf("txt hits = %+v", hits)
	}
}

func TestScanUnknownExtension(t *testing.T) {
	if hits := Scan("a.css", []byte(".hook { }")); len(hits) != 0 {
		t.Fatalf("css hits = %+v", hits)
	}
}
