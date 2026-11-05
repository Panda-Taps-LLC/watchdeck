package sessionindex

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestSearchHitsSnippetsAndOffsets(t *testing.T) {
	e := newEnv(t)
	for i := 0; i < 5; i++ {
		p := writeSession(t, e.projects, "-p", sid(i), session("/p", fmt.Sprintf("word%d", i))+
			assistantText(9, modelTest, strings.Repeat("padding ", 60)+"The NeedleMark is here"+strings.Repeat(" tail", 80)))
		m := tsBase.Add(time.Duration(i) * time.Minute)
		os.Chtimes(p, m, m)
	}
	ix, _ := e.update(t)
	hits, err := ix.Search("needlemark", 3)
	if err != nil || len(hits) != 3 {
		t.Fatalf("hits: %v %+v", err, hits)
	}
	for _, h := range hits {
		if len(h.Snippet) > SnippetLen || !strings.Contains(h.Snippet, "NeedleMark") || strings.Contains(h.Snippet, "\n") {
			t.Errorf("snippet: %q", h.Snippet)
		}
		text := readText(t, e, h.SessionID)
		if !strings.EqualFold(text[h.Offset:h.Offset+10], "needlemark") {
			t.Errorf("offset %d: %q", h.Offset, text[h.Offset:h.Offset+10])
		}
	}
	if hits, _ := ix.Search("word3", 10); len(hits) != 1 || hits[0].SessionID != sid(3) {
		t.Errorf("word3: %+v", hits)
	}
	if hits, _ := ix.Search("absent-term", 10); len(hits) != 0 {
		t.Errorf("absent: %+v", hits)
	}
	if hits, _ := ix.Search("  ", 10); hits != nil {
		t.Errorf("empty query: %+v", hits)
	}
}

func TestSearchNonASCIICaseInsensitive(t *testing.T) {
	e := newEnv(t)
	writeSession(t, e.projects, "-p", sid(1), session("/p", "alpha")+assistantText(9, modelTest, "Über Straße ÉCOLE"))
	ix, _ := e.update(t)
	for q, want := range map[string]int{"über": 1, "école": 1, "STRASSE": 0} { // simple case folding does not expand ß
		hits, err := ix.Search(q, 5)
		if err != nil {
			t.Fatal(err)
		}
		if len(hits) != want {
			t.Errorf("%q: %+v", q, hits)
		}
		for _, h := range hits {
			if !utf8.ValidString(h.Snippet) {
				t.Errorf("invalid utf8 snippet %q", h.Snippet)
			}
		}
	}
}

// A match that straddles the 1 MiB chunk boundary, one just past it, and one
// several chunks in.
func TestScanAcrossChunks(t *testing.T) {
	dir := t.TempDir()
	for _, at := range []int{searchChunk - 4, searchChunk + 5, 3*searchChunk + 17} {
		buf := []byte(strings.Repeat("x", at+500))
		copy(buf[at:], "MatchMe")
		buf[at-50] = '\n'
		p := filepath.Join(dir, fmt.Sprintf("%d.txt", at))
		if err := os.WriteFile(p, buf, 0o600); err != nil {
			t.Fatal(err)
		}
		m, _ := newMatcher("matchme")
		h, ok := (&scanner{m: m}).scan(p)
		if !ok || h.Offset != int64(at) {
			t.Errorf("at %d: ok=%v offset %d", at, ok, h.Offset)
			continue
		}
		if !strings.Contains(h.Snippet, "MatchMe") || len(h.Snippet) > SnippetLen || strings.Contains(h.Snippet, "\n") {
			t.Errorf("at %d: snippet %q", at, h.Snippet)
		}
	}
}

func TestSnippetBounds(t *testing.T) {
	w := []byte(strings.Repeat("é", 300) + "KEY" + strings.Repeat("ü", 300))
	s := 600
	got := snippet(w, s, s+3)
	if len(got) > SnippetLen || !utf8.ValidString(got) || !strings.Contains(got, "KEY") {
		t.Errorf("snippet %d bytes valid=%v %q", len(got), utf8.ValidString(got), got)
	}
}
