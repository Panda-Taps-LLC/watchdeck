package projectscope

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestDisplayAndExpand(t *testing.T) {
	home := "/Users/someone"
	for in, want := range map[string]string{
		"/Users/someone":           "~",
		"/Users/someone/":          "~",
		"/Users/someone/work/proj": "~/work/proj",
		"/Users/someoneelse/x":     "/Users/someoneelse/x",
		"/tmp/x":                   "/tmp/x",
		"relative":                 "relative",
		"":                         "",
	} {
		if got := Display(in, home); got != want {
			t.Errorf("Display(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{
		"~":              "/Users/someone",
		"~/work/proj":    "/Users/someone/work/proj",
		"~/work/../proj": "~/work/../proj", // climbing is left as is, so Resolve refuses it
		"~/../etc":       "~/../etc",
		"~other/x":       "~other/x",
		"/abs":           "/abs",
	} {
		if got := Expand(in, home); got != want {
			t.Errorf("Expand(%q) = %q, want %q", in, got, want)
		}
	}
	if Expand("~/x", "") != "~/x" {
		t.Error("Expand without a home changed the value")
	}
}

func TestResolveAcceptsDisplayForm(t *testing.T) {
	home := t.TempDir()
	proj := filepath.Join(home, "work", "proj")
	known := func() []string { return []string{proj} }
	if got, err := Resolve("~/work/proj", "", home, known); err != nil || got != proj {
		t.Fatalf("Resolve(~/work/proj) = %q, %v", got, err)
	}
	for _, bad := range []string{"~/work/../work/proj", "~/other", "~"} {
		if _, err := Resolve(bad, "", home, known); !errors.Is(err, ErrUnknown) {
			t.Errorf("Resolve(%q) = %v, want ErrUnknown", bad, err)
		}
	}
}
