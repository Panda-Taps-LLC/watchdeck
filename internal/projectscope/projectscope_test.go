package projectscope

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestRootsAddsGitRootsAndDedupes(t *testing.T) {
	home := t.TempDir()
	repo := filepath.Join(home, "repo")
	sub := filepath.Join(repo, "a", "b")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(repo, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	got := Roots([]string{sub, "", "relative", sub + "/", repo, "/nowhere/x"}, home)
	want := []string{sub, repo, "/nowhere/x"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Roots = %v, want %v", got, want)
	}
}

func TestResolve(t *testing.T) {
	home := t.TempDir()
	repo := filepath.Join(home, "repo")
	os.MkdirAll(filepath.Join(repo, ".git"), 0o755)
	known := func() []string { return []string{"/known/proj"} }

	cases := []struct {
		value, def string
		known      func() []string
		want       string
		err        bool
	}{
		{"", "", known, "", false},
		{"", "/cwd", known, "/cwd", false},
		{"/known/proj", "", known, "/known/proj", false},
		{"/known/proj", "", nil, "", true},
		{"/known/proj/", "", known, "", true},
		{"/known/x/../proj", "", known, "", true},
		{"known/proj", "", known, "", true},
		{"/other", "", known, "", true},
		{"/known/proj\x00", "", known, "", true},
		{repo, repo, nil, repo, false},
	}
	for _, c := range cases {
		got, err := Resolve(c.value, c.def, home, c.known)
		if (err != nil) != c.err || got != c.want {
			t.Errorf("Resolve(%q, %q) = %q, %v; want %q, err %v", c.value, c.def, got, err, c.want, c.err)
		}
		if err != nil && !errors.Is(err, ErrUnknown) {
			t.Errorf("error %v is not ErrUnknown", err)
		}
	}
	// a cwd below the repo accepts the repo root
	sub := filepath.Join(repo, "sub")
	os.MkdirAll(sub, 0o755)
	if got, err := Resolve(repo, sub, home, nil); err != nil || got != repo {
		t.Errorf("git root of def: %q %v", got, err)
	}
}
