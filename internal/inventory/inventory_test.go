package inventory

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestScriptsBasicFixture(t *testing.T) {
	got, err := Scripts("testdata/skill-basic", nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []Script{
		{Rel: "install.sh", Lang: "sh", InGlob: false},
		{Rel: "scripts/a.py", Lang: "py", InGlob: true},
		{Rel: "scripts/b.py", Lang: "py", InGlob: true},
		{Rel: "scripts/c.py", Lang: "py", InGlob: true},
		{Rel: "scripts/lib/util.sh", Lang: "sh", InGlob: true},
		{Rel: "scripts/run.sh", Lang: "sh", InGlob: true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Scripts mismatch\n got: %+v\nwant: %+v", got, want)
	}
	if s := Summary(got); s != "py(3) sh(2) +1 outside" {
		t.Fatalf("Summary = %q", s)
	}
}

func TestScriptsGlobs(t *testing.T) {
	cases := []struct {
		name  string
		globs []string
		want  map[string]bool // rel → InGlob
	}{
		{"default", nil, map[string]bool{"install.sh": false, "scripts/a.py": true, "scripts/lib/util.sh": true}},
		{"empty list", []string{}, map[string]bool{"install.sh": false, "scripts/a.py": false}},
		{"two globs", []string{"scripts/*.py", "*.sh"}, map[string]bool{"install.sh": true, "scripts/a.py": true, "scripts/run.sh": false, "scripts/lib/util.sh": false}},
		{"dir shorthand", []string{"scripts"}, map[string]bool{"scripts/a.py": true, "scripts/lib/util.sh": true, "install.sh": false}},
		{"dir shorthand trailing slash", []string{"scripts/"}, map[string]bool{"scripts/a.py": true}},
		{"brace", []string{"{scripts,hooks}/**"}, map[string]bool{"scripts/lib/util.sh": true, "install.sh": false}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Scripts("testdata/skill-basic", tc.globs)
			if err != nil {
				t.Fatal(err)
			}
			byRel := map[string]bool{}
			for _, s := range got {
				byRel[s.Rel] = s.InGlob
			}
			for rel, want := range tc.want {
				if have, ok := byRel[rel]; !ok || have != want {
					t.Errorf("%s: InGlob=%v (present=%v), want %v", rel, have, ok, want)
				}
			}
		})
	}
	if _, err := Scripts("testdata/skill-basic", []string{"["}); err == nil {
		t.Fatal("bad glob accepted")
	}
}

// TestScriptsHeuristics builds a tree at test time because exec bits and
// symlinks do not survive every checkout.
func TestScriptsHeuristics(t *testing.T) {
	root := t.TempDir()
	write := func(rel, content string, mode os.FileMode) {
		t.Helper()
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil { // WriteFile honours umask
			t.Fatal(err)
		}
	}
	// scripts
	write("scripts/by_ext.py", "x = 1\n", 0o644)
	write("scripts/shebang_py", "#!/usr/bin/env python3\nprint(1)\n", 0o644)
	write("scripts/shebang_env_s", "#!/usr/bin/env -S bash -e\necho\n", 0o644)
	write("scripts/shebang_node", "#!/usr/bin/env node\n", 0o644)
	write("scripts/shebang_osa", "#!/usr/bin/osascript\n", 0o644)
	write("scripts/shebang_unknown", "#!/usr/local/bin/lua\n", 0o644)
	write("scripts/execbit_noext", "binary-ish\n", 0o755)
	write("tool.rb", "puts 1\n", 0o644)
	write("Tool.APPLESCRIPT", "display dialog\n", 0o644)
	write("scripts/x.scpt", "", 0o644)
	// not scripts
	write("README.md", "#! not a shebang because .md is data\n", 0o755)
	write("scripts/schema.xsd", "#!/x\n", 0o755)
	write("scripts/plain_noext", "no shebang, no exec bit\n", 0o644)
	write("scripts/uv.lock", "#!/bin/sh\n", 0o755)
	write(".env", "#!/bin/sh\nFAKE=1\n", 0o755)
	write(".env.example", "#!/bin/sh\n", 0o755)
	write("scripts/fake.pem", "#!/bin/sh\n", 0o755)
	write("scripts/fake.key", "#!/bin/sh\n", 0o755)
	write("node_modules/dep/index.js", "", 0o644)
	write(".venv/bin/python", "#!/bin/sh\n", 0o755)
	write("__pycache__/a.py", "", 0o644)
	write(".git/hooks/pre-commit", "#!/bin/sh\n", 0o755)
	if err := os.Symlink(filepath.Join(root, "scripts/by_ext.py"), filepath.Join(root, "scripts/link.py")); err != nil {
		t.Fatal(err)
	}

	got, err := Scripts(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []Script{
		{Rel: "Tool.APPLESCRIPT", Lang: "applescript"},
		{Rel: "scripts/by_ext.py", Lang: "py", InGlob: true},
		{Rel: "scripts/execbit_noext", Lang: "other", InGlob: true},
		{Rel: "scripts/shebang_env_s", Lang: "sh", InGlob: true},
		{Rel: "scripts/shebang_node", Lang: "js", InGlob: true},
		{Rel: "scripts/shebang_osa", Lang: "applescript", InGlob: true},
		{Rel: "scripts/shebang_py", Lang: "py", InGlob: true},
		{Rel: "scripts/shebang_unknown", Lang: "other", InGlob: true},
		{Rel: "scripts/x.scpt", Lang: "applescript", InGlob: true},
		{Rel: "tool.rb", Lang: "rb"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Scripts mismatch\n got: %+v\nwant: %+v", got, want)
	}

	// A symlinked root resolves to the same inventory.
	link := filepath.Join(t.TempDir(), "linked-skill")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	viaLink, err := Scripts(link, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(viaLink, got) {
		t.Fatalf("symlinked root differs:\n%+v\n%+v", viaLink, got)
	}
}

func TestScriptsErrors(t *testing.T) {
	if _, err := Scripts(filepath.Join(t.TempDir(), "missing"), nil); err == nil {
		t.Fatal("missing root accepted")
	}
	f := filepath.Join(t.TempDir(), "file.py")
	if err := os.WriteFile(f, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Scripts(f, nil); err == nil {
		t.Fatal("file root accepted")
	}
}

func TestSummary(t *testing.T) {
	cases := []struct {
		name string
		in   []Script
		want string
	}{
		{"nil", nil, "-"},
		{"empty", []Script{}, "-"},
		{"one", []Script{{Rel: "scripts/a.py", Lang: "py", InGlob: true}}, "py(1)"},
		{"count desc then lang", []Script{
			{Lang: "sh", InGlob: true}, {Lang: "py", InGlob: true}, {Lang: "sh", InGlob: true},
			{Lang: "js", InGlob: true}, {Lang: "py", InGlob: true},
		}, "py(2) sh(2) js(1)"},
		{"only outside", []Script{{Lang: "sh"}, {Lang: "py"}}, "+2 outside"},
		{"mixed", []Script{{Lang: "py", InGlob: true}, {Lang: "sh"}}, "py(1) +1 outside"},
		{"other", []Script{{Lang: "other", InGlob: true}}, "other(1)"},
	}
	for _, tc := range cases {
		if got := Summary(tc.in); got != tc.want {
			t.Errorf("%s: Summary = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestInterpLang(t *testing.T) {
	cases := map[string]string{
		"python": "py", "python3": "py", "python3.12": "py",
		"sh": "sh", "bash": "sh", "zsh": "sh", "dash": "sh",
		"node": "js", "bun": "js", "tsx": "ts", "deno": "ts",
		"ruby": "rb", "perl": "pl", "php8": "php", "osascript": "applescript",
		"lua": "other", "": "other",
	}
	for in, want := range cases {
		if got := interpLang(in); got != want {
			t.Errorf("interpLang(%q) = %q, want %q", in, got, want)
		}
	}
}
