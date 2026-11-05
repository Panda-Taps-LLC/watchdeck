package skillmd

import (
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func fixture(t *testing.T, dir string) Frontmatter {
	t.Helper()
	fm, err := Parse(filepath.Join("testdata", dir, "SKILL.md"))
	if err != nil {
		t.Fatalf("Parse(%s): %v", dir, err)
	}
	return fm
}

func hasProblem(fm Frontmatter, substr string) bool {
	for _, p := range fm.Problems {
		if strings.Contains(p, substr) {
			return true
		}
	}
	return false
}

func TestValid(t *testing.T) {
	fm := fixture(t, "valid")
	if len(fm.Problems) != 0 {
		t.Fatalf("unexpected problems: %v", fm.Problems)
	}
	if fm.Name != "valid" || fm.Description != "A well-formed skill used by the parser tests." {
		t.Errorf("name/description = %q / %q", fm.Name, fm.Description)
	}
	if fm.License != "Apache-2.0" || fm.Compatibility != "Requires git and network access." {
		t.Errorf("license/compatibility = %q / %q", fm.License, fm.Compatibility)
	}
	if want := []string{"Read", "Grep"}; !reflect.DeepEqual(fm.AllowedTools, want) {
		t.Errorf("AllowedTools = %v, want %v", fm.AllowedTools, want)
	}
	if want := map[string]string{"author": "fixture", "version": "1.2.0"}; !reflect.DeepEqual(fm.Metadata, want) {
		t.Errorf("Metadata = %v, want %v", fm.Metadata, want)
	}
	if fm.Raw == nil || fm.Raw["name"] != "valid" {
		t.Errorf("Raw not populated: %v", fm.Raw)
	}
}

func TestMalformedYAMLFallsBackToRegex(t *testing.T) {
	fm := fixture(t, "malformed")
	if !hasProblem(fm, "YAML parse error") {
		t.Fatalf("expected a YAML parse Problem, got %v", fm.Problems)
	}
	if fm.Raw != nil {
		t.Errorf("Raw should be nil on fallback, got %v", fm.Raw)
	}
	if fm.Name != "malformed" {
		t.Errorf("Name = %q, want recovered %q", fm.Name, "malformed")
	}
	if !strings.HasPrefix(fm.Description, "Unterminated quote") {
		t.Errorf("Description not recovered: %q", fm.Description)
	}
	if fm.AllowedTools != nil {
		t.Errorf("AllowedTools should not be recovered on fallback, got %v", fm.AllowedTools)
	}
}

func TestNameMismatch(t *testing.T) {
	fm := fixture(t, "wrong-name")
	if fm.Name != "other-name" {
		t.Fatalf("Name = %q", fm.Name)
	}
	if !hasProblem(fm, `does not match directory name "wrong-name"`) {
		t.Errorf("expected name≠dir Problem, got %v", fm.Problems)
	}
}

func TestNonStringMetadataDropped(t *testing.T) {
	fm := fixture(t, "nonstring-meta")
	if want := map[string]string{"author": "fixture"}; !reflect.DeepEqual(fm.Metadata, want) {
		t.Errorf("Metadata = %v, want %v", fm.Metadata, want)
	}
	for _, key := range []string{"metadata.version", "metadata.experimental", "metadata.tags"} {
		if !hasProblem(fm, key) {
			t.Errorf("expected a Problem for %s, got %v", key, fm.Problems)
		}
	}
	if len(fm.Problems) != 3 {
		t.Errorf("want exactly 3 problems, got %v", fm.Problems)
	}
}

func TestAllowedToolsString(t *testing.T) {
	fm := fixture(t, "tools-string")
	want := []string{"Read", "Grep", "Bash(git add:*)", "Bash(npm run *)"}
	if !reflect.DeepEqual(fm.AllowedTools, want) {
		t.Errorf("AllowedTools = %q, want %q", fm.AllowedTools, want)
	}
	if len(fm.Problems) != 0 {
		t.Errorf("unexpected problems: %v", fm.Problems)
	}
}

func TestAllowedToolsList(t *testing.T) {
	fm := fixture(t, "tools-list")
	want := []string{"Read", "Bash(git status:*)"}
	if !reflect.DeepEqual(fm.AllowedTools, want) {
		t.Errorf("AllowedTools = %q, want %q", fm.AllowedTools, want)
	}
	if !hasProblem(fm, "allowed-tools[2]") {
		t.Errorf("expected a Problem for the non-string entry, got %v", fm.Problems)
	}
}

func TestNoFrontmatterIsError(t *testing.T) {
	_, err := Parse(filepath.Join("testdata", "nofm", "SKILL.md"))
	if !errors.Is(err, ErrNoFrontmatter) {
		t.Fatalf("err = %v, want ErrNoFrontmatter", err)
	}
	if _, err := ParseBytes(nil, "x"); !errors.Is(err, ErrNoFrontmatter) {
		t.Fatalf("empty input: err = %v, want ErrNoFrontmatter", err)
	}
}

// TestYAMLPanicInputIsAnError: frontmatter shaped like the input that
// panics go-yaml v1.19.2 (internal/policy fuzz seed) never panics ParseBytes.
func TestYAMLPanicInputIsAnError(t *testing.T) {
	for _, fm := range []string{
		"name: x\nsubjects:\n  ! #00000000000000000000\n",
		"! #0\n",
		"- ! #0\n",
	} {
		ParseBytes([]byte("---\n"+fm+"---\nbody\n"), "x")
	}
}

func TestFoldedDescription(t *testing.T) {
	fm := fixture(t, "folded")
	want := "Use this skill when the user asks for something long. The folded scalar spans two lines and ends here."
	if fm.Description != want {
		t.Errorf("Description = %q, want %q", fm.Description, want)
	}
	if len(fm.Problems) != 0 {
		t.Errorf("unexpected problems: %v", fm.Problems)
	}
}

func TestFoldedDescriptionRegexFallback(t *testing.T) {
	src := "---\nname: folded\ndescription: >\n  First line\n  second line.\nbroken: [unclosed\n---\n"
	fm, err := ParseBytes([]byte(src), "folded")
	if err != nil {
		t.Fatal(err)
	}
	if !hasProblem(fm, "YAML parse error") {
		t.Fatalf("expected fallback, got %v", fm.Problems)
	}
	if fm.Description != "First line second line." {
		t.Errorf("Description = %q", fm.Description)
	}
}

func TestDuplicateKeyKeepsStructure(t *testing.T) {
	fm := fixture(t, "dupkey")
	if fm.Raw == nil {
		t.Fatalf("expected structure to survive a duplicate key; problems: %v", fm.Problems)
	}
	if fm.Description != "Second description wins." {
		t.Errorf("Description = %q", fm.Description)
	}
	if !reflect.DeepEqual(fm.AllowedTools, []string{"Read"}) {
		t.Errorf("AllowedTools = %v", fm.AllowedTools)
	}
	if len(fm.Problems) != 1 || !strings.HasPrefix(fm.Problems[0], "frontmatter:") {
		t.Errorf("want one duplicate-key Problem, got %v", fm.Problems)
	}
}

func TestUnclosedFrontmatter(t *testing.T) {
	fm := fixture(t, "unclosed")
	if !hasProblem(fm, "closing '---' not found") {
		t.Errorf("expected unclosed Problem, got %v", fm.Problems)
	}
	if fm.Name != "unclosed" {
		t.Errorf("Name = %q", fm.Name)
	}
}

func TestEmptyFrontmatter(t *testing.T) {
	fm, err := ParseBytes([]byte("---\n---\n# body\n"), "empty")
	if err != nil {
		t.Fatal(err)
	}
	if !hasProblem(fm, "name: missing") || !hasProblem(fm, "description: missing") {
		t.Errorf("Problems = %v", fm.Problems)
	}
	if fm.Raw == nil {
		t.Errorf("Raw should be an empty map, got nil")
	}
}

func TestNonMappingFrontmatter(t *testing.T) {
	fm, err := ParseBytes([]byte("---\n- just\n- a list\n---\n"), "list")
	if err != nil {
		t.Fatal(err)
	}
	if fm.Raw != nil || !hasProblem(fm, "YAML parse error") {
		t.Errorf("expected fallback for non-mapping frontmatter: raw=%v problems=%v", fm.Raw, fm.Problems)
	}
}

func TestCRLFAndBOM(t *testing.T) {
	src := "\xef\xbb\xbf---\r\nname: crlf\r\ndescription: Windows line endings.\r\n---\r\nbody\r\n"
	fm, err := ParseBytes([]byte(src), "crlf")
	if err != nil {
		t.Fatal(err)
	}
	if fm.Name != "crlf" || fm.Description != "Windows line endings." || len(fm.Problems) != 0 {
		t.Errorf("fm = %+v", fm)
	}
}

func TestNonStringScalars(t *testing.T) {
	fm, err := ParseBytes([]byte("---\nname: 123\ndescription: true\nallowed-tools: {a: b}\nmetadata: nope\n---\n"), "123")
	if err != nil {
		t.Fatal(err)
	}
	if fm.Name != "123" || fm.Description != "true" {
		t.Errorf("name/description = %q/%q", fm.Name, fm.Description)
	}
	for _, want := range []string{"name: expected a string", "description: expected a string", "allowed-tools: expected a string or a list", "metadata: expected a mapping"} {
		if !hasProblem(fm, want) {
			t.Errorf("missing Problem %q in %v", want, fm.Problems)
		}
	}
}

func TestDescriptionTooLong(t *testing.T) {
	long := strings.Repeat("x", MaxDescriptionLen+1)
	fm, err := ParseBytes([]byte("---\nname: long\ndescription: "+long+"\n---\n"), "long")
	if err != nil {
		t.Fatal(err)
	}
	if !hasProblem(fm, "max 1024") {
		t.Errorf("Problems = %v", fm.Problems)
	}
}

func TestValidName(t *testing.T) {
	good := []string{"a", "pdf", "my-skill", "skill2", "a-b-c-1", strings.Repeat("a", 64)}
	for _, n := range good {
		if err := ValidName(n); err != nil {
			t.Errorf("ValidName(%q) = %v, want nil", n, err)
		}
	}
	bad := []string{"", "-a", "a-", "a--b", "A", "my_skill", "my skill", "héllo", strings.Repeat("a", 65), "a.b"}
	for _, n := range bad {
		if err := ValidName(n); err == nil {
			t.Errorf("ValidName(%q) = nil, want error", n)
		}
	}
}

func TestParseDirName(t *testing.T) {
	fm, err := Parse("testdata/valid/SKILL.md")
	if err != nil {
		t.Fatal(err)
	}
	if len(fm.Problems) != 0 {
		t.Errorf("relative path should derive dir name %q; problems %v", "valid", fm.Problems)
	}
	if _, err := Parse("testdata/does-not-exist/SKILL.md"); err == nil {
		t.Error("missing file should be an error")
	}
}

func TestSplitTools(t *testing.T) {
	cases := map[string][]string{
		"":                                 nil,
		"Read":                             {"Read"},
		"Read Grep":                        {"Read", "Grep"},
		"Read, Grep,Glob":                  {"Read", "Grep", "Glob"},
		"Bash(git add:*), Bash(npm run *)": {"Bash(git add:*)", "Bash(npm run *)"},
		"  Read\tWrite \n":                 {"Read", "Write"},
	}
	for in, want := range cases {
		if got := splitTools(in); !reflect.DeepEqual(got, want) {
			t.Errorf("splitTools(%q) = %q, want %q", in, got, want)
		}
	}
}
