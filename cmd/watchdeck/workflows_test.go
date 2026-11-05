package main

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

func repoFile(t *testing.T, rel ...string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(append([]string{"..", ".."}, rel...)...))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func workflowFiles(t *testing.T) []string {
	t.Helper()
	m, _ := filepath.Glob(filepath.Join("..", "..", ".github", "workflows", "*.yml"))
	if len(m) < 3 { // ci, release, walk
		t.Fatalf("expected at least three workflows, found %v", m)
	}
	return m
}

func isComment(line string) bool {
	return strings.HasPrefix(strings.TrimSpace(line), "#")
}

// TestWorkflowActionsArePinned: every uses: is owner/repo[/path]@<40 hex> # vX.Y.Z.
func TestWorkflowActionsArePinned(t *testing.T) {
	usesRe := regexp.MustCompile(`^\s*-?\s*uses:\s*(.+)$`)
	pinRe := regexp.MustCompile(`^[\w.-]+/[\w.-]+(/[\w./-]+)?@[0-9a-f]{40}\s+#\s*v\d+(\.\d+)*\s*$`)
	matches := 0
	for _, f := range workflowFiles(t) {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(b), "\n") {
			if isComment(line) {
				continue
			}
			m := usesRe.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			matches++
			if !pinRe.MatchString(m[1]) {
				hint := ""
				if strings.HasPrefix(m[1], "./") || strings.HasPrefix(m[1], "docker://") {
					hint = " (local and docker:// forms are not allowed)"
				}
				t.Errorf("%s:%d: not pinned to a 40-hex SHA with a # vX.Y.Z comment: %s%s", f, i+1, m[1], hint)
			}
		}
	}
	if matches < 8 {
		t.Errorf("expected at least 8 uses: lines across the workflows, found %d", matches)
	}
}

// TestWorkflowsDeclarePermissions: one workflow-level permissions block before
// jobs:, none at job level; ci.yml and walk.yml are read-only.
func TestWorkflowsDeclarePermissions(t *testing.T) {
	for _, f := range workflowFiles(t) {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(string(b), "\n")
		perm, jobs, count := -1, -1, 0
		for i, line := range lines {
			if isComment(line) {
				continue
			}
			if strings.HasPrefix(line, "permissions:") && perm < 0 {
				perm = i
			}
			if strings.HasPrefix(line, "jobs:") {
				jobs = i
			}
			if strings.HasPrefix(strings.TrimSpace(line), "permissions:") {
				count++
			}
		}
		if perm < 0 || jobs < 0 || perm > jobs {
			t.Errorf("%s: want a column-0 permissions: before jobs: (permissions line %d, jobs line %d)", f, perm+1, jobs+1)
		}
		if count != 1 {
			t.Errorf("%s: want exactly one permissions: key (no job-level widening), found %d", f, count)
		}
		base := filepath.Base(f)
		if (base == "ci.yml" || base == "walk.yml") && perm >= 0 {
			got := permissionLines(lines, perm)
			if len(got) != 1 || got[0] != "contents: read" {
				t.Errorf("%s: permissions must be exactly contents: read, got %v", f, got)
			}
		}
	}
}

// permissionLines returns the sorted, trimmed lines of the block that starts at
// the column-0 permissions: line, up to the next column-0 key. Comments and
// blank lines are skipped.
func permissionLines(lines []string, start int) []string {
	var out []string
	for _, line := range lines[start+1:] {
		if strings.TrimSpace(line) == "" || isComment(line) {
			continue
		}
		if line[0] != ' ' && line[0] != '\t' {
			break
		}
		out = append(out, strings.TrimSpace(line))
	}
	sort.Strings(out)
	return out
}

func TestReleaseWorkflowPermissions(t *testing.T) {
	lines := strings.Split(repoFile(t, ".github", "workflows", "release.yml"), "\n")
	start := -1
	for i, line := range lines {
		if strings.HasPrefix(line, "permissions:") {
			start = i
			break
		}
	}
	if start < 0 {
		t.Fatal("release.yml has no column-0 permissions:")
	}
	got := strings.Join(permissionLines(lines, start), "|")
	want := "attestations: write|contents: write|id-token: write"
	if got != want {
		t.Errorf("release.yml permissions = %q, want %q", got, want)
	}
}

func TestReleaseSignAndAttestGatedOnPublic(t *testing.T) {
	src := repoFile(t, ".github", "workflows", "release.yml")
	if !strings.Contains(src, `args: release --clean ${{ github.event.repository.visibility != 'public' && '--skip=sign' || '' }}`) {
		t.Error("goreleaser args must skip signing unless the repository is public")
	}
	if strings.Contains(src, "repository.private") {
		t.Error("release.yml must not use repository.private; the gate keys on visibility == 'public' (fail closed)")
	}
	const gate = `if: ${{ github.event.repository.visibility == 'public' }}`
	stepRe := regexp.MustCompile(`^\s*- (name|uses):`)
	var steps []string
	var cur []string
	for _, line := range strings.Split(src, "\n") {
		if stepRe.MatchString(line) && len(cur) > 0 {
			steps = append(steps, strings.Join(cur, "\n"))
			cur = nil
		}
		cur = append(cur, line)
	}
	steps = append(steps, strings.Join(cur, "\n"))
	find := func(action string) string {
		for _, s := range steps {
			if strings.Contains(s, action) {
				return s
			}
		}
		t.Fatalf("release.yml has no step using %s", action)
		return ""
	}
	attest := find("actions/attest-build-provenance@")
	for _, want := range []string{gate, "subject-checksums: dist/checksums.txt"} {
		if !strings.Contains(attest, want) {
			t.Errorf("attest step lacks %q", want)
		}
	}
	cosign := find("sigstore/cosign-installer@")
	for _, want := range []string{gate, "cosign-release: v3.0.6"} {
		if !strings.Contains(cosign, want) {
			t.Errorf("cosign step lacks %q", want)
		}
	}
	var summary string
	for _, s := range steps {
		if strings.Contains(s, "GITHUB_STEP_SUMMARY") {
			summary = s
		}
	}
	if summary == "" {
		t.Error("release.yml has no summary step")
	} else {
		for _, want := range []string{"if: always()", "UNSIGNED draft"} {
			if !strings.Contains(summary, want) {
				t.Errorf("summary step lacks %q", want)
			}
		}
	}
	if !strings.Contains(src, "fetch-depth: 0") {
		t.Error("checkout needs fetch-depth: 0 for the commit-time file times and the changelog")
	}
	if !strings.Contains(src, "GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}") {
		t.Error("goreleaser step must pass GITHUB_TOKEN")
	}
	for _, m := range regexp.MustCompile(`secrets\.(\w+)`).FindAllStringSubmatch(src, -1) {
		if m[1] != "GITHUB_TOKEN" {
			t.Errorf("release.yml references secrets.%s; only GITHUB_TOKEN is allowed", m[1])
		}
	}
}

func TestGoreleaserReproducibleFlags(t *testing.T) {
	src := repoFile(t, ".goreleaser.yaml")
	lines := map[string]bool{}
	for _, l := range strings.Split(src, "\n") {
		lines[strings.TrimSpace(l)] = true
	}
	for _, want := range []string{
		`- -trimpath`,
		`mod_timestamp: "{{ .CommitTimestamp }}"`,
		`- -s -w -buildid= -X main.version={{.Version}}`,
		`name_template: checksums.txt`,
		`- artifacts: archive`,
		`artifacts: checksum`,
		`- cmd: cosign`, // first key of the signs list item
		`signature: "${artifact}.sigstore.json"`,
		`args: ["sign-blob", "--bundle=${signature}", "${artifact}", "--yes"]`,
		`draft: true`,
	} {
		if !lines[want] {
			t.Errorf(".goreleaser.yaml lacks the line %q", want)
		}
	}
	for _, key := range []string{"sboms:", "signs:"} {
		if !regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(key)).MatchString(src) {
			t.Errorf(".goreleaser.yaml lacks a column-0 %s", key)
		}
	}
	if regexp.MustCompile(`(?m)^brews:`).MatchString(src) {
		t.Error("the brews: block must stay commented out until the tap exists")
	}
	if strings.Contains(src, "Permission manifests") {
		t.Error(".goreleaser.yaml still carries the stale description")
	}
	if !strings.Contains(src, "CGO_ENABLED=0") {
		t.Error("builds must set CGO_ENABLED=0")
	}
}
