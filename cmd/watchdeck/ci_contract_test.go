package main

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestCIJobsPinTheirContract pins the jobs and the strings in ci.yml that
// carry meaning: tool versions, the commands each job runs, and the counts
// that tell which jobs run on macOS.
func TestCIJobsPinTheirContract(t *testing.T) {
	b, err := os.ReadFile("../../.github/workflows/ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)

	lines := strings.Split(s, "\n")
	for _, job := range []string{"test", "lint", "vuln", "install", "plugin", "fuzz", "latency", "repro-a", "repro-b", "repro-compare", "secrets"} {
		want := "  " + job + ":"
		found := false
		for _, l := range lines {
			if strings.TrimRight(l, " \t\r") == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("ci.yml has no column-2 job key %q", want)
		}
	}

	for _, want := range []string{
		"staticcheck@v0.8.2",
		"govulncheck@v1.8.0",
		"@anthropic-ai/claude-code@2.1.304",
		"claude plugin validate plugin --strict",
		"claude plugin test plugin",
		"sh scripts/test-install.sh",
		"sh scripts/test-release-scripts.sh",
		"- target: FuzzEval",
		"- target: FuzzGatesNeverAllow",
		"- target: FuzzParsePolicyFile",
		"-fuzztime=20s",
		`CHECK: "1"`,
		"continue-on-error: true",
		"args: build --snapshot --clean",
		"git diff --exit-code -- go.mod go.sum",
		"needs: [repro-a, repro-b]",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("ci.yml lacks %q", want)
		}
	}

	if n := strings.Count(s, "runs-on: macos-latest"); n != 1 {
		t.Errorf("runs-on: macos-latest appears %d times, want 1 (the latency job)", n)
	}
	if n := strings.Count(s, "os: [macos-latest, ubuntu-24.04]"); n != 2 {
		t.Errorf("os matrix [macos-latest, ubuntu-24.04] appears %d times, want 2 (test, install)", n)
	}

	// secrets: the job's own lines and the config it names.
	for _, p := range secretsJobProblems(s) {
		t.Error(p)
	}
	cfg, err := os.ReadFile("../../.gitleaks.toml")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range gitleaksConfigProblems(string(cfg)) {
		t.Error(p)
	}
}

// TestCIGuardCatchesSecretsWeakenings applies the levers that would weaken
// the secrets job silently to the real files' text and requires the guard
// to name each one; the clean text must pass (review of Plan 07, I3).
func TestCIGuardCatchesSecretsWeakenings(t *testing.T) {
	ciB, err := os.ReadFile("../../.github/workflows/ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	cfgB, err := os.ReadFile("../../.gitleaks.toml")
	if err != nil {
		t.Fatal(err)
	}
	ci, cfg := string(ciB), string(cfgB)
	if p := secretsJobProblems(ci); len(p) != 0 {
		t.Fatalf("clean ci.yml: %v", p)
	}
	if p := gitleaksConfigProblems(cfg); len(p) != 0 {
		t.Fatalf("clean .gitleaks.toml: %v", p)
	}

	// inSecrets replaces old with new once, after the secrets job's key, so
	// the same line in another job is left alone.
	inSecrets := func(old, new string) string {
		i := strings.Index(ci, "\n  secrets:\n")
		if i < 0 {
			t.Fatal("no secrets job")
		}
		head, tail := ci[:i], ci[i:]
		if !strings.Contains(tail, old) {
			t.Fatalf("secrets job lacks %q", old)
		}
		return head + strings.Replace(tail, old, new, 1)
	}
	for name, mutated := range map[string]string{
		"fetch-depth removed":         inSecrets("        with:\n          fetch-depth: 0\n", ""),
		"fetch-depth 1":               inSecrets("fetch-depth: 0", "fetch-depth: 1"),
		"job continue-on-error":       inSecrets("  secrets:\n", "  secrets:\n    continue-on-error: true\n"),
		"step continue-on-error":      inSecrets("      - name: Scan the history\n", "      - name: Scan the history\n        continue-on-error: true\n"),
		"job if":                      inSecrets("  secrets:\n", "  secrets:\n    if: false\n"),
		"step if":                     inSecrets("      - name: Scan the history\n", "      - name: Scan the history\n        if: github.event_name == 'push'\n"),
		"scan exit swallowed":         inSecrets(" --config .gitleaks.toml .'", " --config .gitleaks.toml . || true'"),
		"checksum exit swallowed":     inSecrets("| sha256sum -c -\n", "| sha256sum -c - || true\n"),
		"scan line prefixed by echo":  strings.Replace(ci, `run: '"$RUNNER_TEMP/gitleaks" git`, `run: 'echo "$RUNNER_TEMP/gitleaks" git`, 1),
		"scan step only in a comment": inSecrets(`        run: '"$RUNNER_TEMP/gitleaks"`, `        # run: '"$RUNNER_TEMP/gitleaks"`),
	} {
		if p := secretsJobProblems(mutated); len(p) == 0 {
			t.Errorf("ci.yml mutation %q passes the guard", name)
		}
	}
	for name, mutated := range map[string]string{
		"unscoped allowlist":     cfg + "\n[[allowlists]]\ndescription = \"everything\"\npaths = ['''.''']\n",
		"unanchored path":        cfg + "\n[[allowlists]]\ntargetRules = [\"curl-auth-user\"]\npaths = ['''testdata/.*''']\n",
		"regex beside the path":  strings.Replace(cfg, "targetRules = [\"curl-auth-user\"]\n", "targetRules = [\"curl-auth-user\"]\nregexes = ['''.''']\n", 1),
		"empty targetRules":      strings.Replace(cfg, "targetRules = [\"curl-auth-user\"]", "targetRules = []", 1),
		"legacy global table":    cfg + "\n[allowlist]\npaths = ['''.''']\n",
		"inline allowlists key":  strings.Replace(cfg, "title = \"watchdeck\"\n", "title = \"watchdeck\"\nallowlists = [{paths = ['''.''']}]\n", 1),
		"default rules disabled": strings.Replace(cfg, "useDefault = true\n", "useDefault = true\ndisabledRules = [\"curl-auth-user\"]\n", 1),
		"default rules off":      strings.Replace(cfg, "useDefault = true", "useDefault = false", 1),
		"custom rule table":      cfg + "\n[[rules]]\nid = \"x\"\nregex = '''x'''\n",
	} {
		if mutated == cfg {
			t.Fatalf("mutation %q did not apply", name)
		}
		if p := gitleaksConfigProblems(mutated); len(p) == 0 {
			t.Errorf(".gitleaks.toml mutation %q passes the guard", name)
		}
	}
}

// secretsJobProblems checks the secrets job in ci.yml over the job's own
// lines, comments skipped: gitleaks pinned by version, by the release URL
// and by the literal `sha256sum -c` line; the full-history checkout; the
// scan step's exact run line, so no flag can be dropped and no `|| true`
// added; and neither `if:` nor `continue-on-error` anywhere in the job,
// since either would let the job pass without a scan. A re-pin edits this
// function too (CONTRIBUTING "Releasing").
func secretsJobProblems(ci string) []string {
	job := jobLines(strings.Split(ci, "\n"), "secrets")
	if job == nil {
		return []string{"ci.yml has no secrets job"}
	}
	var code []string
	for _, l := range job {
		if t := strings.TrimSpace(l); t != "" && !strings.HasPrefix(t, "#") {
			code = append(code, t)
		}
	}
	has := func(re string) bool {
		r := regexp.MustCompile(re)
		for _, t := range code {
			if r.MatchString(t) {
				return true
			}
		}
		return false
	}
	var out []string
	for _, want := range []struct{ re, what string }{
		{`^fetch-depth:\s*0\s*(#.*)?$`, "fetch-depth: 0 on the checkout"},
		{`gitleaks_8\.30\.1_linux_x64\.tar\.gz`, "gitleaks_8.30.1"},
		{`^https://github\.com/gitleaks/gitleaks/releases/download/v8\.30\.1/gitleaks_8\.30\.1_linux_x64\.tar\.gz$`, "the release URL"},
		{`^echo "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb  gitleaks\.tar\.gz" \| sha256sum -c -$`, "the digest line read by sha256sum -c"},
		{`^run: '"\$RUNNER_TEMP/gitleaks" git --redact --no-banner --exit-code 1 --config \.gitleaks\.toml \.'$`, "the scan step's exact run line"},
	} {
		if !has(want.re) {
			out = append(out, "secrets job lacks "+want.what+" outside a comment")
		}
	}
	ifKey := regexp.MustCompile(`^(-\s+)?if\s*:`)
	for _, t := range code {
		if ifKey.MatchString(t) {
			out = append(out, "secrets job has a condition: "+t)
		}
		if strings.Contains(t, "continue-on-error") {
			out = append(out, "secrets job may fail silently: "+t)
		}
	}
	return out
}

// jobLines returns the lines of the column-2 job key job in a workflow,
// from its key line up to the next non-comment line indented two spaces or
// less (the next job, or a top-level key), or nil when there is no such job.
func jobLines(lines []string, job string) []string {
	start := -1
	for i, l := range lines {
		if strings.TrimRight(l, " \t\r") == "  "+job+":" {
			start = i
			break
		}
	}
	if start < 0 {
		return nil
	}
	for i := start + 1; i < len(lines); i++ {
		t := strings.TrimSpace(lines[i])
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if len(lines[i])-len(strings.TrimLeft(lines[i], " ")) <= 2 {
			return lines[start:i]
		}
	}
	return lines[start:]
}

// gitleaksConfigProblems checks .gitleaks.toml's shape: only `title` at the
// top, `[extend]` with `useDefault = true` and nothing else, and only
// `[[allowlists]]` entries, each rule-scoped (a non-empty `targetRules`)
// and path-anchored (every `paths` entry a literal path ending in a file
// name with an extension and `$`), with no other key, so no entry can
// quiet a rule tree-wide or by content alone. Any other table (the legacy
// `[allowlist]`, custom `[[rules]]`) fails until a reviewer widens this.
func gitleaksConfigProblems(cfg string) []string {
	keyRe := regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*(.*)$`)
	strRe := regexp.MustCompile(`'''(.*?)'''|"((?:[^"\\]|\\.)*)"|'([^']*)'`)
	anchorRe := regexp.MustCompile(`^\^?(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_-]+(?:\\\.[A-Za-z0-9_-]+)+\$$`)
	strs := func(v string) []string {
		var vals []string
		for _, m := range strRe.FindAllStringSubmatch(v, -1) {
			switch {
			case strings.HasPrefix(m[0], "'''"):
				vals = append(vals, m[1])
			case strings.HasPrefix(m[0], `"`):
				vals = append(vals, strings.ReplaceAll(m[2], `\\`, `\`))
			default:
				vals = append(vals, m[3])
			}
		}
		return vals
	}

	type table struct {
		header string
		keys   map[string]string
		order  []string
	}
	tables := []*table{{header: "", keys: map[string]string{}}}
	var last string
	for _, raw := range strings.Split(cfg, "\n") {
		l := strings.TrimSpace(raw)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		cur := tables[len(tables)-1]
		if strings.HasPrefix(l, "[") {
			tables = append(tables, &table{header: l, keys: map[string]string{}})
			last = ""
			continue
		}
		if m := keyRe.FindStringSubmatch(l); m != nil {
			last = m[1]
			cur.keys[last] += m[2]
			cur.order = append(cur.order, last)
			continue
		}
		cur.keys[last] += " " + l // a continuation of a multi-line array
	}

	var out []string
	sawExtend := false
	for _, tb := range tables {
		allowed := map[string]bool{}
		switch tb.header {
		case "":
			allowed["title"] = true
		case "[extend]":
			sawExtend = true
			allowed["useDefault"] = true
			if strings.TrimSpace(tb.keys["useDefault"]) != "true" {
				out = append(out, ".gitleaks.toml does not extend the default rules (useDefault = true)")
			}
		case "[[allowlists]]":
			for _, k := range []string{"description", "targetRules", "paths"} {
				allowed[k] = true
			}
			if len(strs(tb.keys["targetRules"])) == 0 {
				out = append(out, ".gitleaks.toml has an allowlist entry without targetRules (it would quiet every rule)")
			}
			ps := strs(tb.keys["paths"])
			if len(ps) == 0 {
				out = append(out, ".gitleaks.toml has an allowlist entry without paths (it would quiet the rule tree-wide)")
			}
			for _, p := range ps {
				if !anchorRe.MatchString(p) {
					out = append(out, fmt.Sprintf(".gitleaks.toml allowlist path %q is not a literal file path ending in $", p))
				}
			}
		default:
			out = append(out, fmt.Sprintf(".gitleaks.toml has an unreviewed table %s", tb.header))
			continue
		}
		for _, k := range tb.order {
			if !allowed[k] {
				out = append(out, fmt.Sprintf(".gitleaks.toml has an unreviewed key %q in %q", k, tb.header))
			}
		}
	}
	if !sawExtend {
		out = append(out, ".gitleaks.toml does not extend the default rules (useDefault = true)")
	}
	return out
}
