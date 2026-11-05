package policy

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/Panda-Taps-LLC/watchdeck/internal/rules"
)

func TestNormalizePath(t *testing.T) {
	home := "/Users/you"
	cases := []struct {
		in, cwd string
		want    string
		ok      bool
	}{
		{"/etc/hosts", "", "/etc/hosts", true},
		{"~/.zshrc", "", "/Users/you/.zshrc", true},
		{"~", "", "/Users/you", true},
		{"notes/../.zshrc", "/Users/you", "/Users/you/.zshrc", true},
		{"./a//b/./c", "/proj", "/proj/a/b/c", true},
		{"/a/b/../../Users/you/.ssh/id_x", "", "/Users/you/.ssh/id_x", true},
		{"~root/.ssh/id_x", "", "~root/.ssh/id_x", false},
		{"rel/x", "", "rel/x", false},
		{"rel/x", "relcwd", "rel/x", false},
		{"", "/x", "", false},
		{"/a\x00b", "", "", false},
	}
	for _, c := range cases {
		got := NormalizePath(c.in, c.cwd, home)
		if got.Lexical != c.want || got.OK != c.ok {
			t.Errorf("NormalizePath(%q, %q) = %+v, want %q ok=%v", c.in, c.cwd, got, c.want, c.ok)
		}
	}
}

func TestNormalizePathResolvesSymlinks(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	if err := os.MkdirAll(filepath.Join(real, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	// a file that does not exist yet still gets its parent resolved
	got := NormalizePath(filepath.Join(link, "sub", "new.txt"), "", "")
	rr, _ := filepath.EvalSymlinks(real)
	if !got.OK || got.Real != filepath.Join(rr, "sub", "new.txt") {
		t.Fatalf("real spelling: %+v (want under %s)", got, rr)
	}
}

func TestNormalizeHost(t *testing.T) {
	cases := []struct {
		in, want string
		ok       bool
	}{
		{"https://Example.COM/path?q=1", "example.com", true},
		{"https://user:pw@example.com:8443/x", "example.com", true},
		{"//example.com/x", "example.com", true},
		{"user@example.com/x", "example.com", true},
		{"example.com", "example.com", true},
		{"example.com.", "example.com", true},
		{"http://[::1]:8080/", "::1", true},
		{"http://127.0.0.1/", "127.0.0.1", true},
		{"https://%65xample.com/", "", false}, // net/url refuses an escape in a host: not normalisable (gate asks)
		{"https://bücher.example/", "bücher.example", false},
		{"https://xn--bcher-kva.example/", "xn--bcher-kva.example", true},
		{"", "", false},
		{"https:///path", "path", true}, // WHATWG: the slashes collapse
		// WHATWG: special schemes take any number of slashes and backslashes
		{"http:/evil.com/", "evil.com", true},
		{"http:evil.com/x", "evil.com", true},
		{`https:\\evil.com\x`, "evil.com", true},
		{`https://evil.com\@good.com/`, "evil.com", true},
		{"HTTPS:///evil.com", "evil.com", true},
		{"ws:/evil.com", "evil.com", true},
		// other schemes without an authority have no host
		{"javascript:alert(1)", "", false},
		{"data:text/plain,x", "", false},
		{"file:/etc/passwd", "", false},
		// host:port is not a scheme
		{"localhost:8080/x", "localhost", true},
		{"example.com:443", "example.com", true},
	}
	for _, c := range cases {
		got := NormalizeHost(c.in)
		if got.Lexical != c.want || got.OK != c.ok {
			t.Errorf("NormalizeHost(%q) = %+v, want %q ok=%v", c.in, got, c.want, c.ok)
		}
	}
}

func TestSplitMCPTool(t *testing.T) {
	cases := []struct {
		in   string
		want [][2]string
	}{
		{"mcp__github__create_issue", [][2]string{{"github", "create_issue"}}},
		{"mcp__claude_ai_Claude_Docs__batch", [][2]string{{"claude_ai_Claude_Docs", "batch"}}},
		{"mcp__plugin_figma_figma__get_code_connect_map", [][2]string{{"plugin_figma_figma", "get_code_connect_map"}}},
		{"mcp__a__b__c", [][2]string{{"a", "b__c"}, {"a__b", "c"}}},
		{"mcp__nosplit", nil},
		{"Bash", nil},
	}
	for _, c := range cases {
		got, ok := SplitMCPTool(c.in)
		if !reflect.DeepEqual(got, c.want) || ok != (c.want != nil) {
			t.Errorf("SplitMCPTool(%q) = %v %v, want %v", c.in, got, ok, c.want)
		}
	}
}

func TestGateHostAndResolvedEntries(t *testing.T) {
	p := loadPair(t, `version: 2
subjects:
  - {kind: tool, name: web, match: {tools: [WebFetch]}, domains: {deny: [127.0.0.1, '*.pastebin.com'], ask: [example.com]}}
`, "")
	if d := p.GateHost("WebFetch", "127.0.0.1"); d.Action != ActionDeny {
		t.Fatalf("IP literal: %+v", d)
	}
	if d := p.GateHost("WebFetch", "x.pastebin.com"); d.Action != ActionDeny {
		t.Fatalf("subdomain: %+v", d)
	}
	if d := p.GateHost("WebFetch", "example.com"); d.Action != ActionAsk {
		t.Fatalf("ask: %+v", d)
	}
	if d := p.GateHost("WebSearch", "example.com"); d.Action != ActionNone {
		t.Fatalf("other tool: %+v", d)
	}

	// an entry spelled through a symlink matches the target's real spelling
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	os.MkdirAll(real, 0o700)
	link := filepath.Join(dir, "link")
	os.Symlink(real, link)
	q := loadPair(t, "version: 2\nsubjects:\n  - {kind: tool, name: f, match: {tools: [Write]}, paths: {deny: ['"+link+"']}}\n", "")
	rr, _ := filepath.EvalSymlinks(real)
	target := filepath.Join(rr, "x")
	if d := q.ToolGate("Write", target); d.Action != ActionNone {
		t.Fatalf("pure lookup resolved an entry: %+v", d)
	}
	q.ResolveEntries = true
	if d := q.ToolGate("Write", target); d.Action != ActionDeny {
		t.Fatalf("resolved entry: %+v", d)
	}
}

func TestEvalRules(t *testing.T) {
	p := loadPair(t, `version: 2
rules:
  - {id: no-prod-db, tool: Bash, match: {regex: 'psql .*prod'}, action: deny, severity: high}
  - {id: tf, tool: Bash, match: {argv0: [terraform], regex: destroy}, action: ask}
  - {id: gh-delete, tool: 'mcp__github__*', match: {literals: [delete]}, action: log}
  - {id: q, tool: WebSearch, match: {literals: [password]}, action: ask}
`, `version: 2
rules:
  - {id: proj-log, tool: '*', match: {argv0: [curl]}, action: log}
`)
	hits := p.EvalRules("Bash", rules.Input{Command: "psql -h prod; terraform destroy; curl x"})
	var got []string
	for _, h := range hits {
		got = append(got, h.Rule+":"+string(h.Action))
		if h.Pack != UserPack {
			t.Fatalf("pack %q", h.Pack)
		}
	}
	if !reflect.DeepEqual(got, []string{"no-prod-db:deny", "tf:ask", "proj-log:log"}) {
		t.Fatalf("bash hits %v", got)
	}
	// argv0 rules never apply to other tools
	if hits := p.EvalRules("Read", rules.Input{FilePath: "/curl"}); len(hits) != 0 {
		t.Fatalf("argv0 rule on Read: %+v", hits)
	}
	if hits := p.EvalRules("mcp__github__x", rules.Input{Text: `{"op":"delete"}`}); len(hits) != 1 || hits[0].Action != rules.Log {
		t.Fatalf("mcp hits %+v", hits)
	}
	if hits := p.EvalRules("WebSearch", rules.Input{Text: "reset password"}); len(hits) != 1 {
		t.Fatalf("websearch hits %+v", hits)
	}
	// a hand-edited regex that does not compile fails closed (ask/deny) and
	// is skipped for log
	bad := loadPair(t, "version: 2\nrules:\n  - {id: broken, tool: Bash, match: {regex: '('}, action: ask}\n  - {id: broken-log, tool: Bash, match: {regex: '('}, action: log}\n", "")
	if hits := bad.EvalRules("Bash", rules.Input{Command: "ls"}); len(hits) != 1 || hits[0].Rule != "broken" || hits[0].Action != rules.Ask || !strings.Contains(hits[0].Description, "could not be compiled") {
		t.Fatalf("broken rule: %+v", hits)
	}
}

func TestLoadCached(t *testing.T) {
	dir := t.TempDir()
	cache := filepath.Join(dir, "state", CacheFile)
	up := filepath.Join(dir, "cfg", "overrides.yaml")
	pp := filepath.Join(dir, "proj", ".watchdeck.yaml")

	// neither file: no cache written, nothing opened
	l := LoadCached(cache, up, pp)
	if !l.Absent || l.Policy == nil {
		t.Fatalf("absent: %+v", l)
	}
	if _, err := os.Stat(cache); err == nil {
		t.Fatal("cache written with no policy file")
	}

	writeFile(t, up, "version: 2\nsubjects:\n  - {kind: mcp, name: github, tools: {'delete_*': deny}}\n")
	l = LoadCached(cache, up, pp)
	if l.Absent || !l.Rebuilt || l.UserErr != nil || l.Policy.MCPToolAction("github", "delete_repo").Action != ActionDeny {
		t.Fatalf("first load: %+v", l)
	}
	fi, err := os.Stat(cache)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("cache mode: %v %v", fi, err)
	}
	l = LoadCached(cache, up, pp)
	if l.Rebuilt || l.Policy.MCPToolAction("github", "delete_repo").Action != ActionDeny {
		t.Fatalf("cached load: %+v", l)
	}

	// a change in the file (size) rebuilds
	writeFile(t, up, "version: 2\nsubjects:\n  - {kind: mcp, name: github, tools: {'delete_*': ask}}\n")
	l = LoadCached(cache, up, pp)
	if !l.Rebuilt || l.Policy.MCPToolAction("github", "delete_repo").Action != ActionAsk {
		t.Fatalf("after edit: %+v", l)
	}

	// a malformed project file is reported and contributes nothing; the
	// user layer still applies
	writeFile(t, pp, "version: 9\n")
	l = LoadCached(cache, up, pp)
	if l.ProjectErr == nil || l.UserErr != nil || l.Policy.MCPToolAction("github", "delete_repo").Action != ActionAsk {
		t.Fatalf("bad project: %+v", l)
	}
	l = LoadCached(cache, up, pp)
	if l.Rebuilt || l.ProjectErr == nil {
		t.Fatalf("cached error: %+v", l)
	}

	// the cached JSON gives the same policy as a fresh parse
	writeFile(t, pp, "version: 2\npacks: {exfil: {action: deny}}\nsubjects:\n  - {kind: tool, name: f, match: {tools: [Write]}, paths: {deny: ['~/.zshrc'], ask: ['/etc/**']}}\n  - {kind: agent, name: r, match: {agent_type: researcher}, tools: {deny: [Bash]}, skills: {allow: [pdf]}}\n  - {kind: skill, name: pdf, grant: {network: localhost, write: [./out]}}\n")
	writeFile(t, up, "version: 2\ndefaults: {network: localhost}\nrule_overrides: {\"exfil/curl-data-file\": off}\nrules:\n  - {id: r1, tool: Bash, match: {regex: x}, action: deny}\nsubjects:\n  - {kind: command, name: npm, match: {argv0: [npm]}, grant: {network: all, auto_allow: true}}\n")
	fresh := LoadCached("", up, pp)
	LoadCached(cache, up, pp)
	cached := LoadCached(cache, up, pp)
	if cached.Rebuilt {
		t.Fatal("not served from cache")
	}
	if !reflect.DeepEqual(fresh.Policy, cached.Policy) || !reflect.DeepEqual(fresh.Warnings, cached.Warnings) {
		t.Fatalf("cache round trip differs:\n%+v\n%+v", fresh.Policy, cached.Policy)
	}
}

func TestExtraMatchers(t *testing.T) {
	off := rules.Config{Packs: map[string]rules.PackConfig{}}
	f := false
	for _, pk := range rules.Packs() {
		off.Packs[pk.Name] = rules.PackConfig{Enabled: &f}
	}
	empty, _ := New(Layer{}, Layer{})
	if m := empty.ExtraMatchers(off); !reflect.DeepEqual(m, Matchers{}) {
		t.Fatalf("nothing configured: %+v", m)
	}
	// default packs watch Read/Write/Edit (secrets-read, persistence,
	// cred-in-write), not WebFetch before the fetch
	if m := empty.ExtraMatchers(rules.Config{}); !m.Files || m.Web || m.MCP || m.PostWebFetch {
		t.Fatalf("defaults: %+v", m)
	}
	on := true
	pi := rules.Config{Packs: map[string]rules.PackConfig{"prompt-injection": {Enabled: &on}}}
	if m := empty.ExtraMatchers(pi); !m.PostWebFetch {
		t.Fatalf("prompt-injection on: %+v", m)
	}
	p := loadPair(t, `version: 2
subjects:
  - {kind: mcp, name: github, tools: {'delete_*': deny}}
  - {kind: tool, name: web, match: {tools: [WebFetch]}, domains: {deny: ['*.pastebin.com']}}
  - {kind: agent, name: r, match: {agent_type: researcher}, tools: {deny: [Glob, Task]}}
`, "")
	m := p.ExtraMatchers(off)
	if m.Files || !m.Web || !m.MCP || m.All || !reflect.DeepEqual(m.Other, []string{"Glob", "Task"}) {
		t.Fatalf("gates: %+v", m)
	}
	w := loadPair(t, "version: 2\nsubjects:\n  - {kind: agent, name: r, match: {agent_type: '*'}, tools: {ask: ['*']}}\n", "")
	if m := w.ExtraMatchers(off); !m.All || !m.MCP {
		t.Fatalf("wildcard: %+v", m)
	}
	if !p.GatesFor("mcp__github__delete_repo") || p.GatesFor("mcp__other__x") || !p.GatesFor("WebFetch") || p.GatesFor("Read") || !p.GatesFor("Glob") {
		t.Fatal("GatesFor")
	}
	_ = runtime.GOOS
}
