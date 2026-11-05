package policy

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/manifest"
	"github.com/Panda-Taps-LLC/watchdeck/internal/rules"
)

// v1Corpus is every valid overrides input used by internal/manifest's
// tests, plus the two fixture files. Each one is tried as the user file and
// as the project file.
func v1Corpus(t *testing.T) map[string]string {
	t.Helper()
	read := func(name string) string {
		b, err := os.ReadFile(filepath.Join("..", "manifest", "testdata", "overrides", name))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	return map[string]string{
		"fixture-user":      read("user.yaml"),
		"fixture-project":   read("project.yaml"),
		"contract":          "version: 1\ndefaults:\n  auto_allow: false\nskills:\n  pdf:\n    network: all\n    write: [\"~/Library/Caches/pip\"]\n    caches: true\n    auto_allow: true\n",
		"parent-of-deny":    "version: 1\nskills:\n  pdf:\n    write: [\"~\"]\n",
		"relative":          "version: 1\ndefaults:\n  write: [\"build\", \"./out/\", \".\", \"./\"]\n  read: [\"data\"]\n",
		"empty-block":       "version: 1\nskills:\n  pdf:\n",
		"no-blocks":         "version: 1\n",
		"auto-precedence":   "version: 1\ndefaults:\n  auto_allow: true\nskills:\n  pdf:\n    auto_allow: false\n",
		"star-synonym":      "version: 1\nskills:\n  \"*\":\n    network: localhost\n    auto_allow: true\n  pdf:\n    auto_allow: false\n",
		"star-and-defaults": "version: 1\ndefaults:\n  auto_allow: false\n  env: [\"A_KEY\"]\nskills:\n  \"*\":\n    auto_allow: true\n    write: [\"/opt/x\"]\n",
		"project-clipped":   "version: 1\ndefaults:\n  auto_allow: true\n  caches: true\nskills:\n  pdf:\n    network: all\n    write: [\"${CWD}/build\", \"~/Library/Caches/pip\", \"/etc\"]\n    env: [\"API_KEY\"]\n  xlsx:\n    network: localhost\n    read: [\"${TMP}/in\", \"~/Documents\"]\n",
		"read-env":          "version: 1\nskills:\n  csv:\n    read: [\"/data\", \"${CWD}/in\"]\n    env: [\"PGHOST\", \"PGPORT\"]\n    network: none\n",
	}
}

var corpusSkills = []string{"pdf", "docx", "xlsx", "csv", "unknown", "*"}

func writeFile(t *testing.T, path, text string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

type grantResult struct {
	Eff     manifest.Effective
	Ignored []string
}

func manifestGrants(t *testing.T, userDir, projDir string) map[string]grantResult {
	t.Helper()
	u, p, err := manifest.LoadOverrides(userDir, projDir)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]grantResult{}
	for _, s := range corpusSkills {
		e, ig := manifest.Grant(s, u, p)
		out[s] = grantResult{e, ig}
	}
	return out
}

func policyGrants(t *testing.T, userPath, projPath string) map[string]grantResult {
	t.Helper()
	pol, _, err := Load(userPath, projPath)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]grantResult{}
	for _, s := range corpusSkills {
		e, ig := pol.SkillGrant(s)
		out[s] = grantResult{e, ig}
	}
	return out
}

// TestSkillGrantEqualsManifestGrant: for every v1 input as user and as
// project file (and every pair), SkillGrant returns exactly manifest.Grant;
// after saving both files as v2 and reloading, the grants (and the ignored
// lists) are still identical; a second save is byte-identical.
func TestSkillGrantEqualsManifestGrant(t *testing.T) {
	corpus := v1Corpus(t)
	for un, utext := range corpus {
		for pn, ptext := range corpus {
			t.Run(un+"+"+pn, func(t *testing.T) {
				dir := t.TempDir()
				userDir, projDir := filepath.Join(dir, "cfg"), filepath.Join(dir, "proj")
				userPath := filepath.Join(userDir, manifest.UserOverridesFile)
				projPath := filepath.Join(projDir, manifest.ProjectOverridesFile)
				writeFile(t, userPath, utext)
				writeFile(t, projPath, ptext)

				want := manifestGrants(t, userDir, projDir)
				if got := policyGrants(t, userPath, projPath); !reflect.DeepEqual(got, want) {
					t.Fatalf("v1 SkillGrant differs from manifest.Grant:\n got %+v\nwant %+v", got, want)
				}

				// v1 → v2 save, reload.
				for _, p := range []string{userPath, projPath} {
					f, _, err := LoadFile(p)
					if err != nil {
						t.Fatal(err)
					}
					if _, err := Save(p, f); err != nil {
						t.Fatal(err)
					}
				}
				first, _ := os.ReadFile(userPath)
				if !bytes.HasPrefix(first, []byte("# watchdeck policy file")) || !bytes.Contains(first, []byte("\nversion: 2\n")) {
					t.Fatalf("not saved as v2:\n%s", first)
				}
				if got := policyGrants(t, userPath, projPath); !reflect.DeepEqual(got, want) {
					t.Fatalf("after v2 save, SkillGrant differs:\n got %+v\nwant %+v", got, want)
				}
				// manifest.LoadOverrides (hook, run) reads the v2 files the same way.
				if got := manifestGrants(t, userDir, projDir); !reflect.DeepEqual(got, want) {
					t.Fatalf("after v2 save, manifest.Grant differs:\n got %+v\nwant %+v", got, want)
				}
				// Byte-stable re-save.
				f, _, err := LoadFile(userPath)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := Save(userPath, f); err != nil {
					t.Fatal(err)
				}
				second, _ := os.ReadFile(userPath)
				if !bytes.Equal(first, second) {
					t.Fatalf("re-save not byte-stable:\n%s\n---\n%s", first, second)
				}
			})
		}
	}
}

const fullV2 = `version: 2
packs: {secrets-read: on, exfil: {action: ask}, destructive: off, persistence: {enabled: true, action: deny}}
rule_overrides: {"exfil/curl-data-file": off, "pipe-to-shell/curl-pipe-shell": {action: deny}}
rules:
  - {id: no-prod-db, tool: Bash, match: {regex: 'psql .*prod'}, action: deny, severity: high}
  - {id: warn-aws, tool: Bash, match: {argv0: [aws], literals: [" s3 rm "]}, action: log}
defaults: {network: localhost}
subjects:
  - {kind: skill,   name: pdf, grant: {network: all, write: [./out], env: [PDF_KEY], caches: true, auto_allow: true}}
  - {kind: skill,   name: "*", grant: {auto_allow: false}}
  - {kind: command, name: npm-scripts, match: {argv0: [npm], glob: ['npm run *']}, grant: {network: all, write: [./node_modules]}}
  - {kind: command, name: make, match: {argv0: [make]}}
  - {kind: mcp,     name: github, tools: {'delete_*': deny, 'create_*': ask}, launch: {sandbox: true, grant: {network: all}}}
  - {kind: tool,    name: files, match: {tools: [Write, Edit]}, paths: {deny: ['~/.zshrc', '~/Library/LaunchAgents/**'], ask: ['**/.git/config']}}
  - {kind: tool,    name: web,   match: {tools: [WebFetch]}, domains: {deny: ['*.pastebin.com'], ask: [example.org]}}
  - {kind: agent,   name: researcher, match: {agent_type: researcher}, tools: {deny: [Bash, Write]}, skills: {allow: [pdf]}}
scope: {}
`

func TestParseFullV2AndRoundTrip(t *testing.T) {
	f, err := manifest.ParsePolicyFile([]byte(fullV2))
	if err != nil {
		t.Fatal(err)
	}
	if f.Version != 2 || len(f.Subjects) != 8 || len(f.Rules) != 2 || len(f.Packs) != 4 || len(f.RuleOverrides) != 2 {
		t.Fatalf("parsed %+v", f)
	}
	if !*f.Packs["secrets-read"].Enabled || *f.Packs["destructive"].Enabled || f.Packs["exfil"].Action != "ask" || f.Packs["exfil"].Enabled != nil ||
		!*f.Packs["persistence"].Enabled || f.Packs["persistence"].Action != "deny" {
		t.Errorf("packs %+v", f.Packs)
	}
	// It maps 1:1 onto a valid internal/rules configuration.
	cfg := FileRulesConfig(f)
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if pc := cfg.Packs["exfil"]; pc.Action != "ask" || pc.Enabled != nil {
		t.Errorf("rules config exfil = %+v", pc)
	}
	if rc := cfg.Rules["exfil/curl-data-file"]; rc.Enabled == nil || *rc.Enabled {
		t.Errorf("rules config curl-data-file = %+v", rc)
	}
	text := Render(f)
	back, err := manifest.ParsePolicyFile([]byte(text))
	if err != nil {
		t.Fatalf("render does not parse: %v\n%s", err, text)
	}
	if Render(back) != text {
		t.Fatalf("render not stable:\n%s\n---\n%s", text, Render(back))
	}
	if !reflect.DeepEqual(back.SkillOverrides(), f.SkillOverrides()) {
		t.Errorf("skill view changed in round trip")
	}
	// manifest.ParseOverrides projects the same skills.
	ov, err := manifest.ParseOverrides([]byte(fullV2))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(ov, f.SkillOverrides()) {
		t.Errorf("ParseOverrides projection %+v != %+v", ov, f.SkillOverrides())
	}
	if got := ov.Skills["pdf"].Write; !reflect.DeepEqual(got, []string{"${CWD}/out"}) {
		t.Errorf("relative grant path = %q", got)
	}
}

func TestClasses(t *testing.T) {
	f, err := manifest.ParsePolicyFile([]byte(fullV2))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]Class{
		"skill:pdf": ClassSandbox, "skill:*": ClassSandbox, "command:npm-scripts": ClassSandbox, "command:make": ClassSandbox,
		"mcp:github": ClassSandbox, "tool:files": ClassGate, "tool:web": ClassGate, "agent:researcher": ClassGate,
	}
	for _, s := range f.Subjects {
		if got := SubjectClass(s); got != want[s.Kind+":"+s.Name] {
			t.Errorf("%s:%s class %s", s.Kind, s.Name, got)
		}
	}
	// An mcp subject without a sandboxed launch is a gate.
	if c := SubjectClass(manifest.PolicySubject{Kind: KindMCP, Name: "x", MCPTools: map[string]string{"*": "ask"}}); c != ClassGate {
		t.Errorf("mcp tools-only = %s", c)
	}
	// In a project file the launch block is dropped, so the subject is a gate.
	dir := t.TempDir()
	proj := filepath.Join(dir, ".watchdeck.yaml")
	writeFile(t, proj, fullV2)
	pol, _, err := Load("", proj)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range pol.Subjects() {
		if s.Kind == KindMCP && (s.Launch != nil || s.Class() != ClassGate) {
			t.Errorf("project mcp subject kept launch: %+v", s)
		}
	}
}

func TestStrictParseErrors(t *testing.T) {
	cases := map[string]struct{ src, want string }{
		"unknown top":           {"version: 2\nsubject: []\n", "unknown field"},
		"unknown subject key":   {"version: 2\nsubjects:\n  - {kind: skill, name: pdf, grnt: {}}\n", "unknown field"},
		"unknown grant key":     {"version: 2\nsubjects:\n  - {kind: skill, name: pdf, grant: {netwrk: all}}\n", "unknown field"},
		"dup top key":           {"version: 2\npacks: {}\npacks: {}\n", "already defined"},
		"dup key in subject":    {"version: 2\nsubjects:\n  - {kind: skill, name: pdf, name: x}\n", "already defined"},
		"dup subject":           {"version: 2\nsubjects:\n  - {kind: skill, name: pdf}\n  - {kind: skill, name: pdf}\n", "subjects.skill:pdf: duplicate subject"},
		"bad kind":              {"version: 2\nsubjects:\n  - {kind: robot, name: x}\n", "subjects[0].kind: must be one of"},
		"no kind":               {"version: 2\nsubjects:\n  - {name: x}\n", "subjects[0].kind: required"},
		"bad skill name":        {"version: 2\nsubjects:\n  - {kind: skill, name: '-x'}\n", "subjects[0].name: invalid skill name"},
		"star command":          {"version: 2\nsubjects:\n  - {kind: command, name: '*', match: {argv0: [x]}}\n", "subjects[0].name: invalid name"},
		"bad mcp name":          {"version: 2\nsubjects:\n  - {kind: mcp, name: 'a b', tools: {x: deny}}\n", "invalid MCP server name"},
		"command no match":      {"version: 2\nsubjects:\n  - {kind: command, name: c}\n", "match: needs argv0 or glob"},
		"command bad argv0":     {"version: 2\nsubjects:\n  - {kind: command, name: c, match: {argv0: ['a b']}}\n", "match.argv0[0]"},
		"command tools":         {"version: 2\nsubjects:\n  - {kind: command, name: c, match: {argv0: [x], tools: [Bash]}}\n", "only argv0 and glob"},
		"skill match":           {"version: 2\nsubjects:\n  - {kind: skill, name: pdf, match: {argv0: [x]}}\n", "skill:pdf.match: not allowed for kind skill"},
		"skill grant deny":      {"version: 2\nsubjects:\n  - {kind: skill, name: pdf, grant: {write: ['~/.ssh']}}\n", "subjects.skill:pdf.grant.write[0]: cannot grant built-in deny path ~/.ssh"},
		"command grant env":     {"version: 2\nsubjects:\n  - {kind: command, name: c, match: {argv0: [x]}, grant: {env: [lower]}}\n", "grant.env[0]: invalid name"},
		"launch grant deny":     {"version: 2\nsubjects:\n  - {kind: mcp, name: m, launch: {grant: {read: ['~/.aws']}}}\n", "launch.grant.read[0]: cannot grant"},
		"mcp allow":             {"version: 2\nsubjects:\n  - {kind: mcp, name: m, tools: {'*': allow}}\n", "a gate cannot allow"},
		"mcp bad action":        {"version: 2\nsubjects:\n  - {kind: mcp, name: m, tools: {'*': maybe}}\n", "must be deny or ask"},
		"mcp empty":             {"version: 2\nsubjects:\n  - {kind: mcp, name: m}\n", "needs tools or launch"},
		"mcp paths":             {"version: 2\nsubjects:\n  - {kind: mcp, name: m, paths: {deny: [/x]}}\n", "paths: not allowed for kind mcp"},
		"tool allow key":        {"version: 2\nsubjects:\n  - {kind: tool, name: t, match: {tools: [Write]}, paths: {allow: [/x]}}\n", "unknown field"},
		"tool no tools":         {"version: 2\nsubjects:\n  - {kind: tool, name: t, paths: {deny: [/x]}}\n", "match.tools: required"},
		"tool no gate":          {"version: 2\nsubjects:\n  - {kind: tool, name: t, match: {tools: [Write]}}\n", "needs paths or domains"},
		"paths on Bash":         {"version: 2\nsubjects:\n  - {kind: tool, name: t, match: {tools: [Write, Bash]}, paths: {deny: [/x]}}\n", "match.tools[1]: paths apply only to"},
		"paths on a glob":       {"version: 2\nsubjects:\n  - {kind: tool, name: t, match: {tools: ['*']}, paths: {deny: [/x]}}\n", "match.tools[0]: paths apply only to"},
		"tool relative path":    {"version: 2\nsubjects:\n  - {kind: tool, name: t, match: {tools: [Write]}, paths: {deny: [rel/x]}}\n", "paths.deny[0]: invalid entry"},
		"tool cwd var":          {"version: 2\nsubjects:\n  - {kind: tool, name: t, match: {tools: [Write]}, paths: {deny: ['${CWD}/x']}}\n", "paths.deny[0]: invalid entry"},
		"tool dotdot":           {"version: 2\nsubjects:\n  - {kind: tool, name: t, match: {tools: [Write]}, paths: {ask: ['/a/../b']}}\n", "paths.ask[0]: invalid entry"},
		"tool bad domain":       {"version: 2\nsubjects:\n  - {kind: tool, name: t, match: {tools: [WebFetch]}, domains: {deny: ['http://x']}}\n", "domains.deny[0]: invalid entry"},
		"agent allow tools":     {"version: 2\nsubjects:\n  - {kind: agent, name: a, match: {agent_type: r}, tools: {allow: [Bash]}}\n", "a gate cannot allow"},
		"agent no type":         {"version: 2\nsubjects:\n  - {kind: agent, name: a, tools: {deny: [Bash]}}\n", "agent_type: required"},
		"agent empty":           {"version: 2\nsubjects:\n  - {kind: agent, name: a, match: {agent_type: r}}\n", "needs tools or skills"},
		"agent bad skill":       {"version: 2\nsubjects:\n  - {kind: agent, name: a, match: {agent_type: r}, skills: {allow: ['a b']}}\n", "skills.allow[0]"},
		"scope":                 {"version: 2\nscope: {agent_type: researcher}\n", "scope: not supported yet"},
		"subject scope":         {"version: 2\nsubjects:\n  - {kind: skill, name: pdf, scope: {user: me}}\n", "scope: not supported yet"},
		"pack bad id":           {"version: 2\npacks: {Exfil: on}\n", "packs: invalid pack name"},
		"pack bad scalar":       {"version: 2\npacks: {exfil: maybe}\n", "packs.exfil: must be on, off or {enabled"},
		"pack nested":           {"version: 2\npacks: {exfil: {action: [x]}}\n", "packs.exfil: must be on, off"},
		"pack unknown option":   {"version: 2\npacks: {exfil: {level: x}}\n", "packs.exfil: must be on, off"},
		"pack string enabled":   {"version: 2\npacks: {exfil: {enabled: maybe}}\n", "packs.exfil: must be on, off"},
		"pack bad action":       {"version: 2\npacks: {exfil: {action: allow}}\n", "packs.exfil: action: must be one of deny, ask, log"},
		"pack empty map":        {"version: 2\npacks: {exfil: {}}\n", "packs.exfil: empty mapping"},
		"rule override value":   {"version: 2\nrule_overrides: {\"a/b\": allow}\n", "rule_overrides.a/b: must be on, off"},
		"rule override action":  {"version: 2\nrule_overrides: {\"a/b\": {action: allow}}\n", "rule_overrides.a/b: action: must be one of"},
		"rule override id":      {"version: 2\nrule_overrides: {\"A B\": off}\n", "rule_overrides: invalid rule key"},
		"rule override no pack": {"version: 2\nrule_overrides: {\"curl\": off}\n", "rule_overrides: invalid rule key"},
		"rule id with slash":    {"version: 2\nrules:\n  - {id: exfil/curl-data-file, tool: Bash, match: {regex: x}, action: log}\n", "rules[0].id: required"},
		"version float":         {"version: 2.0\n", "version: must be an integer"},
		"version string":        {"version: \"2\"\n", "version: must be an integer"},
		"version string v1":     {"version: \"1\"\nskills: {}\n", "version: must be an integer"},
		"multi document":        {"version: 2\n---\nversion: 2\nsubjects:\n  - {kind: mcp, name: x, tools: {'*': deny}}\n", "more than one YAML document"},
		"multi document v1":     {"version: 1\n---\nversion: 1\n", "more than one YAML document"},
		"rule no match":         {"version: 2\nrules:\n  - {id: r, tool: Bash, action: deny}\n", "rules.r.match: needs"},
		"rule allow":            {"version: 2\nrules:\n  - {id: r, tool: Bash, match: {regex: x}, action: allow}\n", "rules.r.action: must be one of deny, ask, log"},
		"rule severity":         {"version: 2\nrules:\n  - {id: r, tool: Bash, match: {regex: x}, action: log, severity: huge}\n", "rules.r.severity"},
		"rule dup id":           {"version: 2\nrules:\n  - {id: r, tool: Bash, match: {regex: x}, action: log}\n  - {id: r, tool: Bash, match: {regex: y}, action: log}\n", "rules.r.id: duplicate rule id"},
		"rule no tool":          {"version: 2\nrules:\n  - {id: r, match: {regex: x}, action: log}\n", "rules.r.tool: required"},
		"version 3":             {"version: 3\n", "version: must be 1 or 2 (got 3)"},
		"version 2 bad skills":  {"version: 2\nskills:\n  pdf: {}\n", "unknown field"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := manifest.ParsePolicyFile([]byte(c.src))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
			// manifest.ParseOverrides (the hook's reader) refuses the same file.
			if _, err2 := manifest.ParseOverrides([]byte(c.src)); err2 == nil {
				t.Fatalf("ParseOverrides accepted what ParsePolicyFile refused")
			}
		})
	}
}

// TestErrorsCarryNoValues: an error never repeats a value from the file.
func TestErrorsCarryNoValues(t *testing.T) {
	const evil = "EVIL| requested but not granted"
	srcs := []string{
		"version: 2\nsubjects:\n  - {kind: \"" + evil + "\", name: x}\n",
		"version: 2\nsubjects:\n  - {kind: skill, name: \"" + evil + "\"}\n",
		"version: 2\nsubjects:\n  - {kind: mcp, name: m, tools: {\"" + evil + "\": deny}}\n",
		"version: 2\nsubjects:\n  - {kind: mcp, name: m, tools: {x: \"" + evil + "\"}}\n",
		"version: 2\npacks: {\"" + evil + "\": on}\n",
		"version: 2\npacks: {x: {action: \"" + evil + "\"}}\n",
		"version: 2\nrule_overrides: {\"" + evil + "\": on}\n",
		"version: 2\nrules:\n  - {id: \"" + evil + "\", tool: Bash, match: {regex: x}, action: log}\n",
		"version: 2\nsubjects:\n  - {kind: tool, name: t, match: {tools: [Write]}, paths: {deny: [\"" + evil + "\"]}}\n",
		"version: 2\n\"" + evil + "\": 1\n",
		"version: 2\ntemporary:\n  - {id: \"" + evil + "\", kind: rule, rule: exfil/x, until: \"2026-10-24T18:00:00Z\", added: \"2026-10-24T10:00:00Z\"}\n",
		"version: 2\ntemporary:\n  - {id: t-0000abcd, kind: rule, rule: \"" + evil + "\", until: \"2026-10-24T18:00:00Z\", added: \"2026-10-24T10:00:00Z\"}\n",
		"version: 2\ntemporary:\n  - {id: t-0000abcd, kind: rule, rule: exfil/x, until: \"" + evil + "\", added: \"2026-10-24T10:00:00Z\"}\n",
		"version: 2\ntemporary:\n  - {id: t-0000abcd, kind: grant, skill: \"" + evil + "\", grant: {network: all}, until: \"2026-10-24T18:00:00Z\", added: \"2026-10-24T10:00:00Z\"}\n",
	}
	for _, src := range srcs {
		_, err := manifest.ParsePolicyFile([]byte(src))
		if err == nil {
			t.Errorf("accepted %q", src)
			continue
		}
		if strings.Contains(err.Error(), "EVIL") || strings.Contains(err.Error(), "|") {
			t.Errorf("error echoes the value: %v", err)
		}
	}
}

func TestScopeEmptyAccepted(t *testing.T) {
	for _, src := range []string{"version: 2\nscope: {}\n", "version: 2\nscope:\n", "version: 2\n"} {
		f, err := manifest.ParsePolicyFile([]byte(src))
		if err != nil {
			t.Fatalf("%q: %v", src, err)
		}
		if strings.Contains(Render(f), "scope") {
			t.Errorf("empty scope rendered")
		}
	}
}

// builtinPicks chooses built-in packs and rules for the restriction tests
// from rules.Packs(), so re-tuning a pack's defaults does not break them.
type builtinPicks struct {
	onPack, offPack, lowPack, raisePack, disablePack, enablePack string
	ruleLog, ruleAsk, ruleOff, ruleOn                            string
	multiPack, multiR1, multiR2                                  string // a pack with two rules
}

func pickBuiltins(t *testing.T) builtinPicks {
	t.Helper()
	packs := rules.Packs()
	if len(packs) < 6 {
		t.Skipf("need 6 built-in packs, have %d", len(packs))
	}
	var b builtinPicks
	used := map[string]bool{}
	take := func(ok func(rules.Pack) bool) string {
		for _, pk := range packs {
			if !used[pk.Name] && ok(pk) {
				used[pk.Name] = true
				return pk.Name
			}
		}
		t.Skip("no built-in pack fits")
		return ""
	}
	maxRank := func(pk rules.Pack) int {
		m := 0
		for _, r := range pk.Rules {
			if x := rank(string(r.Action)); x > m {
				m = x
			}
		}
		return m
	}
	any := func(rules.Pack) bool { return true }
	b.enablePack = take(func(pk rules.Pack) bool { return !pk.EnabledByDefault() })
	b.lowPack = take(func(pk rules.Pack) bool { return maxRank(pk) >= 2 })
	b.onPack = take(any)
	b.offPack = take(any)
	b.raisePack = take(any)
	b.disablePack = take(any)
	for _, pk := range packs {
		for _, r := range pk.Rules {
			key := pk.Name + "/" + r.ID
			switch {
			case r.Action == rules.Log && b.ruleLog == "":
				b.ruleLog = key
			case r.Action == rules.Ask && b.ruleAsk == "":
				b.ruleAsk = key
			}
		}
	}
	for _, pk := range packs {
		for _, r := range pk.Rules {
			key := pk.Name + "/" + r.ID
			if key == b.ruleLog || key == b.ruleAsk {
				continue
			}
			switch {
			case b.ruleOff == "":
				b.ruleOff = key
			case b.ruleOn == "":
				b.ruleOn = key
			}
		}
		if len(pk.Rules) >= 2 && b.multiPack == "" {
			b.multiPack, b.multiR1, b.multiR2 = pk.Name, pk.Name+"/"+pk.Rules[0].ID, pk.Name+"/"+pk.Rules[1].ID
		}
	}
	if b.ruleLog == "" || b.ruleAsk == "" || b.ruleOn == "" || b.multiPack == "" {
		t.Skip("built-in rules do not cover the cases")
	}
	return b
}

// TestProjectRestrictions: every allow-ish field of a project file is
// ignored with a value-free Warning (command subjects, mcp launch, packs and
// rules that would be disabled or weakened, unknown packs and rules) or
// clipped when the grant is resolved (skill grants), and the same fields in
// the user file take effect.
func TestProjectRestrictions(t *testing.T) {
	b := pickBuiltins(t)
	src := `version: 2
packs:
  ` + b.onPack + `: on
  ` + b.offPack + `: off
  ` + b.lowPack + `: {action: log}
  ` + b.raisePack + `: {action: deny}
  ` + b.disablePack + `: {enabled: false, action: deny}
  ` + b.enablePack + `: {enabled: true}
  nosuch: on
rule_overrides:
  "` + b.ruleLog + `": {action: ask}
  "` + b.ruleAsk + `": {action: log}
  "` + b.ruleOff + `": off
  "` + b.ruleOn + `": on
  "` + b.onPack + `/nosuch": {action: deny}
rules:
  - {id: r1, tool: Bash, match: {regex: x}, action: log}
defaults: {auto_allow: true, caches: true, env: [A_KEY], network: all}
subjects:
  - {kind: command, name: npm, match: {argv0: [npm]}, grant: {network: all, auto_allow: true, env: [NPM_TOKEN], caches: true, write: ['${CWD}/node_modules', '~/.npm']}}
  - {kind: mcp, name: github, tools: {'delete_*': deny}, launch: {sandbox: true, grant: {network: all}}}
  - {kind: mcp, name: launch-only, launch: {sandbox: false}}
  - {kind: tool, name: files, match: {tools: [Write]}, paths: {deny: ['~/.zshrc']}}
  - {kind: agent, name: r, match: {agent_type: researcher}, tools: {ask: [Bash]}, skills: {allow: [pdf]}}
`
	dir := t.TempDir()
	proj := filepath.Join(dir, "p", ".watchdeck.yaml")
	user := filepath.Join(dir, "u", "overrides.yaml")
	writeFile(t, proj, src)

	pol, warns, err := Load("", proj)
	if err != nil {
		t.Fatal(err)
	}
	var ws []string
	for _, w := range warns {
		ws = append(ws, w.String())
	}
	const packWeak = "(the project file can only turn a pack on or raise its action)"
	const ruleWeak = "(the project file can only turn a rule on or raise its action)"
	packW := map[string]string{
		b.offPack:     packWeak,
		b.lowPack:     packWeak,
		b.disablePack: packWeak,
		"nosuch":      "(unknown pack)",
	}
	ruleW := map[string]string{
		b.ruleAsk:            ruleWeak,
		b.ruleOff:            ruleWeak,
		b.onPack + "/nosuch": "(unknown rule)",
	}
	want := []string{
		"project policy ignored: subjects.command:npm (only the user file can define a command subject)",
		"project policy ignored: subjects.mcp:github.launch (only the user file can launch an MCP server)",
		"project policy ignored: subjects.mcp:launch-only.launch (only the user file can launch an MCP server)",
	}
	for _, k := range sortedKeys(packW) {
		want = append(want, "project policy ignored: packs."+k+" "+packW[k])
	}
	for _, k := range sortedKeys(ruleW) {
		want = append(want, "project policy ignored: rule_overrides."+k+" "+ruleW[k])
	}
	if !reflect.DeepEqual(ws, want) {
		t.Fatalf("warnings\n%q\nwant\n%q", ws, want)
	}
	_, pp := pol.Packs()
	if len(pp) != 3 || !*pp[b.onPack].Enabled || pp[b.raisePack].Action != "deny" || !*pp[b.enablePack].Enabled {
		t.Errorf("project packs kept = %+v", pp)
	}
	_, pr := pol.RuleOverrides()
	if len(pr) != 2 || pr[b.ruleLog].Action != "ask" || !*pr[b.ruleOn].Enabled {
		t.Errorf("project rule overrides kept = %v", pr)
	}
	if err := pol.RulesConfig().Validate(); err != nil {
		t.Errorf("project rules config: %v", err)
	}
	if len(pol.Rules()) != 1 || pol.Rules()[0].Source != manifest.SourceProject {
		t.Errorf("project rules = %+v", pol.Rules())
	}
	for _, s := range pol.Subjects() {
		if s.Name == "launch-only" || s.Kind == KindCommand {
			t.Errorf("subject %s:%s kept", s.Kind, s.Name)
		}
	}
	if _, ok := pol.CommandSubject("npm install"); ok {
		t.Error("project command subject applied")
	}

	// Skill defaults: clipped by manifest.Widen, same wording as v1.
	eff, ig := pol.SkillGrant("pdf")
	if eff.AutoAllow || eff.Network != manifest.NetNone || len(ig) != 4 {
		t.Errorf("project defaults honoured: %+v %q", eff, ig)
	}
	// Gates from the project file stay.
	if d := pol.MCPToolAction("github", "delete_repo"); d.Action != ActionDeny {
		t.Errorf("project mcp gate = %+v", d)
	}
	if d := pol.AgentSkillAction("researcher", "xlsx"); d.Action != ActionDeny {
		t.Errorf("project agent skills = %+v", d)
	}

	// A project rule override below the user's pack action is a weakening.
	writeFile(t, user, "version: 2\npacks: {"+b.multiPack+": {action: deny}}\n")
	writeFile(t, proj, "version: 2\nrule_overrides: {\""+b.multiR1+"\": {action: ask}, \""+b.multiR2+"\": {action: deny}}\n")
	pol2, w2, err := Load(user, proj)
	if err != nil {
		t.Fatal(err)
	}
	if len(w2) != 1 || w2[0].Field != "rule_overrides."+b.multiR1 {
		t.Errorf("warnings = %v", w2)
	}
	if cfg := pol2.RulesConfig(); cfg.Packs[b.multiPack].Action != "deny" || len(cfg.Rules) != 1 || cfg.Rules[b.multiR2].Action != "deny" {
		t.Errorf("merged config = %+v", cfg)
	}

	// The same file as the user file: nothing ignored, everything honoured,
	// except unknown packs and rules, which the user file must not name to
	// be saved (Save validates the rules config).
	writeFile(t, user, src)
	upol, uw, err := Load(user, "")
	if err != nil || len(uw) != 0 {
		t.Fatalf("user warnings %v %v", uw, err)
	}
	ueff, _ := upol.SkillGrant("pdf")
	if !ueff.AutoAllow || ueff.Network != manifest.NetAll {
		t.Errorf("user defaults not honoured: %+v", ueff)
	}
	ucs, ok := upol.CommandSubject("npm install")
	if !ok {
		t.Fatal("user command subject missing")
	}
	if ceff, _ := upol.CommandGrant(ucs); !ceff.AutoAllow || ceff.Network != manifest.NetAll {
		t.Errorf("user command grant: %+v", ceff)
	}
	launched := false
	for _, s := range upol.Subjects() {
		if s.Name == "github" && s.Launch != nil && s.Class() == ClassSandbox {
			launched = true
		}
	}
	if !launched {
		t.Error("user mcp launch dropped")
	}
	up, _ := upol.Packs()
	if *up[b.offPack].Enabled {
		t.Errorf("user pack off not kept: %+v", up)
	}
	uf, _, _ := LoadFile(user)
	if _, err := Save(user, uf); err == nil || !strings.Contains(err.Error(), "unknown pack") {
		t.Errorf("save with unknown pack: %v", err)
	}
}

// TestUserOffWins: a pack or rule the user file turns off stays off; the
// project file cannot re-enable it, through the pack or through a rule.
func TestUserOffWins(t *testing.T) {
	b := pickBuiltins(t)
	dir := t.TempDir()
	user := filepath.Join(dir, "u", "overrides.yaml")
	proj := filepath.Join(dir, "p", ".watchdeck.yaml")
	offPack := b.multiPack
	offRule := b.ruleLog
	if pk, _, _ := strings.Cut(offRule, "/"); pk == offPack {
		offRule = b.ruleAsk
	}
	writeFile(t, user, "version: 2\npacks: {"+offPack+": off}\nrule_overrides: {\""+offRule+"\": off}\n")
	writeFile(t, proj, "version: 2\npacks: {"+offPack+": {enabled: true, action: deny}}\nrule_overrides: {\""+b.multiR1+"\": on, \""+offRule+"\": {enabled: true, action: deny}}\n")
	pol, warns, err := Load(user, proj)
	if err != nil {
		t.Fatal(err)
	}
	var fields []string
	for _, w := range warns {
		fields = append(fields, w.Field+" "+w.Reason)
		if strings.Contains(w.String(), "deny") {
			t.Errorf("warning echoes a value: %s", w)
		}
	}
	wantF := []string{
		"packs." + offPack + " the user file turned this pack off",
	}
	ruleKeys := []string{b.multiR1, offRule}
	sort.Strings(ruleKeys)
	for _, k := range ruleKeys {
		wantF = append(wantF, "rule_overrides."+k+" the user file turned this rule or its pack off")
	}
	if !reflect.DeepEqual(fields, wantF) {
		t.Fatalf("warnings\n%q\nwant\n%q", fields, wantF)
	}
	cfg := pol.RulesConfig()
	if pc := cfg.Packs[offPack]; pc.Enabled == nil || *pc.Enabled || pc.Action != "" {
		t.Errorf("pack = %+v", pc)
	}
	if rc := cfg.Rules[offRule]; rc.Enabled == nil || *rc.Enabled {
		t.Errorf("rule = %+v", rc)
	}
	if _, ok := cfg.Rules[b.multiR1]; ok {
		t.Errorf("project re-enabled a rule in a pack the user turned off")
	}
}

// TestSavedFilesAreValidRulesConfig: every v2 file that Save accepts maps
// onto an internal/rules Config that passes its Validate.
func TestSavedFilesAreValidRulesConfig(t *testing.T) {
	dir := t.TempDir()
	srcs := []string{fullV2, "version: 2\n", "version: 2\npacks: {prompt-injection: on}\nrule_overrides: {\"destructive/mkfs\": {enabled: true, action: deny}}\n"}
	for i, src := range srcs {
		f, err := manifest.ParsePolicyFile([]byte(src))
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, strconv.Itoa(i), "overrides.yaml")
		if _, err := Save(path, f); err != nil {
			t.Fatalf("%d: %v", i, err)
		}
		back, _, err := LoadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := FileRulesConfig(back).Validate(); err != nil {
			t.Errorf("%d: %v", i, err)
		}
	}
	bad, _ := manifest.ParsePolicyFile([]byte("version: 2\nrule_overrides: {\"exfil/no-such-rule\": off}\n"))
	if _, err := Save(filepath.Join(dir, "bad.yaml"), bad); err == nil {
		t.Error("unknown rule saved")
	}
}

// TestDuplicateEnvDeduped: a repeated env name renders once.
func TestDuplicateEnvDeduped(t *testing.T) {
	f, err := manifest.ParsePolicyFile([]byte("version: 1\nskills:\n  csv:\n    env: [\"PGHOST\", \"PGHOST\"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if out := Render(f); strings.Count(out, "PGHOST") != 1 {
		t.Errorf("env not deduped:\n%s", out)
	}
}

func TestLoadErrorsNamePath(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "x | requested but not granted", ".watchdeck.yaml")
	writeFile(t, p, "version: 2\nsubjects:\n  - {kind: robot, name: x}\n")
	_, _, err := Load("", p)
	if err == nil || strings.Contains(err.Error(), "|") || !strings.HasPrefix(err.Error(), manifest.DisplayPath(p)+": ") {
		t.Fatalf("err = %v", err)
	}
	// A missing file is empty, not an error.
	pol, w, err := Load(filepath.Join(dir, "none.yaml"), filepath.Join(dir, "none2.yaml"))
	if err != nil || len(w) != 0 || pol.User.Exists || pol.Project.Exists {
		t.Fatalf("missing: %v %v %+v", err, w, pol)
	}
	if eff, _ := pol.SkillGrant("pdf"); !reflect.DeepEqual(eff, manifest.Default()) {
		t.Errorf("empty policy grant = %+v", eff)
	}
}

// ---- Save ----

func TestSaveBackupModeAtomic(t *testing.T) {
	old := backupNow
	backupNow = func() time.Time { return time.Unix(1760000000, 0) }
	t.Cleanup(func() { backupNow = old })

	dir := t.TempDir()
	path := filepath.Join(dir, "cfg", "overrides.yaml")
	v1 := "version: 1\nskills:\n  pdf:\n    network: all\n"
	writeFile(t, path, v1)
	os.Chmod(path, 0o644)

	f, _, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := Apply(&f, Edit{Kind: KindSkill, Name: "docx", Grant: manifest.Edit{Caches: ptr(true)}})
	if err != nil || !changed {
		t.Fatalf("apply %v %v", changed, err)
	}
	bak, err := Save(path, f)
	if err != nil {
		t.Fatal(err)
	}
	if bak != path+".bak-v1-1760000000" { // the v1 → v2 conversion backup
		t.Errorf("backup = %q", bak)
	}
	if b, _ := os.ReadFile(bak); string(b) != v1 {
		t.Errorf("backup content = %q", b)
	}
	if fi, _ := os.Stat(bak); fi.Mode().Perm() != 0o600 {
		t.Errorf("backup mode %v", fi.Mode().Perm())
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Errorf("file mode %v", fi.Mode().Perm())
	}
	// Second save (of a v2 file now): an ordinary backup; third in the same
	// second: -2; the conversion backup untouched.
	if b2, err := Save(path, f); err != nil || b2 != path+".bak-1760000000" {
		t.Fatalf("second backup %q %v", b2, err)
	}
	bak2, err := Save(path, f)
	if err != nil || bak2 != path+".bak-1760000000-2" {
		t.Fatalf("third backup %q %v", bak2, err)
	}
	if b, _ := os.ReadFile(bak); string(b) != v1 {
		t.Errorf("first backup overwritten")
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "cfg", ".overrides-*")); len(left) != 0 {
		t.Errorf("temp files left: %v", left)
	}
	// A new file has no backup.
	fresh := filepath.Join(dir, "new", "overrides.yaml")
	if b, err := Save(fresh, File{}); err != nil || b != "" {
		t.Errorf("fresh save %q %v", b, err)
	}

	// An invalid file is never written; the old one stays.
	before, _ := os.ReadFile(path)
	bad := f.Clone()
	bad.Rules = append(bad.Rules, manifest.PolicyRule{ID: "r", Tool: "Bash", Match: manifest.RuleMatch{Regex: "(unclosed"}, Action: "deny"})
	if _, err := Save(path, bad); err == nil || !strings.Contains(err.Error(), "does not compile") {
		t.Fatalf("bad regex saved: %v", err)
	}
	bad = f.Clone()
	bad.Subjects = append(bad.Subjects, manifest.PolicySubject{Kind: KindMCP, Name: "m", MCPTools: map[string]string{"*": "allow"}})
	if _, err := Save(path, bad); err == nil {
		t.Fatal("gate allow saved")
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(before, after) {
		t.Error("failed save changed the file")
	}
	// A failed write (target is a directory) leaves no temp file.
	dpath := filepath.Join(dir, "isdir")
	os.MkdirAll(filepath.Join(dpath, "sub"), 0o755)
	if _, err := Save(dpath, f); err == nil {
		t.Error("save over a directory succeeded")
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".overrides-*")); len(left) != 0 {
		t.Errorf("temp files left: %v", left)
	}
}

func ptr[T any](v T) *T { return &v }

// TestApplySkillMatchesManifestApply: a skill edit through policy.Apply
// leaves the same skill view, change flag and error text as manifest.Apply.
func TestApplySkillMatchesManifestApply(t *testing.T) {
	all := manifest.NetAll
	edits := []struct {
		name string
		e    manifest.Edit
	}{
		{"pdf", manifest.Edit{Network: &all}},
		{"pdf", manifest.Edit{Network: &all}}, // no change
		{"*", manifest.Edit{Caches: ptr(true)}},
		{"docx", manifest.Edit{AddWrite: []string{"out", "/opt/x"}, AutoAllow: ptr(true)}},
		{"docx", manifest.Edit{RemoveWrite: []string{"./out"}}},
		{"pdf", manifest.Edit{Reset: true}},
		{"pdf", manifest.Edit{AddWrite: []string{"~/.ssh"}}},
		{"bad name", manifest.Edit{Network: &all}},
		{"pdf", manifest.Edit{Network: &all, ClearNetwork: true}},
		{"docx", manifest.Edit{AddEnv: []string{"lower"}}},
	}
	ov := manifest.Overrides{}
	f := File{}
	// Start from a v2 file with non-skill subjects: they must survive.
	f.Subjects = []manifest.PolicySubject{{Kind: KindMCP, Name: "gh", MCPTools: map[string]string{"*": "ask"}}}
	for i, ed := range edits {
		nov, mchanged, merr := manifest.Apply(ov, ed.name, ed.e)
		pchanged, perr := Apply(&f, Edit{Kind: KindSkill, Name: ed.name, Grant: ed.e})
		if (merr == nil) != (perr == nil) || (merr != nil && merr.Error() != perr.Error()) {
			t.Fatalf("edit %d: errors %v vs %v", i, merr, perr)
		}
		if mchanged != pchanged {
			t.Fatalf("edit %d: changed %v vs %v", i, mchanged, pchanged)
		}
		if merr == nil {
			ov = nov
		}
		if !reflect.DeepEqual(normOv(f.SkillOverrides()), normOv(ov)) {
			t.Fatalf("edit %d: skill view %+v vs %+v", i, f.SkillOverrides(), ov)
		}
	}
	if len(f.Subjects) == 0 || f.Subjects[0].Kind != KindMCP {
		t.Errorf("non-skill subject lost: %+v", f.Subjects)
	}
}

func normOv(o manifest.Overrides) manifest.Overrides {
	if len(o.Skills) == 0 {
		o.Skills = nil
	}
	return o
}

func TestApplySubjectsPacksRules(t *testing.T) {
	f := File{Version: 1}
	sub := manifest.PolicySubject{Kind: KindTool, Name: "files", Match: manifest.SubjectMatch{Tools: []string{"Write"}}, Paths: &manifest.GateLists{Deny: []string{"~/.zshrc"}}}
	if ch, err := Apply(&f, Edit{Kind: KindTool, Name: "files", Put: &sub}); err != nil || !ch {
		t.Fatalf("put %v %v", ch, err)
	}
	if f.Version != 2 {
		t.Errorf("version %d", f.Version)
	}
	if ch, _ := Apply(&f, Edit{Kind: KindTool, Name: "files", Put: &sub}); ch {
		t.Error("same put changed")
	}
	bad := sub.Clone()
	bad.Paths = &manifest.GateLists{Deny: []string{"relative"}}
	before := Render(f)
	if _, err := Apply(&f, Edit{Kind: KindTool, Name: "files", Put: &bad}); err == nil || Render(f) != before {
		t.Errorf("invalid put accepted: %v", err)
	}
	if _, err := Apply(&f, Edit{Kind: KindTool, Name: "other", Put: &sub}); err == nil {
		t.Error("mismatched put accepted")
	}
	if ch, err := Apply(&f, Edit{Pack: "exfil", PackSetting: &manifest.Toggle{Action: "ask"}}); err != nil || !ch {
		t.Fatalf("pack %v %v", ch, err)
	}
	if ch, _ := Apply(&f, Edit{Pack: "exfil", PackSetting: &manifest.Toggle{Action: "ask"}}); ch {
		t.Error("same pack toggle changed")
	}
	if ch, err := Apply(&f, Edit{Rule: "exfil/curl-data-file", RuleOverride: &manifest.Toggle{Enabled: ptr(false)}}); err != nil || !ch {
		t.Fatalf("rule %v %v", ch, err)
	}
	if _, err := Apply(&f, Edit{Rule: "exfil/curl-data-file", RuleOverride: &manifest.Toggle{Action: "allow"}}); err == nil {
		t.Error("rule allow accepted")
	}
	if _, err := Apply(&f, Edit{Rule: "exfil/no-such-rule", RuleOverride: &manifest.Toggle{Action: "ask"}}); err == nil {
		t.Error("unknown rule accepted")
	}
	if _, err := Apply(&f, Edit{Pack: "exfil", PackSetting: &manifest.Toggle{}}); err == nil {
		t.Error("empty toggle accepted")
	}
	if ch, _ := Apply(&f, Edit{Kind: KindTool, Name: "files", Delete: true}); !ch || len(f.Subjects) != 0 {
		t.Errorf("delete: %+v", f.Subjects)
	}
	if ch, _ := Apply(&f, Edit{Pack: "exfil"}); !ch || f.Packs != nil {
		t.Errorf("clear pack: %+v", f.Packs)
	}
	if ch, _ := Apply(&f, Edit{Rule: "exfil/curl-data-file"}); !ch || f.RuleOverrides != nil {
		t.Errorf("clear rule: %+v", f.RuleOverrides)
	}
}

// TestSaveKeepsLastTenBackups: after each save only the newest KeepBackups
// ordinary backups remain; the v1 conversion backup is never pruned.
func TestSaveKeepsLastTenBackups(t *testing.T) {
	old := backupNow
	t.Cleanup(func() { backupNow = old })
	dir := t.TempDir()
	path := filepath.Join(dir, "overrides.yaml")
	writeFile(t, path, "version: 1\n")
	writeFile(t, path+".bak-notes", "keep me") // not a backup name Save owns
	f, _, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 25; i++ {
		backupNow = func() time.Time { return time.Unix(1760000000+int64(i/2), 0) }
		if _, err := Save(path, f); err != nil {
			t.Fatal(err)
		}
	}
	ordinary, _ := filepath.Glob(path + ".bak-1*")
	if len(ordinary) != KeepBackups {
		t.Fatalf("ordinary backups = %d: %v", len(ordinary), ordinary)
	}
	// The newest survive: the last save was at +12 (i=24), the one before at
	// +11 -2 (i=23), ...
	for _, want := range []string{".bak-1760000012", ".bak-1760000011-2", ".bak-1760000011", ".bak-1760000007-2"} {
		if _, err := os.Stat(path + want); err != nil {
			t.Errorf("missing %s", want)
		}
	}
	if _, err := os.Stat(path + ".bak-1760000007"); err == nil {
		t.Error("old backup kept")
	}
	if v1, _ := filepath.Glob(path + ".bak-v1-*"); len(v1) != 1 {
		t.Errorf("conversion backups = %v", v1)
	}
	if _, err := os.Stat(path + ".bak-notes"); err != nil {
		t.Error("foreign file pruned")
	}
}

func TestLoadRefusesLargeFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "overrides.yaml")
	big := "version: 2\n# " + strings.Repeat("x", manifest.MaxPolicyFileSize) + "\n"
	writeFile(t, path, big)
	if _, _, err := LoadFile(path); err == nil || !strings.Contains(err.Error(), "larger than 1 MiB") {
		t.Errorf("LoadFile = %v", err)
	}
	if _, _, err := manifest.LoadOverrides(dir, ""); err == nil || !strings.Contains(err.Error(), "larger than 1 MiB") {
		t.Errorf("LoadOverrides = %v", err)
	}
}

// TestNonRegularFilesRefusedPromptly: a policy file that is a FIFO, a
// device or (for a project) a symlink out of the project returns an error at
// once, never blocking a hook call; the error carries no path value.
func TestNonRegularFilesRefusedPromptly(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo")
	if err := mkfifo(fifo); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	outside := filepath.Join(dir, "outside.yaml")
	writeFile(t, outside, "version: 2\n")
	type tc struct{ name, target string }
	adir := filepath.Join(dir, "a-dir")
	os.MkdirAll(adir, 0o755)
	for _, c := range []tc{{"fifo", fifo}, {"dev-null", "/dev/null"}, {"outside", outside}, {"dir", adir}} {
		for _, project := range []bool{false, true} {
			if c.name == "outside" && !project {
				continue // a user file may be a symlink anywhere
			}
			sub := filepath.Join(dir, "case-"+c.name+map[bool]string{false: "-u", true: "-p"}[project])
			os.MkdirAll(sub, 0o755)
			name := "overrides.yaml"
			if project {
				name = ".watchdeck.yaml"
			}
			link := filepath.Join(sub, name)
			if err := os.Symlink(c.target, link); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				var err error
				if project {
					_, _, err = Load("", link)
					if err == nil {
						_, _, err = manifest.LoadOverrides("", sub)
					}
				} else {
					_, _, err = Load(link, "")
					if err == nil {
						_, _, err = manifest.LoadOverrides(sub, "")
					}
				}
				done <- err
			}()
			select {
			case err := <-done:
				if err == nil {
					t.Errorf("%s project=%v: no error", c.name, project)
				} else if strings.Contains(err.Error(), c.target) && c.name != "dev-null" {
					t.Errorf("%s: error repeats the target: %v", c.name, err)
				}
			case <-time.After(3 * time.Second):
				t.Fatalf("%s project=%v: read blocked", c.name, project)
			}
		}
	}
	// manifest.LoadOverrides on the project too: a FIFO .watchdeck.yaml
	// directly in the project (not a symlink).
	pdir := filepath.Join(dir, "direct")
	os.MkdirAll(pdir, 0o755)
	if err := mkfifo(filepath.Join(pdir, ".watchdeck.yaml")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := manifest.LoadOverrides("", pdir); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("direct fifo: %v", err)
	}
	// A symlink inside the project to a file inside the project is fine.
	in := filepath.Join(dir, "inside")
	os.MkdirAll(filepath.Join(in, "conf"), 0o755)
	writeFile(t, filepath.Join(in, "conf", "p.yaml"), "version: 2\n")
	os.Symlink(filepath.Join("conf", "p.yaml"), filepath.Join(in, ".watchdeck.yaml"))
	if _, _, err := Load("", filepath.Join(in, ".watchdeck.yaml")); err != nil {
		t.Errorf("inside symlink: %v", err)
	}
}

// TestSaveSymlinkedFileWritesTarget: an overrides.yaml kept as a symlink
// into a dotfiles directory is saved at its target; the link stays a link
// and the backup sits beside the target.
func TestSaveSymlinkedFileWritesTarget(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "dotfiles", "overrides.yaml")
	writeFile(t, target, "version: 1\nskills:\n  pdf:\n    network: all\n")
	link := filepath.Join(dir, "cfg", "overrides.yaml")
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	f, _, err := LoadFile(link)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(&f, Edit{Kind: KindSkill, Name: "docx", Grant: manifest.Edit{Caches: ptr(true)}}); err != nil {
		t.Fatal(err)
	}
	bak, err := Save(link, f)
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("link replaced by a file (%v)", err)
	}
	if b, _ := os.ReadFile(target); !strings.Contains(string(b), "docx") {
		t.Errorf("target not written: %q", b)
	}
	if real, _ := filepath.EvalSymlinks(target); filepath.Dir(bak) != filepath.Dir(real) {
		t.Errorf("backup %q not beside the target", bak)
	}
}
