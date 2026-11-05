package rulebook

import (
	"errors"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/Panda-Taps-LLC/watchdeck/internal/claudesettings"
	"github.com/Panda-Taps-LLC/watchdeck/internal/manifest"
	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
	"github.com/Panda-Taps-LLC/watchdeck/internal/policy"
	"github.com/Panda-Taps-LLC/watchdeck/internal/rules"
)

func proposeInput(t *testing.T) Input {
	t.Helper()
	p := testEnv(t)
	return Input{Paths: p, ProjectRoot: t.TempDir()}
}

func TestProposePicksMechanism(t *testing.T) {
	in := proposeInput(t)
	user := filepath.Join(in.Paths.ClaudeDir, "settings.json")
	over := in.Paths.OverridesFile()
	type step struct{ mech, file, key, value, sentence string }
	cases := []struct {
		name string
		req  AddRequest
		want []step
	}{
		{"path both", AddRequest{Action: "deny", What: WhatPath, Value: "~/.kube/config"}, []step{
			{MechNative, user, claudesettings.KeyDeny, "Read(~/.kube/config)", "Block reading ~/.kube/config"},
			{MechNative, user, claudesettings.KeyDeny, "Edit(~/.kube/config)", "Block editing ~/.kube/config"},
		}},
		{"path read", AddRequest{Action: "ask", What: WhatPath, Value: "~/.kube/config", Tool: "Read"}, []step{
			{MechNative, user, claudesettings.KeyAsk, "Read(~/.kube/config)", "Ask before reading ~/.kube/config"},
		}},
		{"path edit", AddRequest{Action: "deny", What: WhatPath, Value: "~/.kube/config", Tool: "Edit"}, []step{
			{MechNative, user, claudesettings.KeyDeny, "Edit(~/.kube/config)", "Block editing ~/.kube/config"},
		}},
		{"host", AddRequest{Action: "deny", What: WhatHost, Value: "example.com"}, []step{
			{MechNative, user, claudesettings.KeyDeny, "WebFetch(domain:example.com)", "Block fetching from example.com"},
		}},
		{"mcp", AddRequest{Action: "ask", What: WhatMCP, Value: "mcp__github__create_issue"}, []step{
			{MechNative, user, claudesettings.KeyAsk, "mcp__github__create_issue", "Ask before the MCP tool create_issue on github"},
		}},
		{"command", AddRequest{Action: "deny", What: WhatCommand, Value: "curl"}, []step{
			{MechNative, user, claudesettings.KeyDeny, "Bash(curl *)", "Block running curl *"},
		}},
		{"regex", AddRequest{Action: "deny", What: WhatRegex, Value: `curl\s+-d`}, []step{
			{MechHook, over, "rules", `curl\s+-d`, `Block a Bash call matching /curl\s+-d/`},
		}},
		{"text", AddRequest{Action: "ask", What: WhatText, Value: "rm -rf /", Tool: "Bash"}, []step{
			{MechHook, over, "rules", "rm -rf /", "Ask before a Bash call containing rm -rf /"},
		}},
		{"mcp-launch", AddRequest{What: WhatMCPLaunch, Value: "github"}, []step{
			{MechSubject, over, "subjects", "github", "MCP server github starts under the sandbox"},
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, err := Propose(in, c.req)
			if err != nil {
				t.Fatal(err)
			}
			if len(p.Steps) != len(c.want) {
				t.Fatalf("steps = %+v", p.Steps)
			}
			for i, w := range c.want {
				s := p.Steps[i]
				if s.Mechanism != w.mech || s.File != w.file || s.Key != w.key || s.Value != w.value || s.Sentence != w.sentence {
					t.Errorf("step %d = %+v, want %+v", i, s, w)
				}
				if s.RowID == "" {
					t.Errorf("step %d has no row id", i)
				}
				switch s.Mechanism {
				case MechNative:
					want := RowID(kindForKey(s.Key), claudesettings.ScopeUser, s.Key, s.Value)
					if s.RowID != want || s.IntentID != want {
						t.Errorf("step %d row=%q intent=%q, want both %q", i, s.RowID, s.IntentID, want)
					}
				case MechHook:
					if s.Rule == nil || s.Rule.ID != "user-"+hash8(c.req.Value) || s.RowID != "user:"+s.Rule.ID || s.Rule.Tool != "Bash" {
						t.Errorf("step %d hook rule = %+v row %q", i, s.Rule, s.RowID)
					}
				case MechSubject:
					if s.RowID != "subject:mcp:github" {
						t.Errorf("step %d row = %q", i, s.RowID)
					}
				}
			}
		})
	}

	// skill grants and unknown kinds are not proposed here.
	for _, w := range []What{WhatSkill, "bogus"} {
		if _, err := Propose(in, AddRequest{Action: "deny", What: w, Value: "x"}); err == nil {
			t.Errorf("What %q: no error", w)
		}
	}
	// allow is not an add action; an mcp value must name an MCP tool.
	if _, err := Propose(in, AddRequest{Action: "allow", What: WhatCommand, Value: "ls"}); err == nil {
		t.Error("allow accepted")
	}
	if _, err := Propose(in, AddRequest{Action: "deny", What: WhatMCP, Value: "github"}); err == nil {
		t.Error("mcp value without mcp__ accepted")
	}
	if _, err := Propose(in, AddRequest{Action: "deny", What: WhatPath, Value: "x", Tool: "Write"}); err == nil {
		t.Error("path tool Write accepted")
	}
	if _, err := Propose(in, AddRequest{Action: "deny", What: WhatRegex, Value: "("}); err == nil {
		t.Error("invalid regex accepted")
	}
	// A given intent id is carried to every native step.
	p, err := Propose(in, AddRequest{Action: "deny", What: WhatPath, Value: "~/x", IntentID: "recommended:x"})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range p.Steps {
		if s.IntentID != "recommended:x" {
			t.Errorf("intent = %q", s.IntentID)
		}
	}
}

func TestProposeAnchorsUserScopePaths(t *testing.T) {
	in := proposeInput(t)
	for value, want := range map[string]string{
		"/abs/x":   "Read(//abs/x)",
		"//abs/x":  "Read(//abs/x)",
		"~/x":      "Read(~/x)",
		"rel/x":    "Read(./rel/x)",
		"./x":      "Read(./x)",
		"a/./b/":   "Read(./a/b/**)",
		"secrets/": "Read(./secrets/**)",
		"~/x/":     "Read(~/x/**)",
		"/abs/":    "Read(//abs/**)",
		"~/":       "Read(~/**)",
		"/a/../b":  "Read(//b)",
		".env":     "Read(./.env)",
		"*.pem":    "Read(./*.pem)",
		"/etc/**":  "Read(//etc/**)",
		"~/.ssh/*": "Read(~/.ssh/*)",
	} {
		p, err := Propose(in, AddRequest{Action: "deny", What: WhatPath, Value: value, Tool: "Read"})
		if err != nil {
			t.Fatalf("%q: %v", value, err)
		}
		if len(p.Steps) != 1 || p.Steps[0].Value != want {
			t.Errorf("%q → %+v, want %q", value, p.Steps, want)
		}
	}
}

func TestProposeAnchorsUserScopeRefusals(t *testing.T) {
	in := proposeInput(t)
	for _, v := range []string{"../x", "a/../../x", "./../x", "..", ".", "~", "~user/x"} {
		if _, err := Propose(in, AddRequest{Action: "deny", What: WhatPath, Value: v, Tool: "Read"}); !errors.Is(err, ErrValue) {
			t.Errorf("%q: err = %v", v, err)
		}
	}
}

func TestProposeProjectScopePaths(t *testing.T) {
	in := proposeInput(t)
	proj := paths.ProjectSettings(in.ProjectRoot)
	for value, want := range map[string]string{
		"rel/x":   "Read(/rel/x)",
		"./x":     "Read(/x)",
		"a/./b":   "Read(/a/b)",
		"a/../b":  "Read(/b)",
		"/abs/x":  "Read(//abs/x)",
		"//abs/x": "Read(//abs/x)",
		"~/x":     "Read(~/x)",
		// a trailing slash names a directory: everything under it
		"secrets/": "Read(/secrets/**)",
		"~/x/":     "Read(~/x/**)",
		"/abs/":    "Read(//abs/**)",
	} {
		p, err := Propose(in, AddRequest{Action: "deny", What: WhatPath, Value: value, Tool: "Read", Scope: claudesettings.ScopeProject})
		if err != nil {
			t.Fatalf("%q: %v", value, err)
		}
		if len(p.Steps) != 1 || p.Steps[0].Value != want || p.Steps[0].File != proj {
			t.Errorf("%q → %+v, want %q in %s", value, p.Steps, want, proj)
		}
		if want := RowID(KindNativeDeny, claudesettings.ScopeProject, claudesettings.KeyDeny, want); p.Steps[0].RowID != want {
			t.Errorf("%q row = %q, want %q", value, p.Steps[0].RowID, want)
		}
	}
	// A path that climbs (after cleaning) or a ~ without a slash: refused.
	for _, v := range []string{"../x", "a/../../x", "..", ".", "~", "~user/x"} {
		if _, err := Propose(in, AddRequest{Action: "deny", What: WhatPath, Value: v, Scope: claudesettings.ScopeProject}); !errors.Is(err, ErrValue) {
			t.Errorf("%q at project scope: err = %v", v, err)
		}
	}
	// Project scope without a project root is an error, never a fall-back.
	in.ProjectRoot = ""
	if _, err := Propose(in, AddRequest{Action: "deny", What: WhatPath, Value: "x", Scope: claudesettings.ScopeProject}); !errors.Is(err, ErrScope) {
		t.Errorf("no project root: err = %v", err)
	}
}

func TestProposeRefusesLocalAndManaged(t *testing.T) {
	in := proposeInput(t)
	for _, s := range []claudesettings.Scope{claudesettings.ScopeLocal, claudesettings.ScopeManaged, "other"} {
		_, err := Propose(in, AddRequest{Action: "deny", What: WhatCommand, Value: "curl", Scope: s})
		if !errors.Is(err, ErrScope) {
			t.Errorf("scope %q: err = %v", s, err)
		}
	}
	// Hook rules and MCP launches live in the user policy file only.
	for _, w := range []What{WhatRegex, WhatText, WhatMCPLaunch} {
		_, err := Propose(in, AddRequest{Action: "deny", What: w, Value: "github", Scope: claudesettings.ScopeProject})
		if !errors.Is(err, ErrScope) {
			t.Errorf("%s at project scope: err = %v", w, err)
		}
	}
}

func TestProposeRefusesControlChars(t *testing.T) {
	in := proposeInput(t)
	// A parenthesis would end the native rule early: Bash(foo) *) protects nothing.
	for _, c := range []struct {
		w What
		v string
	}{{WhatCommand, "foo)"}, {WhatCommand, "foo("}, {WhatPath, "a)b"}, {WhatPath, "~/x(1)"}, {WhatHost, "a)b.com"}, {WhatMCP, "mcp__s__t)"},
		// a command prefix with * in it: the rule already ends in " *"
		{WhatCommand, "git push*"}, {WhatCommand, "*"}, {WhatCommand, "git * --force"},
		// a domain is a bare host: no scheme, path, port or user
		{WhatHost, "https://x/y"}, {WhatHost, "example.com/path"}, {WhatHost, "example.com:8080"}, {WhatHost, "user@example.com"}, {WhatHost, "http://example.com"}} {
		if _, err := Propose(in, AddRequest{Action: "deny", What: c.w, Value: c.v}); !errors.Is(err, ErrValue) {
			t.Errorf("%s %q: err = %v", c.w, c.v, err)
		}
	}
	// Hook rules may hold parentheses.
	for _, c := range []struct {
		w What
		v string
	}{{WhatRegex, `(curl|wget)\s`}, {WhatText, "f(x)"}} {
		if _, err := Propose(in, AddRequest{Action: "deny", What: c.w, Value: c.v}); err != nil {
			t.Errorf("%s %q: %v", c.w, c.v, err)
		}
	}
	for _, v := range []string{"", "  ", "a\nb", "a\rb", "a\tb", "a\x00b", "a\x1bb", "a\x7fb"} {
		for _, w := range []What{WhatPath, WhatHost, WhatMCP, WhatCommand, WhatRegex, WhatText, WhatMCPLaunch} {
			if _, err := Propose(in, AddRequest{Action: "deny", What: w, Value: v}); !errors.Is(err, ErrValue) {
				t.Errorf("%s %q: err = %v", w, v, err)
			}
		}
	}
}

func TestProposeSuggestsBashTwin(t *testing.T) {
	in := proposeInput(t)
	p, err := Propose(in, AddRequest{Action: "deny", What: WhatCommand, Value: "curl"})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Steps) != 1 || p.Suggested == nil {
		t.Fatalf("plan = %+v", p)
	}
	s := *p.Suggested
	if s.What != WhatText || s.Value != "curl" || s.Action != "deny" || s.Tool != "Bash" || s.Twin {
		t.Fatalf("suggested = %+v", s)
	}

	p, err = Propose(in, AddRequest{Action: "ask", What: WhatCommand, Value: "git push", Twin: true})
	if err != nil {
		t.Fatal(err)
	}
	if p.Suggested != nil || len(p.Steps) != 2 {
		t.Fatalf("twin plan = %+v", p)
	}
	if p.Steps[0].Mechanism != MechNative || p.Steps[0].Value != "Bash(git push *)" {
		t.Errorf("native step = %+v", p.Steps[0])
	}
	h := p.Steps[1]
	if h.Mechanism != MechHook || h.Rule == nil || h.Rule.Action != "ask" || strings.Join(h.Rule.Match.Literals, ",") != "git push" || h.Rule.Match.Regex != "" {
		t.Errorf("twin step = %+v rule %+v", h, h.Rule)
	}

	// Only a Bash native rule suggests a twin.
	p, err = Propose(in, AddRequest{Action: "deny", What: WhatHost, Value: "example.com"})
	if err != nil || p.Suggested != nil {
		t.Fatalf("host plan = %+v err %v", p, err)
	}
}

// TestProposeTrimsCommandAndHost: a command prefix loses its surrounding
// blanks, a host is written lower-cased.
func TestProposeTrimsCommandAndHost(t *testing.T) {
	in := proposeInput(t)
	for _, c := range []struct {
		req  AddRequest
		want string
	}{
		{AddRequest{Action: "deny", What: WhatCommand, Value: "  git push  "}, "Bash(git push *)"},
		{AddRequest{Action: "deny", What: WhatHost, Value: "Example.COM"}, "WebFetch(domain:example.com)"},
	} {
		p, err := Propose(in, c.req)
		if err != nil {
			t.Fatalf("%q: %v", c.req.Value, err)
		}
		if p.Steps[0].Value != c.want {
			t.Errorf("%q → %q, want %q", c.req.Value, p.Steps[0].Value, c.want)
		}
	}
}

func TestProposePackRuleOverride(t *testing.T) {
	in := proposeInput(t)
	p, r, key := firstPackRule(t)
	for _, action := range []string{"deny", "ask", "log"} {
		plan, err := Propose(in, AddRequest{Action: action, What: WhatPackRule, Value: key})
		if err != nil {
			t.Fatalf("%s: %v", action, err)
		}
		want := Step{
			Mechanism: MechHook, File: in.Paths.OverridesFile(), Key: "rule_overrides", Value: key + ": " + action,
			RowID: RowID(KindPack, "", p.Name, r.ID), Sentence: Sentence(KindPack, action, r.Tool, r.Description),
		}
		if len(plan.Steps) != 1 || plan.Steps[0] != want || plan.Suggested != nil {
			t.Errorf("%s: plan = %+v, want %+v", action, plan, want)
		}
	}
	for _, v := range []string{"nope/" + r.ID, p.Name + "/nope", "nope"} {
		_, err := Propose(in, AddRequest{Action: "deny", What: WhatPackRule, Value: v})
		if !errors.Is(err, ErrValue) || !strings.Contains(err.Error(), v) {
			t.Errorf("%q: err = %v", v, err)
		}
	}
	if _, err := Propose(in, AddRequest{Action: "allow", What: WhatPackRule, Value: key}); err == nil {
		t.Error("allow accepted for a pack rule")
	}
	for _, sc := range []claudesettings.Scope{claudesettings.ScopeProject, claudesettings.ScopeLocal, claudesettings.ScopeManaged} {
		if _, err := Propose(in, AddRequest{Action: "deny", What: WhatPackRule, Value: key, Scope: sc}); !errors.Is(err, ErrScope) {
			t.Errorf("scope %s: err = %v", sc, err)
		}
	}
}

// stepShape is the part of a Step the everywhere tests compare.
type stepShape struct{ mech, file, key, value, row string }

func shapes(p Plan) []stepShape {
	out := make([]stepShape, 0, len(p.Steps))
	for _, s := range p.Steps {
		out = append(out, stepShape{s.Mechanism, s.File, s.Key, s.Value, s.RowID})
	}
	return out
}

// checkOneIntent fails unless every step carries want as its IntentID.
func checkOneIntent(t *testing.T, p Plan, want string) {
	t.Helper()
	for i, s := range p.Steps {
		if s.IntentID != want {
			t.Errorf("step %d (%s %s) intent %q, want %q", i, s.Mechanism, s.Value, s.IntentID, want)
		}
	}
}

func TestIntentFor(t *testing.T) {
	req := AddRequest{Action: "deny", What: WhatPath, Value: "~/.env", Everywhere: true}
	if got, want := IntentFor(req), "intent:path:"+hash8("~/.env"); got != want {
		t.Errorf("IntentFor = %q, want %q", got, want)
	}
	// Two values one slug apart get two intents (R1).
	a := IntentFor(AddRequest{What: WhatHost, Value: "a.b", Everywhere: true})
	b := IntentFor(AddRequest{What: WhatHost, Value: "a-b", Everywhere: true})
	if a == b {
		t.Errorf("a.b and a-b share intent %q", a)
	}
	// One value, two kinds: two intents.
	if IntentFor(AddRequest{What: WhatPath, Value: "x", Everywhere: true}) == IntentFor(AddRequest{What: WhatCommand, Value: "x", Everywhere: true}) {
		t.Error("a path and a command intent on one value share an id")
	}
	// Without Everywhere: the existing default (the caller's id, else "").
	if got := IntentFor(AddRequest{What: WhatPath, Value: "~/.env", IntentID: "keep"}); got != "keep" {
		t.Errorf("IntentFor without everywhere = %q, want the request's own id", got)
	}
}

func TestProposeEverywherePath(t *testing.T) {
	in := proposeInput(t)
	home := in.Paths.Home
	user := filepath.Join(in.Paths.ClaudeDir, "settings.json")
	over := in.Paths.OverridesFile()
	cases := []struct {
		name, value, gate string
		literals          []string
	}{
		{"home", "~/.env", "~/.env", []string{"~/.env", home + "/.env"}},
		{"absolute under home", home + "/proj/.env", "~/proj/.env", []string{home + "/proj/.env", "~/proj/.env"}},
		{"absolute elsewhere", "/etc/fake-secret", "/etc/fake-secret", []string{"/etc/fake-secret"}},
		{"directory", "~/.fake-aws/", "~/.fake-aws", []string{"~/.fake-aws/", home + "/.fake-aws/"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := AddRequest{Action: "deny", What: WhatPath, Value: c.value, Everywhere: true}
			p, err := Propose(in, req)
			if err != nil {
				t.Fatal(err)
			}
			h := hash8(c.value)
			intent := "intent:path:" + h
			if IntentFor(req) != intent {
				t.Fatalf("IntentFor = %q", IntentFor(req))
			}
			a, err := anchorPath(c.value, claudesettings.ScopeUser)
			if err != nil {
				t.Fatal(err)
			}
			name := "intent-path-" + h
			want := []stepShape{
				{MechNative, user, claudesettings.KeyDeny, "Read(" + a + ")", RowID(KindNativeDeny, claudesettings.ScopeUser, claudesettings.KeyDeny, "Read("+a+")")},
				{MechNative, user, claudesettings.KeyDeny, "Edit(" + a + ")", RowID(KindNativeDeny, claudesettings.ScopeUser, claudesettings.KeyDeny, "Edit("+a+")")},
				{MechSubject, over, "subjects", name, "subject:tool:" + name},
				{MechHook, over, "rules", c.value, "user:" + name + "-bash"},
			}
			if got := shapes(p); !reflect.DeepEqual(got, want) {
				t.Fatalf("steps\n got %+v\nwant %+v", got, want)
			}
			checkOneIntent(t, p, intent)
			sub := p.Steps[2].Subject
			if sub == nil {
				t.Fatal("the subject step carries no subject")
			}
			wantSub := manifest.PolicySubject{Kind: policy.KindTool, Name: name,
				Match: manifest.SubjectMatch{Tools: []string{"Grep", "Glob"}},
				Paths: &manifest.GateLists{Deny: []string{c.gate}}}
			if !reflect.DeepEqual(*sub, wantSub) {
				t.Errorf("subject\n got %+v\nwant %+v", *sub, wantSub)
			}
			r := p.Steps[3].Rule
			wantRule := manifest.PolicyRule{ID: name + "-bash", Tool: "Bash", Action: "deny",
				Match: manifest.RuleMatch{Literals: c.literals}}
			if r == nil || !reflect.DeepEqual(*r, wantRule) {
				t.Errorf("rule\n got %+v\nwant %+v", r, wantRule)
			}
			if p.Suggested != nil {
				t.Errorf("suggested %+v, want none", p.Suggested)
			}
		})
	}

	// An ask intent asks on every route.
	p, err := Propose(in, AddRequest{Action: "ask", What: WhatPath, Value: "~/.env", Everywhere: true})
	if err != nil {
		t.Fatal(err)
	}
	if p.Steps[0].Key != claudesettings.KeyAsk || p.Steps[2].Subject.Paths.Ask[0] != "~/.env" || len(p.Steps[2].Subject.Paths.Deny) != 0 || p.Steps[3].Rule.Action != "ask" {
		t.Errorf("ask intent steps %+v", shapes(p))
	}

	// A relative path at user scope has no single place to name for the
	// search tools: refused, value-free.
	_, err = Propose(in, AddRequest{Action: "deny", What: WhatPath, Value: "fake-dir/.env", Everywhere: true})
	if err == nil || strings.Contains(err.Error(), "fake-dir") {
		t.Errorf("relative user-scope everywhere = %v, want a value-free refusal", err)
	}
}

func TestProposeEverywhereHost(t *testing.T) {
	in := proposeInput(t)
	user := filepath.Join(in.Paths.ClaudeDir, "settings.json")
	over := in.Paths.OverridesFile()
	const typed = "Fake-Example.COM"
	const host = "fake-example.com"
	req := AddRequest{Action: "deny", What: WhatHost, Value: typed, Everywhere: true}
	p, err := Propose(in, req)
	if err != nil {
		t.Fatal(err)
	}
	h := hash8(typed) // the value as typed (R1)
	intent := "intent:host:" + h
	name := "intent-host-" + h
	native := "WebFetch(domain:" + host + ")"
	want := []stepShape{
		{MechNative, user, claudesettings.KeyDeny, native, RowID(KindNativeDeny, claudesettings.ScopeUser, claudesettings.KeyDeny, native)},
		{MechNative, user, claudesettings.KeyDeniedDomains, host, RowID(KindSandboxDomain, claudesettings.ScopeUser, claudesettings.KeyDeniedDomains, host)},
		{MechSubject, over, "subjects", name, "subject:tool:" + name},
		{MechHook, over, "rules", host, "user:" + name + "-bash"},
	}
	if got := shapes(p); !reflect.DeepEqual(got, want) {
		t.Fatalf("steps\n got %+v\nwant %+v", got, want)
	}
	checkOneIntent(t, p, intent)
	wantSub := manifest.PolicySubject{Kind: policy.KindTool, Name: name,
		Match:   manifest.SubjectMatch{Tools: []string{"WebFetch"}},
		Domains: &manifest.GateLists{Deny: []string{host}}}
	if sub := p.Steps[2].Subject; sub == nil || !reflect.DeepEqual(*sub, wantSub) {
		t.Errorf("subject\n got %+v\nwant %+v", sub, wantSub)
	}
	wantRule := manifest.PolicyRule{ID: name + "-bash", Tool: "Bash", Action: "deny", Match: manifest.RuleMatch{
		Argv0: []string{"curl", "wget", "nc", "ncat", "telnet", "ssh", "scp", "sftp", "ftp", "rsync",
			"python", "python3", "node", "perl", "ruby", "php", "openssl", "git", "http", "https", "xh", "aria2c"},
		Literals: []string{host},
		Regex:    "(?i)" + regexp.QuoteMeta(host),
	}}
	if r := p.Steps[3].Rule; r == nil || !reflect.DeepEqual(*r, wantRule) {
		t.Errorf("rule\n got %+v\nwant %+v", r, wantRule)
	}
	if p.Steps[1].Sentence != "Sandboxed commands cannot reach "+host {
		t.Errorf("deniedDomains sentence %q", p.Steps[1].Sentence)
	}

	// An IPv4 address is a host too (the study's 127.0.0.1, R13).
	p, err = Propose(in, AddRequest{Action: "deny", What: WhatHost, Value: "127.0.0.1", Everywhere: true})
	if err != nil {
		t.Fatalf("127.0.0.1: %v", err)
	}
	if len(p.Steps) != 4 || p.Steps[0].Value != "WebFetch(domain:127.0.0.1)" || p.Steps[1].Value != "127.0.0.1" {
		t.Errorf("127.0.0.1 steps %+v", shapes(p))
	}

	// The sandbox's domain list has no ask: an ask intent has no such step.
	p, err = Propose(in, AddRequest{Action: "ask", What: WhatHost, Value: host, Everywhere: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range p.Steps {
		if s.Key == claudesettings.KeyDeniedDomains {
			t.Errorf("ask host intent writes %s", s.Key)
		}
	}
	if len(p.Steps) != 3 || p.Steps[1].Subject.Domains.Ask[0] != host || p.Steps[2].Rule.Action != "ask" {
		t.Errorf("ask host intent steps %+v", shapes(p))
	}
}

func TestProposeEverywhereCommandIsTwin(t *testing.T) {
	in := proposeInput(t)
	for _, action := range []string{"deny", "ask"} {
		twin, err := Propose(in, AddRequest{Action: action, What: WhatCommand, Value: "fake-tool", Twin: true})
		if err != nil {
			t.Fatal(err)
		}
		req := AddRequest{Action: action, What: WhatCommand, Value: "fake-tool", Everywhere: true}
		p, err := Propose(in, req)
		if err != nil {
			t.Fatal(err)
		}
		h := hash8("fake-tool")
		intent := "intent:command:" + h
		checkOneIntent(t, p, intent)
		if p.Suggested != nil {
			t.Errorf("%s: suggested %+v, want none (everywhere implies twin)", action, p.Suggested)
		}
		if len(p.Steps) != len(twin.Steps) || len(p.Steps) != 2 {
			t.Fatalf("%s: steps %+v, want the twin's %+v", action, shapes(p), shapes(twin))
		}
		// The native step is the twin's; the hook step is the twin's rule
		// under the intent's id.
		if got, want := shapes(p)[0], shapes(twin)[0]; got != want {
			t.Errorf("%s: native %+v, want %+v", action, got, want)
		}
		wantRule := *twin.Steps[1].Rule
		wantRule.ID = "intent-command-" + h + "-bash"
		if r := p.Steps[1].Rule; r == nil || !reflect.DeepEqual(*r, wantRule) {
			t.Errorf("%s: rule %+v, want %+v", action, r, wantRule)
		}
		if p.Steps[1].RowID != "user:"+wantRule.ID || p.Steps[1].Value != twin.Steps[1].Value {
			t.Errorf("%s: hook step %+v", action, shapes(p)[1])
		}
	}
}

func TestProposeEverywhereRefusesOtherWhat(t *testing.T) {
	in := proposeInput(t)
	for _, req := range []AddRequest{
		{Action: "deny", What: WhatRegex, Value: `fake-secret\d+`},
		{Action: "deny", What: WhatText, Value: "fake-secret-text"},
		{Action: "deny", What: WhatMCP, Value: "mcp__fakesrv__faketool"},
		{What: WhatMCPLaunch, Value: "fakesrv"},
		{Action: "deny", What: WhatPackRule, Value: "cred-in-write/aws-access-key-id"},
		{Action: "deny", What: WhatSkill, Value: "fake-skill"},
	} {
		req.Everywhere = true
		_, err := Propose(in, req)
		if err == nil {
			t.Errorf("%s everywhere: no error", req.What)
			continue
		}
		if strings.Contains(err.Error(), req.Value) {
			t.Errorf("%s everywhere: error %q echoes the value", req.What, err)
		}
		if !strings.Contains(err.Error(), "every route") {
			t.Errorf("%s everywhere: error %q does not say what every route covers", req.What, err)
		}
	}
}

// TestIntentHookRuleMatches runs the Bash rules Propose writes through the
// hook's matcher, pinning what they catch and the documented misses.
func TestIntentHookRuleMatches(t *testing.T) {
	in := proposeInput(t)
	home := in.Paths.Home
	ruleOf := func(req AddRequest) *rules.Matcher {
		t.Helper()
		p, err := Propose(in, req)
		if err != nil {
			t.Fatal(err)
		}
		r := p.Steps[len(p.Steps)-1].Rule
		m, err := rules.NewMatcher(rules.FieldCommand, rules.Match{Regex: r.Match.Regex, Literals: r.Match.Literals, Argv0: r.Match.Argv0})
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	host := ruleOf(AddRequest{Action: "deny", What: WhatHost, Value: "fake-example.com", Everywhere: true})
	path := ruleOf(AddRequest{Action: "deny", What: WhatPath, Value: "~/.fake-env", Everywhere: true})
	for _, c := range []struct {
		m    *rules.Matcher
		cmd  string
		want bool
	}{
		{host, "curl https://fake-example.com/x", true},
		{host, "env FOO=1 wget fake-example.com", true},
		{host, "echo fake-example.com", false},                     // not a network program
		{host, "bash -c 'curl https://fake-example.com/x'", false}, // limit: a program inside sh -c / bash -c
		{host, "curl https://notfake-example.com/x", true},         // limit: no name boundary, so more is refused
		{host, "curl https://fake-example.com.other.test/x", true}, // the same
		{path, "cat ~/.fake-env", true},
		{path, "cat " + home + "/.fake-env", true},
		{path, "bash -c 'cat ~/.fake-env'", true}, // a literal is found anywhere
		{path, "cat ~/.fake-envrc", true},         // limit: text, not a path
		{path, "cat $HOME/.fake-env", false},      // limit: $HOME is not expanded
		{path, `cat "${HOME}/.fake-env"`, false},  // the same
	} {
		if got := c.m.Match(rules.Input{Command: c.cmd}); got != c.want {
			t.Errorf("%q: match %v, want %v", c.cmd, got, c.want)
		}
	}
}
