package main

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Panda-Taps-LLC/watchdeck/internal/manifest"
	"github.com/Panda-Taps-LLC/watchdeck/internal/mcpconfig"
	"github.com/Panda-Taps-LLC/watchdeck/internal/policy"
)

func mcpCmd(a []string, o, e *bytes.Buffer) int { return cmdMCP(a, o, e) }

// mcpTestEnv is newTestEnv plus a golden Claude Code user config (fake
// values) at $CLAUDE_CONFIG_DIR/.claude.json and a fake watchdeck binary.
func mcpTestEnv(t *testing.T) (testEnv, string, []byte, string) {
	t.Helper()
	golden, err := os.ReadFile(filepath.Join("..", "..", "internal", "mcpconfig", "testdata", "claude-user.json"))
	if err != nil {
		t.Fatal(err)
	}
	e := newTestEnv(t) // chdirs into a temp project
	old := sandboxAvailable
	sandboxAvailable = func() bool { return true }
	oldConsole := mcpConsole
	mcpConsole = func(stdout, stderr io.Writer, yes bool) *console {
		return &console{in: bufio.NewReader(strings.NewReader("")), out: stdout, errw: stderr, tty: false, assume: yes}
	}
	t.Cleanup(func() { sandboxAvailable, mcpConsole = old, oldConsole })
	if err := os.MkdirAll(e.claude, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(e.claude, ".claude.json")
	if err := os.WriteFile(cfg, golden, 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(e.home, "bin", "watchdeck")
	os.MkdirAll(filepath.Dir(bin), 0o755)
	os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755)
	return e, cfg, golden, bin
}

// TestMCPWrapUnwrapRoundTrip: wrap writes the wrapped entry, a 0600 backup
// and state file in the state dir, and the launch subject; status shows it;
// unwrap gives back the config byte for byte.
func TestMCPWrapUnwrapRoundTrip(t *testing.T) {
	e, cfg, golden, bin := mcpTestEnv(t)

	code, out, errs := call(t, mcpCmd, "wrap", "canary", "--dry-run", "--binary", bin)
	if code != 0 {
		t.Fatalf("dry run exit %d: %s", code, errs)
	}
	if b, _ := os.ReadFile(cfg); !bytes.Equal(b, golden) {
		t.Fatal("dry run wrote the config")
	}
	if _, err := os.Stat(filepath.Join(e.cfg, "watchdeck", "overrides.yaml")); err == nil {
		t.Fatal("dry run wrote the policy")
	}
	if strings.Contains(out, "fake-value-123") {
		t.Error("env value printed")
	}
	for _, want := range []string{"sandbox.excludedCommands", "watchdeck run *", "network is none", "dry run: nothing written", "\"mcp:canary\""} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}

	code, out, errs = call(t, mcpCmd, "wrap", "canary", "--yes", "--network", "all", "--binary", bin)
	if code != 0 {
		t.Fatalf("wrap exit %d: %s\n%s", code, errs, out)
	}
	if strings.Contains(out, "fake-value-123") {
		t.Error("env value printed")
	}
	data, _ := os.ReadFile(cfg)
	s, err := mcpconfig.Find(data, "canary")
	if err != nil || !s.Wrapped() || s.Command != bin {
		t.Fatalf("not wrapped: %+v %v", s, err)
	}
	if fi, _ := os.Stat(cfg); fi.Mode().Perm() != 0o600 {
		t.Errorf("config mode %v", fi.Mode().Perm())
	}
	baks, _ := filepath.Glob(filepath.Join(e.state, "watchdeck", "mcp-backups", ".claude.json.bak-*"))
	if len(baks) != 1 {
		t.Fatalf("backups %v", baks)
	}
	if fi, _ := os.Stat(baks[0]); fi.Mode().Perm() != 0o600 {
		t.Errorf("backup mode %v", fi.Mode().Perm())
	}
	if b, _ := os.ReadFile(baks[0]); !bytes.Equal(b, golden) {
		t.Error("backup is not the previous config")
	}
	statePath := filepath.Join(e.state, "watchdeck", mcpconfig.StateFile)
	if fi, err := os.Stat(statePath); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("state file: %v", err)
	}
	pf, _, err := policy.LoadFile(filepath.Join(e.cfg, "watchdeck", "overrides.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var sub *manifest.PolicySubject
	for i := range pf.Subjects {
		if pf.Subjects[i].Kind == "mcp" && pf.Subjects[i].Name == "canary" {
			sub = &pf.Subjects[i]
		}
	}
	if sub == nil || sub.Launch == nil || !sub.Launch.Sandbox || sub.Launch.Grant == nil ||
		strings.Join(sub.Launch.Grant.Env, ",") != "FAKE_TOKEN" || sub.Launch.Grant.Network == nil || *sub.Launch.Grant.Network != manifest.NetAll {
		t.Fatalf("subject = %+v", sub)
	}

	code, out, _ = call(t, mcpCmd, "status")
	if code != 0 || !regexpLine(out, "canary", "wrapped", "launch sandbox, network all") || !regexpLine(out, "web", "http", "remote") {
		t.Errorf("status:\n%s", out)
	}
	if !regexpLine(out, "viajson", "stdio", "not wrapped", "no launch policy") {
		t.Errorf("status (viajson):\n%s", out)
	}

	if code, _, errs := call(t, mcpCmd, "wrap", "canary", "--yes", "--binary", bin); code != 1 || !strings.Contains(errs, "already wrapped") {
		t.Errorf("second wrap: %d %s", code, errs)
	}

	code, out, errs = call(t, mcpCmd, "unwrap", "canary", "--yes")
	if code != 0 {
		t.Fatalf("unwrap exit %d: %s", code, errs)
	}
	if !strings.Contains(out, "byte for byte") {
		t.Errorf("unwrap output:\n%s", out)
	}
	if b, _ := os.ReadFile(cfg); !bytes.Equal(b, golden) {
		t.Error("unwrap is not byte-identical to the original config")
	}
	st, _ := mcpconfig.LoadState(statePath)
	if len(st.Servers) != 0 {
		t.Errorf("state not cleared: %+v", st)
	}
}

// regexpLine reports whether one line of out holds every word, in order.
func regexpLine(out string, words ...string) bool {
	for _, l := range strings.Split(out, "\n") {
		rest, ok := l, true
		for _, w := range words {
			i := strings.Index(rest, w)
			if i < 0 {
				ok = false
				break
			}
			rest = rest[i+len(w):]
		}
		if ok {
			return true
		}
	}
	return false
}

// TestMCPWrapRefusals: non-stdio, local scope, unknown names, project
// scope, invalid names and a missing confirmation write nothing.
func TestMCPWrapRefusals(t *testing.T) {
	_, cfg, golden, bin := mcpTestEnv(t)
	cases := []struct {
		args []string
		code int
		want string
	}{
		{[]string{"wrap", "web", "--yes", "--binary", bin}, 1, "not a stdio server"},
		{[]string{"wrap", "nourltype", "--yes", "--binary", bin}, 1, "not a stdio server"},
		{[]string{"wrap", "loc", "--yes", "--binary", bin}, 1, "local-scope server"},
		{[]string{"wrap", "absent", "--yes", "--binary", bin}, 1, "not a user-scope server"},
		{[]string{"wrap", "canary", "--scope", "project", "--yes", "--binary", bin}, 1, "only --scope user"},
		{[]string{"wrap", "canary", "--scope", "local", "--yes", "--binary", bin}, 1, "only --scope user"},
		{[]string{"wrap", "*", "--yes", "--binary", bin}, 3, "invalid server name"},
		{[]string{"wrap", "canary", "--yes", "--binary", "relative/watchdeck"}, 2, "absolute"},
		{[]string{"wrap", "canary", "--binary", bin}, 1, "no terminal to confirm"},
		{[]string{"unwrap", "canary", "--yes"}, 1, "not wrapped"},
		{[]string{"wrap"}, 3, "usage"},
		{[]string{"wrap", "canary", "--yes", "--binary", bin, "--no-such-flag"}, 3, "not defined"},
		{[]string{"frob"}, 3, "unknown subcommand"},
	}
	for _, c := range cases {
		code, _, errs := call(t, mcpCmd, c.args...)
		if code != c.code || !strings.Contains(errs, c.want) {
			t.Errorf("%v: exit %d, stderr %q", c.args, code, errs)
		}
		if b, _ := os.ReadFile(cfg); !bytes.Equal(b, golden) {
			t.Fatalf("%v wrote the config", c.args)
		}
	}
}

// TestMCPWrapKeepsGates: wrap keeps an existing subject's tools gates and
// launch grant, and adds the server's env keys.
func TestMCPWrapKeepsGates(t *testing.T) {
	e, _, _, bin := mcpTestEnv(t)
	dir := filepath.Join(e.cfg, "watchdeck")
	os.MkdirAll(dir, 0o700)
	os.WriteFile(filepath.Join(dir, "overrides.yaml"), []byte("version: 2\nsubjects:\n  - {kind: mcp, name: canary, tools: {'delete_*': deny}, launch: {sandbox: false, grant: {env: [OTHER_KEY], network: localhost}}}\n"), 0o600)
	if code, _, errs := call(t, mcpCmd, "wrap", "canary", "--yes", "--binary", bin); code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	pf, _, err := policy.LoadFile(filepath.Join(dir, "overrides.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	s := pf.Subjects[0]
	if s.MCPTools["delete_*"] != "deny" || !s.Launch.Sandbox || strings.Join(s.Launch.Grant.Env, ",") != "OTHER_KEY,FAKE_TOKEN" ||
		*s.Launch.Grant.Network != manifest.NetLocalhost {
		t.Errorf("subject = %+v / %+v", s, s.Launch.Grant)
	}
}

func TestMCPSubjectArgs(t *testing.T) {
	newTestEnv(t) // the malformed runs below write usage records: keep them in a temp state dir
	for args, want := range map[string]bool{
		"--subject mcp:x -- a":   true,
		"--subject=mcp:x -- a":   true,
		"--skill x -c a":         false,
		"--subject skill:x -- a": false,
		"-- --subject mcp:x":     false,
	} {
		if got := mcpSubjectArgs(strings.Fields(args)); got != want {
			t.Errorf("%q: %v", args, got)
		}
	}
	// Malformed mcp forms are usage errors (3), never a skill run.
	for _, args := range [][]string{{"--subject", "mcp:x", "--"}, {"--subject", "mcp:", "--", "a"}, {"--subject", "mcp:x", "-c", "a"}} {
		if code := cmdRun(args); code != 3 {
			t.Errorf("%v: exit %d", args, code)
		}
	}
}

func TestMCPWrapRefusedWithoutSandbox(t *testing.T) {
	_, cfg, golden, bin := mcpTestEnv(t)
	sandboxAvailable = func() bool { return false }
	code, _, errs := call(t, mcpCmd, "wrap", "canary", "--yes", "--binary", bin)
	if code != 1 || !strings.Contains(errs, "cannot sandbox") {
		t.Errorf("exit %d: %s", code, errs)
	}
	if b, _ := os.ReadFile(cfg); !bytes.Equal(b, golden) {
		t.Error("config written")
	}
}
