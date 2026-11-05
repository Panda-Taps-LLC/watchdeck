//go:build linux

package runner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestMCPLinuxPassThroughAndEnv: under bwrap the canary MCP server answers
// initialize and an env call through RunMCP with pipe descriptors, sees only
// the granted env names, and cannot reach the network. Written 2026-10-14
// for CI (ubuntu-24.04); not run on a developer's Linux machine.
func TestMCPLinuxPassThroughAndEnv(t *testing.T) {
	f := newLinuxFixture(t)
	os.MkdirAll(f.env.UserCfgDir, 0o755)
	if err := os.WriteFile(filepath.Join(f.env.UserCfgDir, "overrides.yaml"), []byte(
		"version: 2\nsubjects:\n  - {kind: mcp, name: canary, launch: {sandbox: true, grant: {env: [FAKE_TOKEN]}}}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.environ = append(f.environ, "FAKE_TOKEN=fake-token-value", "OTHER_TOKEN=not-for-this-server")
	server, _ := filepath.Abs(filepath.Join("..", "..", "testdata", "mcp", "canary_server.py"))
	inR, inW, _ := os.Pipe()
	outR, outW, _ := os.Pipe()
	var errb bytes.Buffer
	done := make(chan int, 1)
	go func() {
		code := RunMCP(context.Background(), MCPOptions{Server: "canary", Argv: []string{"python3", server}, Env: f.env, Environ: f.environ,
			Stdin: inR, Stdout: outW, Stderr: &errb, ActivityPath: f.activity})
		inR.Close()
		outW.Close()
		done <- code
	}()
	rd := bufio.NewReader(outR)
	rt := func(req string) []byte {
		inW.WriteString(req + "\n")
		line, err := rd.ReadBytes('\n')
		if err != nil {
			t.Fatalf("read: %v; stderr %q", err, errb.String())
		}
		return line
	}
	if l := rt(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`); !bytes.Contains(l, []byte(`"watchdeck-canary"`)) {
		t.Fatalf("initialize: %q", l)
	}
	text := func(l []byte) string {
		var r struct {
			Result struct {
				Content []struct{ Text string } `json:"content"`
			} `json:"result"`
		}
		json.Unmarshal(l, &r)
		if len(r.Result.Content) == 0 {
			t.Fatalf("bad response %q", l)
		}
		return r.Result.Content[0].Text
	}
	env := " " + text(rt(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"env","arguments":{}}}`)) + " "
	if !strings.Contains(env, " FAKE_TOKEN ") || strings.Contains(env, " OTHER_TOKEN ") || strings.Contains(env, " CANARY_SECRET ") {
		t.Errorf("env names: %q", env)
	}
	if got := text(rt(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"net","arguments":{"host":"1.1.1.1","port":53}}}`)); !strings.HasPrefix(got, "denied") {
		t.Errorf("network: %q", got)
	}
	inW.Close()
	if code := <-done; code != 0 {
		t.Errorf("exit %d, stderr %q", code, errb.String())
	}
}

// TestRunLinuxDeniesClaudeConfig: under bwrap a skill run cannot read
// ~/.claude.json (hidden by /dev/null) or a relocated CLAUDE_CONFIG_DIR
// (tmpfs). Written 2026-10-14 for CI; not run on a developer machine.
func TestRunLinuxDeniesClaudeConfig(t *testing.T) {
	f := newLinuxFixture(t)
	cfg := filepath.Join(f.home, ".claude.json")
	os.WriteFile(cfg, []byte(`{"fake":"home-value"}`), 0o600)
	rel := filepath.Join(f.home, "relocated-claude")
	os.MkdirAll(rel, 0o700)
	os.WriteFile(filepath.Join(rel, "settings.json"), []byte(`{"fake":"relocated-value"}`), 0o600)
	os.WriteFile(cfg+".backup", []byte(`{"fake":"backup-value"}`), 0o600)
	f.environ = append(f.environ, "CLAUDE_CONFIG_DIR="+rel)
	for _, p := range []string{cfg, cfg + ".backup", filepath.Join(rel, "settings.json")} {
		out, _, _ := f.run("canary-basic", "cat "+p)
		if strings.Contains(out, "value") {
			t.Errorf("%s readable: %q", p, out)
		}
	}
}
