package hook

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestSearchToolGates: Grep and Glob are gated on the directory they search
// (path, default the cwd): under an entry, the entry's action; an ancestor
// of an entry, ask (the search can reach it); elsewhere, nothing.
func TestSearchToolGates(t *testing.T) {
	f := newFx(t)
	f.writeUser(t, "version: 2\nsubjects:\n  - {kind: tool, name: secrets, match: {tools: [Read, Grep, Glob]}, paths: {deny: ['~/.ssh', '~/proj/vault']}}\n")
	cases := []struct {
		tool string
		in   map[string]any
		want string
	}{
		{"Grep", map[string]any{"pattern": "BEGIN", "path": f.home + "/.ssh"}, Deny},
		{"Grep", map[string]any{"pattern": "BEGIN", "path": "~/.ssh/keys"}, Deny},
		{"Grep", map[string]any{"pattern": "BEGIN", "path": f.home}, Ask},  // an ancestor of ~/.ssh
		{"Glob", map[string]any{"pattern": "**/*"}, Ask},                   // cwd ~/proj holds ~/proj/vault
		{"Glob", map[string]any{"pattern": "**/*", "path": "src"}, "none"}, // ~/proj/src
		{"Grep", map[string]any{"pattern": "x", "path": filepath.Join(f.cwd, "vault", "a")}, Deny},
		{"Grep", map[string]any{"pattern": "x", "path": "/usr/share"}, "none"},
	}
	for _, c := range cases {
		out := Decide(f.tool(c.tool, c.in), f.env)
		if got := decisionOf(out); got != c.want {
			t.Errorf("%s %v: %s, want %s (%+v)", c.tool, c.in, got, c.want, out)
		}
		if out != nil && !strings.Contains(out.HookSpecificOutput.PermissionDecisionReason, "tool gate secrets") {
			t.Errorf("%s: reason %q", c.tool, out.HookSpecificOutput.PermissionDecisionReason)
		}
	}
}
