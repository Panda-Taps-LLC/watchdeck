package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPolicyCheck: domain entries without a *. twin are named; an invalid
// file exits 1; a clean file says ok.
func TestPolicyCheck(t *testing.T) {
	home := t.TempDir()
	cfg := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", cfg)
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("WATCHDECK_ACTIVITY", "off")
	p := filepath.Join(cfg, "watchdeck", "overrides.yaml")
	os.MkdirAll(filepath.Dir(p), 0o700)
	write := func(s string) { os.WriteFile(p, []byte(s), 0o600) }

	write("version: 2\nsubjects:\n  - {kind: tool, name: web, match: {tools: [WebFetch]}, domains: {deny: [pastebin.com, evil.test, '*.evil.test']}}\n")
	var out, errb bytes.Buffer
	if code := cmdPolicy([]string{"check"}, &out, &errb); code != 0 {
		t.Fatalf("code %d: %s %s", code, out.String(), errb.String())
	}
	if !strings.Contains(out.String(), "pastebin.com covers only that host") || strings.Contains(out.String(), "evil.test covers") {
		t.Fatalf("lint: %s", out.String())
	}
	write("version: 9\n")
	out.Reset()
	if code := cmdPolicy([]string{"check"}, &out, &errb); code != 1 || !strings.Contains(out.String(), "invalid") {
		t.Fatalf("invalid: %d %s", code, out.String())
	}
	write("version: 2\nsubjects:\n  - {kind: tool, name: web, match: {tools: [WebFetch]}, domains: {deny: ['*.pastebin.com', pastebin.com]}}\n")
	out.Reset()
	if code := cmdPolicy([]string{"check"}, &out, &errb); code != 0 || !strings.Contains(out.String(), "ok: no warnings") {
		t.Fatalf("clean: %d %s", code, out.String())
	}
	if code := cmdPolicy(nil, &out, &errb); code != 3 {
		t.Fatalf("usage: %d", code)
	}
}
