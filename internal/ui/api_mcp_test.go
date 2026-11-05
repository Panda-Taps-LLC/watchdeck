package ui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type mcpView struct {
	ConfigPath string  `json:"config_path"`
	Exists     bool    `json:"exists"`
	ErrorText  *string `json:"error_text"`
	Servers    []struct {
		Name    string `json:"name"`
		Stdio   bool   `json:"stdio"`
		Wrapped bool   `json:"wrapped"`
		Type    string `json:"type"`
		URL     string `json:"url"`
	} `json:"servers"`
}

func getMCP(t *testing.T, ts *testServer) (mcpView, string) {
	t.Helper()
	resp, b := ts.do(t, req{Path: "/api/mcp", Token: ts.s.Token()})
	if resp.StatusCode != 200 {
		t.Fatalf("GET /api/mcp = %d %s", resp.StatusCode, b)
	}
	var v mcpView
	decode(t, b, &v)
	if v.Servers == nil {
		t.Fatalf("servers is null: %s", b)
	}
	return v, string(b)
}

const mcpFixture = `{
  "numStartups": 3,
  "mcpServers": {
    "plain": {"command": "node", "args": ["server.js"], "env": {"API_KEY": "sk-FAKE-not-a-secret"}},
    "boxed": {"command": "/opt/bin/watchdeck", "args": ["run", "--subject", "mcp:boxed", "--", "node", "boxed.js"]},
    "remote": {"type": "http", "url": "https://someone:sk-FAKE-not-a-secret@mcp.example.invalid/v1?token=sk-FAKE-not-a-secret#frag"}
  }
}`

func TestMCPListShape(t *testing.T) {
	o := emptyOptions(t)
	dir := t.TempDir()
	o.Environ = map[string]string{"CLAUDE_CONFIG_DIR": dir}
	cfg := filepath.Join(dir, ".claude.json")
	if err := os.WriteFile(cfg, []byte(mcpFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	ts := startServer(t, o)
	v, raw := getMCP(t, ts)
	if v.ConfigPath != cfg || !v.Exists || v.ErrorText != nil {
		t.Errorf("config_path %q exists %v error_text %v", v.ConfigPath, v.Exists, v.ErrorText)
	}
	if len(v.Servers) != 3 {
		t.Fatalf("servers = %s", raw)
	}
	p, b, r := v.Servers[0], v.Servers[1], v.Servers[2]
	if p.Name != "plain" || !p.Stdio || p.Wrapped || p.Type != "" || p.URL != "" {
		t.Errorf("plain = %+v", p)
	}
	if b.Name != "boxed" || !b.Stdio || !b.Wrapped {
		t.Errorf("boxed = %+v", b)
	}
	if r.Name != "remote" || r.Stdio || r.Wrapped || r.Type != "http" || r.URL != "https://mcp.example.invalid/v1" {
		t.Errorf("remote = %+v", r)
	}
	for _, bad := range []string{"sk-FAKE", "API_KEY", "server.js", "boxed.js", "someone", "token="} {
		if strings.Contains(raw, bad) {
			t.Errorf("/api/mcp carries %q: %s", bad, raw)
		}
	}
}

func TestMCPAbsentAndBroken(t *testing.T) {
	o := emptyOptions(t)
	ts := startServer(t, o)
	v, raw := getMCP(t, ts)
	if v.ConfigPath != filepath.Join(o.Paths.Home, ".claude.json") || v.Exists || v.ErrorText != nil || len(v.Servers) != 0 {
		t.Errorf("absent = %s", raw)
	}

	if err := os.WriteFile(filepath.Join(o.Paths.Home, ".claude.json"), []byte(`{"mcpServers": {`), 0o600); err != nil {
		t.Fatal(err)
	}
	v, raw = getMCP(t, ts)
	if !v.Exists || v.ErrorText == nil || *v.ErrorText == "" || len(v.Servers) != 0 {
		t.Errorf("broken = %s", raw)
	}
}
