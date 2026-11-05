//go:build darwin

package runner

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Panda-Taps-LLC/watchdeck/internal/sandbox"
)

// claudeCfgFixture writes fake Claude Code config files into the fixture
// home: ~/.claude.json, and a relocated CLAUDE_CONFIG_DIR holding its own
// .claude.json and a backup. Fake values only.
func claudeCfgFixture(t *testing.T, f *fixture) (homeCfg, relocated string) {
	t.Helper()
	homeCfg = filepath.Join(f.home, ".claude.json")
	if err := os.WriteFile(homeCfg, []byte(`{"mcpServers":{"x":{"command":"fake","env":{"K":"fake-home-value"}}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	relocated = filepath.Join(f.home, "relocated-claude")
	os.MkdirAll(filepath.Join(relocated, "backups"), 0o700)
	os.WriteFile(filepath.Join(relocated, ".claude.json"), []byte(`{"fake":"relocated-value"}`), 0o600)
	os.WriteFile(filepath.Join(relocated, "backups", ".claude.json.backup.1"), []byte(`{"fake":"backup-value"}`), 0o600)
	os.WriteFile(filepath.Join(f.home, "plain.txt"), []byte("plain-readable\n"), 0o600)
	f.environ = append(f.environ, "CLAUDE_CONFIG_DIR="+relocated)
	return homeCfg, relocated
}

func (f *fixture) runCmd(t *testing.T, skill, cmd string) (string, string, int) {
	t.Helper()
	var out, errb bytes.Buffer
	code := Run(context.Background(), Options{Skills: []string{skill}, Command: cmd, Env: f.env, Environ: f.environ, Stdout: &out, Stderr: &errb, ActivityPath: f.activity})
	return out.String(), errb.String(), code
}

// TestRunDeniesClaudeConfig: a skill script can read neither ~/.claude.json
// nor a relocated CLAUDE_CONFIG_DIR (its .claude.json and the rest of it),
// while an ordinary file in the same home stays readable.
func TestRunDeniesClaudeConfig(t *testing.T) {
	f := newFixture(t)
	homeCfg, relocated := claudeCfgFixture(t, f)
	if out, errb, code := f.runCmd(t, "canary-basic", "/bin/cat "+filepath.Join(f.home, "plain.txt")); code != 0 || !strings.Contains(out, "plain-readable") {
		t.Fatalf("control read failed: %d %q %q", code, out, errb)
	}
	// Siblings Claude Code writes next to the file: a backup and a temp file.
	backup := homeCfg + ".backup"
	tmp := homeCfg + ".tmp.4242.1791940085"
	os.WriteFile(backup, []byte(`{"fake":"backup-sibling-value"}`), 0o600)
	os.WriteFile(tmp, []byte(`{"fake":"tmp-sibling-value"}`), 0o600)
	for _, p := range []string{homeCfg, backup, tmp, filepath.Join(relocated, ".claude.json"), filepath.Join(relocated, "backups", ".claude.json.backup.1")} {
		out, errb, code := f.runCmd(t, "canary-basic", "/bin/cat "+p)
		if code == 0 || strings.Contains(out, "value") {
			t.Errorf("%s readable: %d %q", p, code, out)
		}
		if !strings.Contains(errb, "Operation not permitted") {
			t.Errorf("%s: not a sandbox denial: %q", p, errb)
		}
	}
	// A sibling that appears after the profile is built is covered by the
	// prefix pattern, not only by the existing-file list.
	pol, err := Resolve([]string{"canary-basic"}, Env{Home: f.env.Home, Cwd: f.env.Cwd, CacheDir: f.env.CacheDir, UserCfgDir: f.env.UserCfgDir, Environ: map[string]string{"HOME": f.home}}, true)
	if err != nil {
		t.Fatal(err)
	}
	late := homeCfg + ".tmp.late"
	if err := os.WriteFile(late, []byte(`{"fake":"late-sibling-value"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	res, err := sandbox.Run(context.Background(), sandbox.Options{Profile: pol.Profile, Argv: []string{"/bin/cat", late},
		Env: []string{"PATH=/usr/bin:/bin"}, Dir: f.cwd, Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb})
	if err != nil || res.ExitCode == 0 || strings.Contains(out.String(), "value") {
		t.Errorf("sibling created after the profile was built is readable: %v %d %q %q", err, res.ExitCode, out.String(), errb.String())
	}
}

// TestRunHomeRedirectKeepsAccountDenies: `HOME=/elsewhere watchdeck run …`
// must not move the protected paths: the account home's ~/.ssh, ~/.aws,
// ~/.claude, ~/.claude.json (and siblings) stay denied, while an ordinary
// file there stays readable. The account home is a fake one here.
func TestRunHomeRedirectKeepsAccountDenies(t *testing.T) {
	f := newFixture(t)
	acct, err := os.MkdirTemp("/var/tmp", "watchdeck-acct-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(acct) })
	acct, _ = filepath.EvalSymlinks(acct)
	stubAccountHome(t, acct, nil)
	files := map[string]string{
		".ssh/id_fake":             "fake-key-value",
		".aws/credentials":         "fake-aws-value",
		".claude/settings.json":    `{"fake":"settings-value"}`,
		".claude.json":             `{"fake":"cfg-value"}`,
		".claude.json.backup":      `{"fake":"backup-value"}`,
		".local/state/watchdeck/x": "state-value",
		"plain.txt":                "plain-readable",
	}
	for rel, body := range files {
		p := filepath.Join(acct, rel)
		os.MkdirAll(filepath.Dir(p), 0o700)
		os.WriteFile(p, []byte(body), 0o600)
	}
	// f.env.Home / HOME is the redirected home (the fixture's), not acct.
	for rel := range files {
		out, errb, code := f.runCmd(t, "canary-basic", "/bin/cat "+filepath.Join(acct, rel))
		if rel == "plain.txt" {
			if code != 0 || !strings.Contains(out, "plain-readable") {
				t.Errorf("control: %d %q %q", code, out, errb)
			}
			continue
		}
		if code == 0 || strings.Contains(out, "value") {
			t.Errorf("HOME redirected: %s readable: %q", rel, out)
		}
	}
	// CLAUDE_CONFIG_DIR redirected: the account's ~/.claude and
	// ~/.claude.json stay denied.
	stubAccountHome(t, f.home, nil)
	os.MkdirAll(filepath.Join(f.home, ".claude"), 0o700)
	os.WriteFile(filepath.Join(f.home, ".claude", "settings.json"), []byte(`{"fake":"settings-value"}`), 0o600)
	os.WriteFile(filepath.Join(f.home, ".claude.json"), []byte(`{"fake":"cfg-value"}`), 0o600)
	f.environ = append(f.environ, "CLAUDE_CONFIG_DIR="+filepath.Join(f.cwd, "elsewhere"))
	for _, p := range []string{filepath.Join(f.home, ".claude", "settings.json"), filepath.Join(f.home, ".claude.json")} {
		out, _, code := f.runCmd(t, "canary-basic", "/bin/cat "+p)
		if code == 0 || strings.Contains(out, "value") {
			t.Errorf("CLAUDE_CONFIG_DIR redirected: %s readable: %q", p, out)
		}
	}
}

// TestRunRefusesUnreadableAccountHome: no user database entry, no run.
func TestRunRefusesUnreadableAccountHome(t *testing.T) {
	f := newFixture(t)
	stubAccountHome(t, "", errors.New("no entry"))
	_, errb, code := f.runCmd(t, "canary-basic", "/usr/bin/true")
	if code != ExitPolicy || !strings.Contains(errb, "user database") {
		t.Errorf("exit %d: %q", code, errb)
	}
}

// TestRunClaudeConfigNotReallowed: user override write and read entries for
// those paths do not re-allow them: writes are dropped with a warning,
// reads stay denied.
func TestRunClaudeConfigNotReallowed(t *testing.T) {
	f := newFixture(t)
	homeCfg, relocated := claudeCfgFixture(t, f)
	body := "version: 1\nskills:\n  canary-basic:\n    write: [\"~/.claude.json\", \"" + relocated + "\"]\n    read: [\"~/.claude.json\", \"" + relocated + "\"]\n"
	if err := os.WriteFile(filepath.Join(f.cfg, "overrides.yaml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	out, errb, code := f.runCmd(t, "canary-basic", "/bin/cat "+homeCfg)
	if code == 0 || strings.Contains(out, "fake-home-value") {
		t.Errorf("~/.claude.json readable with a read override: %d %q", code, out)
	}
	if !strings.Contains(errb, "ignored: under a protected path") {
		t.Errorf("dropped write not reported: %q", errb)
	}
	_, _, code = f.runCmd(t, "canary-basic", "/bin/sh -c 'echo planted >> "+homeCfg+"'")
	if code == 0 {
		t.Error("write to ~/.claude.json allowed by a write override")
	}
	_, _, code = f.runCmd(t, "canary-basic", "/bin/sh -c 'echo planted > "+filepath.Join(relocated, "planted")+"'")
	if code == 0 {
		t.Error("write into the relocated CLAUDE_CONFIG_DIR allowed by a write override")
	}
	if b, _ := os.ReadFile(homeCfg); strings.Contains(string(b), "planted") {
		t.Error("~/.claude.json was modified")
	}
	if _, err := os.Stat(filepath.Join(relocated, "planted")); err == nil {
		t.Error("file planted in the relocated config dir")
	}
}
