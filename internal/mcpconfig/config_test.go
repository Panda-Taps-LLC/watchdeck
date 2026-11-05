package mcpconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

const bin = "/usr/local/bin/watchdeck"

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func decode(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	return m
}

// TestWrapUnwrapRoundTripByteIdentical: on the golden configs, wrap then
// unwrap of every stdio user-scope server gives back the file byte for
// byte; wrap changes only that entry (everything else, semantically and
// byte for byte outside the entry, is unchanged).
func TestWrapUnwrapRoundTripByteIdentical(t *testing.T) {
	for _, file := range []string{"claude-user.json", "claude-compact.json"} {
		data := fixture(t, file)
		list, err := List(data)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, s := range list {
			if Wrappable(s) != nil {
				continue
			}
			n++
			out, orig, wrapped, err := Wrap(data, s.Name, bin, false)
			if err != nil {
				t.Fatalf("%s/%s: %v", file, s.Name, err)
			}
			if !bytes.Equal(orig, s.Raw) {
				t.Errorf("%s/%s: original bytes differ", file, s.Name)
			}
			// only the entry changed
			i := bytes.Index(data, orig)
			if !bytes.Equal(out[:i], data[:i]) || !bytes.Equal(out[i+len(wrapped):], data[i+len(orig):]) {
				t.Errorf("%s/%s: bytes outside the entry changed", file, s.Name)
			}
			a, b := decode(t, data), decode(t, out)
			b["mcpServers"].(map[string]any)[s.Name] = a["mcpServers"].(map[string]any)[s.Name]
			if !reflect.DeepEqual(a, b) {
				t.Errorf("%s/%s: a value outside the entry changed", file, s.Name)
			}
			w, err := Find(out, s.Name)
			if err != nil || !w.Wrapped() || w.Command != bin {
				t.Fatalf("%s/%s: not wrapped: %+v %v", file, s.Name, w, err)
			}
			if got := OriginalArgv(w); !reflect.DeepEqual(got, append([]string{s.Command}, s.Args...)) {
				t.Errorf("%s/%s: original argv %q", file, s.Name, got)
			}
			if !reflect.DeepEqual(w.EnvKeys, s.EnvKeys) {
				t.Errorf("%s/%s: env keys %v -> %v", file, s.Name, s.EnvKeys, w.EnvKeys)
			}
			back, exact, err := Unwrap(out, s.Name, orig, wrapped)
			if err != nil || !exact {
				t.Fatalf("%s/%s: unwrap exact=%v err=%v", file, s.Name, exact, err)
			}
			if !bytes.Equal(back, data) {
				t.Errorf("%s/%s: round trip not byte-identical", file, s.Name)
			}
		}
		if n < 3 {
			t.Errorf("%s: only %d wrappable servers", file, n)
		}
	}
}

// TestWrappedEntryFormat: the new entry is indented like Claude Code's
// JSON.stringify(…, null, 2) at its depth; a compact file stays compact.
func TestWrappedEntryFormat(t *testing.T) {
	_, _, wrapped, err := Wrap(fixture(t, "claude-user.json"), "canary", bin, false)
	if err != nil {
		t.Fatal(err)
	}
	want := `{
      "type": "stdio",
      "command": "/usr/local/bin/watchdeck",
      "args": [
        "run",
        "--subject",
        "mcp:canary",
        "--",
        "/usr/bin/python3",
        "/Users/you/mcp/server.py",
        "--flag",
        "a"
      ],
      "env": {
        "FAKE_TOKEN": "fake-value-123"
      }
    }`
	if string(wrapped) != want {
		t.Errorf("wrapped entry:\n%s\nwant:\n%s", wrapped, want)
	}
	_, _, w2, err := Wrap(fixture(t, "claude-user.json"), "noargs", bin, false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(w2), "\"command\": \"/usr/local/bin/watchdeck\",\n      \"args\": [\n        \"run\"") {
		t.Errorf("args not added after command:\n%s", w2)
	}
	_, _, w3, err := Wrap(fixture(t, "claude-compact.json"), "canary", bin, false)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(w3, []byte("\n")) {
		t.Errorf("compact entry got newlines: %s", w3)
	}
	_, _, w4, err := Wrap(fixture(t, "claude-user.json"), "unicode", bin, false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(w4), `"/opt/fake/bin/sérver"`) || !strings.Contains(string(w4), `"<&>"`) {
		t.Errorf("strings re-escaped: %s", w4)
	}
}

// TestWrapRefusals: non-stdio servers, already wrapped ones, missing and
// local-scope-only names, duplicate keys and a relative binary are refused.
func TestWrapRefusals(t *testing.T) {
	data := fixture(t, "claude-user.json")
	for _, name := range []string{"web", "events", "nourltype"} {
		if _, _, _, err := Wrap(data, name, bin, false); err == nil || !strings.Contains(err.Error(), "not a stdio server") {
			t.Errorf("%s: %v", name, err)
		}
	}
	out, _, _, err := Wrap(data, "canary", bin, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := Wrap(out, "canary", bin, false); err == nil || !strings.Contains(err.Error(), "already wrapped") {
		t.Errorf("double wrap: %v", err)
	}
	if _, _, _, err := Wrap(data, "loc", bin, false); !errors.Is(err, ErrNotFound) {
		t.Errorf("local scope: %v", err)
	}
	if got := LocalScopeProjects(data, "loc"); !reflect.DeepEqual(got, []string{"/Users/you/proj"}) {
		t.Errorf("LocalScopeProjects = %v", got)
	}
	if _, _, _, err := Wrap(data, "absent", bin, false); !errors.Is(err, ErrNotFound) {
		t.Errorf("absent: %v", err)
	}
	if _, _, _, err := Wrap(data, "canary", "watchdeck", false); err == nil {
		t.Error("relative binary accepted")
	}
	dupTop := []byte(`{"mcpServers":{},"mcpServers":{"a":{"command":"x"}}}`)
	if _, _, _, err := Wrap(dupTop, "a", bin, false); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("duplicate mcpServers: %v", err)
	}
	dupName := []byte(`{"mcpServers":{"a":{"command":"x"},"a":{"command":"y"}}}`)
	if _, _, _, err := Wrap(dupName, "a", bin, false); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("duplicate name: %v", err)
	}
	for _, bad := range []string{`{"mcpServers":{"a":{"command":"x","command":"y"}}}`, `{"mcpServers":{"a":{"command":"x","env":{"K":"1","K":"2"}}}}`, `[]`, `{"mcpServers":{"a":{"command":"x"}}} trailing`, `{"mcpServers":{"a":{"command":1}}}`, `{"mcpServers":{"a":{"command":"x","args":[1]}}}`} {
		if _, _, _, err := Wrap([]byte(bad), "a", bin, false); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

// TestUnwrapAfterReindent: Claude Code may rewrite the file with its own
// formatting; an entry that is the same JSON value still restores exactly.
func TestUnwrapAfterReindent(t *testing.T) {
	data := fixture(t, "claude-user.json")
	out, orig, wrapped, err := Wrap(data, "canary", bin, false)
	if err != nil {
		t.Fatal(err)
	}
	var compact bytes.Buffer
	json.Compact(&compact, wrapped)
	reindented := bytes.Replace(out, wrapped, compact.Bytes(), 1)
	back, exact, err := Unwrap(reindented, "canary", orig, wrapped)
	if err != nil || !exact {
		t.Fatalf("exact=%v err=%v", exact, err)
	}
	if !bytes.Contains(back, orig) {
		t.Error("original bytes not restored")
	}
}

// TestUnwrapEditedEntry: an entry edited after wrap (env changed) gets its
// command and args back and keeps the edit; exact is false.
func TestUnwrapEditedEntry(t *testing.T) {
	data := fixture(t, "claude-user.json")
	out, orig, wrapped, err := Wrap(data, "canary", bin, false)
	if err != nil {
		t.Fatal(err)
	}
	edited := bytes.Replace(out, []byte(`"fake-value-123"`), []byte(`"fake-value-456"`), 1)
	back, exact, err := Unwrap(edited, "canary", orig, wrapped)
	if err != nil || exact {
		t.Fatalf("exact=%v err=%v", exact, err)
	}
	s, _ := Find(back, "canary")
	if s.Wrapped() || s.Command != "/usr/bin/python3" || !reflect.DeepEqual(s.Args, []string{"/Users/you/mcp/server.py", "--flag", "a"}) {
		t.Errorf("not restored: %+v", s)
	}
	if !bytes.Contains(back, []byte("fake-value-456")) {
		t.Error("the edit was lost")
	}
	if _, _, err := Unwrap(data, "canary", orig, wrapped); err == nil {
		t.Error("unwrap of an unwrapped entry accepted")
	}
}

func TestRedactedEntry(t *testing.T) {
	s, _ := Find(fixture(t, "claude-user.json"), "canary")
	r := RedactedEntry(s.Raw)
	if strings.Contains(r, "fake-value-123") || !strings.Contains(r, `"FAKE_TOKEN": "***"`) {
		t.Errorf("redacted:\n%s", r)
	}
}

func TestUserConfigPath(t *testing.T) {
	if got := UserConfigPath("/h", map[string]string{}); got != "/h/.claude.json" {
		t.Error(got)
	}
	if got := UserConfigPath("/h", map[string]string{"CLAUDE_CONFIG_DIR": "/c"}); got != "/c/.claude.json" {
		t.Error(got)
	}
}

// TestWriteConfigBackupAtomic: a 0600 backup in a 0700 dir, the file's mode
// kept, the change check, and pruning to KeepBackups.
func TestWriteConfigBackupAtomic(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, ".claude.json")
	old := fixture(t, "claude-user.json")
	if err := os.WriteFile(cfg, old, 0o600); err != nil {
		t.Fatal(err)
	}
	next, _, _, err := Wrap(old, "canary", bin, false)
	if err != nil {
		t.Fatal(err)
	}
	bdir := filepath.Join(dir, "state", "mcp-backups")
	data, real, exists, err := ReadConfig(cfg)
	if err != nil || !exists || !bytes.Equal(data, old) {
		t.Fatal(err)
	}
	backup, err := WriteConfig(real, data, next, bdir)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(backup); !bytes.Equal(b, old) {
		t.Error("backup content")
	}
	if fi, _ := os.Stat(backup); fi.Mode().Perm() != 0o600 {
		t.Errorf("backup mode %v", fi.Mode().Perm())
	}
	if fi, _ := os.Stat(bdir); fi.Mode().Perm() != 0o700 {
		t.Errorf("backup dir mode %v", fi.Mode().Perm())
	}
	if fi, _ := os.Stat(cfg); fi.Mode().Perm() != 0o600 {
		t.Errorf("config mode %v", fi.Mode().Perm())
	}
	if b, _ := os.ReadFile(cfg); !bytes.Equal(b, next) {
		t.Error("config not written")
	}
	// The config changes under us: nothing is written.
	beforeRename = func() { os.WriteFile(cfg, []byte(`{"changed":true}`), 0o600) }
	_, err = WriteConfig(real, next, old, bdir)
	beforeRename = func() {}
	if !errors.Is(err, ErrChanged) {
		t.Errorf("err = %v", err)
	}
	if b, _ := os.ReadFile(cfg); string(b) != `{"changed":true}` {
		t.Errorf("written despite the change: %s", b)
	}
	if tmps, _ := filepath.Glob(filepath.Join(dir, ".*.tmp")); len(tmps) != 0 {
		t.Errorf("temp files left: %v", tmps)
	}
	// Pruning keeps the newest KeepBackups.
	os.WriteFile(cfg, old, 0o600)
	base := time.Unix(1_800_000_000, 0)
	for i := 0; i < KeepBackups+3; i++ {
		backupNow = func() time.Time { return base.Add(time.Duration(i) * time.Second) }
		cur, _ := os.ReadFile(cfg)
		if _, err := WriteConfig(cfg, cur, cur, bdir); err != nil {
			t.Fatal(err)
		}
	}
	backupNow = time.Now
	baks, _ := filepath.Glob(filepath.Join(bdir, ".claude.json.bak-*"))
	if len(baks) != KeepBackups {
		t.Errorf("%d backups kept", len(baks))
	}
}

// TestSymlinkedConfigWritesTarget: a symlinked config is edited at its
// target and the link stays a link.
func TestSymlinkedConfigWritesTarget(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "dotfiles", "claude.json")
	os.MkdirAll(filepath.Dir(target), 0o700)
	os.WriteFile(target, fixture(t, "claude-user.json"), 0o600)
	link := filepath.Join(dir, ".claude.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	data, real, _, err := ReadConfig(link)
	if err != nil {
		t.Fatal(err)
	}
	next, _, _, _ := Wrap(data, "canary", bin, false)
	if _, err := WriteConfig(real, data, next, filepath.Join(dir, "b")); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Lstat(link); fi.Mode()&os.ModeSymlink == 0 {
		t.Error("link replaced by a file")
	}
	if b, _ := os.ReadFile(target); !bytes.Equal(b, next) {
		t.Error("target not written")
	}
}

func TestStateRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s", StateFile)
	st, err := LoadState(p)
	if err != nil || len(st.Servers) != 0 {
		t.Fatal(err)
	}
	st.Put(Record{Config: "/c", Name: "b", Original: "{}", Wrapped: "{}"})
	st.Put(Record{Config: "/c", Name: "a", Original: "{}", Wrapped: "{}"})
	st.Put(Record{Config: "/c", Name: "a", Original: "{\"x\":1}", Wrapped: "{}"})
	if err := SaveState(p, st); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", fi.Mode().Perm())
	}
	back, err := LoadState(p)
	if err != nil || len(back.Servers) != 2 || back.Servers[0].Name != "a" || back.Servers[0].Original != "{\"x\":1}" {
		t.Fatalf("%+v %v", back, err)
	}
	back.Delete("/c", "a")
	if _, ok := back.Get("/c", "a"); ok {
		t.Error("not deleted")
	}
}

// TestAllowHomeCwdFlag: the optional flag is written before "--", detected
// as wrapped, and skipped by OriginalArgv.
func TestAllowHomeCwdFlag(t *testing.T) {
	out, _, _, err := Wrap(fixture(t, "claude-user.json"), "canary", bin, true)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := Find(out, "canary")
	if !s.Wrapped() || s.Args[3] != AllowHomeCwdFlag || s.Args[4] != "--" {
		t.Fatalf("args %q", s.Args)
	}
	if got := OriginalArgv(s); !reflect.DeepEqual(got, []string{"/usr/bin/python3", "/Users/you/mcp/server.py", "--flag", "a"}) {
		t.Errorf("original argv %q", got)
	}
}
