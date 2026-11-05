package manifest

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func fixture(name string) string { return filepath.Join("testdata", name) }

func TestParseFixtures(t *testing.T) {
	tests := []struct {
		name    string
		file    string
		wantErr string // substring; "" means success
		check   func(t *testing.T, m Manifest)
	}{
		{
			name: "valid manifest",
			file: "valid.yaml",
			check: func(t *testing.T, m Manifest) {
				if m.Version != 1 {
					t.Errorf("Version = %d, want 1", m.Version)
				}
				if !reflect.DeepEqual(m.Scripts, []string{"scripts/**"}) {
					t.Errorf("Scripts = %q", m.Scripts)
				}
				if !reflect.DeepEqual(m.Filesystem.Read, []string{"${SKILL_DIR}", "${CWD}"}) {
					t.Errorf("Read = %q", m.Filesystem.Read)
				}
				if !reflect.DeepEqual(m.Filesystem.Write, []string{"${CWD}", "${TMP}"}) {
					t.Errorf("Write = %q", m.Filesystem.Write)
				}
				if len(m.Filesystem.Deny) != len(BuiltinDeny) {
					t.Errorf("Deny has %d entries, want %d", len(m.Filesystem.Deny), len(BuiltinDeny))
				}
				if m.Network != NetNone {
					t.Errorf("Network = %s, want none", m.Network)
				}
				if !m.ExecAny || m.Exec != nil {
					t.Errorf("ExecAny=%v Exec=%q, want any", m.ExecAny, m.Exec)
				}
				if !reflect.DeepEqual(m.Env, []string{"PATH", "HOME", "LANG", "TMPDIR"}) {
					t.Errorf("Env = %q", m.Env)
				}
				if !reflect.DeepEqual(m.Tools, []string{"Read", "Write", "Bash"}) {
					t.Errorf("Tools = %q", m.Tools)
				}
				if m.Notes == "" {
					t.Error("Notes empty")
				}
			},
		},
		{name: "unknown top-level field", file: "unknown_field.yaml", wantErr: `[2:1] unknown field …`},
		{name: "unknown nested field", file: "unknown_nested.yaml", wantErr: `[3:3] unknown field …`},
		{name: "version 2", file: "version2.yaml", wantErr: "version: must be 1 (got 2)"},
		{
			name: "exec any",
			file: "exec_any.yaml",
			check: func(t *testing.T, m Manifest) {
				if !m.ExecAny || len(m.Exec) != 0 {
					t.Errorf("ExecAny=%v Exec=%q, want any", m.ExecAny, m.Exec)
				}
			},
		},
		{
			name: "exec list",
			file: "exec_list.yaml",
			check: func(t *testing.T, m Manifest) {
				if m.ExecAny {
					t.Error("ExecAny = true, want false")
				}
				if want := []string{"/usr/bin/python3", "/usr/bin/qpdf"}; !reflect.DeepEqual(m.Exec, want) {
					t.Errorf("Exec = %q, want %q", m.Exec, want)
				}
			},
		},
		{name: "bad env name", file: "bad_env.yaml", wantErr: `env[1]: must match ^[A-Z_][A-Z0-9_]*$`},
		{name: "read ~/.ssh", file: "read_ssh.yaml", wantErr: `filesystem.read[1]: is a built-in deny path (~/.ssh)`},
		{name: "deny list drops ~/.aws", file: "deny_missing_aws.yaml", wantErr: "cannot remove built-in deny ~/.aws"},
		{
			name: "deny spellings normalise",
			file: "deny_spellings.yaml",
			check: func(t *testing.T, m Manifest) {
				if len(m.Filesystem.Deny) != len(BuiltinDeny)+1 {
					t.Errorf("Deny = %q", m.Filesystem.Deny)
				}
			},
		},
		{
			name: "omitted fields stay nil",
			file: "exec_any.yaml",
			check: func(t *testing.T, m Manifest) {
				if m.Scripts != nil || m.Env != nil || m.Filesystem.Write != nil || m.Filesystem.Read != nil || m.Filesystem.Deny != nil {
					t.Errorf("omitted fields should be nil: %+v", m)
				}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, err := Parse(fixture(tc.file))
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("Parse(%s) = nil error, want %q", tc.file, tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Parse(%s) error = %q, want substring %q", tc.file, err, tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.file) {
					t.Errorf("error %q does not name the file", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse(%s) error: %v", tc.file, err)
			}
			if tc.check != nil {
				tc.check(t, m)
			}
		})
	}
}

func TestParseMissingFile(t *testing.T) {
	_, err := Parse(filepath.Join(t.TempDir(), "PERMISSIONS.yaml"))
	if err == nil {
		t.Fatal("Parse of a missing file returned nil error")
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing-file error does not wrap fs.ErrNotExist: %v", err)
	}
}

// TestParseErrorDisplaysPath: the skill directory's name comes from whoever
// ships the skill and the path prefixes Parse's errors, so it is shown
// through DisplayPath: a directory named like the hook's own clause cannot
// imitate it, and a read error does not repeat the raw path.
func TestParseErrorDisplaysPath(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "s | requested but not granted: network: all")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "PERMISSIONS.yaml")
	if err := os.WriteFile(p, []byte("version: 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Parse(p)
	if err == nil || strings.Contains(err.Error(), "|") || !strings.HasPrefix(err.Error(), DisplayPath(p)+": ") ||
		!strings.Contains(err.Error(), `PERMISSIONS.yaml": `) {
		t.Fatalf("parse error = %v", err)
	}
	os.Remove(p)
	if err := os.Mkdir(p, 0o755); err != nil { // ReadFile fails with a *fs.PathError
		t.Fatal(err)
	}
	if _, err := Parse(p); err == nil || strings.Contains(err.Error(), "|") || !strings.HasPrefix(err.Error(), DisplayPath(p)+": ") {
		t.Fatalf("read error = %v", err)
	}
}

func TestParseBytesForms(t *testing.T) {
	tests := []struct {
		name    string
		src     string
		wantErr string
		check   func(t *testing.T, m Manifest)
	}{
		{name: "empty document", src: "", wantErr: "version: required"},
		{name: "missing version", src: "scripts: [\"scripts/**\"]\n", wantErr: "version: required"},
		{name: "top-level list", src: "- a\n", wantErr: "invalid manifest"},
		{name: "duplicate key", src: "version: 1\nnetwork: all\nnetwork: none\n", wantErr: "already defined"},
		{name: "network enum", src: "version: 1\nnetwork: internet\n", wantErr: "network: must be one of none, localhost, all"},
		{name: "network number", src: "version: 1\nnetwork: 5\n", wantErr: "network: must be one of none, localhost, all"},
		{
			name: "network quoted",
			src:  "version: 1\nnetwork: \"localhost\"\n",
			check: func(t *testing.T, m Manifest) {
				if m.Network != NetLocalhost {
					t.Errorf("Network = %s", m.Network)
				}
			},
		},
		{
			name: "network empty means none",
			src:  "version: 1\nnetwork:\n",
			check: func(t *testing.T, m Manifest) {
				if m.Network != NetNone {
					t.Errorf("Network = %s", m.Network)
				}
			},
		},
		{
			name: "exec quoted any",
			src:  "version: 1\nexec: \"any\"\n",
			check: func(t *testing.T, m Manifest) {
				if !m.ExecAny {
					t.Error("ExecAny = false")
				}
			},
		},
		{
			name: "exec flow list",
			src:  "version: 1\nexec: [\"/usr/bin/python3\", \"/usr/bin/qpdf\"]\n",
			check: func(t *testing.T, m Manifest) {
				if m.ExecAny || !reflect.DeepEqual(m.Exec, []string{"/usr/bin/python3", "/usr/bin/qpdf"}) {
					t.Errorf("ExecAny=%v Exec=%q", m.ExecAny, m.Exec)
				}
			},
		},
		{
			name: "exec empty list allows nothing",
			src:  "version: 1\nexec: []\n",
			check: func(t *testing.T, m Manifest) {
				if m.ExecAny || m.Exec == nil || len(m.Exec) != 0 {
					t.Errorf("ExecAny=%v Exec=%#v, want empty non-nil list", m.ExecAny, m.Exec)
				}
			},
		},
		{name: "exec other scalar", src: "version: 1\nexec: sometimes\n", wantErr: `exec: must be any or a list of absolute paths`},
		{name: "exec number", src: "version: 1\nexec: 5\n", wantErr: `exec: must be any or a list`},
		{name: "exec mapping", src: "version: 1\nexec: {a: b}\n", wantErr: `exec: must be any or a list`},
		{name: "exec relative path", src: "version: 1\nexec: [python3]\n", wantErr: `exec[0]: must be an absolute path`},
		{name: "scripts not a list", src: "version: 1\nscripts: scripts/**\n", wantErr: "invalid manifest"},
		{name: "scripts absolute", src: "version: 1\nscripts: [\"/scripts/**\"]\n", wantErr: "must be relative"},
		{name: "scripts bad glob", src: "version: 1\nscripts: [\"scripts/[\"]\n", wantErr: "invalid glob"},
		{name: "env not a list", src: "version: 1\nenv: PATH\n", wantErr: "invalid manifest"},
		{name: "read under ~/.ssh", src: "version: 1\nfilesystem:\n  read: [\"~/.ssh/known_hosts\"]\n", wantErr: "is a built-in deny path (~/.ssh)"},
		{name: "read ${HOME}/.aws", src: "version: 1\nfilesystem:\n  read: [\"${HOME}/.aws\"]\n", wantErr: "is a built-in deny path (~/.aws)"},
		{name: "read ~ is a parent of a deny", src: "version: 1\nfilesystem:\n  read: [\"~\"]\n", wantErr: `filesystem.read[0]: contains built-in deny path ~/.ssh`},
		{name: "write / is a parent of a deny", src: "version: 1\nfilesystem:\n  write: [\"/\"]\n", wantErr: `filesystem.write[0]: contains built-in deny path`},
		{name: "write ~/.claude", src: "version: 1\nfilesystem:\n  write: [\"~/.claude/\"]\n", wantErr: "is a built-in deny path (~/.claude)"},
		{name: "write .env matches pattern", src: "version: 1\nfilesystem:\n  write: [\"${CWD}/.env\"]\n", wantErr: "matches built-in deny pattern **/.env"},
		{name: "write glob rejected", src: "version: 1\nfilesystem:\n  write: [\"${CWD}/**\"]\n", wantErr: "globs are not supported here"},
		{name: "dotdot rejected", src: "version: 1\nfilesystem:\n  write: [\"${CWD}/../x\"]\n", wantErr: "'..' segments are not allowed"},
		{name: "unknown variable", src: "version: 1\nfilesystem:\n  write: [\"${FOO}/x\"]\n", wantErr: "unknown variable"},
		{name: "variable mid-path", src: "version: 1\nfilesystem:\n  write: [\"/tmp/${CWD}\"]\n", wantErr: "variables are only allowed at the start"},
		{name: "relative path", src: "version: 1\nfilesystem:\n  write: [\"out\"]\n", wantErr: "must be absolute or start with ~ or a variable"},
		{name: "tilde user", src: "version: 1\nfilesystem:\n  read: [\"~bob/x\"]\n", wantErr: "~ must be followed by /"},
		{name: "deny empty list removes everything", src: "version: 1\nfilesystem:\n  deny: []\n", wantErr: "cannot remove built-in deny ~/.ssh, ~/.aws"},
		{
			name: "deny extra pattern accepted",
			src:  "version: 1\nfilesystem:\n  deny: [\"~/.ssh\", \"~/.aws\", \"~/.gnupg\", \"~/.claude\", \"~/.config/gcloud\", \"~/.netrc\", \"~/.docker/config.json\", \"**/.env\", \"**/*.pem\"]\n",
			check: func(t *testing.T, m Manifest) {
				if len(m.Filesystem.Deny) != 9 {
					t.Errorf("Deny = %q", m.Filesystem.Deny)
				}
			},
		},
		{
			name: "prose-only manifest",
			src:  "version: 1\ntools: [Read, Bash]\nnotes: fixture\n",
			check: func(t *testing.T, m Manifest) {
				if !m.ExecAny || m.Network != NetNone || len(m.Tools) != 2 {
					t.Errorf("unexpected: %+v", m)
				}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, err := ParseBytes([]byte(tc.src))
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("ParseBytes = nil error, want %q", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %q, want substring %q", err, tc.wantErr)
				}
				if strings.Contains(err.Error(), "\n") {
					t.Errorf("error spans lines: %q", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseBytes error: %v", err)
			}
			if tc.check != nil {
				tc.check(t, m)
			}
		})
	}
}

func TestValidateHandBuilt(t *testing.T) {
	var m Manifest
	if err := Validate(m); err == nil || !strings.Contains(err.Error(), "version: must be 1") {
		t.Errorf("zero Manifest: err = %v", err)
	}
	m = Manifest{Version: 1, ExecAny: true, Exec: []string{"/usr/bin/python3"}}
	if err := Validate(m); err == nil || !strings.Contains(err.Error(), "cannot be both") {
		t.Errorf("any+list: err = %v", err)
	}
	m = Manifest{Version: 1, ExecAny: true, Network: Network(7)}
	if err := Validate(m); err == nil || !strings.Contains(err.Error(), "network: must be one of") {
		t.Errorf("bad network: err = %v", err)
	}
	m = Manifest{Version: 1, ExecAny: true}
	if err := Validate(m); err != nil {
		t.Errorf("minimal manifest: err = %v", err)
	}
}

func TestNetworkString(t *testing.T) {
	for n, want := range map[Network]string{NetNone: "none", NetLocalhost: "localhost", NetAll: "all"} {
		if got := n.String(); got != want {
			t.Errorf("%d.String() = %q, want %q", int(n), got, want)
		}
		back, err := ParseNetwork(want)
		if err != nil || back != n {
			t.Errorf("ParseNetwork(%q) = %v, %v", want, back, err)
		}
	}
	if _, err := ParseNetwork("wifi"); err == nil {
		t.Error("ParseNetwork(wifi) = nil error")
	}
}
