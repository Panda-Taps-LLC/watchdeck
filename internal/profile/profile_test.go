package profile

import (
	"bytes"
	"context"
	"flag"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/manifest"
)

var update = flag.Bool("update", false, "rewrite the golden files under testdata/")

// Fixed fake paths for the goldens. Nothing here exists on disk.
const (
	fakeHome = "/Users/test"
	fakeCWD  = "/Users/test/proj"
	fakeTmp  = "/private/var/folders/xx/T"
)

var fakeDeny = []string{
	fakeHome + "/.ssh",
	fakeHome + "/.aws",
	fakeHome + "/.gnupg",
	fakeHome + "/.claude",
	fakeHome + "/.config/gcloud",
	fakeHome + "/.netrc",
	fakeHome + "/.docker/config.json",
}

func base() Resolved {
	return Resolved{
		SkillDirs:    []string{fakeCWD + "/.claude/skills/pdf"},
		CWD:          fakeCWD,
		Tmp:          fakeTmp,
		DenyPaths:    fakeDeny,
		DenyPatterns: []string{"**/.env"},
		ExecAny:      true,
		Network:      manifest.NetNone,
		Home:         fakeHome,
	}
}

var goldens = map[string]func() Resolved{
	"default": base,
	"deny-all-writes": func() Resolved {
		r := base()
		r.DenyAllWrites = true
		return r
	},
	"localhost": func() Resolved {
		r := base()
		r.Network = manifest.NetLocalhost
		return r
	},
	"network-all": func() Resolved {
		r := base()
		r.Network = manifest.NetAll
		return r
	},
	"exec-allowlist": func() Resolved {
		r := base()
		r.ExecAny = false
		r.ExecAllow = []string{
			"/usr/bin/python3",
			"/bin/bash",
			"/Applications/Xcode.app/Contents/Developer/usr/bin/python3",
			"/bin/ls",
		}
		return r
	},
	"skill-under-dotclaude": func() Resolved {
		r := base()
		r.SkillDirs = []string{fakeHome + "/.claude/skills/pdf"}
		return r
	},
	"deny-regex": func() Resolved {
		r := base()
		r.DenyPatterns = []string{
			"**/id_rsa*",
			"**/.env",
			"**/*.pem",
			"/Users/test/secrets/**",
			"/Users/test/proj/**/credentials.json",
			"**/.aws/**",
			"/etc/master.passwd",
			"**/.env", // duplicate, must collapse
		}
		return r
	},
	"two-skills": func() Resolved {
		r := base()
		r.SkillDirs = []string{
			fakeHome + "/.claude/skills/zeta",
			fakeCWD + "/.claude/skills/alpha",
		}
		r.Write = []string{
			fakeHome + "/Library/Caches/pip",
			fakeHome + "/.cache/uv",
			fakeHome + "/Library/Caches/pip", // duplicate
			fakeCWD,                          // already allowed as CWD
			fakeHome + "/.npm/_cacache/",     // trailing slash is cleaned
		}
		r.DenyAllWrites = true
		return r
	},
}

func TestGoldens(t *testing.T) {
	for name, mk := range goldens {
		t.Run(name, func(t *testing.T) {
			got, err := Compile(mk())
			if err != nil {
				t.Fatalf("Compile: %v", err)
			}
			file := filepath.Join("testdata", name+".sb")
			if *update {
				if err := os.WriteFile(file, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(file)
			if err != nil {
				t.Fatalf("%v (run with -update to create it)", err)
			}
			if string(want) != got {
				t.Errorf("profile differs from %s\n--- want\n%s--- got\n%s", file, want, got)
			}
		})
	}
}

func TestDeterministic(t *testing.T) {
	a := goldens["two-skills"]()
	b := goldens["two-skills"]()
	// Reverse every list in b; the output must not change.
	for _, l := range [][]string{b.SkillDirs, b.Write, b.DenyPaths, b.DenyPatterns} {
		for i, j := 0, len(l)-1; i < j; i, j = i+1, j-1 {
			l[i], l[j] = l[j], l[i]
		}
	}
	pa, err := Compile(a)
	if err != nil {
		t.Fatal(err)
	}
	pb, err := Compile(b)
	if err != nil {
		t.Fatal(err)
	}
	if pa != pb {
		t.Errorf("output depends on input order:\n%s\nvs\n%s", pa, pb)
	}
	if Hash(pa) != Hash(pb) {
		t.Errorf("hash differs for identical profiles")
	}
}

func TestRuleOrder(t *testing.T) {
	r := goldens["exec-allowlist"]()
	r.DenyAllWrites = true
	r.Network = manifest.NetLocalhost
	r.CWD = fakeHome // writable ancestors of the deny paths
	p, err := Compile(r)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"(version 1)",
		"(allow default)",
		"(deny network*)",
		"(allow network-bind",
		"(allow network-inbound",
		"(allow network-outbound",
		"(deny file-write*)",
		"(allow file-write* (subpath",
		`(allow file-write* (literal "/dev/null")`,
		"(deny file-read* (subpath",
		"(deny file-read* (regex",
		"(allow file-read* (subpath",
		"(deny file-write* (subpath",
		`(deny file-write-unlink (literal "/Users/test") (literal "/Users/test/.config") (literal "/Users/test/.docker"))`,
		"(deny file-write* (regex",
		"(deny process-exec*)",
		"(allow process-exec (literal",
	}
	lines := strings.Split(strings.TrimRight(p, "\n"), "\n")
	if len(lines) != len(want) {
		t.Fatalf("got %d lines, want %d:\n%s", len(lines), len(want), p)
	}
	for i, prefix := range want {
		if !strings.HasPrefix(lines[i], prefix) {
			t.Errorf("line %d: want prefix %q, got %q", i+1, prefix, lines[i])
		}
	}
}

func TestEscaping(t *testing.T) {
	r := base()
	r.Write = []string{`/Users/test/odd"q`, `/Users/test/odd\b`}
	p, err := Compile(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`(subpath "/Users/test/odd\"q")`, `(subpath "/Users/test/odd\\b")`} {
		if !strings.Contains(p, want) {
			t.Errorf("missing %s in:\n%s", want, p)
		}
	}
}

func TestGlobToRegex(t *testing.T) {
	ok := map[string]string{
		"**/.env":                       `(^|/)\.env$`,
		"**/*.pem":                      `(^|/)[^/]*\.pem$`,
		"**/id_rsa*":                    `(^|/)id_rsa[^/]*$`,
		"**/foo/**":                     `(^|/)foo(/|$)`,
		"**/a/**/b":                     `(^|/)a/(.*/)?b$`,
		"/abs/dir/**":                   `^/abs/dir(/|$)`,
		"/abs/**/key":                   `^/abs/(.*/)?key$`,
		"/**/x":                         `^/(.*/)?x$`,
		"/etc/master.passwd":            `^/etc/master\.passwd$`,
		"**/file?.txt":                  `(^|/)file[^/]\.txt$`,
		"/Users/test/a+b (c)/**":        `^/Users/test/a\+b \(c\)(/|$)`,
		"**/.aws/credentials":           `(^|/)\.aws/credentials$`,
		"/Users/test/.config/gcloud/**": `^/Users/test/\.config/gcloud(/|$)`,
	}
	for g, want := range ok {
		got, err := globToRegex(g)
		if err != nil {
			t.Errorf("%q: unexpected error %v", g, err)
			continue
		}
		if got != want {
			t.Errorf("%q: got %q, want %q", g, got, want)
		}
	}
	// Behavioural check of the produced regexes against sample paths, using
	// Go's engine as a stand-in for ERE (the constructs are common to both;
	// the live Seatbelt check is in spikes/seatbelt/README.md and TestRealSandbox).
	matches := []struct {
		glob, path string
		want       bool
	}{
		{"**/.env", "/p/.env", true},
		{"**/.env", "/.env", true},
		{"**/.env", "/p/env.txt", false},
		{"**/.env", "/p/.env.example", false},
		{"**/.env", "/p/.envy/x", false},
		{"**/*.pem", "/p/a/cert.pem", true},
		{"**/*.pem", "/p/a/cert.pem/x", false},
		{"/abs/dir/**", "/abs/dir", true},
		{"/abs/dir/**", "/abs/dir/a/b", true},
		{"/abs/dir/**", "/abs/dirx", false},
		{"/abs/**/key", "/abs/key", true},
		{"/abs/**/key", "/abs/a/b/key", true},
		{"/abs/**/key", "/abs/a/b/keys", false},
		{"**/foo/**", "/x/foo", true},
		{"**/foo/**", "/x/foo/y", true},
		{"**/foo/**", "/x/foobar", false},
	}
	for _, m := range matches {
		re, err := globToRegex(m.glob)
		if err != nil {
			t.Fatal(err)
		}
		if got := regexp.MustCompile(re).MatchString(m.path); got != m.want {
			t.Errorf("%q as %q against %q: got %v, want %v", m.glob, re, m.path, got, m.want)
		}
	}
	bad := []string{
		"", "**", "/**", "**/**", "*.pem", "relative/.env", "**/a//b", "**/a/",
		"**/{a,b}", "**/[ab]", `**/a\b`, "**/a**b", "**/a\"b", "**/a\nb", "**/**/x",
	}
	for _, g := range bad {
		if re, err := globToRegex(g); err == nil {
			t.Errorf("%q: expected an error, got %q", g, re)
		}
	}
}

func TestCompileErrors(t *testing.T) {
	cases := map[string]func(r *Resolved){
		"newline in cwd":            func(r *Resolved) { r.CWD = "/Users/test/a\nb" },
		"relative skill dir":        func(r *Resolved) { r.SkillDirs = []string{"skills/pdf"} },
		"empty tmp":                 func(r *Resolved) { r.Tmp = "" },
		"root as write":             func(r *Resolved) { r.Write = []string{"/"} },
		"root as cwd":               func(r *Resolved) { r.CWD = "/" },
		"missing home (deny-home)":  func(r *Resolved) { r.Home = "" },
		"cwd is ancestor of home":   func(r *Resolved) { r.CWD = "/Users" },
		"write is ancestor of home": func(r *Resolved) { r.Write = []string{"/Users"} },
		"skill dir covers deny":     func(r *Resolved) { r.SkillDirs = []string{fakeHome + "/.claude"} },
		"skill dir equals deny":     func(r *Resolved) { r.SkillDirs = []string{fakeHome + "/.ssh"} },
		"bad glob":                  func(r *Resolved) { r.DenyPatterns = []string{"**/{a,b}"} },
		"quote in glob":             func(r *Resolved) { r.DenyPatterns = []string{`**/a"b`} },
		"exec allow-list empty":     func(r *Resolved) { r.ExecAny = false; r.ExecAllow = nil },
		"unknown network":           func(r *Resolved) { r.Network = manifest.Network(42) },
	}
	for name, mutate := range cases {
		r := base()
		mutate(&r)
		if p, err := Compile(r); err == nil {
			t.Errorf("%s: expected an error, got profile:\n%s", name, p)
		}
	}
	// Allowed: cwd equal to home (running from ~), the sensitive re-denies
	// still protect ~/.ssh and friends; and no Home at all under deny-all.
	r := base()
	r.CWD = fakeHome
	if _, err := Compile(r); err != nil {
		t.Errorf("cwd == home should compile: %v", err)
	}
	r = base()
	r.Home = ""
	r.DenyAllWrites = true
	if _, err := Compile(r); err != nil {
		t.Errorf("deny-all without Home should compile: %v", err)
	}
}

func TestHash(t *testing.T) {
	p, err := Compile(base())
	if err != nil {
		t.Fatal(err)
	}
	h := Hash(p)
	if !regexp.MustCompile(`^[0-9a-f]{8}$`).MatchString(h) {
		t.Errorf("Hash = %q, want 8 lowercase hex chars", h)
	}
	if h != Hash(p) {
		t.Error("Hash is not stable")
	}
	if Hash(p+" ") == h {
		t.Error("Hash does not change with content")
	}
}

// probe is run by /usr/bin/python3 inside the sandbox. Every path comes from
// the environment; it prints "<label> <result>" per line.
const probe = `
import errno, os, socket, subprocess
H = os.environ["SP_HOME"]; C = os.environ["SP_CWD"]; S = os.environ["SP_SKILL"]
E = os.environ["SP_ELSEWHERE"]; PORT = int(os.environ.get("SP_PORT", "0"))
def t(label, fn):
    try:
        fn(); print(label, "ALLOWED")
    except socket.timeout:
        print(label, "TIMEOUT")
    except OSError as e:
        print(label, "DENIED(%s)" % errno.errorcode.get(e.errno, e.errno))
def w(p): open(p, "w").write("x")
def r(p): open(p).read()
def net(host, port):
    s = socket.socket(); s.settimeout(2)
    try: s.connect((host, port))
    finally: s.close()
t("write-cwd", lambda: w(os.path.join(C, "out.txt")))
t("write-tmp", lambda: w(os.path.join(os.environ["TMPDIR"], "out.txt")))
t("write-home", lambda: w(os.path.join(H, "out.txt")))
t("write-skill", lambda: w(os.path.join(S, "out.txt")))
t("write-elsewhere", lambda: w(os.path.join(E, "out.txt")))
t("read-ssh", lambda: r(os.path.join(H, ".ssh", "id_fake")))
t("read-settings", lambda: r(os.path.join(H, ".claude", "settings.json")))
t("read-skill", lambda: r(os.path.join(S, "scripts", "x.py")))
t("read-dotenv", lambda: r(os.path.join(C, ".env")))
t("read-notes", lambda: r(os.path.join(C, "notes.txt")))
t("spawn-ls", lambda: subprocess.run(["/bin/ls", C], check=True, stdout=subprocess.DEVNULL))
t("net-remote", lambda: net("192.0.2.1", 80))
if PORT:
    t("net-local", lambda: net("127.0.0.1", PORT))
`

// TestRealSandbox compiles profiles for a throwaway layout and runs the probe
// under /usr/bin/sandbox-exec. It never touches the developer's home: HOME
// for the child is a directory under t.TempDir() holding a fake key file.
func TestRealSandbox(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS only")
	}
	for _, bin := range []string{"/usr/bin/sandbox-exec", "/usr/bin/python3"} {
		if _, err := os.Stat(bin); err != nil {
			t.Skipf("%s not present", bin)
		}
	}
	// A process that is already sandboxed (Claude Code's Bash sandbox, a
	// watchdeck profile) may only re-apply the identical profile; anything
	// else is refused with exit 71 (Spike 2 (c)). Preflight with a profile no
	// outer sandbox would be identical to, and skip narrowly on that string;
	// anything else is a real failure.
	pre := exec.Command("/usr/bin/sandbox-exec", "-p",
		`(version 1)(allow default)(deny network*)(deny file-read* (literal "/nonexistent/watchdeck-preflight"))`, "/usr/bin/true")
	var preErr bytes.Buffer
	pre.Stderr = &preErr
	if err := pre.Run(); err != nil && strings.Contains(preErr.String(), "sandbox_apply") {
		t.Skipf("nested sandbox refused (%s); run outside Claude Code's Bash sandbox", strings.TrimSpace(preErr.String()))
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, "home")
	cwd := filepath.Join(root, "cwd")
	// A dedicated tmp: the real TMPDIR contains this whole layout, so
	// allowing it would re-allow the fake home (see the spike README).
	tmp := filepath.Join(root, "tmp")
	elsewhere := filepath.Join(root, "elsewhere")
	skill := filepath.Join(home, ".claude", "skills", "demo")
	for _, d := range []string{filepath.Join(home, ".ssh"), filepath.Join(skill, "scripts"), cwd, tmp, elsewhere} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]string{
		filepath.Join(home, ".ssh", "id_fake"):          "FAKE-KEY-NOT-REAL\n",
		filepath.Join(home, ".claude", "settings.json"): `{"fake":true}`,
		filepath.Join(skill, "scripts", "x.py"):         `print("x")`,
		filepath.Join(cwd, ".env"):                      "SECRET=fake\n",
		filepath.Join(cwd, "notes.txt"):                 "notes\n",
	}
	for p, c := range files {
		if err := os.WriteFile(p, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// Listener for the localhost case.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	resolved := func() Resolved {
		return Resolved{
			SkillDirs:    []string{skill},
			CWD:          cwd,
			Tmp:          tmp,
			DenyPaths:    []string{filepath.Join(home, ".ssh"), filepath.Join(home, ".claude")},
			DenyPatterns: []string{"**/.env"},
			ExecAny:      true,
			Network:      manifest.NetNone,
			Home:         home,
		}
	}
	common := map[string]string{
		"write-cwd":     "ALLOWED",
		"write-tmp":     "ALLOWED",
		"write-home":    "DENIED(EPERM)",
		"write-skill":   "DENIED(EPERM)",
		"read-ssh":      "DENIED(EPERM)",
		"read-settings": "DENIED(EPERM)",
		"read-skill":    "ALLOWED",
		"read-dotenv":   "DENIED(EPERM)",
		"read-notes":    "ALLOWED",
		"spawn-ls":      "ALLOWED",
		"net-remote":    "DENIED(EPERM)",
	}
	cases := []struct {
		name   string
		mutate func(*Resolved)
		port   int
		extra  map[string]string
	}{
		{"deny-all-writes", func(r *Resolved) { r.DenyAllWrites = true }, 0,
			map[string]string{"write-elsewhere": "DENIED(EPERM)"}},
		{"deny-home", func(*Resolved) {}, 0,
			map[string]string{"write-elsewhere": "ALLOWED"}},
		{"localhost", func(r *Resolved) { r.DenyAllWrites = true; r.Network = manifest.NetLocalhost }, port,
			map[string]string{"write-elsewhere": "DENIED(EPERM)", "net-local": "ALLOWED"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := resolved()
			tc.mutate(&r)
			prof, err := Compile(r)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("profile %s:\n%s", Hash(prof), prof)
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "/usr/bin/sandbox-exec", "-p", prof, "/usr/bin/python3", "-c", probe)
			cmd.Dir = cwd
			cmd.Env = []string{
				"HOME=" + home, "TMPDIR=" + tmp, "PATH=/usr/bin:/bin",
				"SP_HOME=" + home, "SP_CWD=" + cwd, "SP_SKILL=" + skill, "SP_ELSEWHERE=" + elsewhere,
			}
			if tc.port != 0 {
				cmd.Env = append(cmd.Env, "SP_PORT="+strconv.Itoa(tc.port))
			}
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			if err := cmd.Run(); err != nil {
				t.Fatalf("sandbox-exec: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
			}
			if stderr.Len() > 0 {
				t.Logf("stderr:\n%s", stderr.String())
			}
			got := map[string]string{}
			for _, line := range strings.Split(strings.TrimSpace(stdout.String()), "\n") {
				if k, v, ok := strings.Cut(line, " "); ok {
					got[k] = v
				}
			}
			want := map[string]string{}
			for k, v := range common {
				want[k] = v
			}
			for k, v := range tc.extra {
				want[k] = v
			}
			for k, v := range want {
				if got[k] != v {
					t.Errorf("%s: got %q, want %q", k, got[k], v)
				}
			}
			if len(got) != len(want) {
				t.Errorf("probe printed %d results, expected %d:\n%s", len(got), len(want), stdout.String())
			}
		})
	}
}

// renameProbe moves a protected file or one of its ancestors out of the way,
// then reads the moved copy. A DENIED line means the move or the read was
// refused.
const renameProbe = `
import errno, os
H = os.environ["SP_HOME"]
P = os.path.join(H, "proj")
def t(label, fn):
    try:
        fn(); print(label, "ALLOWED")
    except OSError as e:
        print(label, "DENIED(%s)" % errno.errorcode.get(e.errno, e.errno))
def mvread(src, dst, rel):
    os.rename(src, dst); open(os.path.join(dst, rel) if rel else dst).read()
def lnread(src, dst):
    os.link(src, dst); open(dst).read()
t("write-notes", lambda: open(os.path.join(P, "notes.txt"), "w").write("x"))
t("read-dotenv", lambda: open(os.path.join(P, ".env")).read())
t("link-dotenv", lambda: lnread(os.path.join(P, ".env"), os.path.join(P, "y")))
t("mv-dotenv", lambda: mvread(os.path.join(P, ".env"), os.path.join(P, "x"), ""))
t("unlink-dotenv", lambda: os.unlink(os.path.join(P, ".env")))
t("write-sibling", lambda: open(os.path.join(H, ".config", "other"), "w").write("x"))
t("mv-proj-a", lambda: mvread(os.path.join(P, "a"), os.path.join(P, "b"), "secrets/k"))
t("mv-proj", lambda: mvread(P, os.path.join(H, "p2"), "a/secrets/k"))
t("mv-config", lambda: mvread(os.path.join(H, ".config"), os.path.join(H, "c"), "gcloud/k"))
t("rmdir-proj-a", lambda: os.rmdir(os.path.join(P, "a")))
`

// requireSandboxExec skips unless /usr/bin/sandbox-exec can apply a fresh
// profile here (see TestRealSandbox for why a nested apply is refused).
func requireSandboxExec(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "darwin" {
		t.Skip("macOS only")
	}
	for _, bin := range []string{"/usr/bin/sandbox-exec", "/usr/bin/python3"} {
		if _, err := os.Stat(bin); err != nil {
			t.Skipf("%s not present", bin)
		}
	}
	pre := exec.Command("/usr/bin/sandbox-exec", "-p",
		`(version 1)(allow default)(deny network*)(deny file-read* (literal "/nonexistent/watchdeck-preflight"))`, "/usr/bin/true")
	var preErr bytes.Buffer
	pre.Stderr = &preErr
	if err := pre.Run(); err != nil && strings.Contains(preErr.String(), "sandbox_apply") {
		t.Skipf("nested sandbox refused (%s); run outside Claude Code's Bash sandbox", strings.TrimSpace(preErr.String()))
	}
}

// TestRealSandboxRename runs from the home dir (cwd = Home, so every
// ancestor of a protected path is writable) and tries to read protected
// files by renaming them, or one of their ancestors, first. Review
// 2026-10-14: deny patterns blocked reads only, and a literal deny covered
// the path and its contents but not its parents.
func TestRealSandboxRename(t *testing.T) {
	requireSandboxExec(t)
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, "home")
	proj := filepath.Join(home, "proj")
	tmp := filepath.Join(root, "tmp")
	for _, d := range []string{filepath.Join(home, ".config", "gcloud"), filepath.Join(proj, "a", "secrets"), tmp} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range []string{
		filepath.Join(home, ".config", "gcloud", "k"),
		filepath.Join(proj, "a", "secrets", "k"),
		filepath.Join(proj, ".env"),
	} {
		if err := os.WriteFile(p, []byte("FAKE-NOT-REAL\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	prof, err := Compile(Resolved{
		CWD:          home,
		Tmp:          tmp,
		DenyPaths:    []string{filepath.Join(home, ".config", "gcloud"), filepath.Join(proj, "a", "secrets")},
		DenyPatterns: []string{"**/.env"},
		ExecAny:      true,
		Network:      manifest.NetNone,
		Home:         home,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("profile %s:\n%s", Hash(prof), prof)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/sandbox-exec", "-p", prof, "/usr/bin/python3", "-c", renameProbe)
	cmd.Dir = home
	cmd.Env = []string{"HOME=" + home, "TMPDIR=" + tmp, "PATH=/usr/bin:/bin", "SP_HOME=" + home}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("sandbox-exec: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
	}
	got := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(stdout.String()), "\n") {
		if k, v, ok := strings.Cut(line, " "); ok {
			got[k] = v
		}
	}
	want := map[string]string{
		"write-notes":   "ALLOWED",
		"read-dotenv":   "DENIED(EPERM)",
		"link-dotenv":   "DENIED(EPERM)",
		"unlink-dotenv": "DENIED(EPERM)",
		"mv-dotenv":     "DENIED(EPERM)",
		"write-sibling": "ALLOWED",
		"mv-proj-a":     "DENIED(EPERM)",
		"mv-proj":       "DENIED(EPERM)",
		"mv-config":     "DENIED(EPERM)",
		"rmdir-proj-a":  "DENIED(EPERM)",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: got %q, want %q", k, got[k], v)
		}
	}
	if len(got) != len(want) {
		t.Errorf("probe printed %d results, expected %d:\n%s", len(got), len(want), stdout.String())
	}
}
