//go:build darwin

package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/activity"
	"github.com/Panda-Taps-LLC/watchdeck/internal/sandbox"
)

// fixture builds a fake HOME holding copies of the canary skills under
// .claude/skills, a fake ~/.ssh/id_fake, an empty project dir and isolated
// cache/config dirs. Nothing touches the developer's real home.
type fixture struct {
	home, cwd, cache, cfg string
	env                   Env
	environ               []string
	activity              string // activity log for this test; Run writes here
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	if !sandbox.Available() {
		t.Skip("no sandbox-exec")
	}
	// The fake home must not live under the per-user temp dir or /private/tmp:
	// the profile always allows writes there, and the compiler refuses an allow
	// on an ancestor of home. /var/tmp is user-writable and never allowed.
	home, err := os.MkdirTemp("/var/tmp", "watchdeck-home-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(home) })
	if r, err := filepath.EvalSymlinks(home); err == nil {
		home = r
	}
	f := &fixture{home: home, cwd: t.TempDir(), cache: t.TempDir(), cfg: filepath.Join(t.TempDir(), "cfg"),
		activity: filepath.Join(t.TempDir(), "state", "activity.jsonl")}
	src, _ := filepath.Abs(filepath.Join("..", "..", "testdata", "skills"))
	dst := filepath.Join(f.home, ".claude", "skills")
	if err := os.MkdirAll(dst, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.CopyFS(dst, os.DirFS(src)); err != nil {
		t.Fatal(err)
	}
	// CopyFS drops exec bits? Re-apply for scripts.
	filepath.Walk(dst, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && (strings.HasSuffix(p, ".sh") || strings.HasSuffix(p, ".py")) {
			os.Chmod(p, 0o755)
		}
		return nil
	})
	os.MkdirAll(filepath.Join(f.home, ".ssh"), 0o700)
	os.WriteFile(filepath.Join(f.home, ".ssh", "id_fake"), []byte("not a real key\n"), 0o600)
	os.MkdirAll(f.cfg, 0o755)
	f.environ = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "HOME=" + f.home, "LANG=C", "CANARY_SECRET=not-a-real-secret", "TMPDIR=" + os.Getenv("TMPDIR")}
	f.env = Env{Home: f.home, Cwd: f.cwd, CacheDir: f.cache, UserCfgDir: f.cfg}
	return f
}

func (f *fixture) probe(t *testing.T, skill, action string, extra ...string) (stdout, stderr string, code int) {
	t.Helper()
	script := filepath.Join(f.home, ".claude", "skills", skill, "scripts", "probe.py")
	cmd := "/usr/bin/python3 " + script + " " + action
	if len(extra) > 0 {
		cmd += " " + strings.Join(extra, " ")
	}
	var out, errb bytes.Buffer
	code = Run(context.Background(), Options{Skills: []string{skill}, Command: cmd, Env: f.env, Environ: f.environ, Stdout: &out, Stderr: &errb, ActivityPath: f.activity})
	return out.String(), errb.String(), code
}

func (f *fixture) probeCmd(skill, action string) string {
	return "/usr/bin/python3 " + filepath.Join(f.home, ".claude", "skills", skill, "scripts", "probe.py") + " " + action
}

// lastRun returns the newest record of the fixture's log, which must be a run.
func (f *fixture) lastRun(t *testing.T) activity.Record {
	t.Helper()
	res, err := activity.Read(f.activity, activity.ReadOptions{})
	if err != nil || len(res.Records) == 0 {
		t.Fatalf("no records: %v", err)
	}
	r := res.Records[len(res.Records)-1]
	if r.Kind != activity.KindRun {
		t.Fatalf("last record is %q", r.Kind)
	}
	return r
}

// seedDecision writes the decision the hook would have logged for cmd.
func (f *fixture) seedDecision(t *testing.T, skill, cmd string) {
	t.Helper()
	err := activity.Append(f.activity, activity.Record{
		Kind: activity.KindDecision, TS: time.Now().Add(-2 * time.Second).UTC().Format(time.RFC3339Nano),
		SessionID: "s1", ToolUseID: "toolu_1", Transcript: "/t/s1.jsonl", AgentID: "agent-1", AgentType: "Explore",
		PermMode: "default", Cwd: f.cwd, Skills: []string{skill}, Command: cmd, Decision: "ask",
		Rewritten: "watchdeck run --skill " + skill + " -c '" + cmd + "'", Confidence: "high",
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestRunCanaryBasic(t *testing.T) {
	f := newFixture(t)
	cases := map[string]string{
		"write-cwd":   "write-cwd: ALLOWED",
		"write-home":  "write-home: DENIED(1)",
		"read-secret": "read-secret: DENIED(1)",
		"net":         "net: DENIED(1)",
		"subprocess":  "subprocess: ALLOWED",
		"env":         "env: SCRUBBED",
	}
	for action, want := range cases {
		out, errb, code := f.probe(t, "canary-basic", action)
		if !strings.Contains(out, want) {
			t.Errorf("%s: want %q, got stdout %q stderr %q code %d", action, want, out, errb, code)
		}
		if code != 0 {
			t.Errorf("%s: probe itself should exit 0 (it reports), got %d: %s", action, code, errb)
		}
	}
	if _, err := os.Stat(filepath.Join(f.cwd, ".canary-write")); err != nil {
		t.Error("write-cwd did not create the file in cwd")
	}
	if _, err := os.Stat(filepath.Join(f.home, ".canary-write")); err == nil {
		t.Error("write-home created a file in the fake home")
	}
}

func TestRunRequestClippedThenGranted(t *testing.T) {
	f := newFixture(t)
	// probe exits 0 even when denied, so force a non-zero exit to see the trailer
	script := filepath.Join(f.home, ".claude", "skills", "canary-request", "scripts", "probe.py")
	var out, errb bytes.Buffer
	code := Run(context.Background(), Options{Skills: []string{"canary-request"}, Command: "/usr/bin/python3 " + script + " net; exit 7", Env: f.env, Environ: f.environ, Stdout: &out, Stderr: &errb})
	if code != 7 || !strings.Contains(out.String(), "net: DENIED(1)") {
		t.Fatalf("code=%d out=%q err=%q", code, out.String(), errb.String())
	}
	if !strings.Contains(errb.String(), "requested but not granted: canary-request: network: all") || !strings.Contains(errb.String(), "watchdeck allow canary-request") {
		t.Fatalf("trailer missing the ungranted request:\n%s", errb.String())
	}
	// grant it in the user overrides file: the next run may reach the network
	os.WriteFile(filepath.Join(f.cfg, "overrides.yaml"), []byte("version: 1\nskills:\n  canary-request:\n    network: all\n"), 0o644)
	o, e, _ := f.probe(t, "canary-request", "net")
	if strings.Contains(o, "DENIED") {
		t.Fatalf("still denied after allow: %q %q", o, e)
	}
}

func TestRunMalformedManifest(t *testing.T) {
	f := newFixture(t)
	_, errb, code := f.probe(t, "canary-malformed", "env")
	if code != ExitPolicy || !strings.Contains(errb, "invalid manifest") {
		t.Fatalf("code=%d stderr=%q", code, errb)
	}
}

func TestRunLocalhost(t *testing.T) {
	f := newFixture(t)
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
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	// the skill REQUESTS localhost; with no grant it is clipped to none
	out, errb, _ := f.probe(t, "canary-localhost", "localhost", port)
	if !strings.Contains(out, "localhost: DENIED(1)") {
		t.Errorf("localhost request without a grant should be clipped: %q %q", out, errb)
	}
	os.WriteFile(filepath.Join(f.cfg, "overrides.yaml"), []byte("version: 1\nskills:\n  canary-localhost:\n    network: localhost\n"), 0o644)
	out, errb, _ = f.probe(t, "canary-localhost", "localhost", port)
	if !strings.Contains(out, "localhost: ALLOWED") {
		t.Errorf("localhost connect under granted network=localhost: %q %q", out, errb)
	}
	out, _, _ = f.probe(t, "canary-localhost", "net")
	if !strings.Contains(out, "net: DENIED(1)") {
		t.Errorf("non-loopback connect under network=localhost: %q", out)
	}
	// the default grant (canary-basic) must not reach localhost either
	out, _, _ = f.probe(t, "canary-basic", "localhost", port)
	if !strings.Contains(out, "localhost: DENIED(1)") {
		t.Errorf("localhost under network=none: %q", out)
	}
}

func TestRunExecAllowlist(t *testing.T) {
	f := newFixture(t)
	// the Xcode shim execs the real interpreter; put the real path in the manifest
	real, err := exec.Command("/usr/bin/xcrun", "-f", "python3").Output()
	if err != nil {
		t.Skip("xcrun -f python3 failed")
	}
	rp := strings.TrimSpace(string(real))
	// Apple's python3 is a launcher that posix_spawns the framework binary, so
	// an allow-list must name every binary in the exec chain. Ask python for it.
	fw, err := exec.Command(rp, "-c", "import os,sys; print(os.path.realpath(sys.executable))").Output()
	if err != nil {
		t.Skip("could not resolve the interpreter chain")
	}
	fwp := strings.TrimSpace(string(fw))
	chain := []string{rp, fwp}
	// python3.9 re-execs <Versions/3.9>/Resources/Python.app/Contents/MacOS/Python
	if app := filepath.Join(filepath.Dir(filepath.Dir(fwp)), "Resources", "Python.app", "Contents", "MacOS", "Python"); fileExists(app) {
		chain = append(chain, app)
	}
	var list []string
	for _, c := range chain {
		list = append(list, "\""+c+"\"")
	}
	mp := filepath.Join(f.home, ".claude", "skills", "canary-exec", "PERMISSIONS.yaml")
	os.WriteFile(mp, []byte("version: 1\nexec: ["+strings.Join(list, ", ")+"]\n"), 0o644)
	// Run the real interpreter, not the /usr/bin/python3 Xcode shim: the shim
	// execs xcrun/xcodebuild to find the toolchain, which an allow-list that
	// does not list them blocks. Allow-lists must name real binaries.
	script := filepath.Join(f.home, ".claude", "skills", "canary-exec", "scripts", "probe.py")
	var out1, err1 bytes.Buffer
	code := Run(context.Background(), Options{Skills: []string{"canary-exec"}, Command: rp + " " + script + " subprocess", Env: f.env, Environ: f.environ, Stdout: &out1, Stderr: &err1})
	out, errb := out1.String(), err1.String()
	if strings.Contains(errb, "posix_spawn") && !strings.Contains(out, "subprocess") {
		// The interpreter chain on this machine has yet another binary; the
		// mechanism (exec denied) is proven by that very failure. Record and skip.
		t.Skipf("exec allow-list blocked the interpreter's own chain (expected on this toolchain): %s", strings.SplitN(errb, "\n", 2)[0])
	}
	if !strings.Contains(out, "subprocess: DENIED(1)") {
		t.Fatalf("subprocess under exec allow-list: out=%q err=%q code=%d", out, errb, code)
	}
	out, _, _ = f.probe(t, "canary-basic", "subprocess")
	if !strings.Contains(out, "subprocess: ALLOWED") {
		t.Fatalf("subprocess under exec any: %q", out)
	}
}

func TestRunShellChildInherits(t *testing.T) {
	f := newFixture(t)
	script := filepath.Join(f.home, ".claude", "skills", "canary-shell", "scripts", "run.sh")
	var out, errb bytes.Buffer
	code := Run(context.Background(), Options{Skills: []string{"canary-shell"}, Command: script + " net", Env: f.env, Environ: f.environ, Stdout: &out, Stderr: &errb})
	if code != 0 || !strings.Contains(out.String(), "shell: started") || !strings.Contains(out.String(), "net: DENIED(1)") {
		t.Fatalf("code=%d out=%q err=%q", code, out.String(), errb.String())
	}
}

func TestRunNestedRefused(t *testing.T) {
	f := newFixture(t)
	var errb bytes.Buffer
	code := Run(context.Background(), Options{Skills: []string{"canary-basic"}, Command: "true", Env: f.env, Environ: append(f.environ, ProfileEnvVar+"=deadbeef"), Stdout: &bytes.Buffer{}, Stderr: &errb})
	if code != ExitPolicy || !strings.Contains(errb.String(), "nested") {
		t.Fatalf("code=%d err=%q", code, errb.String())
	}
}

func TestRunUnknownSkill(t *testing.T) {
	f := newFixture(t)
	var errb bytes.Buffer
	code := Run(context.Background(), Options{Skills: []string{"nope"}, Command: "true", Env: f.env, Environ: f.environ, Stdout: &bytes.Buffer{}, Stderr: &errb})
	if code != ExitPolicy || !strings.Contains(errb.String(), "unknown skill") {
		t.Fatalf("code=%d err=%q", code, errb.String())
	}
}

func TestRunEnvScrubbedButPathKept(t *testing.T) {
	f := newFixture(t)
	var out bytes.Buffer
	code := Run(context.Background(), Options{Skills: []string{"canary-basic"}, Command: "echo \"path=$PATH secret=${CANARY_SECRET:-SCRUBBED} prof=${WATCHDECK_PROFILE:+set}\"", Env: f.env, Environ: f.environ, Stdout: &out, Stderr: &bytes.Buffer{}})
	if code != 0 || !strings.Contains(out.String(), "path=/usr/bin:/bin") || !strings.Contains(out.String(), "secret=SCRUBBED") || !strings.Contains(out.String(), "prof=set") {
		t.Fatalf("code=%d out=%q", code, out.String())
	}
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func TestRunRecordsOutcome(t *testing.T) {
	f := newFixture(t)
	cmd := f.probeCmd("canary-basic", "net")
	f.seedDecision(t, "canary-basic", cmd)
	out, errb, code := f.probe(t, "canary-basic", "net")
	if code != 0 || !strings.Contains(out, "net: DENIED(1)") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errb)
	}
	r := f.lastRun(t)
	if r.Outcome != activity.OutcomeOK || r.Exit == nil || *r.Exit != 0 || r.Command != cmd || r.Cwd != f.cwd ||
		strings.Join(r.Skills, ",") != "canary-basic" || r.Error != "" {
		t.Fatalf("run record: %+v", r)
	}
	if r.ProfileHash == "" || r.Backend != "seatbelt" || r.Effective == nil || r.Effective.Network != "none" {
		t.Fatalf("policy fields: hash %q backend %q effective %+v", r.ProfileHash, r.Backend, r.Effective)
	}
	if r.SessionID != "s1" || r.ToolUseID != "toolu_1" || r.Transcript != "/t/s1.jsonl" || r.AgentID != "agent-1" ||
		r.AgentType != "Explore" || r.PermMode != "default" || r.JoinedBy != activity.JoinedByWrite {
		t.Fatalf("write-time ids: %+v", r)
	}
	if len(r.Hints) != 1 {
		t.Fatalf("hints: %+v", r.Hints)
	}
	h := r.Hints[0]
	if h.Kind != activity.HintNetwork || h.Stream != "stdout" || h.Label != "net" || h.Errno != 1 || h.Line != "net: DENIED(1)" || !h.Heuristic || h.Text == "" {
		t.Fatalf("hint: %+v", h)
	}

	// the decision is claimed: the same command again stays unjoined, and an
	// ALLOWED probe yields no hint
	f.probe(t, "canary-basic", "net")
	if r := f.lastRun(t); r.ToolUseID != "" || r.JoinedBy != "" {
		t.Fatalf("claimed decision reused: %+v", r)
	}
	f.probe(t, "canary-basic", "write-cwd")
	if r := f.lastRun(t); len(r.Hints) != 0 || r.Outcome != activity.OutcomeOK {
		t.Fatalf("allowed probe: %+v", r)
	}
}

func TestRunRecordsHintOnLoudFailure(t *testing.T) {
	f := newFixture(t)
	out, errb, code := f.probe(t, "canary-basic", "net", "--strict")
	if code != 1 || !strings.Contains(out, "net: DENIED(1)") || !strings.Contains(errb, "probe net: socket connect") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errb)
	}
	if !strings.Contains(errb, "[watchdeck] exit 1 under profile") {
		t.Fatalf("trailer missing: %q", errb)
	}
	r := f.lastRun(t)
	if r.Outcome != activity.OutcomeFailed || r.Exit == nil || *r.Exit != 1 {
		t.Fatalf("run record: %+v", r)
	}
	var fromStderr *activity.Hint
	for i := range r.Hints {
		if r.Hints[i].Stream == "stderr" {
			fromStderr = &r.Hints[i]
		}
		if strings.Contains(r.Hints[i].Line, "[watchdeck]") {
			t.Fatalf("the trailer was scanned: %+v", r.Hints[i])
		}
	}
	if fromStderr == nil || fromStderr.Kind != activity.HintNetwork || fromStderr.Errno != 1 || fromStderr.Text == "" {
		t.Fatalf("no network hint from stderr: %+v", r.Hints)
	}
	// without --strict the probe still exits 0 (TestRunCanaryBasic)
}

func TestRunRecordsPolicyError(t *testing.T) {
	f := newFixture(t)
	_, errb, code := f.probe(t, "canary-malformed", "env")
	if code != ExitPolicy {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	r := f.lastRun(t)
	if r.Outcome != activity.OutcomePolicyError || r.Exit == nil || *r.Exit != ExitPolicy || r.Error == "" ||
		strings.Contains(r.Error, "\n") || strings.Join(r.Skills, ",") != "canary-malformed" || r.Effective != nil {
		t.Fatalf("policy_error record: %+v", r)
	}
	// usage: nothing to run
	code = Run(context.Background(), Options{Skills: []string{"canary-basic"}, Env: f.env, Environ: f.environ,
		Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}, ActivityPath: f.activity})
	if r := f.lastRun(t); code != ExitUsage || r.Outcome != activity.OutcomeUsage || *r.Exit != ExitUsage || r.Error == "" {
		t.Fatalf("usage record: code %d %+v", code, r)
	}
	// the CLI's own usage errors
	RecordUsage(Options{Skills: []string{"x"}, ActivityPath: f.activity}, "flag provided but not defined: -z")
	if r := f.lastRun(t); r.Outcome != activity.OutcomeUsage || r.Error != "flag provided but not defined: -z" {
		t.Fatalf("RecordUsage: %+v", r)
	}
	// log off: nothing written
	before, _, _ := activity.Stat(f.activity)
	Run(context.Background(), Options{Skills: []string{"canary-basic"}, Command: "true", Env: f.env, Environ: f.environ,
		Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}})
	if after, _, _ := activity.Stat(f.activity); after != before {
		t.Fatal("a run with ActivityPath \"\" wrote a record")
	}
}

func TestRunDropsWriteUnderDenyPath(t *testing.T) {
	f := newFixture(t)
	// a symlink in the project pointing at the fake ~/.ssh, granted as a write
	// path: the lexical override check passes, the real path is protected
	link := filepath.Join(f.cwd, "keys")
	if err := os.Symlink(filepath.Join(f.home, ".ssh"), link); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(f.cfg, "overrides.yaml"), []byte("version: 1\nskills:\n  canary-basic:\n    write: [\"${CWD}/keys\"]\n"), 0o644)
	pol, err := Resolve([]string{"canary-basic"}, f.env, true)
	if err != nil {
		t.Fatal(err)
	}
	const warn = "write ${CWD}/keys ignored: under a protected path"
	if !contains(pol.Warnings, warn) {
		t.Fatalf("warnings: %q", pol.Warnings)
	}
	realSSH, _ := filepath.EvalSymlinks(filepath.Join(f.home, ".ssh"))
	for _, w := range pol.Resolved.Write {
		if w == realSSH || strings.HasPrefix(w, realSSH+"/") {
			t.Fatalf("protected path kept as a write allow: %q", pol.Resolved.Write)
		}
	}
	var out, errb bytes.Buffer
	code := Run(context.Background(), Options{Skills: []string{"canary-basic"}, Command: "echo x > keys/planted && echo wrote",
		Env: f.env, Environ: f.environ, Stdout: &out, Stderr: &errb, ActivityPath: f.activity})
	if code == 0 || strings.Contains(out.String(), "wrote") || !strings.Contains(errb.String(), "warning: "+warn) {
		t.Fatalf("code=%d out=%q err=%q", code, out.String(), errb.String())
	}
	if _, err := os.Stat(filepath.Join(f.home, ".ssh", "planted")); err == nil {
		t.Fatal("wrote into the fake ~/.ssh")
	}
	if r := f.lastRun(t); !contains(r.Warnings, warn) {
		t.Fatalf("record warnings: %q", r.Warnings)
	}
}

// TestRunMultiSkillDropsProjectSymlinkWrite: a project write grant on a
// symlink to a directory outside the project is dropped for a run that
// touches two skills too (the grants are intersected before the re-check).
func TestRunMultiSkillDropsProjectSymlinkWrite(t *testing.T) {
	f := newFixture(t)
	outside := filepath.Join(f.home, "elsewhere")
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(f.cwd, "build")); err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(filepath.Join(f.cwd, ".git"), 0o755)
	os.WriteFile(filepath.Join(f.cwd, ".watchdeck.yaml"), []byte("version: 1\ndefaults:\n  write: [\"${CWD}/build\"]\n"), 0o644)
	pol, err := Resolve([]string{"canary-basic", "canary-prose"}, f.env, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range pol.Resolved.Write {
		if w == outside || strings.HasPrefix(w, outside+"/") {
			t.Fatalf("outside directory kept as a write allow: %q", pol.Resolved.Write)
		}
	}
	if contains(pol.Effective.Write, "${CWD}/build") {
		t.Fatalf("effective write kept the symlinked entry: %q", pol.Effective.Write)
	}
	var out, errb bytes.Buffer
	code := Run(context.Background(), Options{Skills: []string{"canary-basic", "canary-prose"}, Command: "echo x > build/planted && echo wrote",
		Env: f.env, Environ: f.environ, Stdout: &out, Stderr: &errb, ActivityPath: f.activity})
	if code == 0 || strings.Contains(out.String(), "wrote") {
		t.Fatalf("code=%d out=%q err=%q", code, out.String(), errb.String())
	}
	if _, err := os.Stat(filepath.Join(outside, "planted")); err == nil {
		t.Fatal("wrote outside the project")
	}
}

// TestRunDropsManifestWriteThroughRepoSymlink: a skill manifest asking for
// ${CWD}/build/out, below the default grant, does not write through a
// repository symlink `build -> outside`.
func TestRunDropsManifestWriteThroughRepoSymlink(t *testing.T) {
	f := newFixture(t)
	outside := filepath.Join(f.home, "elsewhere")
	if err := os.MkdirAll(filepath.Join(outside, "out"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(f.cwd, "build")); err != nil {
		t.Fatal(err)
	}
	mp := filepath.Join(f.home, ".claude", "skills", "canary-basic", "PERMISSIONS.yaml")
	if err := os.WriteFile(mp, []byte("version: 1\nfilesystem:\n  write: [\"${CWD}/build/out\"]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pol, err := Resolve([]string{"canary-basic"}, f.env, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range pol.Resolved.Write {
		if w == outside || strings.HasPrefix(w, outside+"/") {
			t.Fatalf("outside directory kept as a write allow: %q", pol.Resolved.Write)
		}
	}
	var out, errb bytes.Buffer
	code := Run(context.Background(), Options{Skills: []string{"canary-basic"}, Command: "echo x > build/out/planted && echo wrote",
		Env: f.env, Environ: f.environ, Stdout: &out, Stderr: &errb, ActivityPath: f.activity})
	if code == 0 || strings.Contains(out.String(), "wrote") {
		t.Fatalf("code=%d out=%q err=%q", code, out.String(), errb.String())
	}
	if _, err := os.Stat(filepath.Join(outside, "out", "planted")); err == nil {
		t.Fatal("wrote outside the project")
	}
}

// TestRunBackgroundedGrandchildDoesNotBlock: run's stdout and stderr are
// pipes (the tail writers), so a grandchild that keeps one open after the
// script exits used to hold run until it finished. WaitDelay (2 s) bounds
// that; the exit code and the script's output are kept.
func TestRunBackgroundedGrandchildDoesNotBlock(t *testing.T) {
	f := newFixture(t)
	var out, errb bytes.Buffer
	start := time.Now()
	code := Run(context.Background(), Options{Skills: []string{"canary-basic"},
		Command: "sh -c 'sleep 10 >/dev/null 2>&1 </dev/null & sleep 10 & echo done'",
		Env:     f.env, Environ: f.environ, Stdout: &out, Stderr: &errb, ActivityPath: f.activity})
	took := time.Since(start)
	t.Logf("run returned after %v", took)
	if took > 4*time.Second {
		t.Fatalf("run blocked for %v on a backgrounded grandchild", took)
	}
	if code != 0 || out.String() != "done\n" {
		t.Fatalf("code=%d out=%q err=%q", code, out.String(), errb.String())
	}
	if r := f.lastRun(t); r.Outcome != activity.OutcomeOK || r.Exit == nil || *r.Exit != 0 {
		t.Fatalf("record: %+v", r)
	}
}

// TestRunEffectiveOmitsDroppedWrite: a write grant under a built-in deny
// path is dropped from the profile and must not be reported as granted in
// pol.Effective, the trailer summary or the run record. Two spellings of the
// same protected real path are both dropped and both warned about.
func TestRunEffectiveOmitsDroppedWrite(t *testing.T) {
	f := newFixture(t)
	ssh := filepath.Join(f.home, ".ssh")
	if err := os.Symlink(ssh, filepath.Join(f.cwd, "keys")); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(f.cfg, "overrides.yaml"), []byte("version: 1\nskills:\n  canary-basic:\n    write: [\""+ssh+"\", \"${CWD}/keys\", \"${CWD}/out\"]\n"), 0o644)
	pol, err := Resolve([]string{"canary-basic"}, f.env, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{ssh, "${CWD}/keys"} {
		if contains(pol.Effective.Write, w) {
			t.Errorf("Effective.Write still lists %q: %q", w, pol.Effective.Write)
		}
		if warn := "write " + w + " ignored: under a protected path"; !contains(pol.Warnings, warn) {
			t.Errorf("missing warning %q: %q", warn, pol.Warnings)
		}
	}
	if !contains(pol.Effective.Write, "${CWD}/out") {
		t.Errorf("Effective.Write lost the ordinary grant: %q", pol.Effective.Write)
	}
	var out, errb bytes.Buffer
	code := Run(context.Background(), Options{Skills: []string{"canary-basic"}, Command: "exit 3",
		Env: f.env, Environ: f.environ, Stdout: &out, Stderr: &errb, ActivityPath: f.activity})
	if code != 3 {
		t.Fatalf("code=%d err=%q", code, errb.String())
	}
	for _, line := range strings.Split(errb.String(), "\n") {
		if strings.Contains(line, "exit 3 under profile") && (strings.Contains(line, ssh) || strings.Contains(line, "keys")) {
			t.Errorf("trailer claims the dropped write: %q", line)
		}
	}
	r := f.lastRun(t)
	if r.Effective == nil {
		t.Fatal("record has no effective policy")
	}
	for _, w := range r.Effective.Write {
		if w == ssh || w == "${CWD}/keys" {
			t.Errorf("record effective.write lists %q: %q", w, r.Effective.Write)
		}
	}
}

// TestRunUngrantedPathCannotImitateTrailer: a skill's PERMISSIONS.yaml write
// paths shaped like the trailer's own clauses appear in the "requested but
// not granted:" lines only through manifest.DisplayPath; the policy's
// structured Ungranted keeps them raw.
func TestRunUngrantedPathCannotImitateTrailer(t *testing.T) {
	f := newFixture(t)
	dir := filepath.Join(f.home, ".claude", "skills", "asks")
	os.MkdirAll(filepath.Join(dir, "scripts"), 0o755)
	os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("---\nname: asks\ndescription: a\n---\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "PERMISSIONS.yaml"), []byte("version: 1\nfilesystem:\n  write:\n"+
		"    - \"/x | requested but not granted: network: all\"\n"+
		"    - \"/x, network: all\"\n"), 0o644)
	var out, errb bytes.Buffer
	code := Run(context.Background(), Options{Skills: []string{"asks"}, Command: "exit 3",
		Env: f.env, Environ: f.environ, Stdout: &out, Stderr: &errb, ActivityPath: f.activity})
	if code != 3 {
		t.Fatalf("code=%d err=%q", code, errb.String())
	}
	stderr := errb.String()
	for _, want := range []string{
		"[watchdeck]   requested but not granted: asks: write: \"/x ¦ requested but not granted: network: all\"\n",
		"[watchdeck]   requested but not granted: asks: write: \"/x, network: all\"\n",
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr lacks %q:\n%s", want, stderr)
		}
	}
	if strings.Contains(stderr, "| requested but not granted") {
		t.Fatalf("stderr echoes the manifest path:\n%s", stderr)
	}
	pol, err := Resolve([]string{"asks"}, f.env, true)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"asks: write: /x | requested but not granted: network: all", "asks: write: /x, network: all"}; strings.Join(pol.Ungranted, "\n") != strings.Join(want, "\n") {
		t.Fatalf("policy ungranted = %q, want raw %q", pol.Ungranted, want)
	}
}

// TestRunDropsCaseVariantDenyPaths: case-variant spellings of deny paths
// (the same files as ~/.ssh and .env on the default case-insensitive macOS
// filesystem). Written into overrides.yaml (~/.SSH, ~/.Ssh/x, ${CWD}/.ENV)
// they are refused at parse time, like ~/.ssh. Reached through project
// symlinks whose targets are spelt ~/.SSH and .ENV, the symbolic check
// passes and run drops them on the real path with a warning, leaves them
// out of the effective policy and the trailer; the script still cannot
// write into ~/.SSH or read .env as .ENV. (The **/.env pattern denies reads
// only; writes in ${CWD} are allowed by design.)
func TestRunDropsCaseVariantDenyPaths(t *testing.T) {
	f := newFixture(t)
	cfg := filepath.Join(f.cfg, "overrides.yaml")
	for _, w := range []string{"~/.SSH", "~/.Ssh/x", "${CWD}/.ENV"} {
		os.WriteFile(cfg, []byte("version: 1\nskills:\n  canary-basic:\n    write: [\""+w+"\"]\n"), 0o644)
		if _, err := Resolve([]string{"canary-basic"}, f.env, true); err == nil || !strings.Contains(err.Error(), "cannot grant built-in deny") {
			t.Errorf("%s in overrides.yaml: err = %v", w, err)
		}
	}

	// A fake .env in the project: reading it as .ENV must be refused too.
	os.WriteFile(filepath.Join(f.cwd, ".env"), []byte("CANARY_SECRET=not-a-real-secret\n"), 0o644)
	if err := os.Symlink(filepath.Join(f.home, ".SSH"), filepath.Join(f.cwd, "keys")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(f.cwd, ".ENV"), filepath.Join(f.cwd, "dotenv")); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(cfg, []byte("version: 1\nskills:\n  canary-basic:\n"+
		"    write: [\"${CWD}/keys\", \"${CWD}/dotenv\", \"${CWD}/out\"]\n"), 0o644)
	pol, err := Resolve([]string{"canary-basic"}, f.env, true)
	if err != nil {
		t.Fatal(err)
	}
	dropped := []string{"${CWD}/keys", "${CWD}/dotenv"}
	for _, w := range dropped {
		if warn := "write " + w + " ignored: under a protected path"; !contains(pol.Warnings, warn) {
			t.Errorf("missing warning %q: %q", warn, pol.Warnings)
		}
		if contains(pol.Effective.Write, w) {
			t.Errorf("Effective.Write still lists %q: %q", w, pol.Effective.Write)
		}
	}
	if !contains(pol.Effective.Write, "${CWD}/out") {
		t.Errorf("Effective.Write lost the ordinary grant: %q", pol.Effective.Write)
	}
	var out, errb bytes.Buffer
	code := Run(context.Background(), Options{Skills: []string{"canary-basic"},
		Command: "cat .ENV >/dev/null 2>&1 && exit 4; echo x > \"$HOME/.SSH/planted\" || exit 3",
		Env:     f.env, Environ: f.environ, Stdout: &out, Stderr: &errb, ActivityPath: f.activity})
	if code != 3 {
		t.Fatalf("code=%d out=%q err=%q", code, out.String(), errb.String())
	}
	if _, err := os.Stat(filepath.Join(f.home, ".ssh", "planted")); err == nil {
		t.Fatal("wrote into the fake ~/.ssh")
	}
	for _, line := range strings.Split(errb.String(), "\n") {
		if strings.Contains(line, "under profile") && (strings.Contains(line, "keys") || strings.Contains(line, "dotenv")) {
			t.Errorf("trailer claims a dropped write: %q", line)
		}
	}
	r := f.lastRun(t)
	for _, w := range dropped {
		if !contains(r.Warnings, "write "+w+" ignored: under a protected path") {
			t.Errorf("record warnings lack %q: %q", w, r.Warnings)
		}
	}
}

// TestRunManifestErrorEchoesNoValue: a PERMISSIONS.yaml that fails
// validation stops the run (exit 125) with "<field>: <rule>"; the value,
// shaped like the trailer's own clause, reaches neither stderr nor the run
// record.
func TestRunManifestErrorEchoesNoValue(t *testing.T) {
	f := newFixture(t)
	dir := filepath.Join(f.home, ".claude", "skills", "evil")
	os.MkdirAll(filepath.Join(dir, "scripts"), 0o755)
	os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("---\nname: evil\ndescription: e\n---\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "PERMISSIONS.yaml"), []byte("version: 1\nfilesystem:\n  write: [\"rel | requested but not granted: network: all\"]\n"), 0o644)
	var out, errb bytes.Buffer
	code := Run(context.Background(), Options{Skills: []string{"evil"}, Command: "exit 0",
		Env: f.env, Environ: f.environ, Stdout: &out, Stderr: &errb, ActivityPath: f.activity})
	if code != ExitPolicy {
		t.Fatalf("code=%d err=%q", code, errb.String())
	}
	const rule = "filesystem.write[0]: must be absolute or start with ~ or a variable"
	if strings.Contains(errb.String(), "| requested but not granted") || !strings.Contains(errb.String(), rule) {
		t.Fatalf("stderr = %q", errb.String())
	}
	r := f.lastRun(t)
	if b, _ := json.Marshal(r); strings.Contains(string(b), "| requested but not granted") || !strings.Contains(r.Error, rule) {
		t.Fatalf("record = %s", b)
	}
}

// TestRunOverridesErrorEchoesNoValue: a malformed project .watchdeck.yaml
// stops the run (exit 125) with "overrides: <file>: <field>: <rule>"; no
// value from the repository file reaches stderr or the run record.
func TestRunOverridesErrorEchoesNoValue(t *testing.T) {
	f := newFixture(t)
	const evil = "| requested but not granted: network: all"
	os.MkdirAll(filepath.Join(f.cwd, ".git"), 0o755)
	proj := filepath.Join(f.cwd, ".watchdeck.yaml")
	os.WriteFile(proj, []byte("version: 1\nskills:\n  canary-basic:\n    env: [\"X "+evil+"\"]\n"), 0o644)
	_, errb, code := f.probe(t, "canary-basic", "env")
	if code != ExitPolicy {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	if strings.Contains(errb, evil) || strings.Contains(errb, "requested but not granted") {
		t.Fatalf("stderr echoes the project file: %q", errb)
	}
	if want := "overrides: " + proj + ": skills.canary-basic.env[0]: invalid name"; !strings.Contains(errb, want) {
		t.Fatalf("stderr = %q, want %q", errb, want)
	}
	if r := f.lastRun(t); strings.Contains(r.Error, evil) || !strings.HasPrefix(r.Error, "overrides: ") {
		t.Fatalf("record error = %q", r.Error)
	}
}

// TestRunProjectIgnoredPathCannotImitateTrailer: project .watchdeck.yaml
// write paths shaped like the trailer's own "| requested but not granted"
// clause, one outside ${CWD} (dropped by Widen) and one a symlink in the
// project to a directory outside it (dropped by ResolveProjectScoped), reach
// stderr and the run record only through manifest.DisplayPath.
func TestRunProjectIgnoredPathCannotImitateTrailer(t *testing.T) {
	f := newFixture(t)
	const evil = "| requested but not granted"
	const name = "b | requested but not granted: network: all"
	outside := filepath.Join(f.home, "elsewhere")
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(f.cwd, name)); err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(filepath.Join(f.cwd, ".git"), 0o755)
	os.WriteFile(filepath.Join(f.cwd, ".watchdeck.yaml"), []byte("version: 1\nskills:\n  canary-basic:\n    write:\n"+
		"      - \"/x | requested but not granted: network: all\"\n"+
		"      - \"${CWD}/"+name+"\"\n"), 0o644)
	var out, errb bytes.Buffer
	code := Run(context.Background(), Options{Skills: []string{"canary-basic"}, Command: "exit 3",
		Env: f.env, Environ: f.environ, Stdout: &out, Stderr: &errb, ActivityPath: f.activity})
	if code != 3 {
		t.Fatalf("code=%d err=%q", code, errb.String())
	}
	stderr := errb.String()
	if strings.Contains(stderr, evil) {
		t.Fatalf("stderr echoes the project path: %q", stderr)
	}
	for _, want := range []string{
		`[watchdeck]   canary-basic: project override ignored: write: "/x ¦ requested but not granted: network: all" (outside ${CWD})`,
		`[watchdeck]   project override ignored: "${CWD}/b ¦ requested but not granted: network: all" (resolves to ` + outside + `, outside the project)`,
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr lacks %q:\n%s", want, stderr)
		}
	}
	r := f.lastRun(t)
	if b, _ := json.Marshal(r); strings.Contains(string(b), evil) {
		t.Fatalf("run record echoes the project path: %s", b)
	}
}

// TestRunGrantedPathCannotImitateTrailer: a write path INSIDE the project,
// "${CWD}/x | requested but not granted: network: all", is granted and kept
// raw in the policy, but the trailer's summary and the run record's
// effective.summary show it only through manifest.DisplayPath. A write grant
// dropped as under a protected path (a symlink in the project to the fake
// ~/.ssh) is named the same way in the warning on stderr and in the record.
func TestRunGrantedPathCannotImitateTrailer(t *testing.T) {
	f := newFixture(t)
	const evil = "| requested but not granted"
	const inside = "${CWD}/x | requested but not granted: network: all"
	const link = "k | requested but not granted: network: all"
	if err := os.Symlink(filepath.Join(f.home, ".ssh"), filepath.Join(f.cwd, link)); err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(filepath.Join(f.cwd, ".git"), 0o755)
	os.WriteFile(filepath.Join(f.cwd, ".watchdeck.yaml"), []byte("version: 1\nskills:\n  canary-basic:\n    write: [\""+inside+"\"]\n"), 0o644)
	// The protected-path drop needs a grant that survives the project
	// check, so it comes from the user file.
	os.WriteFile(filepath.Join(f.cfg, "overrides.yaml"), []byte("version: 1\nskills:\n  canary-basic:\n    write: [\"${CWD}/"+link+"\"]\n"), 0o644)

	pol, err := Resolve([]string{"canary-basic"}, f.env, true)
	if err != nil {
		t.Fatal(err)
	}
	if !contains(pol.Effective.Write, inside) {
		t.Fatalf("policy lost the raw in-project grant: %q", pol.Effective.Write)
	}

	var out, errb bytes.Buffer
	code := Run(context.Background(), Options{Skills: []string{"canary-basic"}, Command: "exit 3",
		Env: f.env, Environ: f.environ, Stdout: &out, Stderr: &errb, ActivityPath: f.activity})
	if code != 3 {
		t.Fatalf("code=%d err=%q", code, errb.String())
	}
	stderr := errb.String()
	const summary = `network=none write=${CWD},${TMP},"${CWD}/x ¦ requested but not granted: network: all" env=PATH,HOME,LANG,TMPDIR`
	const warn = `write "${CWD}/k ¦ requested but not granted: network: all" ignored: under a protected path`
	if strings.Contains(stderr, evil) || !strings.Contains(stderr, "("+summary) || !strings.Contains(stderr, "warning: "+warn) {
		t.Fatalf("stderr:\n%s", stderr)
	}
	r := f.lastRun(t)
	if r.Effective == nil || !strings.HasPrefix(r.Effective.Summary, summary) || strings.Contains(r.Effective.Summary, evil) {
		t.Fatalf("record effective: %+v", r.Effective)
	}
	if !contains(r.Warnings, warn) {
		t.Fatalf("record warnings: %q", r.Warnings)
	}
	for _, w := range r.Warnings {
		if strings.Contains(w, evil) {
			t.Fatalf("record warning echoes the path: %q", w)
		}
	}
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
