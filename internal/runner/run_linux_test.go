//go:build linux

package runner

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/activity"
	"github.com/Panda-Taps-LLC/watchdeck/internal/sandbox"
)

// linuxFixture is a fake HOME with the canary skills, a fake ~/.ssh/id_fake,
// an empty project dir, isolated cache/config dirs and a temp activity log.
type linuxFixture struct {
	home, cwd, dst, activity string
	env                      Env
	environ                  []string
}

func newLinuxFixture(t *testing.T) *linuxFixture {
	t.Helper()
	if !sandbox.Available() {
		t.Skip("no bwrap")
	}
	home, err := os.MkdirTemp("/var/tmp", "watchdeck-home-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(home) })
	src, _ := filepath.Abs(filepath.Join("..", "..", "testdata", "skills"))
	dst := filepath.Join(home, ".claude", "skills")
	os.MkdirAll(dst, 0o755)
	if err := os.CopyFS(dst, os.DirFS(src)); err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(filepath.Join(home, ".ssh"), 0o700)
	os.WriteFile(filepath.Join(home, ".ssh", "id_fake"), []byte("not a real key\n"), 0o600)
	cwd := t.TempDir()
	return &linuxFixture{
		home: home, cwd: cwd, dst: dst,
		activity: filepath.Join(t.TempDir(), "state", "activity.jsonl"),
		env:      Env{Home: home, Cwd: cwd, CacheDir: t.TempDir(), UserCfgDir: filepath.Join(t.TempDir(), "cfg")},
		environ:  []string{"PATH=/usr/bin:/bin", "HOME=" + home, "LANG=C", "CANARY_SECRET=not-a-real-secret"},
	}
}

func (f *linuxFixture) cmd(skill, action string) string {
	return "python3 " + filepath.Join(f.dst, skill, "scripts", "probe.py") + " " + action
}

func (f *linuxFixture) run(skill, cmd string) (string, string, int) {
	var out, errb bytes.Buffer
	code := Run(context.Background(), Options{Skills: []string{skill}, Command: cmd, Env: f.env, Environ: f.environ, Stdout: &out, Stderr: &errb, ActivityPath: f.activity})
	return out.String(), errb.String(), code
}

func (f *linuxFixture) lastRun(t *testing.T) activity.Record {
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

// Linux canary: the same probe under bubblewrap. Runs in CI (ubuntu-24.04
// with bubblewrap installed); skipped where bwrap is missing.
func TestRunCanaryBasicLinux(t *testing.T) {
	f := newLinuxFixture(t)
	cases := map[string]string{
		"write-cwd":   "write-cwd: ALLOWED",
		"write-home":  "write-home: DENIED",
		"read-secret": "read-secret: DENIED",
		"net":         "net: DENIED",
		"env":         "env: SCRUBBED",
	}
	for action, want := range cases {
		out, errb, code := f.run("canary-basic", f.cmd("canary-basic", action))
		if !strings.Contains(out, want) {
			t.Errorf("%s: want %q, got %q (stderr %q, code %d)", action, want, out, errb, code)
		}
	}
}

func TestRunRecordsOutcomeLinux(t *testing.T) {
	f := newLinuxFixture(t)
	cmd := f.cmd("canary-basic", "net")
	if err := activity.Append(f.activity, activity.Record{
		Kind: activity.KindDecision, TS: time.Now().Add(-2 * time.Second).UTC().Format(time.RFC3339Nano),
		SessionID: "s1", ToolUseID: "toolu_1", Cwd: f.cwd, Skills: []string{"canary-basic"}, Command: cmd,
		Decision: "ask", Rewritten: "watchdeck run --skill canary-basic -c '" + cmd + "'", Confidence: "high",
	}); err != nil {
		t.Fatal(err)
	}
	out, errb, code := f.run("canary-basic", cmd)
	if code != 0 || !strings.Contains(out, "net: DENIED") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errb)
	}
	r := f.lastRun(t)
	if r.Outcome != activity.OutcomeOK || r.Exit == nil || *r.Exit != 0 || r.Backend != "bwrap" || r.ProfileHash == "" ||
		r.Effective == nil || r.Effective.Network != "none" || r.SessionID != "s1" || r.ToolUseID != "toolu_1" || r.JoinedBy != activity.JoinedByWrite {
		t.Fatalf("run record: %+v", r)
	}
	if len(r.Hints) != 1 || r.Hints[0].Kind != activity.HintNetwork || r.Hints[0].Stream != "stdout" || r.Hints[0].Label != "net" {
		t.Fatalf("hints: %+v", r.Hints)
	}
}

func TestRunRecordsHintOnLoudFailureLinux(t *testing.T) {
	f := newLinuxFixture(t)
	out, errb, code := f.run("canary-basic", f.cmd("canary-basic", "net --strict"))
	if code != 1 || !strings.Contains(out, "net: DENIED") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errb)
	}
	r := f.lastRun(t)
	found := false
	for _, h := range r.Hints {
		if h.Stream == "stderr" && h.Kind == activity.HintNetwork && (h.Errno == 101 || h.Errno == 1) {
			found = true
		}
	}
	if r.Outcome != activity.OutcomeFailed || r.Exit == nil || *r.Exit != 1 || !found {
		t.Fatalf("run record: %+v", r)
	}
}

func TestRunRecordsPolicyErrorLinux(t *testing.T) {
	f := newLinuxFixture(t)
	_, errb, code := f.run("canary-malformed", f.cmd("canary-malformed", "env"))
	if code != ExitPolicy {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	if r := f.lastRun(t); r.Outcome != activity.OutcomePolicyError || r.Error == "" || r.Backend != "bwrap" {
		t.Fatalf("record: %+v", r)
	}
}

// TestRunBackgroundedGrandchildDoesNotBlockLinux mirrors the darwin test:
// WaitDelay bounds a grandchild that keeps run's output pipes open.
func TestRunBackgroundedGrandchildDoesNotBlockLinux(t *testing.T) {
	f := newLinuxFixture(t)
	start := time.Now()
	out, errb, code := f.run("canary-basic", "sh -c 'sleep 10 >/dev/null 2>&1 </dev/null & sleep 10 & echo done'")
	took := time.Since(start)
	t.Logf("run returned after %v", took)
	if took > 4*time.Second {
		t.Fatalf("run blocked for %v on a backgrounded grandchild", took)
	}
	if code != 0 || out != "done\n" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errb)
	}
}
