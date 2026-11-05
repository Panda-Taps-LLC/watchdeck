//go:build darwin

package runner

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Panda-Taps-LLC/watchdeck/internal/activity"
)

// TestSandboxDeniesStateDir runs real Seatbelt-sandboxed commands against
// watchdeck's state dir: the default one under the fake home, and one moved
// by XDG_STATE_HOME. Reading the session index and writing into the dir are
// denied. The activity log lives in that same denied dir, as it does by
// default, and run still appends its record, because the parent process
// writes it after the child exits.
func TestSandboxDeniesStateDir(t *testing.T) {
	f := newFixture(t)
	xdg, err := os.MkdirTemp("/var/tmp", "watchdeck-xdgstate-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(xdg) })
	if r, err := filepath.EvalSymlinks(xdg); err == nil {
		xdg = r
	}
	cases := []struct {
		name     string
		environ  []string
		stateDir string
	}{
		{"default", f.environ, filepath.Join(f.home, ".local", "state", "watchdeck")},
		{"xdg", append(append([]string(nil), f.environ...), "XDG_STATE_HOME="+xdg), filepath.Join(xdg, "watchdeck")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			indexText := filepath.Join(c.stateDir, "index", "text")
			if err := os.MkdirAll(indexText, 0o700); err != nil {
				t.Fatal(err)
			}
			secret := filepath.Join(indexText, "s.txt")
			if err := os.WriteFile(secret, []byte("fake-transcript-text\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			logPath := filepath.Join(c.stateDir, "activity.jsonl")
			// bash builtins only: the read and the redirect are the probes
			cmd := `if read -r l < ` + secret + `; then echo "read: ALLOWED $l"; else echo "read: DENIED"; fi; ` +
				`if echo x > ` + filepath.Join(c.stateDir, "planted") + `; then echo "write: ALLOWED"; else echo "write: DENIED"; fi; ` +
				`if echo x > ` + filepath.Join(f.cwd, "ok") + `; then echo "cwd: ALLOWED"; else echo "cwd: DENIED"; fi`
			var out, errb bytes.Buffer
			code := Run(context.Background(), Options{Skills: []string{"canary-basic"}, Command: cmd, Env: f.env,
				Environ: c.environ, Stdout: &out, Stderr: &errb, ActivityPath: logPath})
			o := out.String()
			if code != 0 || !strings.Contains(o, "read: DENIED") || !strings.Contains(o, "write: DENIED") || !strings.Contains(o, "cwd: ALLOWED") {
				t.Fatalf("exit %d\nstdout: %s\nstderr: %s", code, o, errb.String())
			}
			if strings.Contains(o, "fake-transcript-text") {
				t.Error("index text leaked")
			}
			if _, err := os.Stat(filepath.Join(c.stateDir, "planted")); !os.IsNotExist(err) {
				t.Errorf("planted file exists: %v", err)
			}
			res, err := activity.Read(logPath, activity.ReadOptions{})
			if err != nil || len(res.Records) != 1 || res.Records[0].Kind != activity.KindRun || res.Records[0].Outcome != activity.OutcomeOK {
				t.Fatalf("activity record not written to the denied dir: %v %+v", err, res.Records)
			}
		})
	}
}
