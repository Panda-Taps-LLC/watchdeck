package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/claudesettings"
)

// The ui tests run the real binary as a subprocess (the detached child is a
// re-exec of it). They never open a browser: BROWSER always points at a stub
// script, and the server binds 127.0.0.1 only (ui.Listen).

var (
	pkgDir, _ = os.Getwd() // captured before any test changes directory
	buildOnce sync.Once
	builtBin  string
	buildErr  error
	buildDir  string
)

func TestMain(m *testing.M) {
	// No test may reach launchctl or systemctl: service tests install their
	// own fake, everything else gets this refusal.
	serviceRunner = refusingRunner{}
	// No in-process test may read the real managed settings (/Library or
	// /etc): enforce, setup and doctor read Claude Code's settings for
	// coveredTwins. Tests that need managed files set their own.
	managed, err := os.MkdirTemp("", "watchdeck-managed-")
	if err != nil {
		panic(err)
	}
	claudesettings.ManagedDirOverride = func() string { return managed }
	code := m.Run()
	os.RemoveAll(managed)
	if buildDir != "" {
		os.RemoveAll(buildDir)
	}
	os.Exit(code)
}

// testBinary builds the command once per test run into a temp dir.
func testBinary(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		buildDir, buildErr = os.MkdirTemp("", "watchdeck-uitest-")
		if buildErr != nil {
			return
		}
		builtBin = filepath.Join(buildDir, "watchdeck")
		cmd := exec.Command("go", "build", "-o", builtBin, ".")
		cmd.Dir = pkgDir
		if out, err := cmd.CombinedOutput(); err != nil {
			buildErr = &buildError{err, string(out)}
		}
	})
	if buildErr != nil {
		t.Fatalf("build: %v", buildErr)
	}
	return builtBin
}

type buildError struct {
	err error
	out string
}

func (b *buildError) Error() string { return b.err.Error() + "\n" + b.out }

var launchURL = regexp.MustCompile(`^http://127\.0\.0\.1:(\d+)/#t=([A-Za-z0-9_-]{43})$`)

// browserStub writes a BROWSER script that records its argument in a file
// and exits with code; it returns the script and the record file.
func browserStub(t *testing.T, code int) (string, string) {
	t.Helper()
	dir := t.TempDir()
	rec := filepath.Join(dir, "opened.txt")
	script := filepath.Join(dir, "browser.sh")
	body := "#!/bin/sh\nprintf '%s\\n' \"$1\" > '" + rec + "'\nexit " + strconv.Itoa(code) + "\n"
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	return script, rec
}

// killOnCleanup makes sure a server started by a test never outlives it.
func killOnCleanup(t *testing.T, pid int) {
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
}

var startedPID = regexp.MustCompile(`started pid (\d+), listening on 127\.0\.0\.1:\d+ \(idle exit after (\d+) min\)`)

// detach runs `ui --detach` with extra args and returns stdout, stderr and
// the background server's pid (registered for cleanup).
func detach(t *testing.T, bin string, extra ...string) (string, string, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, append([]string{"ui", "--detach", "--port", "0"}, extra...)...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	start := time.Now()
	err := cmd.Run()
	if took := time.Since(start); took > 5*time.Second {
		t.Errorf("ui --detach took %s", took)
	}
	m := startedPID.FindStringSubmatch(errb.String())
	pid := 0
	if m != nil {
		pid, _ = strconv.Atoi(m[1])
		killOnCleanup(t, pid)
	}
	if err != nil {
		t.Fatalf("ui --detach %v: %v\nstdout %q\nstderr %q", extra, err, out.String(), errb.String())
	}
	if m == nil {
		t.Fatalf("no pid line on stderr: %q", errb.String())
	}
	return out.String(), errb.String(), pid
}

func get(t *testing.T, url, token string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	c := &http.Client{Timeout: 5 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	var b bytes.Buffer
	_, _ = b.ReadFrom(resp.Body)
	return resp, b.Bytes()
}

func TestUIDetach(t *testing.T) {
	bin := testBinary(t)
	newTestEnv(t)
	t.Setenv("BROWSER", "/usr/bin/false") // a guard: nothing here may reach a real browser

	// --no-open: exactly one stdout line, the full URL; no token on stderr.
	out, errOut, pid := detach(t, bin, "--no-open", "--idle", "1")
	m := launchURL.FindStringSubmatch(strings.TrimSuffix(out, "\n"))
	if m == nil || strings.Count(out, "\n") != 1 {
		t.Fatalf("stdout %q: want one launch URL line", out)
	}
	port, token := m[1], m[2]
	if strings.Contains(errOut, token) {
		t.Fatalf("token on stderr: %q", errOut)
	}
	if sm := startedPID.FindStringSubmatch(errOut); sm[2] != "1" {
		t.Errorf("idle minutes %s, want 1", sm[2])
	}
	// setsid makes the child a session and process-group leader; Getpgid is
	// available on darwin and linux (Getsid is not in syscall on linux).
	if pgid, err := syscall.Getpgid(pid); err != nil || pgid != pid {
		t.Errorf("child process group %d (err %v), want its own group %d", pgid, err, pid)
	}
	base := "http://127.0.0.1:" + port + "/"
	resp, _ := get(t, base, "")
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Security-Policy"), "default-src 'none'") {
		t.Fatalf("GET / = %d, CSP %q", resp.StatusCode, resp.Header.Get("Content-Security-Policy"))
	}
	resp, body := get(t, base+"api/status", token)
	var st struct {
		NoTranscripts bool `json:"noTranscripts"`
		IdleMinutes   int  `json:"idleMinutes"`
	}
	if resp.StatusCode != 200 || json.Unmarshal(body, &st) != nil || st.NoTranscripts || st.IdleMinutes != 1 {
		t.Fatalf("/api/status = %d %s", resp.StatusCode, body)
	}
	if resp, _ := get(t, base+"api/status", ""); resp.StatusCode != 401 {
		t.Fatalf("/api/status without token = %d, want 401", resp.StatusCode)
	}

	// A fresh state dir for each case: in the same one the next --detach would
	// reuse the running dashboard (TestUIReusesRunningInstance).
	newTestEnv(t)
	// --open with a working opener: the browser gets the token, stdout does not.
	stub, rec := browserStub(t, 0)
	t.Setenv("BROWSER", stub)
	out, errOut, _ = detach(t, bin, "--open", "--no-transcripts")
	opened, err := os.ReadFile(rec)
	if err != nil {
		t.Fatalf("opener not called: %v", err)
	}
	om := launchURL.FindStringSubmatch(strings.TrimSpace(string(opened)))
	if om == nil {
		t.Fatalf("opener got %q", opened)
	}
	if want := "watchdeck ui: opened http://127.0.0.1:" + om[1] + "/ in your browser\n"; out != want {
		t.Fatalf("stdout %q, want %q", out, want)
	}
	if strings.Contains(out+errOut, om[2]) || strings.Contains(out, "#t=") {
		t.Fatalf("token printed: stdout %q stderr %q", out, errOut)
	}
	if !strings.Contains(errOut, "idle exit after 30 min") {
		t.Errorf("detach default idle: %q", errOut)
	}
	resp, body = get(t, "http://127.0.0.1:"+om[1]+"/api/status", om[2])
	if resp.StatusCode != 200 || json.Unmarshal(body, &st) != nil || !st.NoTranscripts {
		t.Fatalf("--no-transcripts not passed through: %d %s", resp.StatusCode, body)
	}

	newTestEnv(t)
	// --open with a failing opener: the URL goes to stdout after all.
	stub, _ = browserStub(t, 1)
	t.Setenv("BROWSER", stub)
	out, _, _ = detach(t, bin, "--open")
	if launchURL.FindStringSubmatch(strings.TrimSuffix(out, "\n")) == nil {
		t.Fatalf("failed opener: stdout %q, want the launch URL", out)
	}
}

func TestUIPrintsNoTokenOnStderr(t *testing.T) {
	bin := testBinary(t)
	newTestEnv(t)
	t.Setenv("BROWSER", "/usr/bin/false")
	cmd := exec.Command(bin, "ui", "--no-open", "--port", "0")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var errb bytes.Buffer
	cmd.Stderr = &errb
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	killOnCleanup(t, cmd.Process.Pid)
	br := bufio.NewReader(stdout)
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("reading the URL: %v (stderr %q)", err, errb.String())
	}
	m := launchURL.FindStringSubmatch(strings.TrimSuffix(line, "\n"))
	if m == nil {
		t.Fatalf("stdout line %q", line)
	}
	if resp, _ := get(t, "http://127.0.0.1:"+m[1]+"/", ""); resp.StatusCode != 200 {
		t.Fatalf("GET / = %d", resp.StatusCode)
	}
	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	rest, _ := bufio.NewReader(br).ReadString(0) // until EOF
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("exit after SIGINT: %v (stderr %q)", err, errb.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("ui did not exit on SIGINT")
	}
	if rest != "" {
		t.Errorf("more stdout after the URL: %q", rest)
	}
	errOut := errb.String()
	if strings.Contains(errOut, m[2]) || strings.Contains(errOut, "#t=") {
		t.Fatalf("token on stderr: %q", errOut)
	}
	if want := "watchdeck ui: listening on 127.0.0.1:" + m[1] + " (idle exit after 30 min)\n"; !strings.HasPrefix(errOut, want) {
		t.Fatalf("stderr %q, want prefix %q", errOut, want)
	}
}

func TestUIUsageErrors(t *testing.T) {
	newTestEnv(t)
	t.Setenv("BROWSER", "/usr/bin/false")
	for _, args := range [][]string{
		{"--bogus"},
		{"extra"},
		{"--port", "70000"},
		{"--idle", "-1"},
		{"--open", "--no-open"},
		{"--detach", "--detached-fd", "3"},
		{"--detached-fd", "1"},
		{"--detached-fd", "2"},
		{"--detached-fd", "-1"},
	} {
		var out, errb bytes.Buffer
		if code := cmdUI(args, &out, &errb); code != 3 {
			t.Errorf("ui %v: exit %d, want 3", args, code)
		}
		if out.Len() != 0 {
			t.Errorf("ui %v printed %q on stdout", args, out.String())
		}
	}
}
