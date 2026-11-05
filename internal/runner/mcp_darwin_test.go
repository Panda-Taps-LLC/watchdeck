//go:build darwin

package runner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/activity"
)

// canaryServer is the canary stdio MCP server (fake data only).
func canaryServer(t *testing.T) []string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join("..", "..", "testdata", "mcp", "canary_server.py"))
	if err != nil {
		t.Fatal(err)
	}
	return []string{"/usr/bin/python3", p}
}

// writePolicy writes the fixture's user overrides file.
func (f *fixture) writePolicy(t *testing.T, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(f.cfg, "overrides.yaml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// mcpSession is a JSON-RPC client over real pipes (*os.File), the code path
// Claude Code exercises: the child inherits the descriptors.
type mcpSession struct {
	in   *os.File // our end: requests
	out  *bufio.Reader
	outF *os.File
	done chan int
	errb *bytes.Buffer
}

func (s *mcpSession) roundTrip(t *testing.T, req string) []byte {
	t.Helper()
	if _, err := s.in.WriteString(req + "\n"); err != nil {
		t.Fatal(err)
	}
	line, err := s.out.ReadBytes('\n')
	if err != nil {
		t.Fatalf("read response to %s: %v (stderr %q)", req, err, s.errb.String())
	}
	return line
}

func (s *mcpSession) notify(t *testing.T, req string) {
	t.Helper()
	if _, err := s.in.WriteString(req + "\n"); err != nil {
		t.Fatal(err)
	}
}

func (s *mcpSession) close(t *testing.T) int {
	t.Helper()
	s.in.Close()
	select {
	case code := <-s.done:
		s.outF.Close()
		return code
	case <-time.After(20 * time.Second):
		t.Fatal("server did not exit after stdin closed")
	}
	return -1
}

// startWrapped runs argv through RunMCP with pipe descriptors.
func (f *fixture) startWrapped(t *testing.T, server string, argv []string) *mcpSession {
	t.Helper()
	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	s := &mcpSession{in: inW, out: bufio.NewReader(outR), outF: outR, done: make(chan int, 1), errb: &bytes.Buffer{}}
	go func() {
		code := RunMCP(context.Background(), MCPOptions{Server: server, Argv: argv, Env: f.env, Environ: f.environ,
			Stdin: inR, Stdout: outW, Stderr: s.errb, ActivityPath: f.activity})
		inR.Close()
		outW.Close()
		s.done <- code
	}()
	return s
}

// startDirect runs argv with no sandbox, as the baseline.
func startDirect(t *testing.T, dir string, environ []string, argv []string) *mcpSession {
	t.Helper()
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Dir = dir
	cmd.Env = environ
	inR, inW, _ := os.Pipe()
	outR, outW, _ := os.Pipe()
	cmd.Stdin, cmd.Stdout = inR, outW
	s := &mcpSession{in: inW, out: bufio.NewReader(outR), outF: outR, done: make(chan int, 1), errb: &bytes.Buffer{}}
	cmd.Stderr = s.errb
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	inR.Close()
	outW.Close()
	go func() {
		cmd.Wait()
		s.done <- cmd.ProcessState.ExitCode()
	}()
	return s
}

const launchPolicy = `version: 2
subjects:
  - kind: mcp
    name: canary
    launch:
      sandbox: true
      grant:
        env: [FAKE_TOKEN]
`

func mcpCall(id int, tool string, args map[string]any) string {
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": map[string]any{"name": tool, "arguments": args}})
	return string(b)
}

func toolText(t *testing.T, line []byte) string {
	t.Helper()
	var r struct {
		Result struct {
			Content []struct{ Text string } `json:"content"`
		} `json:"result"`
	}
	if err := json.Unmarshal(line, &r); err != nil || len(r.Result.Content) == 0 {
		t.Fatalf("bad tool response %q: %v", line, err)
	}
	return r.Result.Content[0].Text
}

// TestMCPPassThroughByteExact: initialize, tools/list and tools/call through
// `run --subject mcp:canary --` return exactly the bytes a direct run
// returns, including a 256 KiB response and non-ASCII text.
func TestMCPPassThroughByteExact(t *testing.T) {
	f := newFixture(t)
	f.writePolicy(t, launchPolicy)
	big := strings.Repeat("abcdefgh", 32<<10)
	reqs := []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}`,
		"", // notifications/initialized: no response
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		mcpCall(3, "echo", map[string]any{"text": "héllo, wörld ✓   <&>"}),
		mcpCall(4, "echo", map[string]any{"text": big}),
		`{"jsonrpc":"2.0","id":5,"method":"nope"}`,
	}
	transcript := func(s *mcpSession) []byte {
		var all []byte
		for _, r := range reqs {
			if r == "" {
				s.notify(t, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
				continue
			}
			all = append(all, s.roundTrip(t, r)...)
		}
		return all
	}
	direct := startDirect(t, f.cwd, f.environ, canaryServer(t))
	want := transcript(direct)
	direct.close(t)

	w := f.startWrapped(t, "canary", canaryServer(t))
	got := transcript(w)
	if code := w.close(t); code != 0 {
		t.Fatalf("wrapped exit %d, stderr %q", code, w.errb.String())
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("wrapped output differs from direct (%d vs %d bytes)", len(got), len(want))
	}
	if !bytes.Contains(got, []byte(`"serverInfo":{"name":"watchdeck-canary"`)) {
		t.Errorf("no initialize result in %q", got[:min(len(got), 300)])
	}
	if !strings.Contains(w.errb.String(), "canary mcp server started") {
		t.Errorf("server stderr not forwarded: %q", w.errb.String())
	}
	// One run record for the server's lifetime, written at exit.
	res, err := activity.Read(f.activity, activity.ReadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 1 {
		t.Fatalf("want 1 record, got %d", len(res.Records))
	}
	r := res.Records[0]
	if r.Kind != activity.KindRun || r.Outcome != activity.OutcomeOK || len(r.Skills) != 0 || !strings.Contains(r.Command, "canary_server.py") {
		t.Errorf("record = %+v", r)
	}
	if r.ToolUseID != "" || r.JoinedBy != "" {
		t.Errorf("mcp run must not be correlated: %+v", r)
	}
	if r.Subject == nil || r.Subject.Kind != "mcp" || r.Subject.Name != "canary" || r.Enforcement != activity.EnforcementSandbox {
		t.Errorf("mcp run subject: %+v %q", r.Subject, r.Enforcement)
	}
}

// TestMCPNoAddedLatency: the median echo round trip through the wrapper is
// within a small bound of a direct run. The bytes never pass through the
// wrapper (inherited descriptors), so the bound is generous for noise only.
func TestMCPNoAddedLatency(t *testing.T) {
	f := newFixture(t)
	f.writePolicy(t, launchPolicy)
	const n = 40
	median := func(s *mcpSession) time.Duration {
		s.roundTrip(t, `{"jsonrpc":"2.0","id":0,"method":"initialize","params":{}}`)
		var ds []time.Duration
		for i := 1; i <= n; i++ {
			start := time.Now()
			s.roundTrip(t, mcpCall(i, "echo", map[string]any{"text": fmt.Sprint(i)}))
			ds = append(ds, time.Since(start))
		}
		sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
		return ds[n/2]
	}
	d := startDirect(t, f.cwd, f.environ, canaryServer(t))
	base := median(d)
	d.close(t)
	w := f.startWrapped(t, "canary", canaryServer(t))
	wrapped := median(w)
	w.close(t)
	bound := base + 5*time.Millisecond
	if raceEnabled {
		bound = base + 50*time.Millisecond
	}
	t.Logf("median round trip: direct %v, wrapped %v", base, wrapped)
	if wrapped > bound {
		t.Errorf("wrapped median %v > bound %v (direct %v)", wrapped, bound, base)
	}
}

// TestMCPNetworkDeniedUnlessGranted: network is none by default for an MCP
// launch, even to localhost; launch.grant.network widens it.
func TestMCPNetworkDeniedUnlessGranted(t *testing.T) {
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
	port := ln.Addr().(*net.TCPAddr).Port
	try := func() string {
		w := f.startWrapped(t, "canary", canaryServer(t))
		w.roundTrip(t, `{"jsonrpc":"2.0","id":0,"method":"initialize","params":{}}`)
		out := toolText(t, w.roundTrip(t, mcpCall(1, "net", map[string]any{"host": "127.0.0.1", "port": port})))
		w.close(t)
		return out
	}
	f.writePolicy(t, launchPolicy)
	if got := try(); !strings.HasPrefix(got, "denied") {
		t.Errorf("network none: got %q", got)
	}
	f.writePolicy(t, strings.Replace(launchPolicy, "env: [FAKE_TOKEN]", "env: [FAKE_TOKEN]\n        network: localhost", 1))
	if got := try(); got != "connected" {
		t.Errorf("network localhost granted: got %q", got)
	}
}

// TestMCPEnvLimitedToListedKeys: the server sees PATH HOME LANG TMPDIR, the
// granted env names (the keys of its config env) and the profile marker,
// never another variable of Claude Code's environment.
func TestMCPEnvLimitedToListedKeys(t *testing.T) {
	f := newFixture(t)
	f.writePolicy(t, launchPolicy)
	f.environ = append(f.environ, "FAKE_TOKEN=fake-token-value", "OTHER_SERVER_TOKEN=not-for-this-server", "SSH_AUTH_SOCK=/nonexistent/agent")
	w := f.startWrapped(t, "canary", canaryServer(t))
	w.roundTrip(t, `{"jsonrpc":"2.0","id":0,"method":"initialize","params":{}}`)
	names := strings.Fields(toolText(t, w.roundTrip(t, mcpCall(1, "env", nil))))
	w.close(t)
	has := map[string]bool{}
	for _, n := range names {
		has[n] = true
	}
	for _, n := range []string{"FAKE_TOKEN", "PATH", "HOME", "LANG", "TMPDIR", ProfileEnvVar} {
		if !has[n] {
			t.Errorf("missing %s in %v", n, names)
		}
	}
	for _, n := range []string{"OTHER_SERVER_TOKEN", "CANARY_SECRET", "SSH_AUTH_SOCK"} {
		if has[n] {
			t.Errorf("%s leaked into the server: %v", n, names)
		}
	}
}

// TestMCPClaudeConfigDenied: the server cannot read ~/.claude.json (every
// server's env values live there; ~/.claude does not cover it) nor write
// outside cwd and temp.
func TestMCPClaudeConfigDenied(t *testing.T) {
	f := newFixture(t)
	f.writePolicy(t, launchPolicy)
	cfg := filepath.Join(f.home, ".claude.json")
	if err := os.WriteFile(cfg, []byte(`{"mcpServers":{"x":{"command":"fake","env":{"K":"fake-value"}}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(cfg+".backup", []byte(`{"fake":"backup"}`), 0o600)
	w := f.startWrapped(t, "canary", canaryServer(t))
	w.roundTrip(t, `{"jsonrpc":"2.0","id":0,"method":"initialize","params":{}}`)
	readCfg := toolText(t, w.roundTrip(t, mcpCall(1, "read", map[string]any{"path": cfg})))
	writeHome := toolText(t, w.roundTrip(t, mcpCall(2, "write", map[string]any{"path": filepath.Join(f.home, "planted")})))
	writeCwd := toolText(t, w.roundTrip(t, mcpCall(3, "write", map[string]any{"path": filepath.Join(f.cwd, "ok")})))
	readBackup := toolText(t, w.roundTrip(t, mcpCall(4, "read", map[string]any{"path": cfg + ".backup"})))
	w.close(t)
	if !strings.HasPrefix(readCfg, "denied") {
		t.Errorf("read ~/.claude.json: %q", readCfg)
	}
	if !strings.HasPrefix(readBackup, "denied") {
		t.Errorf("read ~/.claude.json.backup: %q", readBackup)
	}
	if !strings.HasPrefix(writeHome, "denied") {
		t.Errorf("write home: %q", writeHome)
	}
	if writeCwd != "wrote" {
		t.Errorf("write cwd: %q", writeCwd)
	}
}

// TestMCPNeedsExactLaunchSubject: no subject, a gate-only subject, or a
// "*" / glob subject with a launch block all refuse to start (125), with a
// policy_error record; the server never runs.
func TestMCPNeedsExactLaunchSubject(t *testing.T) {
	f := newFixture(t)
	marker := filepath.Join(f.cwd, "ran")
	argv := []string{"/usr/bin/touch", marker}
	for name, body := range map[string]string{
		"none":      "",
		"gate-only": "version: 2\nsubjects:\n  - {kind: mcp, name: canary, tools: {'delete_*': deny}}\n",
		"star":      "version: 2\nsubjects:\n  - {kind: mcp, name: '*', launch: {sandbox: true, grant: {network: all}}}\n",
		"glob":      "version: 2\nsubjects:\n  - {kind: mcp, name: 'can*', launch: {sandbox: true}}\n",
		"off":       "version: 2\nsubjects:\n  - {kind: mcp, name: canary, launch: {sandbox: false}}\n",
	} {
		os.Remove(filepath.Join(f.cfg, "overrides.yaml"))
		if body != "" {
			f.writePolicy(t, body)
		}
		var errb bytes.Buffer
		code := RunMCP(context.Background(), MCPOptions{Server: "canary", Argv: argv, Env: f.env, Environ: f.environ,
			Stdin: strings.NewReader(""), Stdout: &bytes.Buffer{}, Stderr: &errb, ActivityPath: f.activity})
		if code != ExitPolicy {
			t.Errorf("%s: exit %d, want 125; stderr %q", name, code, errb.String())
		}
		if !strings.Contains(errb.String(), "no launch policy for MCP server canary") {
			t.Errorf("%s: stderr %q", name, errb.String())
		}
		if _, err := os.Stat(marker); err == nil {
			t.Fatalf("%s: the server ran", name)
		}
		r := f.lastRun(t)
		if r.Outcome != activity.OutcomePolicyError {
			t.Errorf("%s: outcome %q", name, r.Outcome)
		}
	}
}

// TestMCPInvalidServerName refuses names the policy file cannot hold.
func TestMCPInvalidServerName(t *testing.T) {
	f := newFixture(t)
	for _, n := range []string{"*", "-x", "a b", ""} {
		code := RunMCP(context.Background(), MCPOptions{Server: n, Argv: []string{"/usr/bin/true"}, Env: f.env, Environ: f.environ,
			Stdin: strings.NewReader(""), Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}})
		if code != ExitPolicy {
			t.Errorf("%q: exit %d", n, code)
		}
	}
}

// TestMCPRelocatedClaudeConfigDirDenied: with CLAUDE_CONFIG_DIR outside
// ~/.claude, its .claude.json and the rest of the dir (Claude Code's own
// config backups, settings, transcripts) are denied too.
func TestMCPRelocatedClaudeConfigDirDenied(t *testing.T) {
	f := newFixture(t)
	f.writePolicy(t, launchPolicy)
	cd := filepath.Join(f.home, "relocated-claude")
	os.MkdirAll(filepath.Join(cd, "backups"), 0o700)
	os.WriteFile(filepath.Join(cd, ".claude.json"), []byte(`{"mcpServers":{}}`), 0o600)
	os.WriteFile(filepath.Join(cd, "backups", ".claude.json.backup.1"), []byte(`{"fake":true}`), 0o600)
	f.environ = append(f.environ, "CLAUDE_CONFIG_DIR="+cd)
	w := f.startWrapped(t, "canary", canaryServer(t))
	w.roundTrip(t, `{"jsonrpc":"2.0","id":0,"method":"initialize","params":{}}`)
	a := toolText(t, w.roundTrip(t, mcpCall(1, "read", map[string]any{"path": filepath.Join(cd, ".claude.json")})))
	b := toolText(t, w.roundTrip(t, mcpCall(2, "read", map[string]any{"path": filepath.Join(cd, "backups", ".claude.json.backup.1")})))
	w.close(t)
	if !strings.HasPrefix(a, "denied") || !strings.HasPrefix(b, "denied") {
		t.Errorf("relocated config readable: %q %q", a, b)
	}
}
