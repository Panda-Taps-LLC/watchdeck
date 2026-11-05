package transcript

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Fixture A is a real capture (2026-10-12); see testdata/e2e-canary/README.md.

func TestLoadFixtureA(t *testing.T) {
	s := loadA(t)
	if s.ID != sessionA || s.Cwd != "/Users/you/proj" || s.Version != "2.1.296" {
		t.Fatalf("id/cwd/version: %q %q %q", s.ID, s.Cwd, s.Version)
	}
	if s.Truncated || s.SkippedLines != 0 || s.SkippedFiles != 0 {
		t.Fatalf("truncated=%v skipped=%d files=%d", s.Truncated, s.SkippedLines, s.SkippedFiles)
	}
	if len(s.Agents) != 2 || s.Agents[0].ID != MainAgentID || s.Agents[0].Kind != "main" || s.Agents[1].ID != subagentA || s.Agents[1].Kind != "subagent" {
		t.Fatalf("agents: %+v", s.Agents)
	}
	main, sub := s.Agents[0], s.Agents[1]
	if main.Model != "claude-opus-5-5" || sub.Model != "claude-opus-5-5" {
		t.Errorf("models: %q %q", main.Model, sub.Model)
	}
	if main.Calls != 3 || sub.Calls != 3 {
		t.Errorf("calls: main %d sub %d", main.Calls, sub.Calls)
	}
	if sub.Type != "Explore" || sub.Name != "Count 'canary' occurrences" || sub.SpawnedBy != agentA || sub.SpawnLink != "meta" || sub.Sidechain {
		t.Errorf("subagent link: %+v", sub)
	}
	if filepath.Base(sub.File) != "agent-"+subagentA+".jsonl" {
		t.Errorf("subagent file: %s", sub.File)
	}

	want := map[string]int{"Bash": 2, "Read": 1, "Agent": 1, "Grep": 1, "SubagentHandback": 1}
	if got := toolNames(s); len(got) != len(want) {
		t.Errorf("tool names: %v", got)
	} else {
		for k, v := range want {
			if got[k] != v {
				t.Errorf("tool %s: got %d want %d", k, got[k], v)
			}
		}
	}
	if countKind(s, "prompt") != 1 || len(s.Prompts) != 1 || !strings.HasPrefix(s.Prompts[0].Summary, "Do exactly three things") || len(s.Prompts[0].Summary) > 120 {
		t.Errorf("prompts: %+v", s.Prompts)
	}
	if countKind(s, "spawn") != 1 || countKind(s, "return") != 1 || countKind(s, "tool_use") != 5 || countKind(s, "tool_result") != 5 {
		t.Errorf("kinds: spawn %d return %d tool_use %d tool_result %d", countKind(s, "spawn"), countKind(s, "return"), countKind(s, "tool_use"), countKind(s, "tool_result"))
	}

	bash := s.Call(bashA)
	if bash == nil || bash.Agent != MainAgentID || bash.ToolCall.Command != "python3 .claude/skills/canary-basic/scripts/probe.py net" {
		t.Fatalf("bash call: %+v", bash)
	}
	res := s.Result(bashA)
	if res == nil || res.IsError || res.Snippet != "net: DENIED(1)" || res.Kind != "tool_result" {
		t.Fatalf("bash result: %+v", res)
	}
	if r := s.Result(readA); r == nil || r.Snippet != "" {
		t.Errorf("read result must carry no snippet: %+v", r)
	}
	if c := s.Call(readA); c == nil || c.ToolCall.Path != "/Users/you/proj/.claude/skills/canary-basic/SKILL.md" {
		t.Errorf("read call: %+v", c)
	}
	sp := s.Call(agentA)
	if sp == nil || sp.Kind != "spawn" || sp.ToolCall.Spawn == nil || sp.ToolCall.Spawn.SubagentType != "Explore" || sp.ToolCall.Spawn.AgentID != subagentA || sp.ToolCall.Spawn.Confidence != "meta" {
		t.Fatalf("spawn call: %+v %+v", sp, sp.ToolCall.Spawn)
	}
	if r := s.Result(agentA); r == nil || r.Kind != "return" || r.Snippet != "" {
		t.Errorf("return: %+v", r)
	}
	for _, id := range []string{grepA, subBashA, handbackA} {
		if c := s.Call(id); c == nil || c.Agent != subagentA {
			t.Errorf("%s should belong to the subagent: %+v", id, c)
		}
	}
	if r := s.Result(subBashA); r == nil || !strings.HasPrefix(r.Snippet, "/Users/you/proj/.claude/skills/canary-basic/scripts/probe.py:3") {
		t.Errorf("subagent bash snippet: %+v", r)
	}

	started, _ := time.Parse(time.RFC3339Nano, "2026-10-13T02:18:31.678Z")
	last, _ := time.Parse(time.RFC3339Nano, "2026-10-13T02:18:56.536Z")
	if !s.Started.Equal(started) || !s.LastEvent.Equal(last) {
		t.Errorf("started %v last %v", s.Started, s.LastEvent)
	}
	if !sub.SpawnTS.Equal(mustTS("2026-10-13T02:18:40.962Z")) || !sub.EndTS.Equal(mustTS("2026-10-13T02:18:52.097Z")) {
		t.Errorf("subagent span %v..%v", sub.SpawnTS, sub.EndTS)
	}
	// Events are merged in time order across files: the subagent's Grep (02:18:43) sits
	// between the main Read result (02:18:39) and the Agent return (02:18:52).
	var order []string
	for _, e := range s.Events {
		if e.IsCall() {
			order = append(order, e.ToolCall.ID)
		}
	}
	if strings.Join(order, ",") != strings.Join([]string{bashA, readA, agentA, grepA, subBashA, handbackA}, ",") {
		t.Errorf("call order: %v", order)
	}
	for i := 1; i < len(s.Events); i++ {
		if s.Events[i].TS.Before(s.Events[i-1].TS) {
			t.Fatalf("events not time ordered at %d", i)
		}
	}
}

func mustTS(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		panic(err)
	}
	return t
}

func TestHookSuccessAttachmentParsed(t *testing.T) {
	s := loadA(t)
	tc := s.Call(bashA).ToolCall
	if tc.HookDecision != "allow" {
		t.Errorf("decision %q", tc.HookDecision)
	}
	want := "watchdeck run --skill canary-basic -c 'python3 .claude/skills/canary-basic/scripts/probe.py net'"
	if tc.HookRewrite != want {
		t.Errorf("rewrite %q", tc.HookRewrite)
	}
	if !strings.HasPrefix(tc.HookReason, "watchdeck: canary-basic has no PERMISSIONS.yaml") {
		t.Errorf("reason %q", tc.HookReason)
	}
	// The command itself is the model's original, never the rewrite (V3).
	if strings.HasPrefix(tc.Command, "watchdeck run") {
		t.Errorf("command must be the original: %q", tc.Command)
	}
	// Calls answered only by unrelated hooks (plain-text stdout) carry no decision.
	for _, id := range []string{readA, agentA, grepA, subBashA, handbackA} {
		if c := s.Call(id).ToolCall; c.HookDecision != "" || c.HookRewrite != "" {
			t.Errorf("%s: unexpected hook fields %+v", id, c)
		}
	}
}

// TestOnlyHookSuccessAttachmentsRetained checks the committed fixture itself:
// the scrub kept only hook_success attachments and removed the named fields.
func TestOnlyHookSuccessAttachmentsRetained(t *testing.T) {
	root := filepath.Join("testdata", "e2e-canary")
	files := 0
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(p, ".jsonl") {
			return err
		}
		files++
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 1<<20), 4<<20)
		n := 0
		for sc.Scan() {
			n++
			line := sc.Text()
			var row map[string]any
			if err := json.Unmarshal([]byte(line), &row); err != nil {
				t.Errorf("%s:%d not JSON: %v", p, n, err)
				continue
			}
			switch row["type"] {
			case "attachment":
				att, _ := row["attachment"].(map[string]any)
				name, _ := att["hookName"].(string)
				stdout, _ := att["stdout"].(string)
				if att["type"] != "hook_success" || !strings.HasPrefix(name, "PreToolUse:") || !strings.Contains(stdout, "watchdeck") {
					t.Errorf("%s:%d attachment %v %q survived the scrub; only watchdeck's PreToolUse rows may", p, n, att["type"], name)
				}
			case "cost-state", "atis-latch", "last-prompt", "queue-operation":
				t.Errorf("%s:%d bookkeeping row %v survived the scrub", p, n, row["type"])
			case "system":
				if row["subtype"] == "stop_hook_summary" {
					t.Errorf("%s:%d stop_hook_summary survived the scrub", p, n)
				}
			}
			for _, bad := range []string{"serverClassifierContext", "organizationUuid", "prompt_snapshot", "credential_org", "sk-ant-", "AKIA", ".app/Contents", "scratchpad", "/private/", "/tmp/", "serverClassifierRequest", "[scrubbed"} {
				if strings.Contains(strings.ToLower(line), strings.ToLower(bad)) {
					t.Errorf("%s:%d contains %q", p, n, bad)
				}
			}
			// no thinking block and no signature blob anywhere (opaque, account-linked)
			if bad := findThinking(row); bad != "" {
				t.Errorf("%s:%d contains %s", p, n, bad)
			}
			// every home path is the scrubbed /Users/you, in plain and escaped form
			if home := otherHome(line); home != "" {
				t.Errorf("%s:%d names a home dir other than /Users/you: %q", p, n, home)
			}
			if strings.Contains(strings.ReplaceAll(line, "you@example.com", ""), "@") {
				t.Errorf("%s:%d contains an email or handle", p, n)
			}
		}
		return sc.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	if files != 4 { // main, subagent, hook-stdin, lifecycle-stdin (M5.2)
		t.Errorf("expected 4 jsonl files in the fixture, found %d", files)
	}
}

// TestHookStdinIdsMatchTranscript is the join contract (V2): every tool_use_id
// the hook saw is a tool_use.id in the main or a subagent file, transcript_path
// names the main file, and agent_id resolves to the subagent file.
func TestHookStdinIdsMatchTranscript(t *testing.T) {
	for _, tc := range []struct {
		dir, session, escaped string
		lines                 int
		subagent              bool
	}{
		{"e2e-canary", sessionA, "-Users-you-proj", 2, true},
		{"e2e-deny", "d484a6af-2106-45c4-9d15-1c2212b76809", "-Users-you-proj", 4, false},
	} {
		t.Run(tc.dir, func(t *testing.T) { checkHookStdinIds(t, tc.dir, tc.session, tc.escaped, tc.lines, tc.subagent) })
	}
}

func checkHookStdinIds(t *testing.T, dir, session, escaped string, wantLines int, wantSubagent bool) {
	projects := fixtureProjects(t, dir)
	s, err := Load(mainPath(projects, escaped, session), Options{ProjectsDir: projects})
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(filepath.Join("testdata", dir, "hook-stdin.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	type hookIn struct {
		SessionID      string `json:"session_id"`
		ToolUseID      string `json:"tool_use_id"`
		TranscriptPath string `json:"transcript_path"`
		Cwd            string `json:"cwd"`
		AgentID        string `json:"agent_id"`
		AgentType      string `json:"agent_type"`
		ToolName       string `json:"tool_name"`
		ToolInput      struct {
			Command string `json:"command"`
		} `json:"tool_input"`
	}
	sc := bufio.NewScanner(f)
	n, subagentSeen := 0, false
	for sc.Scan() {
		n++
		var h hookIn
		if err := json.Unmarshal(sc.Bytes(), &h); err != nil {
			t.Fatal(err)
		}
		if h.SessionID != s.ID {
			t.Errorf("line %d: session %q", n, h.SessionID)
		}
		// transcript_path is the MAIN file for both calls; rebase it through the fixture root instead of touching /Users/you.
		if filepath.Base(h.TranscriptPath) != s.ID+".jsonl" {
			t.Errorf("line %d: transcript_path %q does not name the main file", n, h.TranscriptPath)
		}
		if filepath.Base(filepath.Dir(h.TranscriptPath)) != EscapeProjectDir(h.Cwd) {
			t.Errorf("line %d: escaped dir %q != EscapeProjectDir(%q)", n, filepath.Base(filepath.Dir(h.TranscriptPath)), h.Cwd)
		}
		call := s.Call(h.ToolUseID)
		if call == nil {
			t.Fatalf("line %d: tool_use_id %s not in the transcript", n, h.ToolUseID)
		}
		if call.ToolCall.Name != h.ToolName || call.ToolCall.Command != h.ToolInput.Command {
			t.Errorf("line %d: call %+v != hook %+v", n, call.ToolCall, h)
		}
		if h.AgentID == "" {
			if call.Agent != MainAgentID {
				t.Errorf("line %d: no agent_id but call belongs to %s", n, call.Agent)
			}
			continue
		}
		subagentSeen = true
		a := s.AgentByID(h.AgentID)
		if a == nil || a.ID != h.AgentID || call.Agent != a.ID || a.Type != h.AgentType {
			t.Errorf("line %d: agent_id %s / %s does not resolve: agent %+v call %+v", n, h.AgentID, h.AgentType, a, call)
		}
		if filepath.Base(a.File) != "agent-"+h.AgentID+".jsonl" {
			t.Errorf("line %d: agent file %s", n, a.File)
		}
	}
	if n != wantLines || subagentSeen != wantSubagent {
		t.Errorf("expected %d hook stdin lines (subagent call %v), got %d (subagent %v)", wantLines, wantSubagent, n, subagentSeen)
	}
}

// TestCompactRetention: nothing from assistant text, thinking signatures or
// non-Bash tool results reaches the Session.
func TestCompactRetention(t *testing.T) {
	s := loadA(t)
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	out := string(b)
	for _, leak := range []string{
		"I did all three steps",     // assistant text
		"Probes which capabilities", // the Read result (SKILL.md contents)
		"Found 5 total occurrences", // Grep result
		"cache_read_input_tokens",   // usage
	} {
		if strings.Contains(out, leak) {
			t.Errorf("session retains %q", leak)
		}
	}
	for _, e := range s.Events {
		if e.Snippet != "" && len(e.Snippet) > 240 {
			t.Errorf("snippet over 240: %d", len(e.Snippet))
		}
		if e.IsCall() && len(e.ToolCall.Command) > 512 {
			t.Errorf("command over 512")
		}
	}
}

func TestAgentByIDAcceptsFileStem(t *testing.T) {
	s := loadA(t)
	if s.AgentByID("agent-"+subagentA) == nil || s.AgentByID(subagentA) == nil || s.AgentByID("nope") != nil {
		t.Error("AgentByID")
	}
}

// otherHome returns the first "/Users/<name>" or "-Users-<name>" whose name is
// not "you", or "". It keeps the capturing user's login out of the fixture
// without naming it here.
func otherHome(line string) string {
	for _, prefix := range []string{"/Users/", "-Users-"} {
		rest := line
		for {
			i := strings.Index(rest, prefix)
			if i < 0 {
				break
			}
			rest = rest[i+len(prefix):]
			if !strings.HasPrefix(rest, "you") || (len(rest) > 3 && rest[3] != '/' && rest[3] != '-' && rest[3] != '"' && rest[3] != '\\' && rest[3] != '\'' && rest[3] != ' ' && rest[3] != ':') {
				end := len(rest)
				if end > 24 {
					end = 24
				}
				return prefix + rest[:end]
			}
		}
	}
	return ""
}

func TestOtherHome(t *testing.T) {
	cases := map[string]string{
		`"cwd":"/Users/you/proj"`:            "",
		`"x":"-Users-you-proj"`:              "",
		`"x":"/Users/you"`:                   "",
		`"x":"/Users/someone/proj"`:          "/Users/someone/proj\"",
		`"x":"-Users-someone-proj"`:          "-Users-someone-proj\"",
		`"x":"/Users/youngster/a"`:           "/Users/youngster/a\"",
		`a /Users/you/x then /Users/other/y`: "/Users/other/y",
	}
	for in, want := range cases {
		if got := otherHome(in); got != want {
			t.Errorf("otherHome(%q) = %q want %q", in, got, want)
		}
	}
}

// findThinking reports a "signature" key or a thinking block anywhere in v, or "".
func findThinking(v any) string {
	switch x := v.(type) {
	case map[string]any:
		if _, ok := x["signature"]; ok {
			return "a signature key"
		}
		if x["type"] == "thinking" || x["type"] == "redacted_thinking" {
			return "a thinking block"
		}
		for _, e := range x {
			if r := findThinking(e); r != "" {
				return r
			}
		}
	case []any:
		for _, e := range x {
			if r := findThinking(e); r != "" {
				return r
			}
		}
	}
	return ""
}

func TestFindThinking(t *testing.T) {
	var withSig, withBlock, clean any
	_ = json.Unmarshal([]byte(`{"message":{"content":[{"type":"text","signature":"x"}]}}`), &withSig)
	_ = json.Unmarshal([]byte(`{"message":{"content":[{"type":"thinking","thinking":""}]}}`), &withBlock)
	_ = json.Unmarshal([]byte(`{"message":{"content":[{"type":"text","text":"thinking"}]}}`), &clean)
	if findThinking(withSig) == "" || findThinking(withBlock) == "" || findThinking(clean) != "" {
		t.Error("findThinking")
	}
}
