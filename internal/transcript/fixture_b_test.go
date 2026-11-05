package transcript

import (
	"testing"
)

// Fixture B is SYNTHETIC: shape as assumed on 2026-10-12, not verified against
// Claude Code. See testdata/synthetic-subagents/README.md.

func TestFixtureBAgentsAndSpawnLinks(t *testing.T) {
	s := loadB(t)
	if s.SkippedLines != 0 || s.SkippedFiles != 0 || s.Truncated {
		t.Fatalf("skipped %d files %d truncated %v", s.SkippedLines, s.SkippedFiles, s.Truncated)
	}
	if len(s.Agents) != 4 {
		t.Fatalf("agents: %+v", s.Agents)
	}
	main := s.Agents[0]
	if main.ID != MainAgentID || main.Calls != 6 || main.Model != "claude-opus-5-5" {
		t.Errorf("main: %+v", main)
	}
	// ordered by first timestamp: sub1 (10:00:06), sub2 (10:00:06.5), sidechain (10:00:08)
	sub1, sub2, sc := s.Agents[1], s.Agents[2], s.Agents[3]
	if sub1.ID != "b000000000000001" || sub1.SpawnLink != "meta" || sub1.SpawnedBy != "toolu_B03" || sub1.Type != "Explore" || sub1.Name != "Find TODOs" || sub1.Model != "claude-opus-5-5" || sub1.Calls != 3 {
		t.Errorf("sub1 (meta link): %+v", sub1)
	}
	if sub2.ID != "b000000000000002" || sub2.SpawnLink != "order" || sub2.SpawnedBy != "" || sub2.Model != "claude-sonnet-4-5" || sub2.Calls != 2 {
		t.Errorf("sub2 (order link): %+v", sub2)
	}
	if sub2.Type != "" || sub2.Name != "" {
		t.Errorf("an order-based guess must not borrow the call's type or name: %+v", sub2)
	}
	if sc.ID != "b1000000-0000-4000-8000-0000000000c1" || !sc.Sidechain || sc.Kind != "subagent" || sc.SpawnLink != "" || sc.Model != "claude-sonnet-4-5" || sc.Calls != 1 {
		t.Errorf("legacy sidechain: %+v", sc)
	}
	if c := s.Call("toolu_B06"); c == nil || c.Agent != sc.ID {
		t.Errorf("sidechain Grep attributed to %+v", c)
	}
	if len(s.Prompts) != 1 {
		t.Errorf("sidechain prompts must not count as main prompts: %+v", s.Prompts)
	}

	sp1, sp2 := s.Call("toolu_B03").ToolCall.Spawn, s.Call("toolu_B04").ToolCall.Spawn
	if sp1.AgentID != sub1.ID || sp1.Confidence != "meta" || sp1.SubagentType != "Explore" {
		t.Errorf("spawn 1: %+v", sp1)
	}
	if sp2.AgentID != sub2.ID || sp2.Confidence != "order" || sp2.SubagentType != "general-purpose" {
		t.Errorf("spawn 2: %+v", sp2)
	}
	if r := s.Result("toolu_B03"); r == nil || r.Kind != "return" {
		t.Errorf("return 1: %+v", r)
	}
	if r := s.Result("toolu_B04"); r == nil || r.Kind != "return" {
		t.Errorf("return 2: %+v", r)
	}
}

func TestFixtureBResultLinkWithoutMeta(t *testing.T) {
	// Remove the meta file: sub1 must still link through toolUseResult.agentId.
	projects := fixtureProjects(t, "synthetic-subagents")
	tmp := t.TempDir() + "/projects"
	copyTree(t, projects, tmp)
	if err := removeFile(tmp + "/-Users-you-proj-b/" + sessionB + "/subagents/agent-b000000000000001.meta.json"); err != nil {
		t.Fatal(err)
	}
	s, err := Load(mainPath(tmp, "-Users-you-proj-b", sessionB), Options{ProjectsDir: tmp})
	if err != nil {
		t.Fatal(err)
	}
	a := s.AgentByID("b000000000000001")
	if a == nil || a.SpawnLink != "result" || a.SpawnedBy != "toolu_B03" || a.Type != "Explore" || a.Name != "Find TODOs" {
		t.Errorf("result link: %+v", a)
	}
	b := s.AgentByID("b000000000000002")
	if b == nil || b.SpawnLink != "order" || b.SpawnedBy != "" {
		t.Errorf("order link: %+v", b)
	}
}

func TestFixtureBHookAskWithRewrite(t *testing.T) {
	s := loadB(t)
	tc := s.Call("toolu_B01").ToolCall
	if tc.HookDecision != "ask" || tc.HookRewrite != "watchdeck run --skill canary-request -c 'python3 .claude/skills/canary-request/scripts/probe.py net'" {
		t.Errorf("hook: %+v", tc)
	}
	if r := s.Result("toolu_B01"); r == nil || r.Snippet != "net: DENIED(1)" || r.IsError {
		t.Errorf("result: %+v", r)
	}
	if r := s.Result("toolu_B21"); r == nil || r.Snippet != " 1 file changed, 2 insertions(+)" {
		t.Errorf("subagent bash snippet: %+v", r)
	}
	if r := s.Result("toolu_B11"); r == nil || r.Snippet != "" {
		t.Errorf("grep result must carry no snippet: %+v", r)
	}
}

func TestFixtureBMCPAndSkill(t *testing.T) {
	s := loadB(t)
	mcp := s.Call("toolu_B05")
	if mcp == nil || mcp.Kind != "tool_use" || mcp.ToolCall.MCPServer != "playwright" || mcp.ToolCall.MCPTool != "browser_navigate" {
		t.Errorf("mcp: %+v %+v", mcp, mcp.ToolCall)
	}
	sk := s.Call("toolu_B07")
	if sk == nil || sk.Kind != "skill_invoked" || sk.ToolCall.Skill != "canary-prose" || !sk.IsCall() {
		t.Errorf("skill: %+v %+v", sk, sk.ToolCall)
	}
	if n := countKind(s, "skill_invoked"); n != 1 {
		t.Errorf("skill_invoked events: %d", n)
	}
	want := map[string]int{"Bash": 2, "Read": 2, "Agent": 2, "mcp__playwright__browser_navigate": 1, "Grep": 2, "Skill": 1, "SubagentHandback": 2}
	got := toolNames(s)
	for k, v := range want {
		if got[k] != v {
			t.Errorf("tool %s: got %d want %d", k, got[k], v)
		}
	}
	if len(got) != len(want) {
		t.Errorf("tools: %v", got)
	}
}

func TestMCPSplit(t *testing.T) {
	cases := map[string][2]string{
		"mcp__playwright__browser_navigate": {"playwright", "browser_navigate"},
		"mcp__claude_ai_Claude_Docs__read":  {"claude_ai_Claude_Docs", "read"},
		"mcp__a__b__c":                      {"a", "b__c"},
		"mcp__nounderscore":                 {"", ""},
		"Bash":                              {"", ""},
	}
	for name, want := range cases {
		ld := newLoader(Options{}, "", "x", "x")
		ld.toolUse(&rawBlock{Type: "tool_use", ID: "t", Name: name}, ld.agent(MainAgentID), mustTS("2026-10-12T10:00:00Z"))
		tc := ld.calls["t"]
		if tc.MCPServer != want[0] || tc.MCPTool != want[1] {
			t.Errorf("%s: got %q/%q want %q/%q", name, tc.MCPServer, tc.MCPTool, want[0], want[1])
		}
	}
}
