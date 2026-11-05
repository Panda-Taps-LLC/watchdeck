package mapmodel

import (
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/activity"
	"github.com/Panda-Taps-LLC/watchdeck/internal/manifest"
	"github.com/Panda-Taps-LLC/watchdeck/internal/transcript"
)

// Synthetic sessions and records for the unit tests. Fake ids and paths only.

const sidS = "c0000000-0000-4000-8000-00000000000c"

var t0 = time.Date(2026, 10, 12, 14, 31, 8, 0, time.UTC)

func at(sec float64) time.Time { return t0.Add(time.Duration(sec * float64(time.Second))) }

// sess builds a session from events; Seq follows slice order.
type sess struct {
	s *transcript.Session
}

func newSess() *sess {
	return &sess{s: &transcript.Session{
		ID: sidS, Cwd: "/Users/you/proj", Started: t0, LastEvent: t0,
		Agents: []transcript.Agent{{ID: transcript.MainAgentID, Kind: "main", Model: "claude-opus-5-5"}},
	}}
}

func (b *sess) push(e transcript.Event) *sess {
	e.Seq = len(b.s.Events) + 1
	b.s.Events = append(b.s.Events, e)
	if e.TS.After(b.s.LastEvent) {
		b.s.LastEvent = e.TS
	}
	return b
}

func (b *sess) prompt(sec float64, text string) *sess {
	b.s.Prompts = append(b.s.Prompts, transcript.Prompt{TS: at(sec), Summary: text})
	return b.push(transcript.Event{TS: at(sec), Agent: transcript.MainAgentID, Kind: "prompt"})
}

func (b *sess) call(sec float64, agent, id, name, cmd string) *sess {
	tc := &transcript.ToolCall{ID: id, Name: name, Command: cmd}
	tc.MCPServer, tc.MCPTool = splitMCP(name)
	return b.push(transcript.Event{TS: at(sec), Agent: agent, Kind: "tool_use", ToolCall: tc})
}

func (b *sess) hook(id, decision, rewrite string) *sess {
	for i := range b.s.Events {
		if tc := b.s.Events[i].ToolCall; tc != nil && tc.ID == id {
			tc.HookDecision, tc.HookRewrite = decision, rewrite
		}
	}
	return b
}

func (b *sess) result(sec float64, agent, id, text string, isErr bool) *sess {
	return b.push(transcript.Event{TS: at(sec), Agent: agent, Kind: "tool_result", ResultFor: id, Snippet: text, IsError: isErr})
}

func (b *sess) sub(id, typ string, spawnSec, endSec float64, spawnCall string) *sess {
	b.s.Agents = append(b.s.Agents, transcript.Agent{ID: id, Kind: "subagent", Type: typ, Model: "claude-sonnet-5-5", SpawnTS: at(spawnSec), EndTS: at(endSec), SpawnedBy: spawnCall, SpawnLink: "meta"})
	b.push(transcript.Event{TS: at(spawnSec - 0.5), Agent: transcript.MainAgentID, Kind: "spawn",
		ToolCall: &transcript.ToolCall{ID: spawnCall, Name: "Agent", Spawn: &transcript.Spawn{SubagentType: typ, AgentID: id, Confidence: "meta"}}})
	return b
}

func (b *sess) ret(sec float64, spawnCall string) *sess {
	return b.push(transcript.Event{TS: at(sec), Agent: transcript.MainAgentID, Kind: "return", ResultFor: spawnCall})
}

const probeNet = "python3 .claude/skills/canary-request/scripts/probe.py net"

func rewriteOf(skill, cmd string) string {
	return "watchdeck run --skill " + skill + " -c '" + cmd + "'"
}

// dec is a decision record with a rewrite (confidence high).
func dec(id string, sec float64, decision, skill, cmd string) activity.Record {
	return activity.Record{V: 1, Kind: activity.KindDecision, TS: fmtTS(at(sec)), SessionID: sidS, ToolUseID: id, Cwd: "/Users/you/proj",
		Skills: []string{skill}, Command: cmd, Decision: decision, Rewritten: rewriteOf(skill, cmd), Confidence: "high"}
}

// run is a run record joined at write time to id ("" = not joined).
func run(id string, sec float64, outcome string, exit int, skill, cmd string, hints ...activity.Hint) activity.Record {
	r := activity.Record{V: 1, Kind: activity.KindRun, TS: fmtTS(at(sec)), SessionID: sidS, ToolUseID: id, Cwd: "/Users/you/proj",
		Skills: []string{skill}, Command: cmd, Exit: intp(exit), Outcome: outcome, DurationMS: 400, Backend: "seatbelt", Hints: hints}
	v := manifest.Default().View()
	r.Effective = &v
	if id != "" {
		r.JoinedBy = activity.JoinedByWrite
	} else {
		r.SessionID = ""
	}
	return r
}

func netHint() activity.Hint {
	return activity.Hint{Kind: activity.HintNetwork, Errno: 1, Line: "net: DENIED(1)", Stream: "stdout", Label: "net", Text: "refused", Heuristic: true}
}
