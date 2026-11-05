package transcript

import "sort"

// linkSpawns ties each subagent to the parent's Agent call, by decreasing
// certainty:
//
//  1. "meta":   agent-<id>.meta.json names the call (toolUseId).
//  2. "result": the parent's tool_result row for an Agent call carried
//     toolUseResult.agentId (seen in the 2026-10-12 capture; needs no meta file).
//  3. "order":  the k-th unlinked Agent call, by (timestamp, load order), is
//     paired with the k-th unlinked subagent, by first timestamp. This is a
//     guess: the call's Spawn.AgentID and the agent's SpawnLink say "order",
//     and Agent.SpawnedBy stays empty so no consumer draws a certain edge
//     from it.
//
// Agents that remain unlinked (their spawn was before a tail read, or the
// parent file is missing) keep SpawnLink "".
func (ld *loader) linkSpawns() {
	var subs []*Agent
	for _, id := range ld.agentOrder {
		if id != MainAgentID {
			subs = append(subs, ld.agents[id])
		}
	}
	sort.SliceStable(subs, func(i, j int) bool { return tsLess(subs[i].SpawnTS, subs[j].SpawnTS, subs[i].ID < subs[j].ID) })
	calls := append([]spawnRef(nil), ld.spawnCalls...)
	sort.SliceStable(calls, func(i, j int) bool { return tsLess(calls[i].ts, calls[j].ts, calls[i].seq < calls[j].seq) })

	linkedCall := map[string]bool{}
	linkedAgent := map[string]bool{}
	link := func(a *Agent, tc *ToolCall, how string) {
		a.SpawnedBy, a.SpawnLink = tc.ID, how
		tc.Spawn.AgentID, tc.Spawn.Confidence = a.ID, how
		if a.Type == "" {
			a.Type = tc.Spawn.SubagentType
		}
		if a.Name == "" {
			a.Name = truncate(tc.Spawn.Description, nameLen)
		}
		linkedCall[tc.ID], linkedAgent[a.ID] = true, true
	}

	for _, a := range subs {
		m := ld.meta[a.ID]
		if m == nil || m.ToolUseID == "" {
			continue
		}
		tc := ld.calls[m.ToolUseID]
		if tc == nil || tc.Spawn == nil || linkedCall[tc.ID] {
			continue
		}
		link(a, tc, "meta")
	}
	for _, sr := range calls {
		if linkedCall[sr.tc.ID] {
			continue
		}
		r, ok := ld.results[sr.tc.ID]
		if !ok || r.AgentID == "" {
			continue
		}
		a := ld.agents[r.AgentID]
		if a == nil || a.Kind != "subagent" || linkedAgent[a.ID] {
			continue
		}
		link(a, sr.tc, "result")
	}
	var freeCalls []*ToolCall
	for _, sr := range calls {
		if !linkedCall[sr.tc.ID] {
			freeCalls = append(freeCalls, sr.tc)
		}
	}
	var freeSubs []*Agent
	for _, a := range subs {
		if !linkedAgent[a.ID] {
			freeSubs = append(freeSubs, a)
		}
	}
	for i := 0; i < len(freeCalls) && i < len(freeSubs); i++ {
		freeCalls[i].Spawn.AgentID, freeCalls[i].Spawn.Confidence = freeSubs[i].ID, "order"
		freeSubs[i].SpawnLink = "order"
	}
}
