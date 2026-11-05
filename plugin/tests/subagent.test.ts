// Subagents (Spec C §1.4 step 6): a node per spawn, its calls counted under
// it, collapsed by default, done when its turn completes.

import { expect, mock, test } from 'claude-code/testing'

import { calls, ENV, startSession, world } from './harness.ts'

type AgentNode = { kind: 'agent'; id: string; toolUseId: string; type: string; description: string; calls: number; status: string }

const agent = (state: Record<string, unknown>) =>
  ((state['nodes'] ?? []) as Array<{ kind: string }>).find((n): n is AgentNode => n.kind === 'agent')

test('a subagent collects its calls and is done at its turn.complete', async ($, on) => {
  mock.env(on, ENV)
  mock.store(on)
  const w = world(on)
  await startSession($)
  await $.turn.start({ text: 'look around the canaries', turnId: 't1' })
  const r = await $.agent.spawn({
    tool_use_id: 'toolu_spawn_1',
    prompt: 'find the probes',
    subagentType: 'Explore',
    description: 'look',
    provider: { plugin: 'engine', tier: 'core' },
    parentModel: 'claude-test',
    background: false,
    fork: false,
  })
  expect(r).toMatchObject({ agentId: 'a1' })
  expect(agent(w.state)).toMatchObject({ id: 'a1', toolUseId: 'toolu_spawn_1', type: 'Explore', description: 'look', calls: 0, status: 'running' })

  // the query loop raises a subagent's calls with its agentId; the kit's
  // `$.tool.call` carries it through, its type does not name it
  const inSubagent = { agentId: 'a1' }
  await $.tool.call({ tool: 'Read', file_path: '/sp-test/proj/.claude/skills/canary-basic/SKILL.md', ...inSubagent })
  await $.tool.call({ tool: 'Bash', command: 'ls .claude/skills', ...inSubagent })
  expect(agent(w.state)).toMatchObject({ calls: 2 })
  expect(calls(w).map(n => [n.tool, n['agentId'], n['parent']])).toEqual([
    ['Read', 'a1', 'a1'],
    ['Bash', 'a1', 'a1'],
  ])

  await $.turn.complete({ answer: '', durationMs: 5, isAborted: false, turnId: 't1-a1', reason: 'answer', agentId: 'a1' })
  expect(agent(w.state)).toMatchObject({ status: 'done' })
})
