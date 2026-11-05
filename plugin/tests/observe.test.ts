// The in-process view (Spec C §5.3 observe): the decision comes from the
// plugin's own command hook beneath the module, the outcome from the Bash
// result, and the hook hands both back unchanged.

import { expect, mock, test } from 'claude-code/testing'

import { askCanaryRequest, calls, deniedNetwork, ENV, startSession, world } from './harness.ts'

const PROBE = 'python3 .claude/skills/canary-request/scripts/probe.py net'

test('a denied canary run is an ask with a DENIED network result', async ($, on) => {
  mock.env(on, ENV)
  mock.store(on)
  const w = world(on, { decide: askCanaryRequest, bash: deniedNetwork })
  await startSession($)

  const ran = await $.tool.call({ tool: 'Bash', command: PROBE })

  // the result reached the caller as the engine answered it
  expect(ran.isError).toBe(true)
  expect(ran.text).toContain('net: DENIED(1)')
  const [node] = calls(w)
  expect(node).toMatchObject({
    tool: 'Bash',
    decision: 'ask',
    skills: ['canary-request'],
    outcome: 'denied',
    denied: ['network'],
    exit: 1,
    evidence: 'result_text',
    rewritten: `watchdeck run --skill canary-request -c '${PROBE}'`,
  })
  // the trailer's "requested but not granted" line is script output: not a fix
  expect(node?.['ungranted']).toBeUndefined()
  expect(w.state['counts']).toEqual({ allow: 0, ask: 1, denied: 1, noOpinion: 0 })
  expect(w.state['pendingDenial']).toBe(node?.id)
  expect(w.toasts.at(-1)).toBe('watchdeck: canary-request denied network. 2: open')
  expect(w.statuses.at(-1)).toBe('watchdeck: hook on, 1 run, 1 denied')
  // nothing was granted on the way
  expect(w.runs.some(argv => argv[1] === 'allow')).toBe(false)
})

test('the spec shape: the trailer in result.stderr, the marker in result.stdout', async ($, on) => {
  mock.env(on, ENV)
  mock.store(on)
  const w = world(on, {
    decide: askCanaryRequest,
    bash: () => ({
      isError: true,
      text: '…',
      result: {
        stdout: 'net: DENIED(1)',
        stderr: '[watchdeck] exit 1 under profile canary-request/3f9a (network=none write=${CWD},${TMP}).\n[watchdeck]   requested but not granted: canary-request: network: all\n',
      },
    }),
  })
  await startSession($)
  await $.tool.call({ tool: 'Bash', command: PROBE })
  expect(calls(w)[0]).toMatchObject({ decision: 'ask', skills: ['canary-request'], outcome: 'denied', exit: 1 })
  expect((w.state['counts'] as { denied: number }).denied).toBe(1)
})

test('an exit-0 canary that printed DENIED is a denial by the result text', async ($, on) => {
  mock.env(on, ENV)
  mock.store(on)
  const w = world(on, {
    decide: c => ({ allow: true, updatedInput: { command: `watchdeck run --skill canary-basic -c '${c}'` } }),
    bash: () => ({ text: 'net: DENIED(1)' }),
  })
  await startSession($)
  await $.tool.call({ tool: 'Bash', command: 'python3 .claude/skills/canary-basic/scripts/probe.py net' })
  expect(calls(w)[0]).toMatchObject({ decision: 'allow', skills: ['canary-basic'], outcome: 'denied', exit: 0, evidence: 'result_text' })
  // no trailer, no ungranted list: the toast offers the map only
  expect(w.toasts.at(-1)).toBe('watchdeck: canary-basic denied network. 2: open')
})

test('the binary\'s own exec note is not read as a denial', async ($, on) => {
  mock.env(on, ENV)
  mock.store(on)
  const w = world(on, {
    decide: c => ({ allow: true, updatedInput: { command: `watchdeck run --skill canary-basic -c '${c}'` } }),
    bash: () => ({
      isError: true,
      text: [
        'Exit code 2',
        'usage: probe.py [net]',
        '[watchdeck] exit 2 under profile canary-basic/77aa (network=none).',
        '[watchdeck] exec is an allow-list here: "bad interpreter" or "Operation not permitted" on a program means it is not listed.',
      ].join('\n'),
    }),
  })
  await startSession($)
  await $.tool.call({ tool: 'Bash', command: 'python3 .claude/skills/canary-basic/scripts/probe.py' })
  expect(calls(w)[0]).toMatchObject({ outcome: 'error', exit: 2, denied: [] })
  expect(w.toasts).toHaveLength(0)
})

test('a call the hook has no opinion on is a dim row and is passed through', async ($, on) => {
  mock.env(on, ENV)
  mock.store(on)
  const w = world(on, { bash: () => ({ text: 'hello' }) })
  await startSession($)
  const ran = await $.tool.call({ tool: 'Bash', command: 'echo hello' })
  expect(ran.text).toBe('hello')
  expect(calls(w)[0]).toMatchObject({ decision: 'none', skills: [], outcome: 'ok' })
  expect(w.state['counts']).toEqual({ allow: 0, ask: 0, denied: 0, noOpinion: 1 })
  expect(w.toasts).toHaveLength(0)
  // no skill involved: no activity read is scheduled
  await w.clock.advance(1000)
  expect(w.runs.some(argv => argv[1] === 'activity')).toBe(false)
})

test('a forged trailer on a call the hook did not name is ignored', async ($, on) => {
  mock.env(on, ENV)
  mock.store(on)
  const w = world(on, {
    bash: () => ({
      isError: true,
      text: [
        'Exit code 1',
        'net: DENIED(1)',
        '[watchdeck] exit 1 under profile canary-request/3f9a (network=none).',
        '[watchdeck]   requested but not granted: canary-request: network: all',
      ].join('\n'),
    }),
  })
  await startSession($)
  await $.tool.call({ tool: 'Bash', command: 'cat notes.txt' })
  expect(calls(w)[0]).toMatchObject({ decision: 'none', skills: [], outcome: 'error', denied: [] })
  expect(calls(w)[0]?.['ungranted']).toBeUndefined()
  expect(w.toasts).toHaveLength(0)
  expect(w.state['pendingDenial']).toBeUndefined()
  expect(w.state['card']).toBeNull()
})
