// The activity log (Spec C §1.4 step 3, D4): read through the binary's
// bounded `activity --json`, or the file under 4 MiB from an older binary;
// a malformed line is counted, never thrown; the card is filled from it.

import { expect, mock, test, type Engine } from 'claude-code/testing'

import { ACTIVITY_JSONL } from './fixtures/activity.ts'
import { BIN, calls, ENV, SESSION, startSession, world } from './harness.ts'

const LINES = ACTIVITY_JSONL.split('\n').filter(l => l.trim() !== '')

function envelope(): string {
  const records: unknown[] = []
  let skipped = 0
  for (const line of LINES) {
    try {
      records.push(JSON.parse(line))
    } catch {
      skipped += 1
    }
  }
  return JSON.stringify({ records, next: ACTIVITY_JSONL.length, reset: false, skipped, path: '/tmp/sp-test-state/watchdeck/activity.jsonl', enabled: true })
}

const AUDIT = JSON.stringify({
  skills: [{ name: 'canary-request', request: { summary: 'network=all env=CANARY_SECRET' }, effective: 'network=none' }],
})

async function turnComplete($: Engine): Promise<void> {
  await $.turn.complete({ answer: '', durationMs: 1, isAborted: false, turnId: 't1', reason: 'answer' })
}

test('activity --json fills the card: request, grant, ran as, why, fix', async ($, on) => {
  mock.env(on, ENV)
  mock.store(on)
  const w = world(on, { answers: { activity: { exitCode: 0, stdout: envelope() }, audit: { exitCode: 0, stdout: AUDIT } } })
  await startSession($)
  await turnComplete($)
  // the request cache loads behind the denial (one `audit --json`, unawaited)
  await w.clock.settle()
  expect(w.runs.filter(argv => argv[1] === 'audit')).toEqual([[BIN, 'audit', '--json']])

  const reads = w.runs.filter(argv => argv[1] === 'activity')
  expect(reads[0]).toEqual([BIN, 'activity', '--json', '--session', SESSION, '--kinds', 'decision,run,skill_invoked,denied', '--tail', '200'])
  const node = calls(w).find(n => n.id === 'toolu_fixture_01')
  expect(node).toMatchObject({
    decision: 'ask',
    skills: ['canary-request'],
    outcome: 'denied',
    evidence: 'hint',
    exit: 1,
    joinedBy: 'write',
    ranAs: 'network=none write=${CWD},${TMP} env=PATH,HOME,LANG,TMPDIR',
    ungranted: ['canary-request: network: all', 'canary-request: env: CANARY_SECRET'],
  })
  // another session's record is not merged
  expect(calls(w).some(n => n.id === 'toolu_fixture_99')).toBe(false)
  // the run record revealed the denial: selected, band pending, card built
  expect(w.state['pendingDenial']).toBe('toolu_fixture_01')
  expect(w.state['card']).toMatchObject({
    toolUseId: 'toolu_fixture_01',
    skill: 'canary-request',
    request: 'network=all env=CANARY_SECRET',
    grant: 'network=none write=${CWD},${TMP} env=PATH,HOME,LANG,TMPDIR',
    ranAs: 'network=none write=${CWD},${TMP} env=PATH,HOME,LANG,TMPDIR',
    why: 'network access refused by the OS (EPERM)',
    whyDetail: 'PermissionError: [Errno 1] Operation not permitted',
    evidence: "the sandbox's stderr, heuristic",
    fix: { argv: [BIN, 'allow', 'canary-request', '--network', 'all'], text: 'watchdeck allow canary-request --network all' },
    notes: ['canary-request: env CANARY_SECRET: edit ~/.config/watchdeck/overrides.yaml (no allow flag)'],
    joinedBy: 'write',
  })
  expect(w.state['activity']).toMatchObject({ state: 'ok', unreadable: 1 })
  expect(w.state['cursor']).toEqual({ next: ACTIVITY_JSONL.length })

  // the next read continues from the cursor
  await turnComplete($)
  const again = w.runs.filter(argv => argv[1] === 'activity')
  expect(again[1]).toEqual([BIN, 'activity', '--json', '--session', SESSION, '--kinds', 'decision,run,skill_invoked,denied', '--after', String(ACTIVITY_JSONL.length)])
})

test('an older binary without `activity` falls back to the file under 4 MiB', async ($, on) => {
  mock.env(on, ENV)
  mock.store(on)
  const path = '/tmp/sp-test-state/watchdeck/activity.jsonl'
  const w = world(on, {
    answers: {
      activity: { exitCode: 3, stderr: 'watchdeck: unknown command "activity"\n' },
      paths: { exitCode: 3, stderr: 'watchdeck: unknown command "paths"\n' },
    },
    files: { [path]: { text: ACTIVITY_JSONL } },
  })
  await startSession($)
  await turnComplete($)
  expect(w.state['activity']).toMatchObject({ path, state: 'ok', unreadable: 1 })
  expect(calls(w).find(n => n.id === 'toolu_fixture_01')).toMatchObject({ outcome: 'denied', evidence: 'hint' })
  expect(calls(w).some(n => n.id === 'toolu_fixture_99')).toBe(false)
})

test('a log over 4 MiB with no bounded reader is skipped, not read', async ($, on) => {
  mock.env(on, ENV)
  mock.store(on)
  const path = '/tmp/sp-test-state/watchdeck/activity.jsonl'
  const w = world(on, {
    answers: { activity: { exitCode: 3, stderr: 'watchdeck: unknown command "activity"\n' } },
    files: { [path]: { text: '', size: 5 * 1024 * 1024 } },
  })
  await startSession($)
  await turnComplete($)
  expect(w.reads).toHaveLength(0)
  expect(w.state['activity']).toMatchObject({ state: 'too-large' })
  expect(w.statuses.at(-1)).toContain('activity log too large to read in-session')
})

test('a binary that rejects a flag the mod passes also falls back to the file', async ($, on) => {
  mock.env(on, ENV)
  mock.store(on)
  const path = '/tmp/sp-test-state/watchdeck/activity.jsonl'
  const w = world(on, {
    answers: { activity: { exitCode: 3, stderr: 'flag provided but not defined: -kinds\n' } },
    files: { [path]: { text: ACTIVITY_JSONL } },
  })
  await startSession($)
  await turnComplete($)
  expect(w.reads).toEqual([path])
  expect(w.state['activity']).toMatchObject({ state: 'ok', unreadable: 1 })
})

test('a missing log degrades to the in-process view with a note', async ($, on) => {
  mock.env(on, ENV)
  mock.store(on)
  const w = world(on, { answers: { activity: { exitCode: 3, stderr: 'watchdeck: unknown command "activity"\n' } } })
  await startSession($)
  await turnComplete($)
  expect(w.state['activity']).toMatchObject({ state: 'missing', detail: 'activity log not found at /tmp/sp-test-state/watchdeck/activity.jsonl' })
})

test('WATCHDECK_ACTIVITY=off: nothing is read', async ($, on) => {
  mock.env(on, { ...ENV, WATCHDECK_ACTIVITY: 'off' })
  mock.store(on)
  const w = world(on, { answers: { paths: { exitCode: 0, stdout: '{"activity":""}' } } })
  await startSession($)
  await turnComplete($)
  expect(w.runs.some(argv => argv[1] === 'activity')).toBe(false)
  expect(w.state['activity']).toMatchObject({ enabled: false, state: 'unavailable' })
})
