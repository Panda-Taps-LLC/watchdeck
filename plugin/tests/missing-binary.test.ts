// A missing binary never blocks (Spec C D9, §1.9): the status line says so,
// every hook passes through, nothing is drawn, nothing runs.

import { expect, mock, test } from 'claude-code/testing'

import { engineBand } from './engine.tsx'
import { askCanaryRequest, BIN, calls, deniedNetwork, ENV, startSession, SURFACES, world } from './harness.ts'

test('process.run rejects: binary missing, status says so, calls pass through', async ($, on) => {
  mock.env(on, ENV)
  mock.store(on)
  const w = world(on, { answers: { version: 'deny' }, decide: askCanaryRequest, bash: deniedNetwork })
  await startSession($)
  expect(w.state['binary']).toMatchObject({ state: 'missing', path: BIN })
  expect(w.state['hookOn']).toBe(false)
  expect(w.statuses.at(-1)).toBe('watchdeck: binary not found (hook inactive)')

  const ran = await $.tool.call({ tool: 'Bash', command: 'python3 .claude/skills/canary-request/scripts/probe.py net' })
  expect(ran.isError).toBe(true)
  expect(ran.text).toContain('net: DENIED(1)')
  expect(calls(w)).toHaveLength(0)
  expect(w.toasts).toHaveLength(0)
  expect(w.state['pendingDenial']).toBeUndefined()
  // only the probe ran
  expect(w.runs).toEqual([[BIN, 'version', '--json']])
})

test('nothing on disk: no process is started at all', async ($, on) => {
  mock.env(on, ENV)
  mock.store(on)
  const w = world(on, { binaryOnDisk: false })
  await startSession($)
  expect(w.state['binary']).toMatchObject({ state: 'missing' })
  expect(w.runs).toHaveLength(0)
  expect(w.statuses.at(-1)).toBe('watchdeck: binary not found (hook inactive)')
})

test('a copy under the project or $TMPDIR is refused (decision 13)', async ($, on) => {
  mock.env(on, { ...ENV, PATH: '/sp-test/proj/bin:/sp-test/tmp/bin', TMPDIR: '/sp-test/tmp' })
  mock.store(on)
  const w = world(on, {
    binaryOnDisk: false,
    files: { '/sp-test/proj/bin/watchdeck': { text: '' }, '/sp-test/tmp/bin/watchdeck': { text: '' } },
  })
  await startSession($)
  expect(w.state['binary']).toMatchObject({ state: 'missing' })
  expect((w.state['binary'] as { reason: string }).reason).toContain('only copies under the project directory or $TMPDIR were found')
  expect(w.runs).toHaveLength(0)
  expect(w.logs.filter(l => l.startsWith('debug: watchdeck: refused binary'))).toHaveLength(2)
})

test('no binary: the band stays the engine\'s and nothing runs', async ($, on) => {
  mock.env(on, ENV)
  mock.store(on)
  const w = world(on, { binaryOnDisk: false })
  const engine = engineBand(on)
  await startSession($)
  for (const surface of SURFACES) {
    const band = await $.ui.mount({
      plugin: 'watchdeck',
      surface,
      component: 'AbovePrompt',
      props: { hasSurvey: false, isWorking: false, maxRows: 4, bodyColumns: 120, scroll: { offset: 0, bodyRows: 4 }, view: {} },
    })
    expect(await band.find({ type: 'Text', text: 'engine band' })).toBeDefined()
    await band.unmount()
  }
  expect(engine.drawn).toBe(SURFACES.length)
  expect(w.runs).toHaveLength(0)
})

test('2 with the binary gone since the band was drawn: a toast, no throw, nothing runs', async ($, on) => {
  mock.env(on, ENV)
  mock.store(on)
  const w = world(on, { decide: askCanaryRequest, bash: deniedNetwork })
  engineBand(on)
  let gone = false
  on('state.get', ($, e, next) => (gone && e.key === 'binary' ? { value: { state: 'missing' } } : next(e)))
  await startSession($)
  await $.tool.call({ tool: 'Bash', command: 'python3 .claude/skills/canary-request/scripts/probe.py net' })
  const band = await $.ui.mount({
    plugin: 'watchdeck',
    surface: SURFACES[0],
    component: 'AbovePrompt',
    props: { hasSurvey: false, isWorking: false, maxRows: 4, bodyColumns: 120, scroll: { offset: 0, bodyRows: 4 }, view: {} },
  })
  expect(await band.find({ key: 'band-open' })).toBeDefined()
  // the band only draws with a binary; the press re-reads it
  gone = true
  const before = w.runs.length
  await band.press({ key: 'band-open' })
  expect(w.toasts.at(-1)).toBe('watchdeck: binary not found')
  expect(w.runs.length).toBe(before)
  await band.unmount()
})

test('headless (-p): observes, never toasts or sets the status line', async ($, on) => {
  mock.env(on, ENV)
  mock.store(on)
  const w = world(on, { decide: askCanaryRequest, bash: deniedNetwork })
  await startSession($, false)
  await $.tool.call({ tool: 'Bash', command: 'python3 .claude/skills/canary-request/scripts/probe.py net' })
  expect(calls(w)[0]).toMatchObject({ outcome: 'denied' })
  expect(w.toasts).toHaveLength(0)
  expect(w.statuses).toHaveLength(0)
  expect(w.opens).toHaveLength(0)
})
