// The band above the prompt (Spec C §1.6, D5): one row while a denial is
// pending, with digit hotkeys (1 grant, 2 open the dashboard, 3 fix); the
// engine's own band otherwise.

import { expect, mock, test, type Engine } from 'claude-code/testing'

import { engineBand } from './engine.tsx'
import { askCanaryRequest, BIN, decisionLog, deniedNetwork, ENV, readLog, startSession, SURFACES, world, type World } from './harness.ts'

const BAND = (bodyColumns: number) => ({
  hasSurvey: false,
  isWorking: false,
  maxRows: 4,
  bodyColumns,
  scroll: { offset: 0, bodyRows: 4 },
  view: {},
})

async function deny($: Engine, w: World): Promise<void> {
  await $.tool.call({ tool: 'Bash', command: 'python3 .claude/skills/canary-request/scripts/probe.py net' })
  expect(w.state['pendingDenial']).toBeDefined()
}

test('before the log record, the band shows the denial with 1: grant dim', async ($, on) => {
  mock.env(on, ENV)
  mock.store(on)
  const w = world(on, { decide: askCanaryRequest, bash: deniedNetwork })
  engineBand(on)
  await startSession($)
  await deny($, w)
  for (const surface of SURFACES) {
    const ui = await $.ui.mount({ plugin: 'watchdeck', surface, component: 'AbovePrompt', props: BAND(160) })
    expect((await ui.find({ type: 'Text', text: /1 denied canary-request/ }))?.text).toBe('watchdeck · 1 skill run · 1 denied canary-request: network')
    expect(await ui.find({ key: 'band-grant' })).toBeUndefined()
    expect(await ui.find({ type: 'Text', text: '1: grant' })).toBeDefined()
    expect(await ui.find({ key: 'band-open' })).toBeDefined()
    await ui.unmount()
  }
})

test('with the log record, the band draws 1: grant and 2: open', async ($, on) => {
  mock.env(on, ENV)
  mock.store(on)
  const w = world(on, { decide: askCanaryRequest, bash: deniedNetwork, log: decisionLog(['canary-request: network: all']) })
  const engine = engineBand(on)
  await startSession($)
  await deny($, w)
  await readLog(w)
  for (const surface of SURFACES) {
    const ui = await $.ui.mount({ plugin: 'watchdeck', surface, component: 'AbovePrompt', props: BAND(160) })
    const text = await ui.find({ type: 'Text', text: /1 denied canary-request/ })
    expect(text).toBeDefined()
    expect(text?.text).toContain('watchdeck · 1 skill run · 1 denied canary-request: network · fix watchdeck allow canary-request --network all')
    expect((await ui.find({ key: 'band-grant' }))?.props).toMatchObject({ hotkey: '1', plain: true })
    expect((await ui.find({ key: 'band-open' }))?.props).toMatchObject({ hotkey: '2', plain: true })
    await ui.unmount()
  }
  expect(engine.drawn).toBe(0)
})

test('the band narrows: no fix under 60 columns, counts only under 40', async ($, on) => {
  mock.env(on, ENV)
  mock.store(on)
  const w = world(on, { decide: askCanaryRequest, bash: deniedNetwork, log: decisionLog(['canary-request: network: all']) })
  engineBand(on)
  await startSession($)
  await deny($, w)
  await readLog(w)
  for (const surface of SURFACES) {
    const mid = await $.ui.mount({ plugin: 'watchdeck', surface, component: 'AbovePrompt', props: BAND(55) })
    expect((await mid.find({ type: 'Text', text: /denied/ }))?.text).not.toContain('fix ')
    await mid.unmount()
    const narrow = await $.ui.mount({ plugin: 'watchdeck', surface, component: 'AbovePrompt', props: BAND(39) })
    expect((await narrow.find({ type: 'Text', text: /denied/ }))?.text).toBe('watchdeck · 1 denied')
    expect(await narrow.find({ key: 'band-open' })).toBeDefined()
    await narrow.unmount()
    const tiny = await $.ui.mount({ plugin: 'watchdeck', surface, component: 'AbovePrompt', props: BAND(30) })
    expect((await tiny.find({ type: 'Text', text: /denied/ }))?.text).toBe('1 denied')
    expect(await tiny.find({ key: 'band-grant' })).toBeDefined()
    await tiny.unmount()
  }
})

test('2 opens the dashboard and never a pane', async ($, on) => {
  mock.env(on, ENV)
  mock.store(on)
  const w = world(on, { decide: askCanaryRequest, bash: deniedNetwork })
  engineBand(on)
  await startSession($)
  await deny($, w)
  for (const surface of SURFACES) {
    const ui = await $.ui.mount({ plugin: 'watchdeck', surface, component: 'AbovePrompt', props: BAND(80) })
    await ui.press({ key: 'band-open' })
    // the real argv leads with the absolute binary
    expect(w.runs.at(-1)).toEqual([BIN, 'ui', '--ensure', '--open'])
    await ui.unmount()
  }
  expect(w.opens).toHaveLength(0)
})

test('no denial pending: the band hands over to the engine', async ($, on) => {
  mock.env(on, ENV)
  mock.store(on)
  world(on, { bash: () => ({ text: 'hello' }) })
  const engine = engineBand(on)
  await startSession($)
  await $.tool.call({ tool: 'Bash', command: 'echo hello' })
  for (const surface of SURFACES) {
    const ui = await $.ui.mount({ plugin: 'watchdeck', surface, component: 'AbovePrompt', props: BAND(120) })
    expect(await ui.find({ type: 'Text', text: 'engine band' })).toBeDefined()
    expect(await ui.find({ key: 'band-open' })).toBeUndefined()
    await ui.unmount()
  }
  expect(engine.drawn).toBe(2)
})

test('the next prompt clears the denial band, without calling the binary', async ($, on) => {
  mock.env(on, ENV)
  mock.store(on)
  const w = world(on, { decide: askCanaryRequest, bash: deniedNetwork })
  const engine = engineBand(on)
  await startSession($)
  await deny($, w)
  const shown = await $.ui.mount({ plugin: 'watchdeck', surface: SURFACES[0], component: 'AbovePrompt', props: BAND(120) })
  expect(await shown.find({ key: 'band-open' })).toBeDefined()
  await shown.unmount()
  const runsBefore = w.runs.length
  // a continuation (no typed prompt) or a subagent's turn is not the person moving on
  await $.turn.start({ text: '', turnId: 't-cont' })
  await $.turn.start({ text: 'search the repo', turnId: 't-sub', agentId: 'a1' })
  expect(w.state['pendingDenial']).toBeDefined()
  expect(w.state['pendingDenial']).not.toBeNull()
  await $.turn.start({ text: 'next thing', turnId: 't2' })
  expect(w.state['pendingDenial']).toBeNull()
  for (const surface of SURFACES) {
    const ui = await $.ui.mount({ plugin: 'watchdeck', surface, component: 'AbovePrompt', props: BAND(120) })
    expect(await ui.find({ key: 'band-open' })).toBeUndefined()
    expect(await ui.find({ type: 'Text', text: 'engine band' })).toBeDefined()
    await ui.unmount()
  }
  expect(engine.drawn).toBe(SURFACES.length)
  expect(w.runs.length).toBe(runsBefore)
})
