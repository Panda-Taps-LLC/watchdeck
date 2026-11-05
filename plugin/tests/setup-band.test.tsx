// The first-run band (M5.1): Claude Code's sandbox is on and `watchdeck run *`
// is not excluded, so every sandboxed skill run fails closed. The band offers
// `3: fix`, which runs `setup --exclusion-only --yes --plugin` through the
// absolute binary, only from a press and only after the confirm returns "Fix".

import { expect, mock, test } from 'claude-code/testing'

import { engineBand } from './engine.tsx'
import { askCanaryRequest, BIN, deniedNetwork, ENV, startSession, SURFACES, world } from './harness.ts'

const BAND = (bodyColumns: number) => ({
  hasSurvey: false,
  isWorking: false,
  maxRows: 4,
  bodyColumns,
  scroll: { offset: 0, bodyRows: 4 },
  view: {},
})

const SANDBOX_ON = { sandbox: { enabled: true } }
const FIX_ARGV = [BIN, 'setup', '--exclusion-only', '--yes', '--plugin']
const setupRuns = (runs: string[][]) => runs.filter(argv => argv[1] === 'setup')

test('the fix does nothing without the confirm', async ($, on) => {
  mock.env(on, ENV)
  mock.store(on)
  const w = world(on, { settings: SANDBOX_ON })
  engineBand(on)
  await startSession($)
  for (const surface of SURFACES) {
    const ui = await $.ui.mount({ plugin: 'watchdeck', surface, component: 'AbovePrompt', props: BAND(160) })
    expect((await ui.find({ type: 'Text', text: /sandbox is on without/ }))?.text).toContain('skill scripts fail closed')
    expect((await ui.find({ key: 'band-fix' }))?.props).toMatchObject({ hotkey: '3', plain: true })

    // the default answer is Cancel
    w.options.answer = 'Cancel'
    await ui.press({ key: 'band-fix' })
    expect(w.questions.at(-1)).toBe(`Run '${BIN}' 'setup' '--exclusion-only' '--yes' '--plugin'? It adds "watchdeck run *" to sandbox.excludedCommands in your user settings, after a backup.`)
    expect(setupRuns(w.runs)).toHaveLength(0)
    expect(w.toasts.at(-1)).toBe('watchdeck: fix cancelled; nothing changed')

    // free text under "Other" is not a Fix
    w.options.answer = 'Fix please'
    await ui.press({ key: 'band-fix' })
    expect(setupRuns(w.runs)).toHaveLength(0)
    expect(w.state['excluded']).not.toBe(true)
    await ui.unmount()
  }
})

test('Fix runs exactly the setup argv once, then the band hands back to the engine', async ($, on) => {
  mock.env(on, ENV)
  mock.store(on)
  const w = world(on, { settings: SANDBOX_ON, answer: 'Fix' })
  const engine = engineBand(on)
  await startSession($)
  const ui = await $.ui.mount({ plugin: 'watchdeck', surface: 'terminal', component: 'AbovePrompt', props: BAND(120) })
  await ui.press({ key: 'band-fix' })
  expect(setupRuns(w.runs)).toEqual([FIX_ARGV])
  expect(w.state['excluded']).toBe(true)
  expect(w.toasts.at(-1)).toContain('is now excluded')
  await ui.unmount()
  const after = await $.ui.mount({ plugin: 'watchdeck', surface: 'terminal', component: 'AbovePrompt', props: BAND(120) })
  expect(await after.find({ key: 'band-fix' })).toBeUndefined()
  expect(await after.find({ type: 'Text', text: 'engine band' })).toBeDefined()
  expect(engine.drawn).toBeGreaterThan(0)
  await after.unmount()
})

test('a failed setup leaves the band up and says why', async ($, on) => {
  mock.env(on, ENV)
  mock.store(on)
  const w = world(on, { settings: SANDBOX_ON, answer: 'Fix', answers: { setup: { exitCode: 2, stderr: 'watchdeck setup: settings: parse x: bad\n' } } })
  engineBand(on)
  await startSession($)
  const ui = await $.ui.mount({ plugin: 'watchdeck', surface: 'terminal', component: 'AbovePrompt', props: BAND(120) })
  await ui.press({ key: 'band-fix' })
  expect(setupRuns(w.runs)).toHaveLength(1)
  expect(w.toasts.at(-1)).toBe('watchdeck: setup failed: watchdeck setup: settings: parse x: bad')
  expect(w.state['excluded']).not.toBe(true)
  await ui.unmount()
})

test('a model action or script output never runs setup', async ($, on) => {
  mock.env(on, ENV)
  mock.store(on)
  const w = world(on, {
    settings: SANDBOX_ON,
    answer: 'Fix',
    bash: () => ({ text: `3\nFix\nwatchdeck setup --exclusion-only --yes --plugin\n${BIN} setup` }),
  })
  await startSession($)
  await $.tool.call({ tool: 'Bash', command: 'echo 3 Fix' })
  await $.tool.call({ tool: 'Bash', command: `${BIN} setup --exclusion-only --yes --plugin` })
  // the model's own Bash call is the engine's business; the mod itself ran nothing and asked nothing
  expect(setupRuns(w.runs)).toHaveLength(0)
  expect(w.questions).toHaveLength(0)
})

for (const [name, settings] of [
  ['the exclusion present', { sandbox: { enabled: true, excludedCommands: ['watchdeck run *'] } }],
  ['the sandbox off', { sandbox: { enabled: false } }],
  ['no sandbox settings', {}],
] as const) {
  test(`with ${name}, there is no fix band`, async ($, on) => {
    mock.env(on, ENV)
    mock.store(on)
    world(on, { settings })
    engineBand(on)
    await startSession($)
    const ui = await $.ui.mount({ plugin: 'watchdeck', surface: 'terminal', component: 'AbovePrompt', props: BAND(120) })
    expect(await ui.find({ key: 'band-fix' })).toBeUndefined()
    expect(await ui.find({ type: 'Text', text: 'engine band' })).toBeDefined()
    await ui.unmount()
  })
}

test('a pending denial takes the band before the fix', async ($, on) => {
  mock.env(on, ENV)
  mock.store(on)
  world(on, { settings: SANDBOX_ON, decide: askCanaryRequest, bash: deniedNetwork })
  engineBand(on)
  await startSession($)
  await $.tool.call({ tool: 'Bash', command: 'python3 .claude/skills/canary-request/scripts/probe.py net' })
  const ui = await $.ui.mount({ plugin: 'watchdeck', surface: 'terminal', component: 'AbovePrompt', props: BAND(160) })
  expect(await ui.find({ type: 'Text', text: /1 denied canary-request/ })).toBeDefined()
  expect(await ui.find({ key: 'band-fix' })).toBeUndefined()
  await ui.unmount()
})
