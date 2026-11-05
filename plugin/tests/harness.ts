// The world beneath the mod for every test: the nouns the kit leaves to the
// test (process, fs, settings, session, command, ui), answered from memory
// and recorded. Nothing here reaches the real home, the real store or a real
// process: the binary is a fake path, every `$.process.run` is answered here.
//
// Each test still calls `mock.env` and `mock.store` itself, first thing, so
// the environment it runs under is visible at the top of the test.

import type { On, ProcessRunResult } from 'claude-code'
import { mock, type Engine, type MockClock } from 'claude-code/testing'

/** The binary the mod resolves: the install dir under the test HOME. */
export const BIN = '/tmp/sp-test-home/.local/share/watchdeck/bin/watchdeck'
export const CWD = '/sp-test/proj'
export const SESSION = 'sess-1'
export const ENV = { HOME: '/tmp/sp-test-home', XDG_STATE_HOME: '/tmp/sp-test-state' } as const
export const SURFACES = ['terminal', 'desktop'] as const

/** How a fake `watchdeck <sub>` answers: a result, or a refusal (the call rejects). */
export type Answer = { exitCode: number; stdout?: string; stderr?: string } | 'deny'

/** A Bash result as the engine hands it to `tool.call` hooks. */
export type BashAnswer = { text: string; isError?: boolean; result?: unknown }

export type WorldOptions = {
  /** Whether `fs.stat` finds the binary at BIN. Default true. */
  binaryOnDisk?: boolean
  /** Answers `watchdeck <argv[1]>`; unlisted subcommands exit 3 like an unknown subcommand. */
  answers?: Record<string, Answer>
  /** The Bash result for every Bash call; default a clean exit 0. */
  bash?: (command: string) => BashAnswer
  /** The watchdeck hook's decision beneath the module (`classic.PreToolUse`). */
  decide?: (command: string) => Record<string, unknown>
  /** The label `$.ui.ask` resolves to (answered through AskUserQuestion). */
  answer?: string
  /**
   * The records `watchdeck activity --json` returns, built when asked (so
   * they can name the tool_use_id the kit minted); overrides `answers.activity`.
   */
  log?: (w: World) => Record<string, unknown>[]
  /** Files `fs.stat` and `fs.read` find, by path; `size` defaults to the text's length. */
  files?: Record<string, { text: string; size?: number }>
  /** What `$.settings.read` returns (the merged settings); default `{}`. */
  settings?: Record<string, unknown>
}

export type World = {
  clock: MockClock
  runs: string[][]
  toasts: string[]
  statuses: (string | undefined)[]
  logs: string[]
  opens: unknown[]
  questions: string[]
  /** Every `$.state.set` the mod made, by key: the latest value. */
  state: Record<string, unknown>
  options: WorldOptions
  /** Paths the mod read with `fs.read`. */
  reads: string[]
  /** The tool_use_ids of the Bash calls the test made, in order. */
  bashIds: string[]
}

function result(a: Exclude<Answer, 'deny'>): ProcessRunResult {
  return {
    exitCode: a.exitCode,
    stdout: a.stdout ?? '',
    stderr: a.stderr ?? '',
    isStdoutTruncated: false,
    isStderrTruncated: false,
  }
}

export const DEFAULT_ANSWERS: Record<string, Answer> = {
  version: { exitCode: 0, stdout: '{"version":"0.1.0","platform":"darwin","enforcement":true}\n' },
  paths: { exitCode: 0, stdout: '{"activity":"/tmp/sp-test-state/watchdeck/activity.jsonl"}\n' },
  activity: { exitCode: 0, stdout: '{"records":[],"next":0,"reset":false,"skipped":0}\n' },
  audit: { exitCode: 0, stdout: '{"skills":[]}\n' },
  allow: { exitCode: 0, stdout: 'canary-request: network all\n' },
  setup: { exitCode: 0, stdout: '3. Hooks\n   wrote ~/.claude/settings.json\n' },
  ui: { exitCode: 0, stdout: 'watchdeck ui: opened http://127.0.0.1:47331/ in your browser\n' },
}

/** Installs the bottoms and returns the record of what the mod did. */
export function world(on: On, options: WorldOptions = {}): World {
  const w: World = {
    clock: mock.clock(on, { now: 1_760_000_000_000 }),
    runs: [],
    toasts: [],
    statuses: [],
    logs: [],
    opens: [],
    questions: [],
    state: {},
    options,
    reads: [],
    bashIds: [],
  }
  const answers = { ...DEFAULT_ANSWERS, ...(options.answers ?? {}) }

  on('state.set', ($, e, next) => {
    w.state[e.key] = e.value
    return next(e)
  })
  on('session.start', ($, e) => ({ cwd: e.cwd }))
  on('session.id', () => ({ value: SESSION }))
  on('session.cwd', () => ({ value: CWD }))
  on('session.surfaces', () => ({ value: ['terminal'] as const }))
  on('settings.read', () => ({ value: options.settings ?? {} }))
  on('command.register', ($, e) => ({ value: { command: e.name } }))
  on('ui.status', ($, e) => {
    w.statuses.push(e.text)
    return { value: undefined }
  })
  on('ui.toast', ($, e) => {
    w.toasts.push(e.text)
    return { value: undefined }
  })
  on('ui.log', ($, e) => {
    w.logs.push(`${e.to}: ${e.text}`)
    return { value: undefined }
  })
  on('ui.open', ($, e) => {
    w.opens.push(e)
    return { value: { isPlaced: true as const } }
  })
  on('fs.stat', ($, e) => {
    if (e.path === BIN && options.binaryOnDisk !== false) {
      return { value: { kind: 'file' as const, size: 1, mtimeMs: 0, isLink: false, realPath: BIN } }
    }
    const f = options.files?.[e.path]
    if (f) return { value: { kind: 'file' as const, size: f.size ?? f.text.length, mtimeMs: 0, isLink: false, realPath: e.path } }
    return { deny: `ENOENT: ${e.path}` }
  })
  on('fs.read', ($, e) => {
    w.reads.push(e.path)
    const f = options.files?.[e.path]
    return f ? { value: f.text } : { deny: `ENOENT: ${e.path}` }
  })
  on('process.run', ($, e) => {
    const argv = [...e.argv]
    w.runs.push(argv)
    const sub = argv[0] === BIN ? argv[1] ?? '' : ''
    if (sub === 'activity' && options.log) {
      const records = options.log(w)
      return { value: result({ exitCode: 0, stdout: JSON.stringify({ records, next: records.length, reset: false, skipped: 0 }) }) }
    }
    const a = answers[sub] ?? { exitCode: 3, stderr: `watchdeck: unknown command "${sub}"\n` }
    if (a === 'deny') return { deny: `could not start ${argv[0]}` }
    return { value: result(a) }
  })
  on('classic.PreToolUse', { tool: 'Bash' }, ($, e) => (options.decide ? options.decide(e.command) : {}))
  on('tool.call', ($, e) => {
    if (e.tool === 'AskUserQuestion') {
      const q = e.questions[0]?.question ?? ''
      w.questions.push(q)
      const label = options.answer ?? 'Cancel'
      return { result: { questions: e.questions, answers: { [q]: label } } }
    }
    if (e.tool === 'Bash') {
      w.bashIds.push(e.tool_use_id)
      const b = options.bash ? options.bash(e.command) : { text: '' }
      return b.isError
        ? { isError: true as const, result: b.result, text: b.text }
        : { result: b.result ?? { stdout: b.text, stderr: '', interrupted: false }, text: b.text }
    }
    return { result: {}, text: '' }
  })
  on('agent.spawn', ($, e) => ({ model: 'claude-test', agentId: 'a1' }))
  on('turn.start', ($, e) => ({ turnId: e.turnId }))
  on('turn.complete', () => ({ text: '' }))
  on('skill.prompt', ($, e) => ({ text: e.text }))
  return w
}

/** The decision the plugin's own command hook gives a canary-request probe. */
export function askCanaryRequest(command: string): Record<string, unknown> {
  return {
    ask: 'watchdeck: canary-request under network=none write=${CWD},${TMP} env=PATH,HOME,LANG,TMPDIR; requested but not granted: network: all (grant with: watchdeck allow canary-request ...)',
    updatedInput: { command: `watchdeck run --skill canary-request -c '${command}'` },
    additionalContext: ['This command runs under a watchdeck sandbox for skill \'canary-request\'.'],
  }
}

/** An ask whose reason names other ungranted items for canary-request. */
export function askWith(items: string): (command: string) => Record<string, unknown> {
  return command => ({
    ask: `watchdeck: canary-request under network=none write=\${CWD},\${TMP}; requested but not granted: ${items} (grant with: watchdeck allow canary-request ...)`,
    updatedInput: { command: `watchdeck run --skill canary-request -c '${command}'` },
  })
}

/** A Bash result whose text carries the probe marker and the binary's trailer. */
export function deniedNetwork(): BashAnswer {
  return {
    isError: true,
    text: [
      'Exit code 1',
      'net: DENIED(1)',
      '[watchdeck] exit 1 under profile canary-request/3f9a (network=none write=${CWD},${TMP}).',
      '[watchdeck]   requested but not granted: canary-request: network: all',
      '[watchdeck] If this is a permission error, the policy caused it. Widen: watchdeck allow canary-request --network all | --write <path> | --caches',
    ].join('\n'),
  }
}

export async function startSession($: Engine, interactive = true): Promise<void> {
  await $.session.start({ cwd: CWD, surface: interactive ? 'terminal' : null, isInteractive: interactive })
}

/** The call nodes the mod holds, from its last `nodes` write. */
export function calls(w: World): Array<Record<string, unknown> & { id: string; tool: string; outcome: string }> {
  const nodes = (w.state['nodes'] ?? []) as Array<Record<string, unknown> & { kind: string; id: string; tool: string; outcome: string }>
  return nodes.filter(n => n.kind === 'call')
}

/**
 * A `log` option: the decision record the binary's hook writes for the latest
 * Bash call, naming `ungranted` (the only source of a grant fix).
 */
export function decisionLog(ungranted: string[], skills: string[] = ['canary-request']): (w: World) => Record<string, unknown>[] {
  return w => {
    const id = w.bashIds.at(-1)
    if (!id) return []
    return [
      {
        v: 1,
        kind: 'decision',
        ts: '2026-10-12T21:31:12.410Z',
        session_id: SESSION,
        tool_use_id: id,
        cwd: CWD,
        skills,
        decision: 'ask',
        ungranted,
      },
    ]
  }
}

/** Lets the debounced activity read run (the mod waits 300 ms after a skill run). */
export async function readLog(w: World): Promise<void> {
  await w.clock.advance(400)
}
