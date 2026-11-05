// watchdeck's in-session mod (Spec C §1, 2026-10-12; trimmed to the band on
// 2026-10-18): a band above the prompt when something was denied, with keys
// 1 grant (runs `watchdeck allow` only after an explicit confirm), 2 open
// the dashboard and 3 fix the sandbox exclusion. The command hook in
// hooks.json keeps enforcing; this module observes it and never answers a
// tool call for itself.
//
// Everything that touches `$` lives in this file: `claude plugin validate`
// follows `$` only into functions declared beside the hook, so the pure
// parsers, the tree model and the grant allow-list sit in the sibling files
// and take plain values.

import { atom, read, update } from 'claude-code'
import type { EngineInterface, Register } from 'claude-code'

import type {
  WatchdeckActivityState,
  WatchdeckBinary,
  WatchdeckCallNode,
  WatchdeckCard,
  WatchdeckCounts,
  WatchdeckCursor,
  WatchdeckFix,
  WatchdeckNode,
  WatchdeckRequestCache,
} from '../types'

import {
  activityArgv,
  filterFileRecords,
  MAX_FILE_BYTES,
  mergeRecords,
  parseActivityOutput,
  parseJsonl,
  type ActivityPage,
} from './activity.ts'
import { candidateDirs, isUnder, missingReason, parseVersionOutput, type BinRoots } from './bin.ts'
import { quoteArgv, validateGrantArgv } from './grant.ts'
import {
  DEBOUNCE_MS,
  isDenialOutcome,
  live,
} from './state.ts'
import { bounded, buildCard, countsOf, deniedWhat, ensureParent, ensureSkill, findCall, promptNode, summaryOf } from './tree.ts'
import {
  findDenialMarkers,
  firstLine,
  isSkillName,
  looksDeclined,
  outcomeForExit,
  parseRewrite,
  parseTrailer,
} from './trailer.ts'

type Engine = EngineInterface

// ---------------------------------------------------------------------------
// the $.state atoms, one per key of the contract in ../types

const nodesAtom = atom({ plugin: 'watchdeck', key: 'nodes' } as const, [] as WatchdeckNode[])
const selectedAtom = atom({ plugin: 'watchdeck', key: 'selected' } as const, null as string | null)
const cardAtom = atom({ plugin: 'watchdeck', key: 'card' } as const, null as WatchdeckCard | null)
const countsAtom = atom({ plugin: 'watchdeck', key: 'counts' } as const, {
  allow: 0,
  ask: 0,
  denied: 0,
  noOpinion: 0,
} as WatchdeckCounts)
const pendingDenialAtom = atom({ plugin: 'watchdeck', key: 'pendingDenial' } as const, null as string | null)
const binaryAtom = atom({ plugin: 'watchdeck', key: 'binary' } as const, { state: 'unknown' } as WatchdeckBinary)
const hookOnAtom = atom({ plugin: 'watchdeck', key: 'hookOn' } as const, false)
const sandboxOnAtom = atom({ plugin: 'watchdeck', key: 'sandboxOn' } as const, false)
const excludedAtom = atom({ plugin: 'watchdeck', key: 'excluded' } as const, false)
const cursorAtom = atom({ plugin: 'watchdeck', key: 'cursor' } as const, null as WatchdeckCursor | null)
const activityAtom = atom({ plugin: 'watchdeck', key: 'activity' } as const, {
  path: null,
  enabled: true,
  state: 'unknown',
  unreadable: 0,
} as WatchdeckActivityState)
const requestsAtom = atom({ plugin: 'watchdeck', key: 'requests' } as const, {} as WatchdeckRequestCache)

// ---------------------------------------------------------------------------
// small helpers

function debugLog($: Engine, text: string): void {
  try {
    $.ui.log(`watchdeck: ${text}`, { to: 'debug' })
  } catch {
    // logging never fails a hook
  }
}

function toast($: Engine, text: string): void {
  try {
    $.ui.toast(text)
  } catch (err) {
    debugLog($, `toast failed: ${String(err)}`)
  }
}

function truncate(text: string, max: number): string {
  if (max <= 1) return ''
  return text.length > max ? text.slice(0, max - 1) + '…' : text
}

/** Whether a person is at the prompt; asked of the session once when unknown. */
async function isInteractive($: Engine): Promise<boolean> {
  if (live.interactive === undefined) {
    try {
      live.interactive = (await $.session.surfaces()).length > 0
    } catch {
      live.interactive = false
    }
  }
  return live.interactive
}

// ---------------------------------------------------------------------------
// binary resolution (decision 13)

async function realPathOf($: Engine, path: string): Promise<string> {
  try {
    const st = await $.fs.stat(path, { resolve: true })
    return st.realPath ?? path
  } catch {
    return path
  }
}

/** Finds the first acceptable `watchdeck` executable: never under cwd or $TMPDIR. */
async function locateBinary($: Engine, roots: BinRoots): Promise<{ path: string | null; refused: string[] }> {
  const refused: string[] = []
  const forbidden: string[] = []
  if (roots.cwd) forbidden.push(roots.cwd, await realPathOf($, roots.cwd))
  if (roots.tmpdir) forbidden.push(roots.tmpdir, await realPathOf($, roots.tmpdir))
  for (const dir of candidateDirs(roots)) {
    const path = `${dir}/watchdeck`
    let real = path
    try {
      const st = await $.fs.stat(path, { resolve: true })
      if (st.kind !== 'file') continue
      real = st.realPath ?? path
    } catch {
      continue
    }
    const bad = forbidden.find(root => isUnder(path, root) || isUnder(real, root))
    if (bad !== undefined) {
      refused.push(`${path} (under ${bad})`)
      continue
    }
    return { path, refused }
  }
  return { path: null, refused }
}

/** The health probe: `version --json`, or an older binary's plain line. */
async function probeVersion($: Engine, path: string): Promise<WatchdeckBinary> {
  try {
    const r = await $.process.run([path, 'version', '--json'], { timeoutMs: 5000 })
    if (r.exitCode !== 0) return { state: 'missing', path, reason: `version exited ${r.exitCode}` }
    return { state: 'ok', path, version: parseVersionOutput(r.stdout) }
  } catch (err) {
    return { state: 'missing', path, reason: `could not run ${path}: ${String(err)}` }
  }
}

// ---------------------------------------------------------------------------
// state maintenance

async function statusText($: Engine): Promise<string> {
  const binary = await read($, binaryAtom)
  if (binary.state === 'missing') return 'watchdeck: binary not found (hook inactive)'
  const nodes = await read($, nodesAtom)
  const counts = countsOf(nodes)
  const runs = nodes.filter(n => n.kind === 'call' && n.skills.length > 0).length
  let text = `watchdeck: hook on, ${runs} run${runs === 1 ? '' : 's'}, ${counts.denied} denied`
  if ((await read($, sandboxOnAtom)) && !(await read($, excludedAtom))) {
    text += ' · Claude Code sandbox is on without "watchdeck run *" excluded: sandboxed runs fail closed (exit 126)'
  }
  const activity = await read($, activityAtom)
  if (activity.state === 'too-large') text += ' · activity log too large to read in-session'
  return text
}

async function updateStatus($: Engine): Promise<void> {
  if (!(await isInteractive($))) return
  try {
    $.ui.status(await statusText($))
  } catch (err) {
    debugLog($, `status failed: ${String(err)}`)
  }
}

/** Recomputes counts and the card of the selected call; call after a node change. */
async function recompute($: Engine): Promise<void> {
  const nodes = await read($, nodesAtom)
  await update($, countsAtom, () => countsOf(nodes))
  const selected = await read($, selectedAtom)
  const node = selected ? findCall(nodes, selected) : undefined
  if (!node) {
    await update($, cardAtom, () => null)
    return
  }
  const requests = await read($, requestsAtom)
  const binary = await read($, binaryAtom)
  const home = await $.env.get('HOME')
  await update($, cardAtom, () => buildCard(node, requests, binary.path, home))
}

async function select($: Engine, id: string | null): Promise<void> {
  await update($, selectedAtom, () => id)
  await recompute($)
}

/** Edits one call node on a copy of the list; returns the edited copy. */
async function patchCall($: Engine, id: string, fn: (node: WatchdeckCallNode) => void): Promise<WatchdeckCallNode | undefined> {
  let patched: WatchdeckCallNode | undefined
  await update($, nodesAtom, list => {
    patched = undefined
    return list.map(n => {
      if (n.kind !== 'call' || n.id !== id) return n
      const copy: WatchdeckCallNode = { ...n, skills: [...n.skills], denied: [...n.denied] }
      fn(copy)
      patched = copy
      return copy
    })
  })
  return patched
}

/** One `audit --json` per session fills the request cache (lazy, best effort). */
async function loadRequests($: Engine, force = false): Promise<void> {
  if (live.requestsLoading) return
  const binary = await read($, binaryAtom)
  if (binary.state !== 'ok' || !binary.path) return
  if (!force && Object.keys(await read($, requestsAtom)).length > 0) return
  live.requestsLoading = true
  try {
    const r = await $.process.run([binary.path, 'audit', '--json'], { timeoutMs: 10_000 })
    if (r.exitCode !== 0) return
    const parsed = JSON.parse(r.stdout) as unknown
    const rows: unknown[] = Array.isArray(parsed)
      ? parsed
      : parsed && typeof parsed === 'object' && Array.isArray((parsed as { skills?: unknown }).skills)
        ? (parsed as { skills: unknown[] }).skills
        : []
    const next: Record<string, string> = {}
    for (const row of rows) {
      if (!row || typeof row !== 'object') continue
      // `request` is null for a skill with no PERMISSIONS.yaml: then there is no request to show
      const r2 = row as { name?: unknown; request?: unknown }
      if (typeof r2.name !== 'string') continue
      const req = r2.request && typeof r2.request === 'object' ? (r2.request as { summary?: unknown }).summary : undefined
      if (typeof req === 'string' && req) next[r2.name] = req
    }
    if (Object.keys(next).length > 0) {
      await update($, requestsAtom, () => next)
      await recompute($)
    }
  } catch (err) {
    debugLog($, `audit --json failed: ${String(err)}`)
  } finally {
    live.requestsLoading = false
  }
}

/** Toast, band and status for a denial (Spec C §1.4 step 2); nothing under -p. */
async function announceDenial($: Engine, node: WatchdeckCallNode): Promise<void> {
  if (!(await isInteractive($))) return
  await update($, pendingDenialAtom, () => node.id)
  await select($, node.id)
  const card = await read($, cardAtom)
  const skill = node.skills[0] ?? 'a skill'
  const what =
    node.outcome === 'unsandboxed'
      ? 'NOT SANDBOXED exit 126'
      : node.outcome === 'blocked'
        ? `BLOCKED ${node.error ?? ''}`.trim()
        : `denied ${node.denied.join(', ') || 'unknown'}`
  toast($, `watchdeck: ${skill} ${what}. ${card?.fix ? '1: grant  2: open' : '2: open'}`)
  await updateStatus($)
  void loadRequests($)
}

// ---------------------------------------------------------------------------
// the activity log (D4)

type FetchResult = {
  state: 'ok' | 'missing' | 'too-large' | 'unavailable' | 'error'
  page?: ActivityPage
  detail?: string
  via: 'binary' | 'file' | 'none'
}

/** One bounded read: through the binary when it has `activity`, else the file under 4 MiB. */
async function fetchActivity($: Engine, o: { bin: string; path: string | null; enabled: boolean; sessionId: string; after: number | undefined }): Promise<FetchResult> {
  if (!o.enabled) return { state: 'unavailable', detail: 'activity log off (WATCHDECK_ACTIVITY=off)', via: 'none' }
  try {
    const r = await $.process.run(activityArgv(o.bin, o.sessionId, o.after), { timeoutMs: 5000 })
    if (r.exitCode === 0) return { state: 'ok', page: parseActivityOutput(r.stdout), via: 'binary' }
    // exit 3 is a usage error: a binary without `activity`, or one without a flag the mod passes
    if (r.exitCode !== 3) {
      return { state: 'error', detail: firstLine(r.stderr) || `activity exited ${r.exitCode}`, via: 'binary' }
    }
    debugLog($, `activity --json unusable (${firstLine(r.stderr)}); reading the file`)
  } catch (err) {
    return { state: 'error', detail: `could not run activity: ${String(err)}`, via: 'binary' }
  }
  if (!o.path) return { state: 'missing', detail: 'activity log path unknown', via: 'file' }
  let size = 0
  try {
    size = (await $.fs.stat(o.path)).size
  } catch {
    return { state: 'missing', detail: `activity log not found at ${o.path}`, via: 'file' }
  }
  if (size >= MAX_FILE_BYTES) return { state: 'too-large', detail: 'activity log too large to read in-session', via: 'file' }
  try {
    const text = await $.fs.read(o.path)
    const parsed = parseJsonl(typeof text === 'string' ? text : '')
    return { state: 'ok', page: { records: filterFileRecords(parsed.records, o.sessionId), next: 0, reset: false, skipped: parsed.skipped }, via: 'file' }
  } catch (err) {
    return { state: 'error', detail: `could not read ${o.path}: ${String(err)}`, via: 'file' }
  }
}

/** Reads the log once, merges it, announces a denial it reveals. */
async function refreshActivity($: Engine): Promise<void> {
  if (live.refreshing) {
    live.refreshQueued = true
    return
  }
  live.refreshing = true
  try {
    const binary = await read($, binaryAtom)
    if (binary.state !== 'ok' || !binary.path) return
    const activity = await read($, activityAtom)
    const cursor = await read($, cursorAtom)
    const sessionId = await $.session.id()
    const before = await read($, nodesAtom)
    const res = await fetchActivity($, {
      bin: binary.path,
      path: activity.path,
      enabled: activity.enabled,
      sessionId,
      after: live.firstLoad || cursor === null ? undefined : cursor.next,
    })
    if (res.state !== 'ok' || !res.page) {
      const detail = res.detail
      await update($, activityAtom, a => (detail ? { ...a, state: res.state, detail } : { ...a, state: res.state }))
      if (res.state === 'too-large') await updateStatus($)
      return
    }
    const page = res.page
    if (page.reset) {
      live.firstLoad = true
      await update($, cursorAtom, () => null)
    }
    const merged = bounded(mergeRecords(before, page.records, sessionId))
    await update($, nodesAtom, () => merged)
    await update($, activityAtom, (a): WatchdeckActivityState => ({ ...a, state: 'ok', unreadable: a.unreadable + page.skipped }))
    if (res.via === 'binary' && !page.reset) {
      await update($, cursorAtom, () => ({ next: page.next }))
      live.firstLoad = false
    }
    await recompute($)
    const pending = await read($, pendingDenialAtom)
    for (const n of merged) {
      if (n.kind !== 'call' || !isDenialOutcome(n)) continue
      const prev = findCall(before, n.id)
      if ((prev && isDenialOutcome(prev)) || pending === n.id) continue
      await announceDenial($, n)
      break
    }
  } catch (err) {
    debugLog($, `activity refresh failed: ${String(err)}`)
  } finally {
    live.refreshing = false
    if (live.refreshQueued) {
      live.refreshQueued = false
      scheduleRefresh($)
    }
  }
}

function scheduleRefresh($: Engine): void {
  try {
    live.refreshTimer?.cancel()
    live.refreshTimer = $.clock.after(DEBOUNCE_MS, () => {
      live.refreshTimer = undefined
      void refreshActivity($)
    })
  } catch (err) {
    debugLog($, `could not arm the refresh timer: ${String(err)}`)
  }
}

// ---------------------------------------------------------------------------
// the Bash result (D3)

type BashResult = { isError?: boolean; text?: string; result?: unknown }

/** Applies a Bash result to its node: trailer, exit, markers, declined. */
function applyBashResult(node: WatchdeckCallNode, ran: BashResult): void {
  const text = ran.text ?? ''
  // the engine's errored result stores the error text, not the tool's record; read the fields only when they exist
  const rec = ran.result && typeof ran.result === 'object' ? (ran.result as { stdout?: unknown; stderr?: unknown }) : undefined
  const stdout = typeof rec?.stdout === 'string' ? rec.stdout : ''
  const stderr = typeof rec?.stderr === 'string' ? rec.stderr : ''
  // Only a run the hook named is a skill run. The result is the script's
  // output, so a trailer in it is read for the exit code alone, never for
  // skills or ungranted items: the rewrite names the skills, the log the items.
  const isSkillRun = node.skills.length > 0 || node.decision !== 'none'
  const trailer = isSkillRun ? parseTrailer(stderr) ?? parseTrailer(text) : null
  if (trailer) {
    node.exit = trailer.exit
    node.outcome = outcomeForExit(trailer.exit)
  } else if (ran.isError) {
    const m = /Exit code (\d+)/.exec(text)
    if (m) node.exit = Number(m[1])
    if (node.decision === 'ask' && looksDeclined(text)) {
      node.outcome = 'declined'
      return
    }
    node.outcome = 'error'
    node.error = firstLine(text)
  } else {
    node.exit = 0
    node.outcome = 'ok'
  }
  if (!isSkillRun || node.outcome === 'unsandboxed') return
  // the result text as the model read it, plus the record's own streams when the engine kept them
  const markers = findDenialMarkers([text, stdout, stderr].filter(Boolean).join('\n'))
  if (markers.length > 0) {
    node.outcome = 'denied'
    node.evidence = 'result_text'
    node.denied = Array.from(new Set(markers.map(m => deniedWhat(m.what))))
  }
}

// ---------------------------------------------------------------------------
// the grant path (D6): only from a ui.press handler

/** The confirm flow: validate, ask, run, report. */
async function confirmAndGrant($: Engine, fix: WatchdeckFix, node: WatchdeckCallNode, bin: string): Promise<'granted' | 'cancelled' | 'refused' | 'failed'> {
  const v = validateGrantArgv(fix.argv, {
    bin,
    skills: node.skills,
    home: await $.env.get('HOME'),
    cwd: await $.session.cwd(),
    tmpdir: await $.env.get('TMPDIR'),
  })
  if (!v.ok) {
    toast($, `watchdeck: refusing: unexpected grant (${v.reason})`)
    return 'refused'
  }
  // the dialog shows exactly what runs: the absolute binary and every argument quoted
  const exact = quoteArgv(fix.argv)
  let answer: string
  try {
    answer = await $.ui.ask(`Run ${exact}?`, ['Grant', 'Cancel'])
  } catch {
    return 'cancelled'
  }
  if (answer !== 'Grant') {
    toast($, 'watchdeck: grant cancelled; nothing changed')
    return 'cancelled'
  }
  try {
    const r = await $.process.run(fix.argv, { timeoutMs: 10_000 })
    if (r.exitCode === 0) {
      toast($, `watchdeck: granted: ${firstLine(r.stdout) || fix.text}`)
      $.ui.log(`watchdeck: ran ${exact}`)
      return 'granted'
    }
    const err = firstLine(r.stderr) || `exit ${r.exitCode}`
    toast($, `watchdeck: allow failed: ${err}`)
    $.ui.log(`watchdeck: ${exact} failed: ${err}`)
    return 'failed'
  } catch (err) {
    toast($, `watchdeck: allow could not run: ${String(err)}`)
    return 'failed'
  }
}

/** The grant key's work (band `1`): card → confirm → run; clears the band on success. */
async function grantFromCard($: Engine, toolUseId: string | null): Promise<void> {
  const nodes = await read($, nodesAtom)
  const id = toolUseId ?? (await read($, selectedAtom))
  const node = id ? findCall(nodes, id) : undefined
  if (!node) {
    toast($, 'watchdeck: select a skill run first')
    return
  }
  const binary = await read($, binaryAtom)
  if (binary.state !== 'ok' || !binary.path) {
    toast($, 'watchdeck: binary not found; nothing can be granted from here')
    return
  }
  let card = await read($, cardAtom)
  if (!card || card.toolUseId !== node.id) {
    card = buildCard(node, await read($, requestsAtom), binary.path, await $.env.get('HOME'))
  }
  if (!card.fix) {
    toast($, card.notes[0] ? `watchdeck: ${card.notes[0]}` : 'watchdeck: nothing to grant for this run')
    return
  }
  const outcome = await confirmAndGrant($, card.fix, node, binary.path)
  if (outcome === 'granted') {
    if ((await read($, pendingDenialAtom)) === node.id) await update($, pendingDenialAtom, () => null)
    void loadRequests($, true)
    await recompute($)
    await updateStatus($)
  }
}

/** Band `2`: makes sure the dashboard runs (`ui --ensure --open`: reuses a running one, else starts it with no idle exit) and opens the browser; toasts the port line (never a token). */
async function openDashboard($: Engine): Promise<void> {
  const binary = await read($, binaryAtom)
  if (binary.state !== 'ok' || !binary.path) {
    toast($, 'watchdeck: binary not found')
    return
  }
  try {
    const r = await $.process.run([binary.path, 'ui', '--ensure', '--open'], { timeoutMs: 10_000 })
    if (r.exitCode === 0) {
      toast($, `watchdeck: ${(firstLine(r.stdout) || 'dashboard started').replace(/#t=\S*/, '')}`)
      return
    }
    if (r.exitCode === 3) {
      toast($, 'watchdeck: this binary has no `ui --ensure`; run `watchdeck ui` in a terminal')
      return
    }
    toast($, `watchdeck: ui failed: ${firstLine(r.stderr) || `exit ${r.exitCode}`}`)
  } catch (err) {
    toast($, `watchdeck: ui could not run: ${String(err)}`)
  }
}

/**
 * The band's `3: fix` (first run): Claude Code's sandbox is on and `watchdeck
 * run *` is not excluded, so every sandboxed skill run fails closed. Only from a
 * press, only after the confirm returns exactly "Fix", only this fixed argv with
 * the absolute binary resolved at session start; nothing a script or the model
 * says can shape it.
 */
async function fixExclusion($: Engine): Promise<void> {
  const binary = await read($, binaryAtom)
  if (binary.state !== 'ok' || !binary.path) {
    toast($, 'watchdeck: binary not found; nothing can be fixed from here')
    return
  }
  const argv = [binary.path, 'setup', '--exclusion-only', '--yes', '--plugin']
  const exact = quoteArgv(argv)
  let answer: string
  try {
    answer = await $.ui.ask(`Run ${exact}? It adds "watchdeck run *" to sandbox.excludedCommands in your user settings, after a backup.`, ['Fix', 'Cancel'])
  } catch {
    return
  }
  if (answer !== 'Fix') {
    toast($, 'watchdeck: fix cancelled; nothing changed')
    return
  }
  try {
    const r = await $.process.run(argv, { timeoutMs: 10_000 })
    if (r.exitCode === 0) {
      await update($, excludedAtom, () => true)
      toast($, 'watchdeck: "watchdeck run *" is now excluded from Claude Code\'s sandbox')
      $.ui.log(`watchdeck: ran ${exact}`)
      await updateStatus($)
      return
    }
    const err = firstLine(r.stderr) || `exit ${r.exitCode}`
    toast($, `watchdeck: setup failed: ${err}`)
    $.ui.log(`watchdeck: ${exact} failed: ${err}`)
  } catch (err) {
    toast($, `watchdeck: setup could not run: ${String(err)}`)
  }
}

// ---------------------------------------------------------------------------
// session.start

async function sessionStart($: Engine, e: { cwd: string; isInteractive: boolean }): Promise<void> {
  live.interactive = e.isInteractive
  live.firstLoad = true
  const home = await $.env.get('HOME')
  const tmpdir = await $.env.get('TMPDIR')
  const path = await $.env.get('PATH')
  const found = await locateBinary($, { home, cwd: e.cwd, tmpdir, path })
  for (const r of found.refused) debugLog($, `refused binary ${r}: a copy under the project or $TMPDIR is never run`)
  const binary: WatchdeckBinary = found.path === null
    ? { state: 'missing', reason: missingReason(found.refused) }
    : await probeVersion($, found.path)
  await update($, binaryAtom, () => binary)
  await update($, hookOnAtom, () => binary.state === 'ok')
  if (binary.state === 'ok') debugLog($, `binary ${binary.path} (${binary.version ?? 'version unknown'})`)
  else debugLog($, `binary missing: ${binary.reason ?? ''}`)

  // the fail-closed exit-126 case: Claude Code's sandbox on without the exclusion
  try {
    const settings = await $.settings.read()
    const sandbox = settings['sandbox']
    const box = sandbox && typeof sandbox === 'object' ? (sandbox as { enabled?: unknown; excludedCommands?: unknown }) : undefined
    const enabled = box?.enabled === true
    const excluded = Array.isArray(box?.excludedCommands) && box.excludedCommands.some(c => typeof c === 'string' && /^watchdeck run\b/.test(c))
    await update($, sandboxOnAtom, () => enabled)
    await update($, excludedAtom, () => excluded)
  } catch (err) {
    debugLog($, `settings read failed: ${String(err)}`)
  }

  // the activity log path: `paths --json` when the binary has it, else the XDG rule
  let activityPath: string | null = null
  let enabled = true
  const envPath = await $.env.get('WATCHDECK_ACTIVITY')
  if (envPath === 'off') enabled = false
  else if (envPath) activityPath = envPath
  else {
    const state = await $.env.get('XDG_STATE_HOME')
    const base = state && state.startsWith('/') ? state : home ? `${home}/.local/state` : null
    activityPath = base ? `${base}/watchdeck/activity.jsonl` : null
  }
  if (binary.state === 'ok' && binary.path) {
    try {
      const r = await $.process.run([binary.path, 'paths', '--json'], { timeoutMs: 5000 })
      if (r.exitCode === 0) {
        const p = JSON.parse(r.stdout) as { activity?: unknown }
        if (typeof p.activity === 'string') {
          if (p.activity === '') enabled = false
          else activityPath = p.activity
        }
      }
    } catch (err) {
      debugLog($, `paths --json unavailable: ${String(err)}`)
    }
  }
  await update($, activityAtom, (a): WatchdeckActivityState => ({ ...a, path: activityPath, enabled, state: 'unknown' }))
  await update($, cursorAtom, () => null)

  await updateStatus($)
}

// ---------------------------------------------------------------------------
// register

export const register: Register = on => {
  on('session.start', async ($, e, next) => {
    try {
      await sessionStart($, e)
    } catch (err) {
      debugLog($, `session.start failed: ${String(err)}`)
    }
    return next(e)
  })

  // decisions (D2): the plugin's own command hook answers beneath this module
  on('classic.PreToolUse', { tool: 'Bash' }, async ($, e, next) => {
    const d = await next(e)
    try {
      if ((await read($, binaryAtom)).state !== 'ok') return d
      const decision = d.allow ? 'allow' : d.ask !== undefined ? 'ask' : d.deny !== undefined ? 'deny' : 'none'
      const updated = d.updatedInput?.['command']
      const rewritten = typeof updated === 'string' ? updated : undefined
      const skills = parseRewrite(rewritten)?.skills ?? []
      const reason = d.ask ?? d.deny
      let node = await patchCall($, e.tool_use_id, n => {
        n.decision = decision
        if (reason !== undefined) n.reason = reason
        if (rewritten !== undefined) n.rewritten = rewritten
        if (skills.length > 0) n.skills = skills
      })
      if (!node && decision !== 'none') {
        // a decision for a call this load did not see start (a reload mid-call)
        const now = await $.clock.now()
        await update($, nodesAtom, list => {
          const out = [...list]
          const fresh: WatchdeckCallNode = {
            kind: 'call',
            id: e.tool_use_id,
            parent: ensureParent(out, undefined, now),
            tool: 'Bash',
            summary: summaryOf('Bash', e as Readonly<Record<string, unknown>>),
            command: e.command,
            decision,
            skills,
            outcome: 'waiting',
            denied: [],
          }
          if (reason !== undefined) fresh.reason = reason
          if (rewritten !== undefined) fresh.rewritten = rewritten
          out.push(fresh)
          return bounded(out)
        })
        node = findCall(await read($, nodesAtom), e.tool_use_id)
      }
      if (node && skills.length > 0) {
        // hang the call under its skill node (synthesised when no Skill call came first)
        await update($, nodesAtom, list => {
          const out = [...list]
          const call = findCall(out, e.tool_use_id)
          if (!call) return list
          const parentNode = out.find(n => n.id === call.parent)
          if (parentNode && parentNode.kind === 'skill') return list
          const skillId = ensureSkill(out, skills[0] as string, call.parent, call.agentId)
          return out.map(n => (n.id === call.id && n.kind === 'call' ? { ...n, parent: skillId } : n))
        })
      }
      await recompute($)
    } catch (err) {
      debugLog($, `classic.PreToolUse observe failed: ${String(err)}`)
    }
    return d
  }).catch(($, e, next) => next(e))

  // outcomes (D3) and the rows of every tool
  on('tool.call', async ($, e, next) => {
    // the mod's own calls (the confirm dialog behind $.ui.ask) are never rows
    if (next.origin.plugin === $.plugin.name || e.tool === 'AskUserQuestion') return next(e)
    let tracked = false
    try {
      if ((await read($, binaryAtom)).state === 'ok') {
        const now = await $.clock.now()
        const tool = String(e.tool)
        const agentId = e.agentId
        if (tool === 'Skill') {
          const raw = (e as { skill?: unknown }).skill
          const skill = typeof raw === 'string' && isSkillName(raw) ? raw : ''
          if (skill) {
            await update($, nodesAtom, list => {
              const out = [...list]
              const parent = ensureParent(out, agentId, now)
              if (!out.some(n => n.kind === 'skill' && n.skill === skill && n.parent === parent)) {
                const node: WatchdeckNode = { kind: 'skill', id: e.tool_use_id, parent, skill }
                if (agentId) node.agentId = agentId
                out.push(node)
              }
              return bounded(out)
            })
          }
        } else if (tool !== 'Agent') {
          tracked = true
          await update($, nodesAtom, list => {
            const out = [...list]
            const node: WatchdeckCallNode = {
              kind: 'call',
              id: e.tool_use_id,
              parent: ensureParent(out, agentId, now),
              tool,
              summary: summaryOf(tool, e as Readonly<Record<string, unknown>>),
              decision: 'none',
              skills: [],
              outcome: 'waiting',
              denied: [],
            }
            const command = (e as { command?: unknown }).command
            if (tool === 'Bash' && typeof command === 'string') node.command = command
            if (agentId) node.agentId = agentId
            out.push(node)
            const counted = agentId ? out.map(n => (n.kind === 'agent' && n.id === agentId ? { ...n, calls: n.calls + 1 } : n)) : out
            return bounded(counted)
          })
        }
      }
    } catch (err) {
      debugLog($, `tool.call observe (before) failed: ${String(err)}`)
    }
    const ran = await next(e)
    if (!tracked) return ran
    try {
      const node = await patchCall($, e.tool_use_id, n => {
        if (String(e.tool) === 'Bash') {
          applyBashResult(n, ran as BashResult)
        } else {
          n.outcome = ran.isError ? 'error' : 'ok'
          if (ran.isError) n.error = firstLine(ran.text)
        }
      })
      await recompute($)
      if (node && isDenialOutcome(node)) await announceDenial($, node)
      else if (node && node.skills.length > 0) await updateStatus($)
      if (node && (node.skills.length > 0 || node.decision !== 'none')) scheduleRefresh($)
    } catch (err) {
      debugLog($, `tool.call observe (after) failed: ${String(err)}`)
    }
    return ran
  }).catch(($, e, next) => next(e))

  // subagents
  on('agent.spawn', async ($, e, next) => {
    const r = await next(e)
    try {
      if ((await read($, binaryAtom)).state === 'ok' && r.agentId) {
        const now = await $.clock.now()
        const agentId = r.agentId
        await update($, nodesAtom, list => {
          if (list.some(n => n.id === agentId)) return list
          const out = [...list]
          out.push({
            kind: 'agent',
            id: agentId,
            parent: ensureParent(out, e.parentAgentId, now),
            toolUseId: e.tool_use_id ?? '',
            type: e.subagentType,
            description: e.description,
            calls: 0,
            status: 'running',
            startedAt: now,
          })
          return bounded(out)
        })
      }
    } catch (err) {
      debugLog($, `agent.spawn observe failed: ${String(err)}`)
    }
    return r
  }).catch(($, e, next) => next(e))

  // prompts
  on('turn.start', async ($, e, next) => {
    try {
      // the person moved on: the denial band goes away (key 1 grants only while
      // it shows; the dashboard still lists the denial). Only a typed prompt on
      // the main loop counts: a subagent's turn carries agentId, and a
      // continuation starts with text "".
      if (!e.agentId && e.text.trim() !== '' && (await read($, pendingDenialAtom)) !== null) await update($, pendingDenialAtom, () => null)
    } catch (err) {
      debugLog($, `turn.start clear failed: ${String(err)}`)
    }
    try {
      if ((await read($, binaryAtom)).state === 'ok' && e.text.trim() !== '') {
        const now = await $.clock.now()
        await update($, nodesAtom, list => {
          const id = `prompt:${e.turnId}`
          return list.some(n => n.id === id) ? list : bounded([...list, promptNode(id, e.text, now)])
        })
      }
    } catch (err) {
      debugLog($, `turn.start observe failed: ${String(err)}`)
    }
    return next(e)
  })

  on('turn.complete', async ($, e, next) => {
    try {
      if ((await read($, binaryAtom)).state === 'ok') {
        if (e.agentId) {
          const agentId = e.agentId
          await update($, nodesAtom, list => list.map(n => (n.kind === 'agent' && n.id === agentId ? { ...n, status: 'done' } : n)))
        } else {
          live.refreshTimer?.cancel()
          live.refreshTimer = undefined
          await refreshActivity($)
          await updateStatus($)
        }
      }
    } catch (err) {
      debugLog($, `turn.complete observe failed: ${String(err)}`)
    }
    return next(e)
  })

  // skills the person typed as /name bypass PreToolUse; attribution only
  on('skill.prompt', async ($, e, next) => {
    try {
      if ((await read($, binaryAtom)).state === 'ok' && isSkillName(e.skill)) {
        const now = await $.clock.now()
        await update($, nodesAtom, list => {
          const out = [...list]
          ensureSkill(out, e.skill, ensureParent(out, undefined, now), undefined)
          return bounded(out)
        })
      }
    } catch (err) {
      debugLog($, `skill.prompt observe failed: ${String(err)}`)
    }
    return next(e)
  })

  // the band (§1.6, D5): digits, since letters press only while the band holds the keys
  on('ui.render', { component: 'AbovePrompt' }, async ($, e, next) => {
    if (e.props.hasSurvey) return next(e)
    if ((await read($, binaryAtom)).state !== 'ok') return next(e)
    const nodes = await read($, nodesAtom)
    const pending = await read($, pendingDenialAtom)
    const denial = pending ? findCall(nodes, pending) : undefined
    const waiting = denial
      ? undefined
      : nodes.find(
          (n): n is WatchdeckCallNode =>
            n.kind === 'call' && n.skills.length > 0 && n.decision === 'ask' && (n.outcome === 'waiting' || n.outcome === 'running'),
        )
    // first run: the sandbox is on without the exclusion (a denial or a pending ask comes first)
    const needsFix = !denial && !waiting && (await read($, sandboxOnAtom)) && !(await read($, excludedAtom))
    if (!denial && !waiting && !needsFix) return next(e)

    const { Box, Button, Text } = $.ui.resolve(e)
    const cols = e.props.bodyColumns
    if (needsFix) {
      const full = 'watchdeck · Claude Code sandbox is on without "watchdeck run *" excluded: skill scripts fail closed'
      const text = cols < 60 ? 'watchdeck · sandbox exclusion missing' : full
      return (
        <Box gap={1}>
          <Text dimColor>{truncate(text, Math.max(8, cols - '3: fix'.length - 1))}</Text>
          <Button key="band-fix" plain hotkey="3" onPress={() => { void fixExclusion($) }}>fix</Button>
        </Box>
      )
    }
    const runs = nodes.filter(n => n.kind === 'call' && n.skills.length > 0).length
    const deniedCount = nodes.filter(n => n.kind === 'call' && isDenialOutcome(n)).length
    const card = await read($, cardAtom)
    const fix = denial && card && card.toolUseId === denial.id ? card.fix : undefined

    // the Buttons draw as `1: grant` and `2: open`, one column of gap before each
    // until the log record names what to grant, `1: grant` is drawn dim (from 40 columns)
    const grantShown = !!denial && (!!fix || cols >= 40)
    const room = Math.max(8, cols - (grantShown ? '1: grant'.length + 1 : 0) - ('2: open'.length + 1))
    let text: string
    if (denial) {
      const skill = denial.skills[0] ?? denial.tool
      const what =
        denial.outcome === 'unsandboxed' ? 'not sandboxed' : denial.outcome === 'blocked' ? 'blocked' : denial.denied.join(', ') || 'unknown'
      const runsText = `${runs} skill run${runs === 1 ? '' : 's'}`
      const short = `watchdeck · ${deniedCount} denied`
      if (cols < 40) text = short.length <= room ? short : `${deniedCount} denied`
      else if (cols < 60 || !fix) text = `watchdeck · ${runsText} · ${deniedCount} denied ${skill}: ${what}`
      else text = `watchdeck · ${runsText} · ${deniedCount} denied ${skill}: ${what} · fix ${fix.text}`
    } else {
      const skill = waiting?.skills[0] ?? 'a skill'
      text = cols < 40 ? 'watchdeck · ask pending' : `watchdeck · ask pending for ${skill} (answer the permission dialog)`
    }
    const shown = truncate(text, room)

    return (
      <Box gap={1}>
        <Text dimColor>{shown}</Text>
        {denial && fix ? <Button key="band-grant" plain hotkey="1" onPress={() => { void grantFromCard($, denial.id) }}>grant</Button> : ''}
        {denial && !fix && cols >= 40 ? <Text dimColor>1: grant</Text> : ''}
        <Button key="band-open" plain hotkey="2" onPress={() => { void openDashboard($) }}>open</Button>
      </Box>
    )
  })
}
