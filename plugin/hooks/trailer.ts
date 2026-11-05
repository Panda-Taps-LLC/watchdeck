// Pure parsers for what the watchdeck binary prints and what the hook
// rewrites to. No `$`, no state: unit-testable in isolation.

import type { WatchdeckOutcome } from '../types'

/** The `[watchdeck] exit N under profile <skills>/<hash> (<summary>).` trailer. */
export type Trailer = {
  exit: number
  skills: string[]
  hash: string
  summary: string
  /** `requested but not granted: …` lines, as printed (one item per line). */
  ungranted: string[]
  ignored: string[]
}

const TRAILER = /^\[watchdeck\] exit (\d+) under profile ([^\s/]+)\/([0-9a-fA-F]+) \((.*)\)\.\s*$/gm
const UNGRANTED = /^\[watchdeck\]\s+requested but not granted: (.+?)\s*$/gm
const IGNORED = /^\[watchdeck\]\s+(project override ignored: .+?)\s*$/gm

/** The last trailer in the text: the binary writes its own after the child exited. */
export function parseTrailer(text: string | undefined): Trailer | null {
  if (!text) return null
  let m: RegExpMatchArray | undefined
  for (const found of text.matchAll(TRAILER)) m = found
  if (!m) return null
  const ungranted: string[] = []
  for (const u of text.matchAll(UNGRANTED)) {
    if (u[1]) ungranted.push(u[1])
  }
  const ignored: string[] = []
  for (const i of text.matchAll(IGNORED)) {
    if (i[1]) ignored.push(i[1])
  }
  return {
    exit: Number(m[1]),
    skills: skillNames((m[2] ?? '').split('+')),
    hash: m[3] ?? '',
    summary: m[4] ?? '',
    ungranted,
    ignored,
  }
}

/** Splits a shell line into words: single quotes, double quotes, backslashes. */
export function shellWords(line: string): string[] {
  const out: string[] = []
  let cur = ''
  let inWord = false
  let i = 0
  while (i < line.length) {
    const c = line[i] as string
    if (c === "'") {
      inWord = true
      const end = line.indexOf("'", i + 1)
      if (end < 0) {
        cur += line.slice(i + 1)
        i = line.length
      } else {
        cur += line.slice(i + 1, end)
        i = end + 1
      }
      continue
    }
    if (c === '"') {
      inWord = true
      i += 1
      while (i < line.length && line[i] !== '"') {
        if (line[i] === '\\' && i + 1 < line.length) {
          const n = line[i + 1] as string
          if (n === '"' || n === '\\' || n === '$' || n === '`') {
            cur += n
            i += 2
            continue
          }
        }
        cur += line[i]
        i += 1
      }
      i += 1
      continue
    }
    if (c === '\\' && i + 1 < line.length) {
      inWord = true
      cur += line[i + 1]
      i += 2
      continue
    }
    if (c === ' ' || c === '\t' || c === '\n') {
      if (inWord) {
        out.push(cur)
        cur = ''
        inWord = false
      }
      i += 1
      continue
    }
    inWord = true
    cur += c
    i += 1
  }
  if (inWord) out.push(cur)
  return out
}

/** The hook's rewrite: `watchdeck run --skill X [--skill Y] -c '<original>'`. */
export type Rewrite = { skills: string[]; command: string }

/**
 * A skill name the mod accepts anywhere (rewrite, trailer, log record, grant):
 * no leading `-`, so `watchdeck allow <name>` never reads it as a flag.
 */
export const SKILL_NAME = /^[A-Za-z0-9._][A-Za-z0-9._-]{0,127}$/

export function isSkillName(name: string | undefined): name is string {
  return typeof name === 'string' && SKILL_NAME.test(name)
}

/** The valid names of a list, in order; anything else is dropped. */
export function skillNames(names: readonly unknown[] | undefined): string[] {
  return (names ?? []).filter((n): n is string => typeof n === 'string' && isSkillName(n))
}

export function parseRewrite(rewritten: string | undefined): Rewrite | null {
  if (!rewritten) return null
  const words = shellWords(rewritten.trim())
  let i = 0
  // an optional leading `cd <dir> &&` is not produced by the hook; the form is plain
  if (words[i] === undefined) return null
  if (!/(^|\/)watchdeck$/.test(words[i] as string)) return null
  i += 1
  if (words[i] !== 'run') return null
  i += 1
  const skills: string[] = []
  let command: string | undefined
  while (i < words.length) {
    const w = words[i] as string
    if (w === '--skill' || w === '-skill') {
      const name = words[i + 1]
      if (!isSkillName(name)) return null
      skills.push(name)
      i += 2
      continue
    }
    if (w === '-c') {
      command = words[i + 1]
      i += 2
      break
    }
    return null
  }
  if (skills.length === 0 || command === undefined) return null
  return { skills, command }
}

/** The skills a rewrite names, or none. */
export function skillsOf(rewritten: string | undefined): string[] {
  return parseRewrite(rewritten)?.skills ?? []
}

/** What a canary probe label or a hint kind denotes, in the shared vocabulary. */
export type Denial = 'network' | 'write' | 'read' | 'exec' | 'env' | 'unknown'

const LABELS: Record<string, Denial> = {
  net: 'network',
  localhost: 'network',
  network: 'network',
  'write-home': 'write',
  'write-cwd': 'write',
  write: 'write',
  'read-secret': 'read',
  read: 'read',
  subprocess: 'exec',
  exec: 'exec',
  env: 'env',
}

export function denialOfLabel(label: string): Denial {
  return LABELS[label] ?? 'unknown'
}

/** A denial the script's own output reported (evidence source 3). */
export type Marker = { label: string; what: Denial }

const PROBE = /^([A-Za-z][A-Za-z0-9_-]*): DENIED\((\d+)\)/gm
const GENERIC = /Operation not permitted|\bEPERM\b|\[Errno 1\]/

/**
 * Scans Bash result text for the probe marker, then the generic OS refusal.
 * The binary's own `[watchdeck] …` lines are skipped: the trailer's exec
 * note names "Operation not permitted" itself.
 */
export function findDenialMarkers(raw: string | undefined): Marker[] {
  if (!raw) return []
  const text = raw
    .split('\n')
    .filter(line => !line.startsWith('[watchdeck]'))
    .join('\n')
  const out: Marker[] = []
  for (const m of text.matchAll(PROBE)) {
    const label = m[1] as string
    out.push({ label, what: denialOfLabel(label) })
  }
  if (out.length === 0 && GENERIC.test(text)) {
    out.push({ label: 'script reported', what: 'unknown' })
  }
  return out
}

/** One `<skill>: <kind>: <value>` entry, parsed. */
export type Ungranted = { skill: string; kind: Denial; value: string }

const KINDS: Record<string, Denial> = { network: 'network', write: 'write', read: 'read', exec: 'exec', env: 'env' }

/**
 * Parses one ungranted entry. Accepts the normalised form
 * (`canary-request: network: all`) and the bare v0.1 trailer form
 * (`network: all`), which `fallbackSkill` completes.
 */
export function parseUngranted(entry: string, fallbackSkill: string): Ungranted | null {
  const parts = entry.split(':').map(s => s.trim())
  if (parts.length >= 3) {
    const [skill, kind, ...rest] = parts
    const k = KINDS[kind ?? '']
    if (k && isSkillName(skill)) return { skill, kind: k, value: rest.join(':') }
  }
  if (parts.length === 2) {
    const [kind, value] = parts
    const k = KINDS[kind ?? '']
    if (k && isSkillName(fallbackSkill)) return { skill: fallbackSkill, kind: k, value: value ?? '' }
  }
  return null
}

/** Normalises entries to `<skill>: <kind>: <value>`; drops what does not parse. */
export function normaliseUngranted(entries: readonly string[], skills: readonly string[]): string[] {
  const fallback = skills[0] ?? ''
  const out: string[] = []
  for (const e of entries) {
    const u = parseUngranted(e, fallback)
    if (u) out.push(`${u.skill}: ${u.kind}: ${u.value}`)
  }
  return out
}

/** The outcome an exit code alone implies (no hints, no marker). */
export function outcomeForExit(exit: number): WatchdeckOutcome {
  if (exit === 0) return 'ok'
  if (exit === 126) return 'unsandboxed'
  return 'error'
}

/** Maps a run record's `outcome` enum to the node's outcome, before evidence. */
export function outcomeOfRecord(outcome: string | undefined, exit: number | undefined): WatchdeckOutcome {
  switch (outcome) {
    case 'ok':
      return 'ok'
    case 'no_sandbox':
      return 'unsandboxed'
    case 'failed':
    case 'signaled':
    case 'policy_error':
    case 'usage':
      return 'error'
    default:
      return exit === undefined ? 'ok' : outcomeForExit(exit)
  }
}

/** The engine's refusal text for an ask the person declined (best effort; verified in dogfood). */
const DECLINED = /doesn't want to proceed|does not want to proceed|user (declined|rejected|denied)|rejected (the|this) tool|permission (was )?denied/i

export function looksDeclined(text: string | undefined): boolean {
  return !!text && DECLINED.test(text)
}

/** The first non-empty line of a text, trimmed and bounded. */
export function firstLine(text: string | undefined, max = 200): string {
  if (!text) return ''
  for (const line of text.split('\n')) {
    const t = line.trim()
    if (t) return t.length > max ? t.slice(0, max - 1) + '…' : t
  }
  return ''
}
