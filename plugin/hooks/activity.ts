// The activity log (Spec A §1b schema v1), pure side: the record shape, the
// parsers for `activity --json` and raw JSONL, the argv the reader runs, and
// the merge into the tree. register.tsx does the `$.process` / `$.fs` calls.

import type { WatchdeckCallNode, WatchdeckHint, WatchdeckNode } from '../types'

import { deniedWhat as deniedText, ensureParent, ensureSkill, findCall, findNode } from './tree.ts'
import { denialOfLabel, normaliseUngranted, outcomeOfRecord, isSkillName, parseRewrite, skillNames } from './trailer.ts'

/** One record of the JSONL log; every field optional, `kind` decides. */
export type ActivityRecord = {
  v?: number
  kind?: string
  ts?: string
  session_id?: string
  tool_use_id?: string
  agent_id?: string
  agent_type?: string
  cwd?: string
  skills?: string[]
  command?: string
  decision?: string
  reason?: string
  rewritten?: string
  confidence?: string
  ungranted?: string[]
  exit?: number
  outcome?: string
  duration_ms?: number
  profile_hash?: string
  effective?: { summary?: string }
  hints?: { kind?: string; text?: string; line?: string }[]
  error?: string
  tool_name?: string
  skill?: string
  joined_by?: string
}

export type ActivityPage = {
  records: ActivityRecord[]
  next: number
  reset: boolean
  skipped: number
}

export const KINDS = 'decision,run,skill_invoked,denied'
export const KIND_SET: ReadonlySet<string> = new Set(KINDS.split(','))
/** `$.fs.read` rejects files of 4 MiB or more; the binary's reader has no cap. */
export const MAX_FILE_BYTES = 4 * 1024 * 1024

/** The `watchdeck activity --json` argv for one bounded read (A2). */
export function activityArgv(bin: string, sessionId: string, after: number | undefined): string[] {
  const argv = [bin, 'activity', '--json', '--session', sessionId, '--kinds', KINDS]
  if (after === undefined) argv.push('--tail', '200')
  else argv.push('--after', String(after))
  return argv
}

/** Parses raw JSONL; a torn or malformed line is counted, never thrown. */
export function parseJsonl(text: string): { records: ActivityRecord[]; skipped: number } {
  const records: ActivityRecord[] = []
  let skipped = 0
  for (const line of text.split('\n')) {
    const t = line.trim()
    if (!t) continue
    try {
      const v = JSON.parse(t) as unknown
      if (v && typeof v === 'object' && typeof (v as ActivityRecord).kind === 'string') {
        records.push(v as ActivityRecord)
      } else {
        skipped += 1
      }
    } catch {
      skipped += 1
    }
  }
  return { records, skipped }
}

/** Accepts `activity --json`'s object, or raw JSONL from an older reader. */
export function parseActivityOutput(stdout: string): ActivityPage {
  const t = stdout.trim()
  if (t.startsWith('{')) {
    try {
      const o = JSON.parse(t) as Partial<ActivityPage> & { records?: unknown; kind?: unknown }
      if (!Array.isArray(o.records) && typeof o.kind === 'string') {
        // one raw JSONL record, not the envelope
        return { records: [o as unknown as ActivityRecord], next: 0, reset: false, skipped: 0 }
      }
      const records = Array.isArray(o.records) ? (o.records as ActivityRecord[]) : []
      return {
        records,
        next: typeof o.next === 'number' ? o.next : 0,
        reset: o.reset === true,
        skipped: typeof o.skipped === 'number' ? o.skipped : 0,
      }
    } catch {
      // fall through to JSONL
    }
  }
  const parsed = parseJsonl(t)
  return { records: parsed.records, next: 0, reset: false, skipped: parsed.skipped }
}

/** The records of a whole-file read that belong to this session. */
export function filterFileRecords(records: readonly ActivityRecord[], sessionId: string): ActivityRecord[] {
  return records.filter(r => KIND_SET.has(r.kind ?? '') && (!r.session_id || r.session_id === sessionId))
}

function sameSkills(a: readonly string[], b: readonly string[]): boolean {
  if (a.length !== b.length) return false
  const sa = [...a].sort()
  const sb = [...b].sort()
  return sa.every((v, i) => v === sb[i])
}

function hintsOf(rec: ActivityRecord): WatchdeckHint[] {
  const out: WatchdeckHint[] = []
  for (const h of rec.hints ?? []) {
    if (!h || typeof h.text !== 'string') continue
    const hint: WatchdeckHint = { kind: h.kind ?? 'unknown', text: h.text }
    if (h.line) hint.line = h.line
    out.push(hint)
  }
  return out
}

function tsOf(rec: ActivityRecord): number {
  const t = rec.ts ? Date.parse(rec.ts) : NaN
  return Number.isFinite(t) ? t : 0
}

/** Applies a run record to a call node: exit, outcome, hints, ran-as, join. */
function applyRun(node: WatchdeckCallNode, rec: ActivityRecord): void {
  if (typeof rec.exit === 'number') node.exit = rec.exit
  // the grant fix is built only from what the binary wrote to the log
  if (rec.ungranted && rec.ungranted.length > 0) node.ungranted = normaliseUngranted(rec.ungranted, node.skills)
  if (typeof rec.duration_ms === 'number') node.durationMs = rec.duration_ms
  if (rec.effective?.summary) node.ranAs = rec.effective.summary
  node.joinedBy = rec.joined_by === 'write' ? 'write' : 'heuristic'
  const hints = hintsOf(rec)
  if (hints.length > 0) node.hints = hints
  const base = outcomeOfRecord(rec.outcome, rec.exit)
  if (rec.error) node.error = rec.error
  if (node.outcome === 'blocked' || node.outcome === 'declined') return
  if (hints.length > 0) {
    node.outcome = 'denied'
    node.evidence = 'hint'
    node.denied = Array.from(new Set(hints.map(h => deniedText(denialOfLabel(h.kind)))))
    return
  }
  if (base === 'unsandboxed') {
    node.outcome = 'unsandboxed'
    node.evidence = 'record'
    return
  }
  // the in-process guess from the result text stays for ok / failed runs with no hints
  if (node.outcome !== 'denied') node.outcome = base
}

function newCall(rec: ActivityRecord, parent: string, tool: string): WatchdeckCallNode {
  const node: WatchdeckCallNode = {
    kind: 'call',
    id: rec.tool_use_id as string,
    parent,
    tool,
    summary: (rec.command ?? rec.skill ?? '').slice(0, 200),
    decision: 'none',
    skills: skillNames(rec.skills),
    outcome: 'ok',
    denied: [],
  }
  if (rec.command) node.command = rec.command
  if (rec.agent_id) node.agentId = rec.agent_id
  return node
}

/**
 * Merges a page of records into a copy of the node list and returns it.
 * Decisions join by tool_use_id; runs by tool_use_id when the binary joined
 * them at write time (decision 2), else FIFO by command + skills; `denied`
 * records mark a call blocked; `skill_invoked` records add skill nodes.
 */
export function mergeRecords(nodes: readonly WatchdeckNode[], records: readonly ActivityRecord[], sessionId: string): WatchdeckNode[] {
  const out: WatchdeckNode[] = nodes.map(n => ({ ...n }))
  for (const rec of records) {
    if (rec.session_id && rec.session_id !== sessionId) continue
    switch (rec.kind) {
      case 'decision': {
        if (!rec.tool_use_id) break
        let node = findCall(out, rec.tool_use_id)
        if (!node) {
          node = newCall(rec, ensureParent(out, rec.agent_id, tsOf(rec)), 'Bash')
          out.push(node)
        }
        node.decision = rec.decision === 'allow' ? 'allow' : rec.decision === 'ask' ? 'ask' : node.decision
        if (rec.confidence === 'low' || rec.confidence === 'high') node.confidence = rec.confidence
        if (rec.reason) node.reason = rec.reason
        if (rec.rewritten) node.rewritten = rec.rewritten
        const recSkills = skillNames(rec.skills)
        const skills = recSkills.length > 0 ? recSkills : parseRewrite(rec.rewritten)?.skills ?? node.skills
        node.skills = skills
        if (rec.ungranted && rec.ungranted.length > 0) node.ungranted = normaliseUngranted(rec.ungranted, skills)
        if (skills.length > 0) {
          const parentNode = findNode(out, node.parent)
          if (parentNode && parentNode.kind !== 'skill') {
            node.parent = ensureSkill(out, skills[0] as string, node.parent, node.agentId)
          }
        }
        break
      }
      case 'run': {
        let node: WatchdeckCallNode | undefined
        if (rec.tool_use_id) node = findCall(out, rec.tool_use_id)
        if (!node && rec.command) {
          const skills = skillNames(rec.skills)
          node = out.find(
            (n): n is WatchdeckCallNode =>
              n.kind === 'call' && n.joinedBy === undefined && n.command === rec.command && sameSkills(n.skills, skills),
          )
        }
        if (!node) break
        applyRun(node, rec)
        break
      }
      case 'skill_invoked': {
        const skill = rec.skill
        if (!isSkillName(skill)) break
        const id = rec.tool_use_id ?? `skill:${skill}:${rec.ts ?? ''}`
        if (findNode(out, id)) break
        const parent = ensureParent(out, rec.agent_id, tsOf(rec))
        if (out.some(n => n.kind === 'skill' && n.skill === skill && n.parent === parent)) break
        const node: WatchdeckNode = { kind: 'skill', id, parent, skill }
        if (rec.agent_id) node.agentId = rec.agent_id
        out.push(node)
        break
      }
      case 'denied': {
        if (!rec.tool_use_id) break
        let node = findCall(out, rec.tool_use_id)
        if (!node) {
          node = newCall(rec, ensureParent(out, rec.agent_id, tsOf(rec)), rec.tool_name ?? 'Bash')
          out.push(node)
        }
        node.outcome = 'blocked'
        node.evidence = 'record'
        if (rec.reason) node.error = rec.reason
        if (node.skills.length === 0) node.skills = skillNames(rec.skills)
        break
      }
      default:
        break
    }
  }
  return out
}
