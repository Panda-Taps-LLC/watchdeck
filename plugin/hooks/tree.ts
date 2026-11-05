// The tree model: pure functions over the bounded node list, the counts, the
// card of the selected call and the grant fix built from `ungranted[]`.

import type {
  WatchdeckAgentNode,
  WatchdeckCallNode,
  WatchdeckCard,
  WatchdeckCounts,
  WatchdeckFix,
  WatchdeckNode,
  WatchdeckRequestCache,
  WatchdeckSkillNode,
} from '../types'

import { quoteIfNeeded } from './grant.ts'
import { parseUngranted, type Denial } from './trailer.ts'

export const MAX_NODES = 500
export const SUMMARY_MAX = 200

/** The set of nodes, bounded to the newest MAX_NODES. */
export function bounded(nodes: readonly WatchdeckNode[]): WatchdeckNode[] {
  return nodes.length > MAX_NODES ? nodes.slice(nodes.length - MAX_NODES) : [...nodes]
}

export function findNode(nodes: readonly WatchdeckNode[], id: string): WatchdeckNode | undefined {
  return nodes.find(n => n.id === id)
}

export function findCall(nodes: readonly WatchdeckNode[], id: string): WatchdeckCallNode | undefined {
  const n = findNode(nodes, id)
  return n?.kind === 'call' ? n : undefined
}

export function latestPrompt(nodes: readonly WatchdeckNode[]): WatchdeckNode | undefined {
  for (let i = nodes.length - 1; i >= 0; i -= 1) {
    const n = nodes[i]
    if (n?.kind === 'prompt') return n
  }
  return undefined
}

export function promptNode(id: string, text: string, ts: number): WatchdeckNode {
  return { kind: 'prompt', id, parent: null, text: text.replace(/\s+/g, ' ').trim().slice(0, SUMMARY_MAX), ts }
}

/**
 * The parent a new row hangs under: the agent's node when the call ran in a
 * subagent the mod saw spawn, else the latest prompt. Creates a prompt node
 * named "session" when none exists yet (the mod loaded mid-session).
 */
export function ensureParent(nodes: WatchdeckNode[], agentId: string | undefined, ts: number): string {
  if (agentId) {
    const agent = findNode(nodes, agentId)
    if (agent?.kind === 'agent') return agent.id
  }
  const prompt = latestPrompt(nodes)
  if (prompt) return prompt.id
  const id = `prompt:${ts}`
  nodes.push(promptNode(id, 'session', ts))
  return id
}

/** Finds or creates the skill node a call hangs under (mockup: `◆ skill <name>`). */
export function ensureSkill(nodes: WatchdeckNode[], skill: string, parent: string, agentId: string | undefined): string {
  for (let i = nodes.length - 1; i >= 0; i -= 1) {
    const n = nodes[i]
    if (n?.kind === 'skill' && n.skill === skill && n.parent === parent) return n.id
  }
  const id = `skill:${skill}:${parent}`
  const node: WatchdeckSkillNode = { kind: 'skill', id, parent, skill }
  if (agentId) node.agentId = agentId
  nodes.push(node)
  return id
}

export function summaryOf(tool: string, e: Readonly<Record<string, unknown>>): string {
  const pick = (k: string) => (typeof e[k] === 'string' ? (e[k] as string) : undefined)
  const text =
    pick('command') ??
    pick('file_path') ??
    pick('pattern') ??
    pick('skill') ??
    pick('description') ??
    pick('prompt') ??
    pick('url') ??
    pick('query') ??
    ''
  const one = text.replace(/\s+/g, ' ').trim()
  return one.length > SUMMARY_MAX ? one.slice(0, SUMMARY_MAX - 1) + '…' : one
}

export function countsOf(nodes: readonly WatchdeckNode[]): WatchdeckCounts {
  const c: WatchdeckCounts = { allow: 0, ask: 0, denied: 0, noOpinion: 0 }
  for (const n of nodes) {
    if (n.kind !== 'call') continue
    if (n.outcome === 'denied' || n.outcome === 'blocked') c.denied += 1
    if (n.decision === 'allow') c.allow += 1
    else if (n.decision === 'ask') c.ask += 1
    else if (n.skills.length === 0 && n.outcome !== 'blocked') c.noOpinion += 1
  }
  return c
}

/** The one-line "what was denied" for a run row from its evidence. */
export function deniedWhat(kind: Denial, value?: string): string {
  if (kind === 'network' || kind === 'unknown') return kind
  return value ? `${kind} ${value}` : kind
}

const CACHE_DIRS = ['~/Library/Caches', '~/.cache', '~/.npm/_cacache']

function expandHome(p: string, home: string | undefined): string {
  if (!home) return p
  if (p === '~') return home
  if (p.startsWith('~/')) return home + p.slice(1)
  if (p.startsWith('$HOME/')) return home + p.slice(5)
  if (p.startsWith('${HOME}/')) return home + p.slice(7)
  return p
}

function isCacheDir(p: string, home: string | undefined): boolean {
  const target = expandHome(p, home).replace(/\/+$/, '')
  return CACHE_DIRS.some(c => expandHome(c, home) === target)
}

export type FixBuild = {
  fix?: WatchdeckFix
  /** Human text for items no flag grants (read, env, exec). */
  notes: string[]
}

/**
 * Builds the `watchdeck allow <skill> …` argv from normalised ungranted
 * entries (Spec C §1.8, Spec A §1h): network and write have flags, a write of
 * a cache dir becomes `--caches`; read, env and exec have none and get text.
 * One skill per argv: the first skill with a grantable item.
 */
export function buildFix(ungranted: readonly string[], skills: readonly string[], bin: string | undefined, home: string | undefined): FixBuild {
  const notes: string[] = []
  const bySkill = new Map<string, string[]>()
  const fallback = skills[0] ?? ''
  for (const entry of ungranted) {
    const u = parseUngranted(entry, fallback)
    if (!u) continue
    switch (u.kind) {
      case 'network': {
        if (u.value === 'all' || u.value === 'localhost') {
          const flags = bySkill.get(u.skill) ?? []
          flags.push('--network', u.value)
          bySkill.set(u.skill, flags)
        } else {
          notes.push(`${u.skill}: network ${u.value} is not grantable`)
        }
        break
      }
      case 'write': {
        const flags = bySkill.get(u.skill) ?? []
        if (isCacheDir(u.value, home)) {
          if (!flags.includes('--caches')) flags.push('--caches')
        } else if (u.value) {
          flags.push('--write', expandHome(u.value, home))
        }
        bySkill.set(u.skill, flags)
        break
      }
      case 'read':
        notes.push(`${u.skill}: read ${u.value}: edit ~/.config/watchdeck/overrides.yaml (no allow flag)`)
        break
      case 'env':
        notes.push(`${u.skill}: env ${u.value}: edit ~/.config/watchdeck/overrides.yaml (no allow flag)`)
        break
      case 'exec':
        notes.push(`${u.skill}: exec ${u.value}: edit the skill's PERMISSIONS.yaml exec list`)
        break
      default:
        break
    }
  }
  for (const [skill, flags] of bySkill) {
    if (flags.length === 0) continue
    // --network first, then --write pairs, then --caches: the CLI's own order
    const ordered: string[] = []
    for (let i = 0; i < flags.length; i += 1) {
      if (flags[i] === '--network') ordered.push('--network', flags[i + 1] as string)
    }
    for (let i = 0; i < flags.length; i += 1) {
      if (flags[i] === '--write') ordered.push('--write', flags[i + 1] as string)
    }
    if (flags.includes('--caches')) ordered.push('--caches')
    const text = ['watchdeck', 'allow', skill, ...ordered].map(quoteIfNeeded).join(' ')
    if (!bin) {
      notes.push(`binary not found: run ${text} yourself`)
      return { notes }
    }
    return { fix: { argv: [bin, 'allow', skill, ...ordered], text }, notes }
  }
  return { notes }
}

/**
 * The grant summary the hook's reason states, for the card's `grant` line.
 * Display only: it never feeds the fix or any argv (buildFix reads the
 * log's ungranted list alone).
 */
function grantOf(reason: string | undefined, skill: string): string | undefined {
  if (!reason) return undefined
  // "watchdeck: <skill> under <summary>; …" → the summary
  const m = new RegExp(`(?:^|\\|\\s*)(?:watchdeck: )?${skill.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')} under ([^;|]+)`).exec(reason)
  if (m?.[1]) return m[1].trim()
  const d = /has no PERMISSIONS\.yaml; default profile \(([^)]*)\)/.exec(reason)
  return d?.[1]
}

/** The card of a call node (Spec C §1.5): request / grant / ran as / why / fix. */
export function buildCard(
  node: WatchdeckCallNode,
  requests: WatchdeckRequestCache,
  bin: string | undefined,
  home: string | undefined,
): WatchdeckCard {
  const skill = node.skills[0] ?? ''
  const ungranted = node.ungranted ?? []
  const card: WatchdeckCard = { toolUseId: node.id, skill, notes: [] }
  const req = requests[skill]
  if (req) card.request = req
  else if (ungranted.length > 0) card.request = ungranted.map(u => u.replace(new RegExp(`^${skill}: `), '')).join(', ')
  const grant = grantOf(node.reason, skill)
  if (grant) card.grant = grant
  if (node.ranAs) card.ranAs = node.ranAs
  if (node.joinedBy) card.joinedBy = node.joinedBy
  if (node.outcome === 'blocked') {
    card.why = `blocked before it ran: ${node.error ?? 'permission denied'}`
    card.evidence = 'the activity log (a denied record)'
  } else if (node.hints && node.hints.length > 0) {
    const h = node.hints[0] as { text: string; line?: string }
    card.why = h.text
    if (h.line) card.whyDetail = h.line
    card.evidence = "the sandbox's stderr, heuristic"
  } else if (node.outcome === 'denied') {
    card.why = "the script's own output reported the denial"
    card.evidence = 'the Bash result text'
    if (node.ranAs !== undefined && node.exit === 0) {
      card.notes.push('the run record says ok with no hints; the result text is the only evidence')
    }
  } else if (node.outcome === 'unsandboxed') {
    card.why = 'the sandbox could not be applied; the run refused to start (exit 126)'
  } else if (node.outcome === 'error' && node.error) {
    card.why = node.error
  } else if (node.outcome === 'declined') {
    card.why = 'you declined the ask'
  }
  const built = buildFix(ungranted, node.skills, bin, home)
  if (built.fix) card.fix = built.fix
  card.notes.push(...built.notes)
  return card
}

export function agentCalls(nodes: readonly WatchdeckNode[], agentId: string): number {
  return nodes.filter(n => n.kind === 'call' && n.agentId === agentId).length
}

export function isAgent(n: WatchdeckNode | undefined): n is WatchdeckAgentNode {
  return n?.kind === 'agent'
}
