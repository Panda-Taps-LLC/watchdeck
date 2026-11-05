// watchdeck mod: the state contract (Spec C §1.3, 2026-10-12).
//
// Self-contained: no import, no reference. Every value the hooks module keeps
// in `$.state` is declared here, and `claude plugin validate` holds the
// module's `{ plugin: 'watchdeck', key }` references to these keys.

/** What the watchdeck hook decided for a Bash call (none: it had no opinion). */
export type WatchdeckDecision = 'allow' | 'ask' | 'deny' | 'none'

/** The hook's confidence in its rewrite; `low` runs unsandboxed if approved. */
export type WatchdeckConfidence = 'high' | 'low'

/**
 * How a call ended. `denied` is derived from evidence (a hint, a result marker
 * or a `denied` record), never stored as a run outcome by the binary.
 */
export type WatchdeckOutcome =
  | 'waiting'
  | 'running'
  | 'ok'
  | 'denied'
  | 'declined'
  | 'blocked'
  | 'unsandboxed'
  | 'error'

/**
 * Which of Phase B's three evidence sources (§3.3) decided a denial:
 * a `denied` activity record, a run record's stderr hint, or the Bash
 * result text (`<label>: DENIED(n)`, `Operation not permitted`).
 */
export type WatchdeckEvidence = 'record' | 'hint' | 'result_text'

/** One denial hint from a run record (the sandbox's stderr, heuristic). */
export type WatchdeckHint = {
  kind: string
  text: string
  line?: string
}

export type WatchdeckPromptNode = {
  kind: 'prompt'
  id: string
  parent: null
  text: string
  ts: number
}

export type WatchdeckSkillNode = {
  kind: 'skill'
  id: string
  parent: string
  skill: string
  agentId?: string
  request?: string
}

export type WatchdeckCallNode = {
  kind: 'call'
  /** The tool_use_id. */
  id: string
  parent: string
  tool: string
  /** The row text: the command or the tool's main argument, bounded. */
  summary: string
  /** The original Bash command text, verbatim (the activity join key). */
  command?: string
  agentId?: string
  decision: WatchdeckDecision
  confidence?: WatchdeckConfidence
  reason?: string
  rewritten?: string
  skills: string[]
  /**
   * `<skill>: network: all` entries, set only from an activity-log record the
   * binary wrote (decision or run), never from Bash output or the trailer:
   * the grant fix is built from this alone.
   */
  ungranted?: string[]
  exit?: number
  outcome: WatchdeckOutcome
  /** What was denied: `network`, `write <path>`, `read <path>`, `exec <path>`, `unknown`. */
  denied: string[]
  durationMs?: number
  joinedBy?: 'write' | 'heuristic'
  evidence?: WatchdeckEvidence
  hints?: WatchdeckHint[]
  /** `run.effective.summary` from the activity log. */
  ranAs?: string
  /** A `denied` record's reason, or the run record's error line. */
  error?: string
}

export type WatchdeckAgentNode = {
  kind: 'agent'
  /** The agentId. */
  id: string
  parent: string
  toolUseId: string
  type: string
  description: string
  calls: number
  status: 'running' | 'done'
  startedAt: number
}

export type WatchdeckNode =
  | WatchdeckPromptNode
  | WatchdeckSkillNode
  | WatchdeckCallNode
  | WatchdeckAgentNode

/** The argv the grant key runs (validated again before it runs) and its text. */
export type WatchdeckFix = {
  argv: string[]
  text: string
}

export type WatchdeckCard = {
  toolUseId: string
  skill: string
  request?: string
  grant?: string
  ranAs?: string
  why?: string
  /** The matched stderr line, drawn dim beneath `why`. */
  whyDetail?: string
  evidence?: string
  fix?: WatchdeckFix
  /** Items that have no CLI flag (read, env, exec) and how to grant them by hand. */
  notes: string[]
  joinedBy?: 'write' | 'heuristic'
}

export type WatchdeckCounts = {
  allow: number
  ask: number
  denied: number
  noOpinion: number
}

export type WatchdeckBinary = {
  state: 'unknown' | 'ok' | 'missing'
  /** Absolute path, resolved once at session.start (decision 13). */
  path?: string
  version?: string
  /** Why the binary is missing, when it is. */
  reason?: string
}

/** The activity reader's cursor: `next` from `activity --json`, passed as `--after`. */
export type WatchdeckCursor = { next: number }

/** skill → request summary, from `watchdeck audit --json`. */
export type WatchdeckRequestCache = Record<string, string>

export type WatchdeckActivityState = {
  path: string | null
  /** False when `WATCHDECK_ACTIVITY=off`. */
  enabled: boolean
  /** How the last read went. */
  state: 'unknown' | 'ok' | 'missing' | 'too-large' | 'unavailable' | 'error'
  /** Unparseable records skipped, kept as a count. */
  unreadable: number
  detail?: string
}

declare module 'claude-code' {
  interface PluginState {
    watchdeck: {
      /** Bounded: the last 500. */
      nodes: WatchdeckNode[]
      selected: string | null
      card: WatchdeckCard | null
      counts: WatchdeckCounts
      /** Mirrored to `$.store` for the next session. */
      hideNoOpinion: boolean
      /** tool_use_ids the person answered "keep denied". */
      keptDenied: string[]
      /** The tool_use_id the band shows. */
      pendingDenial: string | null
      binary: WatchdeckBinary
      /** Derived: the module is loaded and the binary is ok. */
      hookOn: boolean
      /** settings `sandbox.enabled`. */
      sandboxOn: boolean
      /** settings `sandbox.excludedCommands` has `watchdeck run *`. */
      excluded: boolean
      cursor: WatchdeckCursor | null
      activity: WatchdeckActivityState
      requests: WatchdeckRequestCache
    }
  }
}
