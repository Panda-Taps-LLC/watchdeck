// The mod's constants, the per-load caches, and the denial vocabulary
// shared with the band (Spec C §1.5). The `$.state` atoms live in
// register.tsx: the validator reads a state source only where it is declared
// in the file that reads it. Nothing here takes `$`.

import type { WatchdeckCallNode } from '../types'

export const PLUGIN = 'watchdeck'
export const DEBOUNCE_MS = 300

/**
 * Per-load caches. A hot reload resets them, which is safe: `interactive`
 * unknown means the session's surfaces are asked once; a dropped debounce
 * timer is re-armed by the next tool call (Spec C §1.9, R11).
 */
export type Live = {
  interactive: boolean | undefined
  refreshTimer: { cancel: () => void } | undefined
  refreshing: boolean
  refreshQueued: boolean
  firstLoad: boolean
  requestsLoading: boolean
}

export const live: Live = {
  interactive: undefined,
  refreshTimer: undefined,
  refreshing: false,
  refreshQueued: false,
  firstLoad: true,
  requestsLoading: false,
}

/** Whether a call's outcome is one the band and the toast announce. */
export function isDenialOutcome(n: WatchdeckCallNode): boolean {
  return n.outcome === 'denied' || n.outcome === 'blocked' || n.outcome === 'unsandboxed' || (n.outcome === 'error' && n.exit === 125)
}
