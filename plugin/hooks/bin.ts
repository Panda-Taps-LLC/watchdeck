// Binary resolution helpers (cross-phase decision 13), pure: the order of
// candidate directories, the "under a forbidden root" test and the version
// probe's output parser. register.tsx does the `$.fs` and `$.process` calls
// (the validator follows `$` only inside the file that holds the hook).

export type BinRoots = {
  home: string | undefined
  cwd: string
  tmpdir: string | undefined
  path: string | undefined
}

function trimSlash(p: string): string {
  return p.length > 1 ? p.replace(/\/+$/, '') : p
}

/** Whether `path` is `root` or lies beneath it (lexical, after trimming). */
export function isUnder(path: string, root: string | undefined): boolean {
  if (!root) return false
  const r = trimSlash(root)
  if (r === '/' || r === '') return false
  const p = trimSlash(path)
  return p === r || p.startsWith(r + '/')
}

/**
 * Candidate directories in order: absolute PATH entries, then the install
 * dirs the plugin's bin/hook.sh also tries. Relative entries are skipped.
 */
export function candidateDirs(roots: BinRoots): string[] {
  const out: string[] = []
  const seen = new Set<string>()
  const add = (dir: string) => {
    const d = trimSlash(dir)
    if (!d.startsWith('/') || seen.has(d)) return
    seen.add(d)
    out.push(d)
  }
  for (const entry of (roots.path ?? '').split(':')) {
    if (entry) add(entry)
  }
  if (roots.home) add(`${roots.home}/.local/share/watchdeck/bin`)
  add('/opt/homebrew/bin')
  add('/usr/local/bin')
  return out
}

/** The version from `version --json` (`{"version":…}`) or the plain `watchdeck <v>` line. */
export function parseVersionOutput(stdout: string): string {
  const out = stdout.trim()
  try {
    const parsed = JSON.parse(out) as { version?: unknown }
    if (parsed && typeof parsed === 'object' && typeof parsed.version === 'string') return parsed.version
  } catch {
    // older binary: plain text
  }
  const m = /^watchdeck\s+(\S+)/.exec(out)
  return m?.[1] ?? out.slice(0, 40)
}

/** Why no binary was accepted, for the status line. */
export function missingReason(refused: readonly string[]): string {
  return refused.length > 0
    ? 'only copies under the project directory or $TMPDIR were found (refused: a sandboxed script can write there)'
    : 'not on PATH, ~/.local/share/watchdeck/bin, /opt/homebrew/bin or /usr/local/bin'
}
