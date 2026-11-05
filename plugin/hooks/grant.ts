// The grant allow-list (Spec C §1.8, D6, decision 13), pure. register.tsx
// runs the confirm flow: a `ui.press` handler, `$.ui.ask` answering exactly
// "Grant", then `$.process.run` of an argv this function accepted.

import { isUnder } from './bin.ts'
import { isSkillName } from './trailer.ts'

/** One argument in single quotes, an embedded quote as `'\''`: always quoted. */
export function shellQuote(arg: string): string {
  return `'${arg.replace(/'/g, `'\\''`)}'`
}

/**
 * The exact argv as the confirm dialog and the transcript show it: argv[0]
 * the full absolute binary path, every element single-quoted, so a path with
 * spaces or a leading dash cannot read as extra flags.
 */
export function quoteArgv(argv: readonly string[]): string {
  return argv.map(shellQuote).join(' ')
}

/** For display only (the card, the band): quotes an argument when it needs it. */
export function quoteIfNeeded(arg: string): string {
  return /^[A-Za-z0-9._\/:=@%+,-]+$/.test(arg) ? arg : shellQuote(arg)
}

export type GrantContext = {
  /** The binary resolved at session.start; the only executable allowed. */
  bin: string
  /** The skills the record named; argv[2] must be one of them. */
  skills: readonly string[]
  home: string | undefined
  cwd: string
  tmpdir: string | undefined
}

export type Validation = { ok: true } | { ok: false; reason: string }

/**
 * The built-in deny paths (the binary's default profile), relative to $HOME.
 * The binary refuses to widen onto these; the mod never offers them.
 */
export const DENY_UNDER_HOME = ['.ssh', '.aws', '.gnupg', '.claude', '.config/gcloud', '.netrc', '.docker/config.json']

/**
 * Why a `--write` target may not be offered, or undefined when it may: an
 * absolute, normalised path (no `..`, `.`, `//`, trailing `/`) under $HOME,
 * the project or $TMPDIR; never $HOME itself, never at or under a built-in
 * deny path (compared case-insensitively: macOS volumes usually are), never a
 * file named `.env`. Lexical only: the binary resolves links and refuses too.
 */
export function unsafeWriteReason(p: string, ctx: Pick<GrantContext, 'home' | 'cwd' | 'tmpdir'>): string | undefined {
  if (!p.startsWith('/') || p.includes('\0') || p.includes('\n')) return 'write path is not absolute'
  const segs = p.split('/').slice(1)
  if (p !== '/' && segs.some(seg => seg === '' || seg === '.' || seg === '..')) return 'write path is not normalised'
  if (!(isUnder(p, ctx.home) || isUnder(p, ctx.cwd) || isUnder(p, ctx.tmpdir))) return 'write path outside $HOME, the project and $TMPDIR'
  const lower = p.toLowerCase()
  const home = ctx.home ? ctx.home.replace(/\/+$/, '') : undefined
  if (home && lower === home.toLowerCase()) return 'write path is $HOME itself'
  if (home) {
    for (const rel of DENY_UNDER_HOME) {
      if (isUnder(lower, `${home}/${rel}`.toLowerCase())) return `write path is under the built-in deny ~/${rel}`
    }
  }
  if ((segs.at(-1) ?? '').toLowerCase() === '.env') return 'write path is a .env file'
  return undefined
}

/**
 * Validates a grant argv: `[bin, 'allow', <skill>, flags…]` where the flags
 * are a subset of `--network localhost|all`, `--write <path>` (see
 * unsafeWriteReason) and `--caches`. Widening only: never `--auto`, never a revoke
 * (`--network none`, `--remove-write`, `--no-caches`, `--reset`), never `*`.
 */
export function validateGrantArgv(argv: readonly string[], ctx: GrantContext): Validation {
  if (argv.length < 4) return { ok: false, reason: 'nothing to grant' }
  if (argv[0] !== ctx.bin || !ctx.bin.startsWith('/')) return { ok: false, reason: 'unexpected executable' }
  if (argv[1] !== 'allow') return { ok: false, reason: 'unexpected subcommand' }
  const skill = argv[2] as string
  if (!isSkillName(skill) || !ctx.skills.includes(skill)) {
    return { ok: false, reason: `unexpected skill ${JSON.stringify(skill)}` }
  }
  let i = 3
  let flags = 0
  while (i < argv.length) {
    const flag = argv[i] as string
    if (flag === '--network') {
      const v = argv[i + 1]
      if (v !== 'localhost' && v !== 'all') return { ok: false, reason: `unexpected network value ${JSON.stringify(v)}` }
      i += 2
    } else if (flag === '--write') {
      const v = argv[i + 1]
      const why = typeof v === 'string' ? unsafeWriteReason(v, ctx) : 'no write path'
      if (why !== undefined) return { ok: false, reason: `${why}: ${JSON.stringify(v)}` }
      i += 2
    } else if (flag === '--caches') {
      i += 1
    } else {
      return { ok: false, reason: `unexpected flag ${JSON.stringify(flag)}` }
    }
    flags += 1
  }
  if (flags === 0) return { ok: false, reason: 'nothing to grant' }
  return { ok: true }
}
