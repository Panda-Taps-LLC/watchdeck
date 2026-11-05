// The pure parts the hooks lean on: the grant allow-list, the binary's
// forbidden roots, the rewrite parser, the ungranted → fix mapping.

import { expect, test } from 'claude-code/testing'

import { candidateDirs, isUnder } from '../hooks/bin.ts'
import { quoteArgv, quoteIfNeeded, shellQuote, unsafeWriteReason, validateGrantArgv, type GrantContext } from '../hooks/grant.ts'
import { findDenialMarkers, parseRewrite, parseTrailer } from '../hooks/trailer.ts'
import { buildFix } from '../hooks/tree.ts'

const BIN = '/opt/sp-test/bin/watchdeck'
const CTX: GrantContext = { bin: BIN, skills: ['canary-request'], home: '/Users/you', cwd: '/Users/you/proj', tmpdir: '/sp-test/tmp' }

test('the grant allow-list takes only widening flags for the record\'s skill', async () => {
  const ok = (argv: string[]) => validateGrantArgv(argv, CTX).ok
  expect(ok([BIN, 'allow', 'canary-request', '--network', 'all'])).toBe(true)
  expect(ok([BIN, 'allow', 'canary-request', '--network', 'localhost', '--caches'])).toBe(true)
  expect(ok([BIN, 'allow', 'canary-request', '--write', '/Users/you/out'])).toBe(true)
  expect(ok([BIN, 'allow', 'canary-request', '--write', '/sp-test/tmp/x'])).toBe(true)
  // never another executable, a relative one, or another subcommand
  expect(ok(['watchdeck', 'allow', 'canary-request', '--network', 'all'])).toBe(false)
  expect(ok(['/Users/you/proj/watchdeck', 'allow', 'canary-request', '--network', 'all'])).toBe(false)
  expect(ok([BIN, 'run', 'canary-request', '--network', 'all'])).toBe(false)
  // never a skill the record did not name, never `*`
  expect(ok([BIN, 'allow', 'canary-basic', '--network', 'all'])).toBe(false)
  expect(ok([BIN, 'allow', '*', '--network', 'all'])).toBe(false)
  // never a revoke or --auto
  for (const flag of [['--network', 'none'], ['--auto'], ['--remove-write', '/Users/you/x'], ['--no-caches'], ['--reset']]) {
    expect(ok([BIN, 'allow', 'canary-request', ...flag])).toBe(false)
  }
  // write paths: absolute, no `..`, under $HOME, the project or $TMPDIR
  expect(ok([BIN, 'allow', 'canary-request', '--write', '/etc/x'])).toBe(false)
  expect(ok([BIN, 'allow', 'canary-request', '--write', 'out'])).toBe(false)
  expect(ok([BIN, 'allow', 'canary-request', '--write', '/Users/you/../../etc'])).toBe(false)
  expect(ok([BIN, 'allow', 'canary-request', '--write', '/Users/yourself/x'])).toBe(false)
  // nothing to grant is not a grant
  expect(ok([BIN, 'allow', 'canary-request'])).toBe(false)
  // a name that reads as a flag is refused even when the record named it
  for (const name of ['--network', '-x', '-', '']) {
    expect(validateGrantArgv([BIN, 'allow', name, '--network', 'all'], { ...CTX, skills: [name] }).ok).toBe(false)
  }
  expect(validateGrantArgv([BIN, 'allow', 'a'.repeat(129), '--network', 'all'], { ...CTX, skills: ['a'.repeat(129)] }).ok).toBe(false)
  expect(validateGrantArgv([BIN, 'allow', '.x_1-y', '--network', 'all'], { ...CTX, skills: ['.x_1-y'] }).ok).toBe(true)
})

test('a binary under the project or $TMPDIR is under a forbidden root', async () => {
  expect(isUnder('/Users/you/proj/bin/watchdeck', '/Users/you/proj')).toBe(true)
  expect(isUnder('/Users/you/proj', '/Users/you/proj/')).toBe(true)
  expect(isUnder('/Users/you/project/watchdeck', '/Users/you/proj')).toBe(false)
  expect(isUnder('/usr/local/bin/watchdeck', '/')).toBe(false)
  expect(isUnder('/usr/local/bin/watchdeck', undefined)).toBe(false)
  expect(candidateDirs({ home: '/Users/you', cwd: '/Users/you/proj', tmpdir: undefined, path: 'bin:/usr/bin::/usr/bin/' })).toEqual([
    '/usr/bin',
    '/Users/you/.local/share/watchdeck/bin',
    '/opt/homebrew/bin',
    '/usr/local/bin',
  ])
})

test('the rewrite parser reads the plain form only', async () => {
  expect(parseRewrite(`watchdeck run --skill canary-request -c 'python3 probe.py net'`)).toEqual({
    skills: ['canary-request'],
    command: 'python3 probe.py net',
  })
  expect(parseRewrite(`watchdeck run --skill a --skill b -c 'echo '"'"'hi'"'"''`)).toEqual({ skills: ['a', 'b'], command: "echo 'hi'" })
  expect(parseRewrite('python3 probe.py')).toBeNull()
  expect(parseRewrite(`watchdeck run -c 'x'`)).toBeNull()
  expect(parseRewrite(`watchdeck run --skill 'a b' -c 'x'`)).toBeNull()
})

test('trailer and markers', async () => {
  const t = parseTrailer('out\n[watchdeck] exit 1 under profile a+b/3f9a (network=none write=${CWD}).\n[watchdeck]   requested but not granted: a: network: all\n')
  expect(t).toEqual({ exit: 1, skills: ['a', 'b'], hash: '3f9a', summary: 'network=none write=${CWD}', ungranted: ['a: network: all'], ignored: [] })
  expect(findDenialMarkers('net: DENIED(1)\nwrite-home: DENIED(1)\nread-secret: ALLOWED').map(m => m.what)).toEqual(['network', 'write'])
  expect(findDenialMarkers('PermissionError: [Errno 1] Operation not permitted')).toEqual([{ label: 'script reported', what: 'unknown' }])
  expect(findDenialMarkers('[watchdeck] "Operation not permitted" on a program means it is not listed.')).toEqual([])
})

test('ungranted items map to allow flags; caches become --caches; the rest is text', async () => {
  const built = buildFix(
    ['s: write: ~/Library/Caches', 's: network: all', 's: write: ~/out', 's: env: TOKEN', 's: exec: /usr/bin/curl'],
    ['s'],
    BIN,
    '/Users/you',
  )
  expect(built.fix).toEqual({
    argv: [BIN, 'allow', 's', '--network', 'all', '--write', '/Users/you/out', '--caches'],
    text: 'watchdeck allow s --network all --write /Users/you/out --caches',
  })
  expect(built.notes).toEqual([
    "s: env TOKEN: edit ~/.config/watchdeck/overrides.yaml (no allow flag)",
    "s: exec /usr/bin/curl: edit the skill's PERMISSIONS.yaml exec list",
  ])
  expect(buildFix(['s: network: all'], ['s'], undefined, '/Users/you')).toEqual({ notes: ['binary not found: run watchdeck allow s --network all yourself'] })
})

test('names that read as flags are dropped everywhere they are parsed', async () => {
  expect(parseRewrite(`watchdeck run --skill -x -c 'y'`)).toBeNull()
  expect(parseRewrite(`watchdeck run --skill --network -c 'y'`)).toBeNull()
  expect(parseTrailer('[watchdeck] exit 1 under profile -x+ok/3f (n).\n')?.skills).toEqual(['ok'])
  expect(buildFix(['-x: network: all', '--network: network: all'], ['-x'], BIN, '/Users/you')).toEqual({ notes: [] })
  // the last trailer wins: the binary writes its own after the child exited
  expect(parseTrailer('[watchdeck] exit 0 under profile a/00 (x).\n[watchdeck] exit 7 under profile a/3f (y).\n')?.exit).toBe(7)
})

test('the confirm quotes every argument; display quotes only what needs it', async () => {
  expect(shellQuote("it's")).toBe("'it'\\''s'")
  expect(shellQuote('')).toBe("''")
  expect(quoteArgv([BIN, 'allow', 's', '--write', '/Users/you/My Out'])).toBe(`'${BIN}' 'allow' 's' '--write' '/Users/you/My Out'`)
  expect(quoteIfNeeded('/Users/you/out')).toBe('/Users/you/out')
  expect(quoteIfNeeded('/Users/you/My Out')).toBe("'/Users/you/My Out'")
})

test('write targets: never $HOME, a built-in deny path, or a .env file', async () => {
  const write = (path: string) => validateGrantArgv([BIN, 'allow', 'canary-request', '--write', path], CTX)
  const refused = [
    '/Users/you',
    '/Users/you/.ssh',
    '/Users/you/.ssh/authorized_keys',
    '/Users/you/.SSH/config',
    '/Users/you/.aws',
    '/Users/you/.aws/credentials',
    '/Users/you/.gnupg/x',
    '/Users/you/.claude',
    '/Users/you/.claude/settings.json',
    '/Users/you/.config/gcloud',
    '/Users/you/.config/gcloud/x',
    '/Users/you/.netrc',
    '/Users/you/.docker/config.json',
    '/Users/you/proj/.env',
    '/sp-test/tmp/.ENV',
    // spellings that would dodge a lexical compare
    '/Users/you//.ssh',
    '/Users/you/./.ssh',
    '/Users/you/.ssh/',
  ]
  for (const path of refused) {
    expect(write(path).ok, path).toBe(false)
  }
  expect(unsafeWriteReason('/Users/you', CTX)).toBe('write path is $HOME itself')
  expect(unsafeWriteReason('/Users/you/.aws/credentials', CTX)).toBe('write path is under the built-in deny ~/.aws')
  expect(unsafeWriteReason('/Users/you/proj/.env', CTX)).toBe('write path is a .env file')
  // neighbours of the deny list stay grantable
  for (const path of ['/Users/you/.sshkeys-notes', '/Users/you/.config/other', '/Users/you/.docker/other.json', '/Users/you/proj/.env.example', '/Users/you/proj']) {
    expect(write(path).ok, path).toBe(true)
  }
})
