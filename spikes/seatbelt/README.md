# Seatbelt spike (macOS, 2026-10-11)

Evidence behind the "verified" claims in `docs/DESIGN.md` §3. Paths are hardcoded to the machine it ran on; edit before re-running.

```
/usr/bin/sandbox-exec -f profile.sb python3 probe.py
```

Result under `profile.sb`:

```
write cwd(project): ALLOWED
write home: DENIED (PermissionError)
read ~/.ssh: DENIED (PermissionError)
network: DENIED (URLError)
```

Findings:

1. The "allow default, then deny" profile shape runs an interpreter cleanly. Deny-default profiles break Python startup.
2. A later `allow file-write*` for a subpath beats an earlier `deny file-write*` on its parent, so the default profile needs no deny-default gymnastics.
3. Nesting is refused. Run inside Claude Code's own Bash sandbox, a second `sandbox-exec` fails with `sandbox_apply: Operation not permitted` in both nesting directions. Enforcement therefore goes through a `watchdeck run` wrapper listed in Claude Code's `sandbox.excludedCommands`.
4. Seatbelt filters network by address and port, not hostname. Domain allow-lists need a local proxy, so v0.1 treats network as `none | localhost | all`.

## Spike 2 (2026-10-11)

Reproduce with `bash spikes/seatbelt/spike2.sh` (driver) and `probe2.py` (probe). Everything runs against a fresh temp root `R` = `realpath $(mktemp -d)` = `/private/var/folders/<x>/<y>/T/sbspike.XXXXXX` holding a fake `R/home` (with `.ssh/id_fake`, `.claude/settings.json`, `.claude/skills/demo/scripts/x.py`), `R/cwd`, `R/tmp` and `R/sock`. No real credential file is touched. Machine: macOS 27.0.1, `/usr/bin/python3` = Xcode shim for `/Applications/Xcode.app/Contents/Developer/usr/bin/python3` (3.9.6). Every probe below exited 0 unless stated; the labelled lines are the probe's stdout.

One trap in the layout, relevant to any test that builds a fake home under `$TMPDIR`: the fake home is *inside* the real `T` directory, so a profile that allows writes to the real `TMPDIR` re-allows the whole fake home. The spike therefore uses `R/tmp` as the profile's `Tmp` and never allows the real `T` dir. In production the real home is not under `T`, so `run` passes the real `TMPDIR`.

### (a) Deny-all writes vs deny-home

Deny-all works. Interpreters start, print, write the cwd and spawn children:

```scheme
(version 1)
(allow default)
(deny network*)
(deny file-write*)
(allow file-write* (subpath "R/cwd") (subpath "R/tmp") (subpath "/private/tmp") (literal "/dev/null") (regex #"^/dev/tty"))
```
```
print: ALLOWED
write-cwd: ALLOWED
spawn-ls: ALLOWED
write-home: DENIED(EPERM)
net-192.0.2.1:80: DENIED(EPERM)
bash write cwd: ALLOWED
bash write home: DENIED
```

What each extra allow buys, found by removing it (A4 in the driver):

| Allow | Without it |
|---|---|
| `(literal "/dev/null")` | `subprocess.run(..., stdout=DEVNULL)` → `spawn-ls: DENIED(EPERM)`; bash `echo x > /dev/null` → `Operation not permitted` |
| `(regex #"^/dev/tty")` | reopening `/dev/tty` or `$(tty)` → DENIED (writes to the already-open pty fd still work). Tested with `pty.fork()` so the child owned a controlling tty. |
| `(regex #"^/dev/fd/")` | `echo x > /dev/stderr`, `> /dev/stdout`, `python open("/dev/stdout","w")` → DENIED(EPERM). `/dev/stdout` is a symlink to `/dev/fd/1` and Seatbelt matches the resolved path. |
| `(literal "/dev/ptmx")` | `pty.openpty()` → DENIED (anything that allocates a pty: `script`, `expect`, pexpect). |

`/private/var/folders/<x>/<y>/C` (the per-user cache dir) was **not** needed by python3, bash or ls. The Xcode `python3` shim does write `xcrun_db-*` into the real `T` dir, using `confstr(_CS_DARWIN_USER_TEMP_DIR)` and ignoring the `TMPDIR` we hand the child. When that dir is not allowed the shim prints `python3: error: couldn't create cache file '/var/folders/.../T/xcrun_db-XXXX' (errno=Operation not permitted)` on stderr and still runs the script (exit 0). The real interpreter behind the shim runs silently under the same profile. Consequence for `run`: `Resolved.Tmp` must be the real per-user `T` directory (realpath of `confstr(_CS_DARWIN_USER_TEMP_DIR)`, which is what `$TMPDIR` normally is), independent of what `TMPDIR` is set to for the child.

Minimal allow set that makes `python3` and `bash -c` work under `(deny file-write*)`: cwd, the real `T` dir, `/private/tmp`, `/dev/null`, `/dev/ptmx`, `^/dev/fd/`, `^/dev/tty`. Reads need nothing extra.

Deny-home (the spike 1 shape, A2 in the driver) gives the same probe output with no stderr noise, because `T`, `/dev` and `C` are not under home. The difference is what else is writable: under deny-home a script may write anywhere outside home (`/opt/homebrew`, `/usr/local`, `/Library`, `/Volumes/*`, other users' dirs the Unix mode bits allow); under deny-all it may not.

**Recommendation: default to deny-all** (`Resolved.DenyAllWrites = true` in `run`). The interpreters start, the extras are four fixed device allows, and the only observed cost is tools that use `DARWIN_USER_CACHE_DIR` (`.../C`), which belong in the `--caches` override alongside `~/Library/Caches`. The compiler's zero value (`DenyAllWrites=false`) is deny-home per the contract; both shapes are golden-tested and both are exercised by the real test.

### (b) Skill under `~/.claude`

```scheme
(version 1)
(allow default)
(deny network*)
(deny file-write* (subpath "R/home"))
(allow file-write* (subpath "R/cwd") (subpath "R/tmp") (subpath "/private/tmp"))
(deny file-read* (subpath "R/home/.ssh") (subpath "R/home/.claude"))
(allow file-read* (subpath "R/home/.claude/skills/demo"))
(deny file-write* (subpath "R/home/.ssh") (subpath "R/home/.claude"))
```
```
$ sandbox-exec -f p.sb python3 R/home/.claude/skills/demo/scripts/x.py
x.py ran
write-cwd: ALLOWED
write-home: DENIED(EPERM)
read-ssh: DENIED(EPERM)
read-settings: DENIED(EPERM)        # R/home/.claude/settings.json
read-skill: ALLOWED                 # R/home/.claude/skills/demo/scripts/x.py
list-skill: ALLOWED
net-192.0.2.1:80: DENIED(EPERM)
write into skill dir: DENIED
```

The read re-allow after the `~/.claude` deny works, no `file-read-metadata` allow on the ancestors was needed, and the trailing write re-deny keeps the skill dir read-only.

Real path vs symlink spelling: Seatbelt only ever sees real paths. With the deny spelled as `/var/folders/.../home/.claude` (the symlink spelling `$TMPDIR` has), `read-ssh` and `read-settings` were **ALLOWED**, whether the probe opened the real path or the symlink spelling. With the deny spelled `/private/var/folders/...` both were DENIED, including when the probe opened them through the `/var/folders` symlink and `HOME` was the symlink spelling. The `HOME` environment variable is irrelevant to Seatbelt; only the profile's spelling matters, and it must be the `realpath`. Every path handed to `profile.Compile` goes through `filepath.EvalSymlinks` first.

### (c) `sandbox-exec` exit codes

```
$ /usr/bin/sandbox-exec -p '(version 1)(allow default)' /usr/bin/sandbox-exec -p '(version 1)(allow default)' /usr/bin/true; echo $?
0
```

That succeeds only because both profiles are the same. The rule, mapped by pairing outer and inner profiles (C2 in the driver): a process that already has a sandbox may apply a profile **only if it compiles to the profile already in force**. Whitespace and duplicated rules do not count; any other difference, stricter or looser, is refused:

| outer | inner | exit |
|---|---|---|
| `(allow default)` | `(allow default)` | 0 |
| `(allow default)(deny network*)` | same | 0 |
| `(allow default)(deny network*)` | same plus a second `(deny network*)` | 0 |
| `(allow default)(deny X)` | `(allow default)(deny X)(deny network*)` (stricter) | 71 |
| `(allow default)(deny X)(deny network*)` | `(allow default)(deny X)` (looser) | 71 |
| `(allow default)` | `(allow default)(deny X)` | 71 |
| `(allow default)(deny X)` | `(allow default)` | 71 |

```
$ sandbox-exec -p '(version 1)(allow default)(deny network*)' sandbox-exec -p '(version 1)(allow default)' /usr/bin/true; echo $?
sandbox-exec: sandbox_apply: Operation not permitted
71
```

So the spike 1 refusal under Claude Code's Bash sandbox is the general rule: a real profile is never identical to the outer one. A skill script running under a watchdeck profile cannot apply a different sandbox either (C3 in the driver: exit 71, same line); re-applying the identical profile is a no-op. Related codes:

| Situation | Exit | stderr |
|---|---|---|
| apply refused (nested) | 71 | `sandbox-exec: sandbox_apply: Operation not permitted` |
| target binary cannot be exec'd | 71 | `sandbox-exec: execvp() of '/nonexistent/bin' failed: No such file or directory` |
| malformed profile | 65 | `sandbox-exec: syntax error: expecting ')'` |
| child exits N | N | (child's) |

Apply failure and exec failure share exit 71, so `internal/sandbox` must match `sandbox_apply` in stderr rather than the exit code.

### (d) Unix domain sockets

`(deny network*)` blocks `connect()` on an `AF_UNIX` socket too (`unix-socket: DENIED(EPERM)`; ALLOWED with no deny). The localhost shape does not re-allow them. `(allow network-outbound (remote unix-socket))` does, while keeping `192.0.2.1:80` denied. v0.1 leaves them denied under `none` and `localhost`: that also closes the Docker socket and mDNSResponder (so DNS fails under `none`, which is the intent).

### (e) The first localhost shape (v0.1 package contracts) leaks

Found while checking (d). With a listener on `127.0.0.1:48123` outside the sandbox:

| Profile after `(deny network*)` | connect 127.0.0.1 | connect 192.0.2.1:80 | bind 127.0.0.1 | bind 0.0.0.0 |
|---|---|---|---|---|
| `(allow network* (local ip "localhost:*"))` `(allow network-outbound (remote ip "localhost:*"))` (contract) | ALLOWED | **TIMEOUT** (SYN left the box) | ALLOWED | ALLOWED |
| `(allow network-outbound (remote ip "localhost:*"))` only | ALLOWED | DENIED(EPERM) | DENIED | DENIED |
| `(allow network-bind (local ip "localhost:*"))` `(allow network-inbound (local ip "localhost:*"))` `(allow network-outbound (remote ip "localhost:*"))` | ALLOWED | DENIED(EPERM) | ALLOWED | ALLOWED |

`(allow network* (local ip "localhost:*"))` matches an unbound outbound socket, so it re-allows every outbound connection. The compiler emits the third row. Remaining caveat: Seatbelt's `localhost` host also matches `INADDR_ANY`, and only `*` or `localhost` are accepted as hosts (`127.0.0.1` is a profile syntax error, exit 65), so a sandboxed server may bind `0.0.0.0` and was observed accepting a connection made to the machine's LAN IP. Dropping the bind/inbound lines closes that at the cost of forbidding local servers.

### Escaping

`(subpath "…odd\"q")` and `(subpath "…odd\\b")` both matched directories literally named `odd"q` and `odd\b` (reads DENIED(EPERM)). `"` and `\` are escaped as `\"` and `\\` in string filters. A `#"…"` regex literal has no escape for `"`, so the compiler rejects patterns containing one. Regex shapes used by the compiler were checked live: `(^|/)\.env$` denied `.env`, allowed `env.txt` and `.env.example`; `^R/cwd/sec/(.*/)?x$` denied `sec/x` and `sec/a/b/x`, allowed `sec/a/b/y`.

### What `internal/profile` emits (summary)

`(version 1)` `(allow default)` → network (`none`: `(deny network*)`; `localhost`: deny plus the three-line shape above; `all`: nothing) → `(deny file-write*)` or `(deny file-write* (subpath Home))` → `(allow file-write* (subpath Tmp) (subpath "/private/tmp") (subpath CWD) (subpath Write…))` plus, under deny-all, `(allow file-write* (literal "/dev/null") (literal "/dev/ptmx") (regex #"^/dev/fd/") (regex #"^/dev/tty"))` → `(deny file-read* (subpath DenyPaths…))` → one `(deny file-read* (regex #"…"))` per DenyPattern → `(allow file-read* (subpath SkillDirs…))` → `(deny file-write* (subpath DenyPaths…))` → optional `(deny process-exec*)` `(allow process-exec (literal …))`. Lists are sorted and deduplicated; the output is byte-stable for the same input. Because the skill-dir read allow comes after the regex denies, a `.env` inside the skill directory itself is readable; that order is the contract's and is noted rather than changed.
