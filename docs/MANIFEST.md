# The manifest, your grant, and overrides

This page is the reference for what a skill may ask for, what you grant, and how the two combine. The front page is [`README.md`](../README.md); the design of record is [`DESIGN.md`](DESIGN.md).

## The manifest

A sidecar file at the skill root, `PERMISSIONS.yaml`. The Agent Skills spec allows extra files in a skill directory, and a sidecar avoids two traps: frontmatter `metadata` is string-to-string only, and claude.ai uploads reject unknown top-level frontmatter fields.

```yaml
# PERMISSIONS.yaml  (skill: pdf)
version: 1
scripts: ["scripts/**"]          # which files this manifest governs
filesystem:
  read:  ["${SKILL_DIR}", "${CWD}"]
  write: ["${CWD}", "${TMP}"]
  # deny: the built-in list always applies. Write `deny:` only to extend it;
  #       it must then still contain every built-in entry.
network: none                     # none | localhost | all
exec: any                         # or an allow-list: ["/usr/bin/python3", "/usr/bin/qpdf"]
env: ["PATH", "HOME", "LANG", "TMPDIR"]   # everything else is scrubbed
tools: ["Read", "Write", "Bash"]  # prose half: declared only, not enforced
notes: "Fills and merges PDFs locally. Never needs the network."
```

| Field | Default when there is no manifest | Enforced by |
|---|---|---|
| `scripts` | `scripts/**` | hook (which files count as the skill's code) |
| `filesystem.read` | everything except the deny list | Seatbelt `file-read*` / bwrap read-only root |
| `filesystem.write` | `${CWD}`, `${TMP}` | Seatbelt `file-write*` / bwrap binds |
| `filesystem.deny` | `~/.ssh ~/.aws ~/.gnupg ~/.claude ~/.config/gcloud ~/.netrc ~/.docker/config.json **/.env`, plus, added by `run` outside the manifest (so a manifest cannot remove them and an override cannot re-allow them): watchdeck's state dir (`${XDG_STATE_HOME:-~/.local/state}/watchdeck`), Claude Code's user config `~/.claude.json` and every `~/.claude.json*` sibling (and the same under `$CLAUDE_CONFIG_DIR`), `$CLAUDE_CONFIG_DIR` itself when it is set to a directory other than `~/.claude`, and, when `$HOME` is not the account's home from the user database, every built-in deny under the account home too | Seatbelt deny / bwrap tmpfs |
| `network` | `none` | Seatbelt `network*` / bwrap `--unshare-net` |
| `exec` | `any` | Seatbelt `process-exec` (not enforced on Linux) |
| `env` | `PATH HOME LANG TMPDIR` | `env -i` in the wrapper |
| `tools` | unset | nothing; `audit` compares it with the prose |

A skill with no manifest gets the default profile. That is the point: every script-bearing skill on your machine is covered on day one, without its author doing anything. `watchdeck init <skill>` drafts a manifest from a scan when you want to publish one. `watchdeck validate [path]` checks a manifest or a skill directory.

A malformed manifest, or one whose `deny:` drops a built-in entry, makes `run` exit 125 and run nothing. `audit` still prints its table and exits 0; `audit --strict` exits 1 in that case, for scripts and CI.

## Request, grant, clip

- **The manifest is a request.** It says what the author thinks the scripts need. It never grants anything by itself.
- **Your grant is the default profile plus your overrides.** Only your user overrides file can widen it beyond the project; a project file is clipped (below).
- **`run` executes under the field-by-field minimum of the two.** Network is the lower of the two levels. A requested write or read path is kept only where the grant allows it. `env` keeps the names both allow, `exec` keeps the requested programs the grant allows, and deny lists only add up. The rules per field are in `internal/manifest/doc.go`, tested by `internal/manifest/effective_test.go`.
- **A request never makes a run fail.** If a skill asks for more than you granted, the run goes ahead under your grant and the extra items are named, as `asks[...]` in `audit`, as "requested but not granted" in the hook's prompt, and in the `[watchdeck]` trailer after a failed run.
- **The fix is printed for you.** The trailer and the dashboard's skill page show the exact `watchdeck allow` line that would grant the missing items. Nothing is granted until you run it or press Grant.

Exit 125 means a policy error before the script runs: a malformed manifest, one that tries to remove a built-in deny, an unknown skill, a nested `watchdeck run` (`WATCHDECK_PROFILE` already set), or a profile the OS rejects.

## Overrides

`watchdeck allow` writes your overrides file, `${XDG_CONFIG_HOME:-~/.config}/watchdeck/overrides.yaml` (`watchdeck paths` prints the exact location). The dashboard's Grant and Revoke buttons write the same file. Hand edits are fine. The file may be version 1 (shown here) or version 2 (see [Policy file v2](#policy-file-v2-overridesyaml)); since 2026-10-13 `watchdeck allow` and the dashboard save it as version 2.

```yaml
# ~/.config/watchdeck/overrides.yaml
version: 1
skills:
  "pdf":
    network: all
    write: ["~/Library/Caches/pip"]
    caches: true          # ~/Library/Caches, ~/.cache, ~/.npm/_cacache
    auto_allow: true      # run this skill's scripts without asking
```

Keys per skill: `network` (`none | localhost | all`), `write` and `read` (paths), `env` (variable names to pass through), `caches`, `auto_allow`. A `defaults:` block (or the key `"*"`) applies to every skill. A skill key must be `*` (every skill) or match `^[A-Za-z0-9._][A-Za-z0-9._-]{0,127}$` (no leading `-`, at most 128 characters, not `.` or `..`); a file with any other key is invalid as a whole. While either overrides file is invalid, no override applies (every skill runs under the default profile, nothing is auto-allowed) and the hook's prompt says so.

### `watchdeck allow`

```
watchdeck allow <skill|*> [--network none|localhost|all] [--write PATH]... [--remove-write PATH]...
                            [--caches|--no-caches] [--auto|--no-auto] [--reset] [--show]
```

| Flag | Effect |
|---|---|
| `--network localhost\|all` | Widen the network grant. |
| `--network none` | Take the network grant back. |
| `--write PATH` (repeatable) | Add a write path. |
| `--remove-write PATH` (repeatable) | Remove a write path you added. |
| `--caches` / `--no-caches` | Allow or stop writes to the usual cache dirs (`~/Library/Caches`, `~/.cache`, `~/.npm/_cacache`). |
| `--auto` / `--no-auto` | Run this skill's scripts without asking, or ask again. |
| `--reset` | Delete the skill's whole block. |
| `--show` | Print the file. |

The result is re-parsed strictly and written atomically, so the file is never left invalid. The skill name must be `*` (every skill) or match `^[A-Za-z0-9._][A-Za-z0-9._-]{0,127}$` (no leading `-`, at most 128 characters, not `.` or `..`); anything else, or an unknown flag, exits 3. There is no flag for `env`, `read` or `exec` in this release: edit the file for `env` and `read`, and the skill's manifest for `exec` (`allow --exec` is planned for v0.2).

### The project file

A project may ship `.watchdeck.yaml` at its git root. It is **untrusted** because it arrives with a cloned repository. It may add read or write paths only under the project directory or temp, and raise network to at most `localhost`. Everything else in it is ignored and reported by `audit` and in the run trailer. The project boundary is checked on real paths, so a symlink inside the repository cannot carry a grant outside it.

### `auto_allow` is narrow

The hook returns `allow` only when the command is solely the skill invocation: an optional leading `cd`, then one call whose program is an interpreter or the skill's own script. Chains, pipes, here-docs and `cat skill/x.py` stay `ask`, even for an auto-allowed skill.

## Policy file v2 (overrides.yaml)

Added 2026-10-13 (M6.1). Version 2 is the same two files, the user `overrides.yaml` (trusted) and the project `.watchdeck.yaml` (untrusted), with room for policies beyond skills. A v2 file needs this version of watchdeck or newer; an older binary refuses it as malformed (`version: must be 1`). Nothing is promised for older readers.

```yaml
version: 2
mode: enforce   # or shadow: watchdeck's own rules are recorded, never enforced (user file only)
packs: {secrets-read: on, exfil: {action: ask}}       # built-in rule packs (internal/rules)
rule_overrides: {"exfil/curl-data-file": off, "persistence/crontab": {action: deny}}
rules:
  - {id: no-prod-db, tool: Bash, match: {regex: 'psql .*prod'}, action: deny, severity: high}
defaults: {network: localhost}                         # the v1 defaults block: every skill
subjects:
  - {kind: skill,   name: pdf, grant: {network: all, write: [./out], caches: true, auto_allow: true}}
  - {kind: command, name: npm-scripts, match: {argv0: [npm], glob: ['npm run *']}, grant: {network: all, write: [./node_modules]}}
  - {kind: mcp,     name: github, tools: {'delete_*': deny, 'create_*': ask}, launch: {sandbox: false, grant: {network: all}}}
  - {kind: tool,    name: files, match: {tools: [Write, Edit]}, paths: {deny: ['~/.zshrc', '~/Library/LaunchAgents/**']}}
  - {kind: tool,    name: web,   match: {tools: [WebFetch]}, domains: {deny: ['*.pastebin.com']}}
  - {kind: agent,   name: researcher, match: {agent_type: researcher}, tools: {deny: [Bash]}, skills: {allow: [pdf]}}
scope: {}   # reserved; must be empty ("not supported yet")
```

Parsing is strict. Any of these makes the whole file invalid:

- an unknown field or a duplicate key;
- a duplicate subject (same kind and name);
- a field that does not belong to the subject's kind;
- a non-empty `scope` (top level or on a subject);
- a `version` that is not the integer 1 or 2 (`2.0` and `"2"` are refused);
- more than one YAML document (`---`; a `%YAML` directive before the `---` is fine);
- a file over 1 MiB (the user file) or 64 KiB (the project file);
- YAML nested more than 64 flow collections deep, indented more than 256 columns, with more than 64 `- ` entries on one line, or with more than 16 aliases;
- a file that is not a regular file (a FIFO, a device, a directory), checked without blocking;
- for the project file, a symlink that resolves outside the project directory.

Errors name the field and the rule, never a value from the file.

### Packs, rule overrides and rules

`packs` and `rule_overrides` map one to one onto the built-in rule packs' configuration (`internal/rules` `Config`). A value is `on` or `off` (also `true`/`false`, `yes`/`no`), or `{enabled: true|false, action: deny|ask|log}` with at least one key. `packs` is keyed by pack name (`exfil`); `rule_overrides` by `<pack>/<rule id>` (`exfil/curl-data-file`). A rule override beats its pack's setting. A file naming an unknown pack or rule can be read but is refused when watchdeck saves it.

The built-in packs are advisory by default: their rules ship as `log` or `ask` (new rules as `log` first), and a user who wants a hard stop opts a pack or a rule up to `deny`.

`rules` are your own gate rules, `{id, tool, match: {regex, literals, argv0}, action: deny|ask|log, severity}`. An id has no `/`, so it can never name or shadow a built-in rule (`<pack>/<id>`). A regex is compiled before the file is saved.

### Subjects and enforcement classes

| Kind | Name | Fields | Class |
|---|---|---|---|
| `skill` | a skill name or `*` | `grant` (the v1 per-skill block) | **sandbox** |
| `command` | a label | `match.argv0`, `match.glob`, `grant` (user file only) | **sandbox** |
| `mcp` | the server name, a glob of it, or `*` | `tools` (tool-name glob → `deny` or `ask`), `launch` (`sandbox`, `grant`) | **gate**; **sandbox** when `launch.sandbox: true` |
| `tool` | a label | `match.tools`, `paths` and/or `domains` (`deny`, `ask` lists) | **gate** |
| `agent` | a label | `match.agent_type`, `tools` (`deny`, `ask` lists of tool names), `skills.allow` | **gate** |

- **sandbox**: OS-enforced through `watchdeck run` (Seatbelt on macOS, bwrap on Linux), like a skill today.
- **gate**: the hook answers deny, ask or nothing. A gate never allows, so Claude Code's own permissions keep the final say. A gate is **not OS-enforced**: it sees the tool call the hook sees and nothing else (a domain gate on WebFetch does not stop a script from opening a socket).

What acts on each part, since 2026-10-14 (M6.3; design of record in [DESIGN.md](DESIGN.md) "Hook enforcement of policy v2"):

| Part | Enforced by | Class |
|---|---|---|
| `skill` subjects, `defaults` | the hook rewrites to `watchdeck run`, which applies the OS sandbox (as in version 1) | sandbox |
| `command` subjects | the hook rewrites a matching single simple command to `watchdeck run --subject command:<name>`; `run` applies the OS sandbox with the default profile widened by `grant` (`TestRunCommandSubjectUnderSandbox`) | sandbox |
| `mcp` `tools` | the hook's answer on `mcp__<server>__<tool>` calls | gate |
| `mcp` `launch` | `watchdeck mcp` (M6.7, separate) | sandbox |
| `tool` `paths` | the hook's answer on Read, Write, Edit, MultiEdit, NotebookEdit | gate |
| `tool` `domains` | the hook's answer on WebFetch (WebSearch carries a query, not a URL: no domain gate) | gate |
| `agent` `tools`, `skills.allow` | the hook's answer on a subagent's calls, by `agent_type` | gate |
| `packs`, `rule_overrides` | the hook runs the built-in packs (advisory: log or ask unless you raise a rule to deny) | gate |
| `rules` | the hook; the field follows the tool (Bash command, file path, WebFetch URL, otherwise the WebSearch query or the tool input as JSON); `argv0` applies to Bash only | gate |

A gate answers deny, ask or nothing, never allow, and the strongest answer across packs, rules and gates wins; a gate's ask turns an auto-allowed skill or command into an ask (still sandboxed), a gate's deny replaces the rewrite. Hook registrations for the extra tools (`enforce install`, `setup`) are added only when your policy has rules or gates for them; run `enforce install` again after adding a gate for a new tool (`doctor` tells you). The plugin registers them all. If your `overrides.yaml` is malformed, every tool call the hook sees asks until it is fixed; a malformed project file is ignored.

Paths are compared after normalisation (relative to the call's cwd, `~` expanded, cleaned, symlinks resolved, case-folded); hosts after `net/url` parsing (no userinfo or port, lower case). Unicode normalisation and IDNA are not applied: a gate answers ask for a host with non-ASCII characters, and an `xn--` host compares as written.

A gate cannot say `allow`: `tools: {'*': allow}` and `paths: {allow: [...]}` are errors. An agent's `skills.allow` is a list that narrows (a skill not on it is denied for that agent type); it never allows anything Claude Code would not.

Matching:

- `command` applies to a **single simple command** only. The command is parsed as bash (mvdan.cc/sh). It must be exactly one plain call. Every word must be inert in bash and in zsh, which Claude Code may run the command in. A word may contain only unquoted text made of letters, digits and `_ . / : @ % + , = -`, and must not start with `=` (even after empty quotes, `''=cmd`) or contain `==`. It may also contain single-quoted text (`'…'`, not `$'…'`), and double-quoted text with no `$`, backquote or backslash. Anything else has no command subject. That includes a pipe, `;`, `&&`, `||` and `&`, a subshell, `{ }`, a function and `!`. It also includes a redirection, a leading `VAR=value`, any expansion (`$x`, `${…}`, `$((…))`, `$(…)`, backquotes, `<(…)`, `=(…)`, `{a,b}`, `~user`), and unquoted glob or extglob characters (`* ? [ ] ( ) ! ^ #`, including zsh qualifiers like `*(e:…:)`). Comments, newlines (so no here-doc or line continuation), text that does not parse and commands over 16 KiB have no subject either. A glob therefore never spans a command separator, and no word can expand into code. `argv0` is the first word, when it is plain text (a quoted or expanded first word matches only `*`): a bare entry (`npm`) matches only a first word without `/`, which the shell finds through `PATH` when `run` executes the command; an absolute entry (`/usr/bin/make`) matches only that exact first word; `*` matches any. `glob` matches the whole command, where `*` spans anything (spaces and `/` included) and `?` is one byte. When both are given, both must match.
- `mcp`: the subject name matches the server, `tools` keys match the tool name (`delete_*`).
- `tool` paths: absolute, `~/…`, `${HOME}/…` or `**/name`; a plain path covers itself and everything below it; globs follow doublestar; comparisons are case-folded. Domains: `example.com` exactly, `*.example.com` any subdomain (not `example.com` itself), `*` any host.

### MCP launch (M6.7, experimental, 2026-10-14)

`launch` on an `mcp` subject is used by `watchdeck run --subject mcp:<name> -- <command> [args…]`, which `watchdeck mcp wrap <name>` writes into Claude Code's user config.

```yaml
subjects:
  - kind: mcp
    name: github                  # exactly the server's name in Claude Code
    tools: {'delete_*': deny}     # gate (hook), unrelated to launch
    launch:
      sandbox: true               # false or absent: run refuses to start the server (exit 125)
      grant:                      # widens the MCP default profile; same keys as a skill grant
        network: all              # default none
        env: [GITHUB_TOKEN]       # wrap adds the keys of the server's config env
        caches: true              # ~/Library/Caches, ~/.cache, ~/.npm/_cacache
        write: ["~/.npm"]
```

- **Base profile.** The skill default: network `none`; writes to the working directory (Claude Code starts a server in the project directory) and temp; env `PATH HOME LANG TMPDIR`; exec any; the built-in deny list and the denies `run` adds to every run (state dir, `~/.claude.json`, `$CLAUDE_CONFIG_DIR/.claude.json`, a relocated `$CLAUDE_CONFIG_DIR`). `~/.claude.json` holds every server's env values. `launch.grant` widens this with the user-file rules (`Widen` with source user). `auto_allow` means nothing here.
- **Exact name only.** The launch grant comes from the subject whose `name` is exactly the server name. A glob or `*` mcp subject never supplies one, so a single wide subject cannot widen every wrapped server; such subjects still count for `tools` gates.
- **User file only.** A project file's `launch` is dropped (see above), so a cloned repository can neither start nor widen a server.
- **No subject, no start.** Without an exact subject with `launch.sandbox: true`, `run --subject mcp:<name>` exits 125 and the server does not start.

Tests: `TestMCPNeedsExactLaunchSubject`, `TestMCPNetworkDeniedUnlessGranted`, `TestMCPEnvLimitedToListedKeys`, `TestMCPClaudeConfigDenied` (`internal/runner`), `TestMCPWrapKeepsGates` (`cmd/watchdeck`).

### Mode

`mode: enforce` (the default; the line is omitted when watchdeck writes the file) or `mode: shadow`. In shadow mode every deny or ask from a pack, a rule or a gate is recorded (`shadow: true`, `would: deny|ask`, `would_reason`) and not printed. It changes nothing about skill grants, command subjects, MCP launch, the Claude Code rules watchdeck mirrors, or the hook's own asks. Any other value makes the file invalid (`mode: must be enforce or shadow`). Only the user file may set it (see below). Written by `watchdeck rules shadow on|off`.

### Precedence

- **Skills**: unchanged from version 1. Default → project `defaults` → project `*` → project skill → user `defaults` → user `*` → user skill. Every step only widens, and the project layer is clipped. The v2 `defaults:` block is the v1 `defaults:` block, and a `kind: skill, name: "*"` subject is the v1 `skills: {"*": …}` key, applied after `defaults`.
- **Gates** (mcp tools, tool paths and domains, agent tools and skills): every matching subject in both files counts, and the decision is the strongest action among them, deny over ask. Specificity never changes the decision: a `deny` from a `*` subject beats an `ask` from an exact one. It only picks which match is named in the decision: exact name over glob over `*` (subject name or match first, then the inner pattern), then the user file over the project file.
- **Commands**: one subject applies, the most specific: argv0 and a glob both matched, then a glob, then an argv0, then only `*` matchers; ties go to the glob with more literal characters, then the smaller name. Its grant is the default profile widened by its `grant` block.
- **Packs and rules**: the user file's toggle for a pack or a rule replaces the project file's; a rule override beats its pack's setting (internal/rules).

### What the project file cannot do

The project file arrives with a cloned repository. Besides the version 1 rules for skill grants (paths only under the project or temp, network at most `localhost`, no `env`, `caches` or `auto_allow`), it cannot:

- define a command subject (ignored; which commands run in a sandbox, and with what grant, is the user's choice);
- launch an MCP server (`launch` is dropped);
- disable or weaken a pack or a rule. A toggle is kept only when it leaves the pack or rule enabled and its action, if any, is at least the default action of every rule it covers. A rule override must also be at least the user file's action for its pack. An unknown pack or rule is ignored;
- re-enable a pack or rule the user file turned off, directly or through a rule override in that pack: the user's `off` wins;
- set `mode` (ignored, reported as `project policy ignored: mode (only the user file can set the mode)`; the user file decides whether rules are enforced).

Each ignored entry is reported as `project policy ignored: <field> (<reason>)`; clipped grant entries keep the version 1 wording `project override ignored: …`. Gates, agent `skills.allow` lists, strengthening toggles and `rules` (deny, ask or log) only add restrictions, so the project file keeps them.

### Migration and backups

A version 1 file keeps working and is read as version 2 in memory: `defaults:` stays `defaults:`, each `skills:` key becomes a `kind: skill` subject. It is rewritten only when `watchdeck allow` or the dashboard saves a change. Each save:

- copies the existing file to `overrides.yaml.bak-<unix seconds>` (then `-2`, `-3`, … within the same second; 0600, never overwritten);
- names that copy `overrides.yaml.bak-v1-<unix seconds>` when the existing file is not version 2, so the conversion keeps the original;
- writes version 2 to a temp file (0600) and renames it into place;
- removes all but the newest 10 `overrides.yaml.bak-<unix seconds>` copies. `.bak-v1-` copies are never removed.

The saved file is rewritten in watchdeck's own layout: sorted (packs and rule overrides by key, subjects by kind then name), re-indented in block style with two spaces, strings double-quoted and lists written inline (`[a, b]`), so your own indentation, `{…}` maps and quoting are not kept, repeated env names written once, and comments dropped. Saving it again gives the same bytes. If you keep a hand-formatted file, edit it by hand and do not save it from `watchdeck allow` or the dashboard (the `.bak-<ts>` copy keeps the previous text).

Tests:

- `TestSkillGrantEqualsManifestGrant`: every version 1 test input, as user and as project file, gives the same grant before and after the version 2 save, and a re-save is byte-identical.
- `TestSaveBackupModeAtomic`, `TestSaveKeepsLastTenBackups`.
- `TestAllowRewritesV1AsV2WithBackup`.
- `TestProjectRestrictions`, `TestSavedFilesAreValidRulesConfig`.
- `TestCommandSubjectPrecedence`, which also covers simple commands only.
