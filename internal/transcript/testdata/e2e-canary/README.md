# e2e-canary: one real Claude Code session, scrubbed

A real capture, not a hand-written fixture. Produced on 2026-10-12 from a single
throwaway `claude -p` session (Claude Code 2.1.296, model `claude-opus-5-5`) in a
temporary project whose `.claude/skills` held `testdata/skills/canary-basic`, with
a temporary `--settings` file (a PreToolUse hook on Bash, wrapped in a one-line
`tee` script that copied the hook's stdin to a file), temporary XDG dirs with
`auto_allow: true`, and this prompt: run `probe.py net`, read `SKILL.md` with the
Read tool, spawn one Explore subagent to grep the project for "canary". The
session cost about $0.45. The capture came from the Wave 0 spike harness, not
from `scripts/fixture-session.sh`; that script reproduces the same shape. This
directory is the capture after `scripts/scrub-transcript.py` and a hand review of
every line.

The session's project was `canary-basic`, which has no `PERMISSIONS.yaml`, so the
hook's decision is `allow` with a rewrite under the default profile. Spec B
expected `canary-request` (a manifest that asks for `network: all`); run
`scripts/fixture-session.sh --skill canary-request` to capture that variant.

## Layout

Mirrors `~/.claude/projects`, so tests point `ClaudeProjectsDir` at `projects/`:

```
projects/-Users-you-proj/a9896c55-0b77-4f85-a0e0-9be2948b8aa6.jsonl         main agent, 10 rows
projects/-Users-you-proj/a9896c55-.../subagents/agent-a3033ade8c1d9c1a5.jsonl   the Explore subagent, 9 rows
projects/-Users-you-proj/a9896c55-.../subagents/agent-a3033ade8c1d9c1a5.meta.json
hook-stdin.jsonl   the two PreToolUse stdin objects the hook received (main Bash call, subagent Bash call)
```

The transcript's cwd is `/Users/you/proj`; the escaped directory name
`-Users-you-proj` is `EscapeProjectDir("/Users/you/proj")`.

## What the scrub did

Dropped rows (nothing the reader uses; they carried the capturing machine's data):

- every `attachment` row except watchdeck's own PreToolUse answer:
  `prompt_snapshot` (the full system prompt), `credential_org`
  (`organizationUuid`), `session_context` (email), `environment`,
  `skill_listing`, `deferred_tools_delta`, `agent_listing_delta`,
  `mcp_instructions_delta`, `model`, `date`, `auto_mode`, `advisor_tool`,
  `remote_session_change`, `total_tokens_reminder`, `queued_command`,
  `hook_additional_context`, and every `hook_success` row of another hook
  (SessionStart, UserPromptSubmit, PreToolUse and PostToolUse status updates,
  SubagentStart, SubagentStop and Stop, including one plugin's metrics JSON):
  20 such rows in all;
- `system` rows with subtype `stop_hook_summary` (they name the machine's hooks);
- `cost-state`, `atis-latch`, `last-prompt` and `queue-operation` rows: session
  bookkeeping without timestamps or tool calls.

The only attachment kept is watchdeck's row (main file row 6, `PreToolUse:Bash`,
`toolUseID` of the probe call): a `hook_success` row whose hook name starts with
`PreToolUse:` and whose stdout is hook JSON naming watchdeck. It is intact and holds
the hook's full JSON: `permissionDecision`, the `updatedInput.command` rewrite to
`watchdeck run --skill canary-basic -c '...'`, and the reason. Its `command` is
`/Users/you/work/hookdump.sh`, the tee wrapper.

Dropped content blocks: both `thinking` blocks (main row 2, subagent row 5).
They were already empty on disk but carried opaque, account-linked `signature`
blobs, and the reader never uses them; those two assistant rows keep an empty
`content` array.

Removed fields everywhere: `serverClassifierContext`, `serverClassifierRequest`,
`organizationUuid`, `rendered`, `renderedRole`, `renderedBesideToolResult`.

Replaced ids (opaque ids tied to the capturing account's API calls): `requestId`
becomes `req_FAKE<n>`, `message.id` (`msg_...`) becomes `msg_FAKE<n>`, and
`promptId` in the transcripts and `prompt_id` in `hook-stdin.jsonl` become
`prompt-FAKE<n>`, and `toolUseResult.harnessSectionHash` becomes
`fakehash<n>`. One mapping covers all files, numbered in first-seen order, so
equal real ids stay equal and joins on them still hold: 5 request ids, 5
message ids, 1 prompt id and 1 hash.

Rewritten strings: the temp project to `/Users/you/proj`, the temp work dir to
`/Users/you/work`, the home dir to `/Users/you`, the escaped forms likewise; any
email to `you@example.com` (none remained); `sk-ant-...` and `AKIA...` patterns to
`REDACTED` (none were present).

Intact: `tool_use` ids, uuids, timestamps, `message.model`, `is_error`, tool
inputs (after the path rewrite), the Bash result `net: DENIED(1)`, the Read
result (the canary's own SKILL.md), the subagent's grep results, `version`,
`gitBranch` (`master`, the temp project's), `usage`, `advisorModel`,
`permissionDecision`.

Review before commit (2026-10-12): `grep -rn -i -E '<login>|@|organizationUuid|sk-ant|AKIA|prompt_snapshot|credential_org' internal/transcript/testdata`,
with `<login>` the capturing user's login name, matched nothing in the data files
(`*.jsonl`, `*.json`); its only matches are this README's own mentions of the
dropped fields. The main and subagent transcripts, the meta file and
`hook-stdin.jsonl` were read end to end. Re-running the scrub over the raw
capture reproduces these files byte for byte. `TestOnlyHookSuccessAttachmentsRetained`
re-checks the data files on every test run: only watchdeck's PreToolUse rows,
no thinking block, no `signature` key, no home path other than `/Users/you`.

## What this capture verifies (2026-10-12)

- Hook stdin keys: `session_id cwd permission_mode prompt_id effort hook_event_name tool_name tool_input tool_use_id transcript_path`, plus `agent_id agent_type` inside the subagent; `transcript_path` names the main file for both calls.
- The hook's `tool_use_id` equals the transcript's `tool_use.id` for the main Bash call (`toolu_012ZTzbEFwgsQu4H4Zv1Sk2m`, main row 3) and the subagent's (`toolu_01FfekpxjThEQTpTcNXLWp5S`, subagent row 6); the hook's `agent_id` equals the subagent file's id and the rows' `agentId`.
- `tool_use.input.command` is the model's original command; the rewrite appears only in the `hook_success` attachment.
- Subagent file path: `<dir>/<session id>/subagents/agent-<agent id>.jsonl`; a `.meta.json` with `agentType`, `description`, `toolUseId`, `spawnDepth`, `requestShape`, `requestNonInteractive` sat next to it. The parent's Agent `tool_result` row also carries `toolUseResult.agentId`, `agentType`, `resolvedModel`.
- `Agent` tool input keys: `description`, `prompt`, `subagent_type`, `run_in_background` (no `model`, no `name`).
- `message.content` is a string on prompt rows and an array of blocks elsewhere; `tool_result.content` is a string (Bash, Read, Grep) or an array of text blocks (Agent, SubagentHandback); `is_error` is present only on Bash results.
- Subagent rows carry `isSidechain: true` and `agentId`; main rows carry `isSidechain: false`. Assistant rows of the subagent carry `attributionAgent: "Explore"`.
- Not seen here: a `Skill` tool_use, `summary` or `file-history-snapshot` rows, a legacy sidechain inside the main file. Those shapes are assumed in `../synthetic-subagents`.
- Observed once (n=1), in the raw capture: the subagent's Bash call has a hook-stdin entry but no watchdeck `hook_success` row. The hook printed nothing for it (no skill involved), and Claude Code appears to write the attachment only when a hook produced output.

## lifecycle-stdin.jsonl (2026-10-13, M5.2)

A second, separate capture: the stdin of `SessionStart`, `UserPromptSubmit` and
`SessionEnd`, one object per line in the order they fired. Produced on
2026-10-13 from one `claude -p "Reply with the single word: ok"` session
(Claude Code 2.1.296) in an empty temporary project, with a temporary
`--settings` file registering a one-line `sh` hook (`cat >> raw.jsonl`) on the
three events, matcher-less groups, and temporary `XDG_STATE_HOME` and
`WATCHDECK_ACTIVITY`. Not made with `scripts/fixture-session.sh`; no
transcript was read or copied. The scrub rewrote exactly two fields: `cwd` to
`/Users/you/proj` and `transcript_path` to
`/Users/you/.claude/projects/-Users-you-proj/<session id>.jsonl`. The ids are
the session's own random UUIDs; the prompt is the harmless text above. Read end
to end before commit; `TestOnlyHookSuccessAttachmentsRetained` re-checks it
for home paths and handles on every run.

What it shows (n=1, `-p` mode, permission mode auto):

- `SessionStart`: `session_id transcript_path cwd hook_event_name source` (`source: "startup"`). No `permission_mode`, `prompt_id`, `model` or pid.
- `UserPromptSubmit`: `session_id transcript_path cwd prompt_id permission_mode hook_event_name prompt`. The `prompt` key carries the prompt text; watchdeck never stores it (`TestLifecycleEventsFromCapture`).
- `SessionEnd`: `session_id transcript_path cwd prompt_id hook_event_name reason` (`reason: "other"` for a `-p` session that finished).
- Matcher-less groups on all three events fired. Not seen here: `source` values `resume`, `clear`, `compact`; other `reason` values; an interactive session.
