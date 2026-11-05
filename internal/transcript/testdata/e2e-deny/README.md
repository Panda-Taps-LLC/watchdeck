# Fixture e2e-deny: how the transcript records denials

Captured 2026-10-19 UTC with Claude Code 2.1.303 by `WATCHDECK_FIXTURE=1 scripts/fixture-session.sh --mode deny`.
One throwaway `claude -p` session in a temp project; the transcript is scrubbed with `scripts/scrub-transcript.py`.

Placed into every fixture home as session C by `scripts/fixture-home.sh` (its transcript only, in fixture A's project dir; `hook-stdin.jsonl` is not copied).

Captured 2026-10-19 UTC with Claude Code 2.1.303.

## Prompt

```
Do exactly four things, one tool call each, in this order, and after each one report in one line what happened. Do not retry anything. (1) Run with the Bash tool: echo rule-deny-marker  (2) Read the file SECRET.md with the Read tool.  (3) Run with the Bash tool: echo classifier-deny-marker  (4) Run with the Bash tool: echo done
```

## Settings keys used (temp `--settings` file, nothing under ~/.claude was written)

- `permissions.defaultMode`: `auto`
- `autoMode.hard_deny`: `$defaults` plus a rule blocking any shell command whose text contains `classifier-deny-marker`
- `permissions.deny`: a Bash prefix rule for `echo rule-deny-marker` and a Read rule for the project's `SECRET.md` (absolute `//` form)
- `hooks.PreToolUse`: matcher `Bash`, a tee wrapper that keeps the hook's stdin, then `watchdeck hook`
- `hooks.PermissionDenied`: matcher `*`, the same tee wrapper
- `--allowedTools Bash,Read`, `--max-turns 8`

## Observed denial shapes

Shapes seen in the first real capture (2026-10-19 UTC, auto mode): a Bash call blocked by a deny rule has a tool_result row with `permissionDecision` reject/config/subcommandResults and an `is_error` result "Permission to use Bash with command ... has been denied."; a Read blocked by a deny rule has NO `permissionDecision` field, only an `is_error` result `<tool_use_error>File is in a directory that is denied by your permission settings.</tool_use_error>`; an allowed call carries accept/config/classifier. The classifier block of a custom autoMode.hard_deny rule is recorded below as observed in this run.

Observed in this run (decision/source/reasonType):

- Bash echo rule-deny-marker: reject/config/subcommandResults; is_error: Permission to use Bash with command echo rule-deny-marker has been denied. (matches the expectation)
- Read SECRET.md: no permissionDecision (expected); is_error: <tool_use_error>File is in a directory that is denied by your permission settings.</tool_use_error> (matches the expectation)
- Bash echo classifier-deny-marker: reject/config/classifier; is_error: Permission for this action was denied by the Claude Code auto mode classifier. Reason: The server-side auto mode classif (matches the expectation)
- Bash echo done: accept/config/classifier (matches the expectation)
- PermissionDenied hook stdin lines: 1 of 4

## toolDenialKind

Transcript tool-result rows also carry a top-level `toolDenialKind` field:

- `permission-rule` on the Bash deny-rule row (`echo rule-deny-marker`);
- `automode-blocked` on the classifier row (`echo classifier-deny-marker`);
- absent on the Read deny row (`SECRET.md`) and on accepted calls.

The `PermissionDenied` hook stdin `reason` for the custom `autoMode.hard_deny` rule is the sentence "The server-side auto mode classifier judged this action dangerous (it gave no explanation)". It does not name the rule: there is no `[Rule Name]` in it.

The person's 'No' is not in this capture; it needs one interactive run (see the approved plan, Phase 2).
