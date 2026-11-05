---
name: watchdeck
description: Use when a Bash command fails with "Operation not permitted", EPERM, or a "[watchdeck]" trailer, or when the user asks what a skill is allowed to do. Explains the sandbox skill scripts run under and how to read and report denials.
---

# watchdeck

Skill scripts on this machine run under a per-skill sandbox. A Bash command that references a skill's script is rewritten to `watchdeck run --skill <name> -c '<command>'` before it executes. The sandbox is enforced by the operating system, not by you.

## When a sandboxed command fails

If the output ends with a `[watchdeck] exit N under profile <skill>/<hash> …` trailer, or the error is `Operation not permitted` / `EPERM`:

1. Report the denial to the user with the trailer verbatim. Say which capability was blocked (network, a write outside the project, a read of a protected path, a subprocess) if the trailer or error makes it clear.
2. Tell the user how to widen the policy if they want to. The trailer names the exact command, for example `watchdeck allow <skill> --network all`.
3. Do **not** work around the sandbox. Never copy the script elsewhere, pipe its contents into an interpreter, inline its code in a here-doc, or re-run it from a different directory. Those are the evasions the sandbox exists to catch, and the user will see them.

## Reading a policy

- `watchdeck audit` lists every installed skill, its scripts, the capabilities its code references, and whether it has a `PERMISSIONS.yaml`.
- A skill's `PERMISSIONS.yaml` is a *request*. The user's grant is the default profile (no network, writes only to the project directory and temp, protected paths like `~/.ssh` hidden, environment scrubbed) unless they widened it with `watchdeck allow`.
- `watchdeck status` shows whether this machine is protected, what needs the user, and the install checks.

## Plugin commands, activity log and dashboard

The plugin ships two slash commands, both user-only: `/watchdeck:status` (protection, what needs the user, install checks) and `/watchdeck:open` (start and open the dashboard). Both carry `disable-model-invocation`, and the Skill tool refuses them from you, because each pre-approves its own shell line. When the user asks what a skill may do or whether watchdeck is set up, run `watchdeck audit` or `watchdeck status` through Bash under the ordinary permission flow, or tell them to type `/watchdeck:status`. Never run `watchdeck allow` yourself, not even when the trailer prints the exact line; a grant is the user's decision. Give them the line and let them run it in a terminal.

Every decision watchdeck makes about a skill script and every `watchdeck run` outcome is appended to the activity log, `${XDG_STATE_HOME:-~/.local/state}/watchdeck/activity.jsonl` (`WATCHDECK_ACTIVITY=off` turns it off). Commands that touch no skill are never recorded. The dashboard, `watchdeck ui`, serves on 127.0.0.1 only behind a one-time link and shows installed skills, grants, the Enforce page and a policy-aware map of the session built from that log. In a session, the plugin draws a band above the prompt when a skill run is denied; granting from the band always asks the user to confirm first. When the user asks what was denied and why, you may read the trailer and the `[watchdeck]` lines in the tool result, and point them at the dashboard for the full record.

## If the user runs Claude Code's own Bash sandbox

`watchdeck run` must be listed in `sandbox.excludedCommands`, otherwise it fails closed with exit 126 and a message. The fix is `watchdeck enforce install`, run once by the user.
