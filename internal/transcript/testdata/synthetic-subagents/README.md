# synthetic-subagents: SYNTHETIC, hand-written on 2026-10-12

Nothing here was produced by Claude Code. The rows copy the line shape of the
real capture in `../e2e-canary` (same top-level keys, `agentId` and
`isSidechain: true` on subagent rows, `toolUseResult` on tool results, a
`hook_success` attachment with the hook's JSON in `stdout`) and add the shapes
the reader must handle that the real capture did not contain. Replace it with a
real capture when one exists; until then every test on it says "shape as
assumed on 2026-10-12, not verified against Claude Code".

Session `b0000000-0000-4000-8000-00000000000b`, cwd `/Users/you/proj-b`
(escaped `-Users-you-proj-b`). Main file, in order:

| row | what | mirrors the real capture? |
|---|---|---|
| 1 | user prompt (string content) | yes |
| 2 | Bash `probe.py net` (`toolu_B01`) | yes |
| 3 | `hook_success` PreToolUse:Bash with an **ask** decision and a rewrite in `updatedInput.command` | shape yes; the real capture has `allow` |
| 4 | Bash result `net: DENIED(1)`, `is_error:false` | yes |
| 5-6 | Read `README.md` and its result | yes |
| 7 | Agent `toolu_B03` (Explore, "Find TODOs") | yes |
| 8 | Agent `toolu_B04` (general-purpose, "Review the diff") | yes (second spawn assumed) |
| 9-10 | `mcp__playwright__browser_navigate` `toolu_B05` and a text-block result | **assumed** (no MCP call in the real capture) |
| 11-13 | a legacy sidechain inside the main file: `isSidechain:true`, no `agentId`, chained by `parentUuid`; Grep `toolu_B06` by `claude-sonnet-4-5` | **assumed** (older layout; the real capture puts subagents in files) |
| 14-15 | Skill `toolu_B07` with `input.skill` | **assumed** (V8 unverified) |
| 16 | Agent result for `toolu_B03` with `toolUseResult.agentId` | yes |
| 17 | Agent result for `toolu_B04` **without** `toolUseResult` | deliberately absent, to exercise order-based linking |
| 18 | assistant text | yes |
| 19 | a `summary` row without a timestamp | **assumed** |

`subagents/agent-b000000000000001.jsonl` (Explore, Grep + Read + SubagentHandback,
`attributionAgent: "Explore"`) has a `.meta.json` naming `toolu_B03`.
`subagents/agent-b000000000000002.jsonl` (Bash `git diff --stat` by
`claude-sonnet-4-5`, then SubagentHandback) has no meta file and no result
`agentId`, so it can only be linked to `toolu_B04` by order.

Expected reading: four agents (main; `b000000000000001` linked by meta;
`b000000000000002` linked by order, `SpawnedBy` empty; the sidechain keyed by the
uuid of row 11, `Sidechain: true`); `toolu_B01` carries `HookDecision "ask"` and
the rewrite; `toolu_B05` splits into server `playwright`, tool `browser_navigate`;
`toolu_B07` is a `skill_invoked` event; the `summary` row is ignored without
counting as skipped.
