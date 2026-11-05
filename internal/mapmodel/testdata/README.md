# mapmodel testdata

## `activity-a.jsonl`: HAND-WRITTEN, partly synthetic (2026-10-12)

An activity log for fixture A (`internal/transcript/testdata/e2e-canary`). Four
records, schema v1, ids copied from that fixture's `hook-stdin.jsonl`. Fake
values only (`fakehash-*`, `/Users/you`).

| line | record | how it relates to the real capture |
|---|---|---|
| 1 | `decision` allow, `canary-basic`, `toolu_012ZTzbEFwgsQu4H4Zv1Sk2m` (main agent) | **faithful**: same id, command, rewrite and reason as the hook's `hook_success` row in the transcript |
| 2 | `run` ok, exit 0, no hints, `joined_by:"write"` | **faithful in shape**: the canary probe prints `net: DENIED(1)` on stdout and exits 0, so the cut can only come from the transcript's Bash result text (`evidence:"result_text"`, Spec B V22). Duration, hash and timestamp are invented |
| 3 | `decision` ask, `canary-request`, `toolu_01FfekpxjThEQTpTcNXLWp5S` (the Explore subagent, `agent_id` `a3033ade8c1d9c1a5`) | **synthetic**: the real call was a plain `grep` that touched no skill and the hook printed nothing for it. The record pretends it ran `canary-request` so one golden covers a subagent's ask, a manifest that asks for more than the default grant, and the hint path |
| 4 | `run` ok, exit 0, one stdout `network` hint (`net: DENIED(1)`), `joined_by:"write"` | **synthetic**, pairs with line 3; exercises `evidence:"hint"` |

## `golden/`

Graph JSON produced by `Build` for fixture A with this log, both views, with
and without hide-none, compared byte for byte by `TestGolden`. Regenerate with
`go test ./internal/mapmodel -run TestGolden -update` and review the diff.
