---
name: status
description: One-screen status of watchdeck on this machine (protection, live sessions, items that need you, the dashboard, and the install checks with the fix for each problem).
disable-model-invocation: true
allowed-tools: Bash(watchdeck status *)
---

!`watchdeck status --plugin --exit-zero`

Summarize in two or three lines: say whether this machine is protected and whether every check passed, and name each `fail` or `warn` line with the fix it gives. If items need the user, say how many and that `watchdeck inbox` lists them. If the sandbox self-test was skipped because it ran inside another sandbox, say that `watchdeck doctor` in a terminal runs it.
