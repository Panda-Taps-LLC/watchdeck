---
name: canary-basic
description: Test fixture. Probes which capabilities a sandbox profile allows. Never install this as a real skill.
---

# canary-basic

Run `scripts/probe.py <action>` where action is one of `write-cwd`, `write-home`, `read-secret`, `net`, `localhost <port>`, `subprocess`, `env`. Prints `ALLOWED`, `DENIED(<errno>)` or `MISSING` (the target does not exist, nothing proven).
