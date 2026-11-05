---
name: canary-exec
description: Test fixture. Exec allow-list that permits the interpreter but not /bin/ls.
---
Run `scripts/probe.py subprocess`; expect DENIED.
