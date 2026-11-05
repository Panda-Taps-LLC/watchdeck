---
name: open
description: Open the watchdeck dashboard in the browser, starting it in the background if it is not running (watchdeck ui --ensure --open).
disable-model-invocation: true
allowed-tools: Bash(watchdeck ui *)
---

!`watchdeck ui --ensure --open`

Tell the user the dashboard is open in their browser; a dashboard started this way keeps running until `watchdeck ui --stop`. This command never prints the dashboard's link or token. If it failed (for example "could not open a browser"), tell the user to run `watchdeck ui` in their own terminal. Run nothing else.
