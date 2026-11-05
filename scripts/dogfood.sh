#!/bin/bash
# Interactive dogfood setup: a throwaway project with three canary skills, an
# isolated watchdeck config (ask mode, no auto_allow) and a TEMPORARY Claude
# Code settings file produced by `watchdeck enforce install --file`.
# ~/.claude/settings.json is never touched. The work dir is kept so you can
# inspect the activity log afterwards; delete it yourself when done.
#
#   scripts/dogfood.sh          # prints the commands to run in another terminal
set -euo pipefail
export PATH="/opt/homebrew/bin:$PATH"
repo="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d -t watchdeck-dogfood)"
bin="$work/bin"; mkdir -p "$bin"
( cd "$repo" && go build -o "$bin/watchdeck" ./cmd/watchdeck )

proj="$work/proj"; mkdir -p "$proj/.claude/skills"
for s in canary-basic canary-request canary-exec; do cp -R "$repo/testdata/skills/$s" "$proj/.claude/skills/"; done
( cd "$proj" && git init -q . )

# Isolated config, cache and state: no overrides.yaml, so every skill run asks.
# The activity log is on by default; it goes into the work dir.
export XDG_CONFIG_HOME="$work/xdg-config" XDG_CACHE_HOME="$work/xdg-cache" XDG_STATE_HOME="$work/xdg-state"
mkdir -p "$XDG_CONFIG_HOME" "$XDG_CACHE_HOME" "$XDG_STATE_HOME"

# Temporary settings: the same edit `watchdeck enforce install` makes, in a temp file.
settings="$work/settings.json"
printf '{}\n' > "$settings"
"$bin/watchdeck" enforce install --file "$settings" >/dev/null

cat > "$work/env.sh" <<EOF
export PATH="$bin:\$PATH"
export XDG_CONFIG_HOME="$XDG_CONFIG_HOME" XDG_CACHE_HOME="$XDG_CACHE_HOME" XDG_STATE_HOME="$XDG_STATE_HOME"
export WATCHDECK_ACTIVITY="$work/activity.jsonl"
EOF

echo "work dir:  $work"
echo "settings:  $settings"
echo "activity:  $work/activity.jsonl"
echo
echo "In a new terminal:"
echo "  source $work/env.sh && cd $proj && claude --settings $settings"
echo
echo "In a second terminal, for watchdeck allow and audit only. Do not start claude there:"
echo "a session launched without --settings has no hook, and its results prove nothing."
echo "  source $work/env.sh && cd $proj"
echo
echo "To watch the session's decisions and runs, in that second terminal:"
echo "  source $work/env.sh && watchdeck ui --no-open"
