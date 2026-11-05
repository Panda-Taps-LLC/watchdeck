#!/bin/bash
# Dashboard walkthrough from a fixture home. Developer tool and manual
# workflow (.github/workflows/walk.yml), never on push; never touches the real
# ~/.claude, config or state dirs.
#
#   scripts/walk.sh [--keep] [--many N] [--live K] [--installed] [--seed S] [--now T]
#                   [--keys] [--axe] [--screenshots DIR] [--shot NAME=ROUTE[@dark][#STATE]]...
#
# Builds the binary into a temp dir, builds a fixture home (fixture-home.sh,
# which gets --many/--live/--installed/--seed/--now verbatim), starts the
# dashboard there, runs scripts/walk/walk.mjs against it (which gets --keys,
# --axe, --screenshots and --shot), stops the dashboard and removes the
# fixture unless --keep. With no flags it is the 17-row route walk. Exits
# with the walk's code (2 for a setup problem).
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
keep=0
fixture_args=()
walk_args=()
need() { [ $# -ge 2 ] && [ -n "$2" ] || { echo "walk: $1 needs a value" >&2; exit 2; }; }
while [ $# -gt 0 ]; do
  case "$1" in
    --keep) keep=1 ;;
    --installed) fixture_args+=("$1") ;;
    --many|--live|--seed|--now) need "$@"; fixture_args+=("$1" "$2"); shift ;;
    --keys|--axe) walk_args+=("$1") ;;
    --screenshots)
      need "$@"
      mkdir -p "$2"
      walk_args+=("$1" "$(cd "$2" && pwd)"); shift ;;
    --shot) need "$@"; walk_args+=("$1" "$2"); shift ;;
    -h|--help) sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "walk: unknown argument $1" >&2; exit 2 ;;
  esac
  shift
done

cd "$repo"
if [ ! -d scripts/walk/node_modules/playwright ]; then
  echo "walk: run 'npm install && npx playwright install chromium' in scripts/walk first" >&2
  exit 2
fi

# The browser is installed under the real home's Playwright cache; the walk runs
# with the fixture HOME, so point Playwright at the cache before HOME changes.
# Only that directory is named: nothing else in the real home is read.
if [ -z "${PLAYWRIGHT_BROWSERS_PATH:-}" ]; then
  case "$(uname -s)" in
    Darwin) PLAYWRIGHT_BROWSERS_PATH="$HOME/Library/Caches/ms-playwright" ;;
    *) PLAYWRIGHT_BROWSERS_PATH="${XDG_CACHE_HOME:-$HOME/.cache}/ms-playwright" ;;
  esac
fi
export PLAYWRIGHT_BROWSERS_PATH

tmp=$(mktemp -d /var/tmp/watchdeck-walk-XXXXXX)
bin="$tmp/watchdeck"
fixture="$tmp/fixture"
envfile="$tmp/env.sh"

# The trap goes in before the build and the fixture, so a failure in either
# still removes the temp dir. The stop runs only once the fixture's env exists.
cleanup() {
  if [ -s "$envfile" ] && [ -x "$bin" ]; then
    # The fixture's env, in a subshell, so the stop reaches the fixture's server.
    ( set -a; . "$envfile" >/dev/null 2>&1; "$bin" ui --stop >/dev/null 2>&1 ) || true
  fi
  if [ "$keep" = 1 ]; then
    echo "walk: kept $tmp (fixture home $fixture/home)"
  else
    rm -rf "$tmp"
  fi
}
trap cleanup EXIT

go build -o "$bin" ./cmd/watchdeck
# The binary goes to the fixture too: with it, fixture-home.sh adds the
# ~/.kube/config intent that walk.mjs's Rules checks look for.
WATCHDECK_BIN="$bin" scripts/fixture-home.sh ${fixture_args[@]+"${fixture_args[@]}"} "$fixture" > "$envfile"

set +e
(
  set -e
  . "$envfile"
  state="$XDG_STATE_HOME/watchdeck"
  # Session A by its id (fixture-home.sh --live adds copies that sort first),
  # else the first live marker. Session C (the deny session) when the fixture
  # has its transcript; shots name it as <C>.
  A=a9896c55-0b77-4f85-a0e0-9be2948b8aa6
  C=d484a6af-2106-45c4-9d15-1c2212b76809
  if [ -e "$state/live/$A" ]; then session=$A; else session=$(ls "$state/live" 2>/dev/null | head -n 1 || true); fi
  [ -n "$session" ] || { echo "walk: no live session in the fixture" >&2; exit 2; }
  c_args=()
  if find "$HOME/.claude/projects" -name "$C.jsonl" 2>/dev/null | grep -q .; then c_args=(--session-c "$C"); fi

  "$bin" ui --no-open --idle 1 --detach >/dev/null
  for _ in $(seq 1 100); do
    [ -s "$state/ui.json" ] && grep -q '"port": *[1-9]' "$state/ui.json" && break
    sleep 0.1
  done
  port=$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["port"])' "$state/ui.json")
  [ "${port:-0}" -gt 0 ] || { echo "walk: dashboard did not publish a port" >&2; exit 2; }

  node "$repo/scripts/walk/walk.mjs" --port "$port" --token-file "$state/ui.token" --session "$session" ${c_args[@]+"${c_args[@]}"} ${walk_args[@]+"${walk_args[@]}"}
)
code=$?
exit $code
