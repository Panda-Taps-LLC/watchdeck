#!/bin/bash
# The README hero GIF from a fixture home. Developer tool, never CI; never
# touches the real ~/.claude, config or state dirs.
#
#   scripts/demo-gif.sh [OUT]        (default docs/images/demo.gif)
#   DEMO_GIF_KEEP=DIR scripts/demo-gif.sh   also keeps the two recordings
#
# Records two videos with Playwright (scripts/walk's install): on the left,
# 480x640, scripts/demo/terminal.html, a rendering of a terminal and a Claude Code
# excerpt (labelled demo in the page); on the right, 800x640 so the sidebar
# shows (the shell wraps into a bar below 760 px), the dashboard Home of a
# fixture home (fixture-home.sh --many 400 --live 3 --installed --seed 7)
# while a Needs you row gets its rule added. ffmpeg trims both to one length,
# joins them side by side and writes a GIF with a palette made from the clip.
# The GIF is removed, exit 1, unless it is exactly 1280x640, at most 4 MiB and
# 10-14 s long. Exit 2 for a setup problem.
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
case "${1:-}" in
  -h|--help) sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
esac
out=${1:-"$repo/docs/images/demo.gif"}
case "$out" in /*) ;; *) out="$PWD/$out" ;; esac

# The clip: fps and dither (12 fps, with mpdecimate below).
# If 4 MiB is exceeded, lower fps to 10, then use dither=none (bayer_scale is
# already 5, its maximum), before shortening the clip.
fps=12
bayer_scale=5
clip_s=12
max_bytes=4194304
min_s=10
max_s=14

cd "$repo"
for tool in node ffmpeg ffprobe go python3; do
  command -v "$tool" >/dev/null || { echo "demo-gif: $tool not found" >&2; exit 2; }
done
if [ ! -d scripts/walk/node_modules/playwright ]; then
  echo "demo-gif: run 'npm install --no-audit --no-fund && npx playwright install chromium' in scripts/walk first" >&2
  exit 2
fi

# Chromium lives in the real home's Playwright cache; the dashboard half runs
# with the fixture HOME, so name the cache before HOME changes (as walk.sh).
if [ -z "${PLAYWRIGHT_BROWSERS_PATH:-}" ]; then
  case "$(uname -s)" in
    Darwin) PLAYWRIGHT_BROWSERS_PATH="$HOME/Library/Caches/ms-playwright" ;;
    *) PLAYWRIGHT_BROWSERS_PATH="${XDG_CACHE_HOME:-$HOME/.cache}/ms-playwright" ;;
  esac
fi
export PLAYWRIGHT_BROWSERS_PATH

tmp=$(mktemp -d /var/tmp/watchdeck-fixture-demo-XXXXXX)
fixture="$tmp/fixture"
envfile="$tmp/env.sh"
bin="$fixture/bin/watchdeck"
cleanup() {
  # The fixture's env, in a subshell, so the stop reaches the fixture's server.
  if [ -s "$envfile" ] && [ -x "$bin" ]; then
    ( set -a; . "$envfile" >/dev/null 2>&1; "$bin" ui --stop >/dev/null 2>&1 ) || true
  fi
  if [ -n "${DEMO_GIF_KEEP:-}" ]; then
    # Keep the two recordings for tuning the ffmpeg step; the fixture goes.
    mkdir -p "$DEMO_GIF_KEEP" && cp "$tmp"/left.webm "$tmp"/right.webm "$tmp"/right.skip "$DEMO_GIF_KEEP"/ 2>/dev/null || true
  fi
  rm -rf "$tmp"
}
trap cleanup EXIT

# Left: the terminal rendering (no fixture needed).
node scripts/demo/terminal.mjs --out "$tmp"

# Right: the dashboard from the fixture home. --installed builds the binary
# into the fixture's bin/ and installs the hooks and the recommended rules
# there, so Home says Protected.
scripts/fixture-home.sh "$fixture" --many 400 --live 3 --installed --seed 7 > "$envfile"
(
  set -e
  . "$envfile"
  state="$XDG_STATE_HOME/watchdeck"
  "$bin" ui --no-open --idle 1 --detach >/dev/null
  for _ in $(seq 1 100); do
    [ -s "$state/ui.json" ] && grep -q '"port": *[1-9]' "$state/ui.json" && break
    sleep 0.1
  done
  port=$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["port"])' "$state/ui.json")
  [ "${port:-0}" -gt 0 ] || { echo "demo-gif: dashboard did not publish a port" >&2; exit 2; }
  # The token goes to the page through the launch URL's #t= fragment only;
  # dashboard.mjs refuses to record while the hash still holds t=.
  node "$repo/scripts/demo/dashboard.mjs" --port "$port" --token-file "$state/ui.token" --out "$tmp"
)

# The right clip starts after the capture guard passed (right.skip, written
# by dashboard.mjs): no frame from while the hash held t= reaches the GIF.
# Both clips to one length: the shorter of the two, at most clip_s.
dur() { ffprobe -v error -show_entries format=duration -of default=nw=1:nk=1 "$1"; }
skip=$(cat "$tmp/right.skip")
echo "demo-gif: right clip starts at ${skip} s (after the capture guard)"
len=$(python3 -I -c 'import sys; l, r, k, c = map(float, sys.argv[1:]); print(f"{min(l, r - k, c):.3f}")' "$(dur "$tmp/left.webm")" "$(dur "$tmp/right.webm")" "$skip" "$clip_s")

mkdir -p "$(dirname "$out")"
rm -f "$out"
# One graph, two palette passes: palettegen reads the whole joined clip
# (stats_mode=diff weights what moves), paletteuse maps every frame to it.
# mpdecimate drops frames that differ from the last kept one only by the
# recordings' encoder noise and fps repeats the kept frame exactly, so the
# GIF stores still stretches once (12 fps without it came out at 4.53 MB);
# diff_mode=rectangle re-dithers only the part of a frame that changed.
ffmpeg -v error -y -t "$len" -i "$tmp/left.webm" -ss "$skip" -t "$len" -i "$tmp/right.webm" \
  -filter_complex "[0:v][1:v]hstack=inputs=2,mpdecimate,fps=$fps,scale=1280:640:flags=lanczos,split[a][b];[a]palettegen=stats_mode=diff[p];[b][p]paletteuse=dither=bayer:bayer_scale=$bayer_scale:diff_mode=rectangle" \
  -loop 0 "$out"

# The three checks. Any failure removes the GIF.
width=$(ffprobe -v error -select_streams v:0 -show_entries stream=width -of default=nw=1:nk=1 "$out")
height=$(ffprobe -v error -select_streams v:0 -show_entries stream=height -of default=nw=1:nk=1 "$out")
seconds=$(dur "$out")
size=$(wc -c < "$out" | tr -d ' ')
echo "demo-gif: ${width}x${height}, ${seconds} s, ${size} bytes"
fail=0
if ! { [ "$width" = 1280 ] && [ "$height" = 640 ]; }; then
  echo "demo-gif: FAIL: not 1280x640" >&2; fail=1
fi
if ! [ "$size" -le "$max_bytes" ]; then
  echo "demo-gif: FAIL: over $max_bytes bytes (lower fps to 10, then dither=none)" >&2; fail=1
fi
if ! python3 -I -c 'import sys; s=float(sys.argv[1]); sys.exit(0 if float(sys.argv[2]) <= s <= float(sys.argv[3]) else 1)' "$seconds" "$min_s" "$max_s"; then
  echo "demo-gif: FAIL: duration outside ${min_s}-${max_s} s" >&2; fail=1
fi
if [ "$fail" = 1 ]; then
  rm -f "$out"
  exit 1
fi
echo "demo-gif: PASS $out"
