#!/bin/bash
# The README screenshots, from a fixture home. Developer tool, never on
# push; never touches the real ~/.claude, config or state dirs.
#
#   scripts/screenshots.sh [OUTDIR]
#
# Runs scripts/walk.sh once on a fixture home built with
# --many 400 --live 3 --installed --seed 7 --now <this run's UTC second>,
# takes the shots below into OUTDIR (default: a new dir under /var/tmp),
# copies them into docs/images, prints each size, and exits 1 if any PNG is
# over 400 KB. Nothing is resized or quantized. The --now value is printed
# first; docs/images/README.md records it.
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
out=${1:-$(mktemp -d /var/tmp/watchdeck-shots-XXXXXX)}
mkdir -p "$out"
out=$(cd "$out" && pwd)
now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
limit=409600
names=(sessions-live needs-resolve session-map rules rules-try home-leak home-dark)

echo "screenshots: --now $now, into $out"
"$repo/scripts/walk.sh" --many 400 --live 3 --installed --seed 7 --now "$now" \
  --screenshots "$out" \
  --shot 'sessions-live=#/sessions' \
  --shot 'needs-resolve=#/#confirm-open' \
  --shot 'session-map=#/sessions/<C>/timeline#fit' \
  --shot 'rules=#/rules' \
  --shot 'rules-try=#/rules#try-open' \
  --shot 'home-leak=#/#leak-row' \
  --shot 'home-dark=#/@dark'

fail=0
for n in "${names[@]}"; do
  f="$out/$n.png"
  [ -s "$f" ] || { echo "screenshots: $n.png missing" >&2; fail=1; continue; }
  cp "$f" "$repo/docs/images/$n.png"
  size=$(wc -c < "$f" | tr -d ' ')
  mark=ok
  if [ "$size" -gt "$limit" ]; then mark="OVER 400 KB"; fail=1; fi
  printf '%-18s %8d bytes  %s\n' "$n.png" "$size" "$mark"
done
[ "$fail" = 0 ] && echo "screenshots: PASS (${#names[@]}, copied to docs/images)" || echo "screenshots: FAIL" >&2
exit $fail
