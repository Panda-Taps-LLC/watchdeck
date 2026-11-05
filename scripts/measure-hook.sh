#!/bin/bash
# Fast-path measurement of `watchdeck hook` (docs/DESIGN.md, Spec A §3).
#
# Builds the hook binary twice, BEFORE (default HEAD~1) and AFTER (default
# HEAD), each from ./cmd/watchdeck in its own git worktree under a mktemp
# dir, and reports for each:
#   - stripped binary size (go build -ldflags "-s -w");
#   - GODEBUG=inittrace=1 of one hook spawn: the 25 slowest package inits,
#     the summed init clock time, and every package of this module that has init
#     work (the acceptance wants none of internal/ui, activity, paths);
#   - wall time per spawn (median, p95) over N spawns (default 200) of a
#     no-opinion payload (`git status`), a rewrite payload (a canary skill
#     script), a SessionStart payload and a UserPromptSubmit payload (M5.2
#     lifecycle: a start record + marker each spawn; a prompt inside a minute
#     of the last record only touches the marker), timed by a `python3 -I`
#     harness with time.perf_counter_ns. A warm-up SessionStart creates the
#     session's marker first, so the PreToolUse runs include the marker touch.
#     A BEFORE binary older than M5.2 has no opinion on the lifecycle events.
# Acceptance (Spec A §3): no-opinion median within +1 ms of BEFORE, p95
# within +2 ms, no new package in inittrace. With CHECK=1 the script exits 2
# when either acceptance line reads OVER; by default it always exits 0, so a
# run on a busy machine still prints its table.
#
# Everything lives under one mktemp dir (fake HOME, project, XDG dirs, one
# cache and state dir per binary so each has its own warm index); the
# worktrees are removed and the dir deleted on exit. Nothing under the real
# home is read or written; the activity log of AFTER lands in its temp state
# dir and stays on, because the append is part of the real cost.
#
#   scripts/measure-hook.sh                 # HEAD~1 vs HEAD, 200 spawns
#   N=500 BEFORE=main AFTER=HEAD scripts/measure-hook.sh
#   CHECK=1 scripts/measure-hook.sh         # exit 2 when the acceptance says OVER (CI)
set -euo pipefail
export PATH="/opt/homebrew/bin:/usr/local/go/bin:$PATH"
repo="$(cd "$(dirname "$0")/.." && pwd)"
before_rev="${BEFORE:-HEAD~1}"
after_rev="${AFTER:-HEAD}"
n="${N:-200}"

work="$(mktemp -d /var/tmp/watchdeck-measure-XXXXXX)"
cleanup() {
  for d in before-src after-src; do
    if [ -d "$work/$d" ]; then git -C "$repo" worktree remove --force "$work/$d" >/dev/null 2>&1 || true; fi
  done
  git -C "$repo" worktree prune >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

build() { # name rev
  local name="$1" rev="$2"
  git -C "$repo" worktree add --quiet --detach "$work/$name-src" "$rev"
  (cd "$work/$name-src" && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o "$work/$name" ./cmd/watchdeck)
  echo "$name: $(git -C "$work/$name-src" rev-parse --short HEAD) $(git -C "$work/$name-src" log -1 --format=%s)"
}
echo "== build"
build before "$before_rev"
build after "$after_rev"
echo "go: $(go version)"
echo "host: $(uname -sm)"

# fake HOME with a project that carries one canary skill
export HOME="$work/home"
proj="$HOME/proj"
mkdir -p "$proj/.claude/skills"
git -C "$proj" init -q .
cp -R "$repo/testdata/skills/canary-basic" "$proj/.claude/skills/"
probe="$proj/.claude/skills/canary-basic/scripts/probe.py"
export XDG_CONFIG_HOME="$work/xdg-config"
unset WATCHDECK_ACTIVITY CLAUDE_CONFIG_DIR CLAUDE_SKILL_DIR
mkdir -p "$XDG_CONFIG_HOME"

noop="$work/noop.json"
rewrite="$work/rewrite.json"
printf '{"session_id":"s","tool_use_id":"toolu_m","cwd":"%s","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git status"}}' "$proj" > "$noop"
printf '{"session_id":"s","tool_use_id":"toolu_m","cwd":"%s","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"python3 %s net"}}' "$proj" "$probe" > "$rewrite"
# M6.3: a Read of a project file (no gate, no pack hit: no opinion) and a
# Bash command that fires a default pack rule (secrets-read/dotenv, log:
# no output, one rule_log record).
printf '{"session_id":"s","tool_use_id":"toolu_m","cwd":"%s","hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":"%s/README.md"}}' "$proj" "$proj" > "$work/read.json"
printf '{"session_id":"s","tool_use_id":"toolu_m","cwd":"%s","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"cat .env"}}' "$proj" > "$work/packhit.json"
printf '{"session_id":"s","transcript_path":"%s/t.jsonl","cwd":"%s","hook_event_name":"SessionStart","source":"startup"}' "$work" "$proj" > "$work/sessionstart.json"
printf '{"session_id":"s","transcript_path":"%s/t.jsonl","cwd":"%s","prompt_id":"p","permission_mode":"default","hook_event_name":"UserPromptSubmit","prompt":"hello"}' "$work" "$proj" > "$work/prompt.json"

echo
echo "== size (bytes)"
sb=$(wc -c < "$work/before" | tr -d ' ')
sa=$(wc -c < "$work/after" | tr -d ' ')
echo "before $sb"
echo "after  $sa"
echo "delta  $((sa - sb))"

# per-binary env: own cache (warm index) and state (activity log)
envfor() { # name
  export XDG_CACHE_HOME="$work/cache-$1" XDG_STATE_HOME="$work/state-$1"
  mkdir -p "$XDG_CACHE_HOME" "$XDG_STATE_HOME"
}

echo
echo "== warm-up and sanity (untimed)"
for b in before after; do
  envfor "$b"
  (cd "$proj" && "$work/$b" index --rebuild >/dev/null)
  out_start="$(cd "$proj" && "$work/$b" hook < "$work/sessionstart.json")"
  out_prompt="$(cd "$proj" && "$work/$b" hook < "$work/prompt.json")"
  if [ -n "$out_start$out_prompt" ]; then echo "FAIL: $b printed on a lifecycle event: $out_start$out_prompt" >&2; exit 1; fi
  out_noop="$(cd "$proj" && "$work/$b" hook < "$noop")"
  out_rw="$(cd "$proj" && "$work/$b" hook < "$rewrite")"
  if [ -n "$out_noop" ]; then echo "FAIL: $b had an opinion on git status: $out_noop" >&2; exit 1; fi
  case "$out_rw" in
    *" run --skill canary-basic -c"*) echo "$b: no-opinion silent, rewrite ok" ;;
    *) echo "FAIL: $b did not rewrite the canary command: $out_rw" >&2; exit 1 ;;
  esac
done

echo
echo "== inittrace (one hook spawn, no-opinion payload; 25 slowest inits by clock ms)"
for b in before after; do
  envfor "$b"
  trace="$work/inittrace-$b.txt"
  (cd "$proj" && GODEBUG=inittrace=1 "$work/$b" hook < "$noop" 2> "$trace" >/dev/null) || true
  echo "-- $b"
  grep '^init ' "$trace" | sort -k5 -n -r | head -25
  awk '/^init /{ms+=$5; allocs+=$(NF-1); n++} END{printf "total: %d packages, %.3f ms clock, %d allocs\n", n, ms, allocs}' "$trace"
  own=$(grep '^init github.com/Panda-Taps-LLC/' "$trace" | awk '{print $2}' | tr '\n' ' ' || true)
  echo "module packages with init work: ${own:-none}"
done
echo "-- packages with init work in after but not in before"
comm -13 <(awk '/^init /{print $2}' "$work/inittrace-before.txt" | sort -u) \
         <(awk '/^init /{print $2}' "$work/inittrace-after.txt" | sort -u) | sed 's/^/  /' || true
[ -n "$(comm -13 <(awk '/^init /{print $2}' "$work/inittrace-before.txt" | sort -u) <(awk '/^init /{print $2}' "$work/inittrace-after.txt" | sort -u))" ] || echo "  none"

harness="$work/harness.py"
cat > "$harness" <<'PY'
import statistics, subprocess, sys, time
binary, payload, n, cwd = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
data = open(payload, "rb").read()
walls = []
for _ in range(n):
    t0 = time.perf_counter_ns()
    subprocess.run([binary, "hook"], input=data, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=cwd, check=True)
    walls.append((time.perf_counter_ns() - t0) / 1e6)
walls.sort()
p95 = walls[min(len(walls) - 1, int(round(0.95 * len(walls))) - 1)]
print(f"{statistics.median(walls):.2f} {p95:.2f} {walls[0]:.2f} {walls[-1]:.2f}")
PY

echo
echo "== wall time per spawn, ms ($n spawns each; median p95 min max)"
for p in noop rewrite read packhit sessionstart prompt; do
  for b in before after; do
    envfor "$b"
    python3 -I "$harness" "$work/$b" "$work/$p.json" "$n" "$proj" > "$work/res-$b-$p"
    printf '%-8s %-7s %s\n' "$p" "$b" "$(cat "$work/res-$b-$p")"
  done
done

# M6.3: the same Read and no-opinion Bash with every pack turned off in the
# user policy file (a user file exists, so the hook reads its policy cache;
# Read then has no rule at all and takes the tool fast filter).
offcfg="$work/xdg-config-packs-off"
mkdir -p "$offcfg/watchdeck"
printf 'version: 2\npacks: {cred-in-write: off, destructive: off, exfil: off, git-force-main: off, persistence: off, pipe-to-shell: off, prompt-injection: off, secrets-read: off}\n' > "$offcfg/watchdeck/overrides.yaml"
for p in read noop; do
  for b in before after; do
    envfor "$b"
    XDG_CONFIG_HOME="$offcfg" python3 -I "$harness" "$work/$b" "$work/$p.json" "$n" "$proj" > "$work/res-$b-$p-off"
    printf '%-8s %-7s %s\n' "$p-off" "$b" "$(cat "$work/res-$b-$p-off")"
  done
done

echo
echo "== acceptance (no-opinion)"
read -r bm bp _ _ < "$work/res-before-noop"
read -r am ap _ _ < "$work/res-after-noop"
acceptance="$(python3 -I - "$bm" "$bp" "$am" "$ap" <<'PY'
import sys
bm, bp, am, ap = map(float, sys.argv[1:])
dm, dp = am - bm, ap - bp
print(f"median delta {dm:+.2f} ms (limit +1.00): {'ok' if dm <= 1.0 else 'OVER'}")
print(f"p95 delta    {dp:+.2f} ms (limit +2.00): {'ok' if dp <= 2.0 else 'OVER'}")
PY
)"
printf '%s\n' "$acceptance"
# CHECK=1 (CI): exit 2 when either line is OVER. The default stays exit 0.
# A case match, not a pipe into grep, so pipefail cannot lose the exit 2.
if [ "${CHECK:-0}" = 1 ]; then
  case "$acceptance" in
    *OVER*)
      echo "CHECK=1: over budget" >&2
      exit 2
      ;;
  esac
fi
