#!/bin/bash
# Build a throwaway fixture HOME for screenshots and manual walks of the
# dashboard. Everything comes from the repo's fixtures; nothing is read from
# the real ~/.claude, ~/.config or ~/.local/state, and nothing is written there.
#
#   scripts/fixture-home.sh [OUTDIR] [--many N] [--live K] [--installed]
#                           [--seed S] [--now T]
#
# OUTDIR must not exist or be empty. Without it, a fresh dir under /var/tmp is
# used: no login name appears in the paths the dashboard shows, and it is not
# below the per-user temp dir, which `watchdeck run` refuses as an ancestor
# of HOME (an allow there would undo the home deny).
#
# Layout under OUTDIR:
#   home/                          HOME: a copy of testdata/home (personal, synced,
#                                  project and plugin skills), __HOME__ rewritten,
#                                  proj/.git
#   home/.claude/skills/canary-*   canary-basic, -exec, -localhost, -prose, -request
#   home/.claude/projects/-Users-you-proj/
#                                  fixture A, the scrubbed real session
#                                  (internal/transcript/testdata/e2e-canary)
#   home/.config/watchdeck/overrides.yaml
#                                  version 2: the canary-basic auto_allow grant (as in
#                                  the capture), the rule fixture-prod-db (ask) and a
#                                  one-hour pause of persistence/crontab from 10 minutes
#                                  before --now (written by fixture-sessions.py)
#   home/.claude/settings.json     testdata's, plus the person's own Claude Code rule
#                                  permissions.deny Bash(npm publish *)
#   home/.claude/projects/-Users-you-proj/e0000000-....jsonl
#                                  session L (Plan 08), synthetic, ended, 58 to 48
#                                  minutes before --now: a fake Slack-shaped token in a
#                                  Read result and a reply (leak watch), three asks by
#                                  fixture-prod-db, one deny by Bash(npm publish *)
#                                  through the hook; its four activity records are in
#                                  the log
#   home/.local/state/watchdeck/activity.jsonl
#                                  internal/mapmodel/testdata/activity-a.jsonl with
#                                  transcript_path pointed at the copy above (mode 0600),
#                                  plus two records stamped now (a curl denial and a
#                                  pack ask) for Home's Needs you
#   home/.claude/projects/-Users-you-proj-b/
#                                  fixture B, synthetic (testdata/synthetic-subagents)
#   home/.claude/projects/-Users-you-proj/d484a6af-....jsonl
#                                  session C, the real deny capture
#                                  (internal/transcript/testdata/e2e-deny), same
#                                  project as A; ended, no activity records (the
#                                  transcript's own denial fields are the point)
#   home/.local/state/watchdeck/sessions.jsonl, live/<A>
#                                  lifecycle records written here: A started and
#                                  open (live for 10 min after this runs), B and
#                                  C ended
#
# Options (scripts/fixture-sessions.py does the generating):
#   --many N     N synthetic ended sessions over the 30 days before --now, over
#                nine projects /Users/you/work/{api,web,infra,docs,cli,mobile,
#                data,ops,lab}; one in four has activity records (an ask from
#                a real pack rule, an auto-mode denial or a domain deny), one
#                in five a subagent
#   --live K     K live copies of fixture A (ids a1000000-0000-4000-8000-0000000000NN),
#                each in its own project (/Users/you/work/api, web, ...), its
#                25 s stretched over 3-5 minutes ending 1, 3, 6 (then every 3)
#                minutes before --now, with A's four captured activity
#                records, a start record and a live marker each
#   --installed  then run `watchdeck rules recommended --install --yes` and
#                `watchdeck enforce install` against the fixture home, with
#                OUTDIR/bin/watchdeck: a copy of $WATCHDECK_BIN when set, else
#                built from this repo (the hooks name that path, so no path
#                outside OUTDIR reaches the fixture's settings.json)
#
# With $WATCHDECK_BIN set, or --installed, the binary in OUTDIR/bin also adds
# one rule that covers every route (Plan 08), before --installed's steps:
# `watchdeck rules add --block --path ~/.kube/config --everywhere --yes`
# (Claude Code's Read and Edit rules, a Grep and Glob rule and a shell rule,
# under one intent id). Without a binary the home has no intent, and the
# summary line says so. scripts/walk.sh always passes its binary.
#   --seed S     generator seed (default 1)
#   --now T      ISO 8601 UTC instant the home is built "as of" (default: now);
#                with the same seed, now and OUTDIR two runs write the same
#                transcripts, activity log and sessions.jsonl (only the live
#                markers' mtimes differ: a marker under 10 minutes old is live,
#                so take screenshots right after building)
#
# The session's recorded cwd stays /Users/you/proj (the transcript and the log
# agree on it); only transcript_path is rewritten, so the map finds the file.
#
# Prints the environment to export, one `export` line per variable, the
# `cd` line, then a `# sessions: ...` comment. Use it with:
#   eval "$(scripts/fixture-home.sh)"
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)

usage() { awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; }
bad() { echo "fixture-home: $*" >&2; exit 3; }
isnum() { case $1 in ''|*[!0-9]*) return 1 ;; esac; }

outarg="" many=0 live=0 installed=0 seed=1 now=""
while [ $# -gt 0 ]; do
  case $1 in
    -h|--help) usage; exit 0 ;;
    --many) [ $# -ge 2 ] && isnum "$2" || bad "--many needs a number"; many=$2; shift 2 ;;
    --live) [ $# -ge 2 ] && isnum "$2" && [ "$2" -le 255 ] || bad "--live needs a number up to 255"; live=$2; shift 2 ;;
    --seed) [ $# -ge 2 ] && isnum "$2" || bad "--seed needs a number"; seed=$2; shift 2 ;;
    --now) [ $# -ge 2 ] || bad "--now needs an ISO 8601 UTC time"; now=$2; shift 2 ;;
    --installed) installed=1; shift ;;
    -*) usage >&2; bad "unknown option $1" ;;
    *) [ -z "$outarg" ] || { usage >&2; bad "one OUTDIR only"; }; outarg=$1; shift ;;
  esac
done

# $WATCHDECK_BIN made absolute now, before anything changes directory.
src_bin=${WATCHDECK_BIN:-}
if [ -n "$src_bin" ]; then
  [ -f "$src_bin" ] && [ -x "$src_bin" ] || bad "WATCHDECK_BIN is not an executable file: $src_bin"
  src_bin=$(cd "$(dirname "$src_bin")" && pwd -P)/$(basename "$src_bin")
fi

# One instant for every stamp this script writes: --now, else the clock.
now=$(python3 -I -c '
import re, sys, datetime
s = sys.argv[1]
if not s:
  t = datetime.datetime.now(datetime.timezone.utc)
else:
  s = s[:-1] + "+00:00" if s.endswith("Z") else s
  s = re.sub(r"\.(\d+)", lambda m: "." + (m.group(1) + "000000")[:6], s, count=1)  # 1-9 digits
  t = datetime.datetime.fromisoformat(s)
  if t.tzinfo is None:
    sys.exit("fixture-home: --now needs Z or a UTC offset")
  t = t.astimezone(datetime.timezone.utc)
print(t.strftime("%Y-%m-%dT%H:%M:%S.%fZ"))
' "$now") || exit 3

if [ -n "$outarg" ]; then
  out=$outarg
  if [ -e "$out" ] && [ -n "$(ls -A "$out")" ]; then
    echo "fixture-home: $out exists and is not empty" >&2
    exit 3
  fi
  mkdir -p "$out"
  out=$(cd "$out" && pwd -P)
else
  out=$(mktemp -d /var/tmp/watchdeck-fixture-XXXXXX)
  out=$(cd "$out" && pwd -P)
fi

home="$out/home"
cp -R "$repo/testdata/home" "$home"

# installed_plugins.json names install paths under __HOME__ (the tests do the same rewrite).
python3 -I -c '
import sys
p, home = sys.argv[1], sys.argv[2]
b = open(p).read().replace("__HOME__", home)
open(p, "w").write(b)
' "$home/.claude/plugins/installed_plugins.json" "$home"

# A git root, so the project root resolves to home/proj.
mkdir -p "$home/proj/.git"
printf 'ref: refs/heads/main\n' > "$home/proj/.git/HEAD"

for c in canary-basic canary-exec canary-localhost canary-prose canary-request; do
  cp -R "$repo/testdata/skills/$c" "$home/.claude/skills/$c"
done

mkdir -p "$home/.claude/projects"
cp -R "$repo/internal/transcript/testdata/e2e-canary/projects/-Users-you-proj" "$home/.claude/projects/"
# Fixture B (synthetic, internal/transcript/testdata/synthetic-subagents): a
# second project, so the Sessions page lists more than one.
cp -R "$repo/internal/transcript/testdata/synthetic-subagents/projects/-Users-you-proj-b" "$home/.claude/projects/"
# Session C (internal/transcript/testdata/e2e-deny): the real deny capture. Its
# cwd is /Users/you/proj, A's project, so only its transcript is copied into
# A's dir (hook-stdin.jsonl stays behind).
sid_c=d484a6af-2106-45c4-9d15-1c2212b76809
cp "$repo/internal/transcript/testdata/e2e-deny/projects/-Users-you-proj/$sid_c.jsonl" "$home/.claude/projects/-Users-you-proj/"

mkdir -p "$home/.config/watchdeck" "$home/.cache" "$home/.local/state/watchdeck"
chmod 700 "$home/.local/state" "$home/.local/state/watchdeck"

activity="$home/.local/state/watchdeck/activity.jsonl"
python3 -I -c '
import sys
src, dst, projects = sys.argv[1:4]
b = open(src).read().replace("/Users/you/.claude/projects", projects)
open(dst, "w").write(b)
' "$repo/internal/mapmodel/testdata/activity-a.jsonl" "$activity" "$home/.claude/projects"
chmod 600 "$activity"

# Two records stamped now, so Home's Needs you has items inside the inbox
# window (7 days without installed_at): an auto-mode denial of curl and a
# watchdeck ask from the pipe-to-shell pack's curl-pipe-shell rule. Both in
# fixture A's session with fresh tool use ids; written by this script, not
# captured. Appended in place, so the file keeps mode 0600.
python3 -I -c '
import json, sys, datetime
dst = sys.argv[1]
now = datetime.datetime.strptime(sys.argv[2], "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=datetime.timezone.utc)
ts = lambda d: (now - datetime.timedelta(seconds=d)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
a = "a9896c55-0b77-4f85-a0e0-9be2948b8aa6"
common = {"v": 1, "harness": "claude-code", "session_id": a, "permission_mode": "auto", "cwd": "/Users/you/proj"}
recs = [
  dict(common, kind="denied", ts=ts(20), tool_use_id="toolu_01FixtureHomeDenied0001", tool_name="Bash", argv0="curl",
       reason="Permission for this action was denied by the Claude Code auto mode classifier. Reason: The server-side auto mode classifier judged this action dangerous (it gave no explanation)"),
  dict(common, kind="decision", ts=ts(10), tool_use_id="toolu_01FixtureHomeGateAsk0002", tool_name="Bash", argv0="curl",
       decision="ask", enforcement="gate", target="evil.example",
       rules=[{"pack": "pipe-to-shell", "id": "curl-pipe-shell", "action": "ask"}]),
]
with open(dst, "a") as f:
  for r in recs:
    f.write(json.dumps(r, separators=(",", ":")) + "\n")
' "$activity" "$now"

# Session lifecycle (M5.2 schema): fixture A started and still open (its
# live marker is written now, so it shows as live for 10 minutes, then
# idle); fixtures B and C started and ended (C's stamps bracket its
# capture). Written by this script, not captured.
python3 -I -c '
import json, os, sys, datetime
state, projects, now = sys.argv[1:4]
a = "a9896c55-0b77-4f85-a0e0-9be2948b8aa6"
b = "b0000000-0000-4000-8000-00000000000b"
c = "d484a6af-2106-45c4-9d15-1c2212b76809"
ta = projects + "/-Users-you-proj/" + a + ".jsonl"
tb = projects + "/-Users-you-proj-b/" + b + ".jsonl"
tc = projects + "/-Users-you-proj/" + c + ".jsonl"
recs = [
  {"v": 1, "kind": "start", "ts": "2026-10-12T10:00:00.000Z", "session_id": b, "transcript_path": tb, "cwd": "/Users/you/proj-b", "source": "startup"},
  {"v": 1, "kind": "end", "ts": "2026-10-12T10:05:00.000Z", "session_id": b, "transcript_path": tb, "cwd": "/Users/you/proj-b", "reason": "other"},
  {"v": 1, "kind": "start", "ts": "2026-10-13T02:18:30.000Z", "session_id": a, "transcript_path": ta, "cwd": "/Users/you/proj", "source": "startup"},
  {"v": 1, "kind": "start", "ts": "2026-10-19T05:16:30.000Z", "session_id": c, "transcript_path": tc, "cwd": "/Users/you/proj", "source": "startup"},
  {"v": 1, "kind": "end", "ts": "2026-10-19T05:17:01.000Z", "session_id": c, "transcript_path": tc, "cwd": "/Users/you/proj", "reason": "other"},
]
p = os.path.join(state, "sessions.jsonl")
with open(os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
  for r in recs:
    f.write(json.dumps(r, separators=(",", ":")) + "\n")
live = os.path.join(state, "live")
os.makedirs(live, mode=0o700, exist_ok=True)
with open(os.open(os.path.join(live, a), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
  json.dump({"logged": now, "transcript_path": ta, "cwd": "/Users/you/proj"}, f)
' "$home/.local/state/watchdeck" "$home/.claude/projects" "$now"
# Transcript mtimes as of each session's last row, not the copy time.
find "$home/.claude/projects/-Users-you-proj" -type f -exec touch -t 202610130219 {} +
find "$home/.claude/projects/-Users-you-proj-b" -type f -exec touch -t 202610121005 {} +
touch -t 202610190517 "$home/.claude/projects/-Users-you-proj/$sid_c.jsonl"

# Always: session L, the v2 overrides and the native rule (Plan 08), plus
# --many and --live when asked for.
python3 -I "$repo/scripts/fixture-sessions.py" --home "$home" --many "$many" --live "$live" \
  --seed "$seed" --now "$now" \
  --fixture-a "$repo/internal/transcript/testdata/e2e-canary/projects/-Users-you-proj/a9896c55-0b77-4f85-a0e0-9be2948b8aa6.jsonl" \
  --activity "$activity" \
  --overrides "$home/.config/watchdeck/overrides.yaml" \
  --claude-settings "$home/.claude/settings.json"

summary="# sessions: A live, B ended, C ended (deny capture), L ended (Plan 08), +$many ended, +$live live"
if [ "$installed" = 1 ] || [ -n "$src_bin" ]; then
  # The hooks name the binary's path, so it always lives in OUTDIR/bin: a
  # $WATCHDECK_BIN under the real home would put a login path into the
  # fixture's settings.json. $WATCHDECK_BIN only says where to copy from.
  mkdir -p "$out/bin"
  bin="$out/bin/watchdeck"
  if [ -n "$src_bin" ]; then
    cp "$src_bin" "$bin"
    chmod 755 "$bin"
  else
    # Built with the caller's environment, so Go's caches stay out of the home.
    (cd "$repo" && go build -o "$bin" ./cmd/watchdeck) >&2
  fi
  # Only these commands see the fixture environment; stdout stays the
  # export lines.
  (
    cd "$home/proj"
    export HOME="$home" XDG_CONFIG_HOME="$home/.config" XDG_CACHE_HOME="$home/.cache" \
      XDG_STATE_HOME="$home/.local/state" CLAUDE_CONFIG_DIR="$home/.claude" WATCHDECK_ACTIVITY="$activity"
    # one intent, every route (the Rules page's "part of" chip)
    "$bin" rules add --block --path '~/.kube/config' --everywhere --yes
    if [ "$installed" = 1 ]; then
      # rules first: with the recommended Read rules in place, the install
      # leaves Read unhooked, as a person's setup does
      "$bin" rules recommended --install --yes
      "$bin" enforce install
    fi
  ) >&2
  summary="$summary; one intent (~/.kube/config, every route)"
  if [ "$installed" = 1 ]; then summary="$summary; installed: hooks and recommended rules ($bin)"; fi
else
  summary="$summary; no intent (set WATCHDECK_BIN or pass --installed)"
fi

cat <<EOF
export HOME='$home'
export XDG_CONFIG_HOME='$home/.config'
export XDG_CACHE_HOME='$home/.cache'
export XDG_STATE_HOME='$home/.local/state'
export CLAUDE_CONFIG_DIR='$home/.claude'
export WATCHDECK_ACTIVITY='$activity'
cd '$home/proj'
$summary
EOF
