#!/bin/bash
# Proves end to end that a rule `watchdeck rules add` writes is a native
# Claude Code deny rule: Claude Code itself refuses the call, and the
# transcript row says so (docs/DESIGN.md section 9, "Not verified yet").
#
# Steps:
#   1. Build watchdeck from this tree into a mktemp dir.
#   2. Run `watchdeck rules add --block --command 'echo native-deny-marker'
#      --yes` with HOME and CLAUDE_CONFIG_DIR pointing into the temp dir, so
#      the rule lands in <tmp>/claude/settings.json and the ledger and
#      overrides in the temp XDG dirs. CLAUDE_CONFIG_DIR is set for this step
#      ONLY: it relocates settings and transcripts but not credentials
#      (CLAUDE.md, "Verified on this Mac"), so `claude -p` must run without it.
#   3. Run one throwaway `claude -p --settings <tmp>/claude/settings.json
#      --permission-mode auto` from inside the temp dir, with the real HOME
#      (credentials), no CLAUDE_CONFIG_DIR and the XDG variables unset (so
#      Claude Code reads its own config as usual), asking it to run exactly
#      `echo native-deny-marker`. The owner authorised throwaway `claude -p`
#      runs on 2026-10-19.
#   4. Open that one session file, ~/.claude/projects/<escaped cwd>/<session
#      id>.jsonl, read-only, and assert exactly one tool_result row carries
#      permissionDecision {decision: reject, source: config, reasonType:
#      subcommandResults} and toolDenialKind permission-rule (the shapes in
#      internal/transcript/testdata/e2e-deny). Prints PASS or FAIL.
#
# The transcript is never copied anywhere; on FAIL only the decision fields
# of each tool_result row are printed. WATCHDECK_ACTIVITY and every XDG dir
# point into the temp dir for the whole script. The temp dir is deleted on
# exit unless --keep is given. The session file itself stays where Claude
# Code wrote it, like any other session.
#
#   scripts/prove-native-deny.sh           # build, add, run, assert
#   scripts/prove-native-deny.sh --keep    # keep the temp dir for a look
set -euo pipefail
export PATH="/opt/homebrew/bin:/usr/local/go/bin:$PATH"

keep=0
for a in "$@"; do
	case "$a" in
	--keep) keep=1 ;;
	*) echo "usage: $0 [--keep]" >&2; exit 3 ;;
	esac
done

repo="$(cd "$(dirname "$0")/.." && pwd)"
marker="native-deny-marker"
for tool in go claude python3; do
	command -v "$tool" >/dev/null 2>&1 || { echo "FAIL: $tool not on PATH" >&2; exit 2; }
done

tmp="$(mktemp -d "${TMPDIR:-/tmp}/watchdeck-prove-XXXXXX")"
cleaned=0
cleanup() {
	[ "$cleaned" = 1 ] && return 0
	cleaned=1
	if [ "$keep" = 1 ]; then
		echo "kept: $tmp"
	else
		rm -rf "$tmp"
	fi
}
# EXIT cleans up on every normal or error exit; an interrupt cleans up and
# exits 130 instead of running on after the trap.
trap cleanup EXIT
trap 'cleanup; exit 130' INT TERM

mkdir -p "$tmp/bin" "$tmp/home" "$tmp/claude" "$tmp/work"
unset CLAUDE_CONFIG_DIR

# 1. build from this tree, before the XDG dirs move (go keeps its caches
# under the real home).
(cd "$repo" && go build -o "$tmp/bin/watchdeck" ./cmd/watchdeck)
export WATCHDECK_ACTIVITY="$tmp/activity.jsonl" \
	XDG_CONFIG_HOME="$tmp/xdg/config" XDG_STATE_HOME="$tmp/xdg/state" \
	XDG_CACHE_HOME="$tmp/xdg/cache" XDG_DATA_HOME="$tmp/xdg/data"

# 2. the native rule, written into the temp settings file only.
env HOME="$tmp/home" CLAUDE_CONFIG_DIR="$tmp/claude" \
	"$tmp/bin/watchdeck" rules add --block --command "echo $marker" --yes
settings="$tmp/claude/settings.json"
[ -f "$settings" ] || { echo "FAIL: rules add wrote no $settings" >&2; exit 1; }
python3 -I - "$settings" "$marker" <<'PY'
import json, sys
deny = json.load(open(sys.argv[1])).get("permissions", {}).get("deny", [])
want = "Bash(echo %s *)" % sys.argv[2]
if want not in deny:
    sys.exit("FAIL: %s not in permissions.deny: %r" % (want, deny))
print("rule in place: " + want)
PY

# 3. one throwaway session from inside the temp work dir.
cd "$tmp/work"
cwd_phys="$(pwd -P)"
cwd_logical="$(pwd -L)"
result="$tmp/claude-result.json"
set +e
env -u XDG_CONFIG_HOME -u XDG_CACHE_HOME -u XDG_STATE_HOME -u XDG_DATA_HOME \
	claude -p --settings "$settings" --permission-mode auto --output-format json \
	-- "Run exactly this shell command and nothing else: echo $marker" >"$result" 2>"$tmp/claude-stderr.txt"
rc=$?
set -e
echo "claude -p exit $rc"
session="$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1])).get("session_id",""))' "$result" 2>/dev/null || true)"
if [ -z "$session" ]; then
	echo "FAIL: no session_id in the claude -p result; last 20 lines of its stderr:" >&2
	tail -n 20 "$tmp/claude-stderr.txt" >&2 || true
	exit 1
fi
echo "session $session"

# 4. find the session file: every character that is not an ASCII letter or
# digit becomes '-' (transcript.EscapeProjectDir); the physical spelling of
# the temp dir first (/private/var/... on macOS), then the logical one.
escape() { printf '%s' "$1" | LC_ALL=C sed 's/[^A-Za-z0-9]/-/g'; }
file=""
for d in "$cwd_phys" "$cwd_logical"; do
	f="$HOME/.claude/projects/$(escape "$d")/$session.jsonl"
	if [ -f "$f" ]; then file="$f"; break; fi
done
[ -n "$file" ] || { echo "FAIL: no session file for $session under ~/.claude/projects/$(escape "$cwd_phys")" >&2; exit 1; }

python3 -I - "$file" <<'PY'
import json, sys
want_pd = {"decision": "reject", "source": "config", "reasonType": "subcommandResults"}
rows, hits = [], 0
with open(sys.argv[1]) as fh:
    for line in fh:
        try:
            r = json.loads(line)
        except ValueError:
            continue
        content = (r.get("message") or {}).get("content")
        if not isinstance(content, list) or not any(isinstance(b, dict) and b.get("type") == "tool_result" for b in content):
            continue
        pd, kind = r.get("permissionDecision"), r.get("toolDenialKind")
        rows.append((pd, kind))
        if isinstance(pd, dict) and all(pd.get(k) == v for k, v in want_pd.items()) and kind == "permission-rule":
            hits += 1
if hits == 1:
    print("PASS: one tool_result row rejected by a config permission rule (toolDenialKind permission-rule)")
    sys.exit(0)
print("FAIL: %d matching rows, want 1; decision fields of each tool_result row:" % hits)
for pd, kind in rows:
    print("  permissionDecision=%s toolDenialKind=%s" % (json.dumps(pd), json.dumps(kind)))
sys.exit(1)
PY
