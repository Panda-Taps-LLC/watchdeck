#!/bin/bash
# End-to-end check: Claude Code + the watchdeck hook + a canary skill.
# Uses a TEMPORARY settings file (--settings) and temporary XDG dirs; the
# user's ~/.claude/settings.json is never touched. Costs a few API tokens.
#
#   WATCHDECK_E2E=1 scripts/e2e.sh                          # hook via --settings
#   WATCHDECK_E2E=1 WATCHDECK_E2E_MODE=plugin scripts/e2e.sh   # hook via the plugin (--plugin-dir)
set -euo pipefail
if [ "${WATCHDECK_E2E:-}" != "1" ]; then echo "set WATCHDECK_E2E=1 to run (uses the Claude API)"; exit 0; fi
export PATH="/opt/homebrew/bin:$PATH"
repo="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
bin="$work/bin"; mkdir -p "$bin"
( cd "$repo" && go build -o "$bin/watchdeck" ./cmd/watchdeck )
export PATH="$bin:$PATH"

# a throwaway project whose .claude/skills holds the canary
proj="$work/proj"; mkdir -p "$proj/.claude/skills"; cd "$proj"; git init -q .
cp -R "$repo/testdata/skills/canary-basic" "$proj/.claude/skills/"
probe="$proj/.claude/skills/canary-basic/scripts/probe.py"

# isolated watchdeck config/cache/state: auto-allow everything so -p needs no
# prompt. The activity log is on by default, so it must point into $work or the
# developer's real state dir gets written.
export XDG_CONFIG_HOME="$work/xdg-config" XDG_CACHE_HOME="$work/xdg-cache" XDG_STATE_HOME="$work/xdg-state"
export WATCHDECK_ACTIVITY="$work/activity.jsonl"
mkdir -p "$XDG_CONFIG_HOME/watchdeck"
# M6.3: a user rule that denies one marker command, for the deny record
printf 'version: 2\ndefaults:\n  auto_allow: true\nrules:\n  - {id: e2e-deny, tool: Bash, match: {literals: [watchdeck-e2e-deny-marker]}, action: deny}\n' > "$XDG_CONFIG_HOME/watchdeck/overrides.yaml"

settings="$work/settings.json"
mode="${WATCHDECK_E2E_MODE:-settings}"   # settings | plugin
extra=()
if [ "$mode" = "plugin" ]; then
  # the plugin's hooks.json registers the hook; its bin/hook.sh finds watchdeck on PATH
  cat > "$settings" <<JSON
{ "permissions": { "allow": ["Bash(watchdeck run *)", "Bash(python3 *)"] } }
JSON
  extra=(--plugin-dir "$repo/plugin")
else
  cat > "$settings" <<JSON
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "Bash", "hooks": [ { "type": "command", "command": "$bin/watchdeck", "args": ["hook"], "timeout": 5 } ] }
    ]
  },
  "permissions": { "allow": ["Bash(watchdeck run *)", "Bash(python3 *)"] }
}
JSON
fi
echo "== mode: $mode"

prompt="Run exactly this command with the Bash tool and then reply with its output verbatim, nothing else: python3 $probe net"
echo "== running claude -p (temp settings, temp project) ..."
claude -p "$prompt" --settings "$settings" ${extra[@]+"${extra[@]}"} --output-format stream-json --verbose --max-turns 3 --allowedTools Bash > "$work/stream.jsonl" 2> "$work/stderr.txt" || true
# M6.3: a command the user rule denies; the hook answers deny (a gate) and
# logs a decision record with decision "deny" and the rule hit.
echo "== running claude -p for the deny check ..."
claude -p "Run exactly this command with the Bash tool, once, and report what happened: echo watchdeck-e2e-deny-marker" --settings "$settings" ${extra[@]+"${extra[@]}"} --output-format stream-json --verbose --max-turns 2 --allowedTools Bash > "$work/stream-deny.jsonl" 2>> "$work/stderr.txt" || true

# The stream shows the model's ORIGINAL tool call, not the hook's rewrite, so
# the evidence is (a) the activity log's decision and run records and (b) the
# sandboxed result.
echo "== activity log:"
python3 -I - "$WATCHDECK_ACTIVITY" "$work/stream.jsonl" <<'PY'
import json, sys, os
records=[]
if os.path.exists(sys.argv[1]):
    for line in open(sys.argv[1]):
        try: records.append(json.loads(line))
        except Exception: pass
decisions=[r for r in records if r.get("kind")=="decision"]
runs=[r for r in records if r.get("kind")=="run"]
for d in decisions: print("   decision", d.get("decision"), "->", str(d.get("rewritten",""))[:160])
for r in runs: print("   run", r.get("outcome"), "exit", r.get("exit"), "joined_by", r.get("joined_by"), "tool_use_id", r.get("tool_use_id"))
results=[]
for line in open(sys.argv[2]):
    line=line.strip()
    if not line: continue
    try: ev=json.loads(line)
    except Exception: continue
    msg=ev.get("message") or {}
    for block in (msg.get("content") or []):
        if isinstance(block, dict) and block.get("type")=="tool_result":
            c=block.get("content")
            if isinstance(c, list): c=" ".join(x.get("text","") for x in c if isinstance(x, dict))
            results.append(str(c))
print("== tool results:")
for r in results: print("  ", r.replace("\n"," | ")[:300])
canary=[d for d in decisions if d.get("decision")=="allow" and str(d.get("rewritten","")).startswith("watchdeck run --skill canary-basic")]
rewritten = len(canary) > 0
denied = any("net: DENIED" in r for r in results)
# exactly one run, outcome ok (the probe reports and exits 0), carrying the
# decision's ids from write-time correlation
joined = False
if canary:
    d = canary[-1]
    mine = [r for r in runs if r.get("tool_use_id") and r.get("tool_use_id")==d.get("tool_use_id")]
    joined = (len(runs)==1 and len(mine)==1 and mine[0].get("outcome")=="ok" and mine[0].get("exit")==0
              and mine[0].get("session_id")==d.get("session_id") and mine[0].get("command")==d.get("command"))
# M6.3: the gate's deny record (a user rule; no rewrite, the rule hit named)
gate = [d for d in decisions if d.get("decision")=="deny" and d.get("argv0")=="echo" and not d.get("command")
        and any(h.get("pack")=="user" and h.get("id")=="e2e-deny" for h in (d.get("rules") or []))
        and d.get("enforcement")=="gate" and not d.get("rewritten")]
for d in gate: print("   deny record", d.get("tool_name"), d.get("rules"), str(d.get("reason",""))[:120])
gate_denied = len(gate) > 0
ok = rewritten and denied and joined and gate_denied
print("== E2E", "PASS" if ok else "FAIL", f"(rewritten={rewritten} denied={denied} run_joined={joined} gate_deny_record={gate_denied})")
sys.exit(0 if ok else 1)
PY
