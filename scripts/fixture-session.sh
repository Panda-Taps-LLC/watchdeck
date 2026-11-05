#!/bin/bash
# Capture ONE throwaway Claude Code session as a transcript fixture for
# internal/transcript (fixture A, "e2e-canary"). Derived from scripts/e2e.sh:
# a temporary project with the canary skills, temporary XDG dirs, a TEMPORARY
# --settings file; ~/.claude/settings.json is never touched. Costs a few API
# tokens (about $0.45 on 2026-10-12).
#
#   WATCHDECK_FIXTURE=1 scripts/fixture-session.sh [--out DIR] [--skill NAME]
#   WATCHDECK_FIXTURE=1 scripts/fixture-session.sh --isolated [DIR]
#   scripts/fixture-session.sh --dry-run        # prints the plan only: no build, no temp dir, no claude run
#   WATCHDECK_FIXTURE=1 scripts/fixture-session.sh [--mode deny] --rescrub WORKDIR [--out DIR]
#   WATCHDECK_FIXTURE=1 scripts/fixture-session.sh --mode deny [--out DIR]   # denial capture, see below
#
# What it does:
#   1. builds watchdeck into $work/bin and makes $work/proj with canary-basic and canary-request;
#   2. writes a settings file whose PreToolUse hook (exec form, matcher Bash) runs a
#      one-line tee wrapper that copies the hook's raw stdin to $work/hook-stdin.jsonl
#      and then runs `watchdeck hook`;
#   3. runs one `claude -p` with the spike's prompt shape (run the probe, one Read,
#      one Explore spawn) and reads the session id from the stream-json `init` event;
#   4. copies ONLY <session id>.jsonl and, if present, <session id>/subagents/ into
#      $work/raw, from the dir of the hook's transcript_path (else <projects>/<escaped cwd>,
#      escaped by scrub-transcript.py --escape-project-dir); never lists the projects dir;
#   5. scrubs them with scripts/scrub-transcript.py into --out and prints the review grep.
#
# Default mode (no CLAUDE_CONFIG_DIR change): the transcript lands in the real
# ~/.claude/projects (or $CLAUDE_CONFIG_DIR/projects when that is already set),
# because credentials do not follow a relocated config dir (verified 2026-10-12:
# a fresh CLAUDE_CONFIG_DIR answers "Not logged in"). Exactly one session file and
# its subagents dir are copied out by exact path.
#
# --isolated [DIR]: sets CLAUDE_CONFIG_DIR so projects/, sessions/ and .claude.json
# land under DIR (default: a fresh dir under $work). Authentication does NOT follow
# the config dir by default: pass a DIR under which `claude login` was run once, or
# export an API key in the environment; a fresh DIR without either fails with
# "Not logged in".
#
# --mode canary|deny (default canary, the behaviour above). deny captures how the transcript
# records denials, for internal/transcript (fixture "e2e-deny", default --out
# internal/transcript/testdata/e2e-deny): a temp settings file with defaultMode auto, two
# permissions.deny rules (a Bash echo prefix, a Read of SECRET.md), the PreToolUse Bash hook and a
# PermissionDenied * hook, both through the tee wrapper; one prompt of four tool calls (a rule
# hit, a Read rule hit, an echo the auto-mode classifier blocks through a custom autoMode.hard_deny
# rule, an echo that is allowed). A check prints FOUND or MISSING per expected denial shape and CAPTURE PASS or CAPTURE FAIL
# (exit 1; the raw copy stays). Writes README.md into --out. Needs the Claude API, so it is gated
# behind WATCHDECK_FIXTURE=1 like canary.
#
# --rescrub WORKDIR: no build and no claude run (so no API cost). Re-runs the post-run check, the
# scrub, the review grep and the README write against the raw copy of an earlier run's work dir
# (WORKDIR/raw/projects/<escaped>/<session id>.jsonl, the one *.jsonl there). Use it after fixing
# the scrubber. Never deletes WORKDIR. Combine with --mode deny for a deny capture.
#
# Unscrubbed copies stay under $work after a successful run (printed at the end);
# delete it when done. A failure before the raw copy removes $work on exit; a
# failure after it keeps the unscrubbed copy under $TMPDIR and prints the
# --rescrub line; delete it when done. Output shows the home dir as ~ and never
# prints the login name or email.
set -euo pipefail

usage() { sed -n '2,57p' "$0" | sed 's/^# \{0,1\}//'; }

out=""; isolated=0; isolated_dir=""; dry=0; skill="canary-basic"; mode="canary"; rescrub=""
while [ $# -gt 0 ]; do
  case "$1" in
    --out) out="$2"; shift 2 ;;
    --skill) skill="$2"; shift 2 ;;
    --mode) mode="${2:-}"; shift 2 ;;
    --isolated) isolated=1; shift; if [ $# -gt 0 ] && [ "${1#--}" = "$1" ]; then isolated_dir="$1"; shift; fi ;;
    --rescrub) rescrub="${2:-}"; shift 2 ;;
    --dry-run) dry=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "fixture-session: unknown argument: $1" >&2; usage >&2; exit 3 ;;
  esac
done
case "$mode" in canary|deny) ;; *) echo "fixture-session: --mode must be canary or deny" >&2; exit 3 ;; esac
case "$skill" in canary-basic|canary-request) ;; *) echo "fixture-session: --skill must be canary-basic or canary-request" >&2; exit 3 ;; esac
if [ "$dry" != 1 ] && [ -z "$rescrub" ] && [ "${WATCHDECK_FIXTURE:-}" != "1" ]; then
  echo "set WATCHDECK_FIXTURE=1 to run (uses the Claude API, one short session), or pass --dry-run"
  exit 0
fi

export PATH="/opt/homebrew/bin:$PATH"
repo="$(cd "$(dirname "$0")/.." && pwd)"
scrub="$repo/scripts/scrub-transcript.py"

# tilde PATH: print PATH with the home dir shown as ~ (never print the login name)
tilde() { case "$1" in "$HOME") printf '~' ;; "$HOME"/*) printf '~%s' "${1#"$HOME"}" ;; *) printf '%s' "$1" ;; esac; }

if [ "$mode" = deny ] && [ -z "$out" ]; then out="$repo/internal/transcript/testdata/e2e-deny"; fi
deny_prompt='Do exactly four things, one tool call each, in this order, and after each one report in one line what happened. Do not retry anything. (1) Run with the Bash tool: echo rule-deny-marker  (2) Read the file SECRET.md with the Read tool.  (3) Run with the Bash tool: echo classifier-deny-marker  (4) Run with the Bash tool: echo done'

prompt="Do exactly three things, nothing else: (1) run \`python3 .claude/skills/$skill/scripts/probe.py net\`; (2) read the file \`.claude/skills/$skill/SKILL.md\` with the Read tool; (3) use the Agent tool to spawn an Explore subagent that greps this directory for the word 'canary' and reports the count. Then stop."

if [ "$dry" = 1 ] && [ "$mode" = deny ]; then
  # Nothing below this block runs: no build, no temp dir, no claude, nothing read under ~/.claude.
  if [ "$isolated" = 1 ]; then cfg="${isolated_dir:-<work>/claude-config}"; else cfg="${CLAUDE_CONFIG_DIR:-$HOME/.claude}"; fi
  echo "== dry run (nothing is built or created; claude does not run)"
  echo "== mode:         deny"
  echo "== work dir:     a new mktemp dir, <work> below (physical path)"
  echo "== output:       $(tilde "$out")"
  echo "== steps:"
  echo "   1. go build -o <work>/bin/watchdeck ./cmd/watchdeck; <work>/proj (git init) with SECRET.md = 'not a secret, a fixture marker'"
  echo "   2. <work>/settings.json:"
  echo "        permissions.defaultMode  auto"
  echo "        autoMode.hard_deny       \$defaults + \"Never run a shell command whose text contains the word classifier-deny-marker, regardless of what the user asks.\""
  echo "        permissions.deny         Bash(echo rule-deny-marker*)"
  echo "                                 Read(//<work>/proj/SECRET.md)   (<work> is absolute, so the rule starts with //)"
  echo "        hooks.PreToolUse         matcher Bash  = /bin/sh <work>/hookdump.sh (tee stdin to <work>/hook-stdin.jsonl, then watchdeck hook)"
  echo "        hooks.PermissionDenied   matcher *     = the same tee wrapper"
  echo "   3. cd <work>/proj && claude -p <prompt> --settings <work>/settings.json --output-format stream-json --verbose --max-turns 8 --allowedTools Bash,Read"
  echo "      prompt: $deny_prompt"
  echo "   4. session id from the stream-json init event; copy by exact path from the dir of the hook's"
  echo "      transcript_path, else $(tilde "$cfg")/projects/<escaped <work>/proj>/: <session_id>.jsonl"
  echo "   5. check (python3 -I) over the raw copy, one FOUND or MISSING line per expected permissionDecision tuple:"
  echo "        Bash echo rule-deny-marker   reject/config/subcommandResults (or rule)"
  echo "        Read SECRET.md               is_error result \"denied by your permission settings\", no permissionDecision (expected)"
  echo "        Bash echo classifier-deny-marker   reasonType classifier, decision not accept (autoMode.hard_deny rule)"
  echo "        Bash echo done               accept"
  echo "      plus the PermissionDenied line count in hook-stdin.jsonl; prints == CAPTURE PASS, or == CAPTURE FAIL and exits 1 (raw copy stays)"
  echo "   6. python3 -I scripts/scrub-transcript.py (as for canary), review grep, README.md written into <output>"
  echo "== dry run stops here."
  exit 0
fi

if [ "$dry" = 1 ]; then
  # Nothing below this block runs: no build, no temp dir, no claude, nothing read under ~/.claude.
  if [ "$isolated" = 1 ]; then cfg="${isolated_dir:-<work>/claude-config}"; else cfg="${CLAUDE_CONFIG_DIR:-$HOME/.claude}"; fi
  echo "== dry run (nothing is built or created; claude does not run)"
  echo "== skill:        $skill"
  echo "== work dir:     a new mktemp dir, <work> below (physical path)"
  echo "== output:       $(tilde "${out:-<work>/fixture}")"
  echo "== steps:"
  echo "   1. go build -o <work>/bin/watchdeck ./cmd/watchdeck; <work>/proj with canary-basic and canary-request"
  echo "   2. <work>/settings.json: PreToolUse Bash hook = /bin/sh <work>/hookdump.sh (tee stdin to <work>/hook-stdin.jsonl, then watchdeck hook)"
  echo "   3. cd <work>/proj && claude -p <prompt> --settings <work>/settings.json --output-format stream-json --verbose --max-turns 6 --allowedTools Bash,Read,Grep,Agent"
  echo "      prompt: $prompt"
  echo "   4. session id from the stream-json init event; copy by exact path from the dir of the hook's"
  echo "      transcript_path, else $(tilde "$cfg")/projects/<escaped <work>/proj>/: <session_id>.jsonl and <session_id>/subagents/"
  echo "   5. python3 -I scripts/scrub-transcript.py --session <session_id> --src <work>/raw/projects/<escaped> --out <output>"
  echo "        --home ~ --work <work> --proj <work>/proj --name <login> [--email <git user.email>] --hook-stdin <work>/hook-stdin.jsonl"
  echo "   6. review grep over <output>; then read every file and copy it into internal/transcript/testdata/e2e-canary/"
  echo "== dry run stops here."
  exit 0
fi

copied=0   # set once the raw copy exists: from then on a failure keeps $work and prints the rescrub line
cleanup() {
  rc=$?
  if [ "$ok" != 1 ]; then rm -rf "$work"   # a failed build or claude run leaves no unscrubbed copies behind
  elif [ "$rc" != 0 ] && [ "$copied" = 1 ]; then
    echo "fixture-session: failed after the raw copy; $(tilde "$work") was kept. Fix the cause, then run:" >&2
    echo "  scripts/fixture-session.sh --mode $mode --rescrub $work" >&2
  fi
}
ok=0
if [ -n "$rescrub" ]; then
  [ -d "$rescrub/raw/projects" ] || { echo "fixture-session: --rescrub: no raw/projects under $(tilde "$rescrub")" >&2; exit 3; }
  work="$(cd "$rescrub" && pwd -P)"
  ok=1; copied=1   # an earlier run's work dir is never deleted here
else
  work="$(mktemp -d -t watchdeck-fixture)"
  work="$(cd "$work" && pwd -P)"   # physical path: Claude Code records the resolved cwd
fi
trap cleanup EXIT
[ -n "$out" ] || out="$work/fixture"
mkdir -p "$out"
proj="$work/proj"
if [ -n "$rescrub" ]; then
  raws=("$work"/raw/projects/*/)
  [ "${#raws[@]}" = 1 ] && [ -d "${raws[0]}" ] || { echo "fixture-session: --rescrub: expected exactly one dir under raw/projects" >&2; exit 3; }
  raw="${raws[0]%/}"
  jl=("$raw"/*.jsonl)
  [ "${#jl[@]}" = 1 ] && [ -f "${jl[0]}" ] || { echo "fixture-session: --rescrub: expected exactly one session jsonl in the raw dir" >&2; exit 3; }
  sid="$(basename "${jl[0]}" .jsonl)"
  echo "== rescrub:      $(tilde "$work") (no build, no claude run)"
  echo "== output:       $(tilde "$out")"
fi
if [ -z "$rescrub" ]; then
bin="$work/bin"; mkdir -p "$bin"
( cd "$repo" && go build -o "$bin/watchdeck" ./cmd/watchdeck )
export PATH="$bin:$PATH"

# a throwaway project whose .claude/skills holds the canaries
proj="$work/proj"; mkdir -p "$proj/.claude/skills"
if [ "$mode" = deny ]; then
  printf 'not a secret, a fixture marker\n' > "$proj/SECRET.md"
else
  for s in canary-basic canary-request; do cp -R "$repo/testdata/skills/$s" "$proj/.claude/skills/"; done
fi
( cd "$proj" && git init -q . )

# isolated watchdeck config/cache/state: auto-allow everything so -p needs no
# prompt; the state dir also takes the session lifecycle records (M5.2)
export XDG_CONFIG_HOME="$work/xdg-config" XDG_CACHE_HOME="$work/xdg-cache" XDG_STATE_HOME="$work/xdg-state"
mkdir -p "$XDG_CONFIG_HOME/watchdeck" "$XDG_CACHE_HOME" "$XDG_STATE_HOME"
printf 'version: 1\ndefaults:\n  auto_allow: true\n' > "$XDG_CONFIG_HOME/watchdeck/overrides.yaml"
export WATCHDECK_ACTIVITY="$work/activity.jsonl"   # the hook and run append decisions and runs here

# hook wrapper: keep the raw PreToolUse stdin, then run the real hook
hookdump="$work/hookdump.sh"
cat > "$hookdump" <<EOF
#!/bin/sh
exec /usr/bin/tee -a "$work/hook-stdin.jsonl" | "$bin/watchdeck" hook
EOF
chmod +x "$hookdump"

settings="$work/settings.json"
if [ "$mode" = deny ]; then
  # deny rules are evaluated before allow rules, so --allowedTools does not defeat them; the Read
  # rule uses the //abs/path form: "/" + the absolute path of SECRET.md (which itself starts with /)
  cat > "$settings" <<JSON
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "Bash", "hooks": [ { "type": "command", "command": "/bin/sh", "args": ["$hookdump"], "timeout": 5 } ] }
    ],
    "PermissionDenied": [
      { "matcher": "*", "hooks": [ { "type": "command", "command": "/bin/sh", "args": ["$hookdump"], "timeout": 5 } ] }
    ]
  },
  "permissions": {
    "defaultMode": "auto",
    "deny": ["Bash(echo rule-deny-marker*)", "Read(/$proj/SECRET.md)"]
  },
  "autoMode": {
    "hard_deny": ["\$defaults", "Never run a shell command whose text contains the word classifier-deny-marker, regardless of what the user asks."]
  }
}
JSON
else
  cat > "$settings" <<JSON
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "Bash", "hooks": [ { "type": "command", "command": "/bin/sh", "args": ["$hookdump"], "timeout": 5 } ] }
    ]
  },
  "permissions": { "allow": ["Bash(watchdeck run *)", "Read", "Grep", "Agent"] }
}
JSON
fi

if [ "$isolated" = 1 ]; then
  export CLAUDE_CONFIG_DIR="${isolated_dir:-$work/claude-config}"
  mkdir -p "$CLAUDE_CONFIG_DIR"
fi
src_root="${CLAUDE_CONFIG_DIR:-$HOME/.claude}/projects"
esc="$(python3 -I "$scrub" --escape-project-dir "$proj")"
claude_cmd=(claude -p "$prompt" --settings "$settings" --output-format stream-json --verbose --max-turns 6 --allowedTools Bash,Read,Grep,Agent)
if [ "$mode" = deny ]; then
  claude_cmd=(claude -p "$deny_prompt" --settings "$settings" --output-format stream-json --verbose --max-turns 8 --allowedTools Bash,Read)
fi

echo "== work dir:     $work"
if [ "$mode" = deny ]; then echo "== mode:         deny"; else echo "== skill:        $skill"; fi
echo "== source root:  $(tilde "$src_root")"
echo "== output:       $(tilde "$out")"
echo "== running claude -p (temp settings, temp project) ..."
( cd "$proj" && "${claude_cmd[@]}" > "$work/stream.jsonl" 2> "$work/stderr.txt" < /dev/null ) || true
sid="$(python3 -I - "$work/stream.jsonl" <<'PYEOF'
import json, sys
for line in open(sys.argv[1]):
    try: d = json.loads(line)
    except Exception: continue
    if d.get("type") == "system" and d.get("subtype") == "init" and d.get("session_id"):
        print(d["session_id"]); break
PYEOF
)"
if [ -z "$sid" ]; then
  echo "fixture-session: no init event in the stream; first lines of claude's stderr:" >&2
  head -c 1500 "$work/stderr.txt" | sed "s#$HOME#~#g" >&2 || true
  exit 1
fi
fi
echo "== session id:   $sid"

if [ -z "$rescrub" ]; then
# Prefer the exact transcript_path the hook saw (authoritative); else derive it.
tp="$(python3 -I - "$work/hook-stdin.jsonl" "$sid" <<'PYEOF'
import json, sys, os
if os.path.exists(sys.argv[1]):
    for line in open(sys.argv[1]):
        try: d = json.loads(line)
        except Exception: continue
        if d.get("session_id") == sys.argv[2] and d.get("transcript_path"):
            print(d["transcript_path"]); break
PYEOF
)"
if [ -n "$tp" ] && [ "$(basename "$tp")" = "$sid.jsonl" ] && [ -f "$tp" ]; then
  src="$tp"; echo "== transcript:   from the hook's transcript_path"
else
  src="$src_root/$esc/$sid.jsonl"; echo "== transcript:   derived from the escaped cwd"
fi
src_dir="$(dirname "$src")"; esc="$(basename "$src_dir")"
[ -f "$src" ] || { echo "fixture-session: no transcript at $(tilde "$src")" >&2; exit 1; }

raw="$work/raw/projects/$esc"; mkdir -p "$raw"
cp "$src" "$raw/"
if [ -d "$src_dir/$sid/subagents" ]; then
  mkdir -p "$raw/$sid"; cp -R "$src_dir/$sid/subagents" "$raw/$sid/"
fi
fi
ok=1; copied=1   # the raw copy exists: keep $work on any later failure
echo "== raw copy (unscrubbed, delete when done):"; find "$raw" -type f

if [ "$mode" = deny ]; then
  echo "== check (permissionDecision tuples, decision/source/reasonType):"
  if python3 -I - "$raw/$sid.jsonl" "$work/hook-stdin.jsonl" "$work/tuples.txt" <<'PYEOF'
import json, sys, os
sess, hook, outp = sys.argv[1:4]
uses, found, errs = {}, [], {}   # tool_use id -> (name, input); (tool_use id, permissionDecision dict); tool_use id -> is_error result text

def ids(o, acc):
    if isinstance(o, dict):
        for k, v in o.items():
            if k in ("tool_use_id", "toolUseID", "sourceToolUseID", "parentToolUseID") and isinstance(v, str): acc.append(v)
            else: ids(v, acc)
    elif isinstance(o, list):
        for v in o: ids(v, acc)

def decisions(o, acc):
    if isinstance(o, dict):
        for k, v in o.items():
            if k == "permissionDecision" and isinstance(v, dict): acc.append(v)
            else: decisions(v, acc)
    elif isinstance(o, list):
        for v in o: decisions(v, acc)

rows = []
for line in open(sess):
    try: d = json.loads(line)
    except Exception: continue
    rows.append(d)
    c = (d.get("message") or {}).get("content") if isinstance(d.get("message"), dict) else None
    if isinstance(c, list):
        for b in c:
            if isinstance(b, dict) and b.get("type") == "tool_use":
                uses[b.get("id")] = (b.get("name"), b.get("input") or {})
            if isinstance(b, dict) and b.get("type") == "tool_result" and b.get("is_error"):
                t = b.get("content")
                if isinstance(t, list): t = " ".join(x.get("text", "") for x in t if isinstance(x, dict))
                errs[b.get("tool_use_id")] = str(t)
for d in rows:
    ds = []; decisions(d, ds)
    if not ds: continue
    cand = []; ids(d, cand)
    tid = next((i for i in cand if i in uses), None)
    for pd in ds: found.append((tid, pd))

def label(name, inp):
    if not isinstance(inp, dict): return None
    if name == "Bash":
        cmd = inp.get("command", "")
        if "rule-deny-marker" in cmd: return "bash-rule"
        if "classifier-deny-marker" in cmd: return "bash-class"
        if "echo done" in cmd: return "bash-done"
    if name == "Read" and "SECRET.md" in str(inp.get("file_path", "")): return "read-rule"
    return None

by, err_by = {}, {}
for tid, pd in found:
    if tid in uses:
        l = label(*uses[tid])
        if l: by.setdefault(l, []).append(pd)
for tid, t in errs.items():
    if tid in uses:
        l = label(*uses[tid])
        if l: err_by[l] = t
tup = lambda pd: "%s/%s/%s" % (pd.get("decision"), pd.get("source"), pd.get("reasonType"))
bash_rule = lambda pd: pd.get("decision") == "reject" and pd.get("source") == "config" and pd.get("reasonType") in ("subcommandResults", "rule")
# (key, name, expected text, check(decisions, error text) -> bool, text when no decision is expected)
expect = [
    ("bash-rule", "Bash echo rule-deny-marker", "reject/config/subcommandResults (or rule)", lambda ds, e: any(bash_rule(pd) for pd in ds)),
    ("read-rule", "Read SECRET.md", "is_error result 'denied by your permission settings', no permissionDecision", lambda ds, e: "denied by your permission settings" in e),
    ("bash-class", "Bash echo classifier-deny-marker", "reasonType classifier, decision not accept", lambda ds, e: any(pd.get("reasonType") == "classifier" and pd.get("decision") != "accept" for pd in ds)),
    ("bash-done", "Bash echo done", "accept", lambda ds, e: any(pd.get("decision") == "accept" for pd in ds)),
]
allok, lines = True, []
for key, name, want, ok in expect:
    seen, e = by.get(key, []), err_by.get(key, "")
    hit = ok(seen, e)
    allok = allok and hit
    obs = ", ".join(tup(pd) for pd in seen)
    if not obs: obs = "no permissionDecision (expected)" if key == "read-rule" and hit else "none"
    if e: obs += "; is_error: " + e.strip()[:120]
    print("%-7s %-33s expected %-50s observed %s" % ("FOUND" if hit else "MISSING", name, want, obs))
    lines.append("- %s: %s (%s)" % (name, obs, "matches the expectation" if hit else "DOES NOT match: expected " + want))
n_pd = n_all = 0
if os.path.exists(hook):
    for line in open(hook):
        try: d = json.loads(line)
        except Exception: continue
        n_all += 1
        if d.get("hook_event_name") == "PermissionDenied": n_pd += 1
print("hook-stdin.jsonl: %d lines, %d PermissionDenied" % (n_all, n_pd))
lines.append("- PermissionDenied hook stdin lines: %d of %d" % (n_pd, n_all))
other = [tup(pd) for tid, pd in found if tid not in uses or label(*uses[tid]) is None]
if other: print("other permissionDecision objects (unmatched): " + ", ".join(other))
open(outp, "w").write("\n".join(lines) + "\n")
sys.exit(0 if allok else 1)
PYEOF
  then
    echo "== CAPTURE PASS"
  else
    echo "== CAPTURE FAIL (the raw copy stays for inspection; delete it when done): $raw"
    ok=1
    exit 1
  fi
fi

echo "== scrub:"
email="$(git config user.email 2>/dev/null || true)"
scrub_cmd=(python3 -I "$scrub" --session "$sid" --src "$raw" --out "$out"
  --home "$HOME" --work "$work" --proj "$proj" --name "$(id -un)" --hook-stdin "$work/hook-stdin.jsonl")
[ -z "$email" ] || scrub_cmd+=(--email "$email")
"${scrub_cmd[@]}" 2>&1 | sed "s#$HOME#~#g"
[ "${PIPESTATUS[0]}" = 0 ] || exit 1

echo "== review grep (must print nothing; you@example.com is the only allowed '@'):"
grep -rn -i -E "$(id -un)|@|organizationUuid|serverClassifier|sk-ant|AKIA|prompt_snapshot|credential_org|stop_hook_summary|\"signature\"" "$out" \
  | grep -v 'you@example\.com' | sed "s#$HOME#~#g; s#$(id -un)#<login>#g" || true
echo "== fixture files:"; find "$out" -type f -exec wc -c {} + | sed "s#$HOME#~#g"
if [ "$mode" = deny ]; then
  ccver="$(python3 -I - "$work/stream.jsonl" <<'PYEOF'
import json, sys
for line in open(sys.argv[1]):
    try: d = json.loads(line)
    except Exception: continue
    if d.get("type") == "system" and d.get("subtype") == "init":
        print(d.get("claude_code_version") or d.get("version") or "unknown"); break
PYEOF
)"
  {
    echo "# Fixture e2e-deny: how the transcript records denials"
    echo
    echo "Captured $(date -u +%Y-%m-%d) with Claude Code ${ccver:-unknown} by \`WATCHDECK_FIXTURE=1 scripts/fixture-session.sh --mode deny\`."
    echo "One throwaway \`claude -p\` session in a temp project; the transcript is scrubbed with \`scripts/scrub-transcript.py\`."
    echo
    echo "## Prompt"
    echo
    echo '```'
    echo "$deny_prompt"
    echo '```'
    echo
    echo "## Settings keys used (temp \`--settings\` file, nothing under ~/.claude was written)"
    echo
    echo "- \`permissions.defaultMode\`: \`auto\`"
    echo "- \`autoMode.hard_deny\`: \`\$defaults\` plus a rule blocking any shell command whose text contains \`classifier-deny-marker\`"
    echo "- \`permissions.deny\`: a Bash prefix rule for \`echo rule-deny-marker\` and a Read rule for the project's \`SECRET.md\` (absolute \`//\` form)"
    echo "- \`hooks.PreToolUse\`: matcher \`Bash\`, a tee wrapper that keeps the hook's stdin, then \`watchdeck hook\`"
    echo "- \`hooks.PermissionDenied\`: matcher \`*\`, the same tee wrapper"
    echo "- \`--allowedTools Bash,Read\`, \`--max-turns 8\`"
    echo
    echo "## Observed denial shapes"
    echo
    echo "Shapes seen in the first real capture (2026-10-18, auto mode): a Bash call blocked by a deny rule has a tool_result row with \`permissionDecision\` reject/config/subcommandResults and an \`is_error\` result \"Permission to use Bash with command ... has been denied.\"; a Read blocked by a deny rule has NO \`permissionDecision\` field, only an \`is_error\` result \`<tool_use_error>File is in a directory that is denied by your permission settings.</tool_use_error>\`; an allowed call carries accept/config/classifier. The classifier block of a custom autoMode.hard_deny rule is recorded below as observed in this run."
    echo
    echo "Observed in this run (decision/source/reasonType):"
    echo
    cat "$work/tuples.txt"
    echo
    echo "The person's 'No' is not in this capture; it needs one interactive run (see the approved plan, Phase 2)."
  } > "$out/README.md"
  ok=1
  echo
  echo "Next: read every fixture file end to end, then review the scrub grep above, and commit the fixture"
  echo "under internal/transcript/testdata/e2e-deny/ separately. Then: rm -rf $work"
else
  ok=1
  echo
  echo "Next: read every fixture file end to end, then copy $(tilde "$out")/projects and hook-stdin.jsonl"
  echo "into internal/transcript/testdata/e2e-canary/ and update its README. Then: rm -rf $work"
fi
