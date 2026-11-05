#!/usr/bin/env python3
"""Scrub one captured Claude Code session into a committable fixture.

Run with `python3 -I` (isolated mode: no site packages, no cwd on sys.path).
Stdlib only. Used by scripts/fixture-session.sh; see internal/transcript/testdata/e2e-canary/README.md
for what the committed fixture went through.

  python3 -I scripts/scrub-transcript.py --session SID --src RAW_PROJECT_DIR --out FIXTURE_DIR \
      --home /Users/owner --work /tmp/work --proj /tmp/work/proj \
      [--email owner@host] [--name TOKEN ...] [--forbid TOKEN ...] [--hook-stdin FILE]
  python3 -I scripts/scrub-transcript.py --escape-project-dir PATH
      prints Claude Code's projects/ directory name for PATH and exits (used by fixture-session.sh)

Input: RAW_PROJECT_DIR/<SID>.jsonl and, if present, RAW_PROJECT_DIR/<SID>/subagents/agent-*.jsonl
and agent-*.meta.json. Nothing else under RAW_PROJECT_DIR is read.

Output: FIXTURE_DIR/projects/-Users-you-proj/<SID>.jsonl, the same subagents/ tree under
FIXTURE_DIR/projects/-Users-you-proj/<SID>/, and FIXTURE_DIR/hook-stdin.jsonl (the lines of
--hook-stdin whose session_id is SID). Nothing is written unless every output line passes the
residual check. A failure prints, on stderr, the output file, the line number and the kind of
residue found (never the line itself), writes nothing and exits 1.

What a row goes through, in order:
  1. rows whose type is cost-state, atis-latch, last-prompt, queue-operation, api-request,
     api-request-blob, api-request-shape or model_refusal_fallback are dropped (session
     bookkeeping and API request captures; the api-request blobs carry the full prompt and the
     account's identity; the reader uses only user, assistant and attachment rows);
  2. system rows with subtype stop_hook_summary, informational or model_refusal_fallback are
     dropped (the first names the machine's hooks);
  3. attachment rows are dropped unless they are watchdeck's own PreToolUse answer: type
     hook_success, hookName starting with "PreToolUse:", and stdout a JSON object whose
     hookSpecificOutput carries a "watchdeck" reason or a "watchdeck run" rewrite. Every
     other hook's row (status bars, plugin hooks, Stop and SessionStart hooks) is dropped
     whole, so no other tool's command, stdout or metrics reach the fixture;
  4. thinking and redacted_thinking content blocks are dropped (the reader never uses them;
     their signature blobs are opaque and account-linked); a message left with no blocks keeps
     an empty content array;
  5. the keys serverClassifierContext, serverClassifierRequest, organizationUuid, rendered,
     renderedRole and renderedBesideToolResult are removed wherever they occur; requestId,
     promptId / prompt_id, msg_... message ids and harnessSectionHash are replaced by
     req_FAKE<n>, prompt-FAKE<n>, msg_FAKE<n> and fakehash<n>, numbered in first-seen order
     (main file, subagent files, hook stdin) with one mapping for all files, so equal real ids
     stay equal; the original values must not survive anywhere;
  6. every string value is rewritten: the temp project path becomes /Users/you/proj, the temp
     work dir /Users/you/work, the home dir /Users/you (escaped "-Users-you-proj" forms included,
     with and without a macOS /private prefix), the given email and any other email-looking
     string become you@example.com, and sk-ant-... / AKIA... patterns become REDACTED;
  7. the serialised line is checked for residue: the --name tokens (case-insensitive), the raw
     home/work/proj paths, organizationUuid, serverClassifierContext, serverClassifierRequest,
     a "signature" key, a thinking block, the original values of faked ids, sk-ant-, AKIA keys, any
     "@" outside you@example.com, and every --forbid token.

Lines that are not JSON are dropped and counted. tool_use ids, uuids, timestamps, message.model,
is_error flags and tool inputs are left intact (after the path rewrite).
"""
import argparse
import json
import os
import re
import sys

SCRUB_HOME = "/Users/you"
SCRUB_PROJ = "/Users/you/proj"
SCRUB_WORK = "/Users/you/work"
SCRUB_EMAIL = "you@example.com"

DROP_TYPES = {"cost-state", "atis-latch", "last-prompt", "queue-operation",
              "api-request", "api-request-blob", "api-request-shape", "model_refusal_fallback"}
DROP_SYSTEM_SUBTYPES = {"stop_hook_summary", "informational", "model_refusal_fallback"}
STRIP_KEYS = {"serverClassifierContext", "serverClassifierRequest", "organizationUuid", "rendered", "renderedRole", "renderedBesideToolResult"}
# Opaque ids tied to the capturing account's API calls, replaced by consistent fakes (the same
# real value always maps to the same fake, across the transcript, subagent files and hook stdin,
# so joins on them still hold). tool_use ids and uuids are kept.
FAKE_KEYS = {"requestId": "req", "promptId": "prompt", "prompt_id": "prompt", "harnessSectionHash": "hash", "requestRef": "ref"}
FAKE_FORMAT = {"req": "req_FAKE%d", "msg": "msg_FAKE%d", "prompt": "prompt-FAKE%d", "hash": "fakehash%d", "ref": "reqref-FAKE%d"}
DROP_BLOCKS = {"thinking", "redacted_thinking"}

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
SK_ANT_RE = re.compile(r"sk-ant-[A-Za-z0-9_-]{8,}")
AKIA_RE = re.compile(r"AKIA[0-9A-Z]{16}")


def escape_project_dir(p):
    """Claude Code's projects/ directory name for a cwd (observed 2026-10-12, Claude Code 2.1.296):
    ASCII letters and digits are kept, every other character becomes '-', one per UTF-16 code
    unit. Names over 200 characters are cut and hashed by Claude Code; this returns the
    untruncated form, which is enough for the short temp paths the capture uses."""
    out = []
    for ch in p:
        if ch.isascii() and ch.isalnum():
            out.append(ch)
        else:
            out.append("--" if ord(ch) > 0xFFFF else "-")
    return "".join(out)


def private_variants(p):
    """macOS reports temp dirs both as /var/... and /private/var/...; cover both."""
    out = [p]
    if p.startswith("/private/"):
        out.append(p[len("/private"):])
    else:
        out.append("/private" + p)
    return out


def build_replacements(home, work, proj):
    pairs = []
    for raw in private_variants(proj):
        pairs.append((escape_project_dir(raw), escape_project_dir(SCRUB_PROJ)))
        pairs.append((raw, SCRUB_PROJ))
    for raw in private_variants(work):
        pairs.append((escape_project_dir(raw), escape_project_dir(SCRUB_WORK)))
        pairs.append((raw, SCRUB_WORK))
    pairs.append((escape_project_dir(home), escape_project_dir(SCRUB_HOME)))
    pairs.append((home, SCRUB_HOME))
    # longest source first so a path is rewritten before any of its prefixes is
    pairs.sort(key=lambda kv: -len(kv[0]))
    seen, out = set(), []
    for k, v in pairs:
        if k and k not in seen and k != v:
            seen.add(k)
            out.append((k, v))
    return out


class Scrubber:
    def __init__(self, args):
        self.repl = build_replacements(args.home, args.work, args.proj)
        self.email = args.email
        self.counts = {}
        self.fakes = {"req": {}, "msg": {}, "prompt": {}, "hash": {}, "ref": {}}  # kind -> real value -> fake
        # (token, label): failures name the label, never the token (it may be a login or a path)
        forbid = [(t, "a --name token") for t in (args.name or [])]
        forbid += [(args.home, "the raw home path"), (args.work, "the raw work path"), (args.proj, "the raw project path")]
        forbid += [(t, t) for t in ["organizationUuid", "serverClassifierContext", "serverClassifierRequest", "sk-ant-",
                                    '"signature":', '"type":"thinking"', '"type":"redacted_thinking"']]
        forbid += [(t, "a --forbid token") for t in (args.forbid or [])]
        self.forbid = [(t, label) for t, label in forbid if t]

    def bump(self, key):
        self.counts[key] = self.counts.get(key, 0) + 1

    def rewrite_str(self, s):
        for k, v in self.repl:
            if k in s:
                s = s.replace(k, v)
        if self.email and self.email in s:
            s = s.replace(self.email, SCRUB_EMAIL)
        s = EMAIL_RE.sub(SCRUB_EMAIL, s)
        s = SK_ANT_RE.sub("REDACTED", s)
        s = AKIA_RE.sub("REDACTED", s)
        return s

    def fake(self, kind, real):
        m = self.fakes[kind]
        if real not in m:
            m[real] = FAKE_FORMAT[kind] % (len(m) + 1)
        return m[real]

    def walk(self, o):
        if isinstance(o, dict):
            out = {}
            for k, v in o.items():
                if k in STRIP_KEYS:
                    continue
                if isinstance(v, str) and v and k in FAKE_KEYS:
                    out[k] = self.fake(FAKE_KEYS[k], v)
                elif isinstance(v, str) and k == "id" and v.startswith("msg_"):
                    out[k] = self.fake("msg", v)
                else:
                    out[k] = self.walk(v)
            return out
        if isinstance(o, list):
            kept = []
            for v in o:
                if isinstance(v, dict) and v.get("type") in DROP_BLOCKS:
                    self.bump("drop:block:%s" % v.get("type"))
                    continue
                kept.append(self.walk(v))
            return kept
        if isinstance(o, str):
            return self.rewrite_str(o)
        return o

    @staticmethod
    def is_watchdeck_hook(att):
        """True when a hook_success row is watchdeck's PreToolUse answer: a PreToolUse hook whose
        stdout is hook JSON with a "watchdeck" reason or a "watchdeck run" rewrite."""
        if att.get("type") != "hook_success" or not str(att.get("hookName", "")).startswith("PreToolUse:"):
            return False
        stdout = (att.get("stdout") or "").strip()
        if not stdout.startswith("{"):
            return False
        try:
            d = json.loads(stdout)
        except ValueError:
            return False
        hs = d.get("hookSpecificOutput") if isinstance(d, dict) else None
        if not isinstance(hs, dict):
            return False
        reason = hs.get("permissionDecisionReason")
        upd = hs.get("updatedInput")
        cmd = upd.get("command") if isinstance(upd, dict) else None
        return (isinstance(reason, str) and reason.startswith("watchdeck")) or (
            isinstance(cmd, str) and cmd.startswith("watchdeck run "))

    def scrub_transcript_line(self, line):
        """Return the scrubbed line, or None when the row is dropped."""
        line = line.rstrip("\n")
        if not line.strip():
            self.bump("drop:empty")
            return None
        try:
            d = json.loads(line)
        except ValueError:
            self.bump("drop:bad_json")
            return None
        if not isinstance(d, dict):
            self.bump("drop:not_object")
            return None
        t = d.get("type")
        if t in DROP_TYPES:
            self.bump("drop:type:%s" % t)
            return None
        if t == "system" and d.get("subtype") in DROP_SYSTEM_SUBTYPES:
            self.bump("drop:system:%s" % d.get("subtype"))
            return None
        if t == "attachment":
            att = d.get("attachment")
            if not isinstance(att, dict):
                self.bump("drop:attachment:?")
                return None
            if not self.is_watchdeck_hook(att):
                kind = att.get("type")
                if kind == "hook_success":
                    kind = "hook_success:%s" % str(att.get("hookName", "?")).split(":")[0]
                self.bump("drop:attachment:%s" % kind)
                return None
            self.bump("keep:attachment:hook_success:watchdeck")
        else:
            self.bump("keep:type:%s" % t)
        return json.dumps(self.walk(d), ensure_ascii=False, separators=(",", ":"))

    def scrub_json_line(self, line):
        """hook-stdin and meta rows: rewrite only, never drop (except non-JSON)."""
        line = line.rstrip("\n")
        if not line.strip():
            return None
        try:
            d = json.loads(line)
        except ValueError:
            self.bump("drop:bad_json")
            return None
        return json.dumps(self.walk(d), ensure_ascii=False, separators=(",", ":"))

    def residue(self, text):
        """Return a description of the first forbidden token found in text, or ''."""
        low = text.lower()
        for tok, label in self.forbid:
            if tok.lower() in low:
                return label
        if AKIA_RE.search(text):
            return "AKIA key"
        if "@" in text.replace(SCRUB_EMAIL, ""):
            return "'@' outside %s" % SCRUB_EMAIL
        return ""


def read_lines(path):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.readlines()


def check_and_collect(scrubber, label, lines, failures):
    for n, ln in enumerate(lines, 1):
        why = scrubber.residue(ln)
        if why:
            failures.append("%s line %d: %s" % (label, n, why))


def main(argv):
    if argv[:1] == ["--escape-project-dir"]:
        if len(argv) != 2:
            print("usage: scrub-transcript.py --escape-project-dir PATH", file=sys.stderr)
            return 3
        print(escape_project_dir(argv[1]))
        return 0
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--session", required=True, help="session id (file stem of the main transcript)")
    ap.add_argument("--src", required=True, help="raw projects/<escaped cwd> dir holding <session>.jsonl")
    ap.add_argument("--out", required=True, help="fixture dir to write (created)")
    ap.add_argument("--home", required=True, help="the capturing user's home dir, e.g. /Users/owner")
    ap.add_argument("--work", required=True, help="the temp work dir of the capture (holds bin/, proj/, the hook wrapper)")
    ap.add_argument("--proj", required=True, help="the temp project dir that was Claude Code's cwd")
    ap.add_argument("--email", default="", help="an email address to replace (any other email-looking string is replaced too)")
    ap.add_argument("--name", action="append", default=[], help="a token that must not survive (the user's login name); repeatable")
    ap.add_argument("--forbid", action="append", default=[], help="an extra token that must not survive; repeatable")
    ap.add_argument("--hook-stdin", default="", help="raw hook stdin capture (one JSON object per line); only this session's lines are kept")
    args = ap.parse_args(argv)

    sid = args.session
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,96}", sid) or sid in (".", ".."):
        print("scrub: bad session id %r" % sid, file=sys.stderr)
        return 2
    main_src = os.path.join(args.src, sid + ".jsonl")
    if not os.path.isfile(main_src):
        print("scrub: no transcript at %s" % main_src, file=sys.stderr)
        return 2

    sc = Scrubber(args)
    outputs = {}  # relative path under --out -> list of lines (with newline)
    failures = []

    esc_out = escape_project_dir(SCRUB_PROJ)
    rel_main = os.path.join("projects", esc_out, sid + ".jsonl")
    main_lines = []
    for ln in read_lines(main_src):
        s = sc.scrub_transcript_line(ln)
        if s is not None:
            main_lines.append(s + "\n")
    outputs[rel_main] = main_lines
    check_and_collect(sc, rel_main, main_lines, failures)

    sub_src = os.path.join(args.src, sid, "subagents")
    if os.path.isdir(sub_src):
        for name in sorted(os.listdir(sub_src)):
            if not name.startswith("agent-"):
                sc.bump("skip:subagents:%s" % name)
                continue
            p = os.path.join(sub_src, name)
            rel = os.path.join("projects", esc_out, sid, "subagents", name)
            if name.endswith(".jsonl"):
                lines = []
                for ln in read_lines(p):
                    s = sc.scrub_transcript_line(ln)
                    if s is not None:
                        lines.append(s + "\n")
            elif name.endswith(".meta.json"):
                lines = []
                s = sc.scrub_json_line("".join(read_lines(p)))
                if s is not None:
                    lines.append(s + "\n")
            else:
                sc.bump("skip:subagents:%s" % name)
                continue
            outputs[rel] = lines
            check_and_collect(sc, rel, lines, failures)

    if args.hook_stdin:
        kept = []
        for ln in read_lines(args.hook_stdin):
            try:
                d = json.loads(ln)
            except ValueError:
                sc.bump("hook-stdin:drop:bad_json")
                continue
            if d.get("session_id") != sid:
                sc.bump("hook-stdin:drop:other_session")
                continue
            s = sc.scrub_json_line(ln)
            if s is not None:
                kept.append(s + "\n")
                sc.bump("hook-stdin:keep")
        outputs["hook-stdin.jsonl"] = kept
        check_and_collect(sc, "hook-stdin.jsonl", kept, failures)

    real_ids = [r for kind in sc.fakes.values() for r in kind]
    for rel, lines in outputs.items():
        for n, ln in enumerate(lines, 1):
            for r in real_ids:
                if r in ln:
                    failures.append("%s line %d: an unreplaced %s id" % (rel, n, next(k for k, m in sc.fakes.items() if r in m)))
    for kind in sorted(sc.fakes):
        sc.counts["fake:%s" % kind] = len(sc.fakes[kind])
    for k in sorted(sc.counts):
        print("%-48s %d" % (k, sc.counts[k]))
    if failures:
        print("scrub: residue found, nothing written:", file=sys.stderr)
        for f in failures:
            print("  " + f, file=sys.stderr)
        return 1

    for rel, lines in outputs.items():
        dst = os.path.join(args.out, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        with open(dst, "w", encoding="utf-8") as f:
            f.writelines(lines)
        print("wrote %s (%d lines, %d bytes)" % (dst, len(lines), sum(len(l.encode("utf-8")) for l in lines)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
