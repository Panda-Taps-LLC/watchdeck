#!/bin/bash
# Spike 2 driver (macOS). Builds a throwaway layout under a fresh temp dir and
# runs every case against it. Nothing here touches the developer's real home.
#
#   bash spikes/seatbelt/spike2.sh            # prints profiles + probe output
#
# Layout (R = realpath of the temp root, /private/var/folders/.../T/sbspike.XXXX):
#   R/home/.ssh/id_fake                       fake key (string "FAKE-KEY-NOT-REAL")
#   R/home/.claude/settings.json              fake settings
#   R/home/.claude/skills/demo/scripts/x.py   fake skill script
#   R/cwd                                     fake working directory
#   R/tmp                                     the "Tmp" of the profile (NOT the real
#                                             TMPDIR: the fake home lives under it,
#                                             so allowing it would re-allow home)
#   R/sock/s.sock                             unix socket for case D
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
PROBE="$HERE/probe2.py"
R=$(realpath "$(mktemp -d "${TMPDIR:-/tmp}/sbspike.XXXXXX")")
REALT=$(realpath "${TMPDIR:-/tmp}")
mkdir -p "$R/home/.ssh" "$R/home/.claude/skills/demo/scripts" "$R/cwd" "$R/tmp" "$R/sock"
echo "FAKE-KEY-NOT-REAL" > "$R/home/.ssh/id_fake"
echo '{"fake":true}' > "$R/home/.claude/settings.json"
echo 'print("x.py ran")' > "$R/home/.claude/skills/demo/scripts/x.py"
trap 'rm -rf "$R"' EXIT

ENV=(env -i HOME="$R/home" TMPDIR="$R/tmp" PATH=/usr/bin:/bin SP_HOME="$R/home" SP_CWD="$R/cwd" SP_SKILL="$R/home/.claude/skills/demo")
SB=/usr/bin/sandbox-exec

case_() { echo; echo "################ $1"; shift; printf '%s\n' "$@" > "$R/p.sb"; echo "--- profile ---"; cat "$R/p.sb"; echo "--- output ---"; }
probe() { (cd "$R/cwd" && "${ENV[@]}" "$SB" -f "$R/p.sb" /usr/bin/python3 "$PROBE" "$@" 2>"$R/err"); echo "exit=$?"; if [ -s "$R/err" ]; then echo "stderr:"; sed 's/^/  /' "$R/err"; fi; }
bashc() { (cd "$R/cwd" && "${ENV[@]}" "$SB" -f "$R/p.sb" /bin/bash -c "$1" 2>&1); echo "exit=$?"; }

echo "R=$R"
echo "REALT=$REALT"
echo "python3=$(/usr/bin/python3 --version 2>&1) via $(xcrun -f python3 2>/dev/null || echo unknown)"
echo "macOS=$(sw_vers -productVersion 2>/dev/null)"

# ---------------------------------------------------------------- (a) writes
case_ "A1 deny-all writes, strict allow set" \
'(version 1)' '(allow default)' '(deny network*)' '(deny file-write*)' \
"(allow file-write* (subpath \"$R/cwd\") (subpath \"$R/tmp\") (subpath \"/private/tmp\") (literal \"/dev/null\") (regex #\"^/dev/tty\"))"
probe print write-cwd spawn-ls write-home read-ssh net-192.0.2.1:80
bashc 'echo "bash: hi"; echo d > "$PWD/b.out" && echo "bash write cwd: ALLOWED"; echo x > "$HOME/b.out" && echo "bash write home: LEAK" || echo "bash write home: DENIED"'
echo "(note: python3 is the Xcode shim; the stderr warning is xcrun writing its cache to the REAL T dir, which this spike deliberately does not allow)"

case_ "A1-real same profile, real interpreter behind the shim" \
'(version 1)' '(allow default)' '(deny network*)' '(deny file-write*)' \
"(allow file-write* (subpath \"$R/cwd\") (subpath \"$R/tmp\") (subpath \"/private/tmp\") (literal \"/dev/null\") (regex #\"^/dev/tty\"))"
REALPY=$(xcrun -f python3 2>/dev/null || echo /usr/bin/python3)
(cd "$R/cwd" && "${ENV[@]}" "$SB" -f "$R/p.sb" "$REALPY" "$PROBE" print write-cwd spawn-ls write-home 2>"$R/err"); echo "exit=$?"; [ -s "$R/err" ] && { echo stderr:; cat "$R/err"; }

case_ "A3 deny-all + the real T dir's xcrun cache allowed (stands in for Tmp = real TMPDIR in production)" \
'(version 1)' '(allow default)' '(deny network*)' '(deny file-write*)' \
"(allow file-write* (subpath \"$R/cwd\") (subpath \"$R/tmp\") (subpath \"/private/tmp\") (literal \"/dev/null\") (regex #\"^/dev/tty\"))" \
"(allow file-write* (regex #\"^$REALT/xcrun_db-\"))"
probe print write-cwd spawn-ls write-home

case_ "A4 deny-all WITHOUT the /dev allows" \
'(version 1)' '(allow default)' '(deny network*)' '(deny file-write*)' \
"(allow file-write* (subpath \"$R/cwd\") (subpath \"$R/tmp\") (subpath \"/private/tmp\"))"
probe print write-cwd spawn-ls write-home
bashc 'echo x > /dev/null && echo "bash >/dev/null: ALLOWED" || echo "bash >/dev/null: DENIED"'
echo "--- /dev/tty reopen test via pty.fork (child owns a controlling tty) ---"
/usr/bin/python3 - "$R/p.sb" <<'PY'
import os, pty, sys, select, time
pid, fd = pty.fork()
if pid == 0:
    os.environ.clear(); os.environ["PATH"] = "/usr/bin:/bin"
    os.execv("/usr/bin/sandbox-exec", ["sandbox-exec", "-f", sys.argv[1], "/bin/bash", "-c",
        'echo "write to inherited pty fd: ALLOWED"; { echo "reopen /dev/tty: ALLOWED" > /dev/tty; } 2>/dev/null || echo "reopen /dev/tty: DENIED"; exit 0'])
out = b""; end = time.time() + 5
while time.time() < end:
    r, _, _ = select.select([fd], [], [], 0.2)
    if r:
        try: chunk = os.read(fd, 4096)
        except OSError: break
        if not chunk: break
        out += chunk
os.waitpid(pid, 0); print(out.decode(errors="replace").replace("\r", ""), end="")
PY

case_ "A2 deny-home shape (spike 1 shape, for comparison)" \
'(version 1)' '(allow default)' '(deny network*)' \
"(deny file-write* (subpath \"$R/home\"))" \
"(allow file-write* (subpath \"$R/cwd\") (subpath \"$R/tmp\") (subpath \"/private/tmp\"))"
probe print write-cwd spawn-ls write-home read-ssh net-192.0.2.1:80
bashc 'echo d > "$PWD/b2.out" && echo "bash write cwd: ALLOWED"; echo x > "$HOME/b2.out" && echo "bash write home: LEAK" || echo "bash write home: DENIED"'

# --------------------------------------------------------- (b) skill under ~/.claude
case_ "B1 skill under fake ~/.claude: deny read on .claude, re-allow the skill dir, re-deny writes" \
'(version 1)' '(allow default)' '(deny network*)' \
"(deny file-write* (subpath \"$R/home\"))" \
"(allow file-write* (subpath \"$R/cwd\") (subpath \"$R/tmp\") (subpath \"/private/tmp\"))" \
"(deny file-read* (subpath \"$R/home/.ssh\") (subpath \"$R/home/.claude\"))" \
"(allow file-read* (subpath \"$R/home/.claude/skills/demo\"))" \
"(deny file-write* (subpath \"$R/home/.ssh\") (subpath \"$R/home/.claude\"))"
echo "run the skill script itself:"; (cd "$R/cwd" && "${ENV[@]}" "$SB" -f "$R/p.sb" /usr/bin/python3 "$R/home/.claude/skills/demo/scripts/x.py" 2>&1); echo "exit=$?"
probe write-cwd write-home read-ssh read-settings read-skill list-skill net-192.0.2.1:80
bashc "echo x > '$R/home/.claude/skills/demo/evil.txt' && echo 'write into skill dir: LEAK' || echo 'write into skill dir: DENIED'"

SYM="${R#/private}"
case_ "B2 same deny spelled with the /var/folders SYMLINK path (what \$TMPDIR looks like)" \
'(version 1)' '(allow default)' \
"(deny file-read* (subpath \"$SYM/home/.ssh\") (subpath \"$SYM/home/.claude\"))"
echo "probe opens the real path:"; probe read-ssh read-settings
echo "probe opens the symlink spelling (HOME=$SYM/home):"
(cd "$R/cwd" && env -i HOME="$SYM/home" PATH=/usr/bin:/bin SP_HOME="$SYM/home" SP_CWD="$R/cwd" "$SB" -f "$R/p.sb" /usr/bin/python3 "$PROBE" read-ssh read-settings 2>&1); echo "exit=$?"

case_ "B3 deny spelled REAL, probe opens via the symlink spelling" \
'(version 1)' '(allow default)' \
"(deny file-read* (subpath \"$R/home/.ssh\") (subpath \"$R/home/.claude\"))"
(cd "$R/cwd" && env -i HOME="$SYM/home" PATH=/usr/bin:/bin SP_HOME="$SYM/home" SP_CWD="$R/cwd" "$SB" -f "$R/p.sb" /usr/bin/python3 "$PROBE" read-ssh read-settings 2>&1); echo "exit=$?"

# ------------------------------------------------------------ (c) apply failure
echo; echo "################ C1 nested sandbox-exec, permissive outer profile"
"$SB" -p '(version 1)(allow default)' "$SB" -p '(version 1)(allow default)' /usr/bin/true 2>"$R/err"; echo "exit=$?"; cat "$R/err"
echo; echo "################ C2 nested: which inner profiles may a sandboxed process apply?"
DX='(deny file-read* (literal "/nonexistent/zzz"))'; DN='(deny network*)'
nest() { echo "outer: $1"; echo "inner: $2"; "$SB" -p "$1" "$SB" -p "$2" /usr/bin/true 2>"$R/err"; echo "  exit=$? $(cat "$R/err")"; }
nest "(version 1)(allow default)$DX" "(version 1)(allow default)$DX"
nest "(version 1)(allow default)$DN" "(version 1)(allow default)$DN$DN"
nest "(version 1)(allow default)$DX" "(version 1)(allow default)$DX$DN"
nest "(version 1)(allow default)$DX$DN" "(version 1)(allow default)$DX"
nest "(version 1)(allow default)" "(version 1)(allow default)$DX"
nest "(version 1)(allow default)$DX" "(version 1)(allow default)"
echo "(rule: the inner profile must compile to the one already applied; any other difference, stricter or looser, is exit 71)"
echo; echo "################ C3 nested inside the A2 profile (a skill script trying to sandbox itself)"
printf '(version 1)\n(allow default)\n(deny network*)\n(deny file-write* (subpath "%s/home"))\n' "$R" > "$R/p.sb"
"$SB" -f "$R/p.sb" "$SB" -p '(version 1)(allow default)' /usr/bin/true 2>"$R/err"; echo "exit=$?"; cat "$R/err"
echo; echo "################ C4 other exit codes for contrast"
echo -n "malformed profile: "; "$SB" -p '(version 1)(allow default' /usr/bin/true 2>"$R/err"; echo "exit=$?"; head -1 "$R/err"
echo -n "missing target: "; "$SB" -p '(version 1)(allow default)' /nonexistent/bin 2>"$R/err"; echo "exit=$?"; cat "$R/err"
echo -n "child exit 7: "; "$SB" -p '(version 1)(allow default)' /bin/sh -c 'exit 7'; echo "exit=$?"

# ------------------------------------------------------------ (d) unix sockets
S="$R/sock/s.sock"
/usr/bin/python3 -c '
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.bind(sys.argv[1]); s.listen(5); s.settimeout(30)
try:
    while True:
        c, _ = s.accept(); c.close()
except Exception: pass' "$S" &
USRV=$!; sleep 0.5
case_ "D1 (deny network*) vs unix socket" '(version 1)' '(allow default)' '(deny network*)'
(cd "$R/cwd" && "${ENV[@]}" SP_SOCK="$S" "$SB" -f "$R/p.sb" /usr/bin/python3 "$PROBE" unix-socket net-192.0.2.1:80 2>&1); echo "exit=$?"
case_ "D2 (deny network*) + (allow network-outbound (remote unix-socket))" '(version 1)' '(allow default)' '(deny network*)' '(allow network-outbound (remote unix-socket))'
(cd "$R/cwd" && "${ENV[@]}" SP_SOCK="$S" "$SB" -f "$R/p.sb" /usr/bin/python3 "$PROBE" unix-socket net-192.0.2.1:80 2>&1); echo "exit=$?"
kill $USRV 2>/dev/null; wait $USRV 2>/dev/null

# ------------------------------------------------------------ (e) localhost shapes
/usr/bin/python3 -c '
import socket
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 48123)); s.listen(5); s.settimeout(30)
try:
    while True:
        c, _ = s.accept(); c.close()
except Exception: pass' &
TSRV=$!; sleep 0.5
NETPROBE='
import socket, errno
def conn(label, host, port):
    s = socket.socket(); s.settimeout(2)
    try: s.connect((host, port)); print(label+": ALLOWED")
    except socket.timeout: print(label+": TIMEOUT")
    except OSError as e: print(label+": DENIED(%s)" % errno.errorcode.get(e.errno, e.errno))
    finally: s.close()
def bind(label, host):
    s = socket.socket()
    try: s.bind((host, 0)); s.listen(1); print(label+": ALLOWED")
    except OSError as e: print(label+": DENIED(%s)" % errno.errorcode.get(e.errno, e.errno))
    finally: s.close()
conn("connect 127.0.0.1:48123", "127.0.0.1", 48123)
conn("connect 192.0.2.1:80", "192.0.2.1", 80)
bind("bind 127.0.0.1", "127.0.0.1")
bind("bind 0.0.0.0", "0.0.0.0")
'
netcase() { case_ "$@"; env -i PATH=/usr/bin:/bin "$SB" -f "$R/p.sb" /usr/bin/python3 -c "$NETPROBE" 2>&1; echo "exit=$?"; }
netcase "E1 first localhost shape (LEAKS outbound)" '(version 1)' '(allow default)' '(deny network*)' '(allow network* (local ip "localhost:*"))' '(allow network-outbound (remote ip "localhost:*"))'
netcase "E2 outbound-only localhost" '(version 1)' '(allow default)' '(deny network*)' '(allow network-outbound (remote ip "localhost:*"))'
netcase "E3 tight localhost: bind + inbound on local localhost, outbound to remote localhost (compiler uses this)" '(version 1)' '(allow default)' '(deny network*)' '(allow network-bind (local ip "localhost:*"))' '(allow network-inbound (local ip "localhost:*"))' '(allow network-outbound (remote ip "localhost:*"))'
kill $TSRV 2>/dev/null; wait $TSRV 2>/dev/null
echo; echo "(E3 caveat, verified separately: a sandboxed server bound to 0.0.0.0 under E3 still accepts a connection made to the machine's LAN IP; Seatbelt's \"localhost\" host matches INADDR_ANY and only * / localhost are legal hosts.)"
