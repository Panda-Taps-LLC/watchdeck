#!/usr/bin/env python3
"""Capability probe for watchdeck tests. Fake paths only; creates nothing outside cwd/HOME given by the test.

With --strict a denial is also reported loudly: one line on stderr naming the
operation and the OS error, and exit 1 (a script that fails on a denial).
Without it the probe reports on stdout and exits 0."""
import os, socket, subprocess, sys

STRICT = False
DENIED = []

# What each probe does, for the --strict stderr line.
WHAT = {
    "write-cwd": "open for write in the working directory",
    "write-home": "open for write in HOME",
    "read-secret": "open of ~/.ssh/id_fake for read",
    "net": "socket connect to 192.0.2.1:80",
    "localhost": "socket connect to 127.0.0.1",
    "subprocess": "subprocess exec of /bin/ls",
}

def denied(label, e):
    print(f"{label}: DENIED({e.errno})")
    DENIED.append(label)
    if STRICT:
        print(f"probe {label}: {WHAT.get(label, label)} refused: {type(e).__name__}: {e}", file=sys.stderr)

class Missing(Exception):
    """The probe target does not exist, so the result proves nothing."""

def report(label, fn):
    try:
        fn()
        print(f"{label}: ALLOWED")
    except Missing as e:
        print(f"{label}: MISSING ({e})")
    except PermissionError as e:
        denied(label, e)
    except (socket.timeout, TimeoutError):
        # The connection attempt left the sandbox; nothing answers at a documentation address.
        print(f"{label}: ALLOWED")
    except OSError as e:
        # EPERM/EACCES (Seatbelt), EROFS (bwrap read-only root), ENETUNREACH (bwrap unshared net)
        if e.errno in (1, 13, 30, 101):
            denied(label, e)
        else:
            print(f"{label}: ERROR({type(e).__name__}:{e.errno})")

def write_cwd():
    with open(os.path.join(os.getcwd(), ".canary-write"), "w") as f:
        f.write("x")

def write_home():
    with open(os.path.join(os.environ["HOME"], ".canary-write"), "w") as f:
        f.write("x")

def read_secret():
    path = os.path.join(os.environ["HOME"], ".ssh", "id_fake")
    try:
        with open(path) as f:
            f.read()
    except FileNotFoundError as e:
        # Seatbelt answers ENOENT for a missing file inside a denied directory and
        # EPERM for a present one (measured 2026-10-12), so ENOENT alone proves
        # nothing on macOS. stat of the directory is EPERM when it is denied.
        try:
            os.stat(os.path.dirname(path))
        except PermissionError as pe:
            raise PermissionError(pe.errno, "directory denied by the sandbox") from e
        except FileNotFoundError:
            raise Missing("~/.ssh does not exist") from e
        if sys.platform.startswith("linux"):
            # bwrap hides a denied path (tmpfs or /dev/null bind); the test created the file.
            raise PermissionError(e.errno, "hidden by the sandbox") from e
        raise Missing("~/.ssh/id_fake does not exist") from e

def net():
    s = socket.create_connection(("192.0.2.1", 80), timeout=2)
    s.close()

def localhost(port):
    s = socket.create_connection(("127.0.0.1", int(port)), timeout=2)
    s.close()

def sub():
    subprocess.run(["/bin/ls", "/"], check=True, capture_output=True)

def env():
    if "CANARY_SECRET" in os.environ:
        print("env: VISIBLE")
    else:
        print("env: SCRUBBED")

def main(argv):
    global STRICT
    if "--strict" in argv:
        STRICT = True
        argv = [a for a in argv if a != "--strict"]
    if not argv:
        print("usage: probe.py <write-cwd|write-home|read-secret|net|localhost PORT|subprocess|env> [--strict]")
        return 2
    a = argv[0]
    if a == "write-cwd": report("write-cwd", write_cwd)
    elif a == "write-home": report("write-home", write_home)
    elif a == "read-secret": report("read-secret", read_secret)
    elif a == "net": report("net", net)
    elif a == "localhost": report("localhost", lambda: localhost(argv[1]))
    elif a == "subprocess": report("subprocess", sub)
    elif a == "env": env()
    else:
        print(f"unknown action {a}"); return 2
    return 1 if (STRICT and DENIED) else 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
