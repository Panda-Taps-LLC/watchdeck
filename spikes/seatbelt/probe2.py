"""Spike 2 probe. Every target path comes from the environment so the script
never touches the developer's real home. Prints one line per probe:
<label>: ALLOWED | DENIED(<errno name>) | TIMEOUT | ERROR(<type>)."""
import errno, os, socket, subprocess, sys

HOME = os.environ["SP_HOME"]        # fake home (real path)
CWD = os.environ["SP_CWD"]          # fake cwd (real path)
SKILL = os.environ.get("SP_SKILL")  # fake skill dir, optional
SOCK = os.environ.get("SP_SOCK")    # unix socket path, optional
ONLY = set(sys.argv[1:])            # run only these probes if given


def t(label, fn):
    if ONLY and label not in ONLY:
        return
    try:
        fn()
        print(f"{label}: ALLOWED", flush=True)
    except socket.timeout:
        print(f"{label}: TIMEOUT", flush=True)
    except OSError as e:
        name = errno.errorcode.get(e.errno, str(e.errno))
        print(f"{label}: DENIED({name})", flush=True)
    except Exception as e:  # noqa: BLE001
        print(f"{label}: ERROR({type(e).__name__}: {e})", flush=True)


def write(p):
    with open(p, "w") as f:
        f.write("x")


def net():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    try:
        s.connect(("192.0.2.1", 80))  # TEST-NET-1, never routable
    finally:
        s.close()


def unix():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(2)
    try:
        s.connect(SOCK)
    finally:
        s.close()


t("print", lambda: print("hello from probe2", flush=True))
t("write-cwd", lambda: write(os.path.join(CWD, "probe2.out")))
t("spawn-ls", lambda: subprocess.run(["/bin/ls", CWD], check=True, stdout=subprocess.DEVNULL))
t("write-home", lambda: write(os.path.join(HOME, "probe2.out")))
t("read-ssh", lambda: open(os.path.join(HOME, ".ssh", "id_fake")).read())
t("read-settings", lambda: open(os.path.join(HOME, ".claude", "settings.json")).read())
if SKILL:
    t("read-skill", lambda: open(os.path.join(SKILL, "scripts", "x.py")).read())
    t("list-skill", lambda: os.listdir(SKILL))
t("net-192.0.2.1:80", net)
if SOCK:
    t("unix-socket", unix)
