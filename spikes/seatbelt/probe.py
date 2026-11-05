import os, urllib.request
def t(label, fn):
    try: fn(); print(f"{label}: ALLOWED")
    except Exception as e: print(f"{label}: DENIED ({type(e).__name__})")
t("write cwd(project)", lambda: open("/Users/you/project/.sb-probe","w").write("x"))
t("write home", lambda: open("/Users/you/.sb-probe","w").write("x"))
t("read ~/.ssh", lambda: os.listdir(os.path.expanduser("~/.ssh")))
t("network", lambda: urllib.request.urlopen("https://example.com", timeout=3))
