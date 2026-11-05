package runner

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/manifest"
	"github.com/Panda-Taps-LLC/watchdeck/internal/profile"
	"github.com/Panda-Taps-LLC/watchdeck/internal/sandbox"
)

// SelfTest is the outcome of SandboxSelfTest: whether this machine's backend
// applies a profile and enforces it on a tiny canary.
type SelfTest struct {
	Backend string `json:"backend"`         // seatbelt | bwrap | "" (none)
	Probe   string `json:"probe,omitempty"` // python3 | shell
	// Unsupported: no enforcement backend on this machine.
	Unsupported bool `json:"unsupported,omitempty"`
	// Nested: the profile could not be applied because this process already
	// runs inside a sandbox (Claude Code's Bash sandbox, for one). Nothing
	// was learned about the backend itself.
	Nested       bool   `json:"nested,omitempty"`
	WriteAllowed bool   `json:"writeAllowed"` // the canary wrote in its working directory
	WriteDenied  bool   `json:"writeDenied"`  // the canary could not write outside it
	NetChecked   bool   `json:"netChecked"`   // python3 only: a connect to a local listener was tried
	NetDenied    bool   `json:"netDenied"`    // and never reached the listener
	Detail       string `json:"detail,omitempty"`
}

// OK is true when the profile applied and every check that ran held.
func (s SelfTest) OK() bool {
	if s.Unsupported || s.Nested {
		return false
	}
	return s.WriteAllowed && s.WriteDenied && (!s.NetChecked || s.NetDenied)
}

// selfTestPy is the python3 canary: argv[1] is the allowed dir, argv[2] the
// denied one, argv[3] a local port with a listener behind it.
const selfTestPy = `import socket, sys
def w(p):
    try:
        open(p, "w").write("x"); return "ok"
    except OSError: return "denied"
print("write-cwd:", w(sys.argv[1] + "/ok"))
print("write-deny:", w(sys.argv[2] + "/f"))
try:
    socket.create_connection(("127.0.0.1", int(sys.argv[3])), timeout=2).close(); print("net: ok")
except OSError: print("net: denied")
`

// selfTestSh is the shell-only canary: $1 the allowed dir, $2 the denied one.
const selfTestSh = `(echo x > "$1/ok") 2>/dev/null && echo "write-cwd: ok" || echo "write-cwd: denied"
(echo x > "$2/f") 2>/dev/null && echo "write-deny: ok" || echo "write-deny: denied"
`

// SandboxSelfTest compiles a profile that denies the network and every write
// outside a fresh temp directory, then runs a canary under it: python3 when
// it is on PATH (writes plus a connect to a local listener), else /bin/sh
// (writes only). Results are judged from the files left behind and from the
// listener, not only from what the canary prints. Everything it creates is
// removed before it returns; nothing is written under the home directory.
func SandboxSelfTest(ctx context.Context, environ map[string]string) SelfTest {
	st := SelfTest{Backend: backend()}
	if !sandbox.Available() {
		st.Unsupported = true
		st.Backend = ""
		st.Detail = "no sandbox backend on this machine (sandbox-exec on macOS, bwrap on Linux)"
		return st
	}
	work, err := os.MkdirTemp("", "watchdeck-selftest-")
	if err != nil {
		st.Detail = "temp dir: " + err.Error()
		return st
	}
	defer os.RemoveAll(work)
	work = realPath(work)
	tmp := userTempDir(environ)
	// The denied target must sit outside every always-writable dir (the user
	// temp dir, /tmp, /private/tmp): /var/tmp, else nothing to test.
	deny := ""
	if base := realPath("/var/tmp"); base != "" && !underAny(base, []string{tmp, realPath("/tmp"), "/private/tmp"}) {
		if d, err := os.MkdirTemp(base, "watchdeck-selftest-deny-"); err == nil {
			defer os.RemoveAll(d)
			deny = realPath(d)
		}
	}
	if deny == "" {
		st.Detail = "no directory outside the temp dirs to test a denied write in (/var/tmp)"
		return st
	}

	res := profile.Resolved{CWD: work, Tmp: tmp, ExecAny: true, Network: manifest.NetNone, DenyAllWrites: true}
	prof, _, err := compile(res)
	if err != nil {
		st.Detail = "profile: " + err.Error()
		return st
	}

	var accepted atomic.Int32
	var argv []string
	py, pyErr := lookPathIn("python3", environ["PATH"])
	ln, lnErr := net.Listen("tcp", "127.0.0.1:0")
	if pyErr == nil && lnErr == nil {
		defer ln.Close()
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				accepted.Add(1)
				c.Close()
			}
		}()
		port := ln.Addr().(*net.TCPAddr).Port
		argv = []string{py, "-c", selfTestPy, work, deny, strconv.Itoa(port)}
		st.Probe = "python3"
		st.NetChecked = true
	} else {
		if lnErr == nil {
			ln.Close()
		}
		argv = []string{"/bin/sh", "-c", selfTestSh, "sh", work, deny}
		st.Probe = "shell"
	}

	env := []string{"PATH=" + orDefault(environ["PATH"], "/usr/bin:/bin"), "TMPDIR=" + tmp, "LANG=C"}
	if h := environ["HOME"]; h != "" {
		env = append(env, "HOME="+h)
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	var out, errb bytes.Buffer
	r, err := sandbox.Run(ctx, sandbox.Options{Profile: prof, Argv: argv, Env: env, Dir: work, Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb})
	switch {
	case errors.Is(err, sandbox.ErrApply):
		st.Nested = true
		st.Detail = "already inside a sandbox: the profile could not be applied here, so nothing was tested"
		return st
	case err != nil:
		st.Detail = err.Error()
		return st
	case r.ExitCode != 0:
		st.Detail = "canary exited " + strconv.Itoa(r.ExitCode) + ": " + firstLine(errb.String())
	}
	_, okErr := os.Stat(filepath.Join(work, "ok"))
	_, denyErr := os.Stat(filepath.Join(deny, "f"))
	st.WriteAllowed = okErr == nil && strings.Contains(out.String(), "write-cwd: ok")
	st.WriteDenied = denyErr != nil && strings.Contains(out.String(), "write-deny: denied")
	if st.NetChecked {
		st.NetDenied = accepted.Load() == 0 && strings.Contains(out.String(), "net: denied")
	}
	return st
}

// lookPathIn finds an executable name in the PATH value given (not the
// process's), so the canary runs the python3 the child's PATH would find.
func lookPathIn(name, pathVar string) (string, error) {
	for _, dir := range filepath.SplitList(pathVar) {
		if dir == "" || !filepath.IsAbs(dir) {
			continue
		}
		p := filepath.Join(dir, name)
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0o111 != 0 {
			return p, nil
		}
	}
	return "", exec.ErrNotFound
}

func orDefault(v, def string) string {
	if v != "" {
		return v
	}
	return def
}
