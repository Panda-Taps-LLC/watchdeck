//go:build unix

package hook

import (
	"os"
	"os/exec"
	"strings"
	"syscall"
)

// indexCmd is the detached `watchdeck index` child: this binary, its own
// session (Setsid, so the hook's exit and Claude Code's process group do
// not take it down), stdio on /dev/null (nil), the call's cwd.
func indexCmd(exe, cwd string) *exec.Cmd {
	c := exec.Command(exe, "index")
	c.Dir = cwd
	c.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	return c
}

func spawnIndexChild(cwd string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if strings.HasSuffix(exe, ".test") {
		return nil // a go test binary has no index command
	}
	c := indexCmd(exe, cwd)
	if err := c.Start(); err != nil {
		return err
	}
	return c.Process.Release()
}
