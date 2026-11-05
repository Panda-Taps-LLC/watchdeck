//go:build unix

package uistate

import (
	"os/exec"
	"syscall"
)

// spawn starts binary with args in a new session (Setsid), stdio on
// /dev/null, cwd "/", and does not wait for it.
func spawn(binary string, args, env []string) (int, error) {
	cmd := exec.Command(binary, args...)
	cmd.Dir = "/"
	cmd.Env = env // nil: inherit
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	pid := cmd.Process.Pid
	// Reap it when it exits, in case this process outlives it; Release
	// alone would leave a zombie in a long-running caller.
	go cmd.Wait() //nolint:errcheck
	return pid, nil
}
