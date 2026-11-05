//go:build darwin || linux

package sandbox

import (
	"os"
	"os/signal"
	"syscall"
	"time"
)

// KillAfter is how long the child gets after a forwarded SIGINT or SIGTERM
// before it is killed. A variable so tests can shorten it.
var KillAfter = 5 * time.Second

// forwardSignals relays SIGINT, SIGTERM, SIGHUP and SIGQUIT received by this
// process to the child, so Ctrl-C, a closing terminal or a client that stops
// an MCP server reach the sandboxed process. After a forwarded SIGINT or
// SIGTERM the child and its descendants are sent SIGKILL if the child is
// still running KillAfter later.
// The returned stop function ends the relay; call it once the child exited.
func forwardSignals(p *os.Process) (stop func()) {
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
	done := make(chan struct{})
	killAfter := KillAfter
	go func() {
		var kill <-chan time.Time
		for {
			select {
			case s := <-sigs:
				_ = p.Signal(s)
				if (s == syscall.SIGINT || s == syscall.SIGTERM) && kill == nil {
					kill = time.After(killAfter)
				}
			case <-kill:
				killTree(p) // descendants too: a TERM-ignoring grandchild (pgroup_unix.go)
				kill = nil
			case <-done:
				return
			}
		}
	}()
	return func() {
		close(done)
		signal.Stop(sigs)
	}
}
