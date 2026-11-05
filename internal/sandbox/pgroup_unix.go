//go:build darwin || linux

package sandbox

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

// The child stays in watchdeck's process group (as before M6.3): when
// Claude Code, a terminal or a test ends the group with SIGKILL, the
// sandboxed child and everything it started die with it. A separate group
// was tried and dropped (verifier, 2026-10-14): a SIGKILL to the shell's
// group then left the child running with ppid 1.
//
// The SIGKILL that follows an ignored SIGINT or SIGTERM must still reach
// grandchildren that ignore SIGTERM, so at escalation watchdeck kills the
// child's whole process tree: descendants first, found by walking parent
// pids (Linux: /proc/<pid>/stat; macOS: ps), then the child.

// killTree sends SIGKILL to every descendant of pid, then to pid.
func killTree(p *os.Process) {
	for _, d := range descendants(p.Pid) {
		_ = syscall.Kill(d, syscall.SIGKILL)
	}
	_ = p.Kill()
}

// descendants returns the pids below pid (children, grandchildren, …).
func descendants(pid int) []int {
	children := map[int][]int{}
	for _, pp := range processTable() {
		children[pp[1]] = append(children[pp[1]], pp[0])
	}
	var out []int
	seen := map[int]bool{pid: true}
	queue := []int{pid}
	for len(queue) > 0 && len(out) < 4096 {
		cur := queue[0]
		queue = queue[1:]
		for _, c := range children[cur] {
			if !seen[c] {
				seen[c] = true
				out = append(out, c)
				queue = append(queue, c)
			}
		}
	}
	return out
}

// processTable lists [pid, ppid] pairs of every process.
func processTable() [][2]int {
	if t := procTable(); t != nil {
		return t
	}
	// macOS (and a Linux without /proc): ps, which needs no privileges.
	out, err := exec.Command("/bin/ps", "-A", "-o", "pid=,ppid=").Output()
	if err != nil {
		return nil
	}
	var t [][2]int
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) != 2 {
			continue
		}
		a, err1 := strconv.Atoi(f[0])
		b, err2 := strconv.Atoi(f[1])
		if err1 == nil && err2 == nil {
			t = append(t, [2]int{a, b})
		}
	}
	return t
}

// procTable reads /proc/<pid>/stat (Linux); nil when /proc is not there.
func procTable() [][2]int {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var t [][2]int
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		b, err := os.ReadFile("/proc/" + e.Name() + "/stat")
		if err != nil {
			continue
		}
		// "pid (comm) state ppid …": comm may hold spaces and parens
		s := string(b)
		i := strings.LastIndexByte(s, ')')
		if i < 0 {
			continue
		}
		f := strings.Fields(s[i+1:])
		if len(f) < 2 {
			continue
		}
		if ppid, err := strconv.Atoi(f[1]); err == nil {
			t = append(t, [2]int{pid, ppid})
		}
	}
	if len(t) == 0 {
		return nil
	}
	return t
}
