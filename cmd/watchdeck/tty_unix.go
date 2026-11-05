//go:build darwin || linux

package main

import (
	"syscall"
	"unsafe"
)

// isTerminal reports whether fd is a terminal: the termios ioctl succeeds
// on a tty and fails on a file, a pipe or /dev/null (which a character
// device test would count as a terminal).
func isTerminal(fd uintptr) bool {
	var t syscall.Termios
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, ioctlGetTermios, uintptr(unsafe.Pointer(&t)))
	return errno == 0
}
