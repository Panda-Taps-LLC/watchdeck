//go:build unix

package sessionindex

import "syscall"

func syscallUmask(m int) int { return syscall.Umask(m) }
