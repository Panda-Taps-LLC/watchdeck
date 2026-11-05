//go:build unix

package service

import "syscall"

const oNoFollow = syscall.O_NOFOLLOW
