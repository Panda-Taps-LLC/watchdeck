package main

import "syscall"

const oNoFollow = syscall.O_NOFOLLOW

// Dup3 exists on every linux arch (arm64 has no Dup2).
func dupTo(old, new int) error { return syscall.Dup3(old, new, 0) }
