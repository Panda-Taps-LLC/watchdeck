package main

import "syscall"

const oNoFollow = syscall.O_NOFOLLOW

func dupTo(old, new int) error { return syscall.Dup2(old, new) }
