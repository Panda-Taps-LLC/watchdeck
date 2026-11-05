//go:build !darwin && !linux

package main

// isTerminal is false where no termios check is wired up: commands then
// never ask, and need --yes to write.
func isTerminal(fd uintptr) bool { return false }
