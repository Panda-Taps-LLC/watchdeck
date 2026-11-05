//go:build !unix

package sessionindex

func syscallUmask(int) int { return 0 }
