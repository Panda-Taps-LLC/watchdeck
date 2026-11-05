//go:build darwin

package policy

import (
	"os"
	"strings"
	"syscall"
	"unsafe"
)

// macOS path aliases (M6.3 verifier findings). The same file can be named
// through /System/Volumes/Data (the data volume behind the firmlinks of
// /Users, /Applications, /Library, /private, /opt, /usr/local …), through
// /.vol/<dev>/<inode>, and through the /.resolve and /.nofollow prefixes.
// The hook strips /System/Volumes/Data, refuses the other three (a path gate
// then asks), and canonicalises the longest existing directory with
// fcntl(F_GETPATH), which returns the path the kernel itself uses (true
// case, symlinks and firmlinks resolved).

const dataVolume = "/System/Volumes/Data"

// aliasPrefix reports whether p (absolute, cleaned) starts with a macOS
// alias root the hook does not resolve.
func aliasPrefix(p string) bool {
	first, _, _ := strings.Cut(strings.TrimPrefix(p, "/"), "/")
	switch first {
	case ".vol", ".resolve", ".nofollow":
		return true
	}
	return false
}

// stripDataVolume maps /System/Volumes/Data/x to /x.
func stripDataVolume(p string) string {
	if p == dataVolume {
		return "/"
	}
	if rest, ok := strings.CutPrefix(p, dataVolume+"/"); ok {
		return "/" + rest
	}
	return p
}

// canonicalDir returns the kernel's path for an existing directory
// (fcntl F_GETPATH), or dir unchanged when it cannot be opened.
func canonicalDir(dir string) string {
	f, err := os.OpenFile(dir, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_DIRECTORY, 0)
	if err != nil {
		return dir
	}
	defer f.Close()
	var buf [1024]byte // MAXPATHLEN
	_, _, errno := syscall.Syscall(syscall.SYS_FCNTL, f.Fd(), syscall.F_GETPATH, uintptr(unsafe.Pointer(&buf[0])))
	if errno != 0 {
		return dir
	}
	n := 0
	for n < len(buf) && buf[n] != 0 {
		n++
	}
	if n == 0 {
		return dir
	}
	return stripDataVolume(string(buf[:n]))
}
