//go:build !darwin

package policy

// No path aliases outside macOS (canon_darwin.go).

func aliasPrefix(string) bool { return false }

func stripDataVolume(p string) string { return p }

func canonicalDir(dir string) string { return dir }
