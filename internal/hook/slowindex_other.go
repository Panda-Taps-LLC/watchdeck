//go:build !unix

package hook

// spawnIndexChild is a no-op where there is no Setsid: the slow build is
// simply abandoned, as before.
func spawnIndexChild(string) error { return nil }
