package policy

import (
	"os"
	"path/filepath"
	"testing"
)

// TestCacheNot0600IsRebuilt: a cache file that is not 0600 (or not ours,
// or not a regular file) is never read: the files are parsed again and the
// cache is replaced with a 0600 one. CacheMatchesFresh agrees.
func TestCacheNot0600IsRebuilt(t *testing.T) {
	dir := t.TempDir()
	cache := filepath.Join(dir, "state", CacheFile)
	up := filepath.Join(dir, "cfg", "overrides.yaml")
	writeFile(t, up, "version: 2\nsubjects:\n  - {kind: mcp, name: github, tools: {'delete_*': deny}}\n")
	LoadCached(cache, up, "")
	if same, ok := CacheMatchesFresh(cache, up, ""); !ok || !same {
		t.Fatalf("fresh cache: same=%v ok=%v", same, ok)
	}
	if err := os.Chmod(cache, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok := CacheMatchesFresh(cache, up, ""); ok {
		t.Fatal("a 0644 cache was read")
	}
	l := LoadCached(cache, up, "")
	if !l.Rebuilt || l.Policy.MCPToolAction("github", "delete_x").Action != ActionDeny {
		t.Fatalf("not rebuilt: %+v", l)
	}
	if fi, _ := os.Stat(cache); fi.Mode().Perm() != 0o600 {
		t.Fatalf("cache mode after rebuild: %v", fi.Mode())
	}
	// a directory in its place is not read either
	os.Remove(cache)
	os.Mkdir(cache, 0o700)
	if l := LoadCached(cache, up, ""); !l.Rebuilt {
		t.Fatal("a directory cache was read")
	}
}
