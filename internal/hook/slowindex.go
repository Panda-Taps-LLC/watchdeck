package hook

import (
	"os"
	"path/filepath"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/index"
	"github.com/Panda-Taps-LLC/watchdeck/internal/skills"
)

// A cold skill index build (first call after a change under a large skills
// tree) can take longer than the watchdog (M6.1 verifier note b). The
// watchdog then answers ask and the process exits, which used to abandon the
// build, so every following call started it again and asked again. Now,
// when the watchdog fires while this call is loading the index, the hook
// starts `watchdeck index` as a detached child (its own session, stdio
// /dev/null, the call's cwd) that finishes the build and writes the cache;
// the next call finds it fresh. At most one child per minute: a marker file
// next to the index records the last spawn.

// Env.loading (set per call by Run) is true while that call is inside
// index.LoadOrBuild.

// spawnIndex starts the detached build; tests replace it.
var spawnIndex = spawnIndexChild

// indexSpawnGap is the least time between two spawned builds.
const indexSpawnGap = time.Minute

func loadIndex(env Env, roots skills.Roots) (*index.Index, error) {
	if env.loading != nil {
		env.loading.Store(true)
		defer env.loading.Store(false)
	}
	ix, _, err := index.LoadOrBuild(index.Path(env.CacheDir), roots, env.UserCfgDir)
	return ix, err
}

// watchdogFired is the onTimeout handler: finish a slow index build.
func watchdogFired(in Input, env Env) {
	if env.loading == nil || !env.loading.Load() || env.CacheDir == "" {
		return
	}
	marker := filepath.Join(filepath.Dir(index.Path(env.CacheDir)), ".index-spawned")
	if fi, err := os.Stat(marker); err == nil && time.Since(fi.ModTime()) < indexSpawnGap {
		return
	}
	_ = os.MkdirAll(filepath.Dir(marker), 0o700)
	f, err := os.OpenFile(marker, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return
	}
	_ = f.Close()
	now := time.Now()
	_ = os.Chtimes(marker, now, now)
	cwd := in.Cwd
	if cwd == "" {
		cwd = env.Home
	}
	_ = spawnIndex(cwd)
}
