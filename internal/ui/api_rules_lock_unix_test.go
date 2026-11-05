//go:build unix

package ui

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/Panda-Taps-LLC/watchdeck/internal/claudesettings"
)

// holdSettingsLock takes <stateDir>/claude-settings.lock the way another
// watchdeck process would, until the test ends or release is called.
func holdSettingsLock(t *testing.T, stateDir string) (release func()) {
	t.Helper()
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filepath.Join(stateDir, claudesettings.LockFile), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	done := false
	release = func() {
		if !done {
			done = true
			syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
			f.Close()
		}
	}
	t.Cleanup(release)
	return release
}

func TestRulesWriteLockBusy409(t *testing.T) {
	o := fixtureOptions(t)
	ts := startServer(t, o)
	n := getRules(t, ts, "").Nonce
	release := holdSettingsLock(t, o.Paths.StateDir)
	code, v, b := postJSON(t, ts, "/api/rules", `{"nonce":"`+n+`",`+pathDenyAdd+`}`)
	if code != 409 || !strings.Contains(v.Error, "holds the settings lock") || v.Nonce == "" {
		t.Errorf("add under a held lock = %d %s, want 409 with a fresh nonce", code, b)
	}
	if strings.Contains(readFile(t, userSettingsPath(o)), "wd-t8") {
		t.Error("the rule was written while the lock was held")
	}
	release()
	// The page retries with the nonce the 409 carried.
	code, _, b = postJSON(t, ts, "/api/rules", `{"nonce":"`+v.Nonce+`",`+pathDenyAdd+`}`)
	if code != 200 {
		t.Errorf("retry after release = %d %s", code, b)
	}
}
