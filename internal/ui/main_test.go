package ui

import (
	"os"
	"testing"

	"github.com/Panda-Taps-LLC/watchdeck/internal/claudesettings"
)

// TestMain points the managed-settings directory at an empty temp dir: the
// Enforce page's install reads Claude Code's settings (CoveredTwins), and
// no test may read the real /Library or /etc.
func TestMain(m *testing.M) {
	managed, err := os.MkdirTemp("", "watchdeck-managed-")
	if err != nil {
		panic(err)
	}
	claudesettings.ManagedDirOverride = func() string { return managed }
	code := m.Run()
	os.RemoveAll(managed)
	os.Exit(code)
}
