package main

import (
	"fmt"
	"io"
	"os"

	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
	"github.com/Panda-Taps-LLC/watchdeck/internal/uistate"
)

// serviceLogMax is the size at which a service's ui.log is rotated (to
// ui.log.1, replacing an older one) when the service starts.
const serviceLogMax = 1 << 20

// rotateServiceLog keeps ui.log bounded for a service. launchd and systemd
// open ui.log as the server's stdout and stderr; when that file is over
// serviceLogMax at start, it is renamed to ui.log.1 and a fresh ui.log
// (0600, O_NOFOLLOW) is put on fds 1 and 2. A `ui --service` whose stdout
// is not ui.log (run by hand from a terminal) is left alone.
func rotateServiceLog(hp paths.Paths, stderr io.Writer) {
	log := uistate.Path(hp, uistate.LogFile)
	fi, err := os.Lstat(log)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() <= serviceLogMax {
		return
	}
	out, err := os.Stdout.Stat()
	if err != nil || !os.SameFile(out, fi) {
		return
	}
	if err := os.Rename(log, log+".1"); err != nil {
		fmt.Fprintf(stderr, "watchdeck ui: could not rotate %s: %v\n", log, err)
		return
	}
	f, err := os.OpenFile(log, os.O_WRONLY|os.O_CREATE|os.O_APPEND|oNoFollow, 0o600)
	if err != nil {
		fmt.Fprintf(stderr, "watchdeck ui: could not reopen %s: %v\n", log, err)
		return
	}
	defer f.Close()
	for _, fd := range []int{1, 2} {
		if err := dupTo(int(f.Fd()), fd); err != nil {
			fmt.Fprintf(stderr, "watchdeck ui: could not redirect output to %s: %v\n", log, err)
			return
		}
	}
	fmt.Fprintf(os.Stderr, "watchdeck ui: rotated %s (over %d bytes) to %s.1\n", log, serviceLogMax, log)
}
