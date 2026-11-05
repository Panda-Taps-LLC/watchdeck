//go:build !darwin && !linux

package sandbox

import "context"

// Available reports whether enforcement can run on this machine.
// Linux (bubblewrap) lands in M3; until then only macOS enforces.
func Available() bool { return false }

func run(ctx context.Context, o Options) (Result, error) {
	return Result{}, ErrUnsupported
}
