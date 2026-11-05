package main

import (
	"os"

	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
)

// hostPaths resolves every location from the real home directory and process
// environment. It is the only place the binary asks the OS for them; tests of
// the library packages inject paths through structs instead.
func hostPaths() (paths.Paths, map[string]string, error) {
	env := paths.EnvMap(os.Environ())
	home, err := os.UserHomeDir()
	if err != nil {
		return paths.Paths{}, env, err
	}
	return paths.Resolve(home, env), env, nil
}
