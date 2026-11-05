package runner

import (
	"context"
	"os"
	"testing"

	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
	"github.com/Panda-Taps-LLC/watchdeck/internal/sandbox"
)

func TestSandboxSelfTest(t *testing.T) {
	if !sandbox.Available() {
		st := SandboxSelfTest(context.Background(), nil)
		if !st.Unsupported || st.OK() {
			t.Fatalf("no backend: %+v", st)
		}
		return
	}
	t.Setenv("WATCHDECK_ACTIVITY", "off")
	env := paths.EnvMap(os.Environ())
	st := SandboxSelfTest(context.Background(), env)
	if st.Nested {
		t.Skip("running inside another sandbox: " + st.Detail)
	}
	if !st.OK() {
		t.Fatalf("self-test failed: %+v", st)
	}
	if st.Probe == "python3" && !st.NetChecked {
		t.Fatalf("python3 probe without a network check: %+v", st)
	}
	// the shell-only probe on its own: python3 is not on the PATH handed in
	st = SandboxSelfTest(context.Background(), map[string]string{"PATH": "/nonexistent", "TMPDIR": env["TMPDIR"]})
	if st.Probe != "shell" || st.NetChecked || !st.OK() {
		t.Fatalf("shell probe: %+v", st)
	}
}
