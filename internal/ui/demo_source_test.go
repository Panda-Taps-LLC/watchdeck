package ui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDemoGifScriptEnforcesCaps: scripts/demo-gif.sh refuses a GIF that is not
// exactly 1280x640, is over 4 MiB, or lasts outside 10-14 s. The script is a
// developer tool that never runs in CI, so this checks its source carries the
// three checks (and removes the file when one fails).
func TestDemoGifScriptEnforcesCaps(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "scripts", "demo-gif.sh"))
	if err != nil {
		t.Fatalf("read demo-gif.sh: %v", err)
	}
	src := string(b)
	for _, want := range []string{
		`"$width" = 1280`,
		`"$height" = 640`,
		`max_bytes=4194304`,
		`"$size" -le "$max_bytes"`,
		`min_s=10`,
		`max_s=14`,
		`ffprobe`,
		`rm -f "$out"`,
	} {
		if !strings.Contains(src, want) {
			t.Errorf("demo-gif.sh does not contain %q", want)
		}
	}
	// The two halves add up to the 1280 width without scaling: 480 for the
	// terminal, 800 for the dashboard (above the 760 px sidebar breakpoint,
	// so the GIF shows the sidebar and not the narrow bar layout).
	for f, size := range map[string]string{"terminal.mjs": "width: 480, height: 640", "dashboard.mjs": "width: 800, height: 640"} {
		m, err := os.ReadFile(filepath.Join("..", "..", "scripts", "demo", f))
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		if strings.Count(string(m), size) != 2 {
			t.Errorf("%s does not record at %s (viewport and recordVideo)", f, size)
		}
	}
	d, _ := os.ReadFile(filepath.Join("..", "..", "scripts", "demo", "dashboard.mjs"))
	if !strings.Contains(string(d), `location.hash.includes("t=")`) {
		t.Errorf("dashboard.mjs has no guard against recording with the token in the hash")
	}
}
