package mapmodel

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite testdata/golden/*.json")

// TestGolden builds fixture A (the scrubbed e2e capture) with the
// hand-written activity log, and the e2e-deny capture (four denial shapes,
// no activity records), both views, with and without hide-none, and
// compares the JSON byte for byte.
func TestGolden(t *testing.T) {
	a, deny := loadA(t), loadDeny(t)
	for _, tc := range []struct {
		name string
		view string
		hide bool
	}{
		{"a-topology", ViewTopology, false},
		{"a-topology-hide-none", ViewTopology, true},
		{"a-timeline", ViewTimeline, false},
		{"a-timeline-hide-none", ViewTimeline, true},
		{"deny-topology", ViewTopology, false},
		{"deny-timeline", ViewTimeline, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var g Graph
			if strings.HasPrefix(tc.name, "deny-") {
				g = Build(deny, nil, nil, optsA(deny, tc.view, tc.hide))
			} else {
				g = Build(a, recsA(t), declaredA(t), optsA(a, tc.view, tc.hide))
			}
			got := mustJSON(t, g)
			path := filepath.Join("testdata", "golden", tc.name+".json")
			if *update {
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, got, 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("%v (run with -update to create it)", err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("%s differs from the golden file; run go test ./internal/mapmodel -run TestGolden -update and review the diff.\ngot:\n%s", path, got)
			}
		})
	}
}
