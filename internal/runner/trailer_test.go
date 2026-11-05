package runner

import (
	"bytes"
	"strings"
	"testing"
)

// With several --skill flags the effective policy is the intersection, so
// widening one skill alone changes nothing; the trailer must name each
// (review 2026-10-14).
func TestTrailerNamesEverySkill(t *testing.T) {
	var buf bytes.Buffer
	writeTrailer(&buf, &Policy{Skills: []string{"alpha", "beta"}, Hash: "deadbeef"}, 1)
	out := buf.String()
	for _, want := range []string{"watchdeck allow alpha ", "watchdeck allow beta "} {
		if !strings.Contains(out, want) {
			t.Errorf("trailer lacks %q:\n%s", want, out)
		}
	}
	if !strings.Contains(out, "every skill") {
		t.Errorf("trailer does not say every named skill needs the grant:\n%s", out)
	}

	buf.Reset()
	writeTrailer(&buf, &Policy{Skills: []string{"alpha"}, Hash: "deadbeef"}, 1)
	if out := buf.String(); !strings.Contains(out, "Widen: watchdeck allow alpha --network all") || strings.Contains(out, "every skill") {
		t.Errorf("single-skill trailer changed:\n%s", out)
	}
}
