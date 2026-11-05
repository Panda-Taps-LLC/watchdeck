package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestMeasureHookScriptHasCheckMode pins the CHECK=1 mode of the latency
// script: CI relies on exit 2 when either acceptance line reads OVER.
func TestMeasureHookScriptHasCheckMode(t *testing.T) {
	const path = "../../scripts/measure-hook.sh"
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{
		"CHECK=1 scripts/measure-hook.sh",
		`if [ "${CHECK:-0}" = 1 ]`,
		`case "$acceptance" in`,
		"*OVER*)",
		"exit 2",
		"(limit +1.00)",
		"(limit +2.00)",
		"set -euo pipefail",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("%s lacks %q", path, want)
		}
	}
	if strings.Contains(s, "| grep -q OVER") {
		t.Errorf("%s pipes into grep -q OVER, which pipefail can turn into a missed exit 2", path)
	}
	acc := strings.Index(s, "== acceptance (no-opinion)")
	exit := strings.LastIndex(s, "exit 2") // the header comment also says it
	if acc < 0 || exit < 0 || exit < acc {
		t.Errorf("exit 2 (at %d) must come after the acceptance block (at %d)", exit, acc)
	}
	if bash, err := exec.LookPath("bash"); err == nil {
		if out, err := exec.Command(bash, "-n", path).CombinedOutput(); err != nil {
			t.Errorf("bash -n: %v\n%s", err, out)
		}
	}
}
