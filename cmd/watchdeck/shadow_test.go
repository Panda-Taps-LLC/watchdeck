package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Panda-Taps-LLC/watchdeck/internal/manifest"
	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
	"github.com/Panda-Taps-LLC/watchdeck/internal/policy"
)

// Shadow mode (Phase 6): rules shadow, doctor, status and policy check.

func TestRulesShadowOnOff(t *testing.T) {
	e := rulesEnv(t)
	p := filepath.Join(e.cfg, paths.BinaryName, "overrides.yaml")
	shadowOn := func() bool {
		t.Helper()
		on, err := policy.ShadowOn(p)
		if err != nil {
			t.Fatal(err)
		}
		return on
	}

	if code, out, errs := call(t, rulesCmd, "shadow"); code != 0 || out != "shadow mode: off\n" {
		t.Fatalf("status: %d %q %q", code, out, errs)
	}
	if code, out, _ := call(t, rulesCmd, "shadow", "on"); code != 1 || !strings.Contains(out, "Not applied") {
		t.Fatalf("no tty: %d %q", code, out)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatalf("written without a confirm: %v", err)
	}

	code, out, errs := call(t, rulesCmd, "shadow", "on", "--yes")
	if code != 0 || !strings.Contains(out, "wrote ") || !strings.Contains(out, "/overrides.yaml") || strings.Contains(out, "backup") ||
		!strings.HasSuffix(out, "shadow mode on\n") || !strings.Contains(out, "Switch shadow mode on: "+paths.BinaryName+"'s own rules") {
		t.Fatalf("on: %d %q %q", code, out, errs)
	}
	if b, _ := os.ReadFile(p); !strings.Contains(string(b), "version: 2\nmode: shadow\n") {
		t.Fatalf("file:\n%s", b)
	}
	if !shadowOn() {
		t.Fatal("ShadowOn false after on")
	}
	if code, out, _ := call(t, rulesCmd, "shadow"); code != 0 || out != "shadow mode: on\n" {
		t.Fatalf("status on: %d %q", code, out)
	}
	if code, out, _ := call(t, rulesCmd, "shadow", "on", "--yes"); code != 0 || out != "nothing changed: shadow mode is already on\n" {
		t.Fatalf("again: %d %q", code, out)
	}
	if n := len(backups(t, p)); n != 0 {
		t.Fatalf("%d backups after a no-op", n)
	}

	code, out, _ = call(t, rulesCmd, "shadow", "off", "--yes")
	if code != 0 || !strings.Contains(out, "backup ") || !strings.Contains(out, "overrides.yaml.bak-") || !strings.HasSuffix(out, "shadow mode off\n") {
		t.Fatalf("off: %d %q", code, out)
	}
	if b, _ := os.ReadFile(p); strings.Contains(string(b), "mode:") {
		t.Fatalf("off left a mode line:\n%s", b)
	}
	if shadowOn() {
		t.Fatal("ShadowOn true after off")
	}

	before, _ := os.ReadFile(p)
	for _, args := range [][]string{{"shadow", "maybe"}, {"shadow", "on", "off"}, {"shadow", "on", "--now"}} {
		if code, _, _ := call(t, rulesCmd, args...); code != 3 {
			t.Fatalf("%v: exit %d, want 3", args, code)
		}
	}
	if after, _ := os.ReadFile(p); !bytes.Equal(before, after) {
		t.Fatal("a usage error wrote the file")
	}

	// a v1 file converts to v2 with its conversion backup, grants intact
	writeFile(t, p, "version: 1\nskills:\n  pdf:\n    network: all\n")
	code, out, _ = call(t, rulesCmd, "shadow", "on", "--yes")
	if code != 0 || !strings.Contains(out, ".bak-v1-") {
		t.Fatalf("v1: %d %q", code, out)
	}
	f, _, err := policy.LoadFile(p)
	if err != nil || f.Mode != manifest.ModeShadow {
		t.Fatalf("v1 after: %+v %v", f, err)
	}
	if g := f.SkillOverrides().Skills["pdf"]; g.Network == nil || *g.Network != manifest.NetAll {
		t.Fatalf("pdf grant lost: %+v", f.SkillOverrides())
	}

	// with the activity log off, switching on says nothing will be recorded
	if code, out, _ := call(t, rulesCmd, "shadow", "off", "--yes"); code != 0 || strings.Contains(out, "note:") {
		t.Fatalf("off before the activity case: %d %q", code, out)
	}
	t.Setenv("WATCHDECK_ACTIVITY", "off")
	code, out, _ = call(t, rulesCmd, "shadow", "on", "--yes")
	if code != 0 || !strings.HasSuffix(out, "shadow mode on\nnote: the activity log is off (WATCHDECK_ACTIVITY=off), so shadow mode records nothing until it is on\n") {
		t.Fatalf("on with the activity log off: %d %q", code, out)
	}
	if code, out, _ := call(t, rulesCmd, "shadow", "off", "--yes"); code != 0 || strings.Contains(out, "note:") {
		t.Fatalf("off with the activity log off carries a note: %d %q", code, out)
	}

	writeFile(t, p, "version: 9\n")
	if code, _, _ := call(t, rulesCmd, "shadow"); code != 2 {
		t.Fatalf("invalid file: exit %d, want 2", code)
	}
}

// shadowCheck returns the shadow mode check of a doctor run.
func shadowCheck(t *testing.T) (doctorCheck, doctorReport) {
	t.Helper()
	rep := runDoctor(false)
	for _, c := range rep.Checks {
		if c.Name == "shadow mode" {
			return c, rep
		}
	}
	t.Fatalf("no shadow mode check: %+v", rep.Checks)
	return doctorCheck{}, rep
}

func TestDoctorShadowWarns(t *testing.T) {
	e := newTestEnv(t)
	passSelfTest(t)
	p := filepath.Join(e.cfg, paths.BinaryName, "overrides.yaml")

	c, off := shadowCheck(t)
	if c.Status != statusPass || c.Message != "off: rules are enforced" {
		t.Fatalf("off: %+v", c)
	}
	writeFile(t, p, "version: 2\nmode: shadow\n")
	c, on := shadowCheck(t)
	if c.Status != statusWarn || c.Message != "on: rules are observed, not enforced; turn enforcement on with: watchdeck rules shadow off" {
		t.Fatalf("on: %+v", c)
	}
	if on.OK != off.OK {
		t.Fatalf("a warn changed OK: %v → %v", off.OK, on.OK)
	}
	writeFile(t, p, "version: 9\n")
	if c, _ := shadowCheck(t); c.Status != statusWarn || !strings.HasPrefix(c.Message, "unknown: ") {
		t.Fatalf("invalid: %+v", c)
	}

	// status, after a complete setup: the warn line and Observing only
	newTestEnv(t)
	passSelfTest(t)
	setupYes(t, setupOptions{})
	if code, out, errs := call(t, rulesCmd, "shadow", "on", "--yes"); code != 0 {
		t.Fatalf("shadow on: %d %q %q", code, out, errs)
	}
	_, out, _ := call(t, statusCmd, "--exit-zero")
	first, _, _ := strings.Cut(out, "\n")
	if !strings.HasSuffix(first, "· Observing only") || !strings.Contains(first, "Protected") {
		t.Fatalf("first line %q", first)
	}
	if !strings.Contains(out, "  warn shadow mode: on: rules are observed") {
		t.Fatalf("status:\n%s", out)
	}
}

func TestPolicyCheckPrintsMode(t *testing.T) {
	e := newTestEnv(t)
	p := filepath.Join(e.cfg, paths.BinaryName, "overrides.yaml")
	writeFile(t, p, "version: 2\nmode: shadow\n")
	var out, errb bytes.Buffer
	if code := cmdPolicy([]string{"check"}, &out, &errb); code != 0 {
		t.Fatalf("code %d: %s %s", code, out.String(), errb.String())
	}
	if !strings.Contains(out.String(), "mode:         shadow (rules are observed, not enforced; watchdeck rules shadow off)") {
		t.Fatalf("shadow:\n%s", out.String())
	}
	writeFile(t, p, "version: 2\n")
	out.Reset()
	if code := cmdPolicy([]string{"check"}, &out, &errb); code != 0 || strings.Contains(out.String(), "mode:") {
		t.Fatalf("plain: %d\n%s", code, out.String())
	}
}
