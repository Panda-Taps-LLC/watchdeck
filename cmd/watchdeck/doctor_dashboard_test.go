package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func checkNamed(t *testing.T, rep doctorReport, name string) doctorCheck {
	t.Helper()
	for _, c := range rep.Checks {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no %q check in %+v", name, rep.Checks)
	return doctorCheck{}
}

// TestDoctorDashboardAndService: both checks are present and never fail;
// the service check runs a command only when the service file exists.
func TestDoctorDashboardAndService(t *testing.T) {
	e := newTestEnv(t)
	passSelfTest(t)
	r := fakeServiceRunner(t)
	rep := runDoctor(false)
	d := checkNamed(t, rep, "dashboard")
	s := checkNamed(t, rep, "service")
	if d.Status != statusPass || !strings.Contains(d.Message, "not running") || !strings.Contains(d.Message, "autostart off") {
		t.Errorf("dashboard check %+v", d)
	}
	if runtime.GOOS == "darwin" || runtime.GOOS == "linux" {
		if s.Status != statusPass || !strings.Contains(s.Message, "not installed") || len(r.calls) != 0 {
			t.Errorf("service check %+v, calls %v", s, r.calls)
		}
	}
	if runtime.GOOS != "darwin" {
		return
	}
	plist := filepath.Join(e.home, "Library", "LaunchAgents", "com.pandataps.watchdeck.plist")
	os.MkdirAll(filepath.Dir(plist), 0o755)
	os.WriteFile(plist, []byte("<plist/>"), 0o644)
	rep = runDoctor(false)
	s = checkNamed(t, rep, "service")
	if s.Status == statusFail || !strings.Contains(s.Message, "installed") || len(r.calls) != 1 || !strings.HasPrefix(r.calls[0], "launchctl print gui/") {
		t.Errorf("installed service check %+v, calls %v", s, r.calls)
	}
}
