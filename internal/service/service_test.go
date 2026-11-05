package service

import (
	"errors"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
)

var update = flag.Bool("update", false, "rewrite the golden files")

// fakeRunner records commands and answers from a table; it never runs
// anything (tests never reach launchctl or systemctl).
type fakeRunner struct {
	calls [][]string
	fail  map[string]bool // "name arg0" prefix → fail
	out   map[string]string
}

func (f *fakeRunner) Run(name string, args ...string) (string, error) {
	c := append([]string{name}, args...)
	f.calls = append(f.calls, c)
	key := strings.Join(c, " ")
	for p := range f.fail {
		if strings.HasPrefix(key, p) {
			return "boom", errors.New("exit status 5")
		}
	}
	for p, o := range f.out {
		if strings.HasPrefix(key, p) {
			return o, nil
		}
	}
	return "", nil
}

// goldenOptions are fixed, fake paths: the goldens do not depend on the host.
func goldenOptions(goos string) Options {
	home := "/Users/you"
	return Options{
		OS:     goos,
		Paths:  paths.Resolve(home, map[string]string{"XDG_STATE_HOME": "/Users/you/state"}),
		Binary: "/Users/you/.local/share/watchdeck/bin/watchdeck",
		UID:    501,
		Environ: map[string]string{
			"XDG_STATE_HOME": "/Users/you/state",
			"HOME":           "/Users/you", // not passed: launchd and systemd set HOME
			"PATH":           "/usr/bin",   // not passed
		},
	}
}

func golden(t *testing.T, name, got string) {
	t.Helper()
	p := filepath.Join("testdata", name)
	if *update {
		os.MkdirAll("testdata", 0o755)
		if err := os.WriteFile(p, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("%v (run with -update to create)", err)
	}
	if got != string(want) {
		t.Fatalf("%s differs from the golden file:\n%s", name, got)
	}
}

func TestPlistGolden(t *testing.T) {
	o := goldenOptions("darwin")
	if o.File() != "/Users/you/Library/LaunchAgents/com.pandataps.watchdeck.plist" {
		t.Fatalf("plist path %s", o.File())
	}
	golden(t, "com.pandataps.watchdeck.plist.golden", Plist(o))
}

func TestUnitGolden(t *testing.T) {
	o := goldenOptions("linux")
	if o.File() != "/Users/you/.config/systemd/user/watchdeck-ui.service" {
		t.Fatalf("unit path %s", o.File())
	}
	golden(t, "watchdeck-ui.service.golden", Unit(o))
	o.Paths = paths.Resolve("/home/you", map[string]string{"XDG_CONFIG_HOME": "/cfg"})
	if o.File() != "/cfg/systemd/user/watchdeck-ui.service" {
		t.Fatalf("XDG_CONFIG_HOME unit path %s", o.File())
	}
}

func TestEscaping(t *testing.T) {
	o := goldenOptions("darwin")
	o.Binary = "/Apps/a&b <x>/watchdeck"
	o.Environ = map[string]string{"WATCHDECK_ACTIVITY": `/t/"q"%n`, "XDG_CACHE_HOME": "/bad\nline"}
	pl := Plist(o)
	if !strings.Contains(pl, "<string>/Apps/a&amp;b &lt;x&gt;/watchdeck</string>") || strings.Contains(pl, "a&b") {
		t.Errorf("plist escaping:\n%s", pl)
	}
	if strings.Contains(pl, "XDG_CACHE_HOME") {
		t.Error("a value with a newline was passed")
	}
	o.OS = "linux"
	un := Unit(o)
	if !strings.Contains(un, `ExecStart="/Apps/a&b <x>/watchdeck" ui --service`) {
		t.Errorf("unit ExecStart:\n%s", un)
	}
	if !strings.Contains(un, `Environment="WATCHDECK_ACTIVITY=/t/\"q\"%%n"`) {
		t.Errorf("unit Environment:\n%s", un)
	}
	o.Binary = "/x\n[Service]\nExecStartPre=/bin/evil"
	if _, err := InstallPlan(o); err == nil {
		t.Error("a binary path with a newline was accepted")
	}
	o.Binary = "relative/watchdeck"
	if _, err := InstallPlan(o); err == nil {
		t.Error("a relative binary was accepted")
	}
	o.OS = "windows"
	o.Binary = "/x"
	if _, err := InstallPlan(o); !errors.Is(err, ErrUnsupported) {
		t.Errorf("windows: %v", err)
	}
}

func tempOptions(t *testing.T, goos string) (Options, *fakeRunner) {
	t.Helper()
	root := t.TempDir()
	home := filepath.Join(root, "home")
	f := &fakeRunner{}
	return Options{
		OS:     goos,
		Paths:  paths.Resolve(home, map[string]string{"XDG_STATE_HOME": filepath.Join(root, "state"), "XDG_CONFIG_HOME": filepath.Join(root, "cfg")}),
		Binary: "/opt/watchdeck/bin/watchdeck",
		UID:    501,
		Runner: f,
	}, f
}

func TestInstallDarwinWithFakeRunner(t *testing.T) {
	o, f := tempOptions(t, "darwin")
	f.fail = map[string]bool{"launchctl bootout": true} // nothing loaded yet
	p, err := Install(o)
	if err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"launchctl", "bootout", "gui/501/com.pandataps.watchdeck"},
		{"launchctl", "bootstrap", "gui/501", o.File()},
	}
	if !reflect.DeepEqual(f.calls, want) {
		t.Fatalf("calls %v, want %v", f.calls, want)
	}
	b, err := os.ReadFile(o.File())
	if err != nil || string(b) != p.Content || !strings.Contains(string(b), "<string>--service</string>") {
		t.Fatalf("plist: %v\n%s", err, b)
	}
	fi, _ := os.Stat(o.File())
	if fi.Mode().Perm() != 0o644 {
		t.Errorf("plist mode %o", fi.Mode().Perm())
	}
	li, err := os.Stat(o.Log())
	if err != nil || li.Mode().Perm() != 0o600 {
		t.Fatalf("ui.log: %v %v", err, li)
	}
	di, _ := os.Stat(o.Paths.StateDir)
	if di.Mode().Perm() != 0o700 {
		t.Errorf("state dir %o", di.Mode().Perm())
	}

	// status: installed; loaded per launchctl print
	f.calls = nil
	f.out = map[string]string{"launchctl print": "gui/501/com.pandataps.watchdeck = {\n\tstate = running\n}"}
	st, err := Status(o)
	if err != nil || !st.Installed || !st.Loaded || st.Detail != "running" {
		t.Fatalf("status %+v %v", st, err)
	}
	if !reflect.DeepEqual(f.calls, [][]string{{"launchctl", "print", "gui/501/com.pandataps.watchdeck"}}) {
		t.Fatalf("status calls %v", f.calls)
	}

	// a bootstrap failure is reported
	f.calls, f.fail = nil, map[string]bool{"launchctl bootstrap": true}
	if _, err := Install(o); err == nil || !strings.Contains(err.Error(), "bootstrap") {
		t.Fatalf("bootstrap failure: %v", err)
	}

	// loaded and bootout fails: reported, plist kept for a retry
	f.calls, f.fail = nil, map[string]bool{"launchctl bootout": true}
	if _, err := Uninstall(o); err == nil || !strings.Contains(err.Error(), "bootout") {
		t.Fatalf("loaded bootout failure: %v", err)
	}
	if _, err := os.Stat(o.File()); err != nil {
		t.Fatal("plist removed although bootout failed")
	}

	// uninstall: bootout, file gone; a second uninstall (not loaded) is fine
	f.calls, f.fail = nil, nil
	if _, err := Uninstall(o); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(o.File()); !os.IsNotExist(err) {
		t.Fatal("plist still there")
	}
	f.fail = map[string]bool{"launchctl bootout": true, "launchctl print": true}
	if _, err := Uninstall(o); err != nil {
		t.Fatalf("second uninstall: %v", err)
	}
	// not installed: status runs nothing
	f.calls = nil
	if st, err := Status(o); err != nil || st.Installed || st.Loaded || len(f.calls) != 0 {
		t.Fatalf("status after uninstall %+v %v calls %v", st, err, f.calls)
	}
}

func TestInstallLinuxWithFakeRunner(t *testing.T) {
	o, f := tempOptions(t, "linux")
	if _, err := Install(o); err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"systemctl", "--user", "daemon-reload"},
		{"systemctl", "--user", "enable", "--now", "watchdeck-ui.service"},
	}
	if !reflect.DeepEqual(f.calls, want) {
		t.Fatalf("calls %v", f.calls)
	}
	if !strings.HasPrefix(o.File(), filepath.Dir(o.Paths.ConfigDir)) {
		t.Fatalf("unit outside XDG_CONFIG_HOME: %s", o.File())
	}
	f.calls = nil
	f.out = map[string]string{"systemctl --user is-active": "active\n"}
	if st, _ := Status(o); !st.Installed || !st.Loaded || st.Detail != "active" {
		t.Fatalf("status %+v", st)
	}
	f.calls = nil
	if _, err := Uninstall(o); err != nil {
		t.Fatal(err)
	}
	want = [][]string{
		{"systemctl", "--user", "disable", "--now", "watchdeck-ui.service"},
		{"systemctl", "--user", "daemon-reload"},
	}
	if !reflect.DeepEqual(f.calls, want) {
		t.Fatalf("uninstall calls %v", f.calls)
	}
}

func TestNoRunnerNoCommands(t *testing.T) {
	o, _ := tempOptions(t, "darwin")
	o.Runner = nil
	if _, err := Install(o); !errors.Is(err, ErrNoRunner) {
		t.Fatalf("Install without a runner: %v", err)
	}
	if _, err := os.Stat(o.File()); err == nil {
		t.Fatal("Install without a runner wrote the plist")
	}
}
