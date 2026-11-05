package main

import (
	"bytes"
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/uistate"
	"github.com/Panda-Taps-LLC/watchdeck/internal/userconfig"
)

// runHook feeds one hook payload to the built binary and returns its exit
// code, stdout and stderr.
func runHook(t *testing.T, bin, payload string) (int, string, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "hook")
	cmd.Stdin = strings.NewReader(payload)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return code, out.String(), errb.String()
}

const sessionStartPayload = `{"session_id":"7c0a1e52-0000-4000-8000-000000000001","transcript_path":"/nonexistent/t.jsonl","cwd":"/tmp","hook_event_name":"SessionStart","source":"startup"}`

// TestSessionStartAutostart: the SessionStart hook starts the dashboard
// only when the user said yes to autostart, prints nothing either way and
// returns quickly (it never waits for the server).
func TestSessionStartAutostart(t *testing.T) {
	bin := testBinary(t)
	newTestEnv(t)
	t.Setenv("BROWSER", "/usr/bin/false")
	hp, _, err := hostPaths()
	if err != nil {
		t.Fatal(err)
	}

	// Default (never asked): nothing starts.
	code, out, errOut := runHook(t, bin, sessionStartPayload)
	if code != 0 || out != "" || errOut != "" {
		t.Fatalf("hook (autostart unset): %d %q %q", code, out, errOut)
	}
	time.Sleep(300 * time.Millisecond)
	if held, _ := uistate.Locked(hp); held {
		t.Fatal("dashboard started although autostart was never turned on")
	}

	// On, but WATCHDECK_UI_AUTOSTART=off: nothing starts.
	if err := userconfig.SetAutostartUI(hp.ConfigFile(), true); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WATCHDECK_UI_AUTOSTART", "off")
	if code, out, errOut := runHook(t, bin, sessionStartPayload); code != 0 || out != "" || errOut != "" {
		t.Fatalf("hook (env off): %d %q %q", code, out, errOut)
	}
	time.Sleep(300 * time.Millisecond)
	if held, _ := uistate.Locked(hp); held {
		t.Fatal("dashboard started although WATCHDECK_UI_AUTOSTART=off")
	}

	// On: the dashboard comes up in auto mode, and the hook still prints
	// nothing and does not wait for it.
	t.Setenv("WATCHDECK_UI_AUTOSTART", "")
	start := time.Now()
	code, out, errOut = runHook(t, bin, sessionStartPayload)
	d := time.Since(start)
	if code != 0 || out != "" || errOut != "" {
		t.Fatalf("hook (autostart on): %d %q %q", code, out, errOut)
	}
	if d > 2*time.Second {
		t.Fatalf("SessionStart hook took %s", d)
	}
	inst := running(t)
	if inst.Status.Mode != uistate.ModeAuto {
		t.Fatalf("autostarted dashboard mode %q", inst.Status.Mode)
	}

	// A second session reuses it.
	if code, out, errOut := runHook(t, bin, strings.Replace(sessionStartPayload, "0001", "0002", 1)); code != 0 || out != "" || errOut != "" {
		t.Fatalf("second SessionStart: %d %q %q", code, out, errOut)
	}
	if again := running(t); again.State.PID != inst.State.PID {
		t.Fatalf("second session started another dashboard (%d vs %d)", again.State.PID, inst.State.PID)
	}

	if code, _, _, _ := runBin(t, bin, "ui", "--stop"); code != 0 {
		t.Fatalf("ui --stop: %d", code)
	}
	notRunning(t)
}
