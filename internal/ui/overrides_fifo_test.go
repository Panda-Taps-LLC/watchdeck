//go:build unix

package ui

import (
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestOverridesFIFONeverBlocks: GET /api/overrides reads the user file with
// manifest.ReadPolicyFile, so a FIFO (or a device) answers 500 at once
// instead of hanging the request with the server lock held.
func TestOverridesFIFONeverBlocks(t *testing.T) {
	o := emptyOptions(t)
	if err := os.MkdirAll(o.Paths.ConfigDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(o.Paths.OverridesFile(), 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	ts := startServer(t, o)
	done := make(chan int, 1)
	go func() {
		resp, _ := ts.do(t, req{Path: "/api/overrides", Token: ts.s.Token()})
		done <- resp.StatusCode
	}()
	select {
	case code := <-done:
		if code != http.StatusInternalServerError {
			t.Errorf("status = %d, want 500", code)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("GET /api/overrides blocked on a FIFO")
	}
}

// TestEnforceProjectSettingsFIFONeverBlocks: GET /api/enforce inspects the
// project's .claude/settings.json through settings.Load, which reads with
// safeio, so a FIFO there (a cloned repo can ship a symlink to /dev/tty or
// /dev/zero as well) is a target error at once, not a request that never
// answers.
func TestEnforceProjectSettingsFIFONeverBlocks(t *testing.T) {
	o := fixtureOptions(t)
	dir := filepath.Join(o.Cwd, ".claude")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(dir, "settings.json"), 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	ts := startServer(t, o)
	type result struct {
		code int
		body []byte
	}
	done := make(chan result, 1)
	go func() {
		resp, b := ts.do(t, req{Path: "/api/enforce", Token: ts.s.Token()})
		done <- result{resp.StatusCode, b}
	}()
	select {
	case r := <-done:
		if r.code != http.StatusOK {
			t.Fatalf("status = %d %s, want 200", r.code, r.body)
		}
		var e enforceJSON
		decode(t, r.body, &e)
		var project *enforceTarget
		for i := range e.Targets {
			if e.Targets[i].ID == targetProject {
				project = &e.Targets[i]
			}
		}
		if project == nil {
			t.Fatalf("no project target in %s", r.body)
		}
		if project.Error == "" {
			t.Errorf("project target has no error for a FIFO settings file: %s", r.body)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("GET /api/enforce blocked on a FIFO project settings file")
	}
}

// TestSkillDetailManifestFIFONeverBlocks: a skill whose PERMISSIONS.yaml is
// a FIFO is listed as invalid with its path set; GET /api/skills/{name}
// reads the text with safeio, so the detail answers at once with no
// manifestText instead of waiting for a writer.
func TestSkillDetailManifestFIFONeverBlocks(t *testing.T) {
	o := fixtureOptions(t)
	p := filepath.Join(o.Paths.Home, ".claude", "skills", "canary-request", "PERMISSIONS.yaml")
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	ts := startServer(t, o)
	type result struct {
		code int
		body []byte
	}
	done := make(chan result, 1)
	go func() {
		resp, b := ts.do(t, req{Path: "/api/skills/canary-request", Token: ts.s.Token()})
		done <- result{resp.StatusCode, b}
	}()
	select {
	case r := <-done:
		if r.code != http.StatusOK {
			t.Fatalf("status = %d %s, want 200", r.code, r.body)
		}
		var d struct {
			ManifestText *string `json:"manifestText"`
		}
		decode(t, r.body, &d)
		if d.ManifestText != nil {
			t.Errorf("manifestText = %q, want null for a FIFO", *d.ManifestText)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("GET /api/skills/{name} blocked on a FIFO PERMISSIONS.yaml")
	}
}
