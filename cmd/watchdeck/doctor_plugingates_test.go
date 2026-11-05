package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestDoctorPluginUncoveredGates: with the plugin on, doctor fails when the
// policy gates a tool the plugin's static hooks.json does not register, and
// names it (review 2026-10-14); a Grep|Glob gate is covered.
func TestDoctorPluginUncoveredGates(t *testing.T) {
	e := newTestEnv(t)
	passSelfTest(t)
	ov := filepath.Join(e.cfg, "watchdeck", "overrides.yaml")
	writeFile(t, ov, "version: 2\nsubjects:\n  - {kind: tool, name: s, match: {tools: [Grep, Glob]}, paths: {deny: ['~/secrets/**']}}\n")
	if c := checkNamed(t, runDoctor(true), "plugin gates"); c.Status != statusPass {
		t.Fatalf("search gates: %+v", c)
	}
	writeFile(t, ov, "version: 2\nsubjects:\n  - {kind: agent, name: x, match: {agent_type: Explore}, tools: {deny: [Task]}}\n")
	if c := checkNamed(t, runDoctor(true), "plugin gates"); c.Status != statusFail || !strings.Contains(c.Message, "Task") {
		t.Fatalf("agent gate: %+v", c)
	}
}
