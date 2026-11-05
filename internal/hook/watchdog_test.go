//go:build unix

package hook

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// TestWatchdogAsksWhenSlow: a hook call that has not finished within
// DecideTimeout answers ask for a Bash or Skill PreToolUse (Claude Code
// would otherwise treat the timeout as no opinion and run the command
// unsandboxed) and nothing for other events.
func TestWatchdogAsksWhenSlow(t *testing.T) {
	f := newFx(t)
	oldT := DecideTimeout
	DecideTimeout = 50 * time.Millisecond
	release := make(chan struct{})
	var wg sync.WaitGroup
	// runtime.Goexit: an abandoned call stops at release instead of going on
	// to write the index into the test's temp dirs while they are removed.
	testDelay = func() { defer wg.Done(); <-release; runtime.Goexit() }
	t.Cleanup(func() {
		close(release)
		wg.Wait() // every abandoned handle has read testDelay and returned
		testDelay = nil
		DecideTimeout = oldT
	})
	cases := []struct {
		name    string
		in      Input
		wantAsk bool
	}{
		{"bash", f.in("python3 " + f.skill("pdf", "scripts/fill.py")), true},
		{"bash-unrelated", f.in("ls"), true},
		{"skill", Input{SessionID: "s", HookEventName: "PreToolUse", ToolName: "Skill", ToolInput: map[string]any{"skill": "pdf"}}, true},
		{"denied", Input{SessionID: "s", HookEventName: "PermissionDenied", ToolName: "Bash", ToolInput: map[string]any{"command": "x"}}, false},
		{"session-start", Input{SessionID: "s", HookEventName: EventSessionStart}, false},
		{"prompt", Input{SessionID: "s", HookEventName: EventUserPromptSubmit}, false},
	}
	for _, c := range cases {
		wg.Add(1)
		raw, _ := json.Marshal(c.in)
		var out bytes.Buffer
		start := time.Now()
		if code := Run(bytes.NewReader(raw), &out, f.env); code != 0 {
			t.Fatalf("%s: exit %d", c.name, code)
		}
		if el := time.Since(start); el > time.Second {
			t.Errorf("%s: took %v", c.name, el)
		}
		if !c.wantAsk {
			if out.Len() != 0 {
				t.Errorf("%s: output %s", c.name, out.Bytes())
			}
			continue
		}
		var o Output
		if err := json.Unmarshal(out.Bytes(), &o); err != nil {
			t.Fatalf("%s: %v %q", c.name, err, out.Bytes())
		}
		if o.HookSpecificOutput.PermissionDecision != Ask || o.HookSpecificOutput.PermissionDecisionReason != SlowReason || o.HookSpecificOutput.UpdatedInput != nil {
			t.Errorf("%s: %+v", c.name, o.HookSpecificOutput)
		}
	}
}

// TestHostileFilesFinishFast: worst-case files within the caps (deeply
// nested or oversized YAML in the project .watchdeck.yaml, the skill's
// PERMISSIONS.yaml and SKILL.md frontmatter; FIFOs in their place) never
// make a hook call slow: each Decide finishes well under the 3 s watchdog.
// The budget is 1 s (2 s under -race): under 100 ms on a dev Mac, but
// GitHub's shared runners took 203 ms (macOS) and 249 ms (ubuntu) on
// 2026-10-14; before the pre-scan the same files took seconds to minutes.
func TestHostileFilesFinishFast(t *testing.T) {
	budget := time.Second
	if raceEnabled {
		budget = 2 * time.Second
	}
	const cap = 64 << 10
	fill := func(prefix, unit, suffix string) string {
		var b strings.Builder
		b.WriteString(prefix)
		for b.Len()+len(unit)+len(suffix) < cap-16 {
			b.WriteString(unit)
		}
		b.WriteString(suffix)
		return b.String()
	}
	nested := func(depth int) string {
		return strings.Repeat("[", depth) + "x" + strings.Repeat("]", depth)
	}
	shapes := map[string]string{
		"flow-deep":    fill("version: 1\nskills: ", "[", "\n"),
		"flow-64-many": fill("version: 1\nx: [", nested(63)+", ", "x]\n"),
		"map-deep":     fill("version: 1\nx: ", "{a: ", "\n"),
		"block-indent": "version: 1\n" + fill("", "a:\n"+strings.Repeat(" ", 250)+"b: c\n", ""),
		"block-steps":  blockSteps(cap),
		"dash-chain":   fill("version: 1\nx:\n  ", "- ", "x\n"),
		"quote-hidden": fill("version: 1\nx: '", "[[[[", "'\n"),
		"long-scalar":  fill("version: 1\nx: \"", "a", "\"\n"),
		"many-keys":    fill("version: 1\n", "k: v\n", ""),
		"anchors":      fill("version: 1\na: &a [x]\n", "b: *a\n", ""),
		"too-big":      strings.Repeat("#", 2*cap),
	}
	for name, text := range shapes {
		t.Run(name, func(t *testing.T) {
			f := newFx(t)
			proj := filepath.Join(f.home, "proj")
			os.MkdirAll(filepath.Join(proj, ".git"), 0o755)
			os.WriteFile(filepath.Join(proj, ".watchdeck.yaml"), []byte(text), 0o644)
			os.WriteFile(f.skill("pdf", "PERMISSIONS.yaml"), []byte(text), 0o644)
			os.WriteFile(f.skill("pdf", "SKILL.md"), []byte("---\n"+text+"\n---\n"), 0o644)
			in := f.in("python3 " + f.skill("pdf", "scripts/fill.py"))
			in.Cwd = proj
			start := time.Now()
			out := Decide(in, f.env)
			if el := time.Since(start); el > budget {
				t.Errorf("Decide took %v (budget %v)", el, budget)
			}
			if out == nil || out.HookSpecificOutput.PermissionDecision != Ask {
				t.Errorf("decision = %+v", out)
			}
		})
	}
}

// blockSteps is a staircase of nested block mappings, each line indented
// one more column, up to the indentation cap, repeated to fill n bytes.
func blockSteps(n int) string {
	var b strings.Builder
	b.WriteString("version: 1\n")
	for b.Len() < n-4096 {
		for i := 0; i < 250 && b.Len() < n-512; i++ {
			b.WriteString(strings.Repeat(" ", i) + "k:\n")
		}
		b.WriteString(strings.Repeat(" ", 250) + "v\n")
		b.WriteString("z" + time.Duration(b.Len()).String() + ":\n")
	}
	return b.String()
}

// TestFIFOSkillFilesNeverBlock: a FIFO in place of PERMISSIONS.yaml,
// SKILL.md or the project's .claude/settings.json makes the hook ask (or
// pass) promptly instead of hanging.
func TestFIFOSkillFilesNeverBlock(t *testing.T) {
	for _, rel := range []string{"perm", "skillmd", "settings", "project"} {
		t.Run(rel, func(t *testing.T) {
			f := newFx(t)
			proj := filepath.Join(f.home, "proj")
			os.MkdirAll(filepath.Join(proj, ".git"), 0o755)
			var p string
			switch rel {
			case "perm":
				p = f.skill("pdf", "PERMISSIONS.yaml")
			case "skillmd":
				p = f.skill("pdf", "SKILL.md")
				os.Remove(p)
			case "settings":
				os.MkdirAll(filepath.Join(proj, ".claude"), 0o755)
				p = filepath.Join(proj, ".claude", "settings.json")
			case "project":
				p = filepath.Join(proj, ".watchdeck.yaml")
			}
			if err := syscall.Mkfifo(p, 0o600); err != nil {
				t.Skipf("mkfifo: %v", err)
			}
			in := f.in("python3 " + f.skill("pdf", "scripts/fill.py"))
			in.Cwd = proj
			done := make(chan *Output, 1)
			go func() { done <- Decide(in, f.env) }()
			select {
			case out := <-done:
				// Without a readable SKILL.md the directory is not a skill:
				// no opinion is the right answer there.
				if rel == "skillmd" && out == nil {
					return
				}
				if out == nil || out.HookSpecificOutput.PermissionDecision != Ask {
					t.Errorf("decision = %+v", out)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("Decide blocked on a FIFO")
			}
		})
	}
}
