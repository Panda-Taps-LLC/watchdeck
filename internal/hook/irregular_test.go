//go:build unix

package hook

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// TestIrregularSkillMDAsks (M6.1 verifier note a): a skill directory whose
// SKILL.md is a FIFO, a directory or a device is still a skill, named by its
// directory; its scripts are rewritten into the sandbox and always asked
// about, even with auto_allow, and the FIFO is never opened.
func TestIrregularSkillMDAsks(t *testing.T) {
	for _, kind := range []string{"fifo", "dir"} {
		t.Run(kind, func(t *testing.T) {
			f := newFx(t)
			dir := filepath.Join(f.home, ".claude", "skills", "odd")
			os.MkdirAll(filepath.Join(dir, "scripts"), 0o755)
			os.WriteFile(filepath.Join(dir, "scripts", "run.py"), []byte("print(1)\n"), 0o644)
			md := filepath.Join(dir, "SKILL.md")
			switch kind {
			case "fifo":
				if err := syscall.Mkfifo(md, 0o644); err != nil {
					t.Skip("mkfifo:", err)
				}
			case "dir":
				os.MkdirAll(md, 0o755)
			}
			f.writeUser(t, "version: 2\ndefaults: {auto_allow: true}\n")
			out := Decide(f.in("python3 "+filepath.Join(dir, "scripts", "run.py")), f.env)
			if decisionOf(out) != Ask {
				t.Fatalf("decision: %+v", out)
			}
			s := out.HookSpecificOutput
			rw, _ := s.UpdatedInput["command"].(string)
			if !strings.HasPrefix(rw, "watchdeck run --skill odd -c ") || !strings.Contains(s.PermissionDecisionReason, "SKILL.md is not a regular file") {
				t.Fatalf("output: %+v", s)
			}
		})
	}
}
