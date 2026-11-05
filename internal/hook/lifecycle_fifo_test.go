package hook

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestLifecycleFIFODoesNotBlockHook: a FIFO planted at live/<id> or at
// sessions.jsonl never blocks the hook: every event returns promptly, exit 0,
// no output, and a PreToolUse decision is still made.
func TestLifecycleFIFODoesNotBlockHook(t *testing.T) {
	for _, where := range []string{"marker", "log"} {
		t.Run(where, func(t *testing.T) {
			f := newFx(t)
			st, _ := lifecycleStore(t)
			f.env.Lifecycle = st
			if err := os.MkdirAll(st.Live, 0o700); err != nil {
				t.Fatal(err)
			}
			p := filepath.Join(st.Live, "s")
			if where == "log" {
				p = st.Log
			}
			if err := syscall.Mkfifo(p, 0o600); err != nil {
				t.Fatal(err)
			}
			cmd := "python3 " + f.skill("pdf", "scripts/fill.py")
			for _, payload := range []string{
				`{"session_id":"s","hook_event_name":"UserPromptSubmit","prompt":"hi","cwd":"/p"}`,
				`{"session_id":"s","hook_event_name":"SessionStart","source":"startup","cwd":"/p"}`,
				`{"session_id":"s","hook_event_name":"PreToolUse","tool_name":"Bash","cwd":"` + f.cwd + `","tool_input":{"command":"` + cmd + `"}}`,
				`{"session_id":"s","hook_event_name":"SessionEnd","reason":"other","cwd":"/p"}`,
			} {
				var out bytes.Buffer
				done := make(chan int, 1)
				go func() { done <- Run(strings.NewReader(payload), &out, f.env) }()
				select {
				case code := <-done:
					pre := strings.Contains(payload, "PreToolUse")
					if code != 0 || (out.Len() == 0) == pre {
						t.Fatalf("%s: exit %d, stdout %q", payload, code, out.String())
					}
				case <-time.After(5 * time.Second):
					t.Fatalf("hook blocked on a FIFO at the %s: %s", where, payload)
				}
			}
		})
	}
}
