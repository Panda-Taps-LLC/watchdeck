package prove

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/Panda-Taps-LLC/watchdeck/internal/demo"
	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
)

// PolicyYAML is the throwaway overrides.yaml: the one Read rule the proof
// needs raised from ask to deny. mode: enforce is explicit so the temporary
// hook never shadows, whatever the default becomes.
const PolicyYAML = "# written by " + paths.BinaryName + " doctor --prove into a throwaway tree\n" +
	"version: 2\n" +
	"mode: enforce\n" +
	"rule_overrides:\n" +
	"  " + RuleID + ":\n" +
	"    action: deny\n"

// RuleID is the pack rule the Read leg proves (internal/rules/packs/secrets-read.yaml).
const RuleID = "secrets-read/read-ssh-private-key"

// idFake is the Read leg's target below the throwaway HOME; it is never created.
const idFake = ".ssh/id_fake"

// RewritePrefix is what the Bash leg's updatedInput.command must start with.
func RewritePrefix() string { return paths.BinaryName + " run --skill " + demo.Skill + " -c " }

// payload is a PreToolUse hook input. Every field is omitempty, unlike
// hook.Input, so no tool_response: null appears.
type payload struct {
	SessionID      string            `json:"session_id,omitempty"`
	TranscriptPath string            `json:"transcript_path,omitempty"`
	Cwd            string            `json:"cwd,omitempty"`
	PermissionMode string            `json:"permission_mode,omitempty"`
	HookEventName  string            `json:"hook_event_name,omitempty"`
	ToolName       string            `json:"tool_name,omitempty"`
	ToolUseID      string            `json:"tool_use_id,omitempty"`
	ToolInput      map[string]string `json:"tool_input,omitempty"`
}

func encode(e *demo.Env, tool, id string, input map[string]string) []byte {
	b, err := json.Marshal(payload{
		SessionID:      SessionID,
		TranscriptPath: filepath.Join(e.Base, "transcript.jsonl"),
		Cwd:            e.Cwd,
		PermissionMode: "default", // a native ask keeps the rewrite in default mode
		HookEventName:  "PreToolUse",
		ToolName:       tool,
		ToolUseID:      id,
		ToolInput:      input,
	})
	if err != nil {
		panic(err) // strings only: cannot fail
	}
	return b
}

// BashPayload is the Bash leg's input: the canary's network probe, exactly
// e.ProbeCommand(python), so the run record's command equals the decision's
// and the write-time join holds. python is the python3 LookPath found, or
// the bare word python3 (the hook's match is textual).
func BashPayload(e *demo.Env, python string) []byte {
	return encode(e, "Bash", BashToolUseID, map[string]string{"command": probeCommand(e, python)})
}

// probeCommand is the command BashPayload carries: e.ProbeCommand with
// python3 when python is "" (the rewrite leg still runs without one).
func probeCommand(e *demo.Env, python string) string {
	if python == "" {
		python = "python3"
	}
	return e.ProbeCommand(python)
}

// ReadPayload is the Read leg's input: a Read of <tmp HOME>/.ssh/id_fake.
func ReadPayload(e *demo.Env) []byte {
	return encode(e, "Read", ReadToolUseID, map[string]string{"file_path": filepath.Join(e.Home, idFake)})
}

// ChildEnv is the hook's and the rewrite's environment: e.Environ(parent)
// (HOME, the XDG dirs, CLAUDE_CONFIG_DIR and the activity log inside the
// tree) without CLAUDE_PROJECT_DIR, which would point the hook's native
// rules at the real project. PATH stays the parent's.
func ChildEnv(e *demo.Env, parent []string) []string {
	var env []string
	for _, kv := range e.Environ(parent) {
		if name, _, _ := strings.Cut(kv, "="); name == "CLAUDE_PROJECT_DIR" {
			continue
		}
		env = append(env, kv)
	}
	return env
}

// writePolicy writes PolicyYAML into cfgDir/overrides.yaml (0600).
func writePolicy(cfgDir string) error {
	return os.WriteFile(filepath.Join(cfgDir, "overrides.yaml"), []byte(PolicyYAML), 0o600)
}
