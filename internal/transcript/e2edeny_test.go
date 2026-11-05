package transcript

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const e2eDenySession = "d484a6af-2106-45c4-9d15-1c2212b76809"

// denyReadJSONL parses every line of a JSONL file into a generic map, independent
// of this package's reader.
func denyReadJSONL(t *testing.T, path string) []map[string]any {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var rows []map[string]any
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 16<<20)
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatal(err)
		}
		rows = append(rows, m)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return rows
}

func e2eDenyRows(t *testing.T) []map[string]any {
	t.Helper()
	return denyReadJSONL(t, filepath.Join("testdata", "e2e-deny", "projects", "-Users-you-proj", e2eDenySession+".jsonl"))
}

func denyContentBlocks(row map[string]any) []map[string]any {
	msg, _ := row["message"].(map[string]any)
	arr, _ := msg["content"].([]any)
	var out []map[string]any
	for _, b := range arr {
		if m, ok := b.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// denyResultText flattens a tool_result's content (string or text blocks).
func denyResultText(b map[string]any) string {
	switch c := b["content"].(type) {
	case string:
		return c
	case []any:
		var sb strings.Builder
		for _, x := range c {
			if m, ok := x.(map[string]any); ok {
				if s, ok := m["text"].(string); ok {
					sb.WriteString(s)
				}
			}
		}
		return sb.String()
	}
	return ""
}

func TestE2EDenyRowShapes(t *testing.T) {
	rows := e2eDenyRows(t)
	type use struct {
		id, name, key string
	}
	var uses []use
	for _, r := range rows {
		for _, b := range denyContentBlocks(r) {
			if b["type"] != "tool_use" {
				continue
			}
			in, _ := b["input"].(map[string]any)
			key, _ := in["command"].(string)
			if key == "" {
				key, _ = in["file_path"].(string)
			}
			uses = append(uses, use{b["id"].(string), b["name"].(string), key})
		}
	}
	if len(uses) != 4 {
		t.Fatalf("expected exactly 4 tool_use blocks, got %d: %+v", len(uses), uses)
	}

	type want struct {
		name, key  string
		decision   map[string]any // nil: no permissionDecision key
		denialKind string         // "": no toolDenialKind key
		isError    bool
		text       string
	}
	wants := []want{
		{"Bash", "echo rule-deny-marker", map[string]any{"decision": "reject", "source": "config", "reasonType": "subcommandResults"}, "permission-rule", true, "has been denied"},
		{"Read", "SECRET.md", nil, "", true, "denied by your permission settings"},
		{"Bash", "echo classifier-deny-marker", map[string]any{"decision": "reject", "source": "config", "reasonType": "classifier"}, "automode-blocked", true, "denied by the Claude Code auto mode classifier"},
		{"Bash", "echo done", map[string]any{"decision": "accept", "source": "config", "reasonType": "classifier"}, "", false, ""},
	}
	for _, w := range wants {
		var matched []use
		for _, u := range uses {
			if u.name == w.name && strings.Contains(u.key, w.key) {
				matched = append(matched, u)
			}
		}
		if len(matched) != 1 {
			t.Fatalf("%s %q: expected exactly 1 tool_use, got %d", w.name, w.key, len(matched))
		}
		id := matched[0].id
		var rowsFound int
		for _, r := range rows {
			if r["type"] != "user" {
				continue
			}
			for _, b := range denyContentBlocks(r) {
				if b["type"] != "tool_result" || b["tool_use_id"] != id {
					continue
				}
				rowsFound++
				pd, hasPD := r["permissionDecision"]
				if w.decision == nil {
					if hasPD {
						t.Errorf("%q: unexpected permissionDecision %v", w.key, pd)
					}
				} else {
					got, _ := pd.(map[string]any)
					if len(got) != len(w.decision) {
						t.Errorf("%q: permissionDecision %v, want %v", w.key, pd, w.decision)
					}
					for k, v := range w.decision {
						if got[k] != v {
							t.Errorf("%q: permissionDecision.%s = %v, want %v", w.key, k, got[k], v)
						}
					}
				}
				kind, hasKind := r["toolDenialKind"]
				if w.denialKind == "" {
					if hasKind {
						t.Errorf("%q: unexpected toolDenialKind %v", w.key, kind)
					}
				} else if kind != w.denialKind {
					t.Errorf("%q: toolDenialKind = %v, want %q", w.key, kind, w.denialKind)
				}
				if isErr, _ := b["is_error"].(bool); isErr != w.isError {
					t.Errorf("%q: is_error = %v, want %v", w.key, b["is_error"], w.isError)
				}
				if !strings.Contains(denyResultText(b), w.text) {
					t.Errorf("%q: result text %q lacks %q", w.key, denyResultText(b), w.text)
				}
			}
		}
		if rowsFound != 1 {
			t.Errorf("%q: expected 1 tool_result row, got %d", w.key, rowsFound)
		}
	}
}

func TestE2EDenyHookStdin(t *testing.T) {
	ids := map[string]bool{}
	for _, r := range e2eDenyRows(t) {
		for _, b := range denyContentBlocks(r) {
			if b["type"] == "tool_use" {
				ids[b["id"].(string)] = true
			}
		}
	}
	hooks := denyReadJSONL(t, filepath.Join("testdata", "e2e-deny", "hook-stdin.jsonl"))
	if len(hooks) != 4 {
		t.Fatalf("expected 4 hook stdin lines, got %d", len(hooks))
	}
	var pre, denied int
	var classifierID string
	for _, r := range e2eDenyRows(t) {
		for _, b := range denyContentBlocks(r) {
			if b["type"] == "tool_use" {
				if in, _ := b["input"].(map[string]any); in["command"] == "echo classifier-deny-marker" {
					classifierID = b["id"].(string)
				}
			}
		}
	}
	if classifierID == "" {
		t.Fatal("classifier-denied tool_use not found")
	}
	for i, h := range hooks {
		id, _ := h["tool_use_id"].(string)
		if !ids[id] {
			t.Errorf("line %d: tool_use_id %q is not a tool_use id in the session", i+1, id)
		}
		if h["tool_name"] != "Bash" {
			t.Errorf("line %d: tool_name %v", i+1, h["tool_name"])
		}
		switch h["hook_event_name"] {
		case "PreToolUse":
			pre++
		case "PermissionDenied":
			denied++
			if id != classifierID {
				t.Errorf("PermissionDenied tool_use_id %q != classifier-denied call %q", id, classifierID)
			}
			in, _ := h["tool_input"].(map[string]any)
			if in["command"] != "echo classifier-deny-marker" {
				t.Errorf("PermissionDenied command = %v", in["command"])
			}
			reason, _ := h["reason"].(string)
			const wantReason = "The server-side auto mode classifier judged this action dangerous (it gave no explanation)"
			if reason != wantReason {
				t.Errorf("reason = %q", reason)
			}
			if strings.Contains(reason, "[") {
				t.Errorf("reason contains '[': %q", reason)
			}
		default:
			t.Errorf("line %d: hook_event_name %v", i+1, h["hook_event_name"])
		}
	}
	if pre != 3 || denied != 1 {
		t.Errorf("PreToolUse %d (want 3), PermissionDenied %d (want 1)", pre, denied)
	}
}
