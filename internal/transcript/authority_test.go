package transcript

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const denyProject = "-Users-you-proj"
const denySession = "d484a6af-2106-45c4-9d15-1c2212b76809"

func loadDeny(t *testing.T) *Session {
	t.Helper()
	projects := fixtureProjects(t, "e2e-deny")
	s, err := Load(mainPath(projects, denyProject, denySession), Options{ProjectsDir: projects})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func callsOf(s *Session) []Event {
	var out []Event
	for _, e := range s.Events {
		if e.IsCall() {
			out = append(out, e)
		}
	}
	return out
}

func resultFor(s *Session, id string) (Event, bool) {
	for _, e := range s.Events {
		if e.IsResult() && e.ResultFor == id {
			return e, true
		}
	}
	return Event{}, false
}

// loadRows writes rows as a one-session project and loads it.
func loadRows(t *testing.T, rows ...string) *Session {
	t.Helper()
	projects := t.TempDir()
	dir := filepath.Join(projects, "-Users-you-proj")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "11111111-1111-4111-8111-111111111111.jsonl")
	if err := os.WriteFile(p, []byte(strings.Join(rows, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Load(p, Options{ProjectsDir: projects})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func useRow(id, name, input string) string {
	return `{"type":"assistant","timestamp":"2026-10-19T00:00:00Z","message":{"role":"assistant","content":[{"type":"tool_use","id":"` + id + `","name":"` + name + `","input":` + input + `}]}}`
}

func TestAuthorityParsedFromFixture(t *testing.T) {
	s := loadDeny(t)
	calls := callsOf(s)
	if len(calls) != 4 {
		t.Fatalf("want 4 calls, got %d", len(calls))
	}
	want := []Authority{
		{Decision: "reject", Source: "config", ReasonType: "subcommandResults", DenialKind: "permission-rule"},
		{},
		{Decision: "reject", Source: "config", ReasonType: "classifier", DenialKind: "automode-blocked"},
		{Decision: "accept", Source: "config", ReasonType: "classifier"},
	}
	for i, c := range calls {
		if c.ToolCall.Authority != want[i] {
			t.Errorf("call %d (%s): authority %+v, want %+v", i, c.ToolCall.Name, c.ToolCall.Authority, want[i])
		}
	}
	for i, wantRej := range []bool{true, false, true, false} {
		if calls[i].ToolCall.Authority.Rejected() != wantRej {
			t.Errorf("call %d Rejected() = %v", i, !wantRej)
		}
	}
	re, ok := resultFor(s, calls[1].ToolCall.ID)
	if !ok || !strings.Contains(re.ErrorText, "denied by your permission settings") {
		t.Errorf("Read error text %q", re.ErrorText)
	}
}

func TestAuthorityOnResultEvent(t *testing.T) {
	s := loadDeny(t)
	read := callsOf(s)[1].ToolCall
	if read.Name != "Read" {
		t.Fatalf("call 1 is %s", read.Name)
	}
	e, ok := resultFor(s, read.ID)
	if !ok {
		t.Fatal("no result event")
	}
	if !e.IsError || e.ErrorText == "" || e.Authority.Known() {
		t.Errorf("result event %+v", e)
	}
	bash := callsOf(s)[0].ToolCall
	be, _ := resultFor(s, bash.ID)
	if be.Authority != bash.Authority || !be.Authority.Known() {
		t.Errorf("event authority %+v vs call %+v", be.Authority, bash.Authority)
	}
}

func TestAuthorityFallbackWithoutDenialKind(t *testing.T) {
	s := loadRows(t,
		useRow("toolu_x1", "Bash", `{"command":"echo hi"}`),
		`{"type":"user","timestamp":"2026-10-19T00:00:01Z","permissionDecision":{"decision":"reject","source":"config","reasonType":"subcommandResults"},"message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_x1","is_error":true,"content":"denied"}]}}`)
	got := callsOf(s)[0].ToolCall.Authority
	want := Authority{Decision: "reject", Source: "config", ReasonType: "subcommandResults"}
	if got != want || got.DenialKind != "" {
		t.Errorf("got %+v want %+v", got, want)
	}
}

func TestAuthorityUnknownBlockedRead(t *testing.T) {
	s := loadRows(t,
		useRow("toolu_r1", "Read", `{"file_path":"/x/y"}`),
		`{"type":"user","timestamp":"2026-10-19T00:00:01Z","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_r1","is_error":true,"content":"some new wording"}]}}`)
	e, ok := resultFor(s, "toolu_r1")
	if !ok || e.ErrorText != "some new wording" || e.Authority.Known() {
		t.Errorf("event %+v", e)
	}
	if callsOf(s)[0].ToolCall.Authority.Known() {
		t.Error("call authority should be unknown")
	}
}

func TestErrorTextEveryTool(t *testing.T) {
	long := strings.Repeat("é", 200)
	s := loadRows(t,
		useRow("toolu_m1", "mcp__srv__do", `{}`),
		`{"type":"user","timestamp":"2026-10-19T00:00:01Z","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_m1","is_error":true,"content":[{"type":"text","text":"mcp failed"}]}]}}`,
		useRow("toolu_m2", "mcp__srv__do", `{}`),
		`{"type":"user","timestamp":"2026-10-19T00:00:02Z","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_m2","is_error":true,"content":"`+long+`"}]}}`,
		useRow("toolu_m3", "mcp__srv__do", `{}`),
		`{"type":"user","timestamp":"2026-10-19T00:00:03Z","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_m3","content":"fine"}]}}`)
	e, _ := resultFor(s, "toolu_m1")
	if e.ErrorText != "mcp failed" || e.Snippet != "" {
		t.Errorf("mcp event %+v", e)
	}
	e2, _ := resultFor(s, "toolu_m2")
	if len(e2.ErrorText) > 160 || e2.ErrorText == "" {
		t.Errorf("long error text len %d", len(e2.ErrorText))
	}
	e3, _ := resultFor(s, "toolu_m3")
	if e3.ErrorText != "" {
		t.Errorf("non-error kept text %q", e3.ErrorText)
	}
}
