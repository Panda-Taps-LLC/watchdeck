package mapmodel

import (
	"reflect"
	"testing"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/activity"
)

// TestMCPServerRunsOnMap (M6.4/M6.7): an MCP server launched through
// `watchdeck run --subject mcp:<name>` leaves a run record with no session
// (Claude Code starts the server, not a hook call). In its cwd's direct
// pseudo-session it is a sandbox run named by its subject.
func TestMCPServerRunsOnMap(t *testing.T) {
	now := time.Date(2026, 10, 14, 9, 0, 0, 0, time.UTC)
	exit := 0
	recs := []activity.Record{
		{V: 1, Kind: activity.KindRun, TS: now.Format(time.RFC3339Nano), Cwd: "/Users/you/proj", Command: "python3 canary_server.py",
			Exit: &exit, Outcome: activity.OutcomeOK, Backend: "seatbelt", Enforcement: activity.EnforcementSandbox,
			Subject: &activity.Subject{Kind: "mcp", Name: "canary"}},
		{V: 1, Kind: activity.KindRun, TS: now.Add(time.Minute).Format(time.RFC3339Nano), Cwd: "/Users/you/proj", Command: "python3 canary_server.py",
			Exit: &exit, Outcome: activity.OutcomeOK, Backend: "seatbelt", Enforcement: activity.EnforcementSandbox,
			Subject: &activity.Subject{Kind: "mcp", Name: "canary"}},
	}
	g := Build(nil, recs, nil, Options{SessionID: "direct:0123456789ab", Cwd: "/Users/you/proj", Now: now.Add(time.Hour)})
	sb := node(g, "sandbox")
	if sb == nil || sb.Count != 2 || !reflect.DeepEqual(sb.Subjects, []string{"mcp canary (sandbox)"}) {
		t.Fatalf("sandbox node: %+v", sb)
	}
	if d, ok := sb.Detail.(*SandboxDetail); !ok || len(d.Subjects) != 1 || d.Subjects[0].Count != 2 {
		t.Fatalf("sandbox detail: %+v", sb.Detail)
	}
}
