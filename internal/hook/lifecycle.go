package hook

import "github.com/Panda-Taps-LLC/watchdeck/internal/lifecycle"

// Lifecycle hook events (M5.2). None of them takes a matcher in the
// registrations, so every source and reason arrives.
const (
	EventSessionStart     = "SessionStart"
	EventSessionEnd       = "SessionEnd"
	EventUserPromptSubmit = "UserPromptSubmit"
)

// recordLifecycle writes the lifecycle record for one of the three events.
// It never writes to stdout and ignores every error: a session must start
// and end whatever the state dir looks like. After a start is recorded,
// lifecycle.OnSessionStart runs when set (cmd/watchdeck/hookcmd.go sets it
// to start the dashboard when autostart is on).
func recordLifecycle(in Input, env Env) {
	st := env.Lifecycle
	switch in.HookEventName {
	case EventSessionStart:
		r, err := st.Start(in.SessionID, in.TranscriptPath, in.Cwd, in.Source)
		if err == nil && !st.Off() {
			if f := lifecycle.OnSessionStart; f != nil {
				f(st, r)
			}
		}
	case EventSessionEnd:
		_ = st.End(in.SessionID, in.TranscriptPath, in.Cwd, in.Reason)
	case EventUserPromptSubmit:
		_ = st.Beat(in.SessionID, in.TranscriptPath, in.Cwd)
	}
}
