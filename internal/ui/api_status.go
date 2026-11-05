package ui

import (
	"encoding/json"
	"net/http"
	"os"
	"runtime"

	"github.com/Panda-Taps-LLC/watchdeck/internal/activity"
	"github.com/Panda-Taps-LLC/watchdeck/internal/lifecycle"
	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
	"github.com/Panda-Taps-LLC/watchdeck/internal/policy"
	"github.com/Panda-Taps-LLC/watchdeck/internal/sandbox"
	"github.com/Panda-Taps-LLC/watchdeck/internal/settings"
)

// statusJSON is GET /api/status.
type statusJSON struct {
	Version              string         `json:"version"`
	Platform             string         `json:"platform"`
	Mode                 string         `json:"mode"` // manual | auto | service ("" from a caller that sets none)
	PID                  int            `json:"pid"`
	EnforcementAvailable bool           `json:"enforcementAvailable"`
	Cwd                  string         `json:"cwd"`         // "" in auto and service mode without ?project=
	ProjectRoot          string         `json:"projectRoot"` // "" when cwd is in no git repository below home
	OverridesPath        string         `json:"overridesPath"`
	ClaudeDir            string         `json:"claudeDir"`
	NoTranscripts        bool           `json:"noTranscripts"`
	Activity             activityStatus `json:"activity"`
	Hook                 map[string]any `json:"hook"`
	IdleMinutes          int            `json:"idleMinutes"`
	// Live is how many sessions are live (lifecycle state, the one source
	// of "live" on every screen); 0 when the store is off or unreadable.
	Live int `json:"live"`
	// Shadow is whether the user overrides file says mode: shadow (watchdeck's
	// own rules are recorded, not enforced); false when the file is absent or
	// cannot be read. Read only: the CLI is the one writer. Never named mode,
	// which is the dashboard's own manual | auto | service.
	Shadow bool `json:"shadow"`
}

type activityStatus struct {
	Path    string `json:"path"`
	Enabled bool   `json:"enabled"` // false when WATCHDECK_ACTIVITY=off
	Size    int64  `json:"size"`    // bytes; 0 when the file does not exist yet
	// LastDecision is the ts of the newest hook decision record, read from the
	// log's tail (activity.LastOfKind); "" when none is in that window. The
	// header uses it to tell "the hook ran from somewhere else" (a --settings
	// file, the plugin) from "the hook is off".
	LastDecision string `json:"lastDecision,omitempty"`
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	o := s.opts
	cwd, err := s.cwdFor(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	st := statusJSON{
		Version:              o.Version,
		Platform:             runtime.GOOS,
		Mode:                 o.Mode,
		PID:                  os.Getpid(),
		EnforcementAvailable: sandbox.Available(),
		Cwd:                  cwd,
		ProjectRoot:          paths.ProjectRoot(cwd, o.Paths.Home),
		OverridesPath:        o.Paths.OverridesFile(),
		ClaudeDir:            o.Paths.ClaudeDir,
		NoTranscripts:        o.NoTranscripts,
		Activity:             activityStatus{Path: o.Paths.Activity, Enabled: o.Paths.Activity != ""},
		IdleMinutes:          int(o.Idle.Minutes()),
	}
	if st.Activity.Enabled {
		if fi, err := os.Stat(o.Paths.Activity); err == nil {
			st.Activity.Size = fi.Size()
		}
		if r, ok, err := activity.LastOfKind(o.Paths.Activity, activity.KindDecision); err == nil && ok {
			st.Activity.LastDecision = r.TS
		}
	}
	user, _ := s.settingsForRequest(cwd)
	st.Hook = hookStatus(user)
	st.Live = liveCount(o.Paths)
	st.Shadow, _ = policy.ShadowOn(o.Paths.OverridesFile())
	writeJSON(w, http.StatusOK, st)
}

// liveCount is the number of live sessions in the lifecycle store at p; 0
// when the store is off or cannot be read.
func liveCount(p paths.Paths) int {
	ls := lifecycle.Store{Log: p.Sessions, Live: p.LiveDir}
	if ls.Off() {
		return 0
	}
	ss, err := ls.List()
	if err != nil {
		return 0
	}
	live, _, _, _ := lifecycle.Counts(ss)
	return live
}

// hookStatus is settings.Inspect of path as a JSON object: "path" plus every
// settings.Status field with its first letter lower-cased (hookInstalled,
// excluded, ...). Going through the struct's own encoding means fields WP5
// adds to Status (skillHook, deniedHook, complete) appear here without an
// edit. A settings file that does not parse yields "path" and "error".
func hookStatus(path string) map[string]any {
	out := map[string]any{"path": path}
	st, err := settings.Inspect(path)
	if err != nil {
		out["error"] = err.Error()
		return out
	}
	b, err := json.Marshal(st)
	if err != nil {
		out["error"] = err.Error()
		return out
	}
	var fields map[string]any
	if err := json.Unmarshal(b, &fields); err != nil {
		out["error"] = err.Error()
		return out
	}
	for k, v := range fields {
		out[lowerFirst(k)] = v
	}
	return out
}

// lowerFirst lower-cases an ASCII first letter: HookInstalled → hookInstalled.
func lowerFirst(k string) string {
	if k != "" && k[0] >= 'A' && k[0] <= 'Z' {
		return string(k[0]+'a'-'A') + k[1:]
	}
	return k
}
