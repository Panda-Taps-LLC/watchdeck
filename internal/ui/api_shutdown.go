package ui

import (
	"net/http"
	"os"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/projectscope"
)

// shutdownView is GET /api/shutdown: a one-use nonce for the POST (the same
// pool and TTL as /api/enforce, tagged for shutdown only) and who would stop.
type shutdownView struct {
	Nonce           string `json:"nonce"`
	NonceTTLSeconds int    `json:"nonceTtlSeconds"`
	PID             int    `json:"pid"`
	Mode            string `json:"mode"`
}

type shutdownRequest struct {
	Nonce string `json:"nonce"`
}

func (s *Server) handleShutdownGet(w http.ResponseWriter, r *http.Request) {
	n, err := s.issueNonce(purposeShutdown)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, shutdownView{Nonce: n, NonceTTLSeconds: int(nonceTTL / time.Second), PID: os.Getpid(), Mode: s.opts.Mode})
}

// handleShutdownPost stops the server gracefully (`watchdeck ui --stop`).
// Besides the guard (Host, Origin, Sec-Fetch-Site, JSON content type,
// bearer), it needs a nonce from GET /api/shutdown, spent by the first POST
// that presents it, so a replayed request does nothing. The answer is
// written before the server begins to shut down; Serve then returns nil.
func (s *Server) handleShutdownPost(w http.ResponseWriter, r *http.Request) {
	var body shutdownRequest
	if !readJSON(w, r, &body) {
		return
	}
	if body.Nonce == "" {
		writeError(w, http.StatusBadRequest, "nonce is required: GET /api/shutdown first")
		return
	}
	if !s.spendNonce(body.Nonce, purposeShutdown) {
		writeError(w, http.StatusForbidden, "stale nonce")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"stopping": true, "pid": os.Getpid()})
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	s.RequestStop()
}

// cwdFor is the working directory a project-scoped request uses: the
// server's Cwd, or the ?project= value when it names a known project
// (projectscope.Resolve). "" means user scope only.
func (s *Server) cwdFor(r *http.Request) (string, error) {
	return projectscope.Resolve(r.URL.Query().Get(projectscope.Param), s.opts.Cwd, s.opts.Paths.Home, s.opts.ProjectRoots)
}

// settingsForRequest is Options.Settings for the request's project: a
// caller-supplied Settings (tests) is used as is.
func (s *Server) settingsForRequest(cwd string) (user, project string) {
	if s.customSettings {
		return s.opts.Settings()
	}
	return settingsFor(s.opts.Paths, cwd)
}
