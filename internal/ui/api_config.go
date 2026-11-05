package ui

import (
	"net/http"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/userconfig"
)

// configJSON is GET /api/config: watchdeck's own config.yaml as the
// Settings page needs it. Autostart and InstalledAt are null when the file
// records no answer (never asked) or no valid date.
type configJSON struct {
	Path            string  `json:"path"`
	Autostart       *bool   `json:"autostart"`
	InstalledAt     *string `json:"installed_at"`
	Nonce           string  `json:"nonce"`
	NonceTTLSeconds int     `json:"nonce_ttl_seconds"`
}

// configRequest is the POST body. Autostart is a pointer so a missing
// field is a 400 rather than a silent false.
type configRequest struct {
	Nonce     string `json:"nonce"`
	Autostart *bool  `json:"autostart"`
}

// configResult is the POST answer, with a fresh nonce for the next write.
type configResult struct {
	Autostart bool   `json:"autostart"`
	Nonce     string `json:"nonce"`
}

// configError is an error body that still hands the page a fresh nonce:
// every failure after the spend returns one so the page can retry.
type configError struct {
	Error string `json:"error"`
	Nonce string `json:"nonce,omitempty"`
}

type configRouter interface{ configRoutes() []route }

func (s *Server) configRoutes() []route {
	return []route{
		{"GET /api/config", http.HandlerFunc(s.handleConfigGet)},
		{"POST /api/config", http.HandlerFunc(s.handleConfigPost)},
	}
}

// handleConfigGet reads config.yaml (a missing file is the zero config)
// and mints a one-use nonce for the POST.
func (s *Server) handleConfigGet(w http.ResponseWriter, r *http.Request) {
	path := s.opts.Paths.ConfigFile()
	c, err := userconfig.Load(path)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := configJSON{Path: path, NonceTTLSeconds: int(nonceTTL / time.Second)}
	if on, set := c.AutostartUI(); set {
		out.Autostart = &on
	}
	if at, ok := c.InstalledAt(); ok {
		v := at.UTC().Format(time.RFC3339)
		out.InstalledAt = &v
	}
	if out.Nonce, err = s.issueNonce(purposeConfig); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// handleConfigPost sets ui.autostart. The body is validated before the
// nonce is spent (400 leaves it usable); a stale one is 403. Every answer
// after the spend carries a fresh nonce.
func (s *Server) handleConfigPost(w http.ResponseWriter, r *http.Request) {
	var body configRequest
	if !readJSON(w, r, &body) {
		return
	}
	if body.Nonce == "" {
		writeError(w, http.StatusBadRequest, "nonce is required: GET /api/config first")
		return
	}
	if body.Autostart == nil {
		writeError(w, http.StatusBadRequest, "autostart is required (true or false)")
		return
	}
	spent := s.spendNonce(body.Nonce, purposeConfig)
	fresh, err := s.issueNonce(purposeConfig)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !spent {
		writeJSON(w, http.StatusForbidden, configError{Error: "stale nonce", Nonce: fresh})
		return
	}
	path := s.opts.Paths.ConfigFile()
	s.mu.Lock()
	err = userconfig.SetAutostartUI(path, *body.Autostart)
	s.mu.Unlock()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, configError{Error: "write " + path + ": " + err.Error(), Nonce: fresh})
		return
	}
	writeJSON(w, http.StatusOK, configResult{Autostart: *body.Autostart, Nonce: fresh})
}
