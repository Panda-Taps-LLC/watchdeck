package ui

import (
	"net/http"
	"net/url"

	"github.com/Panda-Taps-LLC/watchdeck/internal/mcpconfig"
)

// mcpJSON is GET /api/mcp: the user-scope MCP servers in Claude Code's
// config. A config that cannot be read or parsed is ErrorText with an
// empty list, still a 200.
type mcpJSON struct {
	ConfigPath string          `json:"config_path"`
	Exists     bool            `json:"exists"`
	ErrorText  string          `json:"error_text,omitempty"`
	Servers    []mcpServerJSON `json:"servers"`
}

// mcpServerJSON never carries the command, the args or env names: those
// can hold tokens. URL keeps scheme, host and path only.
type mcpServerJSON struct {
	Name    string `json:"name"`
	Stdio   bool   `json:"stdio"`
	Wrapped bool   `json:"wrapped"`
	Type    string `json:"type"`
	URL     string `json:"url"`
}

func (s *Server) mcpRoutes() []route {
	return []route{{"GET /api/mcp", http.HandlerFunc(s.handleMCP)}}
}

func (s *Server) handleMCP(w http.ResponseWriter, r *http.Request) {
	path := mcpconfig.UserConfigPath(s.opts.Paths.Home, s.opts.Environ)
	out := mcpJSON{ConfigPath: path, Servers: []mcpServerJSON{}}
	data, _, exists, err := mcpconfig.ReadConfig(path)
	out.Exists = exists
	if err != nil {
		out.ErrorText = err.Error()
		writeJSON(w, http.StatusOK, out)
		return
	}
	if !exists {
		writeJSON(w, http.StatusOK, out)
		return
	}
	list, err := mcpconfig.List(data)
	if err != nil {
		out.ErrorText = err.Error()
		writeJSON(w, http.StatusOK, out)
		return
	}
	for _, sv := range list {
		out.Servers = append(out.Servers, mcpServerJSON{Name: sv.Name, Stdio: sv.Stdio(), Wrapped: sv.Wrapped(), Type: sv.Type, URL: safeURL(sv.URL)})
	}
	writeJSON(w, http.StatusOK, out)
}

// safeURL drops userinfo, query and fragment, where a remote server's
// token can sit. A URL that does not parse is left out.
func safeURL(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	u.User, u.RawQuery, u.ForceQuery, u.Fragment, u.RawFragment = nil, "", false, "", ""
	return u.String()
}
