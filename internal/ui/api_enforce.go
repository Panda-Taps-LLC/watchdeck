package ui

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/claudesettings"
	"github.com/Panda-Taps-LLC/watchdeck/internal/manifest"
	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
	"github.com/Panda-Taps-LLC/watchdeck/internal/rulebook"
	"github.com/Panda-Taps-LLC/watchdeck/internal/settings"
)

const (
	nonceBytes = 16
	nonceTTL   = 5 * time.Minute
	maxNonces  = 64 // live nonces per purpose; the oldest of that purpose is dropped beyond this

	targetUser    = "user"
	targetProject = "project"

	// projectNote rides on the project target: managed (admin) settings
	// can require the sandbox, and then Claude Code ignores
	// sandbox.excludedCommands from project settings, so `watchdeck run`
	// would stay nested and fail closed.
	projectNote = "Under an admin-required sandbox, sandbox.excludedCommands in project settings is ignored."
)

// enforceJSON is GET /api/enforce.
type enforceJSON struct {
	Targets         []enforceTarget `json:"targets"`
	Nonce           string          `json:"nonce"`
	NonceTTLSeconds int             `json:"nonceTtlSeconds"`
}

// enforceTarget is one settings file. Status is settings.Inspect with
// camelCase keys (hookInstalled, skillHook, deniedHook, excluded,
// sandboxEnabled, complete, hookCommand, exists), the same encoding as
// /api/status "hook". A file that does not parse has Error instead.
type enforceTarget struct {
	ID     string         `json:"id"`
	Path   string         `json:"path"`
	Exists bool           `json:"exists"`
	Status map[string]any `json:"status,omitempty"`
	Error  string         `json:"error,omitempty"`
	Note   string         `json:"note,omitempty"`
}

// enforceRequest is the POST body.
type enforceRequest struct {
	Target string `json:"target"`
	Action string `json:"action"`
	Nonce  string `json:"nonce"`
}

// changeJSON is settings.Change for the page.
type changeJSON struct {
	Added   []string `json:"added"`
	Removed []string `json:"removed"`
	Backup  string   `json:"backup"`
}

type enforceResult struct {
	Change changeJSON     `json:"change"`
	Status map[string]any `json:"status"`
}

func (s *Server) enforceRoutes() []route {
	return []route{
		{"GET /api/enforce", http.HandlerFunc(s.handleEnforceGet)},
		{"POST /api/enforce", http.HandlerFunc(s.handleEnforcePost)},
	}
}

// handleEnforceGet reports the user target and, when cwd is inside a
// project (Options.Settings returns a non-empty project path), the project
// target, plus a fresh one-use nonce for the POST.
func (s *Server) handleEnforceGet(w http.ResponseWriter, r *http.Request) {
	cwd, err := s.cwdFor(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	user, project := s.settingsForRequest(cwd)
	out := enforceJSON{
		Targets:         []enforceTarget{inspectTarget(targetUser, user)},
		NonceTTLSeconds: int(nonceTTL / time.Second),
	}
	if project != "" {
		t := inspectTarget(targetProject, project)
		t.Note = projectNote
		out.Targets = append(out.Targets, t)
	}
	nonce, err := s.issueNonce(purposeEnforce)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out.Nonce = nonce
	writeJSON(w, http.StatusOK, out)
}

// handleEnforcePost installs or uninstalls the hooks in one target. The
// nonce from a GET is required (400 when absent) and is spent by the first
// POST that presents it, whatever the outcome; an unknown, spent or expired
// one is 403 "stale nonce". The body is validated before the nonce is
// looked up, so a malformed request does not spend it.
func (s *Server) handleEnforcePost(w http.ResponseWriter, r *http.Request) {
	var body enforceRequest
	if !readJSON(w, r, &body) {
		return
	}
	if body.Nonce == "" {
		writeError(w, http.StatusBadRequest, "nonce is required: GET /api/enforce first")
		return
	}
	if body.Target != targetUser && body.Target != targetProject {
		writeError(w, http.StatusBadRequest, `target must be "user" or "project"`)
		return
	}
	if body.Action != "install" && body.Action != "uninstall" {
		writeError(w, http.StatusBadRequest, `action must be "install" or "uninstall"`)
		return
	}
	cwd, err := s.cwdFor(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !s.spendNonce(body.Nonce, purposeEnforce) {
		writeError(w, http.StatusForbidden, "stale nonce")
		return
	}

	user, project := s.settingsForRequest(cwd)
	path := user
	if body.Target == targetProject {
		path = project
	}
	if path == "" {
		writeError(w, http.StatusBadRequest, "no project settings target: the current directory is not inside a git repository")
		return
	}

	// s.mu serialises file edits made through the dashboard (overrides
	// and settings alike).
	s.mu.Lock()
	var ch settings.Change
	if body.Action == "install" {
		if s.opts.Binary == "" {
			s.mu.Unlock()
			writeError(w, http.StatusInternalServerError, "install refused: the server does not know its own binary path")
			return
		}
		// M6.3: plus the tool groups the policy has rules or gates for
		projectPolicy := ""
		if root := paths.ProjectRoot(cwd, s.opts.Paths.Home); root != "" {
			projectPolicy = filepath.Join(root, manifest.ProjectOverridesFile)
		}
		// A file tool is left unhooked only for pack rules whose recommended
		// native rules are installed for this target: managed and user
		// settings for a user install, plus the project's own files for a
		// project install (read once per request, never in the hook). A read
		// error covers nothing, which keeps every hook.
		nativeRoot := ""
		if body.Target == targetProject {
			nativeRoot = filepath.Dir(filepath.Dir(path)) // <root>/.claude/settings.json
		}
		var covered []string
		if eff, rerr := claudesettings.Read(claudesettings.Locate(s.opts.Paths, nativeRoot), nil); rerr == nil {
			covered = rulebook.CoveredTwins(eff)
		}
		extra := settings.NeededExtra(filepath.Join(s.opts.Paths.ConfigDir, "overrides.yaml"), projectPolicy, covered)
		ch, err = settings.InstallWith(path, s.opts.Binary, extra)
	} else {
		ch, err = settings.Uninstall(path)
	}
	s.mu.Unlock()
	if err != nil {
		writeError(w, http.StatusInternalServerError, body.Action+" "+path+": "+err.Error())
		return
	}

	res := enforceResult{
		Change: changeJSON{Added: ch.Added, Removed: ch.Removed, Backup: ch.Backup},
		Status: hookStatus(path),
	}
	if res.Change.Added == nil {
		res.Change.Added = []string{}
	}
	if res.Change.Removed == nil {
		res.Change.Removed = []string{}
	}
	delete(res.Status, "path")
	writeJSON(w, http.StatusOK, res)
}

// inspectTarget inspects one settings file. Exists comes from the file
// system so it is meaningful when the file does not parse.
func inspectTarget(id, path string) enforceTarget {
	t := enforceTarget{ID: id, Path: path}
	if _, err := os.Stat(path); err == nil {
		t.Exists = true
	}
	st := hookStatus(path)
	if e, ok := st["error"].(string); ok {
		t.Error = e
		return t
	}
	delete(st, "path")
	t.Status = st
	return t
}

// Nonce purposes: a nonce is good only for the route that issued it, so an
// enforce nonce cannot stop the server and a shutdown nonce cannot edit
// settings.
const (
	purposeEnforce  = "enforce"
	purposeShutdown = "shutdown"
	purposeConfig   = "config"
	purposeRules    = "rules"
	purposeNeeds    = "needs"
)

// issueNonce mints a nonce for purpose, first pruning expired ones and
// then, at the cap, the oldest of the same purpose. The pool is shared but
// the cap is per purpose, so a busy Home tab's needs nonces never evict
// another tab's rules or enforce nonce (final review of Plan 04, finding 5).
func (s *Server) issueNonce(purpose string) (string, error) {
	b := make([]byte, nonceBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	n := hex.EncodeToString(b)
	now := s.opts.Now()
	s.nonceMu.Lock()
	defer s.nonceMu.Unlock()
	for k, at := range s.nonces {
		if now.Sub(at) > nonceTTL {
			delete(s.nonces, k)
		}
	}
	prefix := purpose + ":"
	for {
		live, oldest, first := 0, "", true
		var oldestAt time.Time
		for k, at := range s.nonces {
			if !strings.HasPrefix(k, prefix) {
				continue
			}
			live++
			if first || at.Before(oldestAt) {
				oldest, oldestAt, first = k, at, false
			}
		}
		if live < maxNonces {
			break
		}
		delete(s.nonces, oldest)
	}
	s.nonces[purpose+":"+n] = now
	return n, nil
}

// spendNonce removes n and reports whether it was issued for purpose and
// is still within its TTL. A nonce of another purpose is left alone.
func (s *Server) spendNonce(n, purpose string) bool {
	now := s.opts.Now()
	s.nonceMu.Lock()
	defer s.nonceMu.Unlock()
	key := purpose + ":" + n
	at, ok := s.nonces[key]
	if !ok {
		return false
	}
	delete(s.nonces, key)
	return now.Sub(at) <= nonceTTL
}
