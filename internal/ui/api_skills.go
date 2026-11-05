package ui

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/audit"
	"github.com/Panda-Taps-LLC/watchdeck/internal/manifest"
	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
	"github.com/Panda-Taps-LLC/watchdeck/internal/policy"
	"github.com/Panda-Taps-LLC/watchdeck/internal/safeio"
	"github.com/Panda-Taps-LLC/watchdeck/internal/skills"
)

// maxManifestText caps the PERMISSIONS.yaml text returned by
// /api/skills/{name}; a real manifest is a few hundred bytes.
const maxManifestText = 256 << 10

// maxSkillsCache bounds the /api/skills reports kept (one per project asked for).
const maxSkillsCache = 32

// OverrideJSON mirrors one block of overrides.yaml. Keys follow the YAML
// (auto_allow), absent keys are not set; caches appears only when true, as
// in the file.
type OverrideJSON struct {
	Network   *string  `json:"network,omitempty"`
	Write     []string `json:"write,omitempty"`
	Read      []string `json:"read,omitempty"`
	Env       []string `json:"env,omitempty"`
	Caches    *bool    `json:"caches,omitempty"`
	AutoAllow *bool    `json:"auto_allow,omitempty"`
}

// EditJSON is the body of POST /api/skills/{name}/grant: manifest.Edit in
// JSON. Unknown keys are a 400, so a misspelt field never silently no-ops.
type EditJSON struct {
	Network        *string  `json:"network,omitempty"`
	ClearNetwork   bool     `json:"clearNetwork,omitempty"`
	AddWrite       []string `json:"addWrite,omitempty"`
	RemoveWrite    []string `json:"removeWrite,omitempty"`
	AddRead        []string `json:"addRead,omitempty"`
	RemoveRead     []string `json:"removeRead,omitempty"`
	AddEnv         []string `json:"addEnv,omitempty"`
	RemoveEnv      []string `json:"removeEnv,omitempty"`
	Caches         *bool    `json:"caches,omitempty"`
	AutoAllow      *bool    `json:"autoAllow,omitempty"`
	ClearAutoAllow bool     `json:"clearAutoAllow,omitempty"`
	Reset          bool     `json:"reset,omitempty"`
}

// Edit converts e; an unknown network value is an error.
func (e EditJSON) Edit() (manifest.Edit, error) {
	out := manifest.Edit{
		ClearNetwork: e.ClearNetwork,
		AddWrite:     e.AddWrite, RemoveWrite: e.RemoveWrite,
		AddRead: e.AddRead, RemoveRead: e.RemoveRead,
		AddEnv: e.AddEnv, RemoveEnv: e.RemoveEnv,
		Caches: e.Caches, AutoAllow: e.AutoAllow,
		ClearAutoAllow: e.ClearAutoAllow, Reset: e.Reset,
	}
	if e.Network != nil {
		n, err := manifest.ParseNetwork(*e.Network)
		if err != nil {
			return manifest.Edit{}, err
		}
		out.Network = &n
	}
	return out, nil
}

// overrideJSON converts a block; an empty block is nil (JSON null).
func overrideJSON(o manifest.Override) *OverrideJSON {
	if o.Network == nil && len(o.Write) == 0 && len(o.Read) == 0 && len(o.Env) == 0 && !o.Caches && o.AutoAllow == nil {
		return nil
	}
	j := &OverrideJSON{Write: o.Write, Read: o.Read, Env: o.Env}
	if o.Network != nil {
		n := o.Network.String()
		j.Network = &n
	}
	if o.Caches {
		t := true
		j.Caches = &t
	}
	if o.AutoAllow != nil {
		v := *o.AutoAllow
		j.AutoAllow = &v
	}
	return j
}

// auditOptions are the options `watchdeck audit --verbose` would use from
// the server's cwd: user overrides from ConfigDir, the project's
// .watchdeck.yaml from the git root, CLAUDE_SKILL_DIR honoured.
func (s *Server) auditOptions(cwd string) audit.Options {
	o := s.opts
	roots := skills.Roots{Home: o.Paths.Home, Cwd: cwd}
	if v := o.Environ["CLAUDE_SKILL_DIR"]; v != "" {
		roots.Env = map[string]string{"CLAUDE_SKILL_DIR": v}
	}
	return audit.Options{
		Roots:       roots,
		UserCfgDir:  o.Paths.ConfigDir,
		ProjectRoot: paths.ProjectRoot(cwd, o.Paths.Home),
		Verbose:     true,
	}
}

// skillsReport is GET /api/skills: the `audit --json --verbose` report with
// the time it was built.
type skillsReport struct {
	audit.Report
	GeneratedAt string `json:"generatedAt"`
}

// handleSkills serves the cached report; ?refresh=1 rebuilds it, and the
// guard drops the cache on every POST.
func (s *Server) handleSkills(w http.ResponseWriter, r *http.Request) {
	cwd, err := s.cwdFor(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.skillsMu.Lock()
	defer s.skillsMu.Unlock()
	if s.skillsCache == nil {
		s.skillsCache = map[string][]byte{}
	}
	if r.URL.Query().Get("refresh") == "1" {
		delete(s.skillsCache, cwd)
	}
	body, ok := s.skillsCache[cwd]
	if !ok {
		rep, err := audit.Build(s.auditOptions(cwd))
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		b, err := json.Marshal(skillsReport{Report: rep, GeneratedAt: s.opts.Now().UTC().Format(time.RFC3339)})
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		body = append(b, '\n')
		if len(s.skillsCache) >= maxSkillsCache {
			clear(s.skillsCache) // one report per project; a handful at most in practice
		}
		s.skillsCache[cwd] = body
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

// invalidateSkills drops the cached /api/skills report.
func (s *Server) invalidateSkills() {
	s.skillsMu.Lock()
	s.skillsCache = nil
	s.skillsMu.Unlock()
}

// skillDetail is GET /api/skills/{name}.
type skillDetail struct {
	Row          audit.Row     `json:"row"`
	Override     *OverrideJSON `json:"override"`             // this skill's block in the user overrides file
	Defaults     *OverrideJSON `json:"defaults"`             // the user file's defaults block
	ManifestText *string       `json:"manifestText"`         // PERMISSIONS.yaml as written; null without one
	ParseError   string        `json:"parseError,omitempty"` // overrides.yaml does not parse: override/defaults are null and row ignores the user file
}

func (s *Server) handleSkill(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "*" || !manifest.ValidSkillName(name) {
		writeError(w, http.StatusNotFound, "unknown skill")
		return
	}
	cwd, err := s.cwdFor(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// A malformed user overrides file does not hide the skill: the row is
	// built without it and the parse error is reported beside it.
	opts := s.auditOptions(cwd)
	ov, _, perr := manifest.LoadOverridesFile(s.opts.Paths.OverridesFile())
	if perr != nil {
		opts.UserCfgDir = ""
	}
	row, ok, err := audit.BuildOne(name, opts)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "unknown skill")
		return
	}
	d := skillDetail{Row: row}
	if perr != nil {
		d.ParseError = perr.Error()
	} else {
		d.Override, d.Defaults = overrideJSON(ov.Skills[name]), overrideJSON(ov.Defaults)
	}
	if row.ManifestPath != "" {
		if text, ok := readCapped(row.ManifestPath, maxManifestText); ok {
			d.ManifestText = &text
		}
	}
	writeJSON(w, http.StatusOK, d)
}

// readCapped reads path when it is a regular file of at most limit bytes.
// It goes through safeio like the parser: a skill dir can ship
// PERMISSIONS.yaml as a FIFO or a symlink to /dev/tty, which a plain open
// or read would wait on forever.
func readCapped(path string, limit int64) (string, bool) {
	b, err := safeio.ReadRegular(path, limit, false)
	if err != nil {
		return "", false
	}
	return string(b), true
}

// grantResult is the answer to POST /api/skills/{name}/grant.
type grantResult struct {
	Row           *audit.Row `json:"row"`          // null for "*" and for a name no installed skill has
	Changed       bool       `json:"changed"`      // false when the file already said so
	AllowCommand  *string    `json:"allowCommand"` // the equivalent `watchdeck allow` line; null when the edit has no CLI form
	OverridesPath string     `json:"overridesPath"`
}

// handleGrant applies an EditJSON to the user overrides file. Under s.mu it
// re-reads the file (the CLI may have written it since), applies the edit
// with policy.Apply (manifest.Apply semantics; validates by re-parsing) and
// saves atomically with policy.Save. "*" (sent as %2A) edits the defaults block.
// A name with no installed skill is accepted, as with `watchdeck allow`,
// so the Grants page can revoke a block whose skill is gone.
func (s *Server) handleGrant(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !manifest.ValidSkillName(name) {
		writeError(w, http.StatusBadRequest, "invalid skill name (letters, digits, '.', '_', '-' or \"*\")")
		return
	}
	cwd, err := s.cwdFor(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var body EditJSON
	if !readJSON(w, r, &body) {
		return
	}
	edit, err := body.Edit()
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	path := s.opts.Paths.OverridesFile()
	changed, err := s.applyEdit(path, name, edit)
	if err != nil {
		var bad badEdit
		if errors.As(err, &bad) {
			writeError(w, http.StatusBadRequest, bad.Error())
		} else {
			writeError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	s.invalidateSkills()

	res := grantResult{Changed: changed, OverridesPath: path}
	if cmd, ok := manifest.AllowCommand(name, edit); ok {
		res.AllowCommand = &cmd
	}
	if name != "*" {
		row, ok, err := audit.BuildOne(name, s.auditOptions(cwd))
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if ok {
			res.Row = &row
		}
	}
	writeJSON(w, http.StatusOK, res)
}

// badEdit marks an edit manifest.Apply refused (a 400, not a 500).
type badEdit struct{ error }

// applyEdit is policy.LoadFile → policy.Apply → policy.Save under s.mu (the
// file is saved as policy file v2 with a .bak-<ts> of the previous one). edit.Home is always
// the server's own home (never a client value; EditJSON has no such key), so
// Apply refuses an absolute or symlinked spelling of a built-in deny path
// (<home>/.ssh, a link to it) exactly as `watchdeck allow` does.
func (s *Server) applyEdit(path, name string, edit manifest.Edit) (bool, error) {
	edit.Home = s.opts.Paths.Home
	s.mu.Lock()
	defer s.mu.Unlock()
	f, _, err := policy.LoadFile(path)
	if err != nil {
		return false, err
	}
	changed, err := policy.Apply(&f, policy.Edit{Kind: policy.KindSkill, Name: name, Grant: edit})
	if err != nil {
		return false, badEdit{err}
	}
	if !changed {
		return false, nil
	}
	if _, err := policy.Save(path, f); err != nil {
		return false, err
	}
	return true, nil
}

// overridesView is GET /api/overrides.
type overridesView struct {
	Path       string                  `json:"path"`
	Exists     bool                    `json:"exists"`
	Text       string                  `json:"text"` // the file as written; "" when absent
	ParseError string                  `json:"parseError,omitempty"`
	Defaults   *OverrideJSON           `json:"defaults"`
	Skills     map[string]OverrideJSON `json:"skills"`
}

func (s *Server) handleOverrides(w http.ResponseWriter, r *http.Request) {
	path := s.opts.Paths.OverridesFile()
	v := overridesView{Path: path, Skills: map[string]OverrideJSON{}}
	s.mu.Lock()
	b, rerr := manifest.ReadPolicyFile(path) // O_NONBLOCK, regular files only, 1 MiB cap
	s.mu.Unlock()
	switch {
	case errors.Is(rerr, os.ErrNotExist):
		writeJSON(w, http.StatusOK, v)
		return
	case rerr != nil:
		writeError(w, http.StatusInternalServerError, rerr.Error())
		return
	}
	v.Exists, v.Text = true, string(b)
	o, err := manifest.ParseOverrides(b)
	if err != nil {
		v.ParseError = err.Error()
		writeJSON(w, http.StatusOK, v)
		return
	}
	v.Defaults = overrideJSON(o.Defaults)
	for n, blk := range o.Skills {
		if j := overrideJSON(blk); j != nil {
			v.Skills[n] = *j
		}
	}
	writeJSON(w, http.StatusOK, v)
}
