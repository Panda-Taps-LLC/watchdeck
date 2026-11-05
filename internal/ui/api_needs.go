package ui

import (
	"errors"
	"net/http"
	"path/filepath"
	"slices"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/claudesettings"
	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
	"github.com/Panda-Taps-LLC/watchdeck/internal/projectscope"
	"github.com/Panda-Taps-LLC/watchdeck/internal/rulebook"
	"github.com/Panda-Taps-LLC/watchdeck/internal/userconfig"
)

// needsJSON is GET /api/needs: the inbox. Since is where the window
// starts (installed_at, else seven days back), worked out the way
// rulebook.Open does; ActivityEnabled is false when the log is off, and
// then Items holds only leak watch items. LeakWatch is false under
// --no-transcripts (Options.Leaks nil), when no leak item can show.
// AllowFile is the policy file an allow writes, in display form.
type needsJSON struct {
	Items           []needItem `json:"items"`
	Count           int        `json:"count"`
	Since           string     `json:"since"`
	ActivityEnabled bool       `json:"activity_enabled"`
	LeakWatch       bool       `json:"leak_watch"`
	AllowFile       string     `json:"allow_file"`
	Nonce           string     `json:"nonce"`
	NonceTTLSeconds int        `json:"nonce_ttl_seconds"`
}

// needItem is an inbox item and its fixes ready to show: each of the
// item's Fix requests that Propose accepts, with the first step's
// sentence, mechanism and file. A fix Propose refuses is left out.
// Pausable is true when the item can be allowed for a while, and AllowFor
// says for which ("session", "1h"; never null), from rulebook.AllowFor
// (Plan 08 R10, R11): the page shows its allow buttons from these.
type needItem struct {
	rulebook.Item
	Fixes    []fixJSON `json:"fixes"`
	Pausable bool      `json:"pausable"`
	AllowFor []string  `json:"allow_for"`
}

// fixJSON is one fix. Steps and Files are every step's sentence and every
// file the fix writes (display form, in order, without repeats): an
// everywhere fix writes several rules into two or three files, and the
// confirm lists them all (Plan 08 D8). ProjectFiles are the files the same
// fix writes at project scope (add_rule with scope "project"), in the
// item's own project: empty when the item has no project or Propose
// refuses the fix at that scope (a pack rule, an MCP launch, a regex or
// text rule); never null. The decision sheet's "only in this project"
// is offered when it is non-empty.
type fixJSON struct {
	Index        int                 `json:"index"` // position in the item's fix list: the add_rule "fix" value
	Request      rulebook.AddRequest `json:"request"`
	Sentence     string              `json:"sentence"`
	Mechanism    string              `json:"mechanism"`
	File         string              `json:"file"`
	Steps        []string            `json:"steps"`
	Files        []string            `json:"files"`
	ProjectFiles []string            `json:"project_files"`
}

func (s *Server) needsRoutes() []route {
	return []route{
		{"GET /api/needs", http.HandlerFunc(s.handleNeeds)},
		{"POST /api/needs/{id}", http.HandlerFunc(s.handleNeedsWrite)},
	}
}

// handleNeeds answers GET /api/needs[?project=]. The Book from List is
// passed to Open so an item whose fix is already a rule is not listed. A
// settings file that does not parse is no reason to fail: List turns it
// into a warning. Each GET mints a nonce for the needs write routes.
func (s *Server) handleNeeds(w http.ResponseWriter, r *http.Request) {
	in, err := s.rulebookInput(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	out := needsJSON{
		Items:           []needItem{},
		Since:           s.inboxSince().UTC().Format(time.RFC3339),
		ActivityEnabled: s.opts.Paths.Activity != "",
		LeakWatch:       s.opts.Leaks != nil,
		AllowFile:       projectscope.Display(s.opts.Paths.OverridesFile(), s.opts.Paths.Home),
		NonceTTLSeconds: int(nonceTTL / time.Second),
	}
	items, err := s.inboxItems(in)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	for _, it := range items {
		allow := rulebook.AllowFor(it)
		if allow == nil {
			allow = []string{}
		}
		out.Items = append(out.Items, needItem{Item: it, Fixes: fixesFor(in, it.Project, it.Fix, s.opts.Paths.Home, s.projectScopeOK), Pausable: len(allow) > 0, AllowFor: allow})
	}
	out.Count = len(out.Items)
	nonce, err := s.issueNonce(purposeNeeds)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out.Nonce = nonce
	writeJSON(w, http.StatusOK, out)
}

// fixesFor runs Propose on each fix and keeps those it accepts, each with
// its Index in reqs (the value add_rule takes as fix); never null. File is
// the display form ("~/…" under home): the dialog only names it, and the
// write recomputes the real path from the raw fix. project is the item's
// Project (absolute or "~/…"; "" for none): ProjectFiles come from a
// second Propose of the fix at project scope with that root, which writes
// nothing. They are offered only when projectOK accepts the root
// (projectScopeOK: a git root on this machine, not the home directory,
// and one ?project= resolves), so the sheet never offers "only in this
// project" where the write would refuse it.
func fixesFor(in rulebook.Input, project string, reqs []rulebook.AddRequest, home string, projectOK func(root string) bool) []fixJSON {
	out := []fixJSON{}
	for i, req := range reqs {
		plan, err := rulebook.Propose(in, req)
		if err != nil || len(plan.Steps) == 0 {
			continue
		}
		st := plan.Steps[0]
		f := fixJSON{Index: i, Request: req, Sentence: st.Sentence, Mechanism: st.Mechanism, File: projectscope.Display(st.File, home), Steps: []string{}, Files: []string{}, ProjectFiles: []string{}}
		for _, x := range plan.Steps {
			f.Steps = append(f.Steps, rulebook.StepSentence(home, x))
			if d := projectscope.Display(x.File, home); !slices.Contains(f.Files, d) {
				f.Files = append(f.Files, d)
			}
		}
		if root := projectRootOf(project, home); project != "" && projectOK(root) {
			inP, reqP := in, req
			inP.ProjectRoot = root
			reqP.Scope = claudesettings.ScopeProject
			if planP, err := rulebook.Propose(inP, reqP); err == nil {
				for _, x := range planP.Steps {
					if d := projectscope.Display(x.File, home); !slices.Contains(f.ProjectFiles, d) {
						f.ProjectFiles = append(f.ProjectFiles, d)
					}
				}
			}
		}
		out = append(out, f)
	}
	return out
}

// projectRootOf is an item's Project as the absolute project root a
// project-scope fix is written for: the "~/…" display form expanded
// against home, cleaned.
func projectRootOf(project, home string) string {
	return filepath.Clean(projectscope.Expand(project, home))
}

// projectScopeOK says whether a fix may be scoped to root: a git root on
// this machine (paths.ProjectRoot, which the write resolves ?project= to),
// not the home directory (whose "project" settings file is the user file),
// and a root ?project= would accept (projectscope.Resolve: the server's
// cwd or a known project).
func (s *Server) projectScopeOK(root string) bool {
	home := s.opts.Paths.Home
	if root == "" || root == filepath.Clean(home) || paths.ProjectRoot(root, home) != root {
		return false
	}
	_, err := projectscope.Resolve(root, s.opts.Cwd, home, s.opts.ProjectRoots)
	return err == nil
}

// inboxSince mirrors rulebook.Open with a zero Since: installed_at from
// the config file, else DefaultInboxWindow back; a config that cannot be
// read means the window.
func (s *Server) inboxSince() time.Time {
	if cfg, err := userconfig.Load(s.opts.Paths.ConfigFile()); err == nil {
		if t, ok := cfg.InstalledAt(); ok {
			return t
		}
	}
	return s.opts.Now().Add(-rulebook.DefaultInboxWindow)
}

// needsWrite is the POST /api/needs/{id} body. Fix picks one of the
// item's fixes for add_rule (default the first); For is allow's while,
// "session" or "1h". Scope is add_rule's "" or "user" (the user files, as
// before) or "project": the fix written into the project the call
// happened in, which ?project= must name (the decision sheet's "only in
// this project"); any other action takes no scope.
type needsWrite struct {
	Nonce  string `json:"nonce"`
	Action string `json:"action"`
	Fix    int    `json:"fix,omitempty"`
	For    string `json:"for,omitempty"`
	Scope  string `json:"scope,omitempty"`
}

// projectScopeMismatch is the add_rule refusal when ?project= names a
// known project that is not the item's own. It names no path.
const projectScopeMismatch = "this fix can only be scoped to the project the call happened in; pass that project"

// needsResult answers it. Written, Backups and RowIDs are empty except
// for add_rule and an undo that removed rules; TemporaryIDs is empty
// except for allow. Warning is set when an everywhere path fix wrote a
// Grep and Glob rule that is not watched yet (rulebook.SearchWatchWarning).
type needsResult struct {
	ID           string   `json:"id"`
	Action       string   `json:"action"`
	Written      []string `json:"written"`
	Backups      []string `json:"backups"`
	RowIDs       []string `json:"row_ids"`
	TemporaryIDs []string `json:"temporary_ids"`
	Warning      string   `json:"warning,omitempty"`
	Nonce        string   `json:"nonce"`
}

// handleNeedsWrite answers POST /api/needs/{id}[?project=]:
//
//	add_rule     Propose + Apply on the item's fix, then an add_rule
//	             resolution naming every row the add wrote; with scope
//	             "project" the fix is written at project scope into the
//	             project ?project= resolved to, which must be the item's
//	             own (filepath.Clean of its Project expanded against
//	             home; anything else is a 400 that names no path), and
//	             the resolution carries that root so an undo from
//	             anywhere removes the rows
//	acknowledge  an acknowledge resolution
//	dismiss      a dismiss resolution carrying the item's Signature, so
//	             later items with the same kind, what and why stay out
//	allow        rulebook.Allow for "for" (session | 1h): an ask's rules
//	             paused, or a skill's request granted for an hour; then
//	             an allow resolution naming the temporaries (Plan 08)
//	undo         rulebook.Undo: cancels the latest resolution in force
//	             (removing the rules an add_rule wrote, an everywhere
//	             fix's intent as RemoveIntent does, ending an allow's
//	             temporaries) and reopens it
//
// The others need the id in the open list, read as GET /api/needs
// reads it (404 otherwise); undo looks at the resolutions instead, and
// nothing to undo is a 404 too. An item allow cannot take for that while
// (a native rule, auto mode, a person's no, a skill for one session) is a
// 409 whose error says why, and nothing is written. The action, fix's sign,
// for and scope (the word, that only add_rule takes one, and that scope
// "project" has a project root at all, which auto mode needs ?project=
// for) are checked before the nonce is spent, as is an unknown ?project=;
// every answer after the spend carries a fresh nonce. Resolutions are
// appended under the settings lock, so they line up with a CLI undo.
func (s *Server) handleNeedsWrite(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var body needsWrite
	if !readJSON(w, r, &body) {
		return
	}
	if body.Nonce == "" {
		writeError(w, http.StatusBadRequest, "nonce is required: GET /api/needs first")
		return
	}
	switch body.Action {
	case rulebook.ResolveAddRule, rulebook.ResolveAcknowledge, rulebook.ResolveDismiss, rulebook.ResolveUndo, rulebook.ResolveAllow:
	default:
		writeError(w, http.StatusBadRequest, "action must be add_rule, acknowledge, dismiss, undo or allow")
		return
	}
	if body.Fix < 0 {
		writeError(w, http.StatusBadRequest, "fix must be 0 or more")
		return
	}
	if body.Action == rulebook.ResolveAllow && body.For != rulebook.AllowSession && body.For != rulebook.AllowHour {
		writeError(w, http.StatusBadRequest, "for must be session or 1h")
		return
	}
	switch body.Scope {
	case "", string(claudesettings.ScopeUser), string(claudesettings.ScopeProject):
	default:
		writeError(w, http.StatusBadRequest, "scope must be user or project")
		return
	}
	if body.Scope != "" && body.Action != rulebook.ResolveAddRule {
		writeError(w, http.StatusBadRequest, "scope is for add_rule only")
		return
	}
	in, err := s.rulebookInput(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	projectScope := body.Action == rulebook.ResolveAddRule && body.Scope == string(claudesettings.ScopeProject)
	if projectScope && in.ProjectRoot == "" {
		writeError(w, http.StatusBadRequest, "scope project needs ?project= naming the project the call happened in")
		return
	}
	if projectScope && in.ProjectRoot == filepath.Clean(s.opts.Paths.Home) {
		// The home directory's project settings file is the user file.
		writeError(w, http.StatusBadRequest, "scope project is not for your home directory; add the rule everywhere instead")
		return
	}
	fresh, ok := s.spendAndRenew(w, body.Nonce, purposeNeeds)
	if !ok {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	out := needsResult{ID: id, Action: body.Action, Written: []string{}, Backups: []string{}, RowIDs: []string{}, TemporaryIDs: []string{}, Nonce: fresh}
	stateDir := s.opts.Paths.StateDir

	if body.Action == rulebook.ResolveUndo {
		res, err := rulebook.Undo(in, id)
		if err != nil {
			if errors.Is(err, rulebook.ErrNothingToUndo) {
				writeJSON(w, http.StatusNotFound, writeErrBody{Error: err.Error(), Nonce: fresh})
				return
			}
			failWrite(w, err, fresh)
			return
		}
		writeJSON(w, http.StatusOK, needsFill(out, res))
		return
	}

	item, found, err := s.openItem(in, id)
	if err != nil {
		failWrite(w, err, fresh)
		return
	}
	if !found {
		writeJSON(w, http.StatusNotFound, writeErrBody{Error: "no open inbox item " + id, Nonce: fresh})
		return
	}
	resolution := rulebook.Resolution{ID: id, Action: body.Action}
	switch body.Action {
	case rulebook.ResolveAddRule:
		if len(item.Fix) == 0 {
			writeJSON(w, http.StatusBadRequest, writeErrBody{Error: "this item has no rule to add", Nonce: fresh})
			return
		}
		if body.Fix >= len(item.Fix) {
			writeJSON(w, http.StatusBadRequest, writeErrBody{Error: "fix is out of range for this item", Nonce: fresh})
			return
		}
		req := item.Fix[body.Fix] // a copy: the item's fix list is not changed
		if projectScope {
			// Only the project the call happened in: a known root that
			// is another project is refused without naming either.
			if item.Project == "" || projectRootOf(item.Project, s.opts.Paths.Home) != in.ProjectRoot {
				writeJSON(w, http.StatusBadRequest, writeErrBody{Error: projectScopeMismatch, Nonce: fresh})
				return
			}
			req.Scope = claudesettings.ScopeProject
			resolution.Project = in.ProjectRoot
		}
		plan, err := rulebook.Propose(in, req)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, writeErrBody{Error: err.Error(), Nonce: fresh})
			return
		}
		res, err := rulebook.Apply(in, plan)
		if err != nil {
			failWrite(w, err, fresh)
			return
		}
		out = needsFill(out, res)
		out.Warning = rulebook.SearchWatchWarning(in, plan)
		if len(res.RowIDs) > 0 {
			resolution.RuleID, resolution.RuleIDs = res.RowIDs[0], res.RowIDs
		}
		if req.Everywhere && !projectScope {
			// Undo removes the intent, releasing only its own claims. An
			// intent id carries no scope (DESIGN section 14), so a
			// project-scope add keeps its rows instead: an undo then removes
			// those rows alone and a user-scope twin of the same value stays.
			resolution.IntentID = rulebook.IntentFor(req)
		}
	case rulebook.ResolveAllow:
		ids, err := rulebook.Allow(in, item, body.For)
		if errors.Is(err, rulebook.ErrAllowRefused) || errors.Is(err, rulebook.ErrNotPausable) {
			writeJSON(w, http.StatusConflict, writeErrBody{Error: err.Error(), Nonce: fresh})
			return
		}
		if err != nil {
			failWrite(w, err, fresh)
			return
		}
		out.TemporaryIDs = ids
		resolution.TemporaryIDs = ids
	case rulebook.ResolveDismiss:
		resolution.Signature = rulebook.Signature(item)
	}
	err = claudesettings.Locked(stateDir, func() error { return rulebook.Resolve(stateDir, resolution) })
	if err != nil {
		failWrite(w, err, fresh)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// inboxItems is the open inbox: the activity log's items when the log is
// on, and the leak watch items when Options.Leaks is set (they come from
// the session index, so they need no activity log; Plan 08 D4). Leaks is
// asked for every finding and rulebook.Open applies its own window. With
// neither source nothing is open.
func (s *Server) inboxItems(in rulebook.Input) ([]rulebook.Item, error) {
	if s.opts.Paths.Activity == "" && s.opts.Leaks == nil {
		return nil, nil
	}
	book, err := rulebook.List(in)
	if err != nil {
		return nil, err
	}
	ii := rulebook.InboxInput{Paths: s.opts.Paths, Book: &book}
	if s.opts.Leaks != nil {
		ii.Leaks = s.opts.Leaks(time.Time{})
	}
	return rulebook.Open(ii)
}

// openItem lists the inbox the way GET /api/needs does and finds id.
func (s *Server) openItem(in rulebook.Input, id string) (rulebook.Item, bool, error) {
	items, err := s.inboxItems(in)
	if err != nil {
		return rulebook.Item{}, false, err
	}
	for _, it := range items {
		if it.ID == id {
			return it, true, nil
		}
	}
	return rulebook.Item{}, false, nil
}

// needsFill copies res's lists into out, keeping them non-null.
func needsFill(out needsResult, res rulebook.Result) needsResult {
	if res.Written != nil {
		out.Written = res.Written
	}
	if res.Backups != nil {
		out.Backups = res.Backups
	}
	if res.RowIDs != nil {
		out.RowIDs = res.RowIDs
	}
	return out
}
