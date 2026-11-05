package ui

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/claudesettings"
	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
	"github.com/Panda-Taps-LLC/watchdeck/internal/rulebook"
)

// rulesJSON is GET /api/rules: the rulebook as the Rules page draws it.
// Groups, Recommended and Warnings are rulebook's own types; Drift and
// Files go through view types because claudesettings.Drift and FileState
// carry no json tags (and FileState.Err would marshal as {}). Home is the
// account home, for the page's "~/…" scope labels; ProjectRoot is "" when
// the request has no project (auto mode without ?project=).
type rulesJSON struct {
	Groups          []rulebook.Group `json:"groups"`
	Recommended     []rulebook.Rule  `json:"recommended"`
	Drift           []driftJSON      `json:"drift"`
	Files           []fileJSON       `json:"files"`
	Warnings        []string         `json:"warnings"`
	ProjectRoot     string           `json:"project_root"`
	Home            string           `json:"home"`
	Updated         string           `json:"updated"`
	Nonce           string           `json:"nonce"`
	NonceTTLSeconds int              `json:"nonce_ttl_seconds"`
	// Temporaries are the user policy file's temporaries in force (Plan
	// 08): paused rules and timed grants. Never null.
	Temporaries []rulebook.TemporaryView `json:"temporaries"`
}

// driftJSON is one ledger entry whose string the person removed by hand.
type driftJSON struct {
	Value   string   `json:"value"`
	File    string   `json:"file"`
	Key     string   `json:"key"`
	RuleIDs []string `json:"rule_ids"`
	Reason  string   `json:"reason"`
}

// fileJSON is one settings file List read (or tried to). Error is the
// read or parse error's text, "" when the file read cleanly or is absent.
type fileJSON struct {
	Scope    string `json:"scope"`
	Path     string `json:"path"`
	ReadOnly bool   `json:"read_only"`
	Exists   bool   `json:"exists"`
	Error    string `json:"error"`
}

// proposeRequest is the POST /api/rules/propose body.
type proposeRequest struct {
	Request rulebook.AddRequest `json:"request"`
}

// proposeJSON is its answer: the writes Apply would make. Suggested is
// null unless the plan offers a hook twin.
// A request Propose refuses answers Plan null and Refused the reason.
type proposeJSON struct {
	Plan    *planJSON `json:"plan"`
	Refused string    `json:"refused"`
}

type planJSON struct {
	Steps     []rulebook.Step      `json:"steps"`
	Suggested *rulebook.AddRequest `json:"suggested"`
}

func (s *Server) rulesRoutes() []route {
	return []route{
		{"GET /api/rules", http.HandlerFunc(s.handleRules)},
		{"POST /api/rules/propose", http.HandlerFunc(s.handlePropose)},
		{"POST /api/rules", http.HandlerFunc(s.handleRulesWrite)},
		{"POST /api/rules/recommended", http.HandlerFunc(s.handleRecommendedWrite)},
	}
}

// rulebookInput is the rulebook Input for a request: the server's paths
// and the project root of cwdFor(r) (?project=, else the server's Cwd).
func (s *Server) rulebookInput(r *http.Request) (rulebook.Input, error) {
	cwd, err := s.cwdFor(r)
	if err != nil {
		return rulebook.Input{}, err
	}
	return rulebook.Input{Paths: s.opts.Paths, ProjectRoot: paths.ProjectRoot(cwd, s.opts.Paths.Home)}, nil
}

// handleRules answers GET /api/rules[?project=]. A settings file that
// cannot be read is a row in files with its error text (and a warning);
// the rest of the book is still there. Only a failure of List itself is
// a 500. Each GET mints a nonce for the rules write routes.
func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	in, err := s.rulebookInput(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	book, err := rulebook.List(in)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	nonce, err := s.issueNonce(purposeRules)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := rulesJSON{
		Groups:          book.Groups,
		Recommended:     book.Recommended,
		Drift:           driftView(book.Drift),
		Files:           filesView(book.Files),
		Warnings:        book.Warnings,
		ProjectRoot:     in.ProjectRoot,
		Home:            s.opts.Paths.Home,
		Updated:         book.Updated.UTC().Format(time.RFC3339),
		Nonce:           nonce,
		NonceTTLSeconds: int(nonceTTL / time.Second),
		Temporaries:     rulebook.ListTemporaries(in),
	}
	if out.Groups == nil {
		out.Groups = []rulebook.Group{}
	}
	if out.Recommended == nil {
		out.Recommended = []rulebook.Rule{}
	}
	if out.Warnings == nil {
		out.Warnings = []string{}
	}
	writeJSON(w, http.StatusOK, out)
}

// driftView is never null; RuleIDs falls back to an older entry's lone
// RuleID.
func driftView(ds []claudesettings.Drift) []driftJSON {
	out := make([]driftJSON, 0, len(ds))
	for _, d := range ds {
		ids := append([]string{}, d.Entry.RuleIDs...)
		if len(ids) == 0 && d.Entry.RuleID != "" {
			ids = []string{d.Entry.RuleID}
		}
		out = append(out, driftJSON{Value: d.Entry.Value, File: d.Entry.Path, Key: d.Entry.Key, RuleIDs: ids, Reason: d.Reason})
	}
	return out
}

// filesView is never null.
func filesView(fs []claudesettings.FileState) []fileJSON {
	out := make([]fileJSON, 0, len(fs))
	for _, f := range fs {
		e := ""
		if f.Err != nil {
			e = f.Err.Error()
		}
		out = append(out, fileJSON{Scope: string(f.Scope), Path: f.Path, ReadOnly: f.ReadOnly, Exists: f.Exists, Error: e})
	}
	return out
}

// handlePropose answers POST /api/rules/propose: the plan for one
// AddRequest. It reads and writes nothing, so it takes no nonce; the guard
// (Origin, Sec-Fetch-Site, JSON, bearer) still applies. A request Propose
// refuses (ErrScope, ErrValue, an unknown pack rule, a bad action) is a
// 200 with plan null and refused the specific reason (refusalReason), so a
// person typing a value the rulebook refuses sees the reason under the
// field and the browser logs no failed request; only a malformed body or a
// bad ?project= is a 400.
func (s *Server) handlePropose(w http.ResponseWriter, r *http.Request) {
	var body proposeRequest
	if !readJSON(w, r, &body) {
		return
	}
	in, err := s.rulebookInput(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	plan, err := rulebook.Propose(in, body.Request)
	if err != nil {
		writeJSON(w, http.StatusOK, proposeJSON{Refused: refusalReason(err)})
		return
	}
	steps := plan.Steps
	if steps == nil {
		steps = []rulebook.Step{}
	}
	writeJSON(w, http.StatusOK, proposeJSON{Plan: &planJSON{Steps: steps, Suggested: plan.Suggested}})
}

// refusalReason is a Propose refusal as the specific reason a person
// reads: without the "rulebook: " prefix, without the generic ErrValue or
// ErrScope sentence that wraps it, and without the quoted value when a
// reason follows it ("a(b": a native rule value cannot hold ( or ) reads
// "a native rule value cannot hold ( or )"). A bare sentinel keeps its own
// text. The error itself is unchanged, so errors.Is still works for every
// other caller.
func refusalReason(err error) string {
	msg := err.Error()
	for _, sentinel := range []error{rulebook.ErrValue, rulebook.ErrScope} {
		if errors.Is(err, sentinel) {
			if rest, ok := strings.CutPrefix(msg, sentinel.Error()+": "); ok {
				msg = rest
			}
			break
		}
	}
	msg = strings.TrimPrefix(msg, "rulebook: ")
	if q, qerr := strconv.QuotedPrefix(msg); qerr == nil {
		if rest, ok := strings.CutPrefix(msg[len(q):], ": "); ok && rest != "" {
			msg = rest
		}
	}
	return msg
}

// lockBusyMessage is the 409 text when another watchdeck command holds
// the settings lock.
const lockBusyMessage = "another watchdeck command holds the settings lock; try again"

// rulesWrite is the POST /api/rules body: exactly one of Add, Remove,
// EndTemporary,
// RemoveIntent, Set. Remove takes one row, even a row of an everywhere
// intent; RemoveIntent takes every row of the intent it names.
type rulesWrite struct {
	Nonce        string               `json:"nonce"`
	Add          *rulebook.AddRequest `json:"add,omitempty"`
	Remove       string               `json:"remove,omitempty"`
	RemoveIntent string               `json:"remove_intent,omitempty"`
	Set          *rulesSet            `json:"set,omitempty"`
	// EndTemporary ends a temporary by id (Plan 08; "all" ends every one).
	EndTemporary string `json:"end_temporary,omitempty"`
}

// rulesSet switches a pack rule on or off.
type rulesSet struct {
	ID      string `json:"id"`
	Enabled bool   `json:"enabled"`
}

// writeResult is the answer of the rules write routes: the files written,
// the backups taken, the rows the write touched, and a fresh nonce.
type writeResult struct {
	Written []string `json:"written"`
	Backups []string `json:"backups"`
	RowIDs  []string `json:"row_ids"`
	Nonce   string   `json:"nonce"`
	// Warning is set when the recommended install could not reconcile
	// first (rulebook.Reconcile); the install still ran.
	Warning string `json:"warning,omitempty"`
}

// writeErrBody is an error body that still hands the page a fresh nonce,
// used for every answer after the nonce was spent.
type writeErrBody struct {
	Error string `json:"error"`
	Nonce string `json:"nonce,omitempty"`
}

// recommendedWrite is the POST /api/rules/recommended body. IDs are row
// ids of recommended rules (rulebook.Recommended()[i].ID).
type recommendedWrite struct {
	Nonce  string   `json:"nonce"`
	Action string   `json:"action"`
	IDs    []string `json:"ids,omitempty"`
}

// declinedResult answers decline and undecline: the intent ids declined
// after the write.
type declinedResult struct {
	Declined []string `json:"declined"`
	Nonce    string   `json:"nonce"`
}

// spendAndRenew spends n for purpose and mints a fresh nonce for the
// answer. It writes the answer itself (500 when no nonce can be minted,
// 403 "stale nonce" with the fresh one) and then returns ok false.
func (s *Server) spendAndRenew(w http.ResponseWriter, n, purpose string) (string, bool) {
	spent := s.spendNonce(n, purpose)
	fresh, err := s.issueNonce(purpose)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return "", false
	}
	if !spent {
		writeJSON(w, http.StatusForbidden, writeErrBody{Error: "stale nonce", Nonce: fresh})
		return "", false
	}
	return fresh, true
}

// writeStatus maps a write error to its status: the settings lock held
// elsewhere and a rule watchdeck did not add are 409, a scope or value
// rulebook refuses is 400, anything else 500. The lock gets a fixed
// message the page can show as is.
func writeStatus(err error) (int, string) {
	switch {
	case errors.Is(err, claudesettings.ErrLockTimeout):
		return http.StatusConflict, lockBusyMessage
	case errors.Is(err, rulebook.ErrNotOwned):
		return http.StatusConflict, err.Error()
	case errors.Is(err, rulebook.ErrScope), errors.Is(err, rulebook.ErrValue):
		return http.StatusBadRequest, err.Error()
	}
	return http.StatusInternalServerError, err.Error()
}

// failWrite writes err with the status writeStatus gives and the fresh nonce.
func failWrite(w http.ResponseWriter, err error, fresh string) {
	code, msg := writeStatus(err)
	writeJSON(w, code, writeErrBody{Error: msg, Nonce: fresh})
}

// resultJSON is res with never-null lists and the fresh nonce.
func resultJSON(res rulebook.Result, fresh string) writeResult {
	out := writeResult{Written: res.Written, Backups: res.Backups, RowIDs: res.RowIDs, Nonce: fresh}
	if out.Written == nil {
		out.Written = []string{}
	}
	if out.Backups == nil {
		out.Backups = []string{}
	}
	if out.RowIDs == nil {
		out.RowIDs = []string{}
	}
	return out
}

// findRow is the row of book with id, if any.
func findRow(book rulebook.Book, id string) (rulebook.Rule, bool) {
	for _, g := range book.Groups {
		for _, r := range g.Rows {
			if r.ID == id {
				return r, true
			}
		}
	}
	return rulebook.Rule{}, false
}

// removeRefused says whether Remove refuses row without writing anything:
// rows that are the person's to edit (auto mode, sandbox domains and
// exclusions), the skill defaults, and policy-file rules and subjects
// that live in a project file. Its refusal text is then a 400.
func removeRefused(row rulebook.Rule) bool {
	prefix, rest, _ := strings.Cut(row.ID, ":")
	switch prefix {
	case "automode", "domain", "excluded":
		return true
	case "subject":
		if rest == "skill:*" || strings.HasPrefix(rest, "skill:*:") {
			return true
		}
		return row.Scope == claudesettings.ScopeProject
	case "user":
		return row.Scope == claudesettings.ScopeProject
	}
	return false
}

// handleRulesWrite answers POST /api/rules: add (Propose, then Apply),
// remove (Remove, one row), remove_intent (RemoveIntent, every row of an
// everywhere intent) or set (SetEnabled on a pack row). The body's shape and
// the nonce's presence are checked first, without spending it (400). Then
// the nonce is spent (403 "stale nonce" when it is not good) and the write
// runs under the server's edit mutex; rulebook takes the settings lock
// itself. Every answer after the spend carries a fresh nonce.
func (s *Server) handleRulesWrite(w http.ResponseWriter, r *http.Request) {
	var body rulesWrite
	if !readJSON(w, r, &body) {
		return
	}
	if body.Nonce == "" {
		writeError(w, http.StatusBadRequest, "nonce is required: GET /api/rules first")
		return
	}
	n := 0
	if body.Add != nil {
		n++
	}
	if body.Remove != "" {
		n++
	}
	if body.RemoveIntent != "" {
		n++
	}
	if body.Set != nil {
		n++
	}
	if body.EndTemporary != "" {
		n++
	}
	if n != 1 {
		writeError(w, http.StatusBadRequest, "one of add, remove, remove_intent, set, end_temporary")
		return
	}
	in, err := s.rulebookInput(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	fresh, ok := s.spendAndRenew(w, body.Nonce, purposeRules)
	if !ok {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	var res rulebook.Result
	switch {
	case body.Add != nil:
		req := *body.Add
		// The ledger intent is never the page's to choose: a
		// "recommended:" intent would un-decline a recommended rule.
		req.IntentID = ""
		plan, err := rulebook.Propose(in, req)
		if err != nil {
			// A request Propose refuses is the page's mistake, as on
			// POST /api/rules/propose.
			writeJSON(w, http.StatusBadRequest, writeErrBody{Error: err.Error(), Nonce: fresh})
			return
		}
		if res, err = rulebook.Apply(in, plan); err != nil {
			failWrite(w, err, fresh)
			return
		}
		// A Grep and Glob rule holds only once they are watched.
		out := resultJSON(res, fresh)
		out.Warning = rulebook.SearchWatchWarning(in, plan)
		writeJSON(w, http.StatusOK, out)
		return
	case body.EndTemporary != "":
		if err := rulebook.End(in, body.EndTemporary); err != nil {
			if errors.Is(err, rulebook.ErrNoTemporary) {
				writeJSON(w, http.StatusBadRequest, writeErrBody{Error: err.Error(), Nonce: fresh})
				return
			}
			failWrite(w, err, fresh)
			return
		}
		res.RowIDs = []string{body.EndTemporary}
	case body.Remove != "":
		row, found, err := s.lookupRow(in, body.Remove)
		if err != nil {
			failWrite(w, err, fresh)
			return
		}
		if !found {
			writeJSON(w, http.StatusBadRequest, writeErrBody{Error: `rulebook: no rule "` + body.Remove + `"`, Nonce: fresh})
			return
		}
		if kind, name, base, ok := subjectEntry(body.Remove); ok {
			// A later row of a subject is one of its entries, but Remove
			// deletes the whole subject: refuse rather than loosen more
			// than the person clicked.
			writeJSON(w, http.StatusBadRequest, writeErrBody{
				Error: "remove the " + kind + " " + name + " from its first row (" + base + "); this row is one of its entries",
				Nonce: fresh,
			})
			return
		}
		before, _ := rowIDs(in)
		res, err = rulebook.Remove(in, body.Remove)
		if err == nil && strings.HasPrefix(body.Remove, "subject:") {
			// The whole subject went: report every row that disappeared.
			if after, aerr := rowIDs(in); aerr == nil && before != nil {
				gone := []string{}
				for _, id := range before.order {
					if !after.set[id] {
						gone = append(gone, id)
					}
				}
				if len(gone) > 0 {
					res.RowIDs = gone
				}
			}
		}
		if err != nil {
			if removeRefused(row) && !errors.Is(err, claudesettings.ErrLockTimeout) {
				writeJSON(w, http.StatusBadRequest, writeErrBody{Error: err.Error(), Nonce: fresh})
				return
			}
			failWrite(w, err, fresh)
			return
		}
	case body.RemoveIntent != "":
		// An intent id that is not one, or names nothing left, is the
		// page's mistake (400); the lock and ownership keep their codes.
		if res, err = rulebook.RemoveIntent(in, body.RemoveIntent); err != nil {
			if len(res.Written) == 0 && !errors.Is(err, claudesettings.ErrLockTimeout) && !errors.Is(err, rulebook.ErrNotOwned) {
				writeJSON(w, http.StatusBadRequest, writeErrBody{Error: err.Error(), Nonce: fresh})
				return
			}
			failWrite(w, err, fresh)
			return
		}
	default:
		_, found, err := s.lookupRow(in, body.Set.ID)
		if err != nil {
			failWrite(w, err, fresh)
			return
		}
		if !found {
			writeJSON(w, http.StatusBadRequest, writeErrBody{Error: `rulebook: no rule "` + body.Set.ID + `"`, Nonce: fresh})
			return
		}
		if !strings.HasPrefix(body.Set.ID, "pack:") {
			// SetEnabled refuses any other row before it writes; its
			// sentence says what to do instead.
			_, err := rulebook.SetEnabled(in, body.Set.ID, body.Set.Enabled)
			msg := "only pack rules can be switched"
			if err != nil {
				msg = err.Error()
			}
			writeJSON(w, http.StatusBadRequest, writeErrBody{Error: msg, Nonce: fresh})
			return
		}
		if res, err = rulebook.SetEnabled(in, body.Set.ID, body.Set.Enabled); err != nil {
			failWrite(w, err, fresh)
			return
		}
	}
	writeJSON(w, http.StatusOK, resultJSON(res, fresh))
}

// lookupRow lists the rulebook for in and finds the row id.
func (s *Server) lookupRow(in rulebook.Input, id string) (rulebook.Rule, bool, error) {
	book, err := rulebook.List(in)
	if err != nil {
		return rulebook.Rule{}, false, err
	}
	row, ok := findRow(book, id)
	return row, ok, nil
}

// subjectEntry reports whether id is a later row of a subject,
// subject:<kind>:<name>:<hex8>, and returns the subject's kind, name and
// first-row id subject:<kind>:<name>.
func subjectEntry(id string) (kind, name, base string, ok bool) {
	rest, isSubject := strings.CutPrefix(id, "subject:")
	if !isSubject {
		return "", "", "", false
	}
	parts := strings.SplitN(rest, ":", 3)
	if len(parts) != 3 {
		return "", "", "", false
	}
	return parts[0], parts[1], "subject:" + parts[0] + ":" + parts[1], true
}

// idSet is the row ids of a Book, in order and as a set.
type idSet struct {
	order []string
	set   map[string]bool
}

// rowIDs lists the rulebook for in and returns its row ids.
func rowIDs(in rulebook.Input) (*idSet, error) {
	book, err := rulebook.List(in)
	if err != nil {
		return nil, err
	}
	out := &idSet{set: map[string]bool{}}
	for _, g := range book.Groups {
		for _, r := range g.Rows {
			if !out.set[r.ID] {
				out.set[r.ID] = true
				out.order = append(out.order, r.ID)
			}
		}
	}
	return out, nil
}

// recommendedByID maps the requested row ids to recommended rules. An id
// that names no recommended rule is an error naming it.
func recommendedByID(ids []string) ([]rulebook.Rule, error) {
	all := rulebook.Recommended()
	out := make([]rulebook.Rule, 0, len(ids))
	for _, id := range ids {
		found := false
		for _, r := range all {
			if r.ID == id {
				out = append(out, r)
				found = true
				break
			}
		}
		if !found {
			return nil, errors.New(`rulebook: "` + id + `" is not a recommended rule`)
		}
	}
	return out, nil
}

// handleRecommendedWrite answers POST /api/rules/recommended.
//
//	install    ids empty: the offer (missing rules the person has not
//	           declined); ids given: those recommended rules, declined or
//	           not, that are still missing (a string already in a
//	           settings file is never claimed). Apply un-declines what it
//	           writes. Answer: writeResult.
//	decline    the rules' intent ids go on the declined list.
//	undecline  they come off it. Answer: {"declined": [...], "nonce"}.
//
// The action, the ids' presence for decline and undecline, and the ids
// themselves (the recommended set is fixed) are checked before the nonce
// is spent.
func (s *Server) handleRecommendedWrite(w http.ResponseWriter, r *http.Request) {
	var body recommendedWrite
	if !readJSON(w, r, &body) {
		return
	}
	if body.Nonce == "" {
		writeError(w, http.StatusBadRequest, "nonce is required: GET /api/rules first")
		return
	}
	switch body.Action {
	case "install":
	case "decline", "undecline":
		if len(body.IDs) == 0 {
			writeError(w, http.StatusBadRequest, body.Action+" needs ids")
			return
		}
	default:
		writeError(w, http.StatusBadRequest, "action must be install, decline or undecline")
		return
	}
	chosen, err := recommendedByID(body.IDs)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	in, err := s.rulebookInput(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	fresh, ok := s.spendAndRenew(w, body.Nonce, purposeRules)
	if !ok {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if body.Action != "install" {
		intents := make([]string, 0, len(chosen))
		for _, rule := range chosen {
			intents = append(intents, rulebook.IntentPrefix+rulebook.IntentID(rule.Value))
		}
		if body.Action == "decline" {
			err = rulebook.Decline(s.opts.Paths.StateDir, intents)
		} else {
			err = rulebook.Undecline(s.opts.Paths.StateDir, intents)
		}
		if err != nil {
			failWrite(w, err, fresh)
			return
		}
		d, err := rulebook.LoadDeclined(s.opts.Paths.StateDir)
		if err != nil {
			failWrite(w, err, fresh)
			return
		}
		out := declinedResult{Declined: d.IntentIDs, Nonce: fresh}
		if out.Declined == nil {
			out.Declined = []string{}
		}
		writeJSON(w, http.StatusOK, out)
		return
	}

	// A recommended rule the person removed by hand is declined before the
	// offer is computed, so Add all never puts it back (final review of
	// Plan 04, finding 2). A failed reconcile is a warning, never a block.
	var warning string
	if _, _, err := rulebook.Reconcile(in); err != nil {
		warning = err.Error()
	}
	eff, _ := claudesettings.Read(claudesettings.Locate(in.Paths, in.ProjectRoot), nil)
	missing := rulebook.RecommendedMissing(eff)
	var want []rulebook.Rule
	if len(chosen) == 0 {
		want = rulebook.RecommendedOffer(in, missing, false)
	} else {
		for _, c := range chosen {
			for _, m := range missing {
				if m.ID == c.ID {
					want = append(want, m)
					break
				}
			}
		}
	}
	if len(want) == 0 {
		out := resultJSON(rulebook.Result{}, fresh)
		out.Warning = warning
		writeJSON(w, http.StatusOK, out)
		return
	}
	plan, err := rulebook.RecommendedPlan(in, want)
	if err != nil {
		failWrite(w, err, fresh)
		return
	}
	res, err := rulebook.Apply(in, plan)
	if err != nil {
		failWrite(w, err, fresh)
		return
	}
	out := resultJSON(res, fresh)
	out.Warning = warning
	writeJSON(w, http.StatusOK, out)
}
