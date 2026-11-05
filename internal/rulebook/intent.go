package rulebook

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Panda-Taps-LLC/watchdeck/internal/claudesettings"
	"github.com/Panda-Taps-LLC/watchdeck/internal/manifest"
	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
	"github.com/Panda-Taps-LLC/watchdeck/internal/policy"
	"github.com/Panda-Taps-LLC/watchdeck/internal/settings"
	"github.com/Panda-Taps-LLC/watchdeck/internal/skills"
)

// An intent is one thing a person means ("never read this file", "no
// network to this host", "never run this command") written as every
// concrete rule that covers a route to it, all under one intent id:
//
//	intent:<what>:<fnv32a hex8 of the value as typed>
//
// The native strings are claimed in the ledger under that id; the policy
// file has no ledger, so its rule and subject carry the id in their names:
// the hook rule intent-<what>-<hex8>-bash and the tool subject
// intent-<what>-<hex8>. List reads membership back from both.

// intentPrefix starts every everywhere intent id.
const intentPrefix = "intent:"

// ErrEverywhere is Propose's error for an everywhere request it cannot
// cover. Its text never holds the value.
var ErrEverywhere = errors.New("rulebook: cover every route applies to a path, a host or a command")

// intentWhat reports whether w has an everywhere form.
func intentWhat(w What) bool {
	return w == WhatPath || w == WhatHost || w == WhatCommand
}

// IntentFor is the ledger intent a request's rules are claimed under:
// "intent:<what>:<hash8 of the value as typed>" when Everywhere is set on
// a path, host or command, else the request's own IntentID ("" meaning
// each native step's row id).
func IntentFor(req AddRequest) string {
	if req.Everywhere && intentWhat(req.What) {
		return intentPrefix + string(req.What) + ":" + hash8(req.Value)
	}
	return req.IntentID
}

// intentParts splits an everywhere intent id into its what and hex8.
func intentParts(id string) (what, h string, ok bool) {
	rest, found := strings.CutPrefix(id, intentPrefix)
	if !found {
		return "", "", false
	}
	what, h, found = strings.Cut(rest, ":")
	if !found || !intentWhat(What(what)) || !isHex8(h) {
		return "", "", false
	}
	return what, h, true
}

func isHex8(s string) bool {
	if len(s) != 8 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// intentSubjectName is the tool subject of an intent: intent-<what>-<hex8>.
func intentSubjectName(what, h string) string { return "intent-" + what + "-" + h }

// intentRuleID is the hook rule of an intent: intent-<what>-<hex8>-bash.
func intentRuleID(what, h string) string { return intentSubjectName(what, h) + "-bash" }

// intentOfRule reads the intent id back from a hook rule id
// (intent-<what>-<hex8>-bash); ok is false for any other id.
func intentOfRule(id string) (string, bool) {
	rest, found := strings.CutSuffix(id, "-bash")
	if !found {
		return "", false
	}
	return intentOfSubject(rest)
}

// intentOfSubject reads the intent id back from a tool subject name
// (intent-<what>-<hex8>); ok is false for any other name.
func intentOfSubject(name string) (string, bool) {
	rest, found := strings.CutPrefix(name, "intent-")
	if !found {
		return "", false
	}
	what, h, found := strings.Cut(rest, "-")
	if !found || !intentWhat(What(what)) || !isHex8(h) {
		return "", false
	}
	return intentPrefix + what + ":" + h, true
}

// firstIntent is the first everywhere intent among ledger claims, or "".
func firstIntent(ids []string) string {
	for _, id := range ids {
		if _, _, ok := intentParts(id); ok {
			return id
		}
	}
	return ""
}

// intentHint is what List learns about an intent while it builds rows:
// the value to name in its sentence (from the best row: the hook rule's
// first literal, which is the value as typed, then a tool gate's entry,
// then a native string's inner value) and its action.
type intentHint struct {
	value  string
	prio   int // lower wins; -1 none yet
	action string
}

// markIntent records that r belongs to intent id, naming value at prio.
func (b *builder) markIntent(r *Rule, id string, prio int, value string) {
	if id == "" {
		return
	}
	r.Intent = &IntentRef{ID: id}
	if b.intents == nil {
		b.intents = map[string]*intentHint{}
	}
	h := b.intents[id]
	if h == nil {
		h = &intentHint{prio: -1}
		b.intents[id] = h
	}
	if value != "" && (h.prio < 0 || prio < h.prio) {
		h.value, h.prio = value, prio
	}
	if h.action == "" || r.Action == "deny" {
		h.action = r.Action
	}
}

// nativeIntentValue is the value a native string names: the inside of
// Read(…), Edit(…) and WebFetch(domain:…), the prefix of Bash(… *), or a
// bare sandbox domain.
func nativeIntentValue(v string) string {
	tool, inner := splitRule(v)
	switch tool {
	case "WebFetch":
		return strings.TrimPrefix(inner, "domain:")
	case "Bash":
		return strings.TrimSuffix(inner, " *")
	case "Read", "Edit":
		return displayAbs(inner)
	}
	if inner == "" {
		return v
	}
	return inner
}

// intentSentence is one sentence for a whole intent.
func intentSentence(id string, h *intentHint) string {
	what, _, _ := intentParts(id)
	if h == nil || h.value == "" {
		return "Rules added together to cover every route"
	}
	v := verb(h.action)
	switch What(what) {
	case WhatPath:
		return v + " reading or changing " + h.value + ", by every route"
	case WhatHost:
		return v + " network access to " + h.value + ", by every route"
	}
	return v + " running " + h.value + ", by every route"
}

// fillIntents gives every row of an intent its sentence and row count.
func fillIntents(groups []Group, hints map[string]*intentHint) {
	count := map[string]int{}
	for _, g := range groups {
		for _, r := range g.Rows {
			if r.Intent != nil {
				count[r.Intent.ID]++
			}
		}
	}
	for gi := range groups {
		for ri := range groups[gi].Rows {
			r := &groups[gi].Rows[ri]
			if r.Intent == nil {
				continue
			}
			id := r.Intent.ID
			r.Intent = &IntentRef{ID: id, Sentence: intentSentence(id, hints[id]), Rows: count[id]}
		}
	}
}

// hostArgv0 are the programs a host intent's hook rule looks for: a Bash
// command naming the host through one of them is refused.
func hostArgv0() []string {
	return []string{"curl", "wget", "nc", "ncat", "telnet", "ssh", "scp", "sftp", "ftp", "rsync",
		"python", "python3", "node", "perl", "ruby", "php", "openssl", "git", "http", "https", "xh", "aria2c"}
}

// gateLists puts entry in the deny or ask list.
func gateLists(action, entry string) *manifest.GateLists {
	if action == "ask" {
		return &manifest.GateLists{Ask: []string{entry}}
	}
	return &manifest.GateLists{Deny: []string{entry}}
}

// tildify spells an absolute path under home as ~/…, else returns it.
func tildify(home, p string) string {
	switch {
	case home == "" || home == "/":
		return p
	case p == home:
		return "~"
	case strings.HasPrefix(p, home+"/"):
		return "~" + p[len(home):]
	}
	return p
}

// intentPolicyFile is the policy file an intent of scope writes: the user
// overrides file, or the project's own file for project scope (a deny or
// ask only narrows, which the project file may do).
func intentPolicyFile(in Input, scope claudesettings.Scope) string {
	if scope == claudesettings.ScopeProject {
		return filepath.Join(in.ProjectRoot, manifest.ProjectOverridesFile)
	}
	return in.Paths.OverridesFile()
}

// gatePath spells a path value in the tool gate's grammar: ~/… when it is
// under the home directory, else the absolute path (a project-scope
// relative path joined to the project root). A relative path at user
// scope names a different file in every working directory; the search
// tools' gate has no such form (**/… would make every search ask), so it
// is refused.
func gatePath(in Input, v string, scope claudesettings.Scope) (string, error) {
	c, err := anchorClean(v, scope)
	if err != nil {
		return "", err
	}
	home := filepath.Clean(in.Paths.Home)
	switch {
	case c == "~/":
		return "~", nil
	case strings.HasPrefix(c, "~/"):
		return c, nil
	case strings.HasPrefix(c, "//"):
		return tildify(home, c[1:]), nil
	case strings.HasPrefix(c, "./"):
		return "", errors.New("rulebook: cover every route needs an absolute path, a ~/ path or project scope for a relative one")
	}
	// project scope: /rel is relative to the project root
	return tildify(home, filepath.Join(in.ProjectRoot, c[1:])), nil
}

// pathLiterals are the spellings a Bash command may use for a path: as
// typed, with the home directory as ~, and with ~ expanded; deduplicated.
func pathLiterals(home, v string) []string {
	out := []string{v}
	add := func(s string) {
		for _, x := range out {
			if x == s {
				return
			}
		}
		out = append(out, s)
	}
	if home != "" && home != "/" {
		add(tildify(home, v))
		if strings.HasPrefix(v, "~/") {
			add(home + v[1:])
		}
	}
	return out
}

// plainHost reports whether h holds only what the tool gate's domain
// grammar takes (letters, digits, '.', '-'), so the policy file accepts it.
func plainHost(h string) bool {
	if h == "" || h[0] == '.' || h[0] == '-' {
		return false
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '-') {
			return false
		}
	}
	return true
}

// proposeEverywhere is Propose for an everywhere request:
//
//	path     Read(<a>) and Edit(<a>) as a plain path request writes them;
//	         a Grep|Glob tool subject on the gate spelling of the path;
//	         a Bash hook rule on the path's literal spellings
//	host     WebFetch(domain:<h>); for deny, <h> in
//	         sandbox.network.deniedDomains; a WebFetch tool subject on
//	         <h>; a Bash hook rule naming <h> after a network program
//	command  Bash(<prefix> *) and its twin hook rule (Everywhere implies
//	         Twin)
//
// Every step carries the intent id IntentFor gives; the subject and rule
// carry its hex8 in their names. A project-scope intent writes its native
// strings to the project settings and its subject and rule to the
// project's policy file.
func proposeEverywhere(in Input, req AddRequest) (Plan, error) {
	if !intentWhat(req.What) {
		return Plan{}, ErrEverywhere
	}
	intent := IntentFor(req)
	h := hash8(req.Value)
	name := intentSubjectName(string(req.What), h)
	ruleID := intentRuleID(string(req.What), h)

	nat := req
	nat.Everywhere, nat.IntentID = false, intent
	if req.What == WhatCommand {
		nat.Twin = true
	}
	var gate, host string
	if req.What == WhatPath {
		// Checked before the native rules so a refusal comes first.
		_, scope, err := nativeFile(in, req.Scope)
		if err != nil {
			return Plan{}, err
		}
		if err := checkNativeValue(req.Value); err != nil {
			return Plan{}, err
		}
		if gate, err = gatePath(in, req.Value, scope); err != nil {
			return Plan{}, err
		}
	}
	plan, err := proposeNative(in, nat)
	if err != nil {
		return Plan{}, err
	}
	plan.Suggested = nil
	if len(plan.Steps) == 0 || plan.Steps[0].Mechanism != MechNative {
		return Plan{}, ErrEverywhere
	}
	first := plan.Steps[0]
	scope := claudesettings.ScopeUser
	if strings.HasPrefix(first.RowID, "native:"+string(claudesettings.ScopeProject)+":") {
		scope = claudesettings.ScopeProject
	}
	polFile := intentPolicyFile(in, scope)

	var sub manifest.PolicySubject
	var rule manifest.PolicyRule
	hookValue := req.Value
	switch req.What {
	case WhatCommand:
		// The twin hook step proposeNative added, under the intent's names
		// and in the intent's policy file.
		last := &plan.Steps[len(plan.Steps)-1]
		if last.Rule == nil {
			return Plan{}, ErrEverywhere
		}
		r := *last.Rule
		r.ID = ruleID
		last.Rule, last.File, last.RowID, last.IntentID = &r, polFile, RowID(KindHookRegex, scope, "", ruleID), intent
		return plan, nil
	case WhatPath:
		tools := []string{"Grep", "Glob"}
		sub = manifest.PolicySubject{Kind: policy.KindTool, Name: name, Match: manifest.SubjectMatch{Tools: tools}, Paths: gateLists(req.Action, gate)}
		rule = manifest.PolicyRule{ID: ruleID, Tool: "Bash", Action: req.Action,
			Match: manifest.RuleMatch{Literals: pathLiterals(filepath.Clean(in.Paths.Home), req.Value)}}
	case WhatHost:
		host = strings.TrimPrefix(strings.TrimSuffix(first.Value, ")"), "WebFetch(domain:")
		if !plainHost(host) {
			return Plan{}, errors.New("rulebook: cover every route needs a host name of letters, digits, dots and dashes")
		}
		if req.Action == "deny" {
			// The sandbox's domain list has deny only: an ask intent has
			// no such step.
			plan.Steps = append(plan.Steps, Step{
				Mechanism: MechNative, File: first.File, Key: claudesettings.KeyDeniedDomains, Value: host,
				RowID:    RowID(KindSandboxDomain, scope, claudesettings.KeyDeniedDomains, host),
				Sentence: Sentence(KindSandboxDomain, "deny", "", host), IntentID: intent,
			})
		}
		sub = manifest.PolicySubject{Kind: policy.KindTool, Name: name, Match: manifest.SubjectMatch{Tools: []string{"WebFetch"}}, Domains: gateLists(req.Action, host)}
		rule = manifest.PolicyRule{ID: ruleID, Tool: "Bash", Action: req.Action, Match: manifest.RuleMatch{
			Argv0: hostArgv0(), Literals: []string{host}, Regex: "(?i)" + regexp.QuoteMeta(host),
		}}
		hookValue = host
	}
	entry := gate
	if req.What == WhatHost {
		entry = host
	}
	plan.Steps = append(plan.Steps,
		Step{
			Mechanism: MechSubject, File: polFile, Key: "subjects", Value: name,
			RowID:    RowID(KindSubject, scope, policy.KindTool, name),
			Sentence: toolGateSentence(req.Action, sub.Match.Tools, entry), IntentID: intent, Subject: &sub,
		},
		Step{
			Mechanism: MechHook, File: polFile, Key: "rules", Value: hookValue,
			RowID:    RowID(KindHookRegex, scope, "", ruleID),
			Sentence: hookSentence(rule.Action, rule.Tool, rule.Match), IntentID: intent, Rule: &rule,
		})
	return plan, nil
}

// Removed is what RemoveIntent removed: the files written, their backups
// and the rows that went.
type Removed = Result

// RemoveIntent removes every rule of an everywhere intent: each settings
// string the ledger shows the intent claims (permissions lists and
// sandbox.network.deniedDomains) loses that claim, one ManageKeys per
// file, and the string goes when no other rule claims it; the intent's
// hook rule and tool subject go from the policy file of the intent's
// scope (one save per file). The policy files are loaded and edited in
// memory first, so one that cannot be read or edited stops the removal
// before any file is written; a project's policy file is read only for a
// project-scope intent (or, when no settings string of the intent is
// left to tell its scope, when the user file does not hold it). It runs
// under the settings lock. Removed.RowIDs lists the rows that went; a
// string another rule still claims stays and is not listed. An id that is
// not an intent id, or an intent with nothing left, is an error and
// writes nothing.
func RemoveIntent(in Input, intentID string) (Removed, error) {
	res := Removed{Written: []string{}, Backups: []string{}, RowIDs: []string{}}
	if _, _, ok := intentParts(intentID); !ok {
		return res, fmt.Errorf("rulebook: %q is not an intent id (intent:<what>:<hex8>)", intentID)
	}
	var missing []string
	err := claudesettings.Transact(in.Paths.StateDir, func(led *claudesettings.Ledger) error {
		var err error
		missing, err = removeIntentIn(in, intentID, led, &res)
		return err
	})
	if err != nil {
		return res, err
	}
	if len(missing) > 0 {
		return res, errIntentElsewhere(intentID, missing)
	}
	if len(res.RowIDs) == 0 {
		return res, fmt.Errorf("rulebook: no rule belongs to %s", intentID)
	}
	return res, nil
}

// errIntentElsewhere is the error for an intent with rules left in
// settings files not open here.
func errIntentElsewhere(intentID string, missing []string) error {
	return fmt.Errorf("rulebook: rules of %s are still in %s, a settings file not open here (run this from that project)", intentID, strings.Join(missing, ", "))
}

// removeIntentIn is RemoveIntent's work inside a Transact the caller
// holds (Undo holds one already): it fills res and returns the settings
// files the ledger names that are not open here.
func removeIntentIn(in Input, intentID string, led *claudesettings.Ledger, res *Removed) (missing []string, err error) {
	what, h, ok := intentParts(intentID)
	if !ok {
		return nil, fmt.Errorf("rulebook: %q is not an intent id (intent:<what>:<hex8>)", intentID)
	}
	ruleID, name := intentRuleID(what, h), intentSubjectName(what, h)
	err = func() error {
		locs := writableSettings(in)
		type fileEdit struct {
			loc   claudesettings.Location
			edits []claudesettings.KeyEdit
		}
		var files []*fileEdit
		scopes := map[claudesettings.Scope]bool{}
		for _, e := range led.Entries {
			if !containsStr(e.RuleIDs, intentID) {
				continue
			}
			loc, ok := locationFor(locs, e.Path)
			if !ok {
				if !containsStr(missing, e.Path) {
					missing = append(missing, e.Path)
				}
				continue
			}
			scopes[loc.Scope] = true
			var fe *fileEdit
			for _, x := range files {
				if x.loc.Path == loc.Path {
					fe = x
				}
			}
			if fe == nil {
				fe = &fileEdit{loc: loc}
				files = append(files, fe)
			}
			c := claudesettings.Claim{Value: e.Value, RuleID: intentID}
			placed := false
			for i := range fe.edits {
				if fe.edits[i].Key == e.Key {
					fe.edits[i].Removes = append(fe.edits[i].Removes, c)
					placed = true
				}
			}
			if !placed {
				fe.edits = append(fe.edits, claudesettings.KeyEdit{Key: e.Key, Removes: []claudesettings.Claim{c}})
			}
		}

		// The policy files to edit, tried in memory before any write.
		type polFile struct {
			path    string
			project bool
			scope   claudesettings.Scope
			rows    []string
		}
		user := &polFile{path: in.Paths.OverridesFile(), scope: claudesettings.ScopeUser}
		var project *polFile
		if in.ProjectRoot != "" {
			project = &polFile{path: filepath.Join(in.ProjectRoot, manifest.ProjectOverridesFile), project: true, scope: claudesettings.ScopeProject}
		}
		deletes := func(pf *polFile) func(f *policy.File) (bool, error) {
			return func(f *policy.File) (bool, error) {
				pf.rows = nil
				changed := false
				for _, e := range []struct {
					edit policy.Edit
					row  string
				}{
					{policy.Edit{Kind: policy.KindTool, Name: name, Delete: true}, RowID(KindSubject, pf.scope, policy.KindTool, name)},
					{policy.Edit{DeleteRule: ruleID}, RowID(KindHookRegex, pf.scope, "", ruleID)},
				} {
					c, err := policy.Apply(f, e.edit)
					if err != nil {
						return false, err
					}
					if c {
						pf.rows = append(pf.rows, e.row)
						changed = true
					}
				}
				return changed, nil
			}
		}
		try := func(pf *polFile) (bool, error) {
			f, _, err := loadPolicy(pf.path, pf.project)
			if err != nil {
				return false, err
			}
			return deletes(pf)(&f)
		}
		var touch []*polFile
		switch {
		case len(scopes) > 0:
			if scopes[claudesettings.ScopeUser] || scopes[claudesettings.ScopeLocal] {
				touch = append(touch, user)
			}
			if scopes[claudesettings.ScopeProject] && project != nil {
				touch = append(touch, project)
			}
		default:
			// No settings string left to tell the scope: the user file,
			// and the project's only when the user file does not hold it.
			touch = append(touch, user)
			if project != nil {
				touch = append(touch, project)
			}
		}
		var save []*polFile
		for _, pf := range touch {
			changed, err := try(pf)
			if err != nil {
				return err
			}
			if changed {
				save = append(save, pf)
				if len(scopes) == 0 {
					break
				}
			}
		}

		for _, fe := range files {
			chs, err := claudesettings.ManageKeys(fe.loc, led, fe.edits)
			if err != nil {
				return err
			}
			for _, ch := range chs {
				if len(ch.Removed) > 0 {
					res.wrote(fe.loc.Path, ch.Backup)
					break
				}
			}
			for _, ke := range fe.edits {
				for _, c := range ke.Removes {
					// Gone from the ledger: no rule claims it any more, so
					// its row went (from the file, or the person had
					// already removed it).
					if led.Owners(fe.loc.Path, ke.Key, c.Value) == nil {
						res.RowIDs = append(res.RowIDs, RowID(kindForKey(ke.Key), fe.loc.Scope, ke.Key, c.Value))
					}
				}
			}
		}
		for _, pf := range save {
			if err := editPolicyFile(pf.path, pf.project, res, deletes(pf)); err != nil {
				return err
			}
			res.RowIDs = append(res.RowIDs, pf.rows...)
		}
		return nil
	}()
	return missing, err
}

// SearchWatchWarning is one sentence for a plan that writes a Grep and
// Glob rule (a path intent) while those tools are not watched: no
// PreToolUse group of watchdeck's in any settings file Claude Code reads
// here names them, and the plugin, which registers them, is not active.
// The rule then holds only after enforce install runs again. It is "" for
// any other plan, or when the tools are watched. It only reads; a
// settings file it cannot read counts as watching nothing.
func SearchWatchWarning(in Input, p Plan) string {
	need := false
	for _, s := range p.Steps {
		if s.Subject != nil && strings.Join(s.Subject.Match.Tools, "|") == "Grep|Glob" {
			need = true
		}
	}
	if !need {
		return ""
	}
	claudeDir := in.Paths.ClaudeDir
	if claudeDir == "" {
		claudeDir = filepath.Join(in.Paths.Home, ".claude")
	}
	if _, on, err := skills.PluginActive(claudeDir, in.ProjectRoot, paths.BinaryName); err == nil && on {
		return ""
	}
	left := []string{"Grep", "Glob"}
	for _, l := range claudesettings.Locate(in.Paths, in.ProjectRoot) {
		missing, err := settings.UnhookedTools(l.Path, left)
		if err != nil {
			continue
		}
		if left = missing; len(left) == 0 {
			return ""
		}
	}
	return strings.Join(left, " and ") + " searches are not watched yet; run " + paths.BinaryName + " enforce install again so this rule covers them."
}
