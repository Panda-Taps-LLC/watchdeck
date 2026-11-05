package rulebook

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/activity"
	"github.com/Panda-Taps-LLC/watchdeck/internal/claudesettings"
	"github.com/Panda-Taps-LLC/watchdeck/internal/leakscan"
	"github.com/Panda-Taps-LLC/watchdeck/internal/manifest"
	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
	"github.com/Panda-Taps-LLC/watchdeck/internal/userconfig"
)

// InboxFile is the resolutions file, <stateDir>/inbox.jsonl: append-only
// JSONL, mode 0600.
const InboxFile = "inbox.jsonl"

// DefaultInboxWindow is how far back the inbox looks when installed_at is
// not recorded.
const DefaultInboxWindow = 7 * 24 * time.Hour

// ItemKind is what an inbox item comes from.
type ItemKind string

const (
	ItemDenial         ItemKind = "denial"          // auto mode denied a call (activity "denied")
	ItemAsk            ItemKind = "ask"             // watchdeck's gate denied or asked (activity "decision", enforcement gate)
	ItemSandboxRefusal ItemKind = "sandbox_refusal" // a sandboxed run hit a policy error or the sandbox refused it
	ItemSkillRequest   ItemKind = "skill_request"   // a skill asked for more than its grant
	ItemRejection      ItemKind = "rejection"       // a refusal the caller read from a transcript
	KindLeak           ItemKind = "leak"            // leak watch found a secret-shaped string in a transcript
)

// Authority words, the same strings as internal/mapmodel's.
const (
	authorityClassifier = "classifier"
	authorityHook       = "hook"
	authoritySandbox    = "sandbox"
	authorityUser       = "user"
	authorityLeak       = "leak"
)

// Resolution actions.
const (
	ResolveAddRule     = "add_rule"
	ResolveAcknowledge = "acknowledge"
	ResolveDismiss     = "dismiss"
	ResolveUndo        = "undo"  // cancels the latest earlier resolution of the same id
	ResolveAllow       = "allow" // Plan 08: rules paused or a skill's grant widened for a while (TemporaryIDs)
)

// whatSep joins an item's tool and target in What; Suggest splits on it.
const whatSep = " · "

// Item is one thing in the inbox. What is "<tool> · <target>" (the
// program name for Bash; the tool alone when there is no target), Why the
// reason sentence and Authority the map's word for who decided. RuleIDs
// are the rules that fired, "<pack>/<id>" per hit of a decision record
// (order kept, duplicates dropped; a policy-file rule is "user/<id>" and a
// Claude Code settings rule "claude-settings/<rule>").
type Item struct {
	ID        string       `json:"id"`
	Kind      ItemKind     `json:"kind"`
	TS        time.Time    `json:"ts"`
	Harness   string       `json:"harness"`
	SessionID string       `json:"session_id,omitempty"`
	ToolUseID string       `json:"tool_use_id,omitempty"`
	Agent     string       `json:"agent,omitempty"`
	Project   string       `json:"project,omitempty"`
	What      string       `json:"what"`
	Why       string       `json:"why"`
	Authority string       `json:"authority"`
	RuleIDs   []string     `json:"rule_ids,omitempty"`
	Fix       []AddRequest `json:"fix"`
	// Ungranted (Plan 08, R11) is what a skill_request or sandbox_refusal
	// item's skill asked for and was not given, as GrantFor takes it: from
	// a decision record's ungranted list (network, write, read, env,
	// caches; other fields are left out), and from a run's network hint
	// (network all for each skill of the run). A write or read hint gives
	// nothing: its line is the script's own output, never a policy value.
	Ungranted []UngrantedEdit `json:"ungranted,omitempty"`
	// bySubject is set on an ask item whose record names a policy-file
	// subject other than a skill (a path, domain, MCP or agent rule): that
	// rule may be what decided, and it cannot be paused (AllowFor).
	bySubject bool
	// targetCut is set on a leak item whose target the index cut: What
	// shows it with an ellipsis and Suggest builds no rule from it.
	targetCut bool
}

// Rejection is a refusal the caller found in a transcript. It is never
// read here.
type Rejection struct {
	SessionID, ToolUseID string
	TS                   time.Time
	Tool, Target         string
	Authority, Why       string
}

// Leak is one leak watch finding the caller read from the session index
// (DESIGN §14 "Leak watch"). It is never read here. Ref is the tool use id
// for Where "result" or "input" and the assistant row's uuid for "reply";
// Target and Project are in display form (~ for home). No field holds the
// matched text.
type Leak struct {
	SessionID, Ref, Tool, Target, Where, Pattern, Label, Agent, Project string
	// TargetCut: the index cut Target to its first 120 bytes, so no rule is
	// built from it.
	TargetCut bool
	TS        time.Time
}

// Resolution is one line of the resolutions file.
type Resolution struct {
	V         int      `json:"v"`
	ID        string   `json:"id"`
	Action    string   `json:"action"` // add_rule | acknowledge | dismiss | undo
	TS        string   `json:"ts"`
	RuleID    string   `json:"rule_id,omitempty"`  // the first of RuleIDs (all an older line has)
	RuleIDs   []string `json:"rule_ids,omitempty"` // add_rule: every row the add wrote, in order
	Signature string   `json:"signature,omitempty"`
	// IntentID is set on an add_rule of an everywhere fix (IntentFor): Undo
	// then removes the intent the way RemoveIntent does, releasing only its
	// own claims, instead of removing each row.
	IntentID string `json:"intent_id,omitempty"`
	// TemporaryIDs (action allow) are the temporaries the allow wrote; Undo
	// ends each one.
	TemporaryIDs []string `json:"temporary_ids,omitempty"`
	// Project is the absolute project root an add_rule was written at
	// project scope for (the dashboard's "only in this project"); empty
	// for a user-scope add and every other action. Undo removes the rows
	// with that root as the project, whatever the caller's working
	// directory.
	Project string `json:"project,omitempty"`
}

// ruleIDs is every row an add_rule resolution wrote: RuleIDs, else the
// lone RuleID of a line written before RuleIDs existed.
func (r Resolution) ruleIDs() []string {
	if len(r.RuleIDs) > 0 {
		return r.RuleIDs
	}
	if r.RuleID != "" {
		return []string{r.RuleID}
	}
	return nil
}

// InboxInput is what Open reads. A zero Since means installed_at from the
// config file, else now - DefaultInboxWindow. A nil Book skips the "fix
// already exists" check.
type InboxInput struct {
	Paths      paths.Paths
	Since      time.Time
	Rejections []Rejection
	Leaks      []Leak
	Book       *Book
}

// itemID is hex(sha256(session + NUL + toolUse + NUL + kind))[:16].
func itemID(session, toolUse string, kind ItemKind) string {
	sum := sha256.Sum256([]byte(session + "\x00" + toolUse + "\x00" + string(kind)))
	return hex.EncodeToString(sum[:])[:16]
}

// Signature is hex(sha256(kind + NUL + what + NUL + why))[:16]: what a
// dismiss suppresses.
func Signature(it Item) string {
	sum := sha256.Sum256([]byte(string(it.Kind) + "\x00" + it.What + "\x00" + it.Why))
	return hex.EncodeToString(sum[:])[:16]
}

// Open lists the inbox, newest first: items from the activity log since
// the start (InboxInput.Since) and from the caller's Rejections and Leaks, without
// the resolved ones, those whose Signature was dismissed and those for
// which a suggested fix is already a rule in Book. Resolutions are
// replayed in file order, so an undo cancels the latest earlier
// resolution of its id (the item reopens, a cancelled dismiss stops
// suppressing its signature). With the activity log off
// it lists the Rejections and Leaks only. A config file that cannot be read or
// parsed means the seven-day window.
func Open(in InboxInput) ([]Item, error) {
	since := in.Since
	if since.IsZero() {
		// A config file that cannot be read or does not parse is no reason
		// to fail the inbox: fall back to the window.
		since = time.Now().Add(-DefaultInboxWindow)
		if cfg, err := userconfig.Load(in.Paths.ConfigFile()); err == nil {
			if t, ok := cfg.InstalledAt(); ok {
				since = t
			}
		}
	}
	home := in.Paths.Home
	byID := map[string]Item{}
	add := func(it Item) {
		it.Fix = Suggest(it)
		if old, ok := byID[it.ID]; !ok || !it.TS.Before(old.TS) {
			byID[it.ID] = it
		}
	}
	if in.Paths.Activity != "" {
		res, err := activity.Read(in.Paths.Activity, activity.ReadOptions{Since: since})
		if err != nil {
			return nil, err
		}
		for _, r := range res.Records {
			for _, it := range recordItems(r, home) {
				add(it)
			}
		}
	}
	for _, rj := range in.Rejections {
		if rj.TS.Before(since) {
			continue
		}
		auth := rj.Authority
		if auth == "" {
			auth = authorityUser
		}
		target := rj.Target
		if rj.Tool == "Bash" {
			target = argv0(target)
		}
		add(Item{
			ID: itemID(rj.SessionID, rj.ToolUseID, ItemRejection), Kind: ItemRejection, TS: rj.TS.UTC(),
			Harness: activity.HarnessClaudeCode, SessionID: rj.SessionID, ToolUseID: rj.ToolUseID,
			What: what(rj.Tool, target), Why: rj.Why, Authority: auth,
		})
	}
	for _, lk := range in.Leaks {
		if lk.TS.Before(since) {
			continue
		}
		add(leakItem(lk))
	}
	live, err := readResolutions(in.Paths.StateDir)
	if err != nil {
		return nil, err
	}
	dismissed := map[string]bool{}
	for _, rs := range live {
		for _, r := range rs {
			if r.Action == ResolveDismiss && r.Signature != "" {
				dismissed[r.Signature] = true
			}
		}
	}
	var natives, packs map[string]bool
	if in.Book != nil {
		natives, packs = nativeValues(in.Book), packValues(in.Book)
	}
	out := make([]Item, 0, len(byID))
	for _, it := range byID {
		if len(live[it.ID]) > 0 || dismissed[Signature(it)] {
			continue
		}
		// A leak already happened; a rule that would block it next time
		// does not undo it, so it stays listed (Plan 08 final review I1).
		if it.Kind != KindLeak && natives != nil && fixExists(in.Paths, it, natives, packs) {
			continue
		}
		out = append(out, it)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].TS.Equal(out[j].TS) {
			return out[i].TS.After(out[j].TS)
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// leakItem is a Leak's item: id from the session and Ref, What the tool
// and target ("Reply" for a model reply), Why "<label> appeared in the
// <where>", no rule ids; Suggest gives a leak with a file path a path fix.
// A target that is itself secret-shaped is dropped; one the index cut ends
// in "…" and gets no fix.
func leakItem(lk Leak) Item {
	target := lk.Target
	if len(leakscan.Scan(target)) > 0 {
		// The index drops such a target already; a caller's Leak is not
		// trusted to have been through it.
		target = ""
	}
	cut := lk.TargetCut && target != ""
	if cut {
		target += "…"
	}
	w := what(lk.Tool, target)
	tu := lk.Ref
	if lk.Where == "reply" {
		w, tu = "Reply", ""
	}
	return Item{
		ID: itemID(lk.SessionID, lk.Ref, KindLeak), Kind: KindLeak, TS: lk.TS.UTC(),
		Harness: activity.HarnessClaudeCode, SessionID: lk.SessionID, ToolUseID: tu, Agent: lk.Agent, Project: lk.Project,
		What: w, Why: lk.Label + " appeared in the " + lk.Where, Authority: authorityLeak, targetCut: cut,
	}
}

// recordItems turns one activity record into its items (a decision can be
// both an ask and a skill request).
func recordItems(r activity.Record, home string) []Item {
	t, err := time.Parse(time.RFC3339Nano, r.TS)
	if err != nil {
		return nil
	}
	base := Item{
		TS: t.UTC(), Harness: activity.DefaultHarness(r.Harness), SessionID: r.SessionID, ToolUseID: r.ToolUseID,
		Agent: r.AgentType, Project: projectOf(r.Cwd, home), Why: r.Reason,
	}
	if base.Agent == "" {
		base.Agent = r.AgentID
	}
	mk := func(kind ItemKind, authority, w, why string) Item {
		it := base
		it.Kind, it.Authority, it.What, it.Why = kind, authority, w, why
		it.ID = recordItemID(r, kind)
		return it
	}
	var out []Item
	if r.Kind == activity.KindDecision {
		base.RuleIDs = ruleIDs(r.Rules)
	}
	switch r.Kind {
	case activity.KindDenied:
		out = append(out, mk(ItemDenial, authorityClassifier, recordWhat(r), r.Reason))
	case activity.KindDecision:
		if r.Enforcement == activity.EnforcementGate && (r.Decision == "deny" || r.Decision == "ask") {
			it := mk(ItemAsk, authorityHook, recordWhat(r), r.Reason)
			it.bySubject = r.Subject != nil && r.Subject.Kind != manifest.KindSkill
			out = append(out, it)
		}
		if len(r.Ungranted) > 0 {
			tool := r.ToolName
			if tool == "" {
				tool = "Bash"
			}
			it := mk(ItemSkillRequest, authorityHook, what(tool, strings.Join(r.Skills, ", ")), strings.Join(r.Ungranted, "; "))
			for _, u := range r.Ungranted {
				if e, ok := parseUngranted(u); ok {
					it.Ungranted = append(it.Ungranted, e)
				}
			}
			out = append(out, it)
		}
	case activity.KindRun:
		why := ""
		refused := r.Outcome == activity.OutcomePolicyError
		if refused {
			why = r.Error
		}
		network := false
		for _, h := range r.Hints {
			if h.Kind == activity.HintNetwork || h.Kind == activity.HintWrite || h.Kind == activity.HintRead {
				if !refused {
					why = h.Text
				}
				refused = true
				network = network || h.Kind == activity.HintNetwork
			}
		}
		if refused {
			a := r.Argv0
			if a == "" {
				a = argv0(r.Command)
			}
			it := mk(ItemSandboxRefusal, authoritySandbox, what("Bash", a), why)
			if network {
				for _, sk := range r.Skills {
					if manifest.ValidSkillName(sk) && sk != "*" {
						it.Ungranted = append(it.Ungranted, UngrantedEdit{Skill: sk, Field: "network", Value: "all"})
					}
				}
			}
			out = append(out, it)
		}
	}
	return out
}

// ruleIDs is "<pack>/<id>" per hit, in order, without duplicates; nil
// for none.
func ruleIDs(hits []activity.RuleHit) []string {
	var out []string
	for _, h := range hits {
		if h.Pack == "" || h.ID == "" {
			continue
		}
		id := h.Pack + "/" + h.ID
		if !containsStr(out, id) {
			out = append(out, id)
		}
	}
	return out
}

// recordItemID is itemID, with the record's time (RFC 3339 with
// nanoseconds) standing in for the tool use id when it has none (a run no
// decision was joined to), so such records do not share one id. The byte
// offset is not used: it changes when the log rotates.
func recordItemID(r activity.Record, kind ItemKind) string {
	tu := r.ToolUseID
	if tu == "" {
		tu = "ts:" + r.TS
	}
	return itemID(r.SessionID, tu, kind)
}

// recordWhat is "<tool> · <target>": the program name for Bash (from the
// command when the record kept it), the skill for Skill.
func recordWhat(r activity.Record) string {
	tool := r.ToolName
	switch tool {
	case "Bash":
		a := r.Argv0
		if a == "" {
			a = argv0(r.Command)
		}
		return what(tool, a)
	case "Skill":
		return what(tool, r.Skill)
	}
	return what(tool, r.Target)
}

func what(tool, target string) string {
	if target == "" || target == tool {
		return tool
	}
	return tool + whatSep + target
}

// argv0 is the base name of a command's first word that is not a
// VAR=value assignment, quotes trimmed, at most 64 bytes (the hook's rule).
func argv0(cmd string) string {
	w := ""
	for _, x := range strings.Fields(cmd) {
		if !strings.Contains(x, "=") {
			w = x
			break
		}
	}
	if w == "" {
		return ""
	}
	w = filepath.Base(strings.Trim(w, `'"`))
	if len(w) > 64 {
		w = w[:64]
	}
	return w
}

// projectOf is the git root above cwd (else cwd), with home as ~. A cwd
// the hook already wrote as ~/… is expanded first.
func projectOf(cwd, home string) string {
	if cwd == "" {
		return ""
	}
	if home != "" && (cwd == "~" || strings.HasPrefix(cwd, "~/")) {
		cwd = home + cwd[1:]
	}
	if root := paths.ProjectRoot(cwd, home); root != "" {
		cwd = root
	}
	return tilde(cwd, home)
}

func tilde(p, home string) string {
	h := strings.TrimRight(home, "/")
	switch {
	case h == "":
		return p
	case p == h:
		return "~"
	case strings.HasPrefix(p, h+"/"):
		return "~" + p[len(h):]
	}
	return p
}

// Suggest is the rule that would stop an item: for a denial, ask or
// rejection, an ask on the Bash program (never a block: the program alone
// says little about what the call was for, and a file the call read is
// better stopped with a path rule), or a deny on the file path (Read for
// the read tools, Edit for the write tools), the WebFetch host or the MCP
// tool. A path or host fix is followed by its everywhere form (the same
// value with Everywhere set: every route a tool can take to it, Plan 08
// D8 and R12), which is never the first fix; a Bash program keeps the
// one ask (its everywhere form is the twin Propose suggests). A leak from
// one of the file tools (Read, Write, Edit, MultiEdit, NotebookEdit) gets a
// deny on reading that file, where the secret now sits, and its everywhere
// form. A Grep or Glob leak gets none (its target is the search root, not
// the file), nor does a Bash, WebFetch or reply leak or one whose target
// the index cut (a rule on the cut path would match nothing).
// A sandbox refusal and a skill request get none (a skill's sandbox is
// widened with `rules grant`). For an ask or denial that a built-in pack
// rule fired on, the first fix raises the first such rule in RuleIDs to
// deny (a policy-file or Claude Code settings rule among them is skipped:
// it is not a pack rule), followed by the suggestion above.
func Suggest(it Item) []AddRequest {
	switch it.Kind {
	case ItemDenial, ItemAsk, ItemRejection:
	case KindLeak:
		tool, target, _ := strings.Cut(it.What, whatSep)
		if it.targetCut || target == "" {
			return nil
		}
		switch tool {
		case "Read", "Write", "Edit", "MultiEdit", "NotebookEdit":
			return withEverywhere([]AddRequest{{Action: "deny", What: WhatPath, Value: target, Tool: PathRead}})
		}
		return nil
	default:
		return nil
	}
	var out []AddRequest
	if it.Kind == ItemAsk || it.Kind == ItemDenial {
		for _, id := range it.RuleIDs {
			if _, _, ok := packRule(id); ok {
				out = append(out, AddRequest{Action: "deny", What: WhatPackRule, Value: id})
				break
			}
		}
	}
	if more := suggestRule(it); more != nil {
		out = append(out, withEverywhere(more)...)
	}
	return out
}

// withEverywhere is reqs with the everywhere form of each path or host
// request after it. The everywhere path form covers reading and changing
// (Tool left to its default), since every route to the file is the point.
func withEverywhere(reqs []AddRequest) []AddRequest {
	var out []AddRequest
	for _, r := range reqs {
		out = append(out, r)
		if r.What == WhatPath || r.What == WhatHost {
			e := r
			e.Everywhere, e.Tool = true, ""
			out = append(out, e)
		}
	}
	return out
}

// pathTool is the path rule's tool (PathRead or PathEdit) for a file tool,
// "" for any other.
func pathTool(tool string) string {
	switch tool {
	case "Read", "Grep", "Glob", "NotebookRead":
		return PathRead
	case "Edit", "Write", "MultiEdit", "NotebookEdit":
		return PathEdit
	}
	return ""
}

// suggestRule is Suggest's rule for the item's tool and target.
func suggestRule(it Item) []AddRequest {
	tool, target, _ := strings.Cut(it.What, whatSep)
	switch {
	case tool == "Bash":
		if target == "" {
			return nil
		}
		return []AddRequest{{Action: "ask", What: WhatCommand, Value: target}}
	case tool == "WebFetch":
		if target == "" {
			return nil
		}
		return []AddRequest{{Action: "deny", What: WhatHost, Value: target}}
	case strings.HasPrefix(tool, "mcp__"):
		return []AddRequest{{Action: "deny", What: WhatMCP, Value: tool}}
	}
	pt := pathTool(tool)
	if pt == "" || target == "" {
		return nil
	}
	return []AddRequest{{Action: "deny", What: WhatPath, Value: target, Tool: pt}}
}

// nativeValues is the set of native deny and ask strings in force in b.
func nativeValues(b *Book) map[string]bool {
	m := map[string]bool{}
	for _, g := range b.Groups {
		for _, r := range g.Rows {
			if (r.Kind == KindNativeDeny || r.Kind == KindNativeAsk) && r.State == StateOn {
				m[r.Value] = true
			}
		}
	}
	return m
}

// packValues is the set of "<pack>/<id>: <action>" for every pack rule
// that is on in b.
func packValues(b *Book) map[string]bool {
	m := map[string]bool{}
	for _, g := range b.Groups {
		for _, r := range g.Rows {
			if r.Kind == KindPack && r.State == StateOn {
				m[r.Value+": "+r.Action] = true
			}
		}
	}
	return m
}

// fixExists reports whether one of the item's fixes is already in force:
// a pack-rule fix whose rule is on at that action, or a fix every native
// string of which (as Propose spells it at user scope) is already a rule.
func fixExists(p paths.Paths, it Item, natives, packs map[string]bool) bool {
	for _, f := range it.Fix {
		if f.What == WhatPackRule {
			if packs[f.Value+": "+f.Action] {
				return true
			}
			continue
		}
		if nativeFixExists(p, f, natives) {
			return true
		}
	}
	return false
}

func nativeFixExists(p paths.Paths, f AddRequest, natives map[string]bool) bool {
	plan, err := Propose(Input{Paths: p}, f)
	if err != nil {
		return false
	}
	n := 0
	for _, s := range plan.Steps {
		if s.Mechanism != MechNative {
			continue
		}
		if !natives[s.Value] {
			return false
		}
		n++
	}
	return n > 0
}

// Resolve appends r to <stateDir>/inbox.jsonl (created 0600, its directory
// 0700; a symlink at the path is refused), with V 1 and TS now when empty.
// RuleID and RuleIDs are written together: RuleID is RuleIDs[0], and a
// lone RuleID becomes RuleIDs.
func Resolve(stateDir string, r Resolution) error {
	if stateDir == "" {
		return errors.New("rulebook: no state directory for the inbox")
	}
	if strings.TrimSpace(r.ID) == "" {
		return errors.New("rulebook: an inbox resolution needs an item id")
	}
	switch r.Action {
	case ResolveAddRule, ResolveAcknowledge, ResolveDismiss, ResolveUndo, ResolveAllow:
	default:
		return fmt.Errorf("rulebook: inbox action %q: add_rule, acknowledge, dismiss, undo or allow", r.Action)
	}
	if len(r.RuleIDs) > 0 {
		r.RuleIDs = append([]string(nil), r.RuleIDs...)
		r.RuleID = r.RuleIDs[0]
	} else if r.RuleID != "" {
		r.RuleIDs = []string{r.RuleID}
	}
	if r.V == 0 {
		r.V = 1
	}
	if r.TS == "" {
		r.TS = time.Now().UTC().Format(time.RFC3339Nano)
	}
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	// O_NOFOLLOW: a symlink planted at the path is refused, not followed.
	f, err := os.OpenFile(filepath.Join(stateDir, InboxFile), os.O_WRONLY|os.O_APPEND|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// readResolutions replays the resolutions file in order and returns, per
// item id, the resolutions still in force: an undo cancels the latest
// earlier one of its id (an undo with nothing left to cancel does
// nothing). A missing file is none; a line that does not parse is skipped.
func readResolutions(stateDir string) (map[string][]Resolution, error) {
	live := map[string][]Resolution{}
	if stateDir == "" {
		return live, nil
	}
	f, err := os.Open(filepath.Join(stateDir, InboxFile))
	if errors.Is(err, os.ErrNotExist) {
		return live, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		var r Resolution
		if json.Unmarshal(sc.Bytes(), &r) != nil || r.ID == "" {
			continue
		}
		if r.Action == ResolveUndo {
			if rs := live[r.ID]; len(rs) > 0 {
				live[r.ID] = rs[:len(rs)-1]
			}
			continue
		}
		live[r.ID] = append(live[r.ID], r)
	}
	return live, sc.Err()
}

// ErrNothingToUndo is Undo's error when the item has no resolution in
// force. It is a comparable struct value, like ErrNotOwned, so the var
// needs no init code.
var ErrNothingToUndo error = nothingToUndoError{}

type nothingToUndoError struct{}

func (nothingToUndoError) Error() string { return "nothing to undo" }

// Undo cancels the latest resolution of an inbox item that is still in
// force, under the state-dir lock (claudesettings.Transact), so two undos
// cannot cancel the same resolution twice. An add_rule resolution has
// every row it wrote removed first, in order, each reported in
// Result.RowIDs; when one removal fails (a rule watchdeck does not own, a
// row that is gone) the undo stops there, the error names that row, the
// ledger keeps what was already removed, and nothing is appended. An
// add_rule of an everywhere fix (IntentID set) removes the intent the way
// RemoveIntent does instead: only the intent's own claims are released,
// so a string another rule also claims stays, and an intent the person
// already removed is no error. An allow resolution has all of its
// temporaries ended in one write of the policy file (one already gone,
// expired and pruned or replaced by a later pause, counts as ended). An
// add_rule that carries a Project (written at project scope) has its rows
// or intent removed with that root as in.ProjectRoot, on a copy of in, so
// the undo finds the project's settings file from any working directory
// and the caller's Input is left as it was. Then an undo line is
// appended, so the item reopens. No resolution in force is an error
// wrapping ErrNothingToUndo.
func Undo(in Input, id string) (Result, error) {
	res := Result{Written: []string{}, Backups: []string{}, RowIDs: []string{}}
	var stop error
	err := claudesettings.Transact(in.Paths.StateDir, func(led *claudesettings.Ledger) error {
		live, err := readResolutions(in.Paths.StateDir)
		if err != nil {
			return err
		}
		rs := live[id]
		if len(rs) == 0 {
			return fmt.Errorf("rulebook: %w for inbox item %q", ErrNothingToUndo, id)
		}
		last := rs[len(rs)-1]
		in := in // a fresh copy per run: the caller's Input is untouched
		if last.Action == ResolveAddRule && last.Project != "" {
			in.ProjectRoot = last.Project
			in.projectPolicyOnly = true
		}
		switch {
		case last.Action == ResolveAddRule && last.IntentID != "":
			missing, err := removeIntentIn(in, last.IntentID, led, &res)
			if err == nil && len(missing) > 0 {
				err = errIntentElsewhere(last.IntentID, missing)
			}
			if err != nil {
				// Return nil so the ledger is saved with whatever went.
				stop = fmt.Errorf("rulebook: undo stopped: %w", err)
				return nil
			}
		case last.Action == ResolveAddRule:
			for _, row := range last.ruleIDs() {
				if err := removeRow(in, row, led, &res); err != nil {
					// Return nil so the ledger is saved: earlier rows are
					// already gone from the settings files.
					stop = fmt.Errorf("rulebook: undo stopped at %s: %w", row, err)
					return nil
				}
				res.RowIDs = append(res.RowIDs, row)
			}
		case last.Action == ResolveAllow:
			if err := endTemporaries(in, last.TemporaryIDs, &res); err != nil {
				stop = fmt.Errorf("rulebook: undo stopped: %w", err)
				return nil
			}
		}
		if err := Resolve(in.Paths.StateDir, Resolution{ID: id, Action: ResolveUndo}); err != nil {
			stop = err // the rows are gone: keep the ledger in step
		}
		return nil
	})
	if err != nil {
		return res, err
	}
	return res, stop
}
