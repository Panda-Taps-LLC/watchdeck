package rulebook

import (
	"fmt"
	"hash/fnv"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/claudesettings"
	"github.com/Panda-Taps-LLC/watchdeck/internal/manifest"
	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
	"github.com/Panda-Taps-LLC/watchdeck/internal/policy"
	"github.com/Panda-Taps-LLC/watchdeck/internal/rules"
)

// Kind is where a rule lives and what shape it has.
type Kind string

const (
	KindNativeDeny      Kind = "native-deny"      // permissions.deny
	KindNativeAsk       Kind = "native-ask"       // permissions.ask
	KindNativeAllow     Kind = "native-allow"     // permissions.allow
	KindAutoModeHard    Kind = "automode-hard"    // autoMode.hard_deny
	KindAutoModeSoft    Kind = "automode-soft"    // autoMode.soft_deny
	KindAutoModeAllow   Kind = "automode-allow"   // autoMode.allow
	KindAutoModeEnv     Kind = "automode-env"     // autoMode.environment
	KindSandboxDomain   Kind = "sandbox-domain"   // sandbox.network.allowedDomains / deniedDomains
	KindSandboxExcluded Kind = "sandbox-excluded" // sandbox.excludedCommands
	KindHookRegex       Kind = "hook-regex"       // a rule under rules: in a policy file
	KindSubject         Kind = "subject"          // a subject in a policy file
	KindPack            Kind = "pack"             // a built-in pack rule
)

// Owner says who wrote a rule.
type Owner string

const (
	OwnerUs            Owner = "us"             // watchdeck added it (ledger) or ships it (pack)
	OwnerUser          Owner = "user"           // the person, in a user or local file
	OwnerClaudeDefault Owner = "claude-default" // Claude Code's "$defaults"
	OwnerProject       Owner = "project"        // a project file, shared with the repository
	OwnerManaged       Owner = "managed"        // an administrator's managed settings
)

// Enforcement says what makes a rule hold.
type Enforcement string

const (
	EnforceOS           Enforcement = "os"            // the OS sandbox
	EnforceNativeDeny   Enforcement = "native-deny"   // Claude Code refuses the call
	EnforceNativePrompt Enforcement = "native-prompt" // Claude Code asks the person
	EnforceClassifier   Enforcement = "classifier"    // auto mode's classifier
	EnforceHookGate     Enforcement = "hook-gate"     // watchdeck's hook denies or asks
	EnforceHookSandbox  Enforcement = "hook-sandbox"  // watchdeck's hook rewrites into the sandbox
	EnforceAdvisory     Enforcement = "advisory"      // recorded only
	EnforceAllow        Enforcement = "allow"         // allowed without asking
)

// State says whether a rule is in force.
type State string

const (
	StateOn      State = "on"
	StateOff     State = "off"
	StateRemoved State = "removed" // watchdeck added it; the person removed it since
)

// HarnessClaudeCode is the only harness so far.
const HarnessClaudeCode = "claude-code"

// Group ids, in display order.
const (
	GroupSandbox   = "sandbox"
	GroupBlocked   = "blocked"
	GroupAutoMode  = "automode"
	GroupWatchdeck = paths.BinaryName
	GroupAsk       = "ask"
)

// Source is where a rule is written: the file, the key (a dotted settings
// key, "rules", "subjects" or "packs.<name>") and its position there (-1
// when it is in no file yet).
type Source struct {
	File  string `json:"file"`
	Key   string `json:"key"`
	Index int    `json:"index"`
}

// Rule is one row of the rulebook. Value is the whole settings string for
// the settings kinds ("Read(~/.x)"), "<pack>/<id>" for a pack rule, the
// regex (or the literals joined by ", ") for a hook rule and the subject
// name or gate entry for a subject. Action is deny | ask | allow | log, or
// "" when none applies (sandbox subjects, excluded commands, environment).
type Rule struct {
	ID          string               `json:"id"`
	Harness     string               `json:"harness"`
	Tool        string               `json:"tool"`
	Value       string               `json:"value"`
	Action      string               `json:"action"`
	Sentence    string               `json:"sentence"`
	Kind        Kind                 `json:"kind"`
	Scope       claudesettings.Scope `json:"scope"`
	Owner       Owner                `json:"owner"`
	Enforcement Enforcement          `json:"enforcement"`
	State       State                `json:"state"`
	Source      Source               `json:"source"`
	Recommended bool                 `json:"recommended"`
	Twin        string               `json:"twin"`               // the pack rule ("<pack>/<id>") a native rule pairs with, or ""
	DetailHref  string               `json:"detail_href"`        // "#/rules/skill/<name>" | "#/rules/mcp/<name>" | ""
	Declined    bool                 `json:"declined,omitempty"` // a Book.Recommended row the person said no to (DeclinedFile)
	Intent      *IntentRef           `json:"intent,omitempty"`   // the everywhere intent the row belongs to, or nil
}

// IntentRef names the everywhere intent a row belongs to: its id
// ("intent:<what>:<hex8>"), a sentence for the whole intent and how many
// rows of the Book belong to it.
type IntentRef struct {
	ID       string `json:"id"`
	Sentence string `json:"sentence"`
	Rows     int    `json:"rows"`
}

// Group is one section of the rulebook.
type Group struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	Rows  []Rule `json:"rows"`
}

// Book is every rule on the machine. Recommended lists the recommended
// rules not yet installed; Drift the ledger entries the person removed.
type Book struct {
	Groups      []Group                    `json:"groups"`
	Recommended []Rule                     `json:"recommended"`
	Drift       []claudesettings.Drift     `json:"drift"`
	Files       []claudesettings.FileState `json:"files"`
	Warnings    []string                   `json:"warnings"`
	Updated     time.Time                  `json:"updated"`
}

// Input is what List reads. Nil fields are loaded from Paths and
// ProjectRoot (an empty root reads no project files).
type Input struct {
	Paths       paths.Paths
	ProjectRoot string
	Effective   *claudesettings.Effective // nil: List reads it
	Ledger      *claudesettings.Ledger    // nil: List loads it read-only
	Policy      *policy.Policy            // nil: List loads user + project files
	// projectPolicyOnly is set by Undo for a resolution written at project
	// scope: a policy row of an intent (whose id carries no scope) is then
	// removed from the project policy file only, never from the user file,
	// so a user-scope twin of the same value stays.
	projectPolicyOnly bool
}

// hash8 is fnv32a of s as 8 hex digits.
func hash8(s string) string {
	h := fnv.New32a()
	h.Write([]byte(s))
	return fmt.Sprintf("%08x", h.Sum32())
}

// RowID is a row's stable id:
//
//	native-*          native:<scope>:<key>:<fnv32a hex8 of value>
//	automode-*        automode:<scope>:<key>:<hex8>
//	sandbox-domain    domain:<scope>:<key>:<hex8>
//	sandbox-excluded  excluded:<scope>:<key>:<hex8>
//	pack              pack:<key = pack>/<value = rule id>
//	hook-regex        user:<value = rule id>
//	subject           subject:<key = subject kind>:<value = name>
//
// key is the dotted settings key (claudesettings.KeyDeny…) for the
// settings kinds. A subject's first row has subject:<kind>:<name>; each
// later row of that subject is subject:<kind>:<name>:<hex8 of
// "<list>:<entry>"> (list such as "paths.deny"), so the first three parts
// always name the subject.
func RowID(kind Kind, scope claudesettings.Scope, key, value string) string {
	switch kind {
	case KindNativeDeny, KindNativeAsk, KindNativeAllow:
		return "native:" + string(scope) + ":" + key + ":" + hash8(value)
	case KindAutoModeHard, KindAutoModeSoft, KindAutoModeAllow, KindAutoModeEnv:
		return "automode:" + string(scope) + ":" + key + ":" + hash8(value)
	case KindSandboxDomain:
		return "domain:" + string(scope) + ":" + key + ":" + hash8(value)
	case KindSandboxExcluded:
		return "excluded:" + string(scope) + ":" + key + ":" + hash8(value)
	case KindPack:
		return "pack:" + key + "/" + value
	case KindHookRegex:
		return "user:" + value
	case KindSubject:
		return "subject:" + key + ":" + value
	}
	return string(kind) + ":" + string(scope) + ":" + key + ":" + hash8(value)
}

// kindForKey maps a settings list key to its row kind.
func kindForKey(key string) Kind {
	switch key {
	case claudesettings.KeyDeny:
		return KindNativeDeny
	case claudesettings.KeyAsk:
		return KindNativeAsk
	case claudesettings.KeyAllow:
		return KindNativeAllow
	case claudesettings.KeyHardDeny:
		return KindAutoModeHard
	case claudesettings.KeySoftDeny:
		return KindAutoModeSoft
	case claudesettings.KeyAutoAllow:
		return KindAutoModeAllow
	case claudesettings.KeyEnvironment:
		return KindAutoModeEnv
	case claudesettings.KeyAllowedDomains, claudesettings.KeyDeniedDomains:
		return KindSandboxDomain
	case claudesettings.KeyExcluded:
		return KindSandboxExcluded
	}
	return ""
}

// actionForKey is the action a settings list key states.
func actionForKey(key string) string {
	switch key {
	case claudesettings.KeyDeny, claudesettings.KeyHardDeny, claudesettings.KeySoftDeny, claudesettings.KeyDeniedDomains:
		return "deny"
	case claudesettings.KeyAsk:
		return "ask"
	case claudesettings.KeyAllow, claudesettings.KeyAutoAllow, claudesettings.KeyAllowedDomains:
		return "allow"
	}
	return ""
}

// settingsKeys lists every settings list key in display order.
func settingsKeys() []string {
	return []string{
		claudesettings.KeyDeny, claudesettings.KeyAsk, claudesettings.KeyAllow,
		claudesettings.KeyHardDeny, claudesettings.KeySoftDeny, claudesettings.KeyAutoAllow, claudesettings.KeyEnvironment,
		claudesettings.KeyAllowedDomains, claudesettings.KeyDeniedDomains, claudesettings.KeyExcluded,
	}
}

// listFor returns eff's entries under a settings list key.
func listFor(eff claudesettings.Effective, key string) []claudesettings.Entry {
	switch key {
	case claudesettings.KeyDeny:
		return eff.Deny
	case claudesettings.KeyAsk:
		return eff.Ask
	case claudesettings.KeyAllow:
		return eff.Allow
	case claudesettings.KeyHardDeny:
		return eff.AutoMode.HardDeny
	case claudesettings.KeySoftDeny:
		return eff.AutoMode.SoftDeny
	case claudesettings.KeyAutoAllow:
		return eff.AutoMode.Allow
	case claudesettings.KeyEnvironment:
		return eff.AutoMode.Environment
	case claudesettings.KeyAllowedDomains:
		return eff.Sandbox.AllowedDomains
	case claudesettings.KeyDeniedDomains:
		return eff.Sandbox.DeniedDomains
	case claudesettings.KeyExcluded:
		return eff.Sandbox.Excluded
	}
	return nil
}

// ownExclusion is the sandbox.excludedCommands entry `enforce install`
// writes (settings.ExcludedCommand), spelled here to keep rulebook free of
// the settings package.
func ownExclusion() string { return paths.BinaryName + " run *" }

// scopeOwner is the owner of a string nobody claims, by its file's scope.
func scopeOwner(s claudesettings.Scope) Owner {
	switch s {
	case claudesettings.ScopeProject:
		return OwnerProject
	case claudesettings.ScopeManaged:
		return OwnerManaged
	}
	return OwnerUser // user and local
}

// sourceOwner and sourceScope map a policy file's source.
func sourceOwner(s manifest.Source) Owner {
	if s == manifest.SourceProject {
		return OwnerProject
	}
	return OwnerUser
}

func sourceScope(s manifest.Source) claudesettings.Scope {
	if s == manifest.SourceProject {
		return claudesettings.ScopeProject
	}
	return claudesettings.ScopeUser
}

// enforcementFor is the enforcement of a settings kind.
func enforcementFor(kind Kind) Enforcement {
	switch kind {
	case KindNativeDeny:
		return EnforceNativeDeny
	case KindNativeAsk:
		return EnforceNativePrompt
	case KindNativeAllow:
		return EnforceAllow
	case KindAutoModeHard, KindAutoModeSoft, KindAutoModeAllow, KindAutoModeEnv:
		return EnforceClassifier
	}
	return EnforceOS
}

// hookEnforcement is a pack or hook rule's enforcement by action.
func hookEnforcement(action string) Enforcement {
	if action == "log" {
		return EnforceAdvisory
	}
	return EnforceHookGate
}

// nativeRow is the row for one settings list entry, owned by its scope.
func nativeRow(kind Kind, e claudesettings.Entry, key string) Rule {
	action := actionForKey(key)
	r := Rule{
		ID:          RowID(kind, e.Scope, key, e.Value),
		Harness:     HarnessClaudeCode,
		Value:       e.Value,
		Action:      action,
		Kind:        kind,
		Scope:       e.Scope,
		Owner:       scopeOwner(e.Scope),
		Enforcement: enforcementFor(kind),
		State:       StateOn,
		Source:      Source{File: e.Path, Key: key, Index: e.Index},
	}
	switch kind {
	case KindNativeDeny, KindNativeAsk, KindNativeAllow:
		tool, inner := splitRule(e.Value)
		r.Tool = tool
		r.Sentence = Sentence(kind, action, tool, inner)
	default:
		r.Sentence = Sentence(kind, action, "", e.Value)
	}
	if e.Value == claudesettings.Defaults && strings.HasPrefix(string(kind), "automode-") {
		r.Owner = OwnerClaudeDefault
	}
	return r
}

// builder collects rows into the five groups.
type builder struct {
	sandbox, blocked, automode, watchdeck, ask, askGate, allow []Rule
	intents                                                    map[string]*intentHint // by everywhere intent id
}

func (b *builder) addSettings(r Rule) {
	switch r.Kind {
	case KindNativeDeny:
		b.blocked = append(b.blocked, r)
	case KindNativeAsk:
		b.ask = append(b.ask, r)
	case KindNativeAllow:
		b.allow = append(b.allow, r)
	case KindAutoModeHard, KindAutoModeSoft, KindAutoModeAllow, KindAutoModeEnv:
		b.automode = append(b.automode, r)
	default:
		b.sandbox = append(b.sandbox, r)
	}
}

// addGate puts a gate row in watchdeck, or in ask when its action is ask.
func (b *builder) addGate(r Rule) {
	if r.Action == "ask" {
		b.askGate = append(b.askGate, r)
		return
	}
	b.watchdeck = append(b.watchdeck, r)
}

func (b *builder) groups() []Group {
	nonNil := func(rs []Rule) []Rule {
		if rs == nil {
			return []Rule{}
		}
		return rs
	}
	ask := append(append(append([]Rule{}, b.ask...), b.askGate...), b.allow...)
	return []Group{
		{ID: GroupSandbox, Title: "Sandbox", Rows: nonNil(b.sandbox)},
		{ID: GroupBlocked, Title: "Blocked", Rows: nonNil(b.blocked)},
		{ID: GroupAutoMode, Title: "Auto mode", Rows: nonNil(b.automode)},
		{ID: GroupWatchdeck, Title: paths.BinaryName + " rules", Rows: nonNil(b.watchdeck)},
		{ID: GroupAsk, Title: "Ask first, or allowed without asking", Rows: ask},
	}
}

// List composes every rule on the machine into a Book. It writes nothing:
// the ledger is reconciled on a copy to find Drift, and nothing is saved.
// A settings or policy file that cannot be read becomes a Warning naming
// it, and the rest is still listed; List returns an error only for a
// failure of its own, never for a bad file.
func List(in Input) (Book, error) {
	book := Book{Recommended: []Rule{}, Drift: []claudesettings.Drift{}, Warnings: []string{}, Updated: time.Now().UTC()}

	led := in.Ledger
	if led == nil {
		l, err := claudesettings.LoadLedger(in.Paths.StateDir)
		if err != nil {
			book.Warnings = append(book.Warnings, "ownership ledger: "+err.Error())
		} else {
			led = l
		}
	}

	var eff claudesettings.Effective
	if in.Effective != nil {
		eff = *in.Effective
	} else {
		// Read's only error is "no existing file could be read"; every
		// file's own error is in eff.Files and becomes a warning below.
		eff, _ = claudesettings.Read(claudesettings.Locate(in.Paths, in.ProjectRoot), led)
	}
	book.Files = eff.Files
	for _, f := range eff.Files {
		if f.Err == nil {
			continue
		}
		msg := f.Err.Error()
		if !strings.Contains(msg, f.Path) {
			msg = f.Path + ": " + msg
		}
		book.Warnings = append(book.Warnings, "could not read "+string(f.Scope)+" settings: "+msg)
	}

	var b builder
	recommended := Recommended() // once per List; recommendedFor scans it
	for _, key := range settingsKeys() {
		kind := kindForKey(key)
		for _, e := range listFor(eff, key) {
			r := nativeRow(kind, e, key)
			if led != nil {
				if owners := led.Owners(e.Path, key, e.Value); owners != nil {
					r.Owner = OwnerUs
					b.markIntent(&r, firstIntent(owners), 2, nativeIntentValue(e.Value))
				}
			} else if e.Owned {
				r.Owner = OwnerUs
			}
			if kind == KindSandboxExcluded && e.Value == ownExclusion() && e.Scope != claudesettings.ScopeManaged {
				// `enforce install` writes this entry outside the ledger;
				// it is watchdeck's own, not the person's (Plan 05 Task 6).
				r.Owner = OwnerUs
				r.Sentence = "Runs outside Claude Code's sandbox so " + paths.BinaryName + " can apply its own sandbox: " + e.Value
			}
			if rec, ok := recommendedFor(recommended, key, e.Value); ok {
				r.Recommended, r.Twin = true, rec.Twin
			}
			b.addSettings(r)
		}
	}

	// Drift: reconcile a copy so neither the caller's ledger nor the file changes.
	if led != nil {
		cp := &claudesettings.Ledger{V: led.V, Entries: make([]claudesettings.LedgerEntry, len(led.Entries))}
		for i, e := range led.Entries {
			e.RuleIDs = append([]string(nil), e.RuleIDs...)
			cp.Entries[i] = e
		}
		for _, d := range claudesettings.Reconcile(cp, eff) {
			book.Drift = append(book.Drift, d)
			kind := kindForKey(d.Entry.Key)
			if kind == "" {
				continue
			}
			scope := claudesettings.ScopeUser
			for _, f := range eff.Files {
				if filepath.Clean(f.Path) == filepath.Clean(d.Entry.Path) {
					scope = f.Scope
				}
			}
			r := nativeRow(kind, claudesettings.Entry{Value: d.Entry.Value, Scope: scope, Path: d.Entry.Path, Index: -1}, d.Entry.Key)
			r.Owner, r.State = OwnerUs, StateRemoved
			b.markIntent(&r, firstIntent(d.Entry.RuleIDs), 2, nativeIntentValue(d.Entry.Value))
			if rec, ok := recommendedFor(recommended, d.Entry.Key, d.Entry.Value); ok {
				r.Recommended, r.Twin = true, rec.Twin
			}
			b.addSettings(r)
		}
	}

	pol := in.Policy
	if pol == nil {
		projectPath := ""
		if in.ProjectRoot != "" {
			projectPath = filepath.Join(in.ProjectRoot, manifest.ProjectOverridesFile)
		}
		p, warns, err := policy.Load(in.Paths.OverridesFile(), projectPath)
		if err != nil {
			book.Warnings = append(book.Warnings, "could not read policy: "+err.Error())
			p, _ = policy.New(policy.Layer{}, policy.Layer{})
		}
		for _, w := range warns {
			book.Warnings = append(book.Warnings, w.String())
		}
		pol = p
	}
	addSubjects(&b, pol)
	addPacks(&b, pol.RulesConfig(), &book)
	addUserRules(&b, pol)

	book.Groups = b.groups()
	fillIntents(book.Groups, b.intents)
	missing := RecommendedMissing(eff)
	if len(missing) > 0 {
		d, err := LoadDeclined(in.Paths.StateDir)
		if err != nil {
			book.Warnings = append(book.Warnings, "declined recommended rules: "+err.Error())
		}
		for i := range missing {
			missing[i].Declined = d.Has(IntentPrefix + IntentID(missing[i].Value))
		}
	}
	book.Recommended = append(book.Recommended, missing...)
	return book, nil
}

// layerOf returns the policy layer a source names.
func layerOf(pol *policy.Policy, s manifest.Source) policy.Layer {
	if s == manifest.SourceProject {
		return pol.Project
	}
	return pol.User
}

// addPacks adds one row per built-in pack rule with its effective action
// (rule override, else pack override, else its own) and state.
func addPacks(b *builder, cfg rules.Config, book *Book) {
	packs := rules.Packs()
	if packs == nil {
		if err := rules.LoadError(); err != nil {
			book.Warnings = append(book.Warnings, "built-in rule packs: "+err.Error())
		}
		return
	}
	for _, p := range packs {
		pc, hasPC := cfg.Packs[p.Name]
		packOn := p.EnabledByDefault()
		if hasPC && pc.Enabled != nil {
			packOn = *pc.Enabled
		}
		for ri, r := range p.Rules {
			rc, hasRC := cfg.Rules[p.Name+"/"+r.ID]
			on := packOn
			if hasRC && rc.Enabled != nil {
				on = *rc.Enabled
			}
			act := r.Action
			if hasPC && pc.Action != "" {
				act = pc.Action
			}
			if hasRC && rc.Action != "" {
				act = rc.Action
			}
			state := StateOn
			if !on {
				state = StateOff
			}
			b.watchdeck = append(b.watchdeck, Rule{
				ID:          RowID(KindPack, "", p.Name, r.ID),
				Harness:     HarnessClaudeCode,
				Tool:        r.Tool,
				Value:       p.Name + "/" + r.ID,
				Action:      string(act),
				Sentence:    Sentence(KindPack, string(act), r.Tool, r.Description),
				Kind:        KindPack,
				Scope:       claudesettings.ScopeUser,
				Owner:       OwnerUs,
				Enforcement: hookEnforcement(string(act)),
				State:       state,
				Source:      Source{Key: "packs." + p.Name, Index: ri},
			})
		}
	}
}

// addUserRules adds the user's and the project's own hook rules.
func addUserRules(b *builder, pol *policy.Policy) {
	idx := map[manifest.Source]int{}
	for _, r := range pol.Rules() {
		value := r.Match.Regex
		if value == "" {
			value = strings.Join(r.Match.Literals, ", ")
		}
		if value == "" {
			value = strings.Join(r.Match.Argv0, ", ")
		}
		row := Rule{
			ID:          RowID(KindHookRegex, sourceScope(r.Source), "", r.ID),
			Harness:     HarnessClaudeCode,
			Tool:        r.Tool,
			Value:       value,
			Action:      r.Action,
			Sentence:    hookSentence(r.Action, r.Tool, r.Match),
			Kind:        KindHookRegex,
			Scope:       sourceScope(r.Source),
			Owner:       sourceOwner(r.Source),
			Enforcement: hookEnforcement(r.Action),
			State:       StateOn,
			Source:      Source{File: layerOf(pol, r.Source).Path, Key: "rules", Index: idx[r.Source]},
		}
		if id, ok := intentOfRule(r.ID); ok {
			first := ""
			if len(r.Match.Literals) > 0 {
				first = r.Match.Literals[0]
			}
			b.markIntent(&row, id, 0, first)
		}
		b.watchdeck = append(b.watchdeck, row)
		idx[r.Source]++
	}
}

// addSubjects adds subject rows: skill and command subjects and MCP
// launches are sandbox rows; tool, agent and MCP tool gates give one row
// per entry.
func addSubjects(b *builder, pol *policy.Policy) {
	for _, s := range pol.Subjects() {
		layer := layerOf(pol, s.Source)
		index := -1
		for i, fs := range layer.File.Subjects {
			if fs.Kind == s.Kind && fs.Name == s.Name {
				index = i
				break
			}
		}
		scope := sourceScope(s.Source)
		base := Rule{
			Harness: HarnessClaudeCode,
			Kind:    KindSubject,
			Scope:   scope,
			Owner:   sourceOwner(s.Source),
			State:   StateOn,
			Source:  Source{File: layer.Path, Key: "subjects", Index: index},
		}
		id := RowID(KindSubject, scope, s.Kind, s.Name)
		first := true
		// rowID gives the subject's first row the bare id and every later
		// row the id with the hash of "<list>:<entry>".
		rowID := func(list, entry string) string {
			if first {
				first = false
				return id
			}
			return id + ":" + hash8(list+":"+entry)
		}
		intent := ""
		if s.Kind == policy.KindTool {
			intent, _ = intentOfSubject(s.Name)
		}
		gate := func(list, action, tool, value, sentence string) {
			r := base
			r.ID = rowID(list, value)
			r.Tool, r.Value, r.Action, r.Sentence = tool, value, action, sentence
			r.Enforcement = EnforceHookGate
			if s.Kind == policy.KindMCP {
				r.DetailHref = "#/rules/mcp/" + s.Name
			}
			b.markIntent(&r, intent, 1, value)
			b.addGate(r)
		}

		switch s.Kind {
		case policy.KindSkill, policy.KindCommand:
			r := base
			r.ID, r.Value, r.Enforcement = rowID("", s.Name), s.Name, EnforceOS
			if s.Kind == policy.KindSkill {
				grant, _ := pol.SkillGrant(s.Name)
				r.Tool, r.Sentence, r.DetailHref = "Skill", sandboxSubjectSentence(s.Name, grant), "#/rules/skill/"+s.Name
			} else {
				grant, _ := pol.CommandGrant(s)
				r.Tool, r.Sentence = "Bash", sandboxSubjectSentence(s.Name, grant)
			}
			b.sandbox = append(b.sandbox, r)
		case policy.KindMCP:
			if s.Class() == policy.ClassSandbox {
				r := base
				r.ID, r.Value, r.Tool, r.Enforcement = rowID("launch", s.Name), s.Name, "mcp__"+s.Name, EnforceOS
				r.Sentence, r.DetailHref = mcpLaunchSentence(s.Name), "#/rules/mcp/"+s.Name
				b.sandbox = append(b.sandbox, r)
			}
			globs := make([]string, 0, len(s.MCPTools))
			for g := range s.MCPTools {
				globs = append(globs, g)
			}
			sort.Strings(globs)
			for _, g := range globs {
				act := s.MCPTools[g]
				tool := "mcp__" + s.Name + "__" + g
				gate("tools", act, tool, g, Sentence(KindNativeDeny, act, tool, ""))
			}
		case policy.KindTool:
			tools := s.Match.Tools
			for _, l := range []struct {
				name string
				g    *manifest.GateLists
			}{{"paths", s.Paths}, {"domains", s.Domains}} {
				if l.g == nil {
					continue
				}
				for _, e := range l.g.Deny {
					gate(l.name+".deny", "deny", strings.Join(tools, "|"), e, toolGateSentence("deny", tools, e))
				}
				for _, e := range l.g.Ask {
					gate(l.name+".ask", "ask", strings.Join(tools, "|"), e, toolGateSentence("ask", tools, e))
				}
			}
		case policy.KindAgent:
			at := s.Match.AgentType
			if s.AgentTools != nil {
				for _, t := range s.AgentTools.Deny {
					gate("tools.deny", "deny", t, t, agentSentence(at, "deny", t))
				}
				for _, t := range s.AgentTools.Ask {
					gate("tools.ask", "ask", t, t, agentSentence(at, "ask", t))
				}
			}
			if s.AgentSkills != nil {
				gate("skills.allow", "deny", "Skill", strings.Join(s.AgentSkills, ", "), agentSkillsSentence(at, s.AgentSkills))
			}
		}
	}
}
