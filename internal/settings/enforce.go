package settings

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
)

// ExcludedCommand is the sandbox.excludedCommands entry that lets `watchdeck run`
// apply its own profile when Claude Code's Bash sandbox is on.
const ExcludedCommand = paths.BinaryName + " run *"

// The six hook registrations. All run the same `watchdeck hook` command,
// which dispatches on the event and tool it is given. The three lifecycle
// events (M5.2) are registered without a matcher, so every SessionStart
// source and SessionEnd reason arrives; UserPromptSubmit takes none.
const (
	EventPre          = "PreToolUse"       // sandbox skill scripts (Bash); attribute skill use (Skill)
	EventDenied       = "PermissionDenied" // auto-mode denials
	EventSessionStart = "SessionStart"     // lifecycle: start record and live marker
	EventSessionEnd   = "SessionEnd"       // lifecycle: end record, marker removed
	EventPrompt       = "UserPromptSubmit" // lifecycle: heartbeat
	MatcherBash       = "Bash"
	MatcherSkill      = "Skill"
	MatcherDenied     = "*"          // every tool (2026-10-19; M4 to M6 installs wrote MatcherDeniedOld)
	MatcherDeniedOld  = "Bash|Skill" // the earlier PermissionDenied matcher; Install migrates it to MatcherDenied
	MatcherAll        = ""           // no "matcher" key in the group
)

// registration is one (event, matcher) pair Install adds and Uninstall removes.
type registration struct {
	event, matcher string
}

// registrations lists the hook groups in install order. A slice of
// constants (not a map) so the package stays init-free.
var registrations = []registration{
	{EventPre, MatcherBash},
	{EventPre, MatcherSkill},
	{EventDenied, MatcherDenied},
	{EventSessionStart, MatcherAll},
	{EventSessionEnd, MatcherAll},
	{EventPrompt, MatcherAll},
}

// HookCount is how many hook registrations a complete install holds.
const HookCount = 6

// events lists each event of registrations once, in install order.
func events() []string {
	var out []string
	for _, r := range registrations {
		if len(out) == 0 || out[len(out)-1] != r.event {
			out = append(out, r.event)
		}
	}
	return out
}

// Change reports what Install or Uninstall did.
type Change struct {
	Added   []string
	Removed []string
	Updated []string // our hooks repointed from a missing binary ("hooks.E: old -> new hook")
	Backup  string
}

// Changed is true when anything was added, removed or updated.
func (c Change) Changed() bool { return len(c.Added)+len(c.Removed)+len(c.Updated) > 0 }

// Status describes a settings file's watchdeck state.
type Status struct {
	Exists         bool
	HookInstalled  bool   // PreToolUse group with matcher Bash holding our hook (name kept for compatibility)
	HookCommand    string // command of that Bash group's hook entry; falls back to the Skill or PermissionDenied entry when the Bash group is absent
	SkillHook      bool   // PreToolUse group with matcher Skill holding our hook
	DeniedHook     bool   // PermissionDenied group with matcher * holding our hook
	StartHook      bool   // SessionStart group without a matcher holding our hook (M5.2)
	EndHook        bool   // SessionEnd group without a matcher holding our hook (M5.2)
	PromptHook     bool   // UserPromptSubmit group without a matcher holding our hook (M5.2)
	Excluded       bool   // sandbox.excludedCommands holds ExcludedCommand
	SandboxEnabled bool   // sandbox.enabled is true
	Complete       bool   // all HookCount hooks && Excluded
}

// Count is how many of the HookCount registrations hold our hook.
func (st Status) Count() int {
	n := 0
	for _, b := range st.flags() {
		if b {
			n++
		}
	}
	return n
}

// Missing names the registrations without our hook, in install order
// ("PreToolUse Skill", "SessionStart").
func (st Status) Missing() []string {
	var out []string
	for i, b := range st.flags() {
		if !b {
			out = append(out, registrations[i].label())
		}
	}
	return out
}

// Lifecycle reports whether all three lifecycle hooks are registered.
func (st Status) Lifecycle() bool { return st.StartHook && st.EndHook && st.PromptHook }

// flags is the per-registration state, in registrations order.
func (st Status) flags() []bool {
	return []bool{st.HookInstalled, st.SkillHook, st.DeniedHook, st.StartHook, st.EndHook, st.PromptHook}
}

// label is "Event" or "Event Matcher".
func (r registration) label() string {
	if r.matcher == MatcherAll {
		return r.event
	}
	return r.event + " " + r.matcher
}

// eventGroups returns the hook groups registered under hooks.<event>. With
// create, missing containers are added; an existing value of the wrong type is
// an error rather than something to overwrite.
func eventGroups(obj *Object, event string, create bool) ([]any, *Object, error) {
	if v, ok := obj.Get("hooks"); ok {
		if _, isObj := v.(*Object); !isObj {
			return nil, nil, fmt.Errorf("settings: \"hooks\" is not an object")
		}
	}
	hooks := obj.Object("hooks", create)
	if hooks == nil {
		return nil, nil, nil
	}
	v, present := hooks.Get(event)
	if !present {
		if !create {
			return nil, hooks, nil
		}
		arr := []any{}
		hooks.Set(event, arr)
		return arr, hooks, nil
	}
	arr, ok := v.([]any)
	if !ok {
		return nil, nil, fmt.Errorf("settings: \"hooks.%s\" is not an array", event)
	}
	return arr, hooks, nil
}

// isOurHook reports whether a hook entry runs this binary (paths.BinaryName),
// and returns its command. See hookNamed for what is accepted.
func isOurHook(h any) (string, bool) { return hookNamed(h, paths.BinaryName) }

// hookNamed reports whether a hook entry runs a binary called name, and
// returns its command. Accepted: a binary called name (exec form, any args,
// as v0.1 wrote it), the shell form `… name hook`, and the exec form of a
// binary whose name starts with name when its first arg is `hook` (Install
// records whatever os.Executable resolves to, so a build with a suffixed name
// such as name_darwin_arm64 must still be recognised for idempotence and
// uninstall).
func hookNamed(h any, name string) (string, bool) {
	ho, ok := h.(*Object)
	if !ok {
		return "", false
	}
	cmd, _ := ho.Get("command")
	s, _ := cmd.(string)
	base := s
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	if base == name || strings.HasPrefix(base, name+" ") || strings.Contains(s, "/"+name+" hook") || strings.HasSuffix(s, name+" hook") {
		return s, true
	}
	if strings.HasPrefix(base, name) {
		if args, ok := ho.Array("args"); ok && len(args) > 0 {
			if first, _ := args[0].(string); first == "hook" {
				return s, true
			}
		}
	}
	return "", false
}

// hookText renders a hook entry as the command line it runs: command plus string args.
func hookText(h any) string {
	ho, ok := h.(*Object)
	if !ok {
		return ""
	}
	cmd, _ := ho.Get("command")
	s, _ := cmd.(string)
	if args, ok := ho.Array("args"); ok {
		for _, a := range args {
			if as, ok := a.(string); ok {
				s += " " + as
			}
		}
	}
	return s
}

// groupMatcher returns a group's matcher string ("" when absent or not a string).
func groupMatcher(g *Object) string {
	m, _ := g.Get("matcher")
	s, _ := m.(string)
	return s
}

// findHookFor returns the command of our hook inside a group whose matcher is
// exactly matcher. A group is ours for matcher M when matcher == M and it holds
// an isOurHook entry.
func findHookFor(groups []any, matcher string) (string, bool) {
	for _, g := range groups {
		go_, ok := g.(*Object)
		if !ok || groupMatcher(go_) != matcher {
			continue
		}
		hs, _ := go_.Array("hooks")
		for _, h := range hs {
			if cmd, ok := isOurHook(h); ok {
				return cmd, true
			}
		}
	}
	return "", false
}

// countHooksFor counts our hook entries across every group whose matcher is
// exactly matcher.
func countHooksFor(groups []any, matcher string) int {
	n := 0
	for _, g := range groups {
		go_, ok := g.(*Object)
		if !ok || groupMatcher(go_) != matcher {
			continue
		}
		hs, _ := go_.Array("hooks")
		for _, h := range hs {
			if _, ok := isOurHook(h); ok {
				n++
			}
		}
	}
	return n
}

func newHookGroup(binary, matcher string) *Object {
	h := NewObject()
	h.Set("type", "command")
	h.Set("command", binary)
	h.Set("args", []any{"hook"})
	h.Set("timeout", 5)
	g := NewObject()
	if matcher != MatcherAll {
		g.Set("matcher", matcher)
	}
	g.Set("hooks", []any{h})
	return g
}

func addedLine(r registration, binary string) string {
	line := "hooks." + r.event + ": " + binary + " hook"
	if r.matcher != MatcherAll {
		line += " (matcher " + r.matcher + ")"
	}
	return line
}

// excluded returns sandbox.excludedCommands, the sandbox object (nil when
// absent) and whether ExcludedCommand is listed. A "sandbox" or
// "excludedCommands" value of the wrong type is an error, never overwritten.
func excluded(obj *Object) ([]any, *Object, bool, error) {
	v, present := obj.Get("sandbox")
	if !present {
		return nil, nil, false, nil
	}
	sb, ok := v.(*Object)
	if !ok {
		return nil, nil, false, fmt.Errorf("settings: \"sandbox\" is not an object")
	}
	ev, present := sb.Get("excludedCommands")
	if !present {
		return nil, sb, false, nil
	}
	arr, ok := ev.([]any)
	if !ok {
		return nil, nil, false, fmt.Errorf("settings: \"sandbox.excludedCommands\" is not an array")
	}
	for _, v := range arr {
		if s, ok := v.(string); ok && s == ExcludedCommand {
			return arr, sb, true, nil
		}
	}
	return arr, sb, false, nil
}

// repoint points every exec-form hook entry of ours whose binary is gone (or
// is not an executable file) at binary, and returns one line per entry. A
// Homebrew upgrade with cleanup, or a moved build, leaves such an entry; Claude
// Code then cannot spawn the hook and treats that as a non-blocking error, so
// scripts would run without the rewrite. An entry naming a binary that still
// runs is someone's choice and is left alone, and so is a shell-form entry.
// Nothing is repointed at a binary that is itself missing.
func repoint(obj *Object, binary string) ([]string, error) {
	if !executable(binary) {
		return nil, nil
	}
	var out []string
	for _, event := range append(events(), EventPost) {
		groups, _, err := eventGroups(obj, event, false)
		if err != nil {
			return nil, err
		}
		for _, g := range groups {
			go_, ok := g.(*Object)
			if !ok {
				continue
			}
			hs, _ := go_.Array("hooks")
			for _, h := range hs {
				cmd, ok := isOurHook(h)
				if !ok || cmd == binary || !filepath.IsAbs(cmd) || executable(cmd) {
					continue
				}
				ho := h.(*Object)
				if args, _ := ho.Array("args"); len(args) == 0 {
					continue // shell form: the command line is the user's
				}
				ho.Set("command", binary)
				line := "hooks." + event + ": " + cmd + " -> " + hookText(ho)
				if m := groupMatcher(go_); m != "" {
					line += " (matcher " + m + ")"
				}
				out = append(out, line)
			}
		}
	}
	return out, nil
}

// migrateDenied widens our PermissionDenied registration from the old
// Bash|Skill matcher to "*" (2026-10-19). A group holding only our hook is
// changed in place, so every other byte of the file stays. When the group
// also holds someone else's hook, only our entry leaves it and a new group is
// added by the registrations loop; when a "*" group of ours already exists,
// the old entry is just removed. It never leaves two entries of ours.
func migrateDenied(obj *Object) ([]string, error) {
	groups, hooks, err := eventGroups(obj, EventDenied, false)
	if err != nil || hooks == nil {
		return nil, err
	}
	_, haveNew := findHookFor(groups, MatcherDenied)
	var out []string
	kept := make([]any, 0, len(groups))
	changed := false
	for _, g := range groups {
		go_, ok := g.(*Object)
		if !ok || groupMatcher(go_) != MatcherDeniedOld {
			kept = append(kept, g)
			continue
		}
		hs, _ := go_.Array("hooks")
		var keptHooks []any
		var ours []string
		for _, h := range hs {
			if _, isOurs := isOurHook(h); isOurs {
				ours = append(ours, hookText(h))
				continue
			}
			keptHooks = append(keptHooks, h)
		}
		if len(ours) == 0 {
			kept = append(kept, g)
			continue
		}
		changed = true
		for _, o := range ours {
			out = append(out, "hooks."+EventDenied+": "+o+" (matcher "+MatcherDeniedOld+" -> "+MatcherDenied+")")
		}
		switch {
		case len(keptHooks) == 0 && !haveNew && len(ours) == 1:
			go_.Set("matcher", MatcherDenied)
			kept = append(kept, go_)
			haveNew = true
		case len(keptHooks) == 0:
			// the group held only our entries: drop it
		default:
			go_.Set("hooks", keptHooks)
			kept = append(kept, go_)
		}
	}
	if changed {
		hooks.Set(EventDenied, kept)
	}
	return out, nil
}

// executable reports whether p is a regular file with an execute bit.
func executable(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.Mode().IsRegular() && st.Mode().Perm()&0o111 != 0
}

// Install registers the six hooks (exec form, absolute binary path), each as
// a new group under its event, and adds the sandbox exclusion. Whichever of the
// seven is already present is left alone, so a v0.1 file holding only the Bash
// group gains exactly the five new groups and an M4 file the three lifecycle
// groups. Existing entries are never modified, except that one of ours naming
// a binary that is gone is repointed at binary (repoint).
// Idempotent: a second call reports no change and does not rewrite the file.
func Install(path, binary string) (Change, error) {
	return install(path, binary, false, true, false, Extra{})
}

// InstallExclusion adds only the sandbox exclusion (for a session whose hooks
// come from the plugin), with the same backup and idempotence as Install.
func InstallExclusion(path string) (Change, error) {
	return install(path, "", true, true, false, Extra{})
}

// Plan reports what Install (exclusionOnly false) or InstallExclusion would
// add, without writing anything: the Change.Added lines, then each
// Change.Updated line as "(update) <line>".
func Plan(path, binary string, exclusionOnly bool) ([]string, error) {
	ch, err := install(path, binary, exclusionOnly, false, false, Extra{})
	out := ch.Added
	for _, u := range ch.Updated {
		out = append(out, "(update) "+u)
	}
	return out, err
}

// install does Install, InstallExclusion and their plans. With prune (the
// policy-aware InstallWith and PlanWith), our entry in a file-tools group
// other than the one extra asks for is removed (dropFiles), so a narrowed or
// widened need moves it.
func install(path, binary string, exclusionOnly, write, prune bool, extra Extra) (Change, error) {
	obj, _, err := Load(path)
	if err != nil {
		return Change{}, err
	}
	var ch Change
	if !exclusionOnly {
		// One PreToolUse call must reach the hook once. With a wildcard
		// group (an agent or user rule names tools by a wildcard) our hook
		// lives only there: Bash, Skill and the tool groups are left out, and
		// our entries in them are removed. Without one, our entry in an
		// earlier install's wildcard group is removed (extra.go).
		wild := extra.wildcard()
		removed, err := dropOverlaps(obj, wild)
		if err != nil {
			return Change{}, err
		}
		ch.Removed = append(ch.Removed, removed...)
		if prune && !wild {
			dropped, err := dropFiles(obj, extra.fileMatcher())
			if err != nil {
				return Change{}, err
			}
			ch.Removed = append(ch.Removed, dropped...)
		}
		if ch.Updated, err = repoint(obj, binary); err != nil {
			return Change{}, err
		}
		migrated, err := migrateDenied(obj)
		if err != nil {
			return Change{}, err
		}
		ch.Updated = append(ch.Updated, migrated...)
		for _, r := range append(append([]registration(nil), registrations...), extra.regs()...) {
			if wild && r.event == EventPre && !isWildcard(r.matcher) {
				continue
			}
			groups, hooks, err := eventGroups(obj, r.event, true)
			if err != nil {
				return Change{}, err
			}
			if _, ok := findHookFor(groups, r.matcher); ok {
				continue
			}
			hooks.Set(r.event, append(groups, newHookGroup(binary, r.matcher)))
			ch.Added = append(ch.Added, addedLine(r, binary))
		}
	}
	arr, sb, ok, err := excluded(obj)
	if err != nil {
		return Change{}, err
	}
	if !ok {
		if sb == nil {
			sb = obj.Object("sandbox", true)
		}
		sb.Set("excludedCommands", append(arr, ExcludedCommand))
		ch.Added = append(ch.Added, "sandbox.excludedCommands: "+ExcludedCommand)
	}
	if !ch.Changed() || !write {
		return ch, nil
	}
	ch.Backup, err = Save(path, obj, true)
	return ch, err
}

// Uninstall removes every hook entry that is ours under each event Install
// registers, whatever its matcher, and the sandbox exclusion.
// Groups, arrays and containers left empty by the removal are dropped so the
// file returns to its prior shape.
func Uninstall(path string) (Change, error) { return uninstall(path, true) }

// UninstallPlan lists what Uninstall would remove from the file at path,
// without writing anything.
func UninstallPlan(path string) ([]string, error) {
	ch, err := uninstall(path, false)
	return ch.Removed, err
}

func uninstall(path string, write bool) (Change, error) {
	obj, existed, err := Load(path)
	if err != nil {
		return Change{}, err
	}
	if !existed {
		return Change{}, nil
	}
	var ch Change
	for _, event := range append(events(), EventPost) {
		groups, hooks, err := eventGroups(obj, event, false)
		if err != nil {
			return Change{}, err
		}
		if hooks == nil {
			continue
		}
		kept := make([]any, 0, len(groups))
		for _, g := range groups {
			go_, ok := g.(*Object)
			if !ok {
				kept = append(kept, g)
				continue
			}
			hs, _ := go_.Array("hooks")
			var keptHooks []any
			for _, h := range hs {
				if _, ok := isOurHook(h); ok {
					line := "hooks." + event + ": " + hookText(h)
					if m := groupMatcher(go_); m != "" {
						line += " (matcher " + m + ")"
					}
					ch.Removed = append(ch.Removed, line)
					continue
				}
				keptHooks = append(keptHooks, h)
			}
			if len(keptHooks) == 0 && len(hs) > 0 {
				continue // group held only our hook
			}
			if len(keptHooks) != len(hs) {
				go_.Set("hooks", keptHooks)
			}
			kept = append(kept, go_)
		}
		if len(kept) == len(groups) {
			continue
		}
		if len(kept) == 0 {
			hooks.Delete(event)
		} else {
			hooks.Set(event, kept)
		}
		if hooks.Len() == 0 {
			obj.Delete("hooks")
		}
	}
	arr, sb, ok, err := excluded(obj)
	if err != nil {
		return Change{}, err
	}
	if ok {
		var kept []any
		for _, v := range arr {
			if s, _ := v.(string); s == ExcludedCommand {
				continue
			}
			kept = append(kept, v)
		}
		if len(kept) == 0 {
			sb.Delete("excludedCommands")
		} else {
			sb.Set("excludedCommands", kept)
		}
		if sb.Len() == 0 {
			obj.Delete("sandbox")
		}
		ch.Removed = append(ch.Removed, "sandbox.excludedCommands: "+ExcludedCommand)
	}
	if !ch.Changed() || !write {
		return ch, nil
	}
	ch.Backup, err = Save(path, obj, true)
	return ch, err
}

// Inspect reports the watchdeck state of a settings file without changing it.
func Inspect(path string) (Status, error) {
	obj, existed, err := Load(path)
	if err != nil {
		return Status{}, err
	}
	st := Status{Exists: existed}
	found := make([]bool, len(registrations))
	for i, r := range registrations {
		groups, _, err := eventGroups(obj, r.event, false)
		if err != nil {
			return Status{}, err
		}
		var cmd string
		cmd, found[i] = findHookFor(groups, r.matcher)
		if !found[i] && r.event == EventDenied {
			// a matcher-less group is the same as "*"
			cmd, found[i] = findHookFor(groups, MatcherAll)
		}
		if !found[i] && r.event == EventPre {
			// a wildcard PreToolUse group of ours covers Bash and Skill (M6.3)
			if c, ok := findHookFor(groups, MatcherAnyTool); ok {
				cmd, found[i] = c, true
			} else if c, ok := findHookFor(groups, MatcherAll); ok {
				cmd, found[i] = c, true
			}
		}
		if st.HookCommand == "" {
			st.HookCommand = cmd // the Bash group's command first, then the next one present
		}
	}
	st.HookInstalled, st.SkillHook, st.DeniedHook = found[0], found[1], found[2]
	st.StartHook, st.EndHook, st.PromptHook = found[3], found[4], found[5]
	_, sb, ok, err := excluded(obj)
	if err != nil {
		return Status{}, err
	}
	st.Excluded = ok
	if sb != nil {
		if v, ok := sb.Get("enabled"); ok {
			b, _ := v.(bool)
			st.SandboxEnabled = b
		}
	}
	st.Complete = st.Count() == HookCount && st.Excluded
	return st, nil
}

// Registered is a settings file's PreToolUse registration of our hook.
type Registered struct {
	Command string        // the entry's "command" verbatim
	Args    []string      // its string "args", nil when absent
	Timeout time.Duration // "timeout" in seconds, 0 when absent or not a positive number
	Matcher string        // the group it was found in: MatcherBash, MatcherAnyTool or MatcherAll
	Shell   bool          // not an absolute path without blanks, or has no args: Claude Code runs it through the shell
}

// Text is the command line it runs, command plus args (as hookText renders it).
func (r Registered) Text() string {
	return strings.Join(append([]string{r.Command}, r.Args...), " ")
}

// Registration returns the PreToolUse entry of ours that decides Bash calls
// in the file at path: the Bash group first, then a "*" group, then a
// matcher-less group (the same fallback Inspect uses), never the Skill or
// PermissionDenied groups. found is false for a missing file or a file
// without one; err is a parse error.
func Registration(path string) (r Registered, found bool, err error) {
	obj, _, err := Load(path)
	if err != nil {
		return Registered{}, false, err
	}
	groups, _, err := eventGroups(obj, EventPre, false)
	if err != nil {
		return Registered{}, false, err
	}
	for _, m := range []string{MatcherBash, MatcherAnyTool, MatcherAll} {
		for _, g := range groups {
			go_, ok := g.(*Object)
			if !ok || groupMatcher(go_) != m {
				continue
			}
			hs, _ := go_.Array("hooks")
			for _, h := range hs {
				cmd, ok := isOurHook(h)
				if !ok {
					continue
				}
				r := Registered{Command: cmd, Matcher: m}
				ho := h.(*Object)
				if args, ok := ho.Array("args"); ok {
					for _, a := range args {
						if as, ok := a.(string); ok {
							r.Args = append(r.Args, as)
						}
					}
				}
				if v, ok := ho.Get("timeout"); ok {
					if n, ok := v.(json.Number); ok {
						if f, err := n.Float64(); err == nil && f > 0 {
							r.Timeout = time.Duration(f * float64(time.Second))
						}
					}
				}
				r.Shell = !(strings.HasPrefix(cmd, "/") && !strings.ContainsAny(cmd, " \t")) || len(r.Args) == 0
				return r, true, nil
			}
		}
	}
	return Registered{}, false, nil
}

// Duplicates names each registration that holds our hook more than once in
// the settings file at path ("PreToolUse Bash: 2 entries"). A missing file has
// none.
func Duplicates(path string) ([]string, error) {
	obj, _, err := Load(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, r := range registrations {
		groups, _, err := eventGroups(obj, r.event, false)
		if err != nil {
			return nil, err
		}
		n := countHooksFor(groups, r.matcher)
		if r.event == EventPre {
			// a wildcard group of ours also runs the hook for this tool
			n += countHooksFor(groups, MatcherAnyTool) + countHooksFor(groups, MatcherAll)
		}
		if r.event == EventDenied {
			// an old Bash|Skill group not yet migrated, or a matcher-less one
			n += countHooksFor(groups, MatcherDeniedOld) + countHooksFor(groups, MatcherAll)
		}
		if n > 1 {
			out = append(out, fmt.Sprintf("%s: %d entries", r.label(), n))
		}
	}
	// the extra tool groups overlapping a wildcard group (M6.3)
	pre, _, err := eventGroups(obj, EventPre, false)
	if err != nil {
		return nil, err
	}
	if w := countHooksFor(pre, MatcherAnyTool) + countHooksFor(pre, MatcherAll); w > 0 {
		for _, m := range []string{MatcherFiles, MatcherWeb, MatcherMCP} {
			if n := countHooksFor(pre, m); n > 0 {
				out = append(out, fmt.Sprintf("PreToolUse %s: %d entries besides a wildcard group", m, n))
			}
		}
	}
	return out, nil
}
