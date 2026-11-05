package settings

import (
	"sort"
	"strings"

	"github.com/Panda-Taps-LLC/watchdeck/internal/policy"
)

// Extra hook registrations (M6.3). Beyond the base six, `enforce install`
// and `setup` register PreToolUse for more tools, and PostToolUse for the
// web tools, only when the policy has rules or gates for them, so a user
// without gates on those tools never pays a hook spawn for them. The
// registration is a snapshot of the policy at install time: a gate added
// later needs `enforce install` again, which `doctor` and `enforce status`
// point out.
const (
	EventPost      = "PostToolUse"
	MatcherFiles   = "Read|Write|Edit|MultiEdit|NotebookEdit"
	MatcherSearch  = "Grep|Glob"
	MatcherWeb     = "WebFetch|WebSearch"
	MatcherMCP     = "mcp__.*"
	MatcherAnyTool = "*"
	MatcherPostWeb = "WebFetch|WebSearch"
)

// Extra is the set of extra registrations: PreToolUse matchers and
// PostToolUse matchers.
type Extra struct {
	Pre  []string
	Post []string
}

// PluginExtra is what the plugin's static hooks.json registers beyond the
// base six: it cannot follow the policy, so it registers every tool group
// the hook can gate and the hook answers no opinion when the policy has
// nothing for a tool (the tool fast filter). Grep and Glob carry path gates
// (review 2026-10-14). Other tools named by an agent gate or a user rule,
// and wildcards, are not registered: PluginUncovered names them.
func PluginExtra() Extra {
	return Extra{Pre: []string{MatcherFiles, MatcherSearch, MatcherWeb, MatcherMCP}, Post: []string{MatcherPostWeb}}
}

// PluginUncovered lists the PreToolUse tools in need (NeededExtra) that the
// plugin's static hooks.json does not register, sorted; a wildcard need is
// reported as "*". Gates on these tools never fire for a plugin user.
func PluginUncovered(need Extra) []string {
	covered := map[string]bool{MatcherBash: true, MatcherSkill: true}
	for _, m := range PluginExtra().Pre {
		for _, t := range strings.Split(m, "|") {
			covered[t] = true
		}
	}
	seen := map[string]bool{}
	var out []string
	for _, m := range need.Pre {
		if isWildcard(m) {
			m = MatcherAnyTool
		}
		for _, t := range strings.Split(m, "|") {
			if t == "" || covered[t] || seen[t] || strings.HasPrefix(t, "mcp__") {
				continue
			}
			seen[t] = true
			out = append(out, t)
		}
	}
	sort.Strings(out)
	return out
}

// isWildcard reports whether a PreToolUse matcher matches every tool.
func isWildcard(m string) bool { return m == MatcherAnyTool || m == MatcherAll }

// wildcard reports whether e has a PreToolUse group for every tool.
func (e Extra) wildcard() bool {
	for _, m := range e.Pre {
		if isWildcard(m) {
			return true
		}
	}
	return false
}

// dropOverlaps removes our hook entries that would make one PreToolUse call
// run the hook twice: with wild, our entries in every non-wildcard
// PreToolUse group; without, our entries in wildcard groups. A group left
// with no hooks is dropped. It returns the Uninstall-style lines.
func dropOverlaps(obj *Object, wild bool) ([]string, error) {
	groups, hooks, err := eventGroups(obj, EventPre, false)
	if err != nil || hooks == nil {
		return nil, err
	}
	var removed []string
	kept := make([]any, 0, len(groups))
	for _, g := range groups {
		go_, ok := g.(*Object)
		if !ok || isWildcard(groupMatcher(go_)) == wild {
			kept = append(kept, g)
			continue
		}
		hs, _ := go_.Array("hooks")
		var keptHooks []any
		for _, h := range hs {
			if _, ours := isOurHook(h); ours {
				line := "hooks." + EventPre + ": " + hookText(h)
				if m := groupMatcher(go_); m != "" {
					line += " (matcher " + m + ")"
				}
				removed = append(removed, line)
				continue
			}
			keptHooks = append(keptHooks, h)
		}
		if len(keptHooks) == 0 && len(hs) > 0 {
			continue
		}
		if len(keptHooks) != len(hs) {
			go_.Set("hooks", keptHooks)
		}
		kept = append(kept, go_)
	}
	if len(removed) > 0 {
		hooks.Set(EventPre, kept)
	}
	return removed, nil
}

// IsEmpty reports whether e registers nothing.
func (e Extra) IsEmpty() bool { return len(e.Pre)+len(e.Post) == 0 }

func (e Extra) regs() []registration {
	var out []registration
	for _, m := range e.Pre {
		out = append(out, registration{EventPre, m})
	}
	for _, m := range e.Post {
		out = append(out, registration{EventPost, m})
	}
	return out
}

// Labels names each registration ("PreToolUse Read|Write|…").
func (e Extra) Labels() []string {
	var out []string
	for _, r := range e.regs() {
		out = append(out, r.label())
	}
	return out
}

// ExtraFor maps a policy's needs onto registrations.
func ExtraFor(m policy.Matchers) Extra {
	var e Extra
	if m.All {
		e.Pre = append(e.Pre, MatcherAnyTool)
	} else {
		if len(m.FileTools) > 0 {
			e.Pre = append(e.Pre, strings.Join(m.FileTools, "|"))
		} else if m.Files {
			e.Pre = append(e.Pre, MatcherFiles)
		}
		if m.Web {
			e.Pre = append(e.Pre, MatcherWeb)
		}
		if m.MCP {
			e.Pre = append(e.Pre, MatcherMCP)
		}
		if len(m.Other) > 0 {
			e.Pre = append(e.Pre, strings.Join(m.Other, "|"))
		}
	}
	if m.PostWebFetch {
		e.Post = append(e.Post, MatcherPostWeb)
	}
	return e
}

// NeededExtra loads the policy (user file, and the project file when
// projectPath is set) and returns the registrations it needs. A malformed
// file registers the three tool groups (files, web, MCP), so its gates are
// not silently dropped once it is fixed; the hook asks while it is broken.
//
// The file-tools group names exactly the tools policy.FilesNeed lists (for
// example Write|Edit|MultiEdit|NotebookEdit), and is absent when it lists
// none. covered names the pack rules whose recommended native Claude Code
// rules are installed (rulebook.CoveredTwins); the caller reads Claude
// Code's settings once per command for it (this package cannot import
// claudesettings), and the hook never does. nil covers nothing, which keeps
// every file-tool hook a pack rule asks for.
func NeededExtra(userPath, projectPath string, covered []string) Extra {
	p, _, err := policy.Load(userPath, projectPath)
	if err != nil {
		return Extra{Pre: []string{MatcherFiles, MatcherWeb, MatcherMCP}}
	}
	cfg := p.RulesConfig()
	m := p.ExtraMatchers(cfg)
	m.FileTools, _ = p.FilesNeed(cfg, covered)
	m.Files = false
	return ExtraFor(m)
}

// InstallWith is Install plus the extra registrations. Our entry in an
// earlier install's file-tools group that extra no longer names (a whole
// group narrowed to the write tools, or a group no longer needed) is
// removed, so a file operation no rule needs stops paying a hook spawn;
// Install leaves it.
func InstallWith(path, binary string, extra Extra) (Change, error) {
	return install(path, binary, false, true, true, extra)
}

// IsFileMatcher reports whether a PreToolUse matcher names only file tools
// (policy.FileTools), joined by "|": the file-tools group, whole or narrowed.
func IsFileMatcher(m string) bool {
	if m == "" {
		return false
	}
	for _, t := range strings.Split(m, "|") {
		if !isFileTool(t) {
			return false
		}
	}
	return true
}

func isFileTool(t string) bool {
	for _, f := range policy.FileTools {
		if t == f {
			return true
		}
	}
	return false
}

// fileMatcher is extra's file-tools matcher, or "".
func (e Extra) fileMatcher() string {
	for _, m := range e.Pre {
		if IsFileMatcher(m) {
			return m
		}
	}
	return ""
}

// dropFiles removes our hook entries from PreToolUse file-tools groups
// (IsFileMatcher) whose matcher is not keep, so a changed need moves our
// entry rather than leaving two; someone else's entries stay, and a group
// left with no hooks is dropped. It returns the Uninstall-style lines.
func dropFiles(obj *Object, keep string) ([]string, error) {
	groups, hooks, err := eventGroups(obj, EventPre, false)
	if err != nil || hooks == nil {
		return nil, err
	}
	var removed []string
	kept := make([]any, 0, len(groups))
	for _, g := range groups {
		go_, ok := g.(*Object)
		m := ""
		if ok {
			m = groupMatcher(go_)
		}
		if !ok || !IsFileMatcher(m) || m == keep {
			kept = append(kept, g)
			continue
		}
		hs, _ := go_.Array("hooks")
		var keptHooks []any
		for _, h := range hs {
			if _, ours := isOurHook(h); ours {
				removed = append(removed, "hooks."+EventPre+": "+hookText(h)+" (matcher "+m+")")
				continue
			}
			keptHooks = append(keptHooks, h)
		}
		if len(keptHooks) == 0 && len(hs) > 0 {
			continue
		}
		if len(keptHooks) != len(hs) {
			go_.Set("hooks", keptHooks)
		}
		kept = append(kept, go_)
	}
	if len(removed) > 0 {
		hooks.Set(EventPre, kept)
	}
	return removed, nil
}

// ourFileTools is the set of file tools our hook entries in file-tools
// groups (or a wildcard group) watch.
func ourFileTools(groups []any) map[string]bool {
	out := map[string]bool{}
	for _, g := range groups {
		go_, ok := g.(*Object)
		if !ok {
			continue
		}
		m := groupMatcher(go_)
		if !IsFileMatcher(m) && !isWildcard(m) {
			continue
		}
		hs, _ := go_.Array("hooks")
		for _, h := range hs {
			if _, ours := isOurHook(h); !ours {
				continue
			}
			if isWildcard(m) {
				for _, t := range policy.FileTools {
					out[t] = true
				}
			} else {
				for _, t := range strings.Split(m, "|") {
					out[t] = true
				}
			}
			break
		}
	}
	return out
}

// HookedFileTools lists, in policy.FileTools order, the file tools our hook
// watches in the settings file at path.
func HookedFileTools(path string) ([]string, error) {
	obj, _, err := Load(path)
	if err != nil {
		return nil, err
	}
	groups, _, err := eventGroups(obj, EventPre, false)
	if err != nil {
		return nil, err
	}
	set := ourFileTools(groups)
	var out []string
	for _, t := range policy.FileTools {
		if set[t] {
			out = append(out, t)
		}
	}
	return out, nil
}

// PlanWith is Plan plus the extra registrations.
func PlanWith(path, binary string, exclusionOnly bool, extra Extra) ([]string, error) {
	ch, err := install(path, binary, exclusionOnly, false, true, extra)
	out := ch.Added
	for _, r := range ch.Removed {
		out = append(out, "(remove) "+r)
	}
	for _, u := range ch.Updated {
		out = append(out, "(update) "+u)
	}
	return out, err
}

// ExtraStatus reports which of extra's registrations hold our hook in the
// settings file at path, and which are missing.
func ExtraStatus(path string, extra Extra) (present, missing []string, err error) {
	obj, _, err := Load(path)
	if err != nil {
		return nil, nil, err
	}
	for _, r := range extra.regs() {
		groups, _, err := eventGroups(obj, r.event, false)
		if err != nil {
			return nil, nil, err
		}
		_, ok := findHookFor(groups, r.matcher)
		if !ok && r.event == EventPre {
			_, w1 := findHookFor(groups, MatcherAnyTool)
			_, w2 := findHookFor(groups, MatcherAll)
			ok = w1 || w2 // a wildcard group of ours covers every tool
		}
		if !ok && r.event == EventPre && IsFileMatcher(r.matcher) {
			// file-tools groups of ours that together watch every needed
			// tool (a wider group than needed still covers; install narrows it)
			have := ourFileTools(groups)
			ok = true
			for _, t := range strings.Split(r.matcher, "|") {
				ok = ok && have[t]
			}
		}
		if ok {
			present = append(present, r.label())
		} else {
			missing = append(missing, r.label())
		}
	}
	return present, missing, nil
}

// InstalledExtra lists every registration of our hook beyond the base six
// (PreToolUse groups for other tools, PostToolUse groups), in file order.
func InstalledExtra(path string) ([]string, error) {
	obj, _, err := Load(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, event := range []string{EventPre, EventPost} {
		groups, _, err := eventGroups(obj, event, false)
		if err != nil {
			return nil, err
		}
		for _, g := range groups {
			go_, ok := g.(*Object)
			if !ok {
				continue
			}
			m := groupMatcher(go_)
			if event == EventPre && (m == MatcherBash || m == MatcherSkill) {
				continue
			}
			hs, _ := go_.Array("hooks")
			for _, h := range hs {
				if _, ok := isOurHook(h); ok {
					out = append(out, registration{event, m}.label())
					break
				}
			}
		}
	}
	return out, nil
}

// UnhookedTools returns, in order, the tools in tools that no PreToolUse
// group of ours in the settings file at path watches: a group names a
// tool among its |-separated matcher, or is a wildcard group. A missing
// file watches nothing. It only reads.
func UnhookedTools(path string, tools []string) ([]string, error) {
	obj, _, err := Load(path)
	if err != nil {
		return nil, err
	}
	groups, _, err := eventGroups(obj, EventPre, false)
	if err != nil {
		return nil, err
	}
	watched := map[string]bool{}
	all := false
	for _, g := range groups {
		go_, ok := g.(*Object)
		if !ok {
			continue
		}
		hs, _ := go_.Array("hooks")
		ours := false
		for _, h := range hs {
			if _, ok := isOurHook(h); ok {
				ours = true
				break
			}
		}
		if !ours {
			continue
		}
		m := groupMatcher(go_)
		if isWildcard(m) {
			all = true
			continue
		}
		for _, t := range strings.Split(m, "|") {
			watched[t] = true
		}
	}
	var out []string
	for _, t := range tools {
		if !all && !watched[t] {
			out = append(out, t)
		}
	}
	return out, nil
}
