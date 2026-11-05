package rulebook

import (
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Panda-Taps-LLC/watchdeck/internal/claudesettings"
	"github.com/Panda-Taps-LLC/watchdeck/internal/manifest"
	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
	"github.com/Panda-Taps-LLC/watchdeck/internal/policy"
)

// What is the kind of thing a rule names.
type What string

const (
	WhatPath      What = "path"       // a file path or glob: Read(…) and/or Edit(…)
	WhatHost      What = "host"       // a web host: WebFetch(domain:…)
	WhatMCP       What = "mcp"        // an MCP tool: mcp__server__tool
	WhatCommand   What = "command"    // a command prefix: Bash(<prefix> *)
	WhatRegex     What = "regex"      // a hook rule matching a regex
	WhatText      What = "text"       // a hook rule matching exact text
	WhatSkill     What = "skill"      // a skill grant: not added here (watchdeck allow / rules grant)
	WhatMCPLaunch What = "mcp-launch" // an MCP server started under the sandbox
	WhatPackRule  What = "pack-rule"  // a built-in pack rule's action: "<pack>/<id>" (deny, ask or log)
)

// Mechanisms a Step uses.
const (
	MechNative  = "native"  // a string in a Claude Code settings list
	MechHook    = "hook"    // a rule under rules: in the user policy file
	MechSubject = "subject" // a subject in the user policy file
)

// Path tools for What=path.
const (
	PathRead = "Read"
	PathEdit = "Edit"
	PathBoth = "Both"
)

// AddRequest is one rule a person (or the inbox) asks to add.
type AddRequest struct {
	Action   string               `json:"action"` // deny | ask (ignored for mcp-launch; pack-rule also log)
	What     What                 `json:"what"`
	Value    string               `json:"value"`     // path, host, mcp__s__t, command prefix, regex, exact text, MCP server, <pack>/<id>
	Tool     string               `json:"tool"`      // path: Read | Edit | Both (default); regex/text: default Bash
	Scope    claudesettings.Scope `json:"scope"`     // user (default) | project; local and managed: ErrScope
	Twin     bool                 `json:"twin"`      // also add the hook twin a native Bash rule suggests
	IntentID string               `json:"intent_id"` // ledger claim id; "" means each native step's row id
	// Everywhere asks for one intent covering every route a tool can take
	// to the value (path, host or command; see IntentFor and
	// proposeEverywhere). It implies Twin for a command.
	Everywhere bool `json:"everywhere"`
}

// Step is one write a Plan makes. File is the settings file (native) or
// the user policy file (hook, subject); Key the settings list key, "rules"
// or "subjects"; Value the settings string, the hook rule's regex or text,
// or the subject name. IntentID is the ledger claim of a native step (and,
// in an everywhere plan, the intent of every step); Rule is the rule a
// hook step puts; Subject is the tool subject an everywhere step puts.
type Step struct {
	Mechanism string                  `json:"mechanism"`
	File      string                  `json:"file"`
	Key       string                  `json:"key"`
	Value     string                  `json:"value"`
	RowID     string                  `json:"row_id"`
	Sentence  string                  `json:"sentence"`
	IntentID  string                  `json:"intent_id,omitempty"`
	Rule      *manifest.PolicyRule    `json:"rule,omitempty"`
	Subject   *manifest.PolicySubject `json:"subject,omitempty"`
}

// Plan is what Apply will write. Suggested is the hook twin of a native
// Bash rule when the request did not ask for it.
type Plan struct {
	Steps     []Step      `json:"steps"`
	Suggested *AddRequest `json:"suggested,omitempty"`
}

// ErrScope is returned for a scope rules are never written to.
var ErrScope = errors.New("rulebook: rules are written to user or project settings only")

// ErrValue is returned for an empty value or one holding a control character.
var ErrValue = errors.New("rulebook: value holds a control character or is empty")

// checkValue refuses an empty (or blank) value and any control character
// (C0, DEL, and the C1 range).
func checkValue(v string) error {
	if strings.TrimSpace(v) == "" {
		return fmt.Errorf("%w: the value is empty", ErrValue)
	}
	for _, r := range v {
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
			return fmt.Errorf("%w: the value holds a control character", ErrValue)
		}
	}
	return nil
}

// checkNativeValue refuses a native rule value holding ( or ): a
// parenthesis would close the settings string early (Bash(foo) *) or
// Read(a)b) protects nothing).
func checkNativeValue(v string) error {
	if strings.ContainsAny(v, "()") {
		return fmt.Errorf("%w: %q: a native rule value cannot hold ( or )", ErrValue, v)
	}
	return nil
}

// checkNativeString runs checkNativeValue on a whole settings string: the
// part inside Tool(…) when it has brackets (which must close it), else
// the whole string (an MCP tool name).
func checkNativeString(s string) error {
	i := strings.IndexByte(s, '(')
	if i < 0 {
		return checkNativeValue(s)
	}
	if !strings.HasSuffix(s, ")") || len(s) < i+2 {
		return fmt.Errorf("%w: %q: a native rule is Tool(value)", ErrValue, s)
	}
	return checkNativeValue(s[i+1 : len(s)-1])
}

// nativeFile resolves the settings file a native rule is written to.
func nativeFile(in Input, scope claudesettings.Scope) (string, claudesettings.Scope, error) {
	switch scope {
	case "", claudesettings.ScopeUser:
		claudeDir := in.Paths.ClaudeDir
		if claudeDir == "" {
			claudeDir = filepath.Join(in.Paths.Home, ".claude")
		}
		return filepath.Join(claudeDir, "settings.json"), claudesettings.ScopeUser, nil
	case claudesettings.ScopeProject:
		if in.ProjectRoot == "" {
			return "", "", fmt.Errorf("%w: project scope needs a project root", ErrScope)
		}
		return paths.ProjectSettings(in.ProjectRoot), claudesettings.ScopeProject, nil
	}
	return "", "", ErrScope
}

// anchorPath spells a path the way Claude Code reads it in a settings file
// of the given scope. A /path rule is relative to the settings file's own
// root (~/.claude for user settings, the project root for project
// settings), so an absolute path is always //abs. At user scope a relative
// path becomes ./rel (the working directory); at project scope it becomes
// /rel (the project root). The value is cleaned first (path.Clean, the ~/
// remainder on its own); a ".." left after cleaning, "." alone, and a ~
// not followed by / (~user/x, bare ~) are ErrValue. A value ending in /
// names a directory and gets /** (everything under it): secrets/ is
// ./secrets/**, ~/x/ is ~/x/**, /abs/ is //abs/**.
func anchorPath(v string, scope claudesettings.Scope) (string, error) {
	p, err := anchorClean(v, scope)
	if err != nil || !strings.HasSuffix(v, "/") {
		return p, err
	}
	if !strings.HasSuffix(p, "/") {
		p += "/"
	}
	return p + "**", nil
}

func anchorClean(v string, scope claudesettings.Scope) (string, error) {
	climbs := func(c string) bool {
		return c == "." || c == ".." || strings.HasPrefix(c, "../")
	}
	if strings.HasPrefix(v, "~") {
		rest, ok := strings.CutPrefix(v, "~/")
		if !ok {
			return "", fmt.Errorf("%w: %q: a home path starts with ~/", ErrValue, v)
		}
		if rest == "" {
			return "~/", nil
		}
		c := path.Clean(rest)
		if climbs(c) || strings.HasPrefix(c, "/") {
			return "", fmt.Errorf("%w: %q leaves the home directory", ErrValue, v)
		}
		return "~/" + c, nil
	}
	c := path.Clean(v)
	if strings.HasPrefix(c, "/") {
		return "/" + c, nil // path.Clean leaves no ".." under a leading /
	}
	if climbs(c) {
		return "", fmt.Errorf("%w: %q climbs out of its directory; use an absolute path", ErrValue, v)
	}
	if scope == claudesettings.ScopeProject {
		return "/" + c, nil
	}
	return "./" + c, nil
}

// actionKey is the native list key for an add action.
func actionKey(action string) (string, error) {
	switch action {
	case "deny":
		return claudesettings.KeyDeny, nil
	case "ask":
		return claudesettings.KeyAsk, nil
	}
	return "", fmt.Errorf("rulebook: action %q: rules are added as deny or ask", action)
}

// Propose turns an AddRequest into the writes that add it: a native
// settings string where Claude Code has one, else a hook rule or subject in
// the user policy file. It reads and writes nothing.
func Propose(in Input, req AddRequest) (Plan, error) {
	var plan Plan
	if err := checkValue(req.Value); err != nil {
		return plan, err
	}
	if req.Everywhere {
		return proposeEverywhere(in, req)
	}
	switch req.What {
	case WhatPath, WhatHost, WhatMCP, WhatCommand:
		return proposeNative(in, req)
	case WhatRegex, WhatText:
		if req.Scope != "" && req.Scope != claudesettings.ScopeUser {
			return plan, fmt.Errorf("%w: %s rules are written to the user policy file only", ErrScope, req.What)
		}
		s, err := hookStep(in, req)
		if err != nil {
			return plan, err
		}
		plan.Steps = []Step{s}
		return plan, nil
	case WhatMCPLaunch:
		if req.Scope != "" && req.Scope != claudesettings.ScopeUser {
			return plan, fmt.Errorf("%w: MCP launches are written to the user policy file only", ErrScope)
		}
		if !manifest.ValidMCPServerPattern(req.Value) {
			return plan, fmt.Errorf("rulebook: invalid MCP server name (%s)", manifest.MCPServerRule)
		}
		plan.Steps = []Step{{
			Mechanism: MechSubject,
			File:      in.Paths.OverridesFile(),
			Key:       "subjects",
			Value:     req.Value,
			RowID:     RowID(KindSubject, claudesettings.ScopeUser, policy.KindMCP, req.Value),
			Sentence:  mcpLaunchSentence(req.Value),
		}}
		return plan, nil
	case WhatPackRule:
		s, err := packRuleStep(in, req)
		if err != nil {
			return plan, err
		}
		plan.Steps = []Step{s}
		return plan, nil
	case WhatSkill:
		return plan, errors.New("rulebook: a skill's sandbox is granted with " + paths.BinaryName + " rules grant, not added as a rule")
	}
	return plan, fmt.Errorf("rulebook: unknown rule kind %q", req.What)
}

func proposeNative(in Input, req AddRequest) (Plan, error) {
	var plan Plan
	if err := checkNativeValue(req.Value); err != nil {
		return plan, err
	}
	key, err := actionKey(req.Action)
	if err != nil {
		return plan, err
	}
	file, scope, err := nativeFile(in, req.Scope)
	if err != nil {
		return plan, err
	}
	var values []string
	switch req.What {
	case WhatPath:
		p, err := anchorPath(req.Value, scope)
		if err != nil {
			return plan, err
		}
		switch req.Tool {
		case PathRead:
			values = []string{"Read(" + p + ")"}
		case PathEdit:
			values = []string{"Edit(" + p + ")"}
		case "", PathBoth:
			values = []string{"Read(" + p + ")", "Edit(" + p + ")"}
		default:
			return plan, fmt.Errorf("rulebook: path tool %q: Read, Edit or Both", req.Tool)
		}
	case WhatHost:
		// A bare host only: no scheme, path, port or user. NormalizeHost
		// reads a URL as its host, so anything it had to strip differs.
		h := policy.NormalizeHost(req.Value)
		if !h.OK || h.Lexical != strings.ToLower(strings.TrimSpace(req.Value)) {
			return plan, fmt.Errorf("%w: %q: a domain is a bare host such as example.com", ErrValue, req.Value)
		}
		values = []string{"WebFetch(domain:" + h.Lexical + ")"}
	case WhatMCP:
		if !strings.HasPrefix(req.Value, "mcp__") || !manifest.ValidToolPattern(req.Value) {
			return plan, errors.New("rulebook: an MCP rule names a tool as mcp__<server>__<tool> or mcp__<server>")
		}
		values = []string{req.Value}
	case WhatCommand:
		// The rule already ends in " *"; a * inside the prefix would make
		// it match more than the prefix it names.
		req.Value = strings.TrimSpace(req.Value)
		if strings.Contains(req.Value, "*") {
			return plan, fmt.Errorf("%w: %q: a command prefix cannot hold *; the rule already matches what follows it", ErrValue, req.Value)
		}
		values = []string{"Bash(" + req.Value + " *)"}
	}
	kind := kindForKey(key)
	for _, v := range values {
		row := RowID(kind, scope, key, v)
		intent := req.IntentID
		if intent == "" {
			intent = row
		}
		plan.Steps = append(plan.Steps, Step{
			Mechanism: MechNative, File: file, Key: key, Value: v, RowID: row,
			Sentence: Sentence(kind, req.Action, "", v), IntentID: intent,
		})
	}
	if req.What == WhatCommand {
		twin := AddRequest{Action: req.Action, What: WhatText, Value: req.Value, Tool: "Bash", Scope: claudesettings.ScopeUser}
		if req.Twin {
			s, err := hookStep(in, twin)
			if err != nil {
				return Plan{}, err
			}
			plan.Steps = append(plan.Steps, s)
		} else {
			plan.Suggested = &twin
		}
	}
	return plan, nil
}

// hookStep is the step for a regex or text hook rule in the user policy
// file, id "user-<fnv32a hex8 of value>".
func hookStep(in Input, req AddRequest) (Step, error) {
	if req.Action != "deny" && req.Action != "ask" {
		return Step{}, fmt.Errorf("rulebook: action %q: rules are added as deny or ask", req.Action)
	}
	tool := req.Tool
	if tool == "" {
		tool = "Bash"
	}
	if !manifest.ValidToolPattern(tool) {
		return Step{}, fmt.Errorf("rulebook: invalid tool (%s)", manifest.ToolPatternRule)
	}
	r := manifest.PolicyRule{ID: hookRuleID(req.Value), Tool: tool, Action: req.Action}
	if req.What == WhatRegex {
		if _, err := regexp.Compile(req.Value); err != nil {
			return Step{}, errors.New("rulebook: the regex does not compile (RE2 syntax)")
		}
		r.Match.Regex = req.Value
	} else {
		r.Match.Literals = []string{req.Value}
	}
	return Step{
		Mechanism: MechHook,
		File:      in.Paths.OverridesFile(),
		Key:       "rules",
		Value:     req.Value,
		RowID:     RowID(KindHookRegex, claudesettings.ScopeUser, "", r.ID),
		Sentence:  hookSentence(r.Action, r.Tool, r.Match),
		Rule:      &r,
	}, nil
}

// hookRuleID is the id of a user hook rule: "user-" and the fnv32a hex8 of
// its regex or text.
func hookRuleID(value string) string { return "user-" + hash8(value) }

// hookRuleValue is what a hook rule's id is computed from: its regex, else
// its first literal.
func hookRuleValue(m manifest.RuleMatch) string {
	if m.Regex != "" {
		return m.Regex
	}
	if len(m.Literals) > 0 {
		return m.Literals[0]
	}
	return ""
}

// rulesOverridesKey is a pack-rule step's Key: the policy file's
// rule_overrides map.
const rulesOverridesKey = "rule_overrides"

// packRuleStep is the step that sets a built-in pack rule's action in the
// user policy file: Value "<pack>/<id>: <action>".
func packRuleStep(in Input, req AddRequest) (Step, error) {
	if req.Scope != "" && req.Scope != claudesettings.ScopeUser {
		return Step{}, fmt.Errorf("%w: pack rule overrides are written to the user policy file only", ErrScope)
	}
	if !packAction(req.Action) {
		return Step{}, fmt.Errorf("rulebook: action %q: a pack rule is set to deny, ask or log", req.Action)
	}
	p, r, ok := packRule(req.Value)
	if !ok {
		return Step{}, fmt.Errorf("%w: no built-in pack rule %q", ErrValue, req.Value)
	}
	return Step{
		Mechanism: MechHook,
		File:      in.Paths.OverridesFile(),
		Key:       rulesOverridesKey,
		Value:     req.Value + ": " + req.Action,
		RowID:     RowID(KindPack, "", p.Name, r.ID),
		Sentence:  Sentence(KindPack, req.Action, r.Tool, r.Description),
	}, nil
}

// parsePackRuleStep reads a pack-rule step's Value back, checking it from
// scratch: a known pack rule and a pack action.
func parsePackRuleStep(v string) (key, action string, err error) {
	key, action, ok := strings.Cut(v, ": ")
	if !ok || !packAction(action) {
		return "", "", fmt.Errorf("rulebook: pack rule step %q: <pack>/<id>: deny|ask|log", v)
	}
	if _, _, found := packRule(key); !found {
		return "", "", fmt.Errorf("%w: no built-in pack rule %q", ErrValue, key)
	}
	return key, action, nil
}
