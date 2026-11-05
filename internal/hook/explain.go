package hook

import (
	"strings"

	"github.com/Panda-Taps-LLC/watchdeck/internal/activity"
	"github.com/Panda-Taps-LLC/watchdeck/internal/claudesettings"
	"github.com/Panda-Taps-LLC/watchdeck/internal/lifecycle"
)

// Explanation is what `watchdeck rules explain` reports about one call:
// the hook's verdict and what decided it (Plan 07 Task 1, 2026-10-20).
// It is the decision record's content without the record.
type Explanation struct {
	Verdict     string             `json:"verdict"`                // allow | ask | deny | none (the hook has no opinion)
	Reason      string             `json:"reason,omitempty"`       // the hook's reason, verbatim
	Rewritten   string             `json:"rewritten,omitempty"`    // the updatedInput command; "" when none
	Rules       []activity.RuleHit `json:"rules"`                  // pack, user and Claude Code settings rules that matched
	Subject     *activity.Subject  `json:"subject"`                // the skill, command subject or gate that decided
	Enforcement string             `json:"enforcement,omitempty"`  // sandbox | gate
	Skills      []string           `json:"skills"`                 // sorted, as a record carries them
	Confidence  string             `json:"confidence,omitempty"`   // high | low | ""
	Shadow      bool               `json:"shadow"`                 // a gate verdict was observed in shadow mode, not printed
	Would       string             `json:"would,omitempty"`        // deny | ask: the shadowed verdict
	WouldReason string             `json:"would_reason,omitempty"` // its value-free reasons
	// NativeRule is the person's Claude Code Bash deny or ask rule that
	// matches a Bash command the hook did not check it against (review of
	// Task 1, check 4). The hook matches those rules only before a
	// rewrite (sandboxStage); for every other Bash command Claude Code
	// applies them itself, so the Output above is unchanged and the rule
	// is named here. nil when none matches, when the settings could not be
	// read, when the command could not be parsed, or when the hit is
	// already in Rules.
	NativeRule *NativeRule `json:"native_rule,omitempty"`
}

// NativeRule names one of the person's Claude Code Bash rules.
type NativeRule struct {
	Value string `json:"value"` // the rule as written, e.g. "Bash(curl *)"
	Kind  string `json:"kind"`  // deny | ask
	Scope string `json:"scope"` // managed | user | project | local
}

// Explain is the decision without the record: the same pipeline as a hook
// call (decide, behind the recovery handle uses), with no watchdog, no
// lifecycle touch and no activity line. It clears env.ActivityPath and
// env.Lifecycle itself, so a caller cannot make it write; the skill index
// cache and the policy cache are refreshed exactly as a hook call would
// (D4). The Output is what Decide returns for the same Input and Env
// (TestExplainMatchesDecide); the Explanation names the verdict and what
// decided it. in.Harness is set as Run sets it.
func Explain(in Input, env Env) (*Output, Explanation) {
	env.ActivityPath = ""
	env.Lifecycle = lifecycle.Store{}
	env.loading = nil
	in.Harness = activity.DefaultHarness(env.Harness)
	out, m := decideSafely(in, env)
	ex := Explanation{
		Verdict:     "none",
		Rules:       m.Rules,
		Subject:     m.Subject,
		Enforcement: m.Enforcement,
		Skills:      sortedSkills(m.Skills),
		Confidence:  m.Confidence,
		Shadow:      m.Shadow,
		Would:       m.Would,
		WouldReason: m.WouldReason,
	}
	if out != nil {
		s := out.HookSpecificOutput
		ex.Verdict = s.PermissionDecision
		ex.Reason = s.PermissionDecisionReason
		if s.UpdatedInput != nil {
			ex.Rewritten, _ = s.UpdatedInput["command"].(string)
		}
	}
	ex.NativeRule = nativeRuleFor(in, env, m)
	return out, ex
}

// nativeRuleFor is the Claude Code Bash rule a Bash command matches when
// the pipeline did not check it (no claude-settings hit in m.Rules): the
// same loader and matcher as nativeCheck, read-only, through the rules
// cache a hook call would also write. Only a plain deny or ask is named;
// an unreadable settings file or an unparseable command is left to the
// hook's own answer.
func nativeRuleFor(in Input, env Env, m meta) *NativeRule {
	if in.ToolName != "Bash" {
		return nil
	}
	command, _ := in.ToolInput["command"].(string)
	if strings.TrimSpace(command) == "" {
		return nil
	}
	for _, h := range m.Rules {
		if h.Pack == activity.PackClaudeSettings {
			return nil
		}
	}
	cwd := in.Cwd
	if cwd == "" {
		cwd = env.Home
	}
	bm := claudesettings.MatchBash(loadNativeRules(env, cwd), command)
	if bm.Rule == nil || bm.Rule.Unreadable || bm.Uncertain {
		return nil
	}
	return &NativeRule{Value: bm.Rule.Value, Kind: bm.Rule.Kind, Scope: string(bm.Rule.Scope)}
}
