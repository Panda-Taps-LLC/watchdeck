package hook

import (
	"github.com/Panda-Taps-LLC/watchdeck/internal/activity"
	"github.com/Panda-Taps-LLC/watchdeck/internal/policy"
)

// Doc is the JSON document `watchdeck rules explain --json` prints and the
// dashboard's try route answers (Plan 08 Task 4, D12): one builder beside
// Explain, so the two print the same document. The field set and order
// are the CLI's from Plan 07; TestExplainJSONUnchangedByMove pins the
// bytes.
type Doc struct {
	Tool        string             `json:"tool"`
	Input       map[string]any     `json:"input"`
	Verdict     string             `json:"verdict"` // allow | ask | deny | none
	Reason      string             `json:"reason"`
	Rewritten   string             `json:"rewritten"`
	Rules       []activity.RuleHit `json:"rules"`
	Subject     *activity.Subject  `json:"subject"`
	Enforcement string             `json:"enforcement"`
	Skills      []string           `json:"skills"`
	Confidence  string             `json:"confidence"`
	Shadow      DocShadow          `json:"shadow"`
	NativeRule  *NativeRule        `json:"native_rule"` // the Claude Code Bash rule that matches when the hook did not check it; null otherwise
	Mode        string             `json:"mode"`
	Cwd         string             `json:"cwd"`
}

// DocShadow is the document's shadow mode block.
type DocShadow struct {
	On          bool   `json:"on"` // a verdict was observed in shadow mode and not printed
	Would       string `json:"would"`
	WouldReason string `json:"would_reason"`
}

// BuildDoc is the document for one Explain call: in is the Input that
// was explained (Mode is its PermissionMode, Cwd its Cwd), e the
// Explanation. Rules and Skills are never null. out is the Output Explain
// returned; the document carries nothing from it beyond what e already
// holds, and it is in the signature so a later field needs no new caller.
func BuildDoc(in Input, out *Output, e Explanation) Doc {
	d := Doc{
		Tool: in.ToolName, Input: in.ToolInput, Verdict: e.Verdict, Reason: e.Reason, Rewritten: e.Rewritten,
		Rules: e.Rules, Subject: e.Subject, Enforcement: e.Enforcement, Skills: e.Skills, Confidence: e.Confidence,
		Shadow:     DocShadow{On: e.Shadow, Would: e.Would, WouldReason: e.WouldReason},
		NativeRule: e.NativeRule, Mode: in.PermissionMode, Cwd: in.Cwd,
	}
	if d.Rules == nil {
		d.Rules = []activity.RuleHit{}
	}
	if d.Skills == nil {
		d.Skills = []string{}
	}
	return d
}

// RuleID spells a rule hit the way rules list names the row:
// pack:<pack>/<id> for a built-in rule, user:<id> for the person's own
// rule, claude-settings:<value> for a Claude Code settings rule.
func RuleID(h activity.RuleHit) string {
	switch h.Pack {
	case policy.UserPack:
		return "user:" + h.ID
	case activity.PackClaudeSettings:
		return activity.PackClaudeSettings + ":" + h.ID
	}
	return "pack:" + h.Pack + "/" + h.ID
}
