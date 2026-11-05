package rules

// HasPreRules is HasRules for the rules a PreToolUse call can fire: every
// field but the fetched text (FieldText), which exists only after the tool
// ran (PostToolUse).
func HasPreRules(cfg Config, tool string) bool { return hasFieldRules(cfg, tool, false) }

// HasPostRules reports whether an enabled rule for tool reads the fetched
// text (FieldText), so a PostToolUse registration is worth having.
func HasPostRules(cfg Config, tool string) bool { return hasFieldRules(cfg, tool, true) }

func hasFieldRules(cfg Config, tool string, text bool) bool {
	l := load()
	if l.err != nil {
		return false
	}
	for _, p := range l.packs {
		pc, hasPC := cfg.Packs[p.Name]
		packOn := p.EnabledByDefault()
		if hasPC && pc.Enabled != nil {
			packOn = *pc.Enabled
		}
		for _, r := range p.Rules {
			on := packOn
			if rc, ok := cfg.Rules[p.Name+"/"+r.ID]; ok && rc.Enabled != nil {
				on = *rc.Enabled
			}
			if on && r.c.appliesTo(tool) && (r.c.field == FieldText) == text {
				return true
			}
		}
	}
	return false
}

// ToolRule is one enabled pack rule for a tool, as Config resolves it.
type ToolRule struct {
	ID      string // "<pack>/<rule id>"
	Field   string // the input field it reads
	Action  Action // effective: rule override, else pack override, else Default
	Default Action // the rule's own action
}

// RulesFor lists the enabled rules for tool that a PreToolUse call can fire
// (every field but FieldText), in pack and rule order, with the action Eval
// would report.
func RulesFor(cfg Config, tool string) []ToolRule {
	l := load()
	if l.err != nil {
		return nil
	}
	var out []ToolRule
	for _, p := range l.packs {
		pc, hasPC := cfg.Packs[p.Name]
		packOn := p.EnabledByDefault()
		if hasPC && pc.Enabled != nil {
			packOn = *pc.Enabled
		}
		for _, r := range p.Rules {
			if !r.c.appliesTo(tool) || r.c.field == FieldText {
				continue
			}
			rc, hasRC := cfg.Rules[p.Name+"/"+r.ID]
			on := packOn
			if hasRC && rc.Enabled != nil {
				on = *rc.Enabled
			}
			if !on {
				continue
			}
			act := r.Action
			if hasPC && pc.Action.valid() {
				act = pc.Action
			}
			if hasRC && rc.Action.valid() {
				act = rc.Action
			}
			out = append(out, ToolRule{ID: p.Name + "/" + r.ID, Field: r.c.field, Action: act, Default: r.Action})
		}
	}
	return out
}
