package mapmodel

import (
	"sort"

	"github.com/Panda-Taps-LLC/watchdeck/internal/activity"
)

// Policy subjects and rule hits on the map (M6.4). A call's rule hits come
// from its decision record and its rule_log record; its subject from the
// decision (or the joined run). Topology tool and MCP nodes and timeline
// events carry the hit count (the badge) and the subjects' names; the cards
// list them.

// ruleHits returns the call's rule hits, decision first, without repeats.
func (c *call) ruleHits() []activity.RuleHit {
	var out []activity.RuleHit
	seen := map[string]bool{}
	for _, r := range []*activity.Record{c.dec, c.ruleLog} {
		if r == nil {
			continue
		}
		for _, h := range r.Rules {
			k := h.Pack + "/" + h.ID
			if !seen[k] {
				seen[k] = true
				out = append(out, h)
			}
		}
	}
	return out
}

// subjectLabel is "kind name (enforcement)" for the call's subject, "" when
// it has none (a skill call shows its skills elsewhere).
func (c *call) subjectLabel() string {
	for _, r := range []*activity.Record{c.dec, c.run, c.ruleLog} {
		if r == nil || r.Subject == nil || r.Subject.Kind == "skill" {
			continue
		}
		l := r.Subject.Kind + " " + r.Subject.Name
		if r.Enforcement != "" {
			l += " (" + r.Enforcement + ")"
		}
		return l
	}
	return ""
}

// ruleLabel is "pack/id: action".
func ruleLabel(h activity.RuleHit) string { return h.Pack + "/" + h.ID + ": " + h.Action }

// sortedKeys returns m's keys sorted.
func sortedNames(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
