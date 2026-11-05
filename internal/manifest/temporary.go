package manifest

import (
	"errors"
	"fmt"
	"hash/fnv"
	"strconv"
	"time"
)

// Temporary allows (Plan 08). A temporary is an entry under the user
// policy file's temporary: list that loosens watchdeck's own enforcement
// for a while, and nothing else:
//
//   - kind rule pauses one built-in pack rule or one policy-file rule
//     ("<pack>/<id>", pack "user" for a policy-file rule) until Until, for
//     every session or for one (Session). A paused rule has no opinion,
//     exactly like a rule switched off; it never allows.
//   - kind grant widens one skill's sandbox grant until Until. It is timed
//     only (`watchdeck run` carries no session id) and may never carry
//     auto_allow, so it cannot turn the hook's ask into an allow.
//
// Expired entries are ignored on every read and dropped by the next save;
// nothing reaps them. Only the user file may hold temporaries: a project
// file that has the key is refused.
type Temporary struct {
	ID      string    // t-<8 hex>, TemporaryID
	Kind    string    // TempRule | TempGrant
	Rule    string    // kind rule: "<pack>/<rule id>"
	Skill   string    // kind grant: the skill name
	Grant   *Override // kind grant: what is widened (never AutoAllow)
	Session string    // kind rule: "" for every session, else one session id
	Until   time.Time // exclusive: in force while now < Until
	Added   time.Time
}

// Temporary kinds.
const (
	TempRule  = "rule"
	TempGrant = "grant"
)

// SessionBackstop is the Until of a session-bound pause: a resumed session
// keeps its id, so the pause ends after this long at the latest.
const SessionBackstop = 8 * time.Hour

// Active reports whether t is in force at now (now before Until).
func (t Temporary) Active(now time.Time) bool { return now.Before(t.Until) }

// Clone deep-copies a Temporary.
func (t Temporary) Clone() Temporary {
	if t.Grant != nil {
		g := t.Grant.clone()
		t.Grant = &g
	}
	return t
}

// TemporaryID is "t-" and the fnv32a hex of kind, rule, skill, session
// and the added time (RFC 3339, UTC), NUL-separated: the same pause written
// twice has one id; Until is not part of it.
func TemporaryID(t Temporary) string { return TemporaryIDN(t, 0) }

// TemporaryIDN is TemporaryID with n > 0 folded in after the added time,
// for an entry that would otherwise share its id with a different one
// (two timed grants for one skill within one second); n 0 is TemporaryID.
func TemporaryIDN(t Temporary, n int) string {
	h := fnv.New32a()
	for _, s := range []string{t.Kind, t.Rule, t.Skill, t.Session, t.Added.UTC().Format(time.RFC3339)} {
		h.Write([]byte(s))
		h.Write([]byte{0})
	}
	if n > 0 {
		h.Write([]byte(strconv.Itoa(n)))
		h.Write([]byte{0})
	}
	return fmt.Sprintf("t-%08x", h.Sum32())
}

// ValidTemporaryID reports whether s is t- and 8 lower-case hex digits.
func ValidTemporaryID(s string) bool {
	if len(s) != 10 || s[:2] != "t-" {
		return false
	}
	for i := 2; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// ValidSessionID reports whether s can be a temporary's session: letters,
// digits, '.', '_', '-' (not first), at most 128 characters.
func ValidSessionID(s string) bool { return charsOK(s, 128, "") }

// rawTemporary is one entry under temporary:. Times are strings so a hand
// edit gets the field's own error, not go-yaml's.
type rawTemporary struct {
	ID      string       `yaml:"id"`
	Kind    string       `yaml:"kind"`
	Rule    string       `yaml:"rule"`
	Skill   string       `yaml:"skill"`
	Grant   *rawOverride `yaml:"grant"`
	Session string       `yaml:"session"`
	Until   string       `yaml:"until"`
	Added   string       `yaml:"added"`
}

// convertTemporaries validates the temporary: list. Errors name the field
// path (temporary[i], or temporary.<id> once the id is valid) and the
// rule, never a value.
func convertTemporaries(raw []rawTemporary) ([]Temporary, error) {
	var out []Temporary
	seen := map[string]bool{}
	for i, r := range raw {
		if !ValidTemporaryID(r.ID) {
			return nil, fmt.Errorf("temporary[%d].id: required, t- and 8 hex digits", i)
		}
		field := "temporary." + r.ID
		if seen[r.ID] {
			return nil, errors.New(field + ".id: duplicate id")
		}
		seen[r.ID] = true
		t := Temporary{ID: r.ID, Kind: r.Kind, Session: r.Session}
		switch r.Kind {
		case TempRule:
			if !ValidRuleKey(r.Rule) {
				return nil, errors.New(field + ".rule: required for kind rule, " + RuleKeyRule)
			}
			if r.Skill != "" {
				return nil, errors.New(field + ".skill: not allowed for kind rule")
			}
			if r.Grant != nil {
				return nil, errors.New(field + ".grant: not allowed for kind rule")
			}
			t.Rule = r.Rule
		case TempGrant:
			if r.Skill == "*" || !ValidSkillName(r.Skill) {
				return nil, errors.New(field + ".skill: required for kind grant, a skill name (" + SkillNameRule + "; not *)")
			}
			if r.Rule != "" {
				return nil, errors.New(field + ".rule: not allowed for kind grant")
			}
			if r.Session != "" {
				return nil, errors.New(field + ".session: not allowed for kind grant (a timed grant has no session)")
			}
			if r.Grant == nil {
				return nil, errors.New(field + ".grant: required for kind grant (network, write, read, env or caches)")
			}
			if r.Grant.AutoAllow != nil {
				return nil, errors.New(field + ".grant.auto_allow: not allowed in a temporary (a timed grant never runs a script without asking)")
			}
			g, err := convertOverride(field+".grant", r.Grant)
			if err != nil {
				return nil, err
			}
			if emptyOverride(g) {
				return nil, errors.New(field + ".grant: required for kind grant (network, write, read, env or caches)")
			}
			t.Skill, t.Grant = r.Skill, &g
		default:
			return nil, errors.New(field + ".kind: must be rule or grant")
		}
		if r.Session != "" && !ValidSessionID(r.Session) {
			return nil, errors.New(field + ".session: letters, digits, '.', '_', '-' (not first), at most 128 characters")
		}
		var err error
		if t.Until, err = parseTemporaryTime(r.Until); err != nil {
			return nil, errors.New(field + ".until: required, an RFC 3339 time")
		}
		if t.Added, err = parseTemporaryTime(r.Added); err != nil {
			return nil, errors.New(field + ".added: required, an RFC 3339 time")
		}
		if !t.Until.After(t.Added) {
			return nil, errors.New(field + ".until: must be after added")
		}
		// A session pause carries the backstop and a timed grant lasts at
		// most as long: neither may be written past it by hand.
		if (t.Session != "" || t.Kind == TempGrant) && t.Until.After(t.Added.Add(SessionBackstop)) {
			return nil, errors.New(field + ".until: at most 8 hours after added for a session pause or a grant")
		}
		out = append(out, t)
	}
	return out, nil
}

// parseTemporaryTime reads an RFC 3339 time, kept in UTC to the second
// (the form Render writes, so a file round-trips byte for byte).
func parseTemporaryTime(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, err
	}
	return t.UTC().Truncate(time.Second), nil
}

// errProjectTemporary refuses a project file with a temporary: list.
func errProjectTemporary() error {
	return errors.New("temporary: not allowed in a project file (only your own overrides file can pause a rule or widen a grant for a while)")
}

// BaseSkillOverrides projects a file onto the skill view without its
// temporaries: Defaults, plus one Skills entry per skill subject ("*"
// included). Writers use it, so a timed grant is never saved into the
// permanent one.
func (f PolicyFile) BaseSkillOverrides() Overrides {
	out := Overrides{Defaults: f.Defaults.clone()}
	for _, s := range f.Subjects {
		if s.Kind != KindSkill {
			continue
		}
		if out.Skills == nil {
			out.Skills = map[string]Override{}
		}
		var o Override
		if s.Grant != nil {
			o = s.Grant.clone()
		}
		out.Skills[s.Name] = o
	}
	return out
}

// SkillOverridesAt is the skill view at now: BaseSkillOverrides with every
// grant temporary in force at now folded into its skill's block by
// widening (network the larger, write, read and env appended, caches
// or'ed). While a grant temporary for a skill is in force, that skill's
// block also has auto_allow false: the skill's own user block is the last
// step of Grant's chain, so it always asks, even when the permanent grant,
// the defaults or "*" auto-allow it (a timed grant never runs a script
// without asking). f is not changed; writers read BaseSkillOverrides, so
// the permanent auto_allow on disk is untouched.
func SkillOverridesAt(now time.Time, f *PolicyFile) Overrides {
	out := f.BaseSkillOverrides()
	for _, t := range f.Temporary {
		if t.Kind != TempGrant || t.Grant == nil || !t.Active(now) {
			continue
		}
		if out.Skills == nil {
			out.Skills = map[string]Override{}
		}
		o := widenOverride(out.Skills[t.Skill], *t.Grant)
		no := false
		o.AutoAllow = &no
		out.Skills[t.Skill] = o
	}
	return out
}

// SkillOverrides is SkillOverridesAt(time.Now(), f): the view the hook's
// rewrite, run, audit and the map read through LoadOverrides.
func (f PolicyFile) SkillOverrides() Overrides { return SkillOverridesAt(time.Now(), &f) }

// widenOverride returns a widened by b: the larger network, b's write,
// read and env entries appended (deduped), caches or'ed. AutoAllow stays
// a's.
func widenOverride(a, b Override) Override {
	out := a.clone()
	if b.Network != nil {
		n := *b.Network
		if out.Network != nil {
			n = maxNetwork(*out.Network, n)
		}
		out.Network = &n
	}
	for _, p := range b.Write {
		out.Write = appendUnique(out.Write, p)
	}
	for _, p := range b.Read {
		out.Read = appendUnique(out.Read, p)
	}
	for _, e := range b.Env {
		out.Env = appendUnique(out.Env, e)
	}
	out.Caches = out.Caches || b.Caches
	return out
}
