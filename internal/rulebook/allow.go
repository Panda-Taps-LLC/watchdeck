package rulebook

import (
	"errors"
	"path/filepath"
	"strings"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/manifest"
	"github.com/Panda-Taps-LLC/watchdeck/internal/policy"
)

// Allowing an inbox item for a while (Plan 08 Task 5, D9, R10, R11): an
// ask item whose every rule is one of watchdeck's own (a pack or policy
// file rule) has all of them paused, for this session or for an hour; a
// skill's request or sandbox refusal that names what the skill asked for
// has that grant widened for an hour. Nothing else can be: a native Claude
// Code rule, auto mode's check, a person's no, a path, domain, MCP or agent
// rule and a leak all say why. Nothing here ever allows a call: a paused
// rule has no opinion and a timed grant still asks before each run.

// The "for" words of an inbox allow.
const (
	AllowSession = "session" // until the item's session ends (8 h at most)
	AllowHour    = "1h"
)

// NativeRuleSentence is the refusal for a decision Claude Code made itself
// (its own settings rule, auto mode's check, the person's no): D9.
const NativeRuleSentence = "Claude Code's own rule; change it in Claude Code"

// ErrAllowRefused is Allow's error for an item that cannot be allowed for
// that while; nothing is written. The error's text is the sentence that
// says why (Is matches this value).
var ErrAllowRefused = errors.New("this cannot be allowed for a while")

type allowRefused struct{ msg string }

func (e allowRefused) Error() string        { return e.msg }
func (e allowRefused) Is(target error) bool { return target == ErrAllowRefused }

// AllowFor is the "for" words Allow takes for it, nil for none: an ask
// whose rule ids are all pausable (PauseRowID) and whose record names no
// path, domain, MCP or agent rule gets session (when it names a session)
// and 1h; a skill request or sandbox refusal with Ungranted gets 1h (a
// sandboxed run carries no session id). The Home page shows its allow
// buttons from this.
func AllowFor(it Item) []string {
	switch it.Kind {
	case ItemAsk:
		if it.bySubject || len(it.RuleIDs) == 0 {
			return nil
		}
		for _, id := range it.RuleIDs {
			if _, ok := PauseRowID(id); !ok {
				return nil
			}
		}
		if it.SessionID != "" && manifest.ValidSessionID(it.SessionID) {
			return []string{AllowSession, AllowHour}
		}
		return []string{AllowHour}
	case ItemSkillRequest, ItemSandboxRefusal:
		if len(it.Ungranted) > 0 {
			return []string{AllowHour}
		}
	}
	return nil
}

// allowRefusal is nil when Allow takes it for forWord, else the
// ErrAllowRefused that says why.
func allowRefusal(it Item, forWord string) error {
	for _, w := range AllowFor(it) {
		if w == forWord {
			return nil
		}
	}
	msg := "there is nothing here to allow for a while"
	switch it.Kind {
	case ItemDenial, ItemRejection:
		msg = NativeRuleSentence
	case ItemAsk:
		native := false
		for _, id := range it.RuleIDs {
			if _, ok := PauseRowID(id); !ok {
				native = true
			}
		}
		switch {
		case native:
			msg = NativeRuleSentence
		case it.bySubject:
			msg = "a watchdeck path, domain, MCP or agent rule decided this; it cannot be paused, remove it instead"
		case len(it.RuleIDs) == 0:
			msg = "no watchdeck rule on this item can be paused"
		case forWord == AllowSession:
			msg = "this item names no session; allow it for an hour instead"
		}
	case ItemSkillRequest, ItemSandboxRefusal:
		switch {
		case len(it.Ungranted) == 0:
			msg = "nothing this skill asked for can be granted from here; open the skill instead"
		case forWord == AllowSession:
			msg = "a skill's grant is widened for an hour, not for one session (a sandboxed run carries no session)"
		}
	case KindLeak:
		msg = "a secret seen in a transcript has nothing to allow"
	}
	return allowRefused{msg}
}

// pausedAsLong reports whether rule key ("<pack>/<id>") already has a
// pause in force that lasts at least as long as forWord asks: for this
// session, one bound to that session or one for every session lasting the
// eight-hour backstop; for an hour, one for every session lasting the hour.
// Allow leaves such a rule alone, so a longer pause the person set is
// neither shortened (Pause replaces an entry with the same sessions) nor
// ended by the allow's Undo. A file that cannot be read has none.
func pausedAsLong(in Input, key, session, forWord string) bool {
	f, _, err := policy.LoadFile(in.Paths.OverridesFile())
	if err != nil {
		return false
	}
	now := time.Now().UTC().Truncate(time.Second)
	want := now.Add(time.Hour)
	if forWord == AllowSession {
		want = now.Add(manifest.SessionBackstop)
	}
	for _, t := range f.Temporary {
		if t.Kind != manifest.TempRule || t.Rule != key || !t.Active(now) {
			continue
		}
		if forWord == AllowSession && t.Session == session {
			return true
		}
		if t.Session == "" && !t.Until.Before(want) {
			return true
		}
	}
	return false
}

// Allow allows it for forWord (AllowSession or AllowHour) and returns the
// ids of the temporaries it wrote, for the inbox resolution: an ask item
// has every rule in RuleIDs paused (Pause, one temporary per rule, the same
// until; "session" is session=<item's session>), a skill item has its
// Ungranted widened for an hour (GrantFor once per skill named, in order;
// when one fails, those already written are ended again). An item AllowFor
// does not offer forWord for, an ask naming a rule that is no longer
// there, or an ask whose every rule is already paused at least that long
// (pausedAsLong; such a rule is skipped) is ErrAllowRefused and nothing is
// written.
func Allow(in Input, it Item, forWord string) ([]string, error) {
	if forWord != AllowSession && forWord != AllowHour {
		return nil, errors.New("rulebook: allow for session or 1h")
	}
	if err := allowRefusal(it, forWord); err != nil {
		return nil, err
	}
	var ids []string
	switch it.Kind {
	case ItemAsk:
		var rows []string
		for _, id := range it.RuleIDs {
			row, _ := PauseRowID(id)
			key, _ := pauseKey(row)
			// A rule gone since the call (or in a project file the page did
			// not name) is a refusal that names it, not a failure.
			if pack, rid, _ := strings.Cut(key, "/"); pack == policy.UserPack && !userRuleExists(in, rid) {
				return nil, allowRefused{"the rule " + rid + " is not among your rules here any more; nothing was paused"}
			} else if _, _, found := packRule(key); pack != policy.UserPack && !found {
				return nil, allowRefused{"the rule " + key + " is not a built-in rule any more; nothing was paused"}
			}
			if !pausedAsLong(in, key, it.SessionID, forWord) {
				rows = append(rows, row)
			}
		}
		if len(rows) == 0 {
			return nil, allowRefused{"every rule on this item is already paused for at least that long; nothing was changed"}
		}
		spec := AllowHour
		if forWord == AllowSession {
			spec = "session=" + it.SessionID
		}
		temps, err := Pause(in, rows, spec)
		if err != nil {
			return nil, err
		}
		for _, t := range temps {
			ids = append(ids, t.ID)
		}
	default: // a skill item (allowRefusal let nothing else through)
		var skills []string
		by := map[string][]UngrantedEdit{}
		for _, e := range it.Ungranted {
			if _, ok := by[e.Skill]; !ok {
				skills = append(skills, e.Skill)
			}
			by[e.Skill] = append(by[e.Skill], e)
		}
		for _, sk := range skills {
			t, err := GrantFor(in, sk, by[sk], time.Hour)
			if err != nil {
				for _, id := range ids {
					_ = End(in, id) // best effort: the grant written before this one
				}
				return nil, err
			}
			ids = append(ids, t.ID)
		}
	}
	return ids, nil
}

// StepSentence is s's sentence for a page to show: a hook rule's literals
// with home spelled ~ and repeats dropped (an everywhere path rule matches
// the value as typed and its expanded spelling, which would put the home
// directory on screen and name the same file twice). Any other step's
// sentence is returned as it is.
func StepSentence(home string, s Step) string {
	if s.Rule == nil || len(s.Rule.Match.Literals) == 0 {
		return s.Sentence
	}
	home = filepath.Clean(home)
	m := s.Rule.Match
	var lits []string
	for _, l := range m.Literals {
		if d := tildify(home, l); !containsStr(lits, d) {
			lits = append(lits, d)
		}
	}
	m.Literals = lits
	return hookSentence(s.Rule.Action, s.Rule.Tool, m)
}

// endTemporaries ends every id in one write of the user policy file (one
// backup); an id not in the file, already ended, pruned or replaced, is
// skipped. No id left in the file is no write.
func endTemporaries(in Input, ids []string, res *Result) error {
	return editPolicy(in.Paths.OverridesFile(), res, func(f *policy.File) (bool, error) {
		changed := false
		for _, id := range ids {
			if !manifest.ValidTemporaryID(id) {
				continue
			}
			c, err := policy.Apply(f, policy.Edit{EndTemporary: id})
			if err != nil {
				return false, err
			}
			changed = changed || c
		}
		return changed, nil
	})
}
