package claudesettings

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/settings"
)

// Change reports what one Manage call wrote.
type Change struct {
	Path           string
	Added, Removed []string
	Backup         string // the .bak-<ts> of the previous bytes, "" when nothing was written or the file was new
}

// now is the clock for ledger entries.
var now = time.Now

// beforeSave, when set by a test, runs after the change is applied in memory
// and before the drift check, so a test can write the file "concurrently".
var beforeSave func(path string)

// manageable reports whether Manage may write key.
func manageable(key string) bool {
	switch key {
	case KeyDeny, KeyAsk, KeyAllow, KeyAllowedDomains, KeyDeniedDomains:
		return true
	}
	return false
}

// Manage adds and removes strings in one list key of one writable settings
// file and records ownership in led (in memory; the caller saves led).
//
//   - A ReadOnly location, an unknown key (autoMode keys included), an empty
//     string or "$defaults" is an error and nothing is written.
//   - ruleID is the intent that claims an added string. One string may be
//     claimed by several rule ids; the ledger keeps one entry per string with
//     every id in RuleIDs. An add needs a non-empty ruleID.
//   - An add whose string is absent is appended and claimed for ruleID.
//   - An add whose string is present and owned adds ruleID to its claims
//     (deduplicated) and writes nothing; Change.Added stays empty.
//   - An add whose string is present and unowned is a no-op and is not
//     claimed: the person owns it.
//   - A remove for a rule id that does not claim the string is a no-op. A
//     remove drops ruleID's claim; only when the last claim goes is the
//     string removed from the array (and its entry from the ledger). A claim
//     whose string is already gone from the file is dropped all the same.
//   - Removing the last string leaves the empty array and its parent object
//     in place: the person may have written them, and Claude Code accepts an
//     empty list.
//   - Every other byte stays as it was (settings.Object keeps key order and
//     values; the file is re-encoded the way Claude Code writes it).
//   - The write stats the file, loads it, applies, stats again and saves with
//     settings.SaveSync and a .bak-<ts> only when size and mtime (and
//     existence) are unchanged; on drift it starts over once, then errors.
//     When nothing changes the file is not touched.
func Manage(loc Location, led *Ledger, key string, adds []string, removes []string, ruleID string) (Change, error) {
	if len(adds) > 0 && ruleID == "" {
		return Change{Path: loc.Path}, errors.New("claudesettings: an add needs the rule id that claims it")
	}
	return ManageMany(loc, led, key, claimsFor(adds, ruleID), claimsFor(removes, ruleID))
}

// Claim is one string and the rule id (intent) that claims or releases it.
type Claim struct {
	Value  string
	RuleID string
}

func claimsFor(values []string, ruleID string) []Claim {
	out := make([]Claim, 0, len(values))
	for _, v := range values {
		out = append(out, Claim{Value: v, RuleID: ruleID})
	}
	return out
}

// ManageMany is Manage for many strings with their own rule ids, in one
// load, apply and save of the file (so one .bak-<ts>). Each add and remove
// has Manage's per-string semantics for its own RuleID; new strings are
// appended in the order of adds. The lists are ordered slices, not maps, so
// that order is kept. A string added under several rule ids in one call is
// appended once and claimed by each. Adds run before removes.
func ManageMany(loc Location, led *Ledger, key string, adds, removes []Claim) (Change, error) {
	chs, err := ManageKeys(loc, led, []KeyEdit{{Key: key, Adds: adds, Removes: removes}})
	if len(chs) == 0 {
		return Change{Path: loc.Path}, err
	}
	return chs[0], err
}

// KeyEdit is one key's adds and removes for ManageKeys.
type KeyEdit struct {
	Key           string
	Adds, Removes []Claim
}

// ManageKeys is ManageMany for several keys of one file in one load,
// apply and save (one .bak-<ts> for the file). It returns one Change per
// edit, in order, each with the shared Backup when the file was written.
// Each key appears once. Every edit is checked before anything is read; on any error nothing is
// written and the ledger is untouched.
func ManageKeys(loc Location, led *Ledger, edits []KeyEdit) ([]Change, error) {
	if loc.ReadOnly {
		return nil, fmt.Errorf("claudesettings: %s settings %s are read-only", loc.Scope, loc.Path)
	}
	if led == nil {
		return nil, errors.New("claudesettings: Manage needs a ledger")
	}
	for i, e := range edits {
		for _, prev := range edits[:i] {
			if prev.Key == e.Key {
				return nil, fmt.Errorf("claudesettings: key %q appears twice in one write", e.Key)
			}
		}
		if !manageable(e.Key) {
			return nil, fmt.Errorf("claudesettings: key %q is not managed", e.Key)
		}
		for _, a := range e.Adds {
			if a.RuleID == "" {
				return nil, errors.New("claudesettings: an add needs the rule id that claims it")
			}
		}
		for _, list := range [][]Claim{e.Adds, e.Removes} {
			for _, c := range list {
				if c.Value == "" || c.Value == Defaults {
					return nil, fmt.Errorf("claudesettings: refusing to add or remove %q", c.Value)
				}
			}
		}
	}
	for attempt := 0; attempt < 2; attempt++ {
		results, backup, drift, err := manageOnce(loc.Path, led, edits)
		if err != nil {
			return nil, err
		}
		if drift {
			continue
		}
		// Only now, after a successful write (or none needed), touch the ledger.
		chs := make([]Change, 0, len(edits))
		for i, res := range results {
			key := edits[i].Key
			for _, c := range res.released {
				led.release(loc.Path, key, c.Value, c.RuleID)
			}
			for _, v := range res.dropped {
				led.drop(loc.Path, key, v)
			}
			for _, c := range res.added {
				led.drop(loc.Path, key, c.Value) // a stale claim for a string the person removed is replaced, not duplicated
				led.Entries = append(led.Entries, LedgerEntry{Path: loc.Path, Key: key, Value: c.Value, RuleID: c.RuleID, RuleIDs: []string{c.RuleID}, Added: now().UTC()})
			}
			for _, c := range res.claimed {
				led.claim(loc.Path, key, c.Value, c.RuleID)
			}
			ch := Change{Path: loc.Path, Added: claimValues(res.added), Removed: res.removed}
			if len(res.added) > 0 || len(res.removed) > 0 {
				ch.Backup = backup
			}
			chs = append(chs, ch)
		}
		return chs, nil
	}
	return nil, fmt.Errorf("claudesettings: %s changed while being written, twice; nothing written", loc.Path)
}

func claimValues(cs []Claim) []string {
	var out []string
	for _, c := range cs {
		out = append(out, c.Value)
	}
	return out
}

func hasClaim(cs []Claim, c Claim) bool {
	for _, x := range cs {
		if x == c {
			return true
		}
	}
	return false
}

// manageResult is one pass's plan; ManageMany applies it to the ledger only
// after the write succeeded. added: appended and newly claimed for its
// rule id. claimed: present and owned (or appended earlier in this call
// under another id), the rule id joins the claims. released: that rule id's
// claim goes, others stay. dropped: the last claim goes, so the entry goes.
// removed: the strings taken out of the array (a subset of dropped).
type manageResult struct {
	added, claimed, released []Claim
	removed, dropped         []string
}

type fileStamp struct {
	exists bool
	size   int64
	mod    time.Time
}

func stamp(path string) (fileStamp, error) {
	fi, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return fileStamp{}, nil
	}
	if err != nil {
		return fileStamp{}, err
	}
	return fileStamp{exists: true, size: fi.Size(), mod: fi.ModTime()}, nil
}

// manageOnce is one load, apply, check, save pass over every edit. drift
// is true when the file changed between the first stat and the save;
// nothing was written then.
func manageOnce(path string, led *Ledger, edits []KeyEdit) (results []manageResult, backup string, drift bool, err error) {
	pre, err := stamp(path)
	if err != nil {
		return nil, "", false, err
	}
	obj, _, err := settings.Load(path)
	if err != nil {
		return nil, "", false, err
	}
	changed := false
	for _, e := range edits {
		res, err := applyKey(obj, path, led, e.Key, e.Adds, e.Removes)
		if err != nil {
			return nil, "", false, err
		}
		changed = changed || len(res.added) > 0 || len(res.removed) > 0
		results = append(results, res)
	}
	if !changed {
		return results, "", false, nil
	}
	if beforeSave != nil {
		beforeSave(path)
	}
	post, err := stamp(path)
	if err != nil {
		return nil, "", false, err
	}
	if post != pre {
		return nil, "", true, nil
	}
	backup, err = settings.SaveSync(path, obj, true)
	if err != nil {
		return nil, "", false, err
	}
	return results, backup, false, nil
}

// applyKey applies one key's adds and removes to obj in memory and returns
// the plan for the ledger. It sets the array only when it changed.
func applyKey(obj *settings.Object, path string, led *Ledger, key string, adds, removes []Claim) (res manageResult, err error) {
	parts := splitKey(key)
	// Walk without creating: a parent object is made only when this key's
	// array changes, so a no-op edit in a multi-key call leaves no empty
	// object behind. parent is nil when an ancestor is missing.
	parent := obj
	for _, k := range parts[:len(parts)-1] {
		if _, ok := parent.Get(k); !ok {
			parent = nil
			break
		}
		next := parent.Object(k, false)
		if next == nil {
			return res, fmt.Errorf("claudesettings: %s: %q is not an object", path, k)
		}
		parent = next
	}
	last := parts[len(parts)-1]
	var arr []any
	if parent == nil {
		// nothing to read: the array is absent
	} else if v, ok := parent.Get(last); ok {
		a, isArr := v.([]any)
		if !isArr {
			return res, fmt.Errorf("claudesettings: %s: %s is not an array", path, key)
		}
		arr = a
	}
	for _, v := range arr {
		if _, isStr := v.(string); !isStr {
			return res, fmt.Errorf("claudesettings: %s: %s holds a non-string value; not rewriting it", path, key)
		}
	}
	indexOf := func(s string) int {
		for i, v := range arr {
			if v.(string) == s {
				return i
			}
		}
		return -1
	}
	addedNow := func(v string) bool {
		for _, c := range res.added {
			if c.Value == v {
				return true
			}
		}
		return false
	}
	for _, a := range adds {
		if indexOf(a.Value) >= 0 {
			// Present: added earlier in this call, ours (claim it for this
			// id too) or the person's (left alone).
			if addedNow(a.Value) {
				if !hasClaim(res.added, a) && !hasClaim(res.claimed, a) {
					res.claimed = append(res.claimed, a)
				}
			} else if led.owns(path, key, a.Value) && !hasClaim(res.claimed, a) {
				res.claimed = append(res.claimed, a)
			}
			continue
		}
		arr = append(arr, a.Value)
		res.added = append(res.added, a)
	}
	for _, r := range removes {
		i := led.find(path, key, r.Value)
		if i < 0 || contains(res.dropped, r.Value) || hasClaim(res.released, r) {
			continue
		}
		// The claims left after the releases earlier in this call.
		var ids []string
		for _, id := range led.Entries[i].claims() {
			if !hasClaim(res.released, Claim{Value: r.Value, RuleID: id}) {
				ids = append(ids, id)
			}
		}
		if !contains(ids, r.RuleID) {
			continue // this rule id never claimed it
		}
		if len(ids) > 1 {
			res.released = append(res.released, r)
			continue
		}
		res.dropped = append(res.dropped, r.Value)
		if j := indexOf(r.Value); j >= 0 {
			arr = append(arr[:j:j], arr[j+1:]...)
			res.removed = append(res.removed, r.Value)
		}
	}
	if len(res.added) == 0 && len(res.removed) == 0 {
		return res, nil
	}
	if arr == nil {
		arr = []any{}
	}
	if parent == nil {
		parent = obj
		for _, k := range parts[:len(parts)-1] {
			next := parent.Object(k, true)
			if next == nil {
				return res, fmt.Errorf("claudesettings: %s: %q is not an object", path, k)
			}
			parent = next
		}
	}
	parent.Set(last, arr)
	return res, nil
}
