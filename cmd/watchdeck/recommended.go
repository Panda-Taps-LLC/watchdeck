package main

import (
	"path/filepath"
	"sort"

	"github.com/Panda-Taps-LLC/watchdeck/internal/claudesettings"
	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
	"github.com/Panda-Taps-LLC/watchdeck/internal/rulebook"
)

// userSettingsState is the user-scope FileState in eff, if Read listed one.
func userSettingsState(eff claudesettings.Effective, hp paths.Paths) (claudesettings.FileState, bool) {
	want := filepath.Clean(hp.ClaudeSettings())
	for _, f := range eff.Files {
		if f.Scope == claudesettings.ScopeUser && filepath.Clean(f.Path) == want {
			return f, true
		}
	}
	return claudesettings.FileState{}, false
}

// readNative reads, read-only, the Claude Code settings Claude Code reads
// for root (managed and user always; project and local when root is set).
// A user settings file that exists but cannot be read is an error: nothing
// may be written to it, and nothing it holds can be counted.
func readNative(hp paths.Paths, root string) (claudesettings.Effective, error) {
	eff, _ := claudesettings.Read(claudesettings.Locate(hp, root), nil)
	if f, ok := userSettingsState(eff, hp); ok && f.Exists && f.Err != nil {
		return eff, f.Err
	}
	return eff, nil
}

// recommendedMissing returns the recommended rules the settings Claude Code
// reads for root do not hold yet (rulebook.RecommendedMissing).
func recommendedMissing(hp paths.Paths, root string) ([]rulebook.Rule, error) {
	eff, err := readNative(hp, root)
	if err != nil {
		return nil, err
	}
	return rulebook.RecommendedMissing(eff), nil
}

// ownedEntries returns the ledger entries for the settings file at path
// whose string is still in that file, sorted by key then value. An entry
// whose string the person removed by hand, or that no rule id claims, is
// not counted.
func ownedEntries(led *claudesettings.Ledger, loc claudesettings.Location) (present []claudesettings.LedgerEntry, err error) {
	clean := filepath.Clean(loc.Path)
	var all []claudesettings.LedgerEntry
	for _, e := range led.Entries {
		// an entry no rule id claims owns nothing (Ledger.Owners is nil)
		if filepath.Clean(e.Path) == clean && led.Owners(e.Path, e.Key, e.Value) != nil {
			all = append(all, e)
		}
	}
	if len(all) == 0 {
		return nil, nil
	}
	eff, rerr := claudesettings.Read([]claudesettings.Location{loc}, nil)
	if len(eff.Files) == 1 && eff.Files[0].Err != nil {
		return nil, eff.Files[0].Err
	}
	if rerr != nil {
		return nil, rerr
	}
	in := map[string]bool{}
	for key, list := range map[string][]claudesettings.Entry{
		claudesettings.KeyDeny: eff.Deny, claudesettings.KeyAsk: eff.Ask, claudesettings.KeyAllow: eff.Allow,
		claudesettings.KeyAllowedDomains: eff.Sandbox.AllowedDomains, claudesettings.KeyDeniedDomains: eff.Sandbox.DeniedDomains,
	} {
		for _, en := range list {
			in[key+"\x00"+en.Value] = true
		}
	}
	for _, e := range all {
		if in[e.Key+"\x00"+e.Value] {
			present = append(present, e)
		}
	}
	sort.SliceStable(present, func(i, j int) bool {
		if present[i].Key != present[j].Key {
			return present[i].Key < present[j].Key
		}
		return present[i].Value < present[j].Value
	})
	return present, nil
}

// removeOwned takes every string the ledger says watchdeck added out of the
// settings file at loc: one claudesettings.Transact and one ManageKeys call,
// so one write and one .bak-<ts>. Every claim on each string is released,
// so the string goes; the person's own strings are never touched. A claim
// whose string is already gone is dropped from the ledger all the same. It
// returns how many strings left the file and the backup ("" when nothing
// was written).
func removeOwned(stateDir string, loc claudesettings.Location) (removed int, backup string, err error) {
	clean := filepath.Clean(loc.Path)
	err = claudesettings.Transact(stateDir, func(led *claudesettings.Ledger) error {
		var edits []claudesettings.KeyEdit
		at := map[string]int{}
		for _, e := range led.Entries {
			if filepath.Clean(e.Path) != clean {
				continue
			}
			i, ok := at[e.Key]
			if !ok {
				i = len(edits)
				at[e.Key] = i
				edits = append(edits, claudesettings.KeyEdit{Key: e.Key})
			}
			for _, id := range led.Owners(e.Path, e.Key, e.Value) {
				edits[i].Removes = append(edits[i].Removes, claudesettings.Claim{Value: e.Value, RuleID: id})
			}
		}
		if len(edits) == 0 {
			return nil
		}
		chs, err := claudesettings.ManageKeys(loc, led, edits)
		if err != nil {
			return err
		}
		for _, ch := range chs {
			removed += len(ch.Removed)
			if ch.Backup != "" {
				backup = ch.Backup
			}
		}
		return nil
	})
	return removed, backup, err
}
