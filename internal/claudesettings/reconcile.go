package claudesettings

import "path/filepath"

// ReasonRemovedByUser is the Drift reason for an owned string that is gone.
const ReasonRemovedByUser = "removed by user"

// Drift is a ledger entry that no longer matches the files.
type Drift struct {
	Entry  LedgerEntry
	Reason string
}

// Reconcile compares the ledger with what Read found. An owned string that
// is gone from a file Read loaded cleanly (or from a file that no longer
// exists) is reported as "removed by user" and dropped from led in memory;
// the caller saves led. An entry whose file had a read error, or whose file
// is not among eff.Files (another project's), is left alone: unknown is not
// removed.
func Reconcile(led *Ledger, eff Effective) []Drift {
	if led == nil {
		return nil
	}
	var drifts []Drift
	kept := led.Entries[:0:0]
	for _, e := range led.Entries {
		st, found := fileFor(eff, e.Path)
		entries, known := entriesFor(eff, e.Key)
		switch {
		case !found || st.Err != nil || !known:
			kept = append(kept, e)
		case st.Exists && present(entries, e.Path, e.Value):
			kept = append(kept, e)
		default:
			drifts = append(drifts, Drift{Entry: e, Reason: ReasonRemovedByUser})
		}
	}
	led.Entries = kept
	return drifts
}

func fileFor(eff Effective, path string) (FileState, bool) {
	clean := filepath.Clean(path)
	for _, f := range eff.Files {
		if filepath.Clean(f.Path) == clean {
			return f, true
		}
	}
	return FileState{}, false
}

func present(entries []Entry, path, value string) bool {
	clean := filepath.Clean(path)
	for _, en := range entries {
		if en.Value == value && filepath.Clean(en.Path) == clean {
			return true
		}
	}
	return false
}

// entriesFor maps a dotted key to its list in eff; known is false for a key
// Read does not collect.
func entriesFor(eff Effective, key string) (entries []Entry, known bool) {
	switch key {
	case KeyAllow:
		return eff.Allow, true
	case KeyAsk:
		return eff.Ask, true
	case KeyDeny:
		return eff.Deny, true
	case KeyAllowedDomains:
		return eff.Sandbox.AllowedDomains, true
	case KeyDeniedDomains:
		return eff.Sandbox.DeniedDomains, true
	case KeyExcluded:
		return eff.Sandbox.Excluded, true
	case KeyHardDeny:
		return eff.AutoMode.HardDeny, true
	case KeySoftDeny:
		return eff.AutoMode.SoftDeny, true
	case KeyAutoAllow:
		return eff.AutoMode.Allow, true
	case KeyEnvironment:
		return eff.AutoMode.Environment, true
	}
	return nil, false
}
