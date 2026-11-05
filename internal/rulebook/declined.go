package rulebook

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"github.com/Panda-Taps-LLC/watchdeck/internal/claudesettings"
	"github.com/Panda-Taps-LLC/watchdeck/internal/safeio"
)

// DeclinedFile is the list of recommended rules the person said no to,
// <stateDir>/recommended-declined.json (mode 0600), beside the ledger.
const DeclinedFile = "recommended-declined.json"

// declinedVersion is the declined file's format version.
const declinedVersion = 1

// Declined is the declined file: the ledger intent ids
// (IntentPrefix + IntentID(value)) of the recommended rules not to offer
// again, sorted.
type Declined struct {
	V         int      `json:"v"`
	IntentIDs []string `json:"intent_ids"`
}

// LoadDeclined reads the declined file. A missing file is an empty list; a
// symlink at the path, a file that does not parse or one of another
// version is an error naming the file and saying to delete it.
func LoadDeclined(stateDir string) (Declined, error) {
	empty := Declined{V: declinedVersion, IntentIDs: []string{}}
	if stateDir == "" {
		return empty, nil
	}
	path := filepath.Join(stateDir, DeclinedFile)
	b, err := safeio.ReadRegular(path, safeio.MaxJSON, true)
	if errors.Is(err, fs.ErrNotExist) {
		return empty, nil
	}
	if err != nil {
		return empty, err
	}
	var d Declined
	if err := json.Unmarshal(b, &d); err != nil {
		return empty, fmt.Errorf("rulebook: %s does not parse (%v); delete it to start the declined list over", path, err)
	}
	if d.V != declinedVersion {
		return empty, fmt.Errorf("rulebook: %s has version %d, this build reads %d; delete it to start the declined list over", path, d.V, declinedVersion)
	}
	if d.IntentIDs == nil {
		d.IntentIDs = []string{}
	}
	return d, nil
}

// Has reports whether intentID is declined.
func (d Declined) Has(intentID string) bool { return containsStr(d.IntentIDs, intentID) }

// Decline adds intent ids to the declined file (sorted, without
// duplicates; adding one already there changes nothing), under the
// state-dir lock (claudesettings.Locked; ErrLockTimeout when another
// watchdeck holds it).
func Decline(stateDir string, intentIDs []string) error {
	if stateDir == "" {
		return errNoStateDir()
	}
	return claudesettings.Locked(stateDir, func() error { return decline(stateDir, intentIDs) })
}

// Undecline takes intent ids out of the declined file under the state-dir
// lock; one not there is no change.
func Undecline(stateDir string, intentIDs []string) error {
	if stateDir == "" {
		return errNoStateDir()
	}
	return claudesettings.Locked(stateDir, func() error { return undecline(stateDir, intentIDs) })
}

func errNoStateDir() error { return errors.New("rulebook: no state directory for the declined list") }

// decline is Decline without the lock, for callers already inside
// claudesettings.Transact (Reconcile, Apply).
func decline(stateDir string, intentIDs []string) error {
	return editDeclined(stateDir, func(set map[string]bool) {
		for _, id := range intentIDs {
			if id != "" {
				set[id] = true
			}
		}
	})
}

// undecline is Undecline without the lock, for callers already inside
// claudesettings.Transact.
func undecline(stateDir string, intentIDs []string) error {
	return editDeclined(stateDir, func(set map[string]bool) {
		for _, id := range intentIDs {
			delete(set, id)
		}
	})
}

// editDeclined loads the declined file, applies fn to its set and writes
// it back (atomically, 0600) when the set changed. A file that cannot be
// read (corrupt, another version, a symlink) counts as empty and is
// replaced by the next change: a side file never blocks an install. It
// takes no lock: the caller holds the state-dir lock.
func editDeclined(stateDir string, fn func(set map[string]bool)) error {
	if stateDir == "" {
		return errNoStateDir()
	}
	d, err := LoadDeclined(stateDir)
	if err != nil {
		d = Declined{V: declinedVersion, IntentIDs: []string{}}
	}
	set := make(map[string]bool, len(d.IntentIDs))
	for _, id := range d.IntentIDs {
		set[id] = true
	}
	fn(set)
	ids := make([]string, 0, len(set))
	for id := range set {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	if equalStrings(ids, d.IntentIDs) {
		return nil // nothing changed (a missing file stays missing)
	}
	return writeDeclined(stateDir, Declined{V: declinedVersion, IntentIDs: ids})
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// writeDeclined writes d atomically (temp file, fsync, rename) with mode
// 0600, creating the state dir 0700 when needed.
func writeDeclined(stateDir string, d Declined) error {
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(stateDir, ".declined-*.tmp") // created 0600
	if err != nil {
		return err
	}
	name := tmp.Name()
	fail := func(err error) error {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		return fail(err)
	}
	if _, err := tmp.Write(b); err != nil {
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Rename(name, filepath.Join(stateDir, DeclinedFile)); err != nil {
		os.Remove(name)
		return err
	}
	if dir, err := os.Open(stateDir); err == nil {
		_ = dir.Sync()
		dir.Close()
	}
	return nil
}

// RecommendedOffer is missing without the rules the person declined, or
// all of missing when all is set. A declined file that cannot be read
// declines nothing: the offer is a question, never a write.
func RecommendedOffer(in Input, missing []Rule, all bool) []Rule {
	if all {
		return missing
	}
	d, err := LoadDeclined(in.Paths.StateDir)
	if err != nil {
		return missing
	}
	out := make([]Rule, 0, len(missing))
	for _, r := range missing {
		if !d.Has(IntentPrefix + IntentID(r.Value)) {
			out = append(out, r)
		}
	}
	return out
}
