package rulebook

import (
	"fmt"
	"strings"

	"github.com/Panda-Taps-LLC/watchdeck/internal/claudesettings"
)

// Reconcile drops from the ownership ledger every string watchdeck added
// that the person has since removed from a settings file it can read
// (claudesettings.Reconcile), under the settings lock, and adds each
// dropped recommended rule (an entry claimed by an IntentPrefix intent) to
// the declined list, so it is not offered again. It returns the dropped
// entries and the intent ids it declined. When the settings cannot be read
// nothing is changed. The ledger and the declined list are written inside
// one claudesettings.Transact: a declined file that cannot be read (it is
// never overwritten here) or a failed declined write saves no ledger, and
// a rerun does both.
func Reconcile(in Input) (dropped []claudesettings.Drift, declined []string, err error) {
	err = claudesettings.Transact(in.Paths.StateDir, func(led *claudesettings.Ledger) error {
		eff, err := claudesettings.Read(claudesettings.Locate(in.Paths, in.ProjectRoot), led)
		if err != nil {
			return err
		}
		drifts := claudesettings.Reconcile(led, eff)
		var ids []string
		for _, d := range drifts {
			for _, id := range d.Entry.RuleIDs {
				if strings.HasPrefix(id, IntentPrefix) && !containsStr(ids, id) {
					ids = append(ids, id)
				}
			}
		}
		if len(ids) > 0 {
			// A declined file that cannot be read is an error here, not
			// overwritten: the person's earlier declines would be lost.
			if _, err := LoadDeclined(in.Paths.StateDir); err != nil {
				return fmt.Errorf("rulebook: could not record the declined recommended rules: %w", err)
			}
			if err := decline(in.Paths.StateDir, ids); err != nil {
				return fmt.Errorf("rulebook: could not record the declined recommended rules: %w", err)
			}
		}
		dropped, declined = drifts, ids
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return dropped, declined, nil
}
