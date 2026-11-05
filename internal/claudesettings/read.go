package claudesettings

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/settings"
)

// Dotted keys this package reads (and, for the first five, Manage writes).
const (
	KeyAllow          = "permissions.allow"
	KeyAsk            = "permissions.ask"
	KeyDeny           = "permissions.deny"
	KeyAllowedDomains = "sandbox.network.allowedDomains"
	KeyDeniedDomains  = "sandbox.network.deniedDomains"
	KeyExcluded       = "sandbox.excludedCommands"
	KeyHardDeny       = "autoMode.hard_deny"
	KeySoftDeny       = "autoMode.soft_deny"
	KeyAutoAllow      = "autoMode.allow"
	KeyEnvironment    = "autoMode.environment"
	keyEnabled        = "sandbox.enabled"

	// Defaults is the autoMode placeholder that splices Claude Code's
	// built-in rules in place. Manage never adds, removes or moves it.
	Defaults = "$defaults"
)

// Entry is one string from a list key, with where it came from.
type Entry struct {
	Value string
	Scope Scope
	Path  string
	Index int  // position in that file's array
	Owned bool // the ledger says watchdeck added it
}

// FileState is what Read found at one Location.
type FileState struct {
	Location
	Exists  bool
	Err     error
	Size    int64
	ModTime time.Time
}

// Effective is the merged view of every located file.
type Effective struct {
	Files            []FileState
	Allow, Ask, Deny []Entry
	AutoMode         struct{ HardDeny, SoftDeny, Allow, Environment []Entry }
	Sandbox          struct {
		Enabled                                 *bool
		Excluded, AllowedDomains, DeniedDomains []Entry
	}
}

// Read loads every location (through settings.Load, so reads are capped and
// never block) and unions their list keys in the given order. A file that
// cannot be read or parsed keeps its error in FileState.Err and contributes
// nothing. Read returns an error only when at least one file exists and
// none could be read; all files missing is an empty, valid view. led may
// be nil.
func Read(locs []Location, led *Ledger) (Effective, error) {
	var eff Effective
	ok, failed := 0, 0
	bestRank := -1
	for _, loc := range locs {
		st := FileState{Location: loc}
		fi, err := os.Stat(loc.Path)
		if errors.Is(err, fs.ErrNotExist) {
			eff.Files = append(eff.Files, st)
			continue
		}
		st.Exists = true
		if err == nil {
			st.Size, st.ModTime = fi.Size(), fi.ModTime()
		}
		var obj *settings.Object
		if err == nil {
			var existed bool
			obj, existed, err = settings.Load(loc.Path)
			if err == nil && !existed {
				st.Exists = false // removed between the stat and the read
				eff.Files = append(eff.Files, st)
				continue
			}
		}
		if err != nil {
			st.Err = err
			failed++
			eff.Files = append(eff.Files, st)
			continue
		}
		ok++
		eff.Files = append(eff.Files, st)

		add := func(dst *[]Entry, key string) {
			arr, _ := arrayAt(obj, key)
			for i, v := range arr {
				s, isStr := v.(string)
				if !isStr {
					continue
				}
				*dst = append(*dst, Entry{Value: s, Scope: loc.Scope, Path: loc.Path, Index: i, Owned: led.owns(loc.Path, key, s)})
			}
		}
		add(&eff.Allow, KeyAllow)
		add(&eff.Ask, KeyAsk)
		add(&eff.Deny, KeyDeny)
		add(&eff.AutoMode.HardDeny, KeyHardDeny)
		add(&eff.AutoMode.SoftDeny, KeySoftDeny)
		add(&eff.AutoMode.Allow, KeyAutoAllow)
		add(&eff.AutoMode.Environment, KeyEnvironment)
		add(&eff.Sandbox.Excluded, KeyExcluded)
		add(&eff.Sandbox.AllowedDomains, KeyAllowedDomains)
		add(&eff.Sandbox.DeniedDomains, KeyDeniedDomains)

		if b, isBool := valueAt(obj, keyEnabled).(bool); isBool {
			// Lower rank wins; equal rank (managed drop-ins) lets the later file win.
			if r := scopeRank(loc.Scope); bestRank < 0 || r <= bestRank {
				bestRank = r
				v := b
				eff.Sandbox.Enabled = &v
			}
		}
	}
	if failed > 0 && ok == 0 {
		return eff, fmt.Errorf("claudesettings: none of the %d existing settings files could be read", failed)
	}
	return eff, nil
}

// scopeRank orders scalar precedence: managed, local, project, user.
func scopeRank(s Scope) int {
	switch s {
	case ScopeManaged:
		return 0
	case ScopeLocal:
		return 1
	case ScopeProject:
		return 2
	}
	return 3
}

// splitKey splits a dotted key into its parts without allocating a map.
func splitKey(key string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(key); i++ {
		if key[i] == '.' {
			parts = append(parts, key[start:i])
			start = i + 1
		}
	}
	return append(parts, key[start:])
}

// valueAt returns the value at a dotted key, or nil.
func valueAt(obj *settings.Object, key string) any {
	parts := splitKey(key)
	cur := obj
	for _, k := range parts[:len(parts)-1] {
		if cur = cur.Object(k, false); cur == nil {
			return nil
		}
	}
	v, _ := cur.Get(parts[len(parts)-1])
	return v
}

// arrayAt returns the array at a dotted key; ok is false when absent or not an array.
func arrayAt(obj *settings.Object, key string) ([]any, bool) {
	arr, ok := valueAt(obj, key).([]any)
	return arr, ok
}
