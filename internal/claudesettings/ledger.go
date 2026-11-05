package claudesettings

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/safeio"
)

// LedgerFile is the ledger's name under the state dir.
const LedgerFile = "claude-settings-owned.json"

const ledgerVersion = 1

// Ledger records which settings strings watchdeck added, by file and key.
// Stored at <stateDir>/claude-settings-owned.json, mode 0600.
type Ledger struct {
	V       int           `json:"v"`
	Entries []LedgerEntry `json:"entries"`
}

// LedgerEntry is one owned string and the rule ids (intents) that claim it.
// RuleIDs is the truth; RuleID is written as RuleIDs[0] for readers that
// predate rule_ids, and read into RuleIDs when a file has no rule_ids.
type LedgerEntry struct {
	Path    string    `json:"path"`
	Key     string    `json:"key"`
	Value   string    `json:"value"`
	RuleID  string    `json:"rule_id,omitempty"`
	RuleIDs []string  `json:"rule_ids"`
	Added   time.Time `json:"added"`
}

// LoadLedger reads the ledger; a missing file is an empty v1 ledger. A
// ledger of another version is an error, so a newer watchdeck's file is
// never overwritten by an older one.
func LoadLedger(stateDir string) (*Ledger, error) {
	path := filepath.Join(stateDir, LedgerFile)
	b, err := safeio.ReadRegular(path, safeio.MaxJSON, false)
	if errors.Is(err, fs.ErrNotExist) {
		return &Ledger{V: ledgerVersion}, nil
	}
	if err != nil {
		return nil, err
	}
	var l Ledger
	if err := json.Unmarshal(b, &l); err != nil {
		return nil, fmt.Errorf("claudesettings: parse %s: %w", path, err)
	}
	if l.V != ledgerVersion {
		return nil, fmt.Errorf("claudesettings: %s has version %d, this build reads %d", path, l.V, ledgerVersion)
	}
	for i := range l.Entries {
		normalise(&l.Entries[i])
	}
	return &l, nil
}

// Save writes the ledger atomically (temp file, fsync, rename) with mode
// 0600, creating the state dir 0700 when needed.
func (l *Ledger) Save(stateDir string) error {
	if l.V == 0 {
		l.V = ledgerVersion
	}
	out := Ledger{V: l.V, Entries: make([]LedgerEntry, len(l.Entries))}
	for i, e := range l.Entries { // a copy, so the caller's entries are not rewritten
		e.RuleIDs = append([]string(nil), e.RuleIDs...)
		normalise(&e)
		out.Entries[i] = e
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false) // keep "Bash(a && b)" readable in the file
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		return err
	}
	b := buf.Bytes()
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(stateDir, ".ledger-*.tmp") // created 0600
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
	if err := os.Rename(name, filepath.Join(stateDir, LedgerFile)); err != nil {
		os.Remove(name)
		return err
	}
	if d, err := os.Open(stateDir); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}

// normalise fills RuleIDs from a lone RuleID (a file written before
// rule_ids) and sets RuleID to the first claim, never producing [""].
func normalise(e *LedgerEntry) {
	if len(e.RuleIDs) == 0 && e.RuleID != "" {
		e.RuleIDs = []string{e.RuleID}
	}
	if len(e.RuleIDs) > 0 {
		e.RuleID = e.RuleIDs[0]
	} else {
		e.RuleID = ""
		e.RuleIDs = []string{} // "rule_ids": [], never null
	}
}

// Owners returns the rule ids claiming value under key in path, in claim
// order, or nil when watchdeck does not own that string. An entry no rule
// id claims (a legacy entry with neither rule_id nor rule_ids) owns
// nothing, so it is nil too: rulebook.List shows such a string as the
// person's and rulebook.Remove refuses it, in agreement. The slice is a copy.
func (l *Ledger) Owners(path, key, value string) []string {
	i := l.find(path, key, value)
	if i < 0 {
		return nil
	}
	ids := l.Entries[i].claims()
	if len(ids) == 0 {
		return nil
	}
	return append([]string{}, ids...)
}

// claims returns the entry's rule ids, reading a lone RuleID as one claim
// for an entry built in memory without RuleIDs.
func (e LedgerEntry) claims() []string {
	if len(e.RuleIDs) == 0 && e.RuleID != "" {
		return []string{e.RuleID}
	}
	return e.RuleIDs
}

// find returns the index of the entry for path/key/value, or -1.
func (l *Ledger) find(path, key, value string) int {
	if l == nil {
		return -1
	}
	clean := filepath.Clean(path)
	for i, e := range l.Entries {
		if e.Key == key && e.Value == value && filepath.Clean(e.Path) == clean {
			return i
		}
	}
	return -1
}

// owns reports whether the ledger claims value under key in path.
func (l *Ledger) owns(path, key, value string) bool { return l.find(path, key, value) >= 0 }

// drop removes the entry for path/key/value if present.
func (l *Ledger) drop(path, key, value string) {
	if i := l.find(path, key, value); i >= 0 {
		l.Entries = append(l.Entries[:i], l.Entries[i+1:]...)
	}
}

// claim adds ruleID to the claims on path/key/value, keeping order and
// never duplicating; it does nothing when the string is unowned.
func (l *Ledger) claim(path, key, value, ruleID string) {
	i := l.find(path, key, value)
	if i < 0 {
		return
	}
	e := &l.Entries[i]
	ids := e.claims()
	if contains(ids, ruleID) {
		return
	}
	e.RuleIDs = append(append([]string(nil), ids...), ruleID)
	e.RuleID = e.RuleIDs[0]
}

// release drops ruleID from the claims on path/key/value, keeping the order
// of the others; it never drops the entry (drop does).
func (l *Ledger) release(path, key, value, ruleID string) {
	i := l.find(path, key, value)
	if i < 0 {
		return
	}
	e := &l.Entries[i]
	var kept []string
	for _, id := range e.claims() {
		if id != ruleID {
			kept = append(kept, id)
		}
	}
	e.RuleIDs = kept
	e.RuleID = ""
	if len(kept) > 0 {
		e.RuleID = kept[0]
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
