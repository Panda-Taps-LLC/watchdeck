// Package rulebook composes one list of every rule on the machine that
// decides what Claude Code may do: Claude Code's own permission, auto-mode
// and sandbox settings (read through internal/claudesettings, every scope),
// watchdeck's built-in rule packs (internal/rules) and the person's policy
// files (internal/policy: user rules and subjects). Each rule becomes a Row
// with a plain-English Sentence, who owns it, what enforces it and whether
// it is on, sorted into five groups: sandbox, blocked, automode, watchdeck,
// ask.
//
// List is read-only. It never writes the settings files, the policy files
// or the ownership ledger: it reconciles a copy of the ledger to report
// Drift (strings watchdeck added that the person has since removed) and
// leaves saving to the callers that change things.
//
// Recommended is the twelve native rules watchdeck proposes at setup, each
// paired (Twin) with the built-in pack rule that covers the same ground in
// the hook. A recommended rule's ledger intent id is
// IntentPrefix + IntentID(value) ("recommended:" and the value lower-cased
// with every byte that is not an ASCII letter or digit as '-', one for one:
// Read(~/.ssh/id_*) is "recommended:read----ssh-id---"), so Read(.env)
// and Read(.env.*) never share an id.
//
// Row ids are stable across runs: RowID hashes a settings string with
// fnv32a (8 hex digits) under its scope and key, so the same string in the
// same list and scope always has the same id. A subject's first row has
// the id subject:<kind>:<name>; every later row of the same subject (a
// further tool gate Deny/Ask entry, an agent's per-tool row, an MCP tool
// entry) is subject:<kind>:<name>:<fnv32a hex8 of "<list>:<entry>">, where
// <list> names the gate list ("paths.deny", "tools.ask", "skills.allow").
// Removing any of them removes the whole subject, found by kind and name.
//
// Open is the inbox, the "Needs you" list: auto-mode denials, the hook's
// gate denies and asks, sandbox refusals and skills asking past their grant
// from the activity log since installed_at (else the last seven days), plus
// the refusals a caller read from transcripts (Rejections; never read
// here). Each Item carries Suggest's fix. Resolve appends add_rule,
// acknowledge or dismiss to <stateDir>/inbox.jsonl (0600); a resolved id
// leaves the list, a dismiss also hides every item with the same
// Signature, and an item whose fix is already a native rule in the Book
// is closed.
//
// The package is linked into the one watchdeck binary, which is also the
// hook, so it is init-free: constants and plain functions only, no
// package-level maps, regexps, templates or computed vars.
package rulebook
