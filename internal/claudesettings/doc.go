// Package claudesettings locates and reads Claude Code's own settings files
// into one Effective view, and writes the user-scope list entries watchdeck
// owns, keeping ownership in a ledger because a pattern string such as
// "Bash(rm *)" cannot carry a marker.
//
// Files, in the order Locate lists them and Read unions list keys:
//
//	managed  darwin: /Library/Application Support/ClaudeCode/managed-settings.json,
//	         then managed-settings.d/*.json in name order (hidden files skipped);
//	         linux: the same names under /etc/claude-code. Always ReadOnly.
//	         Other systems list no managed file.
//	user     <ClaudeDir>/settings.json (CLAUDE_CONFIG_DIR or ~/.claude)
//	project  <root>/.claude/settings.json
//	local    <root>/.claude/settings.local.json
//
// List keys (permissions.allow/ask/deny, autoMode.hard_deny/soft_deny/allow/
// environment, sandbox.excludedCommands, sandbox.network.allowedDomains/
// deniedDomains) are unioned in that order; duplicates across files stay
// separate entries, and the literal "$defaults" stays an Entry at its place.
// Entry.Index is the position inside that file's array (non-string elements
// are skipped on read but still count for Index). The one scalar,
// sandbox.enabled, is an override, not a union: managed wins (a later
// drop-in over the base file), then local, then project, then user, which is
// Claude Code's precedence.
//
// Manage writes one list key in one writable file. It mutates only the
// in-memory Ledger passed to it; the caller persists it with Ledger.Save.
// Reconcile likewise drops entries from the Ledger in memory.
// Ownership is per string, with the rule ids (intents) that claim it: the
// Ledger keeps one entry per file, list key and value, and its RuleIDs list
// every rule that asked for the string. Manage adds a claim when a rule adds
// a string watchdeck already owns and removes the string only when its last
// claim goes; a string the person wrote is never claimed. Transact holds
// <stateDir>/claude-settings.lock (flock, 2 s deadline, then ErrLockTimeout)
// around load, edit and save of the Ledger, so the dashboard and the CLI
// never lose each other's claims. On Windows the lock is a no-op.
// ManagedDirOverride (nil in production, never an environment variable) lets
// tests in other packages keep Locate away from the real managed directory.
//
// The package is linked into the PreToolUse hook (Plan 02 Task 7), so it is
// init-free: constants and plain functions only, no package-level maps,
// regexps or templates.
package claudesettings
