// Package manifest parses a skill's PERMISSIONS.yaml (the REQUEST), the
// project and user override files (what the owner GRANTS), and clips the two
// into the policy that `watchdeck run` enforces.
//
// # The entitlement model
//
// A skill author declares what the skill's scripts need in PERMISSIONS.yaml.
// That file is only a request. The grant starts at Default() and is widened
// only by the project's .watchdeck.yaml and the user's overrides.yaml, in
// that order (see Grant). The project file ships with a cloned repository,
// so it is untrusted: it may only add paths under ${CWD} or ${TMP} and raise
// network to localhost; anything else it asks for is dropped and reported
// (see Widen). The user file may widen anything. The policy a script runs
// under is
//
//	eff, ungranted := Clip(request, grant)
//
// Clip never fails because a skill asked for too much; it narrows the request
// to the grant and reports every refused item in ungranted, as
// human-readable strings such as "network: all" or "write: ~/Library/Caches/pip".
// The CLI prints those in the hook's "ask" reason and in the run trailer next
// to the `watchdeck allow` command that would grant them.
//
// Parse errors are different: a malformed manifest (unknown field, wrong
// version, bad enum, relative exec path, bad env name) or a manifest that
// tries to read, write or un-deny a built-in deny path is an error from
// Parse/ParseBytes/Validate. The CLI maps those to exit 125.
//
// # Clip semantics, field by field
//
//   - Network: min(request, grant). A request above the grant adds
//     "network: <request>" to ungranted.
//   - Scripts: taken from the request when given, otherwise the grant's.
//     Scripts only decide which files count as the skill's code (so more
//     of the skill gets sandboxed); widening them is safe.
//   - Write: when the request lists filesystem.write, each entry is kept only
//     if it equals or lies under a grant entry (compared after normalisation,
//     variables kept symbolic). Refused entries become "write: <path>". When
//     the request omits filesystem.write, the grant's list is used.
//   - Read: when the request lists filesystem.read, entries under a deny
//     (grant.Deny or grant.DenyPatterns), or outside grant.Read when that is
//     non-nil, become "read: <path>". A nil Read means "everything except
//     deny"; a nil request inherits the grant's. In v0.1 reads beyond the
//     deny list are not enforced by the profile, so Read is informational.
//   - Deny: grant.Deny ∪ request.Deny. Plain paths go to Deny, ** globs to
//     DenyPatterns. A request can only add denies; Validate rejects one that
//     omits a built-in entry while listing deny at all.
//   - Exec: if the grant is "any", the request's answer stands (an explicit
//     list narrows). If the grant is a list and the request is "any", the
//     grant's list is used; nothing is reported because ExecAny cannot tell
//     an omitted exec from an explicit `exec: any`. If both are lists the
//     result is the intersection and missing paths become "exec: <path>".
//   - Env: request ⊆ grant kept, extras become "env: NAME". An omitted env
//     inherits the grant's.
//   - Tools and Notes are the prose half of the manifest; they are parsed
//     and validated but not part of Effective.
//   - AutoAllow comes from the grant only.
//
// Paths are compared after normalisation: `${HOME}` and `~` are the same,
// trailing slashes are dropped, and `..` segments are rejected at parse time
// so cleaning can never hop over a variable prefix. Variables (${SKILL_DIR},
// ${CWD}, ${TMP}, ${HOME}, ~) are never expanded here; `run` does that.
//
// No function in this package reads the user's home or environment. File
// locations come in as arguments (see LoadOverrides).
package manifest
