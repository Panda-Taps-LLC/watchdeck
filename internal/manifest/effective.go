package manifest

import (
	"fmt"
	"strings"
)

// Effective is a fully resolved policy. Variables (${SKILL_DIR} ${CWD} ${TMP}
// ~) are still symbolic; `run` expands them. A nil Read means "everything
// except deny". Deny holds plain paths, DenyPatterns holds ** globs.
type Effective struct {
	Scripts, Read, Write, Deny, DenyPatterns []string
	Network                                  Network
	ExecAny                                  bool
	Exec                                     []string
	Env                                      []string
	AutoAllow                                bool
	// ProjectScoped lists Read/Write entries that came from the untrusted
	// project override. They passed a lexical ${CWD}/${TMP} check; the
	// resolver must re-check them on real paths (ResolveProjectScoped) so a
	// symlink inside the repo cannot point the grant outside the project.
	ProjectScoped []string
	// RequestScoped lists Read/Write entries a skill manifest narrowed to
	// below ${CWD} or ${TMP} (an entry the grant holds exactly is not one).
	// The lexical Clip check cannot see a repository symlink either, so they
	// get the same real-path re-check.
	RequestScoped []string
}

// Default is the grant every skill gets with no overrides: read everything
// except the built-in deny list, write ${CWD} and ${TMP}, no network, exec
// anything, env PATH HOME LANG TMPDIR, approval "ask". Each call returns
// fresh slices.
func Default() Effective {
	deny, patterns := splitDeny(BuiltinDeny)
	return Effective{
		Scripts:      []string{"scripts/**"},
		Read:         nil,
		Write:        []string{"${CWD}", "${TMP}"},
		Deny:         deny,
		DenyPatterns: patterns,
		Network:      NetNone,
		ExecAny:      true,
		Exec:         nil,
		Env:          []string{"PATH", "HOME", "LANG", "TMPDIR"},
		AutoAllow:    false,
	}
}

// clone deep-copies an Effective so callers can widen or narrow it freely.
func (e Effective) clone() Effective {
	e.Scripts = cloneStrings(e.Scripts)
	e.Read = cloneStrings(e.Read)
	e.Write = cloneStrings(e.Write)
	e.Deny = cloneStrings(e.Deny)
	e.DenyPatterns = cloneStrings(e.DenyPatterns)
	e.Exec = cloneStrings(e.Exec)
	e.Env = cloneStrings(e.Env)
	e.ProjectScoped = cloneStrings(e.ProjectScoped)
	e.RequestScoped = cloneStrings(e.RequestScoped)
	return e
}

// Summary is the one-line policy string used by the audit table and the run
// trailer. Format, stable and in insertion order:
//
//	network=<none|localhost|all> write=<p1,p2,...> env=<N1,N2,...>[ exec=<p1,p2,...>]
//
// The exec part appears only when exec is restricted to a list. An empty
// list prints as "-". Default().Summary() is
// "network=none write=${CWD},${TMP} env=PATH,HOME,LANG,TMPDIR".
//
// Write and exec paths are display text here, each rendered through
// DisplayPath: a project override may add a write path under ${CWD} such as
// "${CWD}/x | requested but not granted: network: all", and the summary is
// printed in the hook's permission reason and the run trailer. Env names are
// validated (^[A-Z_][A-Z0-9_]*$) and printed as they are. The policy itself
// keeps the raw values.
func (e Effective) Summary() string {
	var b strings.Builder
	fmt.Fprintf(&b, "network=%s write=%s env=%s", e.Network, joinPathsOrDash(e.Write), joinOrDash(e.Env))
	if !e.ExecAny {
		fmt.Fprintf(&b, " exec=%s", joinPathsOrDash(e.Exec))
	}
	return b.String()
}

// DisplayUngranted renders one Clip ungranted item ("write: <path>") for
// display text: the kind is kept and the value goes through DisplayPath. A
// skill's PERMISSIONS.yaml is untrusted, and the item is printed after the
// hook's own "requested but not granted:" and joined with ", ", so a path
// such as "/x, network: all" must not read as a second item. Structured
// ungranted[] fields (records, the dashboard's Grant buttons) keep the raw
// item.
func DisplayUngranted(item string) string {
	kind, value, ok := strings.Cut(item, ": ")
	if !ok {
		return DisplayPath(item)
	}
	return kind + ": " + DisplayPath(value)
}

// joinPathsOrDash is joinOrDash over DisplayPath of each element.
func joinPathsOrDash(ps []string) string {
	if len(ps) == 0 {
		return "-"
	}
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = DisplayPath(p)
	}
	return strings.Join(out, ",")
}

func joinOrDash(s []string) string {
	if len(s) == 0 {
		return "-"
	}
	return strings.Join(s, ",")
}

func minNetwork(a, b Network) Network {
	if a < b {
		return a
	}
	return b
}

func maxNetwork(a, b Network) Network {
	if a > b {
		return a
	}
	return b
}

// Clip narrows request to grant field by field and reports what was refused.
// It never returns an error for over-asking; see the package documentation
// for the per-field rules. The request should already have passed Validate.
func Clip(request Manifest, grant Effective) (eff Effective, ungranted []string) {
	eff = grant.clone()

	// network: min, report a request above the grant
	if request.Network > grant.Network {
		ungranted = append(ungranted, "network: "+request.Network.String())
	}
	eff.Network = minNetwork(request.Network, grant.Network)

	// scripts: the request may only ADD globs. The grant's globs (scripts/**)
	// always stay, so a manifest cannot shrink what counts as the skill's code
	// and slip a script past the hook.
	for _, g := range request.Scripts {
		eff.Scripts = appendUnique(eff.Scripts, g)
	}

	// write: keep request entries within the grant
	if request.Filesystem.Write != nil {
		eff.Write = []string{}
		for _, p := range request.Filesystem.Write {
			n := normPath(p)
			if withinAny(n, grant.Write) {
				eff.Write = appendUnique(eff.Write, n)
				eff.RequestScoped = markRequestScoped(eff.RequestScoped, n, grant.Write)
			} else {
				ungranted = append(ungranted, "write: "+n)
			}
		}
	}

	// read: drop request entries under a deny or outside a restricted grant
	if request.Filesystem.Read != nil {
		eff.Read = []string{}
		for _, p := range request.Filesystem.Read {
			n := normPath(p)
			denied := underDeny(n, grant.Deny, grant.DenyPatterns)
			outside := grant.Read != nil && !withinAny(n, grant.Read)
			if denied || outside {
				ungranted = append(ungranted, "read: "+n)
			} else {
				eff.Read = appendUnique(eff.Read, n)
				eff.RequestScoped = markRequestScoped(eff.RequestScoped, n, grant.Read)
			}
		}
	}

	// deny: union; the request can only add
	reqDeny, reqPatterns := splitDeny(request.Filesystem.Deny)
	for _, d := range reqDeny {
		eff.Deny = appendUnique(eff.Deny, d)
	}
	for _, p := range reqPatterns {
		eff.DenyPatterns = appendUnique(eff.DenyPatterns, p)
	}

	// exec
	switch {
	case grant.ExecAny:
		eff.ExecAny = request.ExecAny
		if request.ExecAny {
			eff.Exec = nil
		} else {
			eff.Exec = normAll(request.Exec)
			if eff.Exec == nil {
				eff.Exec = []string{}
			}
		}
	case request.ExecAny:
		eff.ExecAny = false
		eff.Exec = cloneStrings(grant.Exec)
	default:
		eff.ExecAny = false
		eff.Exec = []string{}
		for _, p := range request.Exec {
			n := normPath(p)
			if containsPath(grant.Exec, n) {
				eff.Exec = appendUnique(eff.Exec, n)
			} else {
				ungranted = append(ungranted, "exec: "+n)
			}
		}
	}

	// env: request ⊆ grant
	if request.Env != nil {
		eff.Env = []string{}
		for _, name := range request.Env {
			if contains(grant.Env, name) {
				eff.Env = appendUnique(eff.Env, name)
			} else {
				ungranted = append(ungranted, "env: "+name)
			}
		}
	}

	eff.AutoAllow = grant.AutoAllow
	return eff, dedupe(ungranted)
}

// Intersect combines two effective policies for a run that touches both
// skills: writes ∩, reads ∩ (nil is the identity), env ∩, exec ∩,
// network = min, deny ∪, scripts ∪, AutoAllow only if both allow,
// ProjectScoped ∪, RequestScoped ∪.
func Intersect(a, b Effective) Effective {
	var out Effective
	for _, s := range a.Scripts {
		out.Scripts = appendUnique(out.Scripts, s)
	}
	for _, s := range b.Scripts {
		out.Scripts = appendUnique(out.Scripts, s)
	}

	switch {
	case a.Read == nil:
		out.Read = cloneStrings(b.Read)
	case b.Read == nil:
		out.Read = cloneStrings(a.Read)
	default:
		out.Read = intersectPaths(a.Read, b.Read)
	}
	out.Write = intersectPaths(a.Write, b.Write)

	for _, d := range a.Deny {
		out.Deny = appendUnique(out.Deny, normPath(d))
	}
	for _, d := range b.Deny {
		out.Deny = appendUnique(out.Deny, normPath(d))
	}
	for _, p := range a.DenyPatterns {
		out.DenyPatterns = appendUnique(out.DenyPatterns, p)
	}
	for _, p := range b.DenyPatterns {
		out.DenyPatterns = appendUnique(out.DenyPatterns, p)
	}

	out.Network = minNetwork(a.Network, b.Network)

	switch {
	case a.ExecAny && b.ExecAny:
		out.ExecAny = true
	case a.ExecAny:
		out.Exec = normAll(b.Exec)
	case b.ExecAny:
		out.Exec = normAll(a.Exec)
	default:
		out.Exec = []string{}
		for _, p := range a.Exec {
			if containsPath(b.Exec, p) {
				out.Exec = appendUnique(out.Exec, normPath(p))
			}
		}
	}
	if !out.ExecAny && out.Exec == nil {
		out.Exec = []string{}
	}

	out.Env = []string{}
	for _, name := range a.Env {
		if contains(b.Env, name) {
			out.Env = appendUnique(out.Env, name)
		}
	}

	out.AutoAllow = a.AutoAllow && b.AutoAllow

	// project marks ∪: an entry either side took from the project file is
	// still re-checked on real paths (ResolveProjectScoped) after the merge
	for _, s := range append(cloneStrings(a.ProjectScoped), b.ProjectScoped...) {
		out.ProjectScoped = appendUnique(out.ProjectScoped, s)
	}
	for _, s := range append(cloneStrings(a.RequestScoped), b.RequestScoped...) {
		out.RequestScoped = appendUnique(out.RequestScoped, s)
	}
	return out
}

// markRequestScoped adds n to marks when it lies below ${CWD} or ${TMP} and
// the grant does not hold it exactly: a path the request chose inside the
// project, which a repository symlink could point elsewhere.
func markRequestScoped(marks []string, n string, grant []string) []string {
	if !strings.HasPrefix(n, "${CWD}/") && !strings.HasPrefix(n, "${TMP}/") {
		return marks
	}
	if contains(grant, n) {
		return marks
	}
	return appendUnique(marks, n)
}

// intersectPaths keeps the entries of each list that lie within the other,
// so the result is the set of paths both lists allow (subpaths included).
// The result is never nil.
func intersectPaths(x, y []string) []string {
	out := []string{}
	for _, p := range x {
		if n := normPath(p); withinAny(n, y) {
			out = appendUnique(out, n)
		}
	}
	for _, p := range y {
		if n := normPath(p); withinAny(n, x) {
			out = appendUnique(out, n)
		}
	}
	return out
}
