package policy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/manifest"
)

// Edit is one change to a policy file. Exactly one group is used:
//
//   - Kind skill: Grant is applied to the skill's block with
//     manifest.Apply semantics (Name "*" edits the defaults block; Reset,
//     removal of an absent entry, Home's real-path deny check and every
//     error message are manifest.Apply's).
//   - Any other kind: Put inserts or replaces the subject Kind/Name (Put's
//     own Kind and Name must match), Delete removes it.
//   - Pack / Rule (Kind ""): set or clear a pack setting or a rule override.
//   - PutRule / DeleteRule (Kind ""): insert or replace (by ID, keeping its
//     place) or remove one of the file's own rules under rules:.
//   - SetMode (Kind ""): the file's mode (shadow mode, Phase 6).
//   - AddTemporary / EndTemporary (Kind ""): add an entry to the
//     temporary: list (its ID is filled from manifest.TemporaryID when
//     empty; times are kept in UTC to the second; the same entry again is
//     no change, another entry with its id an error) or remove the entry
//     with that id (an unknown id is no change). Plan 08.
type Edit struct {
	Kind Kind
	Name string

	Grant manifest.Edit

	Put    *manifest.PolicySubject
	Delete bool

	Pack        string
	PackSetting *manifest.Toggle // nil with Pack set clears it

	Rule         string           // "<pack>/<rule id>"
	RuleOverride *manifest.Toggle // nil with Rule set clears it

	PutRule    *manifest.PolicyRule // a rule under rules:, replaced by ID
	DeleteRule string               // the ID of a rule under rules: to remove

	SetMode string // ModeEnforce | ModeShadow: set the file's mode; enforce removes the line

	AddTemporary *manifest.Temporary // a temporary: entry to add
	EndTemporary string              // the id of a temporary: entry to remove
}

// Apply applies e to f in place. changed is false (and f untouched) when the
// file already says so. The result is validated by rendering it and parsing
// it back strictly; on any error f is unchanged. A changed file becomes
// version 2.
func Apply(f *File, e Edit) (changed bool, err error) {
	next := f.Clone()
	switch {
	case e.Kind == KindSkill:
		changed, err = applySkill(&next, e)
	case e.Kind != "":
		changed, err = applySubject(&next, e)
	case e.Pack != "":
		changed, err = applyPack(&next, e)
	case e.Rule != "":
		changed, err = applyRule(&next, e)
	case e.PutRule != nil:
		changed = applyPutRule(&next, *e.PutRule)
	case e.DeleteRule != "":
		changed = applyDeleteRule(&next, e.DeleteRule)
	case e.SetMode != "":
		changed, err = applyMode(&next, e.SetMode)
	case e.AddTemporary != nil:
		changed, err = applyAddTemporary(&next, *e.AddTemporary)
	case e.EndTemporary != "":
		changed = applyEndTemporary(&next, e.EndTemporary)
	default:
		return false, errors.New("edit: nothing to change")
	}
	if err != nil || !changed {
		return false, err
	}
	next.Version = 2
	if err := check(next); err != nil {
		return false, err
	}
	*f = next
	return true, nil
}

// applyMode sets the file's mode; enforce is stored as "" (no line).
func applyMode(f *File, mode string) (bool, error) {
	var want string
	switch mode {
	case manifest.ModeEnforce:
	case manifest.ModeShadow:
		want = manifest.ModeShadow
	default:
		return false, errors.New("edit: mode must be enforce or shadow")
	}
	if f.Mode == want {
		return false, nil
	}
	f.Mode = want
	return true, nil
}

// applyTemporaryCanon is t with UTC times cut to the second and its ID
// filled: the form Render writes.
func applyTemporaryCanon(t manifest.Temporary) manifest.Temporary {
	t = t.Clone()
	t.Added = t.Added.UTC().Truncate(time.Second)
	t.Until = t.Until.UTC().Truncate(time.Second)
	if t.ID == "" {
		t.ID = manifest.TemporaryID(t)
	}
	return t
}

func applyAddTemporary(f *File, t manifest.Temporary) (bool, error) {
	t = applyTemporaryCanon(t)
	for _, cur := range f.Temporary {
		if cur.ID != t.ID {
			continue
		}
		if Render(File{Version: 2, Temporary: []manifest.Temporary{cur}}) == Render(File{Version: 2, Temporary: []manifest.Temporary{t}}) {
			return false, nil
		}
		return false, errors.New("edit: another temporary has this id")
	}
	f.Temporary = append(f.Temporary, t)
	return true, nil
}

func applyEndTemporary(f *File, id string) bool {
	for i, cur := range f.Temporary {
		if cur.ID == id {
			f.Temporary = append(f.Temporary[:i:i], f.Temporary[i+1:]...)
			if len(f.Temporary) == 0 {
				f.Temporary = nil
			}
			return true
		}
	}
	return false
}

// pruneTemporaries is ts without the entries expired at now (a new slice).
func pruneTemporaries(ts []manifest.Temporary, now time.Time) []manifest.Temporary {
	var out []manifest.Temporary
	for _, t := range ts {
		if t.Active(now) {
			out = append(out, t)
		}
	}
	return out
}

// applySkill edits the skill's permanent block. It reads the view without
// temporaries (BaseSkillOverrides): the folded view would write a timed
// grant into the permanent one.
func applySkill(f *File, e Edit) (bool, error) {
	out, changed, err := manifest.Apply(f.BaseSkillOverrides(), e.Name, e.Grant)
	if err != nil || !changed {
		return false, err
	}
	f.Defaults = out.Defaults
	var subs []manifest.PolicySubject
	done := map[string]bool{}
	for _, s := range f.Subjects {
		if s.Kind != KindSkill {
			subs = append(subs, s)
			continue
		}
		g, ok := out.Skills[s.Name]
		if !ok {
			continue // block deleted
		}
		gc := g
		s.Grant = &gc
		subs = append(subs, s)
		done[s.Name] = true
	}
	for _, n := range sortedKeys(out.Skills) {
		if done[n] {
			continue
		}
		g := out.Skills[n]
		subs = append(subs, manifest.PolicySubject{Kind: KindSkill, Name: n, Grant: &g})
	}
	f.Subjects = subs
	return true, nil
}

func applySubject(f *File, e Edit) (bool, error) {
	idx := -1
	for i, s := range f.Subjects {
		if s.Kind == e.Kind && s.Name == e.Name {
			idx = i
			break
		}
	}
	switch {
	case e.Delete:
		if idx < 0 {
			return false, nil
		}
		f.Subjects = append(f.Subjects[:idx:idx], f.Subjects[idx+1:]...)
		return true, nil
	case e.Put != nil:
		if e.Put.Kind != e.Kind || e.Put.Name != e.Name {
			return false, errors.New("edit: put subject kind/name differ from the edit's")
		}
		put := e.Put.Clone()
		if idx >= 0 {
			if Render(File{Version: 2, Subjects: []manifest.PolicySubject{f.Subjects[idx]}}) ==
				Render(File{Version: 2, Subjects: []manifest.PolicySubject{put}}) {
				return false, nil
			}
			f.Subjects[idx] = put
		} else {
			f.Subjects = append(f.Subjects, put)
		}
		return true, nil
	}
	return false, errors.New("edit: put or delete required for kind " + e.Kind)
}

func applyPack(f *File, e Edit) (bool, error) {
	if !manifest.ValidPackID(e.Pack) {
		return false, errors.New("edit: invalid pack name (" + manifest.PackIDRule + ")")
	}
	return applyToggle(&f.Packs, e.Pack, e.PackSetting)
}

func applyRule(f *File, e Edit) (bool, error) {
	if !manifest.ValidRuleKey(e.Rule) {
		return false, errors.New("edit: invalid rule key (" + manifest.RuleKeyRule + ")")
	}
	return applyToggle(&f.RuleOverrides, e.Rule, e.RuleOverride)
}

// applyPutRule inserts r, or replaces the rule with r's ID in place; an
// identical rule is no change. Validation is check's (the strict parse
// enforces the id, tool, match and action rules; the regex is compiled).
func applyPutRule(f *File, r manifest.PolicyRule) bool {
	r.Match.Literals = append([]string(nil), r.Match.Literals...)
	r.Match.Argv0 = append([]string(nil), r.Match.Argv0...)
	if len(r.Match.Literals) == 0 {
		r.Match.Literals = nil
	}
	if len(r.Match.Argv0) == 0 {
		r.Match.Argv0 = nil
	}
	for i, cur := range f.Rules {
		if cur.ID != r.ID {
			continue
		}
		if Render(File{Version: 2, Rules: []manifest.PolicyRule{cur}}) == Render(File{Version: 2, Rules: []manifest.PolicyRule{r}}) {
			return false
		}
		f.Rules[i] = r
		return true
	}
	f.Rules = append(f.Rules, r)
	return true
}

// applyDeleteRule removes the rule with id; an unknown id is no change.
func applyDeleteRule(f *File, id string) bool {
	for i, cur := range f.Rules {
		if cur.ID == id {
			f.Rules = append(f.Rules[:i:i], f.Rules[i+1:]...)
			return true
		}
	}
	return false
}

func applyToggle(m *map[string]manifest.Toggle, key string, t *manifest.Toggle) (bool, error) {
	cur, had := (*m)[key]
	if t == nil {
		if !had {
			return false, nil
		}
		delete(*m, key)
		if len(*m) == 0 {
			*m = nil
		}
		return true, nil
	}
	if t.Enabled == nil && t.Action == "" {
		return false, errors.New("edit: empty toggle (set enabled and/or action)")
	}
	if had && cur.Equal(*t) {
		return false, nil
	}
	if *m == nil {
		*m = map[string]manifest.Toggle{}
	}
	(*m)[key] = t.Clone()
	return true, nil
}

// check renders f as v2, parses it back strictly, requires a byte-identical
// re-render, compiles every rule regex and requires the packs and
// rule_overrides to be a valid internal/rules configuration (known packs
// and rules): a file that fails here is never written.
func check(f File) error {
	f.Version = 2
	text := Render(f)
	back, err := manifest.ParsePolicyFile([]byte(text))
	if err != nil {
		return err
	}
	if Render(back) != text {
		return errors.New("policy does not round-trip (internal error)")
	}
	for i, r := range back.Rules {
		if r.Match.Regex == "" {
			continue
		}
		if _, err := regexp.Compile(r.Match.Regex); err != nil {
			return fmt.Errorf("rules[%d].match.regex: does not compile (RE2 syntax)", i)
		}
	}
	if err := FileRulesConfig(back).Validate(); err != nil {
		return err
	}
	return nil
}

// backupNow is the clock for backup names; tests replace it.
var backupNow = time.Now

const (
	maxBackupsPerSecond = 10000
	// KeepBackups is how many <path>.bak-<ts> files Save keeps; older ones
	// are removed after a successful save. Conversion backups
	// (<path>.bak-v1-<ts>) are never removed.
	KeepBackups = 10
)

// Save writes f to path as version 2: render, parse back and re-render
// byte for byte, compile rule regexes, validate the rules configuration (an
// invalid file is never written); copy an existing file to
// <path>.bak-<unix seconds> (then -2, -3, … when taken; created
// exclusively, 0600, never overwriting a backup), or to
// <path>.bak-v1-<unix seconds> when the existing file is not version 2 (the
// conversion backup, kept for good); write a temp file beside the target
// with mode 0600, fsync, rename over path; then remove all but the newest
// KeepBackups <path>.bak-<ts> files. A v1 file becomes v2 here and only
// here. Temporaries expired at the time of the save are dropped from what
// is written (Plan 08: nothing else reaps them); f itself is not changed.
// Returns the backup path ("" when there was no file).
func Save(path string, f File) (backup string, err error) {
	f.Version = 2
	f.Temporary = pruneTemporaries(f.Temporary, time.Now())
	if err := check(f); err != nil {
		return "", fmt.Errorf("refusing to write an invalid policy file: %w", err)
	}
	text := Render(f)
	// A symlinked file (a dotfiles setup may link it) is saved at its
	// target, backups beside it, so the rename does not replace the link.
	if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		if r, err := filepath.EvalSymlinks(path); err == nil {
			path = r
		}
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	old, rerr := manifest.ReadPolicyFile(path)
	switch {
	case rerr == nil:
		tag := "bak-"
		if !isV2(old) {
			tag = "bak-v1-"
		}
		if backup, err = writeBackup(path, tag, old); err != nil {
			return "", err
		}
	case !errors.Is(rerr, os.ErrNotExist):
		return "", rerr
	}
	tmp, err := os.CreateTemp(dir, ".overrides-*.tmp")
	if err != nil {
		return backup, err
	}
	name := tmp.Name()
	fail := func(err error) (string, error) {
		tmp.Close()
		os.Remove(name)
		return backup, err
	}
	if _, err := tmp.WriteString(text); err != nil {
		return fail(err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return backup, err
	}
	if err := os.Rename(name, path); err != nil {
		os.Remove(name)
		return backup, err
	}
	pruneBackups(path)
	return backup, nil
}

// isV2 reports whether b parses as a version 2 policy file.
func isV2(b []byte) bool {
	f, err := manifest.ParsePolicyFile(b)
	return err == nil && f.Version == 2
}

// pruneBackups removes all but the newest KeepBackups <path>.bak-<ts>[-N]
// files (by timestamp, then N). Conversion backups and anything else are
// left alone. Errors are ignored: a stale backup is harmless.
func pruneBackups(path string) {
	dir, base := filepath.Split(path)
	if dir == "" {
		dir = "."
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	type bak struct {
		name  string
		ts, n int64
	}
	var baks []bak
	for _, e := range ents {
		rest, ok := strings.CutPrefix(e.Name(), base+".bak-")
		if !ok || !e.Type().IsRegular() {
			continue
		}
		tsStr, nStr, hasN := strings.Cut(rest, "-")
		ts, err := strconv.ParseInt(tsStr, 10, 64)
		if err != nil {
			continue // bak-v1-… and foreign names
		}
		n := int64(1)
		if hasN {
			if n, err = strconv.ParseInt(nStr, 10, 64); err != nil {
				continue
			}
		}
		baks = append(baks, bak{e.Name(), ts, n})
	}
	if len(baks) <= KeepBackups {
		return
	}
	sort.Slice(baks, func(i, j int) bool {
		if baks[i].ts != baks[j].ts {
			return baks[i].ts > baks[j].ts
		}
		return baks[i].n > baks[j].n
	})
	for _, b := range baks[KeepBackups:] {
		os.Remove(filepath.Join(dir, b.name))
	}
}

func writeBackup(path, tag string, data []byte) (string, error) {
	base := fmt.Sprintf("%s.%s%d", path, tag, backupNow().Unix())
	for n := 1; n <= maxBackupsPerSecond; n++ {
		name := base
		if n > 1 {
			name = fmt.Sprintf("%s-%d", base, n)
		}
		fh, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return "", err
		}
		if _, err := fh.Write(data); err != nil {
			fh.Close()
			os.Remove(name)
			return "", err
		}
		if err := fh.Close(); err != nil {
			os.Remove(name)
			return "", err
		}
		return name, nil
	}
	return "", errors.New("too many backups this second")
}

// ---- render ----

// Render writes f as a version 2 file: a header comment, version: 2,
// mode: shadow when the file is in shadow mode (enforce, the default, is
// never written), then packs and rule_overrides (sorted by id), rules (file order), defaults,
// and subjects sorted by kind (skill, command, mcp, tool, agent) then name,
// then temporary (file order).
// Strings are double-quoted. Render(ParsePolicyFile(Render(f))) ==
// Render(f). Comments and hand ordering of a file are not kept.
func Render(f File) string {
	var b strings.Builder
	b.WriteString("# watchdeck policy file. Edited by `watchdeck allow` and the dashboard; hand edits are fine (comments are not kept).\n")
	b.WriteString("version: 2\n")
	if f.Mode == manifest.ModeShadow {
		b.WriteString("mode: shadow\n")
	}
	renderToggles(&b, "packs", f.Packs)
	renderToggles(&b, "rule_overrides", f.RuleOverrides)
	if len(f.Rules) > 0 {
		b.WriteString("rules:\n")
		for _, r := range f.Rules {
			fmt.Fprintf(&b, "  - id: %q\n", r.ID)
			fmt.Fprintf(&b, "    tool: %q\n", r.Tool)
			b.WriteString("    match:\n")
			if r.Match.Regex != "" {
				fmt.Fprintf(&b, "      regex: %q\n", r.Match.Regex)
			}
			if len(r.Match.Literals) > 0 {
				fmt.Fprintf(&b, "      literals: [%s]\n", quoteList(r.Match.Literals))
			}
			if len(r.Match.Argv0) > 0 {
				fmt.Fprintf(&b, "      argv0: [%s]\n", quoteList(r.Match.Argv0))
			}
			fmt.Fprintf(&b, "    action: %s\n", r.Action)
			if r.Severity != "" {
				fmt.Fprintf(&b, "    severity: %s\n", r.Severity)
			}
		}
	}
	if !manifest.EmptyOverride(f.Defaults) {
		b.WriteString("defaults:\n")
		renderGrant(&b, "  ", f.Defaults)
	}
	if len(f.Subjects) > 0 {
		subs := append([]manifest.PolicySubject(nil), f.Subjects...)
		sort.SliceStable(subs, func(i, j int) bool {
			ki, kj := manifest.KindOrder(subs[i].Kind), manifest.KindOrder(subs[j].Kind)
			if ki != kj {
				return ki < kj
			}
			return subs[i].Name < subs[j].Name
		})
		b.WriteString("subjects:\n")
		for _, s := range subs {
			renderSubject(&b, s)
		}
	}
	if len(f.Temporary) > 0 {
		b.WriteString("temporary:\n")
		for _, t := range f.Temporary {
			renderTemporary(&b, t)
		}
	}
	return b.String()
}

// renderTemporary writes one temporary: entry, times as RFC 3339 in UTC.
func renderTemporary(b *strings.Builder, t manifest.Temporary) {
	fmt.Fprintf(b, "  - id: %q\n", t.ID)
	fmt.Fprintf(b, "    kind: %s\n", t.Kind)
	if t.Rule != "" {
		fmt.Fprintf(b, "    rule: %q\n", t.Rule)
	}
	if t.Skill != "" {
		fmt.Fprintf(b, "    skill: %q\n", t.Skill)
	}
	if t.Grant != nil {
		if manifest.EmptyOverride(*t.Grant) {
			b.WriteString("    grant: {}\n")
		} else {
			b.WriteString("    grant:\n")
			renderGrant(b, "      ", *t.Grant)
		}
	}
	if t.Session != "" {
		fmt.Fprintf(b, "    session: %q\n", t.Session)
	}
	fmt.Fprintf(b, "    until: %q\n", t.Until.UTC().Format(time.RFC3339))
	fmt.Fprintf(b, "    added: %q\n", t.Added.UTC().Format(time.RFC3339))
}

func renderSubject(b *strings.Builder, s manifest.PolicySubject) {
	fmt.Fprintf(b, "  - kind: %s\n", s.Kind)
	fmt.Fprintf(b, "    name: %q\n", s.Name)
	const in = "    "
	m := s.Match
	if len(m.Argv0)+len(m.Glob)+len(m.Tools) > 0 || m.AgentType != "" {
		b.WriteString(in + "match:\n")
		if len(m.Argv0) > 0 {
			fmt.Fprintf(b, "%s  argv0: [%s]\n", in, quoteList(m.Argv0))
		}
		if len(m.Glob) > 0 {
			fmt.Fprintf(b, "%s  glob: [%s]\n", in, quoteList(m.Glob))
		}
		if len(m.Tools) > 0 {
			fmt.Fprintf(b, "%s  tools: [%s]\n", in, quoteList(m.Tools))
		}
		if m.AgentType != "" {
			fmt.Fprintf(b, "%s  agent_type: %q\n", in, m.AgentType)
		}
	}
	if s.Grant != nil {
		if manifest.EmptyOverride(*s.Grant) {
			b.WriteString(in + "grant: {}\n")
		} else {
			b.WriteString(in + "grant:\n")
			renderGrant(b, in+"  ", *s.Grant)
		}
	}
	if len(s.MCPTools) > 0 {
		b.WriteString(in + "tools:\n")
		for _, k := range sortedKeys(s.MCPTools) {
			fmt.Fprintf(b, "%s  %q: %s\n", in, k, s.MCPTools[k])
		}
	}
	if s.Launch != nil {
		b.WriteString(in + "launch:\n")
		fmt.Fprintf(b, "%s  sandbox: %v\n", in, s.Launch.Sandbox)
		if s.Launch.Grant != nil {
			if manifest.EmptyOverride(*s.Launch.Grant) {
				b.WriteString(in + "  grant: {}\n")
			} else {
				b.WriteString(in + "  grant:\n")
				renderGrant(b, in+"    ", *s.Launch.Grant)
			}
		}
	}
	renderGate(b, in, "paths", s.Paths)
	renderGate(b, in, "domains", s.Domains)
	renderGate(b, in, "tools", s.AgentTools)
	if s.AgentSkills != nil {
		fmt.Fprintf(b, "%sskills:\n%s  allow: [%s]\n", in, in, quoteList(s.AgentSkills))
	}
}

func renderToggles(b *strings.Builder, key string, m map[string]manifest.Toggle) {
	if len(m) == 0 {
		return
	}
	b.WriteString(key + ":\n")
	for _, id := range sortedKeys(m) {
		t := m[id]
		if t.IsScalar() {
			v := "off"
			if *t.Enabled {
				v = "on"
			}
			fmt.Fprintf(b, "  %q: %s\n", id, v)
			continue
		}
		var kv []string
		if t.Enabled != nil {
			kv = append(kv, fmt.Sprintf("enabled: %v", *t.Enabled))
		}
		if t.Action != "" {
			kv = append(kv, "action: "+t.Action)
		}
		fmt.Fprintf(b, "  %q: {%s}\n", id, strings.Join(kv, ", "))
	}
}

func renderGate(b *strings.Builder, in, key string, g *manifest.GateLists) {
	if g.IsEmpty() {
		return
	}
	fmt.Fprintf(b, "%s%s:\n", in, key)
	if len(g.Deny) > 0 {
		fmt.Fprintf(b, "%s  deny: [%s]\n", in, quoteList(g.Deny))
	}
	if len(g.Ask) > 0 {
		fmt.Fprintf(b, "%s  ask: [%s]\n", in, quoteList(g.Ask))
	}
}

func renderGrant(b *strings.Builder, in string, o manifest.Override) {
	if o.Network != nil {
		fmt.Fprintf(b, "%snetwork: %s\n", in, o.Network.String())
	}
	if len(o.Write) > 0 {
		fmt.Fprintf(b, "%swrite: [%s]\n", in, quoteList(o.Write))
	}
	if len(o.Read) > 0 {
		fmt.Fprintf(b, "%sread: [%s]\n", in, quoteList(o.Read))
	}
	if len(o.Env) > 0 {
		fmt.Fprintf(b, "%senv: [%s]\n", in, quoteList(dedupe(o.Env)))
	}
	if o.Caches {
		fmt.Fprintf(b, "%scaches: true\n", in)
	}
	if o.AutoAllow != nil {
		fmt.Fprintf(b, "%sauto_allow: %v\n", in, *o.AutoAllow)
	}
}

func quoteList(xs []string) string {
	q := make([]string, len(xs))
	for i, x := range xs {
		q[i] = fmt.Sprintf("%q", x)
	}
	return strings.Join(q, ", ")
}

// dedupe removes repeated strings, keeping first occurrences in order.
func dedupe(xs []string) []string {
	var out []string
	for _, x := range xs {
		dup := false
		for _, y := range out {
			if y == x {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, x)
		}
	}
	return out
}
