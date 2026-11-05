package mapmodel

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/activity"
	"github.com/Panda-Taps-LLC/watchdeck/internal/manifest"
)

// Verdicts of declared vs did (§3.8).
const (
	VerdictAsDeclared = "as_declared" // the manifest declares what the script tried
	VerdictUndeclared = "undeclared"  // no manifest, or it lacks a capability the script tried
	VerdictClean      = "clean"       // ran, nothing refused or reported
	VerdictUnknown    = "unknown"     // never ran
)

// SkillDetail is a skill node's card (topology) or a skill/sandbox event's
// card (timeline).
type SkillDetail struct {
	Command       string         `json:"command,omitempty"`  // timeline events only
	Decision      string         `json:"decision,omitempty"` // timeline events only
	Requested     []string       `json:"requested"`
	Granted       []string       `json:"granted,omitempty"`
	RanUnder      []string       `json:"ran_under,omitempty"`
	CalledBy      string         `json:"called_by,omitempty"`
	Outcome       *Outcome       `json:"outcome,omitempty"`
	DeclaredVsDid *DeclaredVsDid `json:"declared_vs_did,omitempty"`
	Fix           string         `json:"fix,omitempty"`
	Grant         *Grant         `json:"grant,omitempty"`
	Joined        string         `json:"joined,omitempty"` // timeline events: how the call met its decision and run
	// Inferred: the call shown was approved as far as its Bash result says,
	// but no run record proves the script ran ("ask ✓ (inferred)").
	Inferred bool `json:"inferred,omitempty"`
}

// pick is the call whose result the card shows: the newest denied call,
// else the newest call.
func (a *skillAgg) pick() *call {
	var pick *call
	for _, c := range a.calls {
		if c.v.policy == PolicyDeny || pick == nil || pick.v.policy != PolicyDeny {
			pick = c
		}
	}
	return pick
}

// Outcome is what happened to the skill's (latest, or latest denied) call.
type Outcome struct {
	Tone     string `json:"tone"`
	Label    string `json:"label"`
	Exit     *int   `json:"exit,omitempty"`
	Evidence string `json:"evidence,omitempty"`
	Stream   string `json:"stream,omitempty"` // evidence "hint": the stream the hint came from (stdout | stderr)
	TS       string `json:"ts,omitempty"`
}

// DeclaredVsDid compares the manifest with what the runs reported. Floor is
// always true: the sandbox reports what it refused, not everything the
// script did.
type DeclaredVsDid struct {
	Verdict  string `json:"verdict"`
	Declared string `json:"declared"`
	Did      string `json:"did"`
	// DidItems is Did as its phrases ("1 connect, refused", "write allowed"),
	// so the page can list them one per line (one entry when there is one
	// phrase); absent when the runs reported nothing ("ran, nothing
	// refused…", "not run"), where Did is a summary, not a list.
	DidItems []string `json:"did_items,omitempty"`
	Floor    bool     `json:"floor"`
}

// Grant is the body the card POSTs to /api/skills/{skill}/grant (minus
// "skill"); the keys are the A3 server's EditJSON names.
type Grant struct {
	Skill    string   `json:"skill"`
	Network  string   `json:"network,omitempty"`
	AddWrite []string `json:"addWrite,omitempty"`
}

// skillAgg is everything the session did with one skill.
type skillAgg struct {
	name     string
	first    time.Time
	firstSeq int
	calls    []*call            // calls whose command ran (or tried to run) the skill's scripts
	invokes  []*call            // Skill tool calls naming it
	orphans  []*activity.Record // runs no call claims
	orphanV  []verdict
	execs    int // calls that ran plus orphan runs

	d         Declared
	hasD      bool
	ungranted []string // clip form, current grant first, else the newest record's
	tone      string
	sub       string
	detail    SkillDetail
}

// skillInfo aggregates calls per skill and builds each skill's card.
func (m *model) skillInfo() {
	m.skillAgg = map[string]*skillAgg{}
	get := func(name string, ts time.Time, seq int) *skillAgg {
		a := m.skillAgg[name]
		if a == nil {
			a = &skillAgg{name: name, first: ts, firstSeq: seq}
			m.skillAgg[name] = a
			m.skillOrder = append(m.skillOrder, name)
		} else if tsLess(ts, a.first) {
			a.first, a.firstSeq = ts, seq
		}
		return a
	}
	for _, c := range m.calls {
		for _, s := range c.skills {
			a := get(s, c.ts, c.seq)
			a.calls = append(a.calls, c)
			if c.v.ran {
				a.execs++
			}
		}
		if c.invoked != "" && !contains(c.skills, c.invoked) {
			a := get(c.invoked, c.ts, c.seq)
			a.invokes = append(a.invokes, c)
		}
		if c.v.ran {
			m.execs++
		}
	}
	for i, r := range m.orphans {
		v := orphanVerdict(r)
		m.orphanV = append(m.orphanV, v)
		for _, s := range uniqSorted(r.Skills) {
			a := get(s, recTime(r), 1<<22+i)
			a.orphans = append(a.orphans, r)
			a.orphanV = append(a.orphanV, v)
			a.execs++
		}
		m.execs++
	}
	sort.SliceStable(m.skillOrder, func(i, j int) bool {
		a, b := m.skillAgg[m.skillOrder[i]], m.skillAgg[m.skillOrder[j]]
		if tsLess(a.first, b.first) != tsLess(b.first, a.first) {
			return tsLess(a.first, b.first)
		}
		if a.firstSeq != b.firstSeq {
			return a.firstSeq < b.firstSeq
		}
		return a.name < b.name
	})
	for _, name := range m.skillOrder {
		m.buildSkill(m.skillAgg[name])
	}
}

// orphanVerdict judges a run that no call claims: sandbox stage only.
func orphanVerdict(r *activity.Record) verdict {
	v := verdict{ran: true}
	sandboxStage(&v, r, nil, false)
	v.policy = PolicyNone
	if v.sandboxDeny {
		v.policy = PolicyDeny
	}
	if v.evidence == "" {
		v.evidence = EvidenceRun
	}
	return v
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

func (m *model) buildSkill(a *skillAgg) {
	a.d, a.hasD = m.declared[a.name]
	a.ungranted = a.currentUngranted()

	d := &a.detail
	d.Requested = requestedItems(a.d, a.hasD)
	if a.hasD {
		d.Granted = grantedItems(a.d.Granted)
	}
	if v := a.latestView(); v != nil {
		d.RanUnder = viewItems(v)
	}
	d.CalledBy = m.calledBy(a)
	d.Outcome = a.outcome()
	d.DeclaredVsDid = a.declaredVsDid()
	if p := a.pick(); p != nil {
		d.Inferred = p.v.approvalInferred
	}
	d.Fix, d.Grant = fixFor(a.name, a.ungranted)

	a.sub = skillSub(a.d, a.hasD, a.ungranted)
	a.tone = "ok"
	if len(a.ungranted) > 0 {
		a.tone = "ask"
	}
}

// currentUngranted is the Declared list (the grant as it is now), else the
// newest record's list for this skill.
//
// Without a Declared entry there is no fix: a record's ungranted list is
// what was refused then, and offering it again after a grant would be
// stale. Callers pass Declared for every skill the session names.
func (a *skillAgg) currentUngranted() []string {
	if a.hasD {
		return normUngranted(a.name, a.d.Ungranted)
	}
	return nil
}

// normUngranted strips the records' "<skill>: " prefix and drops other
// skills' items.
func normUngranted(skill string, xs []string) []string {
	var out []string
	for _, x := range xs {
		if name, rest, ok := strings.Cut(x, ": "); ok && !isCapability(name) {
			if name != skill {
				continue
			}
			x = rest
		}
		out = append(out, x)
	}
	return out
}

func isCapability(s string) bool {
	switch s {
	case "network", "write", "read", "exec", "env":
		return true
	}
	return false
}

func (a *skillAgg) latestView() *manifest.View {
	for i := len(a.calls) - 1; i >= 0; i-- {
		if r := a.calls[i].run; r != nil && r.Effective != nil {
			return r.Effective
		}
	}
	for i := len(a.orphans) - 1; i >= 0; i-- {
		if a.orphans[i].Effective != nil {
			return a.orphans[i].Effective
		}
	}
	return nil
}

// outcome is the newest denied call's result, else the newest call's.
func (a *skillAgg) outcome() *Outcome {
	if pick := a.pick(); pick != nil {
		return callOutcome(pick)
	}
	if n := len(a.orphans); n > 0 {
		v := a.orphanV[n-1]
		return &Outcome{Tone: outTone(v), Label: v.out, Exit: v.exit, Evidence: v.evidence, Stream: v.stream, TS: a.orphans[n-1].TS}
	}
	if n := len(a.invokes); n > 0 {
		c := a.invokes[n-1]
		label := "invoked"
		if c.v.blocked {
			label = c.v.gate
		}
		return &Outcome{Tone: toneOf(c.v.policy), Label: label, Evidence: c.v.evidence, TS: fmtTS(c.ts)}
	}
	return nil
}

func outTone(v verdict) string {
	switch v.outTone {
	case "deny", "ok":
		return v.outTone
	}
	return "none"
}

// callOutcome is one call's result as the card shows it.
func callOutcome(c *call) *Outcome {
	v := c.v
	if v.ran {
		o := &Outcome{Tone: outTone(v), Label: v.out, Exit: v.exit, Evidence: v.evidence, Stream: v.stream, TS: fmtTS(c.ts)}
		if c.run != nil {
			o.TS = c.run.TS
		} else if c.res != nil && !c.res.ts.IsZero() {
			o.TS = fmtTS(c.res.ts)
		}
		return o
	}
	label := v.gate
	if label == "" {
		label = "no check"
	}
	return &Outcome{Tone: toneOf(v.policy), Label: label, Evidence: v.evidence, TS: fmtTS(c.ts)}
}

// declaredVsDid compares the request with the denials and reaches the runs
// reported (§3.8).
func (a *skillAgg) declaredVsDid() *DeclaredVsDid {
	dv := &DeclaredVsDid{Floor: true, Declared: declaredText(a.d, a.hasD)}
	tried := map[string]int{}
	reached := map[string]int{}
	ran := false
	var lastExit *int
	add := func(v verdict) {
		if !v.ran {
			return
		}
		ran = true
		if v.exit != nil {
			lastExit = v.exit
		}
		for _, k := range v.tried {
			tried[k]++
		}
		for _, k := range v.reached {
			reached[k]++
		}
	}
	for _, c := range a.calls {
		add(c.v)
	}
	for _, v := range a.orphanV {
		add(v)
	}
	if !ran {
		dv.Verdict, dv.Did = VerdictUnknown, "not run"
		return dv
	}
	var did []string
	for _, k := range []string{activity.HintNetwork, activity.HintWrite, activity.HintRead, activity.HintExec, activity.HintUnknown} {
		if n := tried[k]; n > 0 {
			did = append(did, triedWords(k, n))
		}
	}
	for _, k := range []string{activity.HintNetwork, activity.HintWrite, activity.HintRead, activity.HintExec} {
		if reached[k] > 0 {
			did = append(did, reachedWords(k))
		}
	}
	if len(did) == 0 {
		dv.Verdict = VerdictClean
		dv.Did = "ran, nothing refused"
		if lastExit != nil {
			dv.Did += ", exit " + strconv.Itoa(*lastExit)
		}
		return dv
	}
	dv.Did, dv.DidItems = strings.Join(did, ", "), did
	if !a.hasD {
		dv.Verdict = VerdictUnknown
		return dv
	}
	dv.Verdict = VerdictAsDeclared
	for k := range tried {
		if !a.d.HasManifest || !declares(a.d.Request, k) {
			dv.Verdict = VerdictUndeclared
		}
	}
	for k := range reached {
		if !a.d.HasManifest || !declares(a.d.Request, k) {
			dv.Verdict = VerdictUndeclared
		}
	}
	return dv
}

func triedWords(kind string, n int) string {
	switch kind {
	case activity.HintNetwork:
		return plural(n, "connect", "connects") + ", refused"
	case activity.HintWrite, activity.HintRead, activity.HintExec:
		return plural(n, kind, kind+"s") + ", refused"
	}
	return plural(n, "denial", "denials") + " reported"
}

func reachedWords(kind string) string {
	if kind == activity.HintNetwork {
		return "network reached"
	}
	return kind + " allowed"
}

// declares reports whether the request asks for the capability kind.
func declares(m manifest.Manifest, kind string) bool {
	switch kind {
	case activity.HintNetwork:
		return m.Network != manifest.NetNone
	case activity.HintWrite:
		return len(m.Filesystem.Write) > 0
	case activity.HintRead:
		return len(m.Filesystem.Read) > 0
	case activity.HintExec:
		return m.ExecAny || len(m.Exec) > 0
	}
	return false
}

func declaredText(d Declared, ok bool) string {
	switch {
	case !ok:
		return "not loaded"
	case !d.HasManifest:
		return "no manifest"
	}
	return strings.Join(requestedItems(d, ok), ", ")
}

// requestedItems is the request as short phrases: "net all", "write +1", "env +1".
func requestedItems(d Declared, ok bool) []string {
	if !ok {
		return []string{"not loaded"}
	}
	if !d.HasManifest {
		return []string{"no manifest"}
	}
	r := d.Request
	out := []string{"net " + r.Network.String()}
	if n := extra(r.Filesystem.Write, manifest.Default().Write); n > 0 {
		out = append(out, "write +"+strconv.Itoa(n))
	}
	if n := len(r.Filesystem.Read); n > 0 {
		out = append(out, "read +"+strconv.Itoa(n))
	}
	if n := extra(r.Env, manifest.Default().Env); n > 0 {
		out = append(out, "env +"+strconv.Itoa(n))
	}
	if n := len(r.Exec); n > 0 && !r.ExecAny {
		out = append(out, "exec "+strconv.Itoa(n)+" only")
	}
	return out
}

// grantedItems is the current grant: "net none", "cwd, tmp".
func grantedItems(e manifest.Effective) []string {
	out := []string{"net " + e.Network.String(), writeWords(e.Write)}
	if n := extra(e.Env, manifest.Default().Env); n > 0 {
		out = append(out, "env +"+strconv.Itoa(n))
	}
	return out
}

// viewItems is the policy a run ran under: "net none", "cwd, tmp", "env default".
func viewItems(v *manifest.View) []string {
	env := "env default"
	if n := extra(v.Env, manifest.Default().Env); n > 0 {
		env = "env +" + strconv.Itoa(n)
	}
	return []string{"net " + v.Network, writeWords(v.Write), env}
}

// writeWords names the symbolic write roots and counts the rest, so no
// absolute path is shown.
func writeWords(ws []string) string {
	var parts []string
	n := 0
	for _, w := range ws {
		switch w {
		case "${CWD}":
			parts = append(parts, "cwd")
		case "${TMP}":
			parts = append(parts, "tmp")
		default:
			n++
		}
	}
	if n > 0 {
		parts = append(parts, "+"+strconv.Itoa(n))
	}
	if len(parts) == 0 {
		return "no writes"
	}
	return strings.Join(parts, ", ")
}

func extra(xs, base []string) int {
	n := 0
	for _, x := range xs {
		if !contains(base, x) {
			n++
		}
	}
	return n
}

// skillSub is the line under a skill's shield; it agrees with the card.
func skillSub(d Declared, ok bool, ungranted []string) string {
	switch {
	case !ok:
		return "policy not loaded"
	case !d.HasManifest:
		return "no manifest · default"
	case d.Request.Network != manifest.NetNone:
		return fmt.Sprintf("asked net %s · granted %s", d.Request.Network, d.Granted.Network)
	case len(ungranted) > 0:
		return "asked " + shortItem(ungranted[0]) + " · not granted"
	}
	return "declared · all granted"
}

// shortItem turns "env: NAME" into "env NAME" and hides paths ("write +1").
func shortItem(item string) string {
	kind, rest, _ := strings.Cut(item, ": ")
	switch kind {
	case "write", "read", "exec":
		return kind + " +1"
	case "network":
		return "net " + rest
	}
	return kind + " " + rest
}

// fixFor turns the ungranted items that have a CLI form (network, write)
// into the `watchdeck allow` line and the grant body. Both are empty when
// the current grant covers them.
func fixFor(skill string, ungranted []string) (string, *Grant) {
	var e manifest.Edit
	g := &Grant{Skill: skill}
	for _, item := range ungranted {
		kind, rest, _ := strings.Cut(item, ": ")
		switch kind {
		case "network":
			if n, err := manifest.ParseNetwork(rest); err == nil && n != manifest.NetNone {
				e.Network = &n
				g.Network = n.String()
			}
		case "write":
			if rest != "" {
				e.AddWrite = append(e.AddWrite, rest)
				g.AddWrite = append(g.AddWrite, rest)
			}
		}
	}
	cmd, ok := manifest.AllowCommand(skill, e)
	if !ok {
		return "", nil
	}
	return cmd, g
}

// calledBy is "Main agent via Bash, once".
func (m *model) calledBy(a *skillAgg) string {
	calls := a.calls
	if len(calls) == 0 {
		calls = a.invokes
	}
	if len(calls) == 0 {
		if len(a.orphans) > 0 {
			return "caller unknown (no decision matched the run)"
		}
		return ""
	}
	var agents, tools []string
	for _, c := range calls {
		if l := m.agentLabel(c.agent); !contains(agents, l) {
			agents = append(agents, l)
		}
		if !contains(tools, c.tool) {
			tools = append(tools, c.tool)
		}
	}
	return strings.Join(agents, " and ") + " via " + strings.Join(tools, "/") + ", " + times(len(calls))
}

func times(n int) string {
	switch n {
	case 1:
		return "once"
	case 2:
		return "twice"
	}
	return strconv.Itoa(n) + " times"
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}

func fmtTS(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}
