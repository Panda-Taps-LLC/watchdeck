package mapmodel

import (
	"strconv"
	"strings"

	"github.com/Panda-Taps-LLC/watchdeck/internal/activity"
)

// Policies, one per tool call (§3.3).
const (
	PolicyAllow = "allow"
	PolicyAsk   = "ask"
	PolicyDeny  = "deny"
	PolicyNone  = "none"
)

// Evidence sources, as the card names them.
const (
	EvidenceDenied     = "denied"          // an auto-mode denial record (PermissionDenied)
	EvidenceRun        = "run"             // the run's outcome (exit status; 125/126/3 are denials)
	EvidenceHint       = "hint"            // the run's denial hints (stdout/stderr, heuristic)
	EvidenceResultText = "result_text"     // the transcript's Bash result text
	EvidenceHook       = "hook_attachment" // the transcript's hook_success row (no activity decision)
)

// Authorities: who decided a call. Policy (above) is what watchdeck's own
// evidence says; authority names the party that answered, read first from
// the transcript's permission verdict (permissionDecision, toolDenialKind,
// the denied-read error text), then from watchdeck's records.
const (
	AuthorityDenyRule   = "deny_rule"  // native permissions.deny
	AuthorityClassifier = "classifier" // auto-mode block
	AuthorityAuto       = "auto"       // auto-mode accept (classifier passed)
	AuthorityAllowRule  = "allow_rule" // native allow rule or read-only auto-approval
	AuthorityUser       = "user"       // the person answered a prompt (accept or reject)
	AuthorityHook       = "hook"       // watchdeck's hook decided (deny, ask, rewrite)
	AuthoritySandbox    = "sandbox"    // the OS sandbox refused something at run time
	AuthorityBlocked    = "blocked"    // an unrecognised reject, or an error with no decision fields that is not "Exit code N"
	AuthorityNone       = "none"       // nobody spoke
)

// deniedBySettings is Claude Code's error text for a file tool blocked by a
// permissions.deny rule; that result row carries no decision fields
// (e2e-deny fixture, captured 2026-10-19 UTC).
const deniedBySettings = "denied by your permission settings"

// verdict is what policy did to one call. The gate is the hook's decision
// (the tool→skill edge); the sandbox stage is what happened when the script
// ran (the skill→sandbox edge).
type verdict struct {
	policy string // allow | ask | deny | none
	// observed is shadow mode's "observed: would deny|ask" (Plan 06), ""
	// for an enforced call; observe also puts it in gate.
	observed  string
	authority string // Authority*: who decided the call
	// authRejected: authorityOf's rejected flag (refused before anything
	// ran, as that authority reported it). totals reads it for a person's
	// "No" and an unrecognised rejection.
	authRejected bool

	decision    string // the gate's decision: allow | ask | deny | ""
	decisionSrc string // "activity" | EvidenceHook | ""
	gate        string // badge on the tool→skill edge: allow, ask ✓, ask ✗, ask …, ask (unsandboxed), ask, BLOCKED <reason>
	gatePolicy  string
	gateTone    string

	unsandboxed bool // asked without a rewrite: if approved it ran unconfined
	rejected    bool // asked, the user declined, nothing ran
	pending     bool // asked, live, no answer yet
	approved    bool // asked and it went ahead
	// approvalInferred: approved is read from a Bash result that is not a
	// rejection, with no joined run record to prove the script ran.
	approvalInferred bool
	blocked          bool // refused before running

	ran         bool // the script ran under the sandbox
	ranInferred bool // ran, known from the transcript only (no run record)
	out         string
	outTone     string // deny | ok | grey
	sandboxDeny bool
	exit        *int
	evidence    string
	stream      string // the winning hint's stream (stdout | stderr) when evidence is "hint"

	tried   []string // capability kinds the script reported refused (hints, result markers)
	reached []string // capability kinds the script reported allowed (result markers)
}

// toneOf maps a policy to a badge tone.
func toneOf(policy string) string {
	switch policy {
	case PolicyAllow:
		return "ok"
	case PolicyAsk:
		return "ask"
	case PolicyDeny:
		return "deny"
	}
	return "none"
}

// judge applies the one precedence of §3.3 and the cross-phase decision 3:
// deny when a denied record exists, or the joined run has any hint (whatever
// its exit), or the run's outcome is policy_error, no_sandbox or usage; then
// the transcript's Bash result text; otherwise the decision (the activity
// record, else the transcript's hook attachment); otherwise none.
func judge(c *call, live bool) verdict {
	v := judgeEnforced(c, live)
	observe(&v, c)
	return v
}

// observe adds shadow mode's label (Plan 06): a verdict a rule would have
// given and did not enforce. A call nothing else labelled gets
// "observed: would deny|ask" in grey; a call with its own label (the
// sandbox stage's ask or allow) gets it after " · ". It never sets a
// policy, so the policy ring, the totals and BlockedCalls do not move.
func observe(v *verdict, c *call) {
	if c.dec == nil || !c.dec.Shadow || c.dec.Would == "" {
		return
	}
	v.observed = "observed: would " + c.dec.Would
	if v.gate == "" {
		v.gate, v.gateTone = v.observed, "grey"
		return
	}
	v.gate += " · " + v.observed
}

// judgeEnforced is judge without shadow mode's label: what was enforced.
func judgeEnforced(c *call, live bool) verdict {
	var v verdict
	var rewritten, reason string
	switch {
	case c.dec != nil:
		v.decision, v.decisionSrc, rewritten, reason = c.dec.Decision, "activity", c.dec.Rewritten, c.dec.Reason
	case c.hookDecision != "":
		v.decision, v.decisionSrc, rewritten, reason = c.hookDecision, EvidenceHook, c.hookRewrite, c.hookReason
	}

	authority, rej := authorityOf(c)
	v.authority, v.authRejected = authority, rej

	// 1. Refused before running.
	if c.denied != nil || v.decision == PolicyDeny {
		v.blocked, v.policy, v.gatePolicy, v.gateTone = true, PolicyDeny, PolicyDeny, "deny"
		if c.denied != nil {
			v.gate, v.evidence = "BLOCKED "+blockedWhat(c.denied.Reason), EvidenceDenied
		} else {
			v.gate, v.evidence = "BLOCKED "+blockedWhat(reason), v.decisionSrc
		}
		return v
	}

	// 2. The gate. The transcript's verdict says whether the call was
	// rejected; the result-text guess is the fallback when it has none.
	rejected := c.run == nil && rej
	answered := c.run != nil || c.res != nil
	switch v.decision {
	case PolicyAsk:
		v.gatePolicy, v.gateTone = PolicyAsk, "ask"
		v.unsandboxed = rewritten == ""
		switch {
		case rejected:
			v.rejected, v.gate = true, "ask ✗"
		case !answered && live:
			v.pending, v.gate = true, "ask …"
		case v.unsandboxed:
			v.approved, v.gate = answered, "ask (unsandboxed)"
			v.approvalInferred = answered && c.run == nil
		case c.run != nil:
			v.approved, v.gate = true, "ask ✓"
		case answered:
			v.approved, v.approvalInferred, v.gate = true, true, "ask ✓ (inferred)"
		default:
			v.gate = "ask"
		}
	case PolicyAllow:
		v.gatePolicy, v.gateTone, v.gate = PolicyAllow, "ok", "allow"
		v.unsandboxed = rewritten == "" && c.run == nil
	}

	// 3. The sandbox stage: a joined run; or, when the activity log has no
	// decision for the call (only the transcript's hook attachment), a
	// rewritten call whose result came back: it ran sandboxed and the log
	// did not see it. An activity decision without a joined run is not
	// inferred to have run (the run may belong to another decision).
	switch {
	case c.run != nil:
		v.ran = true
	case v.decisionSrc == EvidenceHook && rewritten != "" && c.res != nil && !rejected:
		v.ran, v.ranInferred = true, true
	}
	if v.ran {
		sandboxStage(&v, c.run, c.res, rejected)
	}

	switch {
	case v.sandboxDeny:
		v.policy = PolicyDeny
	case v.gatePolicy != "":
		v.policy = v.gatePolicy
	default:
		v.policy = PolicyNone
	}
	if v.evidence == "" {
		switch {
		case v.ran && !v.ranInferred:
			v.evidence = EvidenceRun
		case v.decisionSrc == EvidenceHook:
			v.evidence = EvidenceHook
		}
	}
	return v
}

// sandboxStage fills the run's outcome and the denial evidence.
func sandboxStage(v *verdict, run *activity.Record, res *resultView, rejected bool) {
	if run != nil {
		v.exit = run.Exit
		switch run.Outcome {
		case activity.OutcomeNoSandbox:
			v.deny("NOT SANDBOXED exit "+exitOr(run.Exit, 126), EvidenceRun)
		case activity.OutcomePolicyError:
			v.deny("POLICY ERROR exit "+exitOr(run.Exit, 125), EvidenceRun)
		case activity.OutcomeUsage:
			v.deny("USAGE ERROR exit "+exitOr(run.Exit, 3), EvidenceRun)
		}
		for _, h := range run.Hints {
			v.tried = addKind(v.tried, runHintKind(h))
		}
		if len(run.Hints) > 0 {
			h := badgeHint(run.Hints)
			label := "DENIED"
			if k := runHintKind(h); k != activity.HintUnknown {
				label += " " + k
			}
			v.deny(label, EvidenceHint)
			if v.evidence == EvidenceHint {
				v.stream = h.Stream
			}
		}
	}
	if res != nil && !rejected {
		label, tried, reached := scanResult(res.text)
		for _, k := range tried {
			v.tried = addKind(v.tried, k)
		}
		for _, k := range reached {
			v.reached = addKind(v.reached, k)
		}
		if label != "" {
			v.deny(label, EvidenceResultText)
		}
	}
	if v.sandboxDeny {
		return
	}
	switch {
	case run == nil:
		v.out, v.outTone = "ran", "ok"
	case run.Outcome == activity.OutcomeOK:
		v.out, v.outTone = "exit 0", "ok"
	case run.Outcome == activity.OutcomeSignaled:
		v.out, v.outTone = "signaled", "grey"
		if run.Exit != nil {
			v.out = "signaled exit " + strconv.Itoa(*run.Exit)
		}
	default:
		v.out, v.outTone = "exit "+exitOr(run.Exit, -1), "grey"
	}
}

// deny records the first (highest-ranked) denial; later sources only add
// to tried/reached.
func (v *verdict) deny(label, evidence string) {
	if v.sandboxDeny {
		return
	}
	v.sandboxDeny, v.out, v.outTone, v.evidence = true, label, "deny", evidence
}

func exitOr(p *int, d int) string {
	if p != nil {
		return strconv.Itoa(*p)
	}
	if d < 0 {
		return "?"
	}
	return strconv.Itoa(d)
}

func addKind(list []string, k string) []string {
	for _, x := range list {
		if x == k {
			return list
		}
	}
	return append(list, k)
}

// hintKind is the badge word for a hint kind (the shared vocabulary).
func hintKind(k string) string {
	switch k {
	case activity.HintNetwork, activity.HintWrite, activity.HintRead, activity.HintExec:
		return k
	}
	return activity.HintUnknown
}

// runHintKind is a run hint's capability: its kind, or, when the scanner
// could not tell, the kind its probe label names.
func runHintKind(h activity.Hint) string {
	k := hintKind(h.Kind)
	if k == activity.HintUnknown && h.Label != "" {
		k = probeKind(h.Label)
	}
	return k
}

// badgeHint is the hint the edge badge names: the first one that carries a
// probe label or a known kind, else the first.
func badgeHint(hs []activity.Hint) activity.Hint {
	for _, h := range hs {
		if h.Label != "" || runHintKind(h) != activity.HintUnknown {
			return h
		}
	}
	return hs[0]
}

// probeKind maps a canary probe label to a capability (mirrors
// runner.labelKind; runner is not imported to keep this package small).
func probeKind(label string) string {
	switch {
	case label == "net" || label == "localhost":
		return activity.HintNetwork
	case strings.HasPrefix(label, "write-"):
		return activity.HintWrite
	case strings.HasPrefix(label, "read-"):
		return activity.HintRead
	case label == "subprocess":
		return activity.HintExec
	}
	return activity.HintUnknown
}

// scanResult reads a Bash result snippet for the probe markers
// "<label>: DENIED(<n>)" and "<label>: ALLOWED", and for the generic denial
// texts. label is the first denial's badge ("" when none).
func scanResult(text string) (label string, tried, reached []string) {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		name, rest, ok := strings.Cut(line, ": ")
		if !ok || !probeLabel(name) {
			continue
		}
		k := probeKind(name)
		switch {
		case strings.HasPrefix(rest, "DENIED("):
			tried = addKind(tried, k)
			if label == "" {
				if k == activity.HintUnknown {
					label = "DENIED (script reported)"
				} else {
					label = "DENIED " + k
				}
			}
		case rest == "ALLOWED":
			reached = addKind(reached, k)
		}
	}
	if label == "" {
		for _, s := range []string{"DENIED(", "Operation not permitted", "EPERM", "[Errno 1]"} {
			if strings.Contains(text, s) {
				label = "DENIED (script reported)"
				tried = addKind(tried, activity.HintUnknown)
				break
			}
		}
	}
	return label, tried, reached
}

func probeLabel(s string) bool {
	if s == "" || len(s) > 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// authorityOf names who decided a call, first match wins: a sandbox
// refusal on the run; an auto-mode denial record; watchdeck's hook (deny,
// ask, or a rewrite); then the transcript's verdict (deny rule, classifier
// block, the person, allow rule, classifier accept); then a denied-read
// error text; then an error on a call with no decision fields at all
// that is not an ordinary failed command ("Exit code N"): blocked, reason
// unknown; else none. rejected reports a refusal before anything ran: the
// transcript's reject, a deny rule or classifier block, a hook deny, or,
// only when the transcript recorded no verdict, a result text that reads as
// the person's "no".
func authorityOf(c *call) (authority string, rejected bool) {
	a := c.authority
	decision, rewrite := c.hookDecision, c.hookRewrite
	if c.dec != nil {
		decision, rewrite = c.dec.Decision, c.dec.Rewritten
	}
	rej := a.Rejected()
	if !a.Known() {
		rej = isRejection(c)
	}
	refused := c.denied != nil || decision == PolicyDeny
	switch {
	case !refused && sandboxRefused(c, decision, rewrite, rej):
		return AuthoritySandbox, false
	case c.denied != nil:
		return AuthorityClassifier, true
	case decision == PolicyDeny:
		return AuthorityHook, true
	case decision == PolicyAsk || (decision != "" && rewrite != ""):
		return AuthorityHook, rej
	case a.Rejected() && (a.DenialKind == "permission-rule" || a.ReasonType == "subcommandResults"):
		return AuthorityDenyRule, true
	case a.Rejected() && (a.DenialKind == "automode-blocked" || a.ReasonType == "classifier"):
		return AuthorityClassifier, true
	case a.Source == "user":
		return AuthorityUser, rej
	case a.Decision == "accept" && a.ReasonType == "rule":
		return AuthorityAllowRule, false
	case a.Decision == "accept" && a.ReasonType == "classifier":
		return AuthorityAuto, false
	case a.Source == "hook":
		// A hook answered and watchdeck has no decision for the call.
		return AuthorityHook, rej
	case a.Rejected():
		// A rejection this reader does not recognise: never "none".
		return AuthorityBlocked, true
	case c.res != nil && c.res.isError && strings.Contains(c.errText, deniedBySettings):
		return AuthorityDenyRule, true
	case !a.Known() && c.res != nil && c.res.isError && !strings.HasPrefix(c.errText, "Exit code"):
		// No decision fields at all, and not an ordinary failed command
		// (Claude Code starts those with "Exit code N").
		return AuthorityBlocked, rej
	}
	return AuthorityNone, false
}

// sandboxRefused reports whether the call's script ran under the sandbox
// and the sandbox stage found a denial (the same evidence judge's sandbox
// stage reads: the run's outcome and hints, then the result text).
func sandboxRefused(c *call, decision, rewrite string, rejected bool) bool {
	ran := c.run != nil
	if !ran && c.dec == nil && decision != "" && rewrite != "" && c.res != nil && !rejected {
		ran = true // the transcript's hook rewrite came back: it ran, the log did not see it
	}
	if !ran {
		return false
	}
	var v verdict
	sandboxStage(&v, c.run, c.res, c.run == nil && rejected)
	return v.sandboxDeny
}

// isRejection reports a user's "no" to an ask: the Bash result is an error
// that says the user declined. The exact wording is unverified (Spec B V20);
// this matches Claude Code's "The user doesn't want to proceed with this
// tool use. The tool use was rejected ..." and close variants.
func isRejection(c *call) bool {
	if c.res == nil || !c.res.isError {
		return false
	}
	t := strings.ToLower(c.res.text)
	if !strings.Contains(t, "user") {
		return false
	}
	return strings.Contains(t, "reject") || strings.Contains(t, "doesn't want") || strings.Contains(t, "does not want") || strings.Contains(t, "declin")
}

// blockedWhat is the reason word after BLOCKED: the first line, short.
func blockedWhat(reason string) string {
	reason = strings.TrimSpace(reason)
	if i := strings.IndexByte(reason, '\n'); i >= 0 {
		reason = strings.TrimSpace(reason[:i])
	}
	if reason == "" {
		return "by auto mode"
	}
	return clip(reason, 60)
}

// clip cuts s to at most n runes, adding "…" when it cut.
func clip(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

// judgeAll computes every call's verdict.
func (m *model) judgeAll() {
	for _, c := range m.calls {
		c.v = judge(c, m.live)
	}
}
