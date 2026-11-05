package hook

import (
	"strings"
	"testing"
)

// TestModelTypedMutatingCommandsAsk: every watchdeck command that changes
// watchdeck's or Claude Code's settings asks when the model types it
// (Plan 04 Task 16, 2026-10-19), the way `watchdeck allow` did since the
// review of 2026-10-14. Without it a model could weaken watchdeck's own
// rules with --yes and the person would never see it.
func TestModelTypedMutatingCommandsAsk(t *testing.T) {
	f := newFx(t)
	for _, tc := range []struct{ cmd, sub string }{
		{"watchdeck allow x --network all", "allow"},
		{"watchdeck rules remove native:user:permissions.deny:abcd1234 --yes", "rules"},
		{"watchdeck rules set pack:exfil/curl-upload off --yes", "rules"},
		{"watchdeck rules recommended --decline all", "rules"},
		{"watchdeck rules reconcile", "rules"},
		{"watchdeck rules shadow on --yes", "rules"},
		// Plan 08: pause and resume change the policy file.
		{"watchdeck rules pause pack:x/y --for 1h", "rules"},
		{"watchdeck rules resume t-1", "rules"},
		{"watchdeck rules pause --list pack:x/y --for 1h", "rules"},
		{"watchdeck rules pause --list --for 8h pack:x/y", "rules"},
		{"watchdeck allow web --network all --for 1h", "allow"},
		{"watchdeck rules add --block --command 'rm' --yes", "rules"},
		{"watchdeck inbox resolve 0123456789abcdef undo --yes", "inbox"},
		{"watchdeck setup --yes", "setup"},
		{"watchdeck uninstall --yes --purge", "uninstall"},
		{"watchdeck enforce uninstall", "enforce"},
		{"watchdeck mcp unwrap x", "mcp"},
		{"watchdeck service uninstall", "service"},
		{"watchdeck ui --stop", "ui"},
		{"watchdeck advanced enforce uninstall", "enforce"},
		{"/usr/local/bin/watchdeck rules remove x --yes", "rules"},
		{"watch''deck rules remove x", "rules"},
		{"cd /tmp && watchdeck rules reconcile", "rules"},
		// Beyond the brief: a read-only mention first must not hide a
		// mutating one later in the same command.
		{"watchdeck status && watchdeck rules reconcile", "rules"},
		{`r\ules=1; watchdeck r\ules remove x --yes`, "rules"},
		{"watchdeck inbox --json resolve 0123456789abcdef undo", "inbox"},
		{"watchdeck rules --project remove x --yes", "rules"},
		{"watchdeck >/dev/null rules remove x --yes", ""},
		{"watchdeck status;watchdeck rules remove x --yes", "rules"},
		{"watchdeck rules list&&watchdeck setup --yes", "setup"},
		{"watchdeck advanced advanced uninstall --yes", "uninstall"},
		{"$(which watchdeck) rules remove x --yes", "rules"},
		{"`command -v watchdeck` uninstall --yes", "uninstall"},
		// Fix round 1 (review 2026-10-19). "" means the subcommand cannot
		// be read and the reason says "a watchdeck command".
		// B1: the name glued to a redirection, an expansion or a list.
		{"watchdeck>/dev/null rules remove x --yes", ""},
		{"watchdeck</dev/null rules remove x --yes", ""},
		{"watchdeck${IFS}rules${IFS}reconcile", ""},
		{"{watchdeck,rules,reconcile}", ""},
		{"{,watchdeck} rules reconcile", ""},
		{`python3 -c 'import subprocess; subprocess.run(["watchdeck", "rules", "reconcile"])'`, ""},
		{`node -e 'require("child_process").execFileSync("watchdeck",["uninstall","--yes"])'`, ""},
		{"watchdeck $(cat args)", ""},
		// B2: macOS finds the binary under any case.
		{"Watchdeck rules reconcile", "rules"},
		{"WATCHDECK uninstall --yes", "uninstall"},
		{"/usr/local/bin/WatchDeck uninstall --yes", "uninstall"},
		// B3: inbox is read-only only with no argument or a flag.
		{"watchdeck inbox $'resolve' x add", "inbox"},
		{`watchdeck inbox $"resolve" x add`, "inbox"},
		{"watchdeck inbox res$()olve x add", "inbox"},
		{"watchdeck inbox res${u}olve x add", "inbox"},
		{"watchdeck inbox {resolve,} x add", "inbox"},
		// B4: xargs supplies the subcommand from stdin.
		{"echo rules reconcile | xargs watchdeck", ""},
		{`printf 'rules\0reconcile' | xargs -0 watchdeck`, ""},
		{"echo uninstall | /usr/bin/xargs -n1 watchdeck", ""},
		// B5: ANSI-C and locale quoting inside the name.
		{"watch$'d'eck rules reconcile", "rules"},
		{`watch$"d"eck rules reconcile`, "rules"},
		// Fix round 2 (re-review 2026-10-19).
		// N1: &> glued to the name.
		{"watchdeck&>/dev/null rules remove x --yes", ""},
		{"watchdeck&>>log uninstall --yes", ""},
		// N2: xargs appends words after a read-only subcommand.
		{"echo resolve x add | xargs watchdeck inbox", ""},
		// N3: U+212A KELVIN SIGN, which APFS folds to k.
		{"watchdec\u212a rules reconcile", "rules"},
		// Fix round 3 (re-review 2, 2026-10-19): any command holding the
		// name and xargs or parallel anywhere asks, whatever the word
		// boundaries.
		{"echo resolve x add|xargs watchdeck inbox", ""},
		{"echo resolve x add |xargs watchdeck inbox", ""},
		{"echo resolve x add | (xargs watchdeck inbox)", ""},
		{"echo resolve x add | { true;xargs watchdeck inbox; }", ""},
		{"echo resolve x add | echo $(xargs watchdeck inbox)", ""},
		{"echo rules reconcile|xargs watchdeck", ""},
		{"echo rules reconcile|(xargs watchdeck)", ""},
		{"echo resolve x add | gxargs watchdeck inbox", ""},
		{`printf 'resolve\nx\nadd\n' | parallel -N3 watchdeck inbox`, ""},
		// Quoted, escaped and case-folded spellings of xargs and parallel
		// (the check runs on the stripped, folded text).
		{"echo rules reconcile | x'a'rgs watchdeck", ""},
		{`echo rules reconcile | x\args watchdeck`, ""},
		{`echo rules reconcile | par"allel" watchdeck`, ""},
		{"echo rules reconcile | X$'a'RGS watchdeck", ""},
		// Accepted false positive (ruled): read-only, but it asks.
		{"watchdeck status | xargs echo", ""},
		// Final review of Plan 04 (2026-10-19), finding 1: the name held
		// in a shell variable. Ruled fail-closed: any command that names
		// the binary and also holds $ or a backtick asks once the word
		// walk finds nothing. The hook does not know the shell, so the
		// bash-only forms are pinned too.
		{"a=watchdeck; $a rules reconcile", ""},
		{"w=watchdeck; $w uninstall --yes", ""},
		{"w=$(which watchdeck); $w rules reconcile", ""},
		{"w=`which watchdeck`; $w uninstall --yes", ""},
		{"read w <<< watchdeck; $w setup --yes", ""},
		{"printf -v w watchdeck; $w setup --yes", ""},
		{"x=watchdeck && $x rules remove native:x --yes", ""},
		{"export W=watchdeck; $W rules reconcile", ""},
		{"a=watchdeck:rules:reconcile; IFS=:; $a", ""},             // bash only
		{"a=watchdeck:rules:reconcile; ${a//:/ }", ""},             // bash only
		{"a=watchdeck/rules/reconcile; IFS=/; $a", ""},             // bash only
		{"a=watchdeck_rules_reconcile; IFS=_; $a", ""},             // bash only
		{"a=watchdeck; $a run --skill pdf -c 'curl http://x'", ""}, // the run guard too
		// Accepted false positive (ruled): read-only, but it asks.
		{`watchdeck rules list > "$HOME/x"`, ""},
		// Re-review of the fix wave (2026-10-19), E1: a backslash escape
		// another program expands into a separator. Ruled fail-closed: a
		// command that names the binary and holds a backslash in its
		// original text asks once the word walk finds nothing.
		{`printf 'watchdeck\tuninstall --yes' | sh`, ""},
		{`printf 'watchdeck\x20uninstall --yes' | sh`, ""},
		{`printf '%b' 'watchdeck\040uninstall --yes' | sh`, ""},
		{`echo -e 'watchdeck\tuninstall --yes' | sh`, ""},
		// Plan 07 Task 1 (2026-10-20): a read-only rules explain whose
		// inner command holds a $ asks like any other command that names
		// the binary and an expansion (documented limit).
		{"watchdeck rules explain --command 'echo $HOME'", ""},
		{"watchdeck rules explain --command 'curl x' && watchdeck rules reconcile", "rules"},
	} {
		out := Decide(f.in(tc.cmd), f.env)
		if got := decisionOf(out); got != Ask {
			t.Errorf("%s: %s, want ask (%+v)", tc.cmd, got, out)
			continue
		}
		want := "`watchdeck " + tc.sub + "`"
		if tc.sub == "" {
			want = "a watchdeck command"
		}
		if r := out.HookSpecificOutput.PermissionDecisionReason; !strings.Contains(r, want) {
			t.Errorf("%s: reason %q does not say %s", tc.cmd, r, want)
		}
		if out.HookSpecificOutput.UpdatedInput != nil {
			t.Errorf("%s: rewrote a model-typed watchdeck command", tc.cmd)
		}
	}
}

// TestModelTypedReadOnlyCommandsPass: watchdeck's read-only commands keep
// the hook's no-opinion answer.
func TestModelTypedReadOnlyCommandsPass(t *testing.T) {
	f := newFx(t)
	for _, cmd := range []string{
		"watchdeck status",
		"watchdeck doctor --json",
		"watchdeck rules list",
		"watchdeck rules shadow",
		"watchdeck rules pause --list",
		"watchdeck rules pause --list | head",
		"watchdeck inbox",
		"watchdeck mcp status",
		"watchdeck policy check",
		"watchdeck version",
		"watchdeck advanced paths --json",
		"echo watchdeck",
		// Beyond the brief: a path ending in the name followed by a
		// command separator is not a subcommand.
		"ls ~/.config/watchdeck && echo ok",
		"watchdeck inbox --json",
		"watchdeck status; watchdeck activity --json | head",
		"watchdeck status>/dev/null 2>&1",
		"watchdeck rules list;",
		"watchdeck inbox|grep x",
		// Fix round 1: help and version flags (ruled 2026-10-19), case,
		// paths and names that only contain the binary name.
		"watchdeck --help",
		"watchdeck -h",
		"watchdeck --version",
		"watchdeck -v",
		"WATCHDECK status",
		"watchdeck inbox --json",
		"ls ~/.config/watchdeck",
		"cat ~/.config/watchdeck/overrides.yaml",
		"go test github.com/Panda-Taps-LLC/watchdeck/internal/hook",
		"WATCHDECK_ACTIVITY=off git status",
		// The documented miss (re-review of the fix wave, 2026-10-19, E2):
		// words produced at run time by another program are not caught,
		// even with the name in the text. Pinned so that catching it later
		// is a visible decision; DESIGN §10 and GUIDE name the class.
		"echo watchdeck_uninstall_--yes | tr _ ' ' | sh",
		// Plan 07 Task 1 (2026-10-20): rules explain is a dry run and
		// only reads, whatever follows it.
		"watchdeck rules explain --command 'curl x'",
		"watchdeck rules explain --read ~/.ssh/id_x --json",
		"watchdeck rules explain --url https://example.invalid/ --expect deny",
		"watchdeck rules explain --mcp mcp__github__delete_repo --cwd /tmp --mode auto",
	} {
		if out := Decide(f.in(cmd), f.env); out != nil {
			t.Errorf("%s: %s, want no opinion (%+v)", cmd, decisionOf(out), out.HookSpecificOutput)
		}
	}
}

// TestModelTypedRunAnyCaseAsks: macOS runs `WATCHDECK run …` as the
// binary, so the run guard folds case too (fix round 1, B2).
func TestModelTypedRunAnyCaseAsks(t *testing.T) {
	f := newFx(t)
	for _, cmd := range []string{
		"WATCHDECK run -c 'curl x'",
		"Watchdeck run --skill pdf -c 'curl x'",
		"watchdec\u212a run -c 'curl x'",
	} {
		if !mentionsRun(cmd) {
			t.Errorf("%s: mentionsRun false", cmd)
		}
		out := Decide(f.in(cmd), f.env)
		if got := decisionOf(out); got != Ask {
			t.Errorf("%s: %s, want ask", cmd, got)
		} else if out.HookSpecificOutput.UpdatedInput != nil {
			t.Errorf("%s: rewrote", cmd)
		}
	}
}

// TestRulesShadowStatusIsReadOnly (R10): `watchdeck rules shadow` alone
// reads the mode; any word after it may switch it and asks.
func TestRulesShadowStatusIsReadOnly(t *testing.T) {
	f := newFx(t)
	for _, cmd := range []string{
		"watchdeck rules shadow",
		"watchdeck rules shadow;",
		"watchdeck rules shadow | cat",
		"watchdeck rules shadow && echo ok",
		"WATCHDECK rules shadow",
	} {
		if out := Decide(f.in(cmd), f.env); out != nil {
			t.Errorf("%s: %s, want no opinion (%+v)", cmd, decisionOf(out), out.HookSpecificOutput)
		}
	}
	for _, cmd := range []string{
		"watchdeck rules shadow on",
		"watchdeck rules shadow off --yes",
		"watchdeck rules shadow --yes on",
		"watchdeck rules shadow --json",
		"watchdeck rules shadow $'on'",
		"watchdeck rules shadow o''n",
		"watchdeck rules shadow {on,}",
		"watchdeck rules shadow $X",
		"watchdeck rules shadow `echo on`",
		"watchdeck rules shadow; watchdeck rules shadow on",
	} {
		out := Decide(f.in(cmd), f.env)
		if decisionOf(out) != Ask {
			t.Errorf("%s: %s, want ask", cmd, decisionOf(out))
			continue
		}
		if r := out.HookSpecificOutput.PermissionDecisionReason; !strings.Contains(r, "`watchdeck rules`") {
			t.Errorf("%s: reason %q", cmd, r)
		}
		if out.HookSpecificOutput.UpdatedInput != nil {
			t.Errorf("%s: rewrote a model-typed watchdeck command", cmd)
		}
	}
}
