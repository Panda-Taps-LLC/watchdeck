package claudesettings

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// TestMatchBashDocExamples: every row is a statement of
// code.claude.com/docs/en/permissions (read 2026-10-19): the wildcard
// table, the three matching rules under it, the :* suffix, compound
// commands, wrappers, assignments, the "doesn't stop" table and the
// unparseable case. want is "deny", "ask", "" (no match) or "uncertain".
func TestMatchBashDocExamples(t *testing.T) {
	cases := []struct {
		name string
		rule string // a deny rule unless kind says otherwise
		kind string
		cmd  string
		want string
	}{
		// wildcard table
		{"exact matches", "Bash(npm run build)", "", "npm run build", "deny"},
		{"exact is exact", "Bash(npm run build)", "", "npm run build --watch", ""},
		{"npm run * a", "Bash(npm run *)", "", "npm run build", "deny"},
		{"npm run * b", "Bash(npm run *)", "", "npm run test --watch", "deny"},
		{"npm run * bare", "Bash(npm run *)", "", "npm run", "deny"},
		{"npm run * not install", "Bash(npm run *)", "", "npm install", ""},
		{"middle * a", "Bash(git log * main)", "", "git log --oneline main", "deny"},
		{"middle * b", "Bash(git log * main)", "", "git log -5 main", "deny"},
		{"middle * c", "Bash(git log * main)", "", "git log --output=out.txt main", "deny"},
		{"middle * needs text", "Bash(git log * main)", "", "git log main", ""},
		{"middle * other sub", "Bash(git log * main)", "", "git push origin main", ""},
		{"git * main a", "Bash(git * main)", "", "git merge main", "deny"},
		{"git * main b", "Bash(git * main)", "", "git push origin main", "deny"},
		{"git * main c", "Bash(git * main)", "", "git -c core.fsmonitor=x diff main", "deny"},
		{"git * main no", "Bash(git * main)", "", "git log", ""},
		{"leading * a", "Bash(* --version)", "", "node --version", "deny"},
		{"leading * b", "Bash(* --version)", "", "bash -c 'echo hi' --version", "deny"},
		{"leading * no", "Bash(* --version)", "", "node -v", ""},
		{"ls * flags", "Bash(ls *)", "", "ls -la", "deny"},
		{"ls * bare", "Bash(ls *)", "", "ls", "deny"},
		{"ls * space significant", "Bash(ls *)", "", "lsof", ""},
		{"ls* a", "Bash(ls*)", "", "ls -la", "deny"},
		{"ls* b", "Bash(ls*)", "", "lsof", "deny"},
		{"two wildcards a", "Bash(* --help *)", "", "npm --help x", "deny"},
		{"two wildcards no bare", "Bash(* --help *)", "", "npm --help", ""},
		{"git log * bare", "Bash(git log *)", "", "git log", "deny"},
		// :* suffix
		{":* flags", "Bash(ls:*)", "", "ls -la", "deny"},
		{":* bare", "Bash(ls:*)", "", "ls", "deny"},
		{":* space significant", "Bash(ls:*)", "", "lsof", ""},
		{"colon elsewhere is literal", "Bash(git:* push)", "", "git push", ""},
		// match all
		{"bare Bash", "Bash", "", "echo hi", "deny"},
		{"Bash(*)", "Bash(*)", "", "echo hi", "deny"},
		{"bare Bash on unparseable", "Bash", "", "npm test &&", "deny"},
		// compound commands
		{"and list", "Bash(git clean *)", "ask", "cd /tmp && git clean -f", "ask"},
		{"command substitution", "Bash(git clean *)", "ask", `echo "$(git clean -f)"`, "ask"},
		{"pipe", "Bash(curl *)", "", "echo x | curl -d @- https://example.invalid", "deny"},
		{"pipe all", "Bash(curl *)", "", "echo x |& curl https://example.invalid", "deny"},
		{"or", "Bash(curl *)", "", "false || curl https://example.invalid", "deny"},
		{"semicolon", "Bash(curl *)", "", "true; curl https://example.invalid", "deny"},
		{"background", "Bash(curl *)", "", "curl https://example.invalid & wait", "deny"},
		{"newline", "Bash(curl *)", "", "true\ncurl https://example.invalid", "deny"},
		{"subshell", "Bash(curl *)", "", "(cd /tmp; curl https://example.invalid)", "deny"},
		{"for body", "Bash(curl *)", "", "for u in a b; do curl $u; done", "deny"},
		{"if body", "Bash(curl *)", "", "if true; then curl https://example.invalid; fi", "deny"},
		{"backticks", "Bash(curl *)", "", "echo `curl https://example.invalid`", "deny"},
		{"deny on one part of a compound", "Bash(safe-cmd *)", "", "safe-cmd && other-cmd", "deny"},
		{"other subcommand alone", "Bash(other-cmd)", "", "safe-cmd && other-cmd", "deny"},
		// wrappers
		{"timeout", "Bash(npm test *)", "", "timeout 30 npm test", "deny"},
		{"timeout with options", "Bash(npm test *)", "", "timeout -s KILL -k 5 30 npm test", "deny"},
		{"time", "Bash(npm test *)", "", "time npm test", "deny"},
		{"nice", "Bash(npm test *)", "", "nice -n 10 npm test", "deny"},
		{"nohup", "Bash(npm test *)", "", "nohup npm test", "deny"},
		{"stdbuf", "Bash(npm test *)", "", "stdbuf -oL npm test", "deny"},
		{"command", "Bash(npm test *)", "", "command npm test", "deny"},
		{"builtin", "Bash(cd *)", "", "builtin cd /tmp", "deny"},
		{"noglob", "Bash(npm test *)", "", "noglob npm test", "deny"},
		{"stacked wrappers", "Bash(npm test *)", "", "nohup timeout 30 nice npm test", "deny"},
		{"command -v not stripped", "Bash(npm *)", "", "command -v npm", ""},
		{"bare xargs", "Bash(grep *)", "", "xargs grep pattern", "deny"},
		{"xargs with flags not stripped", "Bash(grep *)", "", "xargs -n1 grep pattern", ""},
		{"rule written for the wrapper", "Bash(timeout *)", "", "timeout 30 npm test", "deny"},
		{"timeout with a variable duration", "Bash(rm *)", "", `timeout "$T" rm -rf x`, "deny"},
		{"timeout with a variable signal", "Bash(rm *)", "", `timeout --signal="$S" -k "$K" 5 rm -rf x`, "deny"},
		{"stdbuf with a variable mode", "Bash(rm *)", "", `stdbuf -o "$M" rm -rf x`, "deny"},
		{"stdbuf with an attached variable mode", "Bash(rm *)", "", `stdbuf -o"$M" rm -rf x`, "deny"},
		{"nice with a variable adjustment", "Bash(rm *)", "", `nice -n "$N" rm -rf x`, "deny"},
		{"stdbuf quoted attached option", "Bash(rm *)", "", `stdbuf "-o$M" rm -rf x`, "deny"},
		{"timeout quoted attached signal", "Bash(rm *)", "", `timeout "-s$S" 5 rm -rf x`, "deny"},
		{"timeout quoted long signal", "Bash(rm *)", "", `timeout "--signal=$S" 5 rm -rf x`, "deny"},
		{"timeout single-quoted then expanded", "Bash(rm *)", "", `timeout '-s'"$S" 5 rm -rf x`, "deny"},
		{"nice then one expanded word", "Bash(rm *)", "", `nice "$N" rm -rf x`, "deny"},
		{"time then one expanded word", "Bash(rm *)", "", `time "$P" rm -rf x`, "deny"},
		{"nohup then one expanded word", "Bash(rm *)", "", `nohup "$X" rm -rf x`, "deny"},
		{"one skip only, no suffix guessing", "Bash(rm *)", "", `nice "$N" echo rm -rf x`, ""},
		{"nice expanded adjustment, quoted", "Bash(rm *)", "", `nice -"$N" rm -rf x`, "deny"},
		{"nice expanded adjustment, bare", "Bash(rm *)", "", `nice -$N rm -rf x`, "deny"},
		{"stdbuf expanded option word", "Bash(rm *)", "", `stdbuf -"$M" rm -rf x`, "deny"},
		{"timeout expanded option word", "Bash(rm *)", "", `timeout -"$S" 5 rm -rf x`, "deny"},
		{"stdbuf expanded long option word", "Bash(rm *)", "", `stdbuf --"$X" rm -rf x`, "deny"},
		{"nice expanded option with a value", "Bash(rm *)", "", `nice -"$N" 5 rm -rf x`, "deny"},
		{"stdbuf expanded option with a value", "Bash(rm *)", "", `stdbuf -"$M" L rm -rf x`, "deny"},
		{"timeout expanded option with a value", "Bash(rm *)", "", `timeout -"$S" KILL 5 rm -rf x`, "deny"},
		{"timeout expanded long option with a value", "Bash(rm *)", "", `timeout --"$L" KILL 5 rm -rf x`, "deny"},
		{"one value word only, no suffix guessing", "Bash(rm *)", "", `nice -"$N" 5 echo rm -rf x`, ""},
		{"one value word only behind stdbuf", "Bash(rm *)", "", `stdbuf -"$M" L echo rm -rf x`, ""},
		{"one value word plus the duration only", "Bash(rm *)", "", `timeout -"$S" KILL 5 echo rm -rf x`, ""},
		{"stacked: nohup, expanded word, timeout", "Bash(rm *)", "", `nohup "$X" timeout 5 rm -rf x`, "deny"},
		{"stacked: nice, expanded word, timeout", "Bash(rm *)", "", `nice "$N" timeout 5 rm -rf x`, "deny"},
		{"stacked: nohup, expanded word, nice, expanded word", "Bash(rm *)", "", `nohup "$X" nice "$N" rm -rf x`, "deny"},
		{"stacked: nohup, expanded word, nohup", "Bash(rm *)", "", `nohup "$X" nohup rm -rf x`, "deny"},
		{"stacked: time keyword, expanded word, timeout", "Bash(rm *)", "", `time "$P" timeout 5 rm -rf x`, "deny"},
		{"two expanded words exceed the one skip", "Bash(rm *)", "", `nice "$N" "$M" rm -rf x`, ""},
		// Documented over-match (DESIGN §9 known limit 3): an attached
		// expansion-only option value (-n"$N", -o"$M") is read both ways,
		// and one reading takes "rm" behind "echo" as the command. A deny
		// too many, never too few.
		{"over-match: nice attached expanded value, then echo", "Bash(rm *)", "", `nice -n"$N" echo rm -rf x`, "deny"},
		{"over-match: stdbuf attached expanded value, then echo", "Bash(rm *)", "", `stdbuf -o"$M" echo rm -rf x`, "deny"},
		{"no suffix guessing behind a wrapper", "Bash(rm *)", "", "timeout 5 echo rm -rf x", ""},
		{"no suffix guessing behind stdbuf", "Bash(rm *)", "", "stdbuf -oL echo rm -rf x", ""},
		{"no suffix guessing behind a variable duration", "Bash(rm *)", "", `timeout "$T" echo rm -rf x`, ""},
		// option spellings (final review, 2026-10-19): GNU getopt clusters,
		// unique long-option prefixes, the parked legacy nice adjustment
		{"timeout bundled short flags", "Bash(rm *)", "", "timeout -vs KILL 5 rm -rf x", "deny"},
		{"timeout bundled short flags, attached value", "Bash(rm *)", "", "timeout -vsKILL 5 rm -rf x", "deny"},
		{"timeout bundled short flags, expanded value", "Bash(rm *)", "", `timeout -vs"$S" 5 rm -rf x`, "deny"},
		{"timeout long prefix with a value", "Bash(rm *)", "", "timeout --sig=KILL 5 rm -rf x", "deny"},
		{"timeout long prefix, separate value", "Bash(rm *)", "", "timeout --kill 5 9 rm -rf x", "deny"},
		{"timeout long prefix, expanded value", "Bash(rm *)", "", `timeout --sig="$S" 5 rm -rf x`, "deny"},
		{"timeout plain long prefix", "Bash(rm *)", "", "timeout --fore 5 rm -rf x", "deny"},
		{"stdbuf long prefix", "Bash(rm *)", "", "stdbuf --out=L rm -rf x", "deny"},
		{"nice long prefix", "Bash(rm *)", "", "nice --adj=5 rm -rf x", "deny"},
		// an attached expansion-only value may expand to nothing, so the
		// option then takes the next word (Plan 03 Task 2)
		{"timeout attached expansion value, separate value", "Bash(rm *)", "", `timeout -s"$X" KILL 5 rm -rf x`, "deny"},
		{"timeout bundled attached expansion value, separate value", "Bash(rm *)", "", `timeout -vs"$X" KILL 5 rm -rf x`, "deny"},
		{"timeout -k attached expansion value, separate value", "Bash(rm *)", "", `timeout -k"$K" 9 5 rm -rf x`, "deny"},
		{"nice -n attached expansion value, separate value", "Bash(rm *)", "", `nice -n"$N" 5 rm -rf x`, "deny"},
		{"stdbuf -o attached expansion value, separate value", "Bash(rm *)", "", `stdbuf -o"$M" L rm -rf x`, "deny"},
		{"timeout attached expansion value is one value word", "Bash(rm *)", "", `timeout -s"$X" KILL 5 echo rm -rf x`, ""},
		{"nice attached expansion value is one value word", "Bash(rm *)", "", `nice -n"$N" 5 echo rm -rf x`, ""},
		{"stdbuf attached expansion value is one value word", "Bash(rm *)", "", `stdbuf -o"$M" L echo rm -rf x`, ""},
		{"timeout attached literal then expansion value", "Bash(rm *)", "", `timeout -sKILL"$X" 5 rm -rf x`, "deny"},
		{"nice legacy then -n", "Bash(rm *)", "", "nice -10 -n 5 rm -rf x", "deny"},
		{"nice legacy then attached -n", "Bash(rm *)", "", "nice -10 -n5 rm -rf x", "deny"},
		{"nice legacy then long option", "Bash(rm *)", "", "nice -10 --adjustment=5 rm -rf x", "deny"},
		{"nice legacy then expanded option word", "Bash(rm *)", "", `nice -10 -"$N" 5 rm -rf x`, "deny"},
		{"nice legacy alone", "Bash(rm *)", "", "nice -10 rm -rf x", "deny"},
		{"more than eight readings: the last one is still read", "Bash(rm *)", "", `nice -"$A" 1 -"$B" 2 -"$C" 3 -"$D" 4 -"$E" 5 -"$F" 6 -"$G" 7 -"$H" 8 -"$I" 9 -"$J" 10 rm -rf x`, "deny"},
		{"timeout duration then -- runs --", "Bash(rm *)", "", "timeout 5 -- rm -rf x", ""},
		{"plain long option given a value runs nothing", "Bash(rm *)", "", "timeout --foreground=x 5 rm -rf x", ""},
		{"ambiguous long prefix runs nothing", "Bash(rm *)", "", "timeout --ver 5 rm -rf x", ""},
		{"unknown short in a cluster runs nothing", "Bash(rm *)", "", "timeout -vz 5 rm -rf x", ""},
		{"no suffix guessing after a long prefix", "Bash(rm *)", "", "timeout --sig=KILL 5 echo rm -rf x", ""},
		// line continuation (final review, 2026-10-19)
		{"backslash-newline inside a word", "Bash(rm *)", "", "r\\\nm -rf x", "deny"},
		{"backslash-newline between words", "Bash(rm -rf x)", "", "rm -rf \\\nx", "deny"},
		{"backslash-newline inside double quotes", `Bash(echo "ab")`, "", "echo \"a\\\nb\"", "deny"},
		{"backslash-newline behind a wrapper", "Bash(rm *)", "", "timeout 5 r\\\nm -rf x", "deny"},
		{"backslash-newline in single quotes is literal", "Bash(echo 'ab')", "", "echo 'a\\\nb'", ""},
		{"escaped backslash then newline is not joined", "Bash(echo ab)", "", "echo a\\\\\nb", ""},
		// assignments
		{"deny past any assignment", "Bash(rm *)", "", "FOO=bar rm -rf tmp/", "deny"},
		{"ask past two assignments", "Bash(rm *)", "ask", "A=1 B=2 rm -rf tmp/", "ask"},
		{"assignment then wrapper", "Bash(npm test *)", "", "NODE_ENV=test timeout 5 npm test", "deny"},
		// doesn't stop (documented non-matches stay non-matches)
		{"curl by path", "Bash(curl *)", "", "/usr/bin/curl https://example.com", ""},
		{"curl in sh -c", "Bash(curl *)", "", "sh -c 'curl https://example.com'", ""},
		{"rm by path", "Bash(rm *)", "", "/bin/rm -rf build/", ""},
		{"rm in bash -c", "Bash(rm *)", "", "bash -c 'rm -rf build/'", ""},
		{"git -C push", "Bash(git push *)", "", "git -C . push origin main", ""},
		{"git -c push", "Bash(git push *)", "", "git -c push.default=current push origin main", ""},
		{"quoted push", "Bash(git push *)", "", "git 'push' origin main", ""},
		{"stops plain curl", "Bash(curl *)", "", "curl https://example.com", "deny"},
		// unparseable
		{"dangling and", "Bash(npm *)", "", "npm test &&", "uncertain"},
		{"unterminated quote", "Bash(npm *)", "", "echo 'oops", "uncertain"},
		// conservative choices
		{"rule with an operator matches the whole command", "Bash(npm test && rm *)", "", "npm test && rm -rf x", "deny"},
		{"star inside quotes is a wildcard", `Bash(echo "*")`, "", `echo "anything"`, "deny"},
		{"extra spaces collapse", "Bash(rm -rf build)", "", "rm  -rf   build", "deny"},
		{"redirect kept or dropped", "Bash(rm -rf build)", "", "rm -rf build 2>/dev/null", "deny"},
		{"declaration", "Bash(export *)", "", "export FOO=1", "deny"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			kind := c.kind
			if kind == "" {
				kind = "deny"
			}
			eff := Effective{}
			e := Entry{Value: c.rule, Scope: ScopeUser}
			if kind == "deny" {
				eff.Deny = []Entry{e}
			} else {
				eff.Ask = []Entry{e}
			}
			rules := BashRules(eff)
			if len(rules) != 1 {
				t.Fatalf("BashRules(%q) = %+v", c.rule, rules)
			}
			m := MatchBash(rules, c.cmd)
			got := ""
			switch {
			case m.Rule != nil:
				got = m.Rule.Kind
			case m.Uncertain:
				got = "uncertain"
			}
			if got != c.want {
				t.Fatalf("rule %q, command %q: got %q (subcommand %q), want %q", c.rule, c.cmd, got, m.Subcommand, c.want)
			}
		})
	}
}

// TestBashRulesSelection: only Bash entries become rules, deny before ask,
// with the value as written and the scope kept.
func TestBashRulesSelection(t *testing.T) {
	eff := Effective{
		Allow: []Entry{{Value: "Bash(rm *)", Scope: ScopeUser}},
		Ask:   []Entry{{Value: "Bash(git clean:*)", Scope: ScopeProject}, {Value: "Read(./.env)", Scope: ScopeProject}},
		Deny:  []Entry{{Value: "WebFetch", Scope: ScopeUser}, {Value: "Bash(curl *)", Scope: ScopeManaged}, {Value: "Bashful", Scope: ScopeUser}},
	}
	got := BashRules(eff)
	want := []BashRule{
		{Pattern: "curl *", Kind: "deny", Scope: ScopeManaged, Value: "Bash(curl *)"},
		{Pattern: "git clean *", Kind: "ask", Scope: ScopeProject, Value: "Bash(git clean:*)"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
}

// TestMatchBashDenyBeforeAsk: a deny rule wins over an ask rule matching
// the same command, whatever the order in the list.
func TestMatchBashDenyBeforeAsk(t *testing.T) {
	rules := []BashRule{
		{Pattern: "git *", Kind: "ask", Value: "Bash(git *)"},
		{Pattern: "git push *", Kind: "deny", Value: "Bash(git push *)"},
	}
	m := MatchBash(rules, "git status && git push origin main")
	if m.Rule == nil || m.Rule.Kind != "deny" || m.Subcommand != "git push origin main" {
		t.Fatalf("got %+v", m)
	}
	if m := MatchBash(nil, "npm test &&"); m.Rule != nil || m.Uncertain {
		t.Fatalf("no rules must not be uncertain: %+v", m)
	}
}

// TestLoadCachedRules: the cache is reused while no candidate file
// changed, a changed file or a new managed drop-in rebuilds it, an
// unreadable settings file becomes a match-all ask, and with no settings
// file at all nothing is written.
func TestLoadCachedRules(t *testing.T) {
	p := tempPaths(t)
	managed := filepath.Join(t.TempDir(), "managed")
	cache := filepath.Join(p.StateDir, RulesCacheFile)
	root := filepath.Join(p.Home, "proj")

	if r := loadCachedRulesAt(cache, managed, p, root); len(r) != 0 {
		t.Fatalf("no files: %+v", r)
	}
	if fileExists(cache) {
		t.Fatal("cache written with no settings file")
	}

	writeFile(t, filepath.Join(p.ClaudeDir, "settings.json"), `{"permissions":{"deny":["Bash(curl *)"]}}`)
	r := loadCachedRulesAt(cache, managed, p, root)
	if len(r) != 1 || r[0].Value != "Bash(curl *)" {
		t.Fatalf("user rule: %+v", r)
	}
	if !fileExists(cache) {
		t.Fatal("cache not written")
	}
	// cached result equals the fresh one
	if r2 := loadCachedRulesAt(cache, managed, p, root); !reflect.DeepEqual(r, r2) {
		t.Fatalf("cached %+v != %+v", r2, r)
	}
	// a project file is picked up
	writeFile(t, filepath.Join(root, ".claude", "settings.json"), `{"permissions":{"ask":["Bash(git clean *)"]}}`)
	if r := loadCachedRulesAt(cache, managed, p, root); len(r) != 2 || r[1].Scope != ScopeProject {
		t.Fatalf("project rule: %+v", r)
	}
	// a new managed drop-in is picked up (the directory's stat changes)
	writeFile(t, filepath.Join(managed, "managed-settings.d", "10-org.json"), `{"permissions":{"deny":["Bash(wget *)"]}}`)
	r = loadCachedRulesAt(cache, managed, p, root)
	if len(r) != 3 || r[0].Value != "Bash(wget *)" || r[0].Scope != ScopeManaged {
		t.Fatalf("drop-in rule: %+v", r)
	}
	// an unreadable settings file is a match-all ask naming the scope
	writeFile(t, filepath.Join(root, ".claude", "settings.local.json"), `{not json`)
	r = loadCachedRulesAt(cache, managed, p, root)
	found := false
	for _, x := range r {
		if x.Unreadable && x.Kind == "ask" && x.Scope == ScopeLocal {
			found = true
		}
	}
	if !found {
		t.Fatalf("unreadable file not reported: %+v", r)
	}
	if m := MatchBash(r, "echo hi"); m.Rule == nil || !m.Rule.Unreadable {
		t.Fatalf("unreadable rule must match everything: %+v", m)
	}
	// LoadCachedRules with explicit locations reads the same files
	locs := locate(managed, p, root)
	if r2 := LoadCachedRules(filepath.Join(t.TempDir(), RulesCacheFile), locs); !reflect.DeepEqual(r, r2) {
		t.Fatalf("LoadCachedRules %+v != %+v", r2, r)
	}
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// TestMatchBashChainCost: 1,200 chained wrappers, each followed by an
// expanded word or option word, stay linear: the walk stops at a start it
// has seen before it records forms, a wrapper's option scan visits each
// word once, and forms are deduplicated through a set. No reading is ever
// dropped (a cap would fail open), so one wrapper with 1,200 readings is
// timed too. The bound is
// generous (1 s); before the fix the slowest unit took about 46 ms on an
// M-series Mac and grew quadratically.
func TestMatchBashChainCost(t *testing.T) {
	rules := []BashRule{{Pattern: "rm *", Kind: KindDeny, Scope: ScopeUser, Value: "Bash(rm *)"}}
	var units []string
	for _, c := range []string{`nice -"$N" 5 `, `timeout -"$S" KILL 5 `, `nohup "$X" `, `stdbuf -"$M" L `, `nice -10 -"$N" 5 `, `timeout -v"$S" KILL 5 `} {
		units = append(units, strings.Repeat(c, 1200)+"rm -rf x")
	}
	// one wrapper with 1,200 readings (no cap: every reading is walked)
	units = append(units, "nice "+strings.Repeat(`-"$N" 5 `, 1200)+"rm -rf x")
	for _, c := range units {
		unit := c[:24]
		start := time.Now()
		m := MatchBash(rules, c)
		took := time.Since(start)
		if m.Rule == nil {
			t.Errorf("%q x1200: no match", unit)
		}
		if took > time.Second {
			t.Errorf("%q x1200: took %v", unit, took)
		}
		t.Logf("%-28q… x1200: %v", unit, took)
	}
}
