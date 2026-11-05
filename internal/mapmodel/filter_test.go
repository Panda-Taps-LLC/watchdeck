package mapmodel

import (
	"reflect"
	"strings"
	"testing"
)

// TestNodeAuthorityOnEventNodes: in fixture A's timeline every event node
// a tick points at carries the tick's authority word, and so does every
// other event node built from that call (its skill and run events). The
// deny fixture's timeline holds the deny_rule, classifier and auto words.
func TestNodeAuthorityOnEventNodes(t *testing.T) {
	a, deny := loadA(t), loadDeny(t)
	for name, g := range map[string]Graph{
		"a":    Build(a, recsA(t), declaredA(t), optsA(a, ViewTimeline, false)),
		"deny": Build(deny, nil, nil, optsA(deny, ViewTimeline, false)),
	} {
		byCall := map[string]string{}
		for _, tk := range g.Ticks {
			if tk.Authority == "" {
				t.Errorf("%s: tick %s has no authority", name, tk.ID)
			}
			byCall[tk.ID] = tk.Authority
			n := node(g, tk.Node)
			if n == nil {
				t.Errorf("%s: tick %s names no node (%q)", name, tk.ID, tk.Node)
				continue
			}
			if n.Authority != tk.Authority {
				t.Errorf("%s: node %s authority %q, tick %q", name, n.ID, n.Authority, tk.Authority)
			}
		}
		seen := 0
		for _, n := range g.Nodes {
			if !n.Event || n.ToolUseID == "" {
				if n.Authority != "" {
					t.Errorf("%s: node %s is not a call's event but has authority %q", name, n.ID, n.Authority)
				}
				continue
			}
			seen++
			if want := byCall[n.ToolUseID]; n.Authority != want {
				t.Errorf("%s: event %s authority %q, its call's tick %q", name, n.ID, n.Authority, want)
			}
		}
		if seen == 0 {
			t.Errorf("%s: no call events", name)
		}
	}
	// Topology: a tool node whose calls share one word carries it; the Bash
	// node of the deny fixture mixes deny_rule, classifier and auto.
	g := Build(deny, nil, nil, optsA(deny, ViewTopology, false))
	if n := node(g, "tool:Read"); n == nil || n.Authority != AuthorityDenyRule {
		t.Errorf("deny topology tool:Read = %+v, want authority deny_rule", n)
	}
	if n := node(g, "tool:Bash"); n == nil || n.Authority != "" {
		t.Errorf("deny topology tool:Bash = %+v, want no authority (mixed)", n)
	}
}

// TestAuthorityFilterDropsCalls: Authorities keeps only the calls decided by
// the named parties, in both views, while ticks and totals stay the whole
// session and shown counts the calls kept. The deny fixture has no hook
// decision, so ["hook"] keeps nothing; ["deny_rule"] keeps two of four.
func TestAuthorityFilterDropsCalls(t *testing.T) {
	deny := loadDeny(t)
	all := Build(deny, nil, nil, optsA(deny, ViewTopology, false))
	if all.Shown != 4 || len(all.Ticks) != 4 {
		t.Fatalf("unfiltered: shown %d, %d ticks; want 4, 4", all.Shown, len(all.Ticks))
	}
	opts := func(view string, words ...string) Options {
		o := optsA(deny, view, false)
		o.Authorities = words
		return o
	}

	hook := Build(deny, nil, nil, opts(ViewTopology, AuthorityHook))
	if hook.Shown != 0 {
		t.Errorf("hook: shown %d, want 0", hook.Shown)
	}
	for _, id := range []string{"tool:Bash", "tool:Read"} {
		if node(hook, id) != nil {
			t.Errorf("hook: %s kept", id)
		}
	}
	if node(hook, "agent:main") == nil {
		t.Error("hook: the main agent went")
	}

	for _, view := range []string{ViewTopology, ViewTimeline} {
		g := Build(deny, nil, nil, opts(view, AuthorityDenyRule))
		if g.Shown != 2 {
			t.Errorf("%s deny_rule: shown %d, want 2", view, g.Shown)
		}
		if len(g.Ticks) != len(all.Ticks) || !reflect.DeepEqual(g.Totals, all.Totals) {
			t.Errorf("%s deny_rule: ticks or totals changed: %d %+v", view, len(g.Ticks), g.Totals)
		}
		kept := 0
		for _, tk := range g.Ticks {
			if tk.Authority == AuthorityDenyRule {
				if tk.Node == "" {
					t.Errorf("%s: kept call %s has no node", view, tk.ID)
				}
				kept++
			} else if tk.Node != "" {
				t.Errorf("%s: dropped %s call %s still names %s", view, tk.Authority, tk.ID, tk.Node)
			}
		}
		if kept != 2 {
			t.Errorf("%s: %d deny_rule ticks, want 2", view, kept)
		}
		for _, n := range g.Nodes {
			if n.Authority != "" && n.Authority != AuthorityDenyRule {
				t.Errorf("%s: node %s with authority %q survived", view, n.ID, n.Authority)
			}
		}
		if view == ViewTopology {
			// The Bash node shrinks to its one deny_rule call.
			if b := node(g, "tool:Bash"); b == nil || b.Count != 1 || b.Authority != AuthorityDenyRule {
				t.Errorf("topology deny_rule: tool:Bash = %+v, want count 1, deny_rule", b)
			}
		} else {
			events := 0
			for _, n := range g.Nodes {
				if n.Event && strings.HasPrefix(n.ID, "ev:toolu_") {
					events++
				}
			}
			if events != 2 {
				t.Errorf("timeline deny_rule: %d call events, want 2", events)
			}
		}
	}

	// Two words widen the set; order and repeats do not matter.
	two := Build(deny, nil, nil, opts(ViewTimeline, AuthorityAuto, AuthorityClassifier, AuthorityAuto))
	if two.Shown != 2 {
		t.Errorf("auto+classifier: shown %d, want 2", two.Shown)
	}

	// Fixture A: sandbox keeps the two Bash calls; the spawn is structure
	// and stays (and counts as shown), as under HideNone.
	a := loadA(t)
	o := optsA(a, ViewTimeline, false)
	o.Authorities = []string{AuthoritySandbox}
	ga := Build(a, recsA(t), declaredA(t), o)
	if ga.Shown != 3 {
		t.Errorf("A sandbox: shown %d, want 3 (two Bash, one spawn)", ga.Shown)
	}
	if node(ga, "ev:toolu_01PEzFa65hdCYERmSZVb9Yej") != nil {
		t.Error("A sandbox: the allow_rule Read event stayed")
	}
	if node(ga, "ev:spawn:a3033ade8c1d9c1a5") == nil || node(ga, "ev:"+idMainProbe+":run") == nil {
		t.Error("A sandbox: the spawn or the Bash run went")
	}
}

// TestShownUnderHideNone: HideNone stays a policy filter (calls with no
// policy go, spawns stay); shown counts what it keeps.
func TestShownUnderHideNone(t *testing.T) {
	a := loadA(t)
	g := Build(a, recsA(t), declaredA(t), optsA(a, ViewTimeline, true))
	if g.Shown != 3 {
		t.Errorf("A hide-none: shown %d, want 3 (two Bash, one spawn)", g.Shown)
	}
	if all := Build(a, recsA(t), declaredA(t), optsA(a, ViewTimeline, false)); all.Shown != 6 {
		t.Errorf("A: shown %d, want 6", all.Shown)
	}
}

func TestIsAuthority(t *testing.T) {
	for _, w := range []string{AuthorityDenyRule, AuthorityClassifier, AuthorityAuto, AuthorityAllowRule, AuthorityUser, AuthorityHook, AuthoritySandbox, AuthorityBlocked, AuthorityNone} {
		if !IsAuthority(w) {
			t.Errorf("IsAuthority(%q) = false", w)
		}
	}
	for _, w := range []string{"", "Hook", "deny", "allow", " hook", "all"} {
		if IsAuthority(w) {
			t.Errorf("IsAuthority(%q) = true", w)
		}
	}
}

// TestAllAuthoritiesIsNoFilter: naming all nine words drops nothing, and the
// re-run of the skill aggregates on the kept calls gives the same Graph,
// byte for byte, as no filter (fixture A has skills, runs, a subagent and a
// hide-none variant; the deny fixture has native denials).
func TestAllAuthoritiesIsNoFilter(t *testing.T) {
	nine := []string{AuthorityDenyRule, AuthorityClassifier, AuthorityAuto, AuthorityAllowRule, AuthorityUser, AuthorityHook, AuthoritySandbox, AuthorityBlocked, AuthorityNone}
	a, deny := loadA(t), loadDeny(t)
	for _, view := range []string{ViewTopology, ViewTimeline} {
		for _, hide := range []bool{false, true} {
			o := optsA(a, view, hide)
			want := mustJSON(t, Build(a, recsA(t), declaredA(t), o))
			o.Authorities = nine
			if got := mustJSON(t, Build(a, recsA(t), declaredA(t), o)); string(got) != string(want) {
				t.Errorf("A %s hide=%v: all nine words changed the graph", view, hide)
			}
		}
		o := optsA(deny, view, false)
		want := mustJSON(t, Build(deny, nil, nil, o))
		o.Authorities = nine
		if got := mustJSON(t, Build(deny, nil, nil, o)); string(got) != string(want) {
			t.Errorf("deny %s: all nine words changed the graph", view)
		}
	}
}

// TestNodeTextCarriesNoRawAuthorityWord: node text is on-screen copy. Who
// decided travels only in Node.Authority (the dashboard prints its label),
// so no Label, Sub or Sub2 in fixture A or the deny fixture, in either view,
// holds an authority word: no " · "-separated piece of the text is one of
// the nine words (the shape the timeline used to append), and the phrase
// "no opinion" appears nowhere. A word inside a longer piece is the
// session's own data or plain English, not an authority word: a command
// such as "echo classifier-deny-marker", "granted none", "OS sandbox".
func TestNodeTextCarriesNoRawAuthorityWord(t *testing.T) {
	a, deny := loadA(t), loadDeny(t)
	words := []string{AuthorityDenyRule, AuthorityClassifier, AuthorityAuto, AuthorityAllowRule, AuthorityUser, AuthorityHook, AuthoritySandbox, AuthorityBlocked, AuthorityNone}
	for _, w := range words {
		if !IsAuthority(w) {
			t.Fatalf("%q is not an authority word", w)
		}
	}
	bad := func(s string) string {
		if strings.Contains(strings.ToLower(s), "no opinion") {
			return "no opinion"
		}
		for _, piece := range strings.Split(s, " · ") {
			for _, w := range words {
				if strings.TrimSpace(piece) == w {
					return w
				}
			}
		}
		return ""
	}
	checked := 0
	for _, view := range []string{ViewTimeline, ViewTopology} {
		graphs := map[string]Graph{
			"a":    Build(a, recsA(t), declaredA(t), optsA(a, view, false)),
			"deny": Build(deny, nil, nil, optsA(deny, view, false)),
		}
		for name, g := range graphs {
			for _, n := range g.Nodes {
				for field, s := range map[string]string{"label": n.Label, "sub": n.Sub, "sub2": n.Sub2} {
					checked++
					if w := bad(s); w != "" {
						t.Errorf("%s %s %s %s: %q holds %q", name, view, n.ID, field, s, w)
					}
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("no nodes checked")
	}
}
