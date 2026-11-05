package rulebook

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/activity"
	"github.com/Panda-Taps-LLC/watchdeck/internal/claudesettings"
	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
	"github.com/Panda-Taps-LLC/watchdeck/internal/rules"
)

// inboxEnv is testEnv with the activity log under the temp state dir.
func inboxEnv(t *testing.T) paths.Paths {
	t.Helper()
	p := testEnv(t)
	p.Activity = filepath.Join(p.StateDir, "activity.jsonl")
	return p
}

func ts(d time.Duration) string { return time.Now().Add(-d).UTC().Format(time.RFC3339Nano) }

func appendRec(t *testing.T, p paths.Paths, r activity.Record) {
	t.Helper()
	if err := activity.Append(p.Activity, r); err != nil {
		t.Fatal(err)
	}
}

func byKind(items []Item) map[ItemKind]Item {
	m := map[ItemKind]Item{}
	for _, it := range items {
		m[it.Kind] = it
	}
	return m
}

func TestInboxFromDeniedAndDecisions(t *testing.T) {
	p := inboxEnv(t)
	proj := filepath.Join(p.Home, "src", "app")
	if err := os.MkdirAll(filepath.Join(proj, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(proj, "pkg")
	appendRec(t, p, activity.Record{Kind: activity.KindDenied, TS: ts(5 * time.Hour), SessionID: "s1", ToolUseID: "t1",
		Cwd: sub, ToolName: "Bash", Argv0: "curl", Reason: "auto mode blocked a network download"})
	appendRec(t, p, activity.Record{Kind: activity.KindDecision, TS: ts(4 * time.Hour), SessionID: "s1", ToolUseID: "t2",
		Cwd: proj, ToolName: "Read", Target: "~/.netrc", Decision: "deny", Enforcement: activity.EnforcementGate,
		Reason: "watchdeck: denied by policy: reads of ~/.netrc"})
	appendRec(t, p, activity.Record{Kind: activity.KindRun, TS: ts(3 * time.Hour), SessionID: "s1", ToolUseID: "t3",
		Cwd: proj, Command: "python3 scripts/fetch.py", Outcome: activity.OutcomeOK,
		Hints: []activity.Hint{{Kind: activity.HintNetwork, Line: "urlopen error", Stream: "stderr", Text: "The sandbox blocked a network connection."}}})
	appendRec(t, p, activity.Record{Kind: activity.KindDecision, TS: ts(2 * time.Hour), SessionID: "s1", ToolUseID: "t4",
		AgentType: "Explore", Cwd: proj, ToolName: "Bash", Command: "python3 scripts/fetch.py", Skills: []string{"fetcher"},
		Decision: "ask", Enforcement: activity.EnforcementSandbox, Ungranted: []string{"fetcher: network: all"}})
	// Not items: an allow decision, a sandbox ask without ungranted, a clean run.
	appendRec(t, p, activity.Record{Kind: activity.KindDecision, TS: ts(90 * time.Minute), SessionID: "s1", ToolUseID: "t5",
		ToolName: "Bash", Command: "ls", Decision: "allow", Enforcement: activity.EnforcementSandbox})
	appendRec(t, p, activity.Record{Kind: activity.KindRun, TS: ts(80 * time.Minute), SessionID: "s1", ToolUseID: "t6",
		Command: "ls", Outcome: activity.OutcomeOK})

	rej := []Rejection{{SessionID: "s2", ToolUseID: "t9", TS: time.Now().Add(-time.Hour), Tool: "WebFetch",
		Target: "example.test", Authority: "user", Why: "The person said no."}}
	leaks := []Leak{{SessionID: "s3", Ref: "t10", Tool: "Read", Target: "~/src/app/.env", Where: "result",
		Pattern: "slack-token", Label: "Slack token", Project: "~/src/app", TS: time.Now().Add(-30 * time.Minute)}}
	in := InboxInput{Paths: p, Rejections: rej, Leaks: leaks}
	items, err := Open(in)
	if err != nil {
		t.Fatal(err)
	}
	wantOrder := []ItemKind{KindLeak, ItemRejection, ItemSkillRequest, ItemSandboxRefusal, ItemAsk, ItemDenial}
	if len(items) != len(wantOrder) {
		t.Fatalf("got %d items, want %d: %+v", len(items), len(wantOrder), items)
	}
	for i, k := range wantOrder {
		if items[i].Kind != k {
			t.Fatalf("item %d kind %s, want %s (newest first)", i, items[i].Kind, k)
		}
	}
	m := byKind(items)
	d := m[ItemDenial]
	if d.What != "Bash · curl" || d.Authority != "classifier" || d.Why != "auto mode blocked a network download" ||
		d.Project != "~/src/app" || d.Harness != "claude-code" || d.SessionID != "s1" || d.ToolUseID != "t1" {
		t.Fatalf("denial item: %+v", d)
	}
	if a := m[ItemAsk]; a.What != "Read · ~/.netrc" || a.Authority != "hook" {
		t.Fatalf("ask item: %+v", a)
	}
	if s := m[ItemSandboxRefusal]; s.What != "Bash · python3" || s.Authority != "sandbox" || s.Why != "The sandbox blocked a network connection." {
		t.Fatalf("sandbox item: %+v", s)
	}
	if s := m[ItemSkillRequest]; s.Agent != "Explore" || s.Why != "fetcher: network: all" || len(s.Fix) != 0 {
		t.Fatalf("skill item: %+v", s)
	}
	if r := m[ItemRejection]; r.What != "WebFetch · example.test" || r.Authority != "user" || len(r.Fix) != 2 || !r.Fix[1].Everywhere {
		t.Fatalf("rejection item: %+v", r)
	}
	if want := itemID("s1", "t1", ItemDenial); d.ID != want || len(d.ID) != 16 {
		t.Fatalf("denial id %q, want %q", d.ID, want)
	}
	again, err := Open(in)
	if err != nil {
		t.Fatal(err)
	}
	for i := range items {
		if items[i].ID != again[i].ID {
			t.Fatalf("id %d changed between Open calls: %s vs %s", i, items[i].ID, again[i].ID)
		}
	}
}

func TestInboxOnlyAfterInstall(t *testing.T) {
	p := inboxEnv(t)
	installed := time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339)
	writeFile(t, p.ConfigFile(), "installed_at: \""+installed+"\"\n")
	appendRec(t, p, activity.Record{Kind: activity.KindDenied, TS: ts(3 * time.Hour), SessionID: "s", ToolUseID: "old",
		ToolName: "Bash", Argv0: "curl", Reason: "before install"})
	appendRec(t, p, activity.Record{Kind: activity.KindDenied, TS: ts(time.Hour), SessionID: "s", ToolUseID: "new",
		ToolName: "Bash", Argv0: "wget", Reason: "after install"})
	items, err := Open(InboxInput{Paths: p})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].ToolUseID != "new" {
		t.Fatalf("want only the record after installed_at, got %+v", items)
	}
}

func TestInboxWithoutInstallDateUsesWindow(t *testing.T) {
	p := inboxEnv(t)
	appendRec(t, p, activity.Record{Kind: activity.KindDenied, TS: ts(8 * 24 * time.Hour), SessionID: "s", ToolUseID: "eight",
		ToolName: "Bash", Argv0: "curl", Reason: "eight days"})
	appendRec(t, p, activity.Record{Kind: activity.KindDenied, TS: ts(6 * 24 * time.Hour), SessionID: "s", ToolUseID: "six",
		ToolName: "Bash", Argv0: "curl", Reason: "six days"})
	items, err := Open(InboxInput{Paths: p})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].ToolUseID != "six" {
		t.Fatalf("want only the 6-day-old record, got %+v", items)
	}
	// Since overrides the window.
	items, err = Open(InboxInput{Paths: p, Since: time.Now().Add(-9 * 24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 {
		t.Fatalf("Since: want 2 items, got %+v", items)
	}
	// The log off: only rejections, no error.
	p.Activity = ""
	items, err = Open(InboxInput{Paths: p, Rejections: []Rejection{{SessionID: "s", ToolUseID: "r", TS: time.Now(), Tool: "Bash", Target: "rm", Why: "no"}}})
	if err != nil || len(items) != 1 || items[0].Kind != ItemRejection {
		t.Fatalf("log off: %+v %v", items, err)
	}
}

func TestInboxResolve0600(t *testing.T) {
	p := inboxEnv(t)
	appendRec(t, p, activity.Record{Kind: activity.KindDenied, TS: ts(3 * time.Hour), SessionID: "s", ToolUseID: "a",
		ToolName: "Bash", Argv0: "curl", Reason: "network"})
	appendRec(t, p, activity.Record{Kind: activity.KindDenied, TS: ts(2 * time.Hour), SessionID: "s", ToolUseID: "b",
		ToolName: "Bash", Argv0: "rm", Reason: "deletes files"})
	items, err := Open(InboxInput{Paths: p})
	if err != nil || len(items) != 2 {
		t.Fatalf("%+v %v", items, err)
	}
	var curl, rm Item
	for _, it := range items {
		if it.ToolUseID == "a" {
			curl = it
		} else {
			rm = it
		}
	}
	if err := Resolve(p.StateDir, Resolution{ID: curl.ID, Action: "acknowledge"}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(p.StateDir, InboxFile))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("inbox file mode %v, want 0600", fi.Mode().Perm())
	}
	items, err = Open(InboxInput{Paths: p})
	if err != nil || len(items) != 1 || items[0].ID != rm.ID {
		t.Fatalf("after acknowledge: %+v %v", items, err)
	}
	if err := Resolve(p.StateDir, Resolution{ID: rm.ID, Action: "dismiss", Signature: Signature(rm)}); err != nil {
		t.Fatal(err)
	}
	// A later item with the same kind, what and why stays dismissed.
	appendRec(t, p, activity.Record{Kind: activity.KindDenied, TS: ts(time.Hour), SessionID: "s2", ToolUseID: "c",
		ToolName: "Bash", Argv0: "rm", Reason: "deletes files"})
	appendRec(t, p, activity.Record{Kind: activity.KindDenied, TS: ts(time.Hour), SessionID: "s2", ToolUseID: "d",
		ToolName: "Bash", Argv0: "rm", Reason: "a different reason"})
	items, err = Open(InboxInput{Paths: p})
	if err != nil || len(items) != 1 || items[0].ToolUseID != "d" {
		t.Fatalf("after dismiss: %+v %v", items, err)
	}
	if err := Resolve(p.StateDir, Resolution{ID: "x", Action: "approve"}); err == nil {
		t.Fatal("an unknown action must be refused")
	}
	if err := Resolve(p.StateDir, Resolution{Action: "acknowledge"}); err == nil {
		t.Fatal("an empty id must be refused")
	}
}

func TestInboxItemClosesWhenRuleExists(t *testing.T) {
	p := inboxEnv(t)
	appendRec(t, p, activity.Record{Kind: activity.KindDenied, TS: ts(2 * time.Hour), SessionID: "s", ToolUseID: "a",
		ToolName: "Bash", Argv0: "curl", Reason: "network"})
	appendRec(t, p, activity.Record{Kind: activity.KindDecision, TS: ts(time.Hour), SessionID: "s", ToolUseID: "b",
		ToolName: "Read", Target: "~/.netrc", Decision: "ask", Enforcement: activity.EnforcementGate, Reason: "netrc"})
	book := &Book{Groups: []Group{{ID: GroupBlocked, Rows: []Rule{
		{Kind: KindNativeDeny, Value: "Bash(curl *)", State: StateOn},
		{Kind: KindNativeDeny, Value: "Read(~/.netrc)", State: StateRemoved},
	}}}}
	items, err := Open(InboxInput{Paths: p, Book: book})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].ToolUseID != "b" {
		t.Fatalf("want only the netrc item (its rule was removed), got %+v", items)
	}
	// Without a Book nothing is closed.
	items, _ = Open(InboxInput{Paths: p})
	if len(items) != 2 {
		t.Fatalf("nil Book: want 2 items, got %d", len(items))
	}
}

func TestSuggestTable(t *testing.T) {
	cases := []struct {
		name string
		it   Item
		want []AddRequest
	}{
		// A Bash item suggests an ask on the program, never a block: the
		// program alone says little about what the call was for.
		{"denial bash", Item{Kind: ItemDenial, What: "Bash · curl"}, []AddRequest{{Action: "ask", What: WhatCommand, Value: "curl"}}},
		{"ask bash", Item{Kind: ItemAsk, What: "Bash · rm"}, []AddRequest{{Action: "ask", What: WhatCommand, Value: "rm"}}},
		{"rejection bash", Item{Kind: ItemRejection, What: "Bash · git"}, []AddRequest{{Action: "ask", What: WhatCommand, Value: "git"}}},
		{"denial bash no argv0", Item{Kind: ItemDenial, What: "Bash"}, nil},
		{"ask read", Item{Kind: ItemAsk, What: "Read · ~/.netrc"}, []AddRequest{{Action: "deny", What: WhatPath, Value: "~/.netrc", Tool: PathRead}, {Action: "deny", What: WhatPath, Value: "~/.netrc", Everywhere: true}}},
		{"ask write", Item{Kind: ItemAsk, What: "Write · ~/notes/x.md"}, []AddRequest{{Action: "deny", What: WhatPath, Value: "~/notes/x.md", Tool: PathEdit}, {Action: "deny", What: WhatPath, Value: "~/notes/x.md", Everywhere: true}}},
		{"denial grep", Item{Kind: ItemDenial, What: "Grep · /etc"}, []AddRequest{{Action: "deny", What: WhatPath, Value: "/etc", Tool: PathRead}, {Action: "deny", What: WhatPath, Value: "/etc", Everywhere: true}}},
		{"denial file no target", Item{Kind: ItemDenial, What: "Edit"}, nil},
		{"denial webfetch", Item{Kind: ItemDenial, What: "WebFetch · example.test"}, []AddRequest{{Action: "deny", What: WhatHost, Value: "example.test"}, {Action: "deny", What: WhatHost, Value: "example.test", Everywhere: true}}},
		{"ask mcp", Item{Kind: ItemAsk, What: "mcp__files__delete"}, []AddRequest{{Action: "deny", What: WhatMCP, Value: "mcp__files__delete"}}},
		{"sandbox refusal", Item{Kind: ItemSandboxRefusal, What: "Bash · python3"}, nil},
		{"skill request", Item{Kind: ItemSkillRequest, What: "Bash · fetcher"}, nil},
		{"unknown tool", Item{Kind: ItemDenial, What: "Task · general-purpose"}, nil},
	}
	for _, c := range cases {
		if got := Suggest(c.it); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: Suggest = %+v, want %+v", c.name, got, c.want)
		}
	}
}

// TestInboxCorruptConfigUsesWindow: a config.yaml that cannot be read or
// does not parse is no reason to fail; the inbox falls back to the
// seven-day window.
func TestInboxCorruptConfigUsesWindow(t *testing.T) {
	for name, setup := range map[string]func(p paths.Paths){
		"invalid":    func(p paths.Paths) { writeFile(t, p.ConfigFile(), "installed_at: [not, a, time\n\t:::\n") },
		"bad date":   func(p paths.Paths) { writeFile(t, p.ConfigFile(), "installed_at: \"yesterday\"\n") },
		"unreadable": func(p paths.Paths) { writeFile(t, p.ConfigFile(), "x: 1\n"); os.Chmod(p.ConfigFile(), 0) },
		"directory":  func(p paths.Paths) { os.MkdirAll(p.ConfigFile(), 0o700) },
	} {
		t.Run(name, func(t *testing.T) {
			p := inboxEnv(t)
			setup(p)
			appendRec(t, p, activity.Record{Kind: activity.KindDenied, TS: ts(8 * 24 * time.Hour), SessionID: "s", ToolUseID: "eight",
				ToolName: "Bash", Argv0: "curl", Reason: "eight days"})
			appendRec(t, p, activity.Record{Kind: activity.KindDenied, TS: ts(6 * 24 * time.Hour), SessionID: "s", ToolUseID: "six",
				ToolName: "Bash", Argv0: "curl", Reason: "six days"})
			items, err := Open(InboxInput{Paths: p})
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if len(items) != 1 || items[0].ToolUseID != "six" {
				t.Fatalf("want only the 6-day-old record, got %+v", items)
			}
		})
	}
}

// TestInboxResolveRefusesSymlink: a symlink planted at inbox.jsonl is
// refused (O_NOFOLLOW), and the file it points at is left untouched.
func TestInboxResolveRefusesSymlink(t *testing.T) {
	p := inboxEnv(t)
	target := filepath.Join(t.TempDir(), "elsewhere")
	writeFile(t, target, "keep\n")
	if err := os.MkdirAll(p.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(p.StateDir, InboxFile)); err != nil {
		t.Fatal(err)
	}
	if err := Resolve(p.StateDir, Resolution{ID: "abc", Action: ResolveAcknowledge}); err == nil {
		t.Fatal("Resolve followed a symlink at inbox.jsonl")
	}
	if got := string(readBytes(t, target)); got != "keep\n" {
		t.Fatalf("the symlink's target changed: %q", got)
	}
}

func TestItemCarriesRuleIDs(t *testing.T) {
	p := inboxEnv(t)
	_, _, key := firstPackRule(t)
	pack, id, _ := strings.Cut(key, "/")
	appendRec(t, p, activity.Record{Kind: activity.KindDecision, TS: ts(time.Hour), SessionID: "s", ToolUseID: "a",
		ToolName: "Read", Target: "~/.netrc", Decision: "ask", Enforcement: activity.EnforcementGate, Reason: "netrc",
		Rules: []activity.RuleHit{
			{Pack: "user", ID: "user-0000abcd", Action: "ask"},
			{Pack: pack, ID: id, Action: "ask"},
			{Pack: "user", ID: "user-0000abcd", Action: "ask"},
		}})
	appendRec(t, p, activity.Record{Kind: activity.KindDenied, TS: ts(2 * time.Hour), SessionID: "s", ToolUseID: "b",
		ToolName: "Bash", Argv0: "curl", Reason: "network"})
	items, err := Open(InboxInput{Paths: p})
	if err != nil || len(items) != 2 {
		t.Fatalf("%+v %v", items, err)
	}
	m := byKind(items)
	if got := m[ItemAsk].RuleIDs; !reflect.DeepEqual(got, []string{"user/user-0000abcd", key}) {
		t.Errorf("rule ids = %v", got)
	}
	if got := m[ItemDenial].RuleIDs; got != nil {
		t.Errorf("denial without hits: rule ids = %v", got)
	}
	b, _ := json.Marshal(m[ItemDenial])
	if strings.Contains(string(b), "rule_ids") {
		t.Errorf("empty rule_ids marshalled: %s", b)
	}
}

func TestSuggestPrefersPackRuleDeny(t *testing.T) {
	_, _, key := firstPackRule(t)
	base := Item{Kind: ItemAsk, What: "Read · ~/.netrc", RuleIDs: []string{"user/user-0000abcd", "claude-settings/Bash(curl *)", key}}
	got := Suggest(base)
	want := []AddRequest{
		{Action: "deny", What: WhatPackRule, Value: key},
		{Action: "deny", What: WhatPath, Value: "~/.netrc", Tool: PathRead},
		{Action: "deny", What: WhatPath, Value: "~/.netrc", Everywhere: true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ask: %+v", got)
	}
	base.Kind = ItemDenial
	if got := Suggest(base); !reflect.DeepEqual(got, want) {
		t.Errorf("denial: %+v", got)
	}
	// A rejection keeps today's suggestion only.
	base.Kind = ItemRejection
	if got := Suggest(base); !reflect.DeepEqual(got, want[1:]) {
		t.Errorf("rejection: %+v", got)
	}
	// No built-in pack rule among the ids: today's suggestion only.
	if got := Suggest(Item{Kind: ItemAsk, What: "Read · ~/.netrc", RuleIDs: []string{"user/user-0000abcd"}}); !reflect.DeepEqual(got, want[1:]) {
		t.Errorf("user rule only: %+v", got)
	}
	// The pack-rule fix stands alone when there is no other.
	if got := Suggest(Item{Kind: ItemAsk, What: "Task", RuleIDs: []string{key}}); !reflect.DeepEqual(got, want[:1]) {
		t.Errorf("tool without target: %+v", got)
	}
}

func TestUndoReopensItem(t *testing.T) {
	p := inboxEnv(t)
	appendRec(t, p, activity.Record{Kind: activity.KindDenied, TS: ts(3 * time.Hour), SessionID: "s", ToolUseID: "a",
		ToolName: "Bash", Argv0: "curl", Reason: "network"})
	appendRec(t, p, activity.Record{Kind: activity.KindDenied, TS: ts(2 * time.Hour), SessionID: "s", ToolUseID: "b",
		ToolName: "Bash", Argv0: "rm", Reason: "deletes files"})
	items, err := Open(InboxInput{Paths: p})
	if err != nil || len(items) != 2 {
		t.Fatalf("%+v %v", items, err)
	}
	rm, curl := items[0], items[1]
	in := Input{Paths: p}
	if err := Resolve(p.StateDir, Resolution{ID: curl.ID, Action: ResolveAcknowledge}); err != nil {
		t.Fatal(err)
	}
	if err := Resolve(p.StateDir, Resolution{ID: rm.ID, Action: ResolveDismiss, Signature: Signature(rm)}); err != nil {
		t.Fatal(err)
	}
	if items, _ := Open(InboxInput{Paths: p}); len(items) != 0 {
		t.Fatalf("after resolving: %+v", items)
	}
	if _, err := Undo(in, curl.ID); err != nil {
		t.Fatal(err)
	}
	items, _ = Open(InboxInput{Paths: p})
	if len(items) != 1 || items[0].ID != curl.ID {
		t.Fatalf("after undo of acknowledge: %+v", items)
	}
	// Undoing the dismiss stops it suppressing its signature.
	if _, err := Undo(in, rm.ID); err != nil {
		t.Fatal(err)
	}
	items, _ = Open(InboxInput{Paths: p})
	if len(items) != 2 {
		t.Fatalf("after undo of dismiss: %+v", items)
	}
	// Resolve, resolve again, undo once: still resolved by the first.
	_ = Resolve(p.StateDir, Resolution{ID: curl.ID, Action: ResolveAcknowledge})
	_ = Resolve(p.StateDir, Resolution{ID: curl.ID, Action: ResolveDismiss, Signature: Signature(curl)})
	if _, err := Undo(in, curl.ID); err != nil {
		t.Fatal(err)
	}
	items, _ = Open(InboxInput{Paths: p})
	if len(items) != 1 || items[0].ID != rm.ID {
		t.Fatalf("after one undo of two: %+v", items)
	}
	// Resolve accepts undo; the file keeps its format.
	if err := Resolve(p.StateDir, Resolution{ID: curl.ID, Action: ResolveUndo}); err != nil {
		t.Fatal(err)
	}
	if items, _ = Open(InboxInput{Paths: p}); len(items) != 2 {
		t.Fatalf("after Resolve undo: %+v", items)
	}
}

func TestUndoAddRuleRemovesRule(t *testing.T) {
	p := inboxEnv(t)
	user := filepath.Join(p.ClaudeDir, "settings.json")
	writeFile(t, user, seedSettings)
	in := Input{Paths: p}
	appendRec(t, p, activity.Record{Kind: activity.KindDecision, TS: ts(time.Hour), SessionID: "s", ToolUseID: "a",
		ToolName: "Read", Target: "~/.kube/config", Decision: "ask", Enforcement: activity.EnforcementGate, Reason: "kube"})
	items, err := Open(InboxInput{Paths: p})
	if err != nil || len(items) != 1 {
		t.Fatalf("%+v %v", items, err)
	}
	it := items[0]
	res, err := Apply(in, mustPropose(t, in, it.Fix[0]))
	if err != nil {
		t.Fatal(err)
	}
	if err := Resolve(p.StateDir, Resolution{ID: it.ID, Action: ResolveAddRule, RuleID: res.RowIDs[0]}); err != nil {
		t.Fatal(err)
	}
	if deny, _ := listAt(t, user, "permissions.deny"); !containsStr(deny, "Read(~/.kube/config)") {
		t.Fatalf("rule not added: %v", deny)
	}
	ur, err := Undo(in, it.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(ur.Written, []string{user}) {
		t.Errorf("undo result = %+v", ur)
	}
	if deny, _ := listAt(t, user, "permissions.deny"); containsStr(deny, "Read(~/.kube/config)") {
		t.Fatalf("rule still there: %v", deny)
	}
	if items, _ = Open(InboxInput{Paths: p}); len(items) != 1 {
		t.Fatalf("item not reopened: %+v", items)
	}
	// An add_rule whose rule watchdeck does not own: reported, nothing appended.
	writeFile(t, user, `{"permissions":{"deny":["Read(~/.kube/config)"]}}`)
	row := RowID(KindNativeDeny, "user", "permissions.deny", "Read(~/.kube/config)")
	if err := Resolve(p.StateDir, Resolution{ID: it.ID, Action: ResolveAddRule, RuleID: row}); err != nil {
		t.Fatal(err)
	}
	before := readBytes(t, filepath.Join(p.StateDir, InboxFile))
	if _, err := Undo(in, it.ID); !errors.Is(err, ErrNotOwned) {
		t.Fatalf("undo of a foreign rule: err = %v", err)
	}
	if after := readBytes(t, filepath.Join(p.StateDir, InboxFile)); string(after) != string(before) {
		t.Fatal("undo appended after a failed Remove")
	}
}

func TestUndoNothing(t *testing.T) {
	p := inboxEnv(t)
	in := Input{Paths: p}
	if _, err := Undo(in, "0123456789abcdef"); !errors.Is(err, ErrNothingToUndo) || !strings.Contains(err.Error(), `nothing to undo for inbox item "0123456789abcdef"`) {
		t.Fatalf("no resolution: err = %v", err)
	}
	if err := Resolve(p.StateDir, Resolution{ID: "0123456789abcdef", Action: ResolveAcknowledge}); err != nil {
		t.Fatal(err)
	}
	if _, err := Undo(in, "0123456789abcdef"); err != nil {
		t.Fatal(err)
	}
	if _, err := Undo(in, "0123456789abcdef"); !errors.Is(err, ErrNothingToUndo) {
		t.Fatalf("already undone: err = %v", err)
	}
}

func TestUndoRemovesEveryRow(t *testing.T) {
	p := inboxEnv(t)
	user := filepath.Join(p.ClaudeDir, "settings.json")
	writeFile(t, user, seedSettings)
	in := Input{Paths: p}
	res, err := Apply(in, mustPropose(t, in, AddRequest{Action: "deny", What: WhatPath, Value: "~/.kube/config"}))
	if err != nil || len(res.RowIDs) != 2 {
		t.Fatalf("%+v %v", res, err)
	}
	const id = "0123456789abcdef"
	if err := Resolve(p.StateDir, Resolution{ID: id, Action: ResolveAddRule, RuleIDs: res.RowIDs}); err != nil {
		t.Fatal(err)
	}
	// Both ids are written, and rule_id is the first.
	var line Resolution
	if err := json.Unmarshal(readBytes(t, filepath.Join(p.StateDir, InboxFile)), &line); err != nil {
		t.Fatal(err)
	}
	if line.RuleID != res.RowIDs[0] || !reflect.DeepEqual(line.RuleIDs, res.RowIDs) {
		t.Fatalf("line = %+v", line)
	}
	ur, err := Undo(in, id)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(ur.RowIDs, res.RowIDs) {
		t.Errorf("undo row ids = %v, want %v", ur.RowIDs, res.RowIDs)
	}
	deny, _ := listAt(t, user, "permissions.deny")
	if containsStr(deny, "Read(~/.kube/config)") || containsStr(deny, "Edit(~/.kube/config)") {
		t.Fatalf("strings still there: %v", deny)
	}
	if led := loadLedger(t, in); len(led.Entries) != 0 {
		t.Fatalf("ledger not empty: %+v", led.Entries)
	}

	// A failure part way stops there, names the id, appends nothing and
	// keeps the ledger in step with what was removed.
	res, err = Apply(in, mustPropose(t, in, AddRequest{Action: "deny", What: WhatPath, Value: "~/.kube/config"}))
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{res.RowIDs[0], "user:user-0000dead", res.RowIDs[1]}
	if err := Resolve(p.StateDir, Resolution{ID: id, Action: ResolveAddRule, RuleIDs: ids}); err != nil {
		t.Fatal(err)
	}
	before := readBytes(t, filepath.Join(p.StateDir, InboxFile))
	_, err = Undo(in, id)
	if err == nil || !strings.Contains(err.Error(), "user:user-0000dead") {
		t.Fatalf("partial undo: err = %v", err)
	}
	if after := readBytes(t, filepath.Join(p.StateDir, InboxFile)); string(after) != string(before) {
		t.Fatal("undo appended after a failed removal")
	}
	deny, _ = listAt(t, user, "permissions.deny")
	if containsStr(deny, "Read(~/.kube/config)") || !containsStr(deny, "Edit(~/.kube/config)") {
		t.Fatalf("after partial undo: %v", deny)
	}
	led := loadLedger(t, in)
	if len(led.Entries) != 1 || led.Entries[0].Value != "Edit(~/.kube/config)" {
		t.Fatalf("ledger after partial undo: %+v", led.Entries)
	}
}

func TestUndoReadsOldRuleIDLine(t *testing.T) {
	p := inboxEnv(t)
	user := filepath.Join(p.ClaudeDir, "settings.json")
	writeFile(t, user, seedSettings)
	in := Input{Paths: p}
	res, err := Apply(in, mustPropose(t, in, AddRequest{Action: "deny", What: WhatPath, Value: "~/.kube/config", Tool: PathRead}))
	if err != nil {
		t.Fatal(err)
	}
	// A line written before rule_ids existed.
	const id = "0123456789abcdef"
	writeFile(t, filepath.Join(p.StateDir, InboxFile),
		`{"v":1,"id":"`+id+`","action":"add_rule","ts":"2026-10-19T10:00:00Z","rule_id":"`+res.RowIDs[0]+`"}`+"\n")
	ur, err := Undo(in, id)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(ur.RowIDs, res.RowIDs) {
		t.Errorf("row ids = %v", ur.RowIDs)
	}
	if deny, _ := listAt(t, user, "permissions.deny"); containsStr(deny, "Read(~/.kube/config)") {
		t.Fatalf("string still there: %v", deny)
	}
}

// TestSuggestEverywhereSecondForWebFetch (Plan 08 D8, R12): a WebFetch
// item's one-click fix stays the one host rule, and its everywhere form
// comes right after it; a Bash item keeps its one ask (the twin is its
// everywhere form), an MCP item gets none. Both host fixes propose.
func TestSuggestEverywhereSecondForWebFetch(t *testing.T) {
	for _, kind := range []ItemKind{ItemDenial, ItemAsk, ItemRejection} {
		got := Suggest(Item{Kind: kind, What: "WebFetch · example.test"})
		if len(got) != 2 || got[0].Everywhere || got[0].What != WhatHost || got[0].Value != "example.test" ||
			!got[1].Everywhere || got[1].What != WhatHost || got[1].Value != "example.test" || got[1].Action != "deny" {
			t.Errorf("%s: %+v", kind, got)
		}
		if IntentFor(got[1]) == "" || IntentFor(got[0]) != "" {
			t.Errorf("%s: intents %q %q", kind, IntentFor(got[0]), IntentFor(got[1]))
		}
	}
	in := Input{Paths: testEnv(t)}
	plan, err := Propose(in, Suggest(Item{Kind: ItemDenial, What: "WebFetch · example.test"})[1])
	if err != nil || len(plan.Steps) < 3 || plan.Steps[0].Value != "WebFetch(domain:example.test)" {
		t.Fatalf("everywhere plan %+v %v", plan, err)
	}
	for _, s := range plan.Steps {
		if s.IntentID != IntentFor(AddRequest{What: WhatHost, Value: "example.test", Everywhere: true}) {
			t.Errorf("step %s carries intent %q", s.RowID, s.IntentID)
		}
	}
	for _, it := range []Item{{Kind: ItemDenial, What: "Bash · curl"}, {Kind: ItemAsk, What: "mcp__files__delete"}} {
		for _, f := range Suggest(it) {
			if f.Everywhere {
				t.Errorf("%s: an everywhere fix %+v", it.What, f)
			}
		}
	}
	// With a pack rule first the order is pack rule, host, everywhere host.
	_, _, key := firstPackRule(t)
	got := Suggest(Item{Kind: ItemAsk, What: "WebFetch · example.test", RuleIDs: []string{key}})
	if len(got) != 3 || got[0].What != WhatPackRule || got[1].Everywhere || !got[2].Everywhere {
		t.Errorf("with a pack rule: %+v", got)
	}
}

// TestSuggestLeakPathFix (Plan 08 R12, Task 5 fix round 1): a leak from one
// of the file tools (Read, Write, Edit, MultiEdit, NotebookEdit) gets a deny
// on reading that file, where the secret now sits, and its everywhere form;
// a Grep or Glob leak (its target is the search root), a Bash, WebFetch or
// reply leak, one whose target was dropped as secret-shaped, and one whose
// target was cut get none.
func TestSuggestLeakPathFix(t *testing.T) {
	cases := []struct {
		what string
		want []AddRequest
	}{
		{"Read · ~/proj/.env", []AddRequest{{Action: "deny", What: WhatPath, Value: "~/proj/.env", Tool: PathRead}, {Action: "deny", What: WhatPath, Value: "~/proj/.env", Everywhere: true}}},
		// A search's target is its root, not the file holding the secret.
		{"Grep · ~/proj", nil},
		{"Glob · ~/proj", nil},
		// The secret now sits in the file: the fix stops reading it again.
		{"Write · ~/proj/config.py", []AddRequest{{Action: "deny", What: WhatPath, Value: "~/proj/config.py", Tool: PathRead}, {Action: "deny", What: WhatPath, Value: "~/proj/config.py", Everywhere: true}}},
		{"Edit · ~/proj/config.py", []AddRequest{{Action: "deny", What: WhatPath, Value: "~/proj/config.py", Tool: PathRead}, {Action: "deny", What: WhatPath, Value: "~/proj/config.py", Everywhere: true}}},
		{"NotebookEdit · ~/proj/n.ipynb", []AddRequest{{Action: "deny", What: WhatPath, Value: "~/proj/n.ipynb", Tool: PathRead}, {Action: "deny", What: WhatPath, Value: "~/proj/n.ipynb", Everywhere: true}}},
		{"Bash · cat", nil},
		{"WebFetch · example.test", nil},
		{"Reply", nil},
		{"Read", nil},
	}
	for _, c := range cases {
		if got := Suggest(Item{Kind: KindLeak, What: c.what}); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: %+v, want %+v", c.what, got, c.want)
		}
	}
	// Through Open: a key-shaped target is dropped, so there is no fix.
	p := inboxEnv(t)
	key := "gh" + "p_" + strings.Repeat("A1b2", 9)
	items, err := Open(InboxInput{Paths: p, Leaks: []Leak{
		{SessionID: "s1", Ref: "toolu_1", Tool: "Read", Target: "~/proj/" + key, Where: "result", Pattern: "github-token", Label: "GitHub token", TS: time.Now().Add(-time.Minute)},
	}})
	if err != nil || len(items) != 1 {
		t.Fatalf("%+v %v", items, err)
	}
	if items[0].What != "Read" || items[0].Fix != nil || strings.Contains(fmt.Sprintf("%+v", items[0]), key[:9]) {
		t.Errorf("key-shaped target kept: %+v", items[0])
	}
	// A target the index cut (over 120 bytes) is shown with an ellipsis and
	// gets no fix: a rule on the cut path would match nothing.
	items, err = Open(InboxInput{Paths: p, Leaks: []Leak{
		{SessionID: "s1", Ref: "toolu_2", Tool: "Read", Target: "~/proj/" + strings.Repeat("d", 113), TargetCut: true, Where: "result", Pattern: "slack-token", Label: "Slack token", TS: time.Now().Add(-time.Minute)},
	}})
	if err != nil || len(items) != 1 {
		t.Fatalf("%+v %v", items, err)
	}
	if !strings.HasSuffix(items[0].What, "d…") || items[0].Fix != nil || Suggest(items[0]) != nil {
		t.Errorf("cut target: what %q fix %+v", items[0].What, items[0].Fix)
	}
}

// TestAllowForAndRefusals: the words AllowFor offers, and the sentence
// Allow refuses with, item by item; a refusal writes nothing.
func TestAllowForAndRefusals(t *testing.T) {
	_, _, key := firstPackRule(t)
	cases := []struct {
		it      Item
		allow   string
		refusal string // for "session"
	}{
		{Item{Kind: ItemAsk, SessionID: "s1", RuleIDs: []string{key, "user/no-prod"}}, "session,1h", ""},
		{Item{Kind: ItemAsk, RuleIDs: []string{key}}, "1h", "names no session"},
		{Item{Kind: ItemAsk, SessionID: "s1", RuleIDs: []string{key, "claude-settings/Bash(rm *)"}}, "", NativeRuleSentence},
		{Item{Kind: ItemAsk, SessionID: "s1", RuleIDs: []string{key}, bySubject: true}, "", "remove it instead"},
		{Item{Kind: ItemAsk, SessionID: "s1"}, "", "can be paused"},
		{Item{Kind: ItemDenial, SessionID: "s1"}, "", NativeRuleSentence},
		{Item{Kind: ItemRejection, SessionID: "s1"}, "", NativeRuleSentence},
		{Item{Kind: ItemSkillRequest, Ungranted: []UngrantedEdit{{Skill: "web", Field: "network", Value: "all"}}}, "1h", "not for one session"},
		{Item{Kind: ItemSandboxRefusal}, "", "open the skill"},
		{Item{Kind: KindLeak, SessionID: "s1"}, "", "nothing to allow"},
	}
	in := Input{Paths: testEnv(t)}
	for i, c := range cases {
		if got := strings.Join(AllowFor(c.it), ","); got != c.allow {
			t.Errorf("%d %s: AllowFor %q, want %q", i, c.it.Kind, got, c.allow)
		}
		if c.refusal == "" {
			continue
		}
		_, err := Allow(in, c.it, AllowSession)
		if !errors.Is(err, ErrAllowRefused) || !strings.Contains(err.Error(), c.refusal) {
			t.Errorf("%d %s: Allow session = %v, want %q", i, c.it.Kind, err, c.refusal)
		}
	}
	if _, err := os.Stat(in.Paths.OverridesFile()); !os.IsNotExist(err) {
		t.Errorf("a refused allow wrote the policy file: %v", err)
	}
}

// TestStepSentenceHidesHome: an everywhere path rule's hook step names the
// file once, with home as ~.
func TestStepSentenceHidesHome(t *testing.T) {
	p := testEnv(t)
	plan, err := Propose(Input{Paths: p}, AddRequest{Action: "deny", What: WhatPath, Value: "~/.netrc", Everywhere: true})
	if err != nil {
		t.Fatal(err)
	}
	var hook Step
	for _, s := range plan.Steps {
		if s.Mechanism == MechHook {
			hook = s
		}
	}
	if !strings.Contains(hook.Sentence, p.Home) {
		t.Fatalf("the raw sentence %q no longer names the expanded path; this test is vacuous", hook.Sentence)
	}
	got := StepSentence(p.Home, hook)
	if strings.Contains(got, p.Home) || strings.Count(got, "~/.netrc") != 1 {
		t.Errorf("StepSentence = %q", got)
	}
	if s := plan.Steps[0]; StepSentence(p.Home, s) != s.Sentence {
		t.Errorf("a native step's sentence changed: %q", StepSentence(p.Home, s))
	}
}

// TestUndoAllowIsOneWrite: Undo of an allow that paused two rules ends
// both in one write of the policy file (one backup), and one already
// ended is no reason to fail.
func TestUndoAllowIsOneWrite(t *testing.T) {
	p := inboxEnv(t)
	in := Input{Paths: p}
	packs := rules.Packs()
	if len(packs) == 0 || len(packs[0].Rules) < 2 {
		t.Fatalf("need a pack with two rules: %v", rules.LoadError())
	}
	a, b := packs[0].Name+"/"+packs[0].Rules[0].ID, packs[0].Name+"/"+packs[0].Rules[1].ID
	it := Item{ID: "item-1", Kind: ItemAsk, SessionID: "s1", RuleIDs: []string{a, b}}
	ids, err := Allow(in, it, AllowSession)
	if err != nil || len(ids) != 2 {
		t.Fatalf("Allow = %v %v", ids, err)
	}
	if err := Resolve(p.StateDir, Resolution{ID: it.ID, Action: ResolveAllow, TemporaryIDs: ids}); err != nil {
		t.Fatal(err)
	}
	res, err := Undo(in, it.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Backups) != 1 || len(res.Written) != 1 || len(ListTemporaries(in)) != 0 {
		t.Errorf("undo wrote %v (backups %v); temporaries %+v", res.Written, res.Backups, ListTemporaries(in))
	}
	// Again, with one of the two ended on the Rules page first.
	ids, err = Allow(in, it, AllowHour)
	if err != nil {
		t.Fatal(err)
	}
	if err := Resolve(p.StateDir, Resolution{ID: it.ID, Action: ResolveAllow, TemporaryIDs: ids}); err != nil {
		t.Fatal(err)
	}
	if err := End(in, ids[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := Undo(in, it.ID); err != nil || len(ListTemporaries(in)) != 0 {
		t.Errorf("undo with one already ended: %v; temporaries %+v", err, ListTemporaries(in))
	}
}

// TestAllowRefusesGoneRule: a rule on the item that is no longer in the
// policy file (removed since, or in a project file the page did not name)
// is a refusal, not a failure, and nothing is written.
func TestAllowRefusesGoneRule(t *testing.T) {
	in := Input{Paths: testEnv(t)}
	_, _, key := firstPackRule(t)
	_, err := Allow(in, Item{Kind: ItemAsk, SessionID: "s1", RuleIDs: []string{key, "user/gone-rule"}}, AllowHour)
	if !errors.Is(err, ErrAllowRefused) || !strings.Contains(err.Error(), "gone-rule") {
		t.Fatalf("Allow = %v", err)
	}
	if _, err := os.Stat(in.Paths.OverridesFile()); !os.IsNotExist(err) {
		t.Errorf("the policy file was written: %v", err)
	}
}

// TestUndoUsesResolutionProject: an add_rule resolution written at project
// scope carries the project root, and Undo removes its rows from that
// project's settings file with an Input that names no project (the CLI run
// from another directory, the dashboard with no ?project=) or another one.
func TestUndoUsesResolutionProject(t *testing.T) {
	p := inboxEnv(t)
	root := filepath.Join(p.Home, "proj")
	if err := os.MkdirAll(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	proj := paths.ProjectSettings(root)
	user := filepath.Join(p.ClaudeDir, "settings.json")
	inP := Input{Paths: p, ProjectRoot: root}
	req := AddRequest{Action: "ask", What: WhatCommand, Value: "curl", Scope: claudesettings.ScopeProject}
	want := RowID(KindNativeAsk, claudesettings.ScopeProject, claudesettings.KeyAsk, "Bash(curl *)")
	for i, from := range []Input{{Paths: p}, {Paths: p, ProjectRoot: filepath.Join(p.Home, "other")}} {
		id := fmt.Sprintf("%016d", i)
		res, err := Apply(inP, mustPropose(t, inP, req))
		if err != nil {
			t.Fatal(err)
		}
		if len(res.RowIDs) != 1 || res.RowIDs[0] != want {
			t.Fatalf("rows = %v, want [%s]", res.RowIDs, want)
		}
		if ask, _ := listAt(t, proj, "permissions.ask"); !containsStr(ask, "Bash(curl *)") {
			t.Fatalf("rule not added to %s: %v", proj, ask)
		}
		if err := Resolve(p.StateDir, Resolution{ID: id, Action: ResolveAddRule, RuleIDs: res.RowIDs, Project: root}); err != nil {
			t.Fatal(err)
		}
		ur, err := Undo(from, id)
		if err != nil {
			t.Fatalf("undo %d: %v", i, err)
		}
		if !reflect.DeepEqual(ur.Written, []string{proj}) || !reflect.DeepEqual(ur.RowIDs, []string{want}) {
			t.Errorf("undo %d result = %+v", i, ur)
		}
		if ask, _ := listAt(t, proj, "permissions.ask"); containsStr(ask, "Bash(curl *)") {
			t.Errorf("undo %d left the rule in %s: %v", i, proj, ask)
		}
		if _, err := os.Stat(user); !os.IsNotExist(err) {
			t.Errorf("undo %d touched the user settings file: %v", i, err)
		}
		live, err := readResolutions(p.StateDir)
		if err != nil || len(live[id]) != 0 {
			t.Errorf("undo %d: resolutions in force %+v, %v", i, live[id], err)
		}
	}
	// The caller's Input is not changed by the override.
	from := Input{Paths: p}
	if err := Resolve(p.StateDir, Resolution{ID: "0000000000000099", Action: ResolveAcknowledge, Project: root}); err != nil {
		t.Fatal(err)
	}
	if _, err := Undo(from, "0000000000000099"); err != nil || from.ProjectRoot != "" {
		t.Errorf("undo of an acknowledge: %v, ProjectRoot %q", err, from.ProjectRoot)
	}
}
