package rulebook

import (
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"testing"
	"time"
)

// TestInboxLeakItems: each Leak the caller passes (leak watch, DESIGN §14)
// is an item of kind leak, with the brief's id, what, why and authority;
// a file leak gets the path deny and its everywhere form (Plan 08 Task 5),
// a reply none; a dismiss suppresses the same tool, target, pattern and
// place in a later call.
func TestInboxLeakItems(t *testing.T) {
	p := inboxEnv(t)
	now := time.Now()
	leaks := []Leak{
		{SessionID: "s1", Ref: "toolu_1", Tool: "Read", Target: "~/proj/.env", Where: "result",
			Pattern: "slack-token", Label: "Slack token", Agent: "a1b2", Project: "~/proj", TS: now.Add(-2 * time.Hour)},
		{SessionID: "s1", Ref: "uuid-2", Where: "reply", Pattern: "github-token", Label: "GitHub token",
			Project: "~/proj", TS: now.Add(-time.Hour)},
		{SessionID: "s1", Ref: "toolu_3", Tool: "Bash", Target: "curl", Where: "input",
			Pattern: "stripe-live", Label: "Stripe live key", TS: now.Add(-8 * 24 * time.Hour)}, // before the window
	}
	items, err := Open(InboxInput{Paths: p, Leaks: leaks})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 {
		t.Fatalf("items: %+v", items)
	}
	reply, result := items[0], items[1] // newest first
	sum := sha256.Sum256([]byte("s1\x00toolu_1\x00leak"))
	if result.ID != hex.EncodeToString(sum[:])[:16] {
		t.Errorf("result id %s", result.ID)
	}
	if result.Kind != KindLeak || result.What != "Read · ~/proj/.env" || result.Why != "Slack token appeared in the result" ||
		result.Authority != "leak" || result.ToolUseID != "toolu_1" || result.SessionID != "s1" || result.Agent != "a1b2" ||
		result.Project != "~/proj" || result.Harness != "claude-code" || result.RuleIDs != nil {
		t.Errorf("result item: %+v", result)
	}
	sum = sha256.Sum256([]byte("s1\x00uuid-2\x00leak"))
	if reply.ID != hex.EncodeToString(sum[:])[:16] || reply.Kind != KindLeak || reply.What != "Reply" ||
		reply.Why != "GitHub token appeared in the reply" || reply.ToolUseID != "" || reply.Authority != "leak" || reply.Fix != nil {
		t.Errorf("reply item: %+v", reply)
	}
	wantFix := []AddRequest{
		{Action: "deny", What: WhatPath, Value: "~/proj/.env", Tool: PathRead},
		{Action: "deny", What: WhatPath, Value: "~/proj/.env", Everywhere: true},
	}
	if !reflect.DeepEqual(result.Fix, wantFix) || !reflect.DeepEqual(Suggest(result), wantFix) {
		t.Errorf("result fix %+v, want %+v", result.Fix, wantFix)
	}

	// Dismiss the result item: a later leak of the same pattern from the
	// same tool and target, in the same place, stays out; another pattern
	// does not.
	if err := Resolve(p.StateDir, Resolution{ID: result.ID, Action: ResolveDismiss, Signature: Signature(result)}); err != nil {
		t.Fatal(err)
	}
	leaks = append(leaks,
		Leak{SessionID: "s2", Ref: "toolu_9", Tool: "Read", Target: "~/proj/.env", Where: "result",
			Pattern: "slack-token", Label: "Slack token", TS: now.Add(-time.Minute)},
		Leak{SessionID: "s2", Ref: "toolu_10", Tool: "Read", Target: "~/proj/.env", Where: "result",
			Pattern: "github-token", Label: "GitHub token", TS: now.Add(-time.Minute)})
	items, err = Open(InboxInput{Paths: p, Leaks: leaks})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 || items[0].ToolUseID != "toolu_10" || items[1].ID != reply.ID {
		t.Fatalf("after dismiss: %+v", items)
	}
}

// A leak whose tool is not known and that has no target is named by the
// tool word alone.
func TestInboxLeakWhatWithoutTarget(t *testing.T) {
	p := inboxEnv(t)
	items, err := Open(InboxInput{Paths: p, Leaks: []Leak{{SessionID: "s", Ref: "r", Tool: "unknown", Where: "result",
		Pattern: "slack-token", Label: "Slack token", TS: time.Now()}}})
	if err != nil || len(items) != 1 || items[0].What != "unknown" {
		t.Fatalf("%+v %v", items, err)
	}
}

// TestInboxLeakNotHiddenByExistingRule (Plan 08 final review I1): a leak is
// a report of something that already happened, so a rule that already
// blocks reading the file does not hide it. A Write leak of ~/proj/.env is
// listed with an empty Book and with a Book that holds Read(~/proj/.env).
func TestInboxLeakNotHiddenByExistingRule(t *testing.T) {
	p := inboxEnv(t)
	leaks := []Leak{{SessionID: "s1", Ref: "toolu_1", Tool: "Write", Target: "~/proj/.env", Where: "input",
		Pattern: "slack-token", Label: "Slack token", TS: time.Now().Add(-time.Minute)}}
	for name, book := range map[string]*Book{
		"empty book": {},
		"read denied": {Groups: []Group{{ID: "native", Rows: []Rule{
			{Kind: KindNativeDeny, State: StateOn, Value: "Read(~/proj/.env)"},
		}}}},
	} {
		items, err := Open(InboxInput{Paths: p, Leaks: leaks, Book: book})
		if err != nil {
			t.Fatal(err)
		}
		if len(items) != 1 || items[0].Kind != KindLeak {
			t.Errorf("%s: %d items, want the one leak: %+v", name, len(items), items)
		}
	}
}
