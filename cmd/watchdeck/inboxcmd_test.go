package main

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/activity"
	"github.com/Panda-Taps-LLC/watchdeck/internal/claudesettings"
	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
	"github.com/Panda-Taps-LLC/watchdeck/internal/policy"
	"github.com/Panda-Taps-LLC/watchdeck/internal/rulebook"
	"github.com/Panda-Taps-LLC/watchdeck/internal/rules"
)

func TestInboxListsAndResolves(t *testing.T) {
	e := rulesEnv(t)
	settingsPath := filepath.Join(e.claude, "settings.json")
	writeFile(t, settingsPath, "{}\n")
	ago := func(d time.Duration) string { return time.Now().Add(-d).UTC().Format(time.RFC3339Nano) }
	for _, r := range []activity.Record{
		{Kind: activity.KindDenied, TS: ago(3 * time.Hour), SessionID: "s1", ToolUseID: "t1", Cwd: e.proj,
			ToolName: "Bash", Argv0: "curl", Reason: "auto mode blocked a network download"},
		{Kind: activity.KindDenied, TS: ago(2 * time.Hour), SessionID: "s1", ToolUseID: "t2", Cwd: e.proj,
			ToolName: "WebFetch", Target: "example.test", Reason: "auto mode blocked a fetch"},
		{Kind: activity.KindDenied, TS: ago(time.Hour), SessionID: "s1", ToolUseID: "t3", Cwd: e.proj,
			ToolName: "Bash", Argv0: "wget", Reason: "auto mode blocked a download"},
		{Kind: activity.KindDecision, TS: ago(4 * time.Hour), SessionID: "s1", ToolUseID: "t4", Cwd: e.proj,
			ToolName: "Bash", Command: "python3 scripts/fetch.py", Skills: []string{"fetcher"}, Decision: "ask",
			Enforcement: activity.EnforcementSandbox, Ungranted: []string{"fetcher: network: all"}},
	} {
		if err := activity.Append(e.activityPath(), r); err != nil {
			t.Fatal(err)
		}
	}
	code, out, errs := call(t, inboxCmd)
	if code != 0 {
		t.Fatalf("exit %d\n%s%s", code, out, errs)
	}
	// A Bash item suggests an ask on the program, and a path rule as the
	// alternative when a file was the target.
	for _, want := range []string{"denial", "Bash · curl", "auto mode blocked a network download",
		"    fix: watchdeck rules add --ask --command curl\n       or a path rule if a file was the target: watchdeck rules add --block --read <path>\n",
		"--domain example.test"} {
		if !strings.Contains(out, want) {
			t.Errorf("inbox lacks %q:\n%s", want, out)
		}
	}
	if i, j := strings.Index(out, "wget"), strings.Index(out, "curl"); i < 0 || j < 0 || i > j {
		t.Errorf("not newest first:\n%s", out)
	}
	code, out, _ = call(t, inboxCmd, "--json")
	if code != 0 {
		t.Fatalf("--json exit %d", code)
	}
	var items []rulebook.Item
	if err := json.Unmarshal([]byte(out), &items); err != nil || len(items) != 4 {
		t.Fatalf("--json: %v, %d items\n%s", err, len(items), out)
	}
	byWhat := map[string]rulebook.Item{}
	for _, it := range items {
		byWhat[it.What] = it
	}
	curl, fetch, wget := byWhat["Bash · curl"], byWhat["WebFetch · example.test"], byWhat["Bash · wget"]
	var skillReq rulebook.Item
	for _, it := range items {
		if it.Kind == rulebook.ItemSkillRequest {
			skillReq = it
		}
	}
	if curl.ID == "" || fetch.ID == "" || wget.ID == "" || skillReq.ID == "" || len(skillReq.Fix) != 0 {
		t.Fatalf("items: %+v", items)
	}
	_, out, _ = call(t, inboxCmd)
	if want := "fix: watchdeck rules grant fetcher … then watchdeck inbox resolve " + skillReq.ID + " ack"; !strings.Contains(out, want) {
		t.Errorf("inbox lacks %q:\n%s", want, out)
	}
	// add on an item with no rule to add: exit 1, nothing written.
	code, out, _ = call(t, inboxCmd, "resolve", skillReq.ID, "add", "--yes")
	if code != 1 || !strings.Contains(out, "this item has no rule to add; use ack or dismiss") {
		t.Errorf("add on skill_request: exit %d\n%s", code, out)
	}
	if len(backups(t, settingsPath)) != 0 {
		t.Errorf("add on skill_request wrote settings")
	}
	if code, _, _ := call(t, inboxCmd, "resolve", skillReq.ID, "ack"); code != 0 {
		t.Errorf("ack skill_request exit %d", code)
	}

	// add without --yes and no terminal prints the rule and the plan and exits 1.
	rule := "rule: watchdeck rules add --ask --command curl\n"
	if code, out, _ := call(t, inboxCmd, "resolve", curl.ID, "add"); code != 1 || !strings.Contains(out, "Bash(curl *)") || !strings.HasPrefix(out, rule) {
		t.Fatalf("no tty: exit %d\n%s", code, out)
	}
	// With --yes the exact rule is printed too, before anything is written.
	code, out, errs = call(t, inboxCmd, "resolve", curl.ID, "add", "--yes")
	if code != 0 {
		t.Fatalf("resolve add exit %d\n%s%s", code, out, errs)
	}
	if !strings.HasPrefix(out, rule) || strings.Index(out, rule) > strings.Index(out, "wrote ") {
		t.Errorf("--yes: the rule is not printed first:\n%s", out)
	}
	if !has(settingsList(t, settingsPath, "ask"), "Bash(curl *)") || has(settingsList(t, settingsPath, "deny"), "Bash(curl *)") {
		t.Errorf("want Bash(curl *) in ask only: ask %v deny %v", settingsList(t, settingsPath, "ask"), settingsList(t, settingsPath, "deny"))
	}
	if !strings.Contains(out, "backup") {
		t.Errorf("no backup line:\n%s", out)
	}
	if code, _, _ := call(t, inboxCmd, "resolve", fetch.ID, "ack"); code != 0 {
		t.Errorf("ack exit %d", code)
	}
	if code, _, _ := call(t, inboxCmd, "resolve", wget.ID, "dismiss"); code != 0 {
		t.Errorf("dismiss exit %d", code)
	}
	code, out, _ = call(t, inboxCmd)
	if code != 0 || strings.Contains(out, curl.ID) || strings.Contains(out, fetch.ID) || strings.Contains(out, wget.ID) || strings.Contains(out, skillReq.ID) {
		t.Errorf("resolved items still listed (exit %d):\n%s", code, out)
	}
	if !strings.Contains(out, "nothing needs you") {
		t.Errorf("empty inbox line missing:\n%s", out)
	}
	if code, _, errs := call(t, inboxCmd, "resolve", "0123456789abcdef", "ack"); code != 2 {
		t.Errorf("unknown id: exit %d\n%s", code, errs)
	}
}

// TestInboxActivityOffSaysSo: with the activity log off the inbox can list
// transcript rejections only, and says so instead of "nothing needs you".
// TestInboxPackRuleFix: an item a built-in pack rule fired on suggests
// raising that rule to block, which no rules add flag spells, so the
// inbox names it and points at resolve add; resolve add sets the override.
func TestInboxPackRuleFix(t *testing.T) {
	e := rulesEnv(t)
	writeFile(t, filepath.Join(e.claude, "settings.json"), "{}\n")
	packs := rules.Packs()
	if len(packs) == 0 || len(packs[0].Rules) == 0 {
		t.Fatalf("no built-in packs: %v", rules.LoadError())
	}
	pack, id := packs[0].Name, packs[0].Rules[0].ID
	key := pack + "/" + id
	r := activity.Record{Kind: activity.KindDecision, TS: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano),
		SessionID: "s1", ToolUseID: "t1", Cwd: e.proj, ToolName: "Read", Target: "~/.netrc", Decision: "ask",
		Enforcement: activity.EnforcementGate, Reason: "netrc", Rules: []activity.RuleHit{{Pack: pack, ID: id, Action: "ask"}}}
	if err := activity.Append(e.activityPath(), r); err != nil {
		t.Fatal(err)
	}
	code, out, errs := call(t, inboxCmd, "--json")
	var items []rulebook.Item
	if code != 0 || json.Unmarshal([]byte(out), &items) != nil || len(items) != 1 {
		t.Fatalf("--json exit %d: %s%s", code, out, errs)
	}
	itemID := items[0].ID
	code, out, errs = call(t, inboxCmd)
	if code != 0 {
		t.Fatalf("exit %d\n%s%s", code, out, errs)
	}
	want := "    fix: set the watchdeck rule " + key + " to block: watchdeck inbox resolve " + itemID + " add\n" +
		"       or: watchdeck rules add --block --read '~/.netrc'\n"
	if !strings.Contains(out, want) {
		t.Errorf("inbox lacks %q:\n%s", want, out)
	}
	code, out, errs = call(t, inboxCmd, "resolve", itemID, "add", "--yes")
	if code != 0 {
		t.Fatalf("resolve add exit %d\n%s%s", code, out, errs)
	}
	if !strings.Contains(out, "rule: set the watchdeck rule "+key+" to block\n") {
		t.Errorf("resolve add lacks the rule line:\n%s", out)
	}
	f, _, err := policy.LoadFile(filepath.Join(e.cfg, paths.BinaryName, "overrides.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if tg := f.RuleOverrides[key]; tg.Action != "deny" {
		t.Errorf("override = %+v, want action deny", tg)
	}
}

func TestInboxActivityOffSaysSo(t *testing.T) {
	e := rulesEnv(t)
	writeFile(t, filepath.Join(e.claude, "settings.json"), "{}\n")
	t.Setenv("WATCHDECK_ACTIVITY", "off")
	code, out, errs := call(t, inboxCmd)
	if code != 0 {
		t.Fatalf("exit %d\n%s%s", code, out, errs)
	}
	want := "the activity log is off (WATCHDECK_ACTIVITY=off): only transcript rejections can be listed\n"
	if out != want {
		t.Errorf("output %q, want %q", out, want)
	}
}

// TestInboxResolveUndo: undo reopens a resolved item; after an add it
// removes the rule the add wrote first and names it.
func TestInboxResolveUndo(t *testing.T) {
	e := rulesEnv(t)
	settingsPath := filepath.Join(e.claude, "settings.json")
	writeFile(t, settingsPath, "{}\n")
	ago := func(d time.Duration) string { return time.Now().Add(-d).UTC().Format(time.RFC3339Nano) }
	for _, r := range []activity.Record{
		{Kind: activity.KindDenied, TS: ago(2 * time.Hour), SessionID: "s1", ToolUseID: "t1", Cwd: e.proj,
			ToolName: "Bash", Argv0: "curl", Reason: "auto mode blocked a network download"},
		{Kind: activity.KindDenied, TS: ago(time.Hour), SessionID: "s1", ToolUseID: "t2", Cwd: e.proj,
			ToolName: "WebFetch", Target: "example.test", Reason: "auto mode blocked a fetch"},
	} {
		if err := activity.Append(e.activityPath(), r); err != nil {
			t.Fatal(err)
		}
	}
	_, out, _ := call(t, inboxCmd, "--json")
	var items []rulebook.Item
	if err := json.Unmarshal([]byte(out), &items); err != nil || len(items) != 2 {
		t.Fatalf("--json: %v\n%s", err, out)
	}
	var curl, fetch string
	for _, it := range items {
		switch it.What {
		case "Bash · curl":
			curl = it.ID
		case "WebFetch · example.test":
			fetch = it.ID
		}
	}
	if code, out, errs := call(t, inboxCmd, "resolve", curl, "add", "--yes"); code != 0 {
		t.Fatalf("add: exit %d\n%s%s", code, out, errs)
	}
	if !has(settingsList(t, settingsPath, "ask"), "Bash(curl *)") {
		t.Fatal("add did not write Bash(curl *)")
	}
	if code, _, _ := call(t, inboxCmd, "resolve", fetch, "ack"); code != 0 {
		t.Fatal("ack failed")
	}
	if _, out, _ := call(t, inboxCmd); !strings.Contains(out, "nothing needs you") {
		t.Fatalf("resolved items listed:\n%s", out)
	}

	// no terminal, no --yes: nothing undone
	if code, out, _ := call(t, inboxCmd, "resolve", curl, "undo"); code != 1 || !strings.Contains(out, "Not undone") {
		t.Fatalf("no tty: exit %d\n%s", code, out)
	}
	if !has(settingsList(t, settingsPath, "ask"), "Bash(curl *)") {
		t.Fatal("an unconfirmed undo removed the rule")
	}

	row := rulebook.RowID(rulebook.KindNativeAsk, claudesettings.ScopeUser, claudesettings.KeyAsk, "Bash(curl *)")
	code, out, errs := call(t, inboxCmd, "resolve", curl, "undo", "--yes")
	if code != 0 || !strings.Contains(out, "removed "+row+"\n") || !strings.HasSuffix(out, "reopened "+curl+"\n") || !strings.Contains(out, "backup ") {
		t.Fatalf("undo add: exit %d\n%s%s", code, out, errs)
	}
	if has(settingsList(t, settingsPath, "ask"), "Bash(curl *)") {
		t.Error("undo left Bash(curl *) in the settings")
	}
	// an undo of an ack removes nothing
	code, out, errs = call(t, inboxCmd, "resolve", fetch, "undo", "--yes")
	if code != 0 || strings.Contains(out, "removed ") || !strings.HasSuffix(out, "reopened "+fetch+"\n") {
		t.Fatalf("undo ack: exit %d\n%s%s", code, out, errs)
	}
	_, out, _ = call(t, inboxCmd)
	if !strings.Contains(out, curl) || !strings.Contains(out, fetch) {
		t.Errorf("undone items not back in the inbox:\n%s", out)
	}
	if code, _, errs := call(t, inboxCmd, "resolve", curl, "undo", "--yes"); code != 2 || !strings.Contains(errs, "nothing to undo") {
		t.Errorf("second undo: exit %d\n%s", code, errs)
	}
}
