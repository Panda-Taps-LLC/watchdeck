package rulebook

import (
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/activity"
	"github.com/Panda-Taps-LLC/watchdeck/internal/manifest"
	"github.com/Panda-Taps-LLC/watchdeck/internal/policy"
)

const tempUserRules = "version: 2\nrules:\n  - {id: no-prod-db, tool: Bash, match: {regex: 'psql .*prod'}, action: deny}\n"

func loadTemps(t *testing.T, in Input) []manifest.Temporary {
	t.Helper()
	f, _, err := policy.LoadFile(in.Paths.OverridesFile())
	if err != nil {
		t.Fatal(err)
	}
	return f.Temporary
}

func near(t *testing.T, got, want time.Time) {
	t.Helper()
	if d := got.Sub(want); d < -5*time.Second || d > 5*time.Second {
		t.Fatalf("time %s, want about %s", got, want)
	}
}

func TestPauseWritesOneTemporaryPerRow(t *testing.T) {
	in := Input{Paths: testEnv(t)}
	writeFile(t, in.Paths.OverridesFile(), tempUserRules)
	got, err := Pause(in, []string{"pack:pipe-to-shell/curl-pipe-shell", "user:no-prod-db", "pack:pipe-to-shell/curl-pipe-shell"}, "1h")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Rule != "pipe-to-shell/curl-pipe-shell" || got[1].Rule != "user/no-prod-db" || !got[0].Until.Equal(got[1].Until) {
		t.Fatalf("paused %+v", got)
	}
	near(t, got[0].Until, time.Now().Add(time.Hour))
	file := loadTemps(t, in)
	if len(file) != 2 || file[0].ID != got[0].ID || file[1].ID != got[1].ID || file[0].Session != "" || file[0].Kind != manifest.TempRule {
		t.Fatalf("file %+v", file)
	}
	// session=<id>: bound to that session, with the 8 h backstop.
	s, err := Pause(in, []string{"pack:secrets-read/ssh-private-key"}, "session=abc-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(s) != 1 || s[0].Session != "abc-1" || !s[0].Until.Equal(s[0].Added.Add(manifest.SessionBackstop)) {
		t.Fatalf("session pause %+v", s)
	}
	if _, err := Pause(in, []string{"pack:secrets-read/ssh-private-key"}, "8h"); err != nil {
		t.Fatal(err)
	}
	// Pausing a paused rule again replaces its entry (same sessions), so
	// there is never a second one: here 1h becomes 8h.
	re, err := Pause(in, []string{"user:no-prod-db"}, "8h")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, x := range loadTemps(t, in) {
		if x.Rule == "user/no-prod-db" {
			n++
			if x.ID != re[0].ID || !x.Until.Equal(re[0].Until) {
				t.Fatalf("re-pause kept the old entry: %+v", x)
			}
		}
	}
	if n != 1 {
		t.Fatalf("%d entries for one rule", n)
	}
	near(t, re[0].Until, time.Now().Add(8*time.Hour))
	for _, bad := range []string{"", "2h", "1h ", "session=", "session=-x", "forever"} {
		if _, err := Pause(in, []string{"user:no-prod-db"}, bad); err == nil {
			t.Errorf("for %q accepted", bad)
		}
	}
	// An unknown pack or user rule is refused, and so is no row at all.
	for _, ids := range [][]string{{"pack:pipe-to-shell/nope"}, {"user:nope"}, {}} {
		if _, err := Pause(in, ids, "1h"); err == nil {
			t.Errorf("%q accepted", ids)
		}
	}
	// The policy view agrees.
	p, _, err := policy.Load(in.Paths.OverridesFile(), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := p.Paused("user", "no-prod-db", "x"); !ok {
		t.Fatal("not paused")
	}
	if _, ok := p.Paused("secrets-read", "ssh-private-key", "other"); !ok {
		t.Fatal("8h pause not in force")
	}
}

func TestPauseRefusesNativeRowWritesNothing(t *testing.T) {
	in := Input{Paths: testEnv(t)}
	writeFile(t, in.Paths.OverridesFile(), tempUserRules)
	before := readBytes(t, in.Paths.OverridesFile())
	for _, c := range []struct{ id, sentence string }{
		{"native:user:permissions.deny:abcd1234", "Claude Code's own rule; change it in Claude Code"},
		{"automode:user:autoMode.soft_deny:abcd1234", "Claude Code's own rule; change it in Claude Code"},
		{"subject:skill:web", "a skill's sandbox grant; use watchdeck allow web --for 1h"},
		{"subject:skill:web:0a1b2c3d", "a skill's sandbox grant; use watchdeck allow web --for 1h"},
		{"subject:tool:files", "remove it instead"},
	} {
		_, err := Pause(in, []string{"pack:pipe-to-shell/curl-pipe-shell", c.id}, "1h")
		if !errors.Is(err, ErrNotPausable) {
			t.Fatalf("%s: %v", c.id, err)
		}
		if !strings.Contains(err.Error(), c.sentence) {
			t.Fatalf("%s: sentence %q, want %q", c.id, err, c.sentence)
		}
	}
	if got := readBytes(t, in.Paths.OverridesFile()); string(got) != string(before) {
		t.Fatalf("file changed:\n%s", got)
	}
}

// TestInboxItemsCarryUngranted (R11): a skill request carries one edit
// per ungranted item; a sandbox refusal with a network hint carries
// network all per skill; a write hint carries nothing (its line is the
// script's output, never a policy value).
func TestInboxItemsCarryUngranted(t *testing.T) {
	p := inboxEnv(t)
	appendRec(t, p, activity.Record{Kind: activity.KindDecision, TS: ts(time.Minute), SessionID: "s", ToolUseID: "toolu_1", ToolName: "Bash",
		Decision: "ask", Enforcement: activity.EnforcementSandbox, Skills: []string{"web"},
		Ungranted: []string{"web: network: all", "web: write: ${CWD}/out", "web: exec: /bin/x", "bad"}})
	appendRec(t, p, activity.Record{Kind: activity.KindRun, TS: ts(30 * time.Second), SessionID: "s", ToolUseID: "toolu_2", Skills: []string{"web"},
		Command: "python3 get.py", Outcome: activity.OutcomeFailed, Hints: []activity.Hint{{Kind: activity.HintNetwork, Text: "network access refused by the OS (EPERM)"}}})
	appendRec(t, p, activity.Record{Kind: activity.KindRun, TS: ts(20 * time.Second), SessionID: "s", ToolUseID: "toolu_3", Skills: []string{"web"},
		Command: "python3 put.py", Outcome: activity.OutcomeFailed, Hints: []activity.Hint{{Kind: activity.HintWrite, Line: "x: /Users/you/.ssh: Operation not permitted", Text: "write outside the allowed paths refused (EPERM)"}}})
	items, err := Open(InboxInput{Paths: p})
	if err != nil {
		t.Fatal(err)
	}
	var req, netRefusal, writeRefusal *Item
	for i := range items {
		switch {
		case items[i].Kind == ItemSkillRequest:
			req = &items[i]
		case items[i].Kind == ItemSandboxRefusal && items[i].ToolUseID == "toolu_2":
			netRefusal = &items[i]
		case items[i].Kind == ItemSandboxRefusal && items[i].ToolUseID == "toolu_3":
			writeRefusal = &items[i]
		}
	}
	if req == nil || netRefusal == nil || writeRefusal == nil {
		t.Fatalf("items %+v", items)
	}
	want := []UngrantedEdit{{Skill: "web", Field: "network", Value: "all"}, {Skill: "web", Field: "write", Value: "${CWD}/out"}}
	if !reflect.DeepEqual(req.Ungranted, want) {
		t.Errorf("skill request %+v", req.Ungranted)
	}
	if !reflect.DeepEqual(netRefusal.Ungranted, []UngrantedEdit{{Skill: "web", Field: "network", Value: "all"}}) {
		t.Errorf("network refusal %+v", netRefusal.Ungranted)
	}
	if len(writeRefusal.Ungranted) != 0 {
		t.Errorf("write refusal %+v", writeRefusal.Ungranted)
	}
}

func TestGrantForWritesTimedGrant(t *testing.T) {
	in := Input{Paths: testEnv(t)}
	tmp, err := GrantFor(in, "web", []UngrantedEdit{{Skill: "web", Field: "network", Value: "all"}, {Skill: "web", Field: "write", Value: "${CWD}/out"}}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if tmp.Kind != manifest.TempGrant || tmp.Skill != "web" || tmp.Grant == nil || tmp.Grant.Network == nil || *tmp.Grant.Network != manifest.NetAll ||
		!reflect.DeepEqual(tmp.Grant.Write, []string{"${CWD}/out"}) || tmp.Grant.AutoAllow != nil || !manifest.ValidTemporaryID(tmp.ID) {
		t.Fatalf("temporary %+v", tmp)
	}
	near(t, tmp.Until, time.Now().Add(time.Hour))
	file := loadTemps(t, in)
	if len(file) != 1 || file[0].ID != tmp.ID {
		t.Fatalf("file %+v", file)
	}
	user, _, err := manifest.LoadOverrides(in.Paths.ConfigDir, "")
	if err != nil {
		t.Fatal(err)
	}
	if eff, _ := manifest.Grant("web", user, manifest.Overrides{}); eff.Network != manifest.NetAll {
		t.Fatalf("grant network %v", eff.Network)
	}
	// The permanent grant is untouched.
	f, _, _ := policy.LoadFile(in.Paths.OverridesFile())
	if len(f.Subjects) != 0 {
		t.Fatalf("subjects written %+v", f.Subjects)
	}
	// An edit for another skill is refused.
	if _, err := GrantFor(in, "web", []UngrantedEdit{{Skill: "pdf", Field: "network", Value: "all"}}, time.Hour); err == nil {
		t.Fatal("edit for another skill accepted")
	}
}

func TestGrantForRefusesAutoAllow(t *testing.T) {
	in := Input{Paths: testEnv(t)}
	writeFile(t, in.Paths.OverridesFile(), tempUserRules)
	before := readBytes(t, in.Paths.OverridesFile())
	cases := []struct {
		edits []UngrantedEdit
		d     time.Duration
	}{
		{[]UngrantedEdit{{Skill: "web", Field: "auto_allow", Value: "true"}}, time.Hour},
		{[]UngrantedEdit{{Skill: "web", Field: "network", Value: "all"}, {Skill: "web", Field: "auto_allow", Value: "true"}}, time.Hour},
		{[]UngrantedEdit{{Skill: "web", Field: "network", Value: "all"}}, 0},
		{[]UngrantedEdit{{Skill: "web", Field: "network", Value: "all"}}, 9 * time.Hour},
		{[]UngrantedEdit{{Skill: "web", Field: "write", Value: "~/.ssh"}}, time.Hour},
		{[]UngrantedEdit{{Skill: "web", Field: "network", Value: "lots"}}, time.Hour},
		{nil, time.Hour},
	}
	for i, c := range cases {
		if _, err := GrantFor(in, "web", c.edits, c.d); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	if _, err := GrantFor(in, "*", []UngrantedEdit{{Skill: "*", Field: "network", Value: "all"}}, time.Hour); err == nil {
		t.Error("* accepted")
	}
	if got := readBytes(t, in.Paths.OverridesFile()); string(got) != string(before) {
		t.Fatalf("file changed:\n%s", got)
	}
}

func TestEndRemovesEntry(t *testing.T) {
	in := Input{Paths: testEnv(t)}
	writeFile(t, in.Paths.OverridesFile(), tempUserRules)
	ps, err := Pause(in, []string{"user:no-prod-db", "pack:pipe-to-shell/curl-pipe-shell"}, "session=s1")
	if err != nil {
		t.Fatal(err)
	}
	g, err := GrantFor(in, "web", []UngrantedEdit{{Skill: "web", Field: "network", Value: "all"}}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	views := ListTemporaries(in)
	if len(views) != 3 {
		t.Fatalf("views %+v", views)
	}
	for _, v := range views {
		if v.ID == "" || v.Sentence == "" || v.Until == "" || (v.Kind == manifest.TempRule && v.Session != "s1") {
			t.Errorf("view %+v", v)
		}
	}
	if err := End(in, ps[0].ID); err != nil {
		t.Fatal(err)
	}
	if got := loadTemps(t, in); len(got) != 2 || got[0].ID != ps[1].ID || got[1].ID != g.ID {
		t.Fatalf("after end %+v", got)
	}
	if err := End(in, ps[0].ID); err == nil {
		t.Fatal("ending an absent id succeeded")
	}
	if err := End(in, "all"); err != nil {
		t.Fatal(err)
	}
	if got := loadTemps(t, in); len(got) != 0 {
		t.Fatalf("after end all %+v", got)
	}
	if v := ListTemporaries(in); len(v) != 0 {
		t.Fatalf("views after %+v", v)
	}
	// The file's rules are kept.
	f, _, _ := policy.LoadFile(in.Paths.OverridesFile())
	if len(f.Rules) != 1 {
		t.Fatalf("rules %+v", f.Rules)
	}
	if _, err := os.Stat(in.Paths.OverridesFile()); err != nil {
		t.Fatal(err)
	}
}

// TestGrantForTwiceInOneSecond (Plan 08 final review minor 7): two timed
// grants for one skill written within one second get two ids and both
// stay in the file; the id once hashed only kind, skill and the added
// second, so the second write was refused as "another temporary has this
// id".
func TestGrantForTwiceInOneSecond(t *testing.T) {
	for attempt := 0; attempt < 5; attempt++ {
		in := Input{Paths: testEnv(t)}
		a, err := GrantFor(in, "web", []UngrantedEdit{{Skill: "web", Field: "network", Value: "all"}}, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		b, err := GrantFor(in, "web", []UngrantedEdit{{Skill: "web", Field: "write", Value: "${CWD}/out"}}, 2*time.Hour)
		if err != nil {
			t.Fatalf("second grant: %v", err)
		}
		if !a.Added.Equal(b.Added) {
			continue // a second boundary fell between them; try again
		}
		if a.ID == b.ID || !manifest.ValidTemporaryID(b.ID) {
			t.Fatalf("ids %s %s", a.ID, b.ID)
		}
		file := loadTemps(t, in)
		if len(file) != 2 || file[0].ID != a.ID || file[1].ID != b.ID {
			t.Fatalf("file %+v", file)
		}
		// The same grant again in the same second is no change, not a
		// third entry under a new id.
		c, err := GrantFor(in, "web", []UngrantedEdit{{Skill: "web", Field: "network", Value: "all"}}, time.Hour)
		if err != nil {
			t.Fatalf("same grant again: %v", err)
		}
		if !c.Added.Equal(a.Added) {
			continue
		}
		if file := loadTemps(t, in); len(file) != 2 || c.ID != a.ID {
			t.Fatalf("same grant again: id %s, file %+v", c.ID, file)
		}
		return
	}
	t.Skip("no two grants landed in one second in five tries")
}
