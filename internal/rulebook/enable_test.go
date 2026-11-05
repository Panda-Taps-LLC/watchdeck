package rulebook

import (
	"reflect"
	"strings"
	"testing"

	"github.com/Panda-Taps-LLC/watchdeck/internal/manifest"
	"github.com/Panda-Taps-LLC/watchdeck/internal/policy"
	"github.com/Panda-Taps-LLC/watchdeck/internal/rules"
)

// firstPackRule is a real built-in pack rule: its pack, the rule and the
// "<pack>/<id>" key.
func firstPackRule(t *testing.T) (rules.Pack, rules.Rule, string) {
	t.Helper()
	packs := rules.Packs()
	if len(packs) == 0 || len(packs[0].Rules) == 0 {
		t.Fatalf("no built-in packs: %v", rules.LoadError())
	}
	p, r := packs[0], packs[0].Rules[0]
	return p, r, p.Name + "/" + r.ID
}

func packRow(t *testing.T, in Input, id string) Rule {
	t.Helper()
	b, err := List(in)
	if err != nil {
		t.Fatal(err)
	}
	r, _, ok := findRow(b, id)
	if !ok {
		t.Fatalf("no row %s", id)
	}
	return r
}

func TestSetEnabledPackRule(t *testing.T) {
	in, _ := applyEnv(t)
	p, r, key := firstPackRule(t)
	row := RowID(KindPack, "", p.Name, r.ID)
	over := in.Paths.OverridesFile()
	if _, err := policy.Save(over, policy.File{Version: 2, RuleOverrides: map[string]manifest.Toggle{key: {Action: "ask"}}}); err != nil {
		t.Fatal(err)
	}

	res, err := SetEnabled(in, row, false)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(res.Written, []string{over}) || len(res.Backups) != 1 || !reflect.DeepEqual(res.RowIDs, []string{row}) {
		t.Errorf("result = %+v", res)
	}
	f, _, err := policy.LoadFile(over)
	if err != nil {
		t.Fatal(err)
	}
	if tg := f.RuleOverrides[key]; tg.Enabled == nil || *tg.Enabled || tg.Action != "ask" {
		t.Errorf("off: toggle = %+v", tg)
	}
	if got := packRow(t, in, row); got.State != StateOff || got.Action != "ask" {
		t.Errorf("off: row state %s action %s", got.State, got.Action)
	}

	if _, err := SetEnabled(in, row, true); err != nil {
		t.Fatal(err)
	}
	f, _, _ = policy.LoadFile(over)
	if tg := f.RuleOverrides[key]; tg.Enabled == nil || !*tg.Enabled || tg.Action != "ask" {
		t.Errorf("on: toggle = %+v", tg)
	}
	if got := packRow(t, in, row); got.State != StateOn || got.Action != "ask" {
		t.Errorf("on: row state %s action %s", got.State, got.Action)
	}

	// An unknown pack rule is refused.
	if _, err := SetEnabled(in, "pack:nope/nope", false); err == nil {
		t.Error("unknown pack rule accepted")
	}
}

func TestSetEnabledRefusesOtherRows(t *testing.T) {
	in, _ := applyEnv(t)
	for _, id := range []string{"native:user:permissions.deny:00000000", "user:user-0000abcd", "subject:mcp:github", "automode:user:autoMode.allow:00000000", "nope"} {
		_, err := SetEnabled(in, id, false)
		if err == nil || !strings.Contains(err.Error(), "only watchdeck pack rules can be switched off; remove the rule instead") {
			t.Errorf("%s: err = %v", id, err)
		}
	}
}
