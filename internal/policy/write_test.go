package policy

import (
	"reflect"
	"testing"

	"github.com/Panda-Taps-LLC/watchdeck/internal/manifest"
)

func TestApplyPutRule(t *testing.T) {
	var f File
	r := manifest.PolicyRule{ID: "user-0000abcd", Tool: "Bash", Match: manifest.RuleMatch{Regex: `curl\s`}, Action: "deny"}
	changed, err := Apply(&f, Edit{PutRule: &r})
	if err != nil || !changed {
		t.Fatalf("put: changed=%v err=%v", changed, err)
	}
	if len(f.Rules) != 1 || !reflect.DeepEqual(f.Rules[0], r) {
		t.Fatalf("rules = %+v", f.Rules)
	}
	if f.Version != 2 {
		t.Fatalf("version = %d", f.Version)
	}

	// The same rule again: no change.
	same := r
	if changed, err := Apply(&f, Edit{PutRule: &same}); err != nil || changed {
		t.Fatalf("same put: changed=%v err=%v", changed, err)
	}

	// A second rule, then a replacement of the first by ID keeps its place.
	other := manifest.PolicyRule{ID: "user-0000beef", Tool: "Bash", Match: manifest.RuleMatch{Literals: []string{"wget"}}, Action: "ask"}
	if changed, err := Apply(&f, Edit{PutRule: &other}); err != nil || !changed {
		t.Fatalf("other: changed=%v err=%v", changed, err)
	}
	repl := manifest.PolicyRule{ID: "user-0000abcd", Tool: "Bash", Match: manifest.RuleMatch{Regex: `curl\s`}, Action: "ask"}
	if changed, err := Apply(&f, Edit{PutRule: &repl}); err != nil || !changed {
		t.Fatalf("replace: changed=%v err=%v", changed, err)
	}
	if len(f.Rules) != 2 || f.Rules[0].ID != "user-0000abcd" || f.Rules[0].Action != "ask" || f.Rules[1].ID != "user-0000beef" {
		t.Fatalf("after replace: %+v", f.Rules)
	}

	// An invalid regex is refused and f is untouched.
	before := f.Clone()
	bad := manifest.PolicyRule{ID: "user-0000dead", Tool: "Bash", Match: manifest.RuleMatch{Regex: `(`}, Action: "deny"}
	if changed, err := Apply(&f, Edit{PutRule: &bad}); err == nil || changed {
		t.Fatalf("bad regex: changed=%v err=%v", changed, err)
	}
	if Render(f) != Render(before) {
		t.Fatalf("f changed after a refused put")
	}

	// An invalid id is refused too (check parses the result strictly).
	badID := manifest.PolicyRule{ID: "pack/rule", Tool: "Bash", Match: manifest.RuleMatch{Literals: []string{"x"}}, Action: "deny"}
	if changed, err := Apply(&f, Edit{PutRule: &badID}); err == nil || changed {
		t.Fatalf("bad id: changed=%v err=%v", changed, err)
	}
	if Render(f) != Render(before) {
		t.Fatalf("f changed after a refused put (id)")
	}
}

func TestApplyDeleteRule(t *testing.T) {
	f := File{Version: 2, Rules: []manifest.PolicyRule{
		{ID: "user-00000001", Tool: "Bash", Match: manifest.RuleMatch{Literals: []string{"a"}}, Action: "deny"},
		{ID: "user-00000002", Tool: "Bash", Match: manifest.RuleMatch{Literals: []string{"b"}}, Action: "ask"},
	}}
	changed, err := Apply(&f, Edit{DeleteRule: "user-00000001"})
	if err != nil || !changed {
		t.Fatalf("delete: changed=%v err=%v", changed, err)
	}
	if len(f.Rules) != 1 || f.Rules[0].ID != "user-00000002" {
		t.Fatalf("rules = %+v", f.Rules)
	}
	if changed, err := Apply(&f, Edit{DeleteRule: "user-00000001"}); err != nil || changed {
		t.Fatalf("unknown id: changed=%v err=%v", changed, err)
	}
	if len(f.Rules) != 1 {
		t.Fatalf("rules = %+v", f.Rules)
	}
}
