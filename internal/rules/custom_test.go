package rules

import "testing"

func TestMatcher(t *testing.T) {
	m, err := NewMatcher(FieldCommand, Match{Regex: `psql .*prod`})
	if err != nil {
		t.Fatal(err)
	}
	if !m.Match(Input{Command: "psql -h db-prod"}) || m.Match(Input{Command: "psql -h staging"}) {
		t.Fatal("regex matcher wrong")
	}
	a, err := NewMatcher(FieldCommand, Match{Argv0: []string{"terraform"}, Regex: `destroy`})
	if err != nil {
		t.Fatal(err)
	}
	if !a.Match(Input{Command: "cd x && terraform destroy"}) || a.Match(Input{Command: "echo terraform; ls destroy"}) {
		t.Fatal("argv0 matcher wrong")
	}
	if _, err := NewMatcher(FieldCommand, Match{Regex: `(`}); err == nil {
		t.Fatal("invalid regex accepted")
	}
	if _, err := NewMatcher(FieldURL, Match{Argv0: []string{"x"}}); err == nil {
		t.Fatal("argv0 on url accepted")
	}
	l, _ := NewMatcher(FieldText, Match{Literals: []string{"Secret"}})
	if !l.Match(Input{Text: "a secret query"}) {
		t.Fatal("literal-only matcher is case-folded")
	}
	var nilM *Matcher
	if nilM.Match(Input{Command: "x"}) {
		t.Fatal("nil matcher matched")
	}
}
