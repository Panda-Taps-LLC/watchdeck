package hook

import (
	"reflect"
	"testing"
)

// TestRunSkillFlagsSubjectAlias: a denied `watchdeck run --subject
// skill:x` names skill x, like --skill x; a command subject names none.
func TestRunSkillFlagsSubjectAlias(t *testing.T) {
	cases := map[string][]string{
		"watchdeck run --skill a --subject skill:b -c 'x'": {"a", "b"},
		"watchdeck run --subject=skill:c -c 'x'":           {"c"},
		"watchdeck run --subject command:npm -c 'x'":       nil,
	}
	for cmd, want := range cases {
		if got := runSkillFlags(cmd, "/tmp", nil); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: %v, want %v", cmd, got, want)
		}
	}
}
