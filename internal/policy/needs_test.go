package policy

import (
	"reflect"
	"strings"
	"testing"

	"github.com/Panda-Taps-LLC/watchdeck/internal/rules"
)

// allTwins are the pack rules the twelve recommended native rules cover
// (rulebook.CoveredTwins with every string installed; rulebook imports this
// package, so the list is spelled out here).
var allTwins = []string{
	"persistence/launch-agent-write", "persistence/shell-rc-write", "persistence/systemd-unit-write",
	"secrets-read/read-aws-credentials", "secrets-read/read-dotenv", "secrets-read/read-other-credentials", "secrets-read/read-ssh-private-key",
}

// TestFilesNeedTable: a file tool needs the hook for a gate, the person's
// own rule, or an enabled pack rule at ask or deny whose native twin is not
// installed (a rule raised above its default never counts as covered). Log
// rules never count.
func TestFilesNeedTable(t *testing.T) {
	off := false
	credOff := map[string]rules.PackConfig{"cred-in-write": {Enabled: &off}}
	writes := []string{"Write", "Edit", "MultiEdit", "NotebookEdit"}
	all := []string{"Read", "Write", "Edit", "MultiEdit", "NotebookEdit"}
	cases := []struct {
		name, user string
		cfg        rules.Config
		covered    []string
		tools      []string
		why        string
	}{
		{"default packs, all twins covered", "", rules.Config{}, allTwins, writes, "cred-in-write/aws-access-key-id asks before a write"},
		{"default packs, nothing covered", "", rules.Config{}, nil, all, "secrets-read/read-ssh-private-key asks before a read"},
		{"cred-in-write off, all covered", "", rules.Config{Packs: credOff}, allTwins, nil, ""},
		{"Read path gate, all covered", "version: 2\nsubjects:\n  - {kind: tool, name: s, match: {tools: [Read]}, paths: {deny: ['~/secrets/**']}}\n", rules.Config{}, allTwins, all, "a path rule for Read"},
		{"search gate only", "version: 2\nsubjects:\n  - {kind: tool, name: s, match: {tools: [Grep, Glob]}, paths: {deny: ['~/secrets/**']}}\n", rules.Config{Packs: credOff}, allTwins, nil, ""},
		{"agent gate", "version: 2\nsubjects:\n  - {kind: agent, name: r, match: {agent_type: researcher}, tools: {deny: [Edit]}}\n", rules.Config{Packs: credOff}, allTwins, []string{"Edit"}, "an agent rule for Edit"},
		{"user file rule", "version: 2\nrules:\n  - {id: no-pem, tool: Read, match: {regex: '\\.pem$'}, action: ask}\n", rules.Config{Packs: credOff}, allTwins, []string{"Read"}, "your rule no-pem"},
		{"user bash rule", "version: 2\nrules:\n  - {id: tf, tool: Bash, match: {argv0: [terraform]}, action: ask}\n", rules.Config{Packs: credOff}, allTwins, nil, ""},
		{"pack rule raised to deny", "", rules.Config{Packs: credOff, Rules: map[string]rules.RuleConfig{"secrets-read/read-ssh-private-key": {Action: rules.Deny}}}, allTwins, []string{"Read"}, "secrets-read/read-ssh-private-key set to deny"},
		{"log rule raised to ask", "", rules.Config{Packs: credOff, Rules: map[string]rules.RuleConfig{"secrets-read/read-other-credentials": {Action: rules.Ask}}}, allTwins, []string{"Read"}, "secrets-read/read-other-credentials asks before a read"},
		{"persistence raised to ask", "", rules.Config{Packs: map[string]rules.PackConfig{"cred-in-write": {Enabled: &off}, "persistence": {Action: rules.Ask}}}, allTwins, []string{"Write", "Edit", "MultiEdit"}, "persistence/shell-rc-write asks before an edit"},
		{"deny on a disabled pack", "", rules.Config{Packs: map[string]rules.PackConfig{"cred-in-write": {Enabled: &off}, "secrets-read": {Enabled: &off}}, Rules: map[string]rules.RuleConfig{"secrets-read/read-ssh-private-key": {Action: rules.Deny}}}, nil, nil, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var p *Policy
			if c.user == "" {
				p, _ = New(Layer{}, Layer{})
			} else {
				p = loadPair(t, c.user, "")
			}
			tools, why := p.FilesNeed(c.cfg, c.covered)
			if !reflect.DeepEqual(tools, c.tools) || !strings.HasPrefix(why, c.why) || (c.why == "" && why != "") {
				t.Fatalf("FilesNeed = %v %q, want %v %q", tools, why, c.tools, c.why)
			}
		})
	}
	var nilP *Policy
	if tools, why := nilP.FilesNeed(rules.Config{}, nil); !reflect.DeepEqual(tools, all) || why == "" {
		t.Fatalf("nil policy: %v %q", tools, why)
	}
}
