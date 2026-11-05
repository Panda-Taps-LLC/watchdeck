package leakscan

import (
	"strings"
	"testing"

	"github.com/Panda-Taps-LLC/watchdeck/internal/rules"
)

// fakeKeys builds one key-shaped value per pattern. They are assembled here,
// as internal/rules/rules_test.go does, so no file in the repo holds a whole
// one: AWS's documented example key id, a PEM header with no key, and tokens
// padded with FAKE and runs of 0.
func fakeKeys() map[string]string {
	return map[string]string{
		"aws-access-key-id": "AKIA" + "IOSFODNN7" + "EXAMPLE",
		"private-key-pem":   "-----BEGIN RSA " + "PRIVATE KEY-----",
		"github-token":      "ghp" + "_" + "FAKE" + strings.Repeat("0", 32),
		"slack-token":       "xoxb" + "-" + strings.Repeat("0", 10) + "-FAKE",
		"anthropic-key":     "sk" + "-ant-" + "api03-" + "FAKE" + strings.Repeat("0", 32),
		"openai-key":        "sk" + "-proj-" + "FAKE" + strings.Repeat("0", 32),
		"stripe-live":       "sk" + "_live_" + "FAKE" + strings.Repeat("0", 16),
		"aws-secret-key":    "aws_secret_access_key" + " = " + "FAKE" + strings.Repeat("0", 36),
	}
}

func TestPatternIDsInOrder(t *testing.T) {
	want := []string{"aws-access-key-id", "private-key-pem", "github-token", "slack-token",
		"anthropic-key", "openai-key", "stripe-live", "aws-secret-key"}
	ps := Patterns()
	if len(ps) != len(want) {
		t.Fatalf("%d patterns, want %d", len(ps), len(want))
	}
	for i := range ps {
		if ps[i].ID != want[i] || ps[i].Label == "" || len(ps[i].Prefilters) == 0 {
			t.Errorf("pattern %d = %q %q %v, want id %q with a label and prefilters", i, ps[i].ID, ps[i].Label, ps[i].Prefilters, want[i])
		}
	}
}

// TestPatternsMatchCredInWritePack: the four ids the cred-in-write pack
// shares with leak watch use the pack's regex and literals exactly.
func TestPatternsMatchCredInWritePack(t *testing.T) {
	var pack *rules.Pack
	packs := rules.Packs()
	for i := range packs {
		if packs[i].Name == "cred-in-write" {
			pack = &packs[i]
		}
	}
	if pack == nil {
		t.Fatalf("no cred-in-write pack: %v", rules.LoadError())
	}
	ps := Patterns()
	for _, id := range []string{"aws-access-key-id", "private-key-pem", "github-token", "slack-token"} {
		var rule *rules.Rule
		for i := range pack.Rules {
			if pack.Rules[i].ID == id {
				rule = &pack.Rules[i]
			}
		}
		if rule == nil {
			t.Fatalf("cred-in-write has no rule %s", id)
		}
		found := false
		for i := range ps {
			if ps[i].ID != id {
				continue
			}
			found = true
			if ps[i].Regex.Expr != rule.Match.Regex {
				t.Errorf("%s regex %q, pack %q", id, ps[i].Regex.Expr, rule.Match.Regex)
			}
			if strings.Join(ps[i].Prefilters, "\x00") != strings.Join(rule.Match.Literals, "\x00") {
				t.Errorf("%s prefilters %q, pack literals %q", id, ps[i].Prefilters, rule.Match.Literals)
			}
		}
		if !found {
			t.Errorf("no pattern %s", id)
		}
	}
}

func ids(hits []Hit) []string {
	var out []string
	for _, h := range hits {
		out = append(out, h.ID)
	}
	return out
}

func TestScanTable(t *testing.T) {
	keys := fakeKeys()
	labels := map[string]string{}
	ps := Patterns()
	for i := range ps {
		labels[ps[i].ID] = ps[i].Label
	}
	for id, v := range keys {
		for _, text := range []string{v, "token: " + v + "\n", `{"k":"` + v + `"}`} {
			hits := Scan(text)
			if len(hits) != 1 || hits[0].ID != id || hits[0].Label != labels[id] {
				t.Errorf("%s in %q: hits %v", id, text, ids(hits))
			}
		}
	}
	// The label is matched in any case, the value only after it.
	upper := "AWS_SECRET_ACCESS_KEY" + "=" + "FAKE" + strings.Repeat("0", 36)
	if got := ids(Scan(upper)); len(got) != 1 || got[0] != "aws-secret-key" {
		t.Errorf("upper-case label: %v", got)
	}
	misses := map[string]string{
		"short github placeholder":   "ghp" + "_xxx",
		"bare anthropic prefix":      "sk" + "-ant-",
		"short aws example":          "AKIA" + "EXAMPLE",
		"prose about a private key":  "keep the PRIVATE KEY out of the repo",
		"old-style bare sk- key":     "sk" + "-" + "FAKE" + strings.Repeat("0", 44),
		"secret-shaped, no label":    "FAKE" + strings.Repeat("0", 36),
		"lower-case aws key id":      "akia" + "iosfodnn7" + "example",
		"short stripe live":          "sk" + "_live_" + "FAKE",
		"stripe test key":            "sk" + "_test_" + "FAKE" + strings.Repeat("0", 16),
		"short openai project":       "sk" + "-proj-" + "FAKE",
		"bare slack prefix":          "xoxb" + "-",
		"aws label, short value":     "aws_secret_access_key" + " = " + "FAKE",
		"public key header":          "-----BEGIN " + "PUBLIC KEY-----",
		"github token inside a word": "x" + "ghp" + "_" + "FAKE" + strings.Repeat("0", 32),
	}
	for name, text := range misses {
		if hits := Scan(text); len(hits) != 0 {
			t.Errorf("%s (%q): hits %v", name, text, ids(hits))
		}
	}
	// Several kinds in one text: each id once, in pattern order.
	all := ""
	for i := range ps {
		all += "x " + keys[ps[i].ID] + " " + keys[ps[i].ID] + "\n"
	}
	got := ids(Scan(all))
	if len(got) != len(ps) {
		t.Fatalf("all: %v", got)
	}
	for i := range ps {
		if got[i] != ps[i].ID {
			t.Errorf("all[%d] = %s, want %s", i, got[i], ps[i].ID)
		}
	}
}

func TestScanCapsAtMaxBlock(t *testing.T) {
	key := fakeKeys()["slack-token"]
	if got := ids(Scan(strings.Repeat("a", MaxBlock-len(key)-1) + " " + key)); len(got) != 1 {
		t.Fatalf("a key ending at MaxBlock: %v", got)
	}
	if got := ids(Scan(strings.Repeat("a", MaxBlock) + " " + key)); len(got) != 0 {
		t.Fatalf("a key after MaxBlock was found: %v", got)
	}
}

// TestScanNoRegexWithoutPrefilter (R15): a text with no prefilter
// substring runs no regex at all.
func TestScanNoRegexWithoutPrefilter(t *testing.T) {
	text := strings.Repeat("lorem ipsum dolor sit amet, consectetur ", (1<<20)/40)
	if len(text) < 1<<19 {
		t.Fatal("text too short")
	}
	before := regexRuns.Load()
	if hits := Scan(text); len(hits) != 0 {
		t.Fatalf("hits %v", ids(hits))
	}
	if n := regexRuns.Load() - before; n != 0 {
		t.Fatalf("%d regex runs over a text with no prefilter substring", n)
	}
	// The counter does count: a prefilter substring runs that one regex.
	before = regexRuns.Load()
	Scan("the xoxb- placeholder")
	if n := regexRuns.Load() - before; n != 1 {
		t.Fatalf("%d regex runs for one prefilter hit, want 1", n)
	}
}
