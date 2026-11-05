// Package leakscan finds secret-shaped strings in text: the lexical
// patterns of leak watch (Plan 08 D3, DESIGN §14 "Leak watch").
//
// A pattern is a set of literal prefilters and one regular expression. Scan
// cuts the text to MaxBlock bytes, then for each pattern runs a
// strings.Contains on its prefilters and only on a prefilter hit runs the
// regex. A hit names the pattern and never the matched text, so nothing
// that stores a Hit stores a secret.
//
// The four ids leak watch shares with the cred-in-write pack
// (internal/rules/packs/cred-in-write.yaml) use the pack's regex and
// literals exactly; TestPatternsMatchCredInWritePack pins that. Precision
// comes before recall: an old bare "sk-" OpenAI key, a JWT or a
// high-entropy string with no known prefix is not found (stated gaps).
//
// The package does no init-time work: the patterns are static data and each
// regex is a lazyre.Regexp, compiled on first use.
package leakscan

import (
	"strings"
	"sync/atomic"

	"github.com/Panda-Taps-LLC/watchdeck/internal/lazyre"
)

// MaxBlock is the most of one text Scan reads, 64 KiB.
const MaxBlock = 64 << 10

// Pattern is one kind of secret. Prefilters are literal substrings, at
// least one of which a match must contain; a Regex that starts with "(?i)"
// folds case for its prefilters too.
type Pattern struct {
	ID, Label  string
	Prefilters []string
	Regex      lazyre.Regexp
}

// Hit is one pattern found in a text. It carries no matched text.
type Hit struct {
	ID, Label string
}

// patterns is the table, in the order Patterns returns it. It must not be
// copied element by element (a lazyre.Regexp holds a sync.Once): index it.
var patterns = [...]Pattern{
	{
		ID: "aws-access-key-id", Label: "AWS access key id",
		Prefilters: []string{"AKIA", "ASIA", "ABIA", "ACCA"},
		Regex:      lazyre.Regexp{Expr: `\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b`},
	},
	{
		ID: "private-key-pem", Label: "Private key",
		Prefilters: []string{"PRIVATE KEY"},
		Regex:      lazyre.Regexp{Expr: `-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----`},
	},
	{
		ID: "github-token", Label: "GitHub token",
		Prefilters: []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"},
		Regex:      lazyre.Regexp{Expr: `\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b`},
	},
	{
		ID: "slack-token", Label: "Slack token",
		Prefilters: []string{"xox"},
		Regex:      lazyre.Regexp{Expr: `\bxox[abposr]-[A-Za-z0-9-]{10,}`},
	},
	{
		ID: "anthropic-key", Label: "Anthropic API key",
		Prefilters: []string{"sk-ant-"},
		Regex:      lazyre.Regexp{Expr: `\bsk-ant-[A-Za-z0-9_-]{32,}`},
	},
	{
		ID: "openai-key", Label: "OpenAI API key",
		Prefilters: []string{"sk-proj-", "sk-svcacct-", "sk-admin-"},
		Regex:      lazyre.Regexp{Expr: `\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{32,}`},
	},
	{
		ID: "stripe-live", Label: "Stripe live key",
		Prefilters: []string{"sk_live_", "rk_live_"},
		Regex:      lazyre.Regexp{Expr: `\b[sr]k_live_[A-Za-z0-9]{16,}`},
	},
	{
		ID: "aws-secret-key", Label: "AWS secret access key",
		Prefilters: []string{"aws_secret_access_key"},
		Regex:      lazyre.Regexp{Expr: `(?i)aws_secret_access_key["']?\s*[:=]\s*["']?[A-Za-z0-9/+]{40}(?:[^A-Za-z0-9/+=]|$)`},
	},
}

// regexRuns counts regex runs (tests: TestScanNoRegexWithoutPrefilter).
var regexRuns atomic.Int64

// Patterns returns the table: aws-access-key-id, private-key-pem,
// github-token, slack-token, anthropic-key, openai-key, stripe-live,
// aws-secret-key. Callers must not modify it, and should index it rather
// than range over it by value.
func Patterns() []Pattern { return patterns[:] }

// Scan reports each pattern found in the first MaxBlock bytes of text,
// once, in pattern order.
func Scan(text string) []Hit {
	if len(text) > MaxBlock {
		text = text[:MaxBlock]
	}
	var out []Hit
	for i := range patterns {
		p := &patterns[i]
		if !prefilter(text, p) {
			continue
		}
		regexRuns.Add(1)
		if p.Regex.MatchString(text) {
			out = append(out, Hit{ID: p.ID, Label: p.Label})
		}
	}
	return out
}

func prefilter(text string, p *Pattern) bool {
	fold := strings.HasPrefix(p.Regex.Expr, "(?i)")
	for _, lit := range p.Prefilters {
		if fold {
			if containsFoldASCII(text, lit) {
				return true
			}
		} else if strings.Contains(text, lit) {
			return true
		}
	}
	return false
}

// containsFoldASCII reports whether s contains sub, ASCII letters compared
// without case. sub must be lower-case ASCII; nothing is allocated.
func containsFoldASCII(s, sub string) bool {
	n := len(sub)
	if n == 0 {
		return true
	}
	for i := 0; i+n <= len(s); i++ {
		if lowerASCII(s[i]) != sub[0] {
			continue
		}
		j := 1
		for j < n && lowerASCII(s[i+j]) == sub[j] {
			j++
		}
		if j == n {
			return true
		}
	}
	return false
}

func lowerASCII(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}
