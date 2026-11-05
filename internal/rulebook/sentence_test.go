package rulebook

import (
	"testing"

	"github.com/Panda-Taps-LLC/watchdeck/internal/manifest"
)

func TestSentenceTemplates(t *testing.T) {
	cases := []struct {
		name string
		got  string
		want string
	}{
		// Verbs.
		{"deny verb", Sentence(KindNativeDeny, "deny", "Read", "~/.ssh/id_*"), "Block reading ~/.ssh/id_*"},
		{"ask verb", Sentence(KindNativeAsk, "ask", "Read", "./.env"), "Ask before reading ./.env"},
		{"allow verb", Sentence(KindNativeAllow, "allow", "Read", "./src/**"), "Allow without asking reading ./src/**"},
		{"log verb", Sentence(KindHookRegex, "log", "Bash", "psql .*prod"), "Note a Bash call matching /psql .*prod/"},
		// Native shapes, split.
		{"edit", Sentence(KindNativeAsk, "ask", "Edit", "~/.zshrc"), "Ask before editing ~/.zshrc"},
		{"bash", Sentence(KindNativeDeny, "deny", "Bash", "curl *"), "Block running curl *"},
		{"bare bash", Sentence(KindNativeAsk, "ask", "Bash", ""), "Ask before running any command"},
		{"webfetch domain", Sentence(KindNativeDeny, "deny", "WebFetch", "domain:example.com"), "Block fetching from example.com"},
		{"bare webfetch", Sentence(KindNativeAsk, "ask", "WebFetch", ""), "Ask before fetching from the web"},
		{"mcp tool", Sentence(KindNativeDeny, "deny", "mcp__github__delete_repo", ""), "Block the MCP tool delete_repo on github"},
		{"mcp server", Sentence(KindNativeAsk, "ask", "mcp__github", ""), "Ask before every tool on the MCP server github"},
		{"mcp all", Sentence(KindNativeDeny, "deny", "mcp__*", ""), "Block every MCP tool"},
		{"star", Sentence(KindNativeAsk, "ask", "*", ""), "Ask before every tool"},
		{"other T(v)", Sentence(KindNativeDeny, "deny", "Write", "~/x"), "Block Write ~/x"},
		{"bare T", Sentence(KindNativeAsk, "ask", "WebSearch", ""), "Ask before using WebSearch"},
		// Native shapes, whole settings string (tool "").
		{"whole read", Sentence(KindNativeDeny, "deny", "", "Read(~/.ssh/id_*)"), "Block reading ~/.ssh/id_*"},
		{"whole bash", Sentence(KindNativeAsk, "ask", "", "Bash(git push *)"), "Ask before running git push *"},
		{"whole bare", Sentence(KindNativeAsk, "ask", "", "Bash"), "Ask before running any command"},
		{"whole webfetch", Sentence(KindNativeAllow, "allow", "", "WebFetch(domain:docs.example.com)"), "Allow without asking fetching from docs.example.com"},
		{"whole mcp", Sentence(KindNativeDeny, "deny", "", "mcp__github__delete_repo"), "Block the MCP tool delete_repo on github"},
		// Auto mode.
		{"hard", Sentence(KindAutoModeHard, "", "", "no prod"), "Auto mode blocks: no prod"},
		{"soft", Sentence(KindAutoModeSoft, "", "", "no force push"), "Auto mode blocks unless you allowed it: no force push"},
		{"auto allow", Sentence(KindAutoModeAllow, "", "", "reading docs"), "Auto mode allows: reading docs"},
		{"env", Sentence(KindAutoModeEnv, "", "", "this is a dev box"), "Auto mode knows: this is a dev box"},
		{"defaults", Sentence(KindAutoModeHard, "", "", "$defaults"), "Claude Code's built-in list"},
		// Sandbox settings.
		{"domain allowed", Sentence(KindSandboxDomain, "allow", "", "example.com"), "Sandboxed commands may reach example.com"},
		{"domain denied", Sentence(KindSandboxDomain, "deny", "", "evil.example"), "Sandboxed commands cannot reach evil.example"},
		{"excluded", Sentence(KindSandboxExcluded, "", "", "docker *"), "Runs outside Claude Code's sandbox: docker *"},
		// Pack: the description verbatim.
		{"pack", Sentence(KindPack, "deny", "Bash", "curl or wget uploads an SSH private key."), "curl or wget uploads an SSH private key."},
		// Hook rules.
		{"hook regex", hookSentence("deny", "Bash", manifest.RuleMatch{Regex: "psql .*prod"}), "Block a Bash call matching /psql .*prod/"},
		{"hook literals", hookSentence("ask", "Bash", manifest.RuleMatch{Literals: []string{"s3 rm", "s3 rb"}}), "Ask before a Bash call containing s3 rm, s3 rb"},
		{"hook any tool", hookSentence("log", "*", manifest.RuleMatch{Regex: "token"}), "Note any call matching /token/"},
		{"hook via Sentence", Sentence(KindHookRegex, "deny", "*", "x+"), "Block any call matching /x+/"},
		{"hook any literals", hookSentence("ask", "", manifest.RuleMatch{Literals: []string{"s3 rm"}}), "Ask before any call containing s3 rm"},
		{"hook any argv0", hookSentence("deny", "*", manifest.RuleMatch{Argv0: []string{"nc"}}), "Block any call running nc"},
		{"bash colon form", Sentence(KindNativeDeny, "deny", "", "Bash(git:*)"), "Block running git:*"},
		// Claude Code spells an absolute path //abs; the sentence shows /abs
		// (display only; the rule keeps //).
		{"absolute read", Sentence(KindNativeDeny, "deny", "", "Read(//srv/proj/.env)"), "Block reading /srv/proj/.env"},
		{"absolute edit", Sentence(KindNativeAsk, "ask", "Edit", "//srv/proj/.env"), "Ask before editing /srv/proj/.env"},
		{"absolute other", Sentence(KindNativeDeny, "deny", "Write", "//srv/x"), "Block Write /srv/x"},
		{"bash keeps slashes", Sentence(KindNativeDeny, "deny", "Bash", "//x"), "Block running //x"},
		// Subjects.
		{"skill", sandboxSubjectSentence("pdf", manifest.Default()), "pdf runs sandboxed: " + manifest.Default().Summary()},
		{"mcp launch", mcpLaunchSentence("github"), "MCP server github starts under the sandbox"},
		{"tool gate", Sentence(KindSubject, "deny", "Write", "~/.zshrc"), "Block Write on ~/.zshrc"},
		{"tool gate ask", toolGateSentence("ask", []string{"WebFetch"}, "example.org"), "Ask before WebFetch on example.org"},
		{"agent tool", agentSentence("researcher", "deny", "Bash"), "Agent researcher: Block Bash"},
		{"agent skill list", agentSkillsSentence("researcher", []string{"pdf", "docs"}), "Agent researcher: Block every skill except pdf, docs"},
		{"agent no skills", agentSkillsSentence("researcher", []string{}), "Agent researcher: Block every skill"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s:\n got  %q\n want %q", c.name, c.got, c.want)
		}
	}
}
