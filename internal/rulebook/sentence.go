package rulebook

import (
	"strings"

	"github.com/Panda-Taps-LLC/watchdeck/internal/claudesettings"
	"github.com/Panda-Taps-LLC/watchdeck/internal/manifest"
)

// verb is the sentence verb for an action.
func verb(action string) string {
	switch action {
	case "deny":
		return "Block"
	case "ask":
		return "Ask before"
	case "allow":
		return "Allow without asking"
	case "log":
		return "Note"
	}
	return "Check"
}

// splitRule splits a settings string "Tool(inner)" into its tool and inner
// text; a bare "Tool" (or "Tool()") has an empty inner.
func splitRule(s string) (tool, inner string) {
	if i := strings.IndexByte(s, '('); i > 0 && strings.HasSuffix(s, ")") {
		return s[:i], s[i+1 : len(s)-1]
	}
	return s, ""
}

// Sentence renders one rule as plain English. For the native kinds, tool
// and value are the split settings string (tool "Read", value "~/.x"; a
// bare tool has value ""), or tool is "" and value is the whole string
// ("Read(~/.x)"). Auto-mode kinds take the prose text as value; the literal
// "$defaults" reads as Claude Code's built-in list. Sandbox domains read
// action "deny" as cannot reach, anything else as may reach. A pack rule's
// value is its Description, returned verbatim. A hook rule's value is its
// regex (a literals-only rule is rendered by List). A subject's tool and
// value are a tool gate's tool and entry.
func Sentence(kind Kind, action, tool, value string) string {
	switch kind {
	case KindNativeDeny, KindNativeAsk, KindNativeAllow:
		if tool == "" {
			tool, value = splitRule(value)
		}
		return nativeSentence(verb(action), tool, value)
	case KindAutoModeHard, KindAutoModeSoft, KindAutoModeAllow, KindAutoModeEnv:
		if value == claudesettings.Defaults {
			return "Claude Code's built-in list"
		}
		switch kind {
		case KindAutoModeHard:
			return "Auto mode blocks: " + value
		case KindAutoModeSoft:
			return "Auto mode blocks unless you allowed it: " + value
		case KindAutoModeAllow:
			return "Auto mode allows: " + value
		}
		return "Auto mode knows: " + value
	case KindSandboxDomain:
		if action == "deny" {
			return "Sandboxed commands cannot reach " + value
		}
		return "Sandboxed commands may reach " + value
	case KindSandboxExcluded:
		return "Runs outside Claude Code's sandbox: " + value
	case KindPack:
		return value
	case KindHookRegex:
		return hookSentence(action, tool, manifest.RuleMatch{Regex: value})
	case KindSubject:
		return verb(action) + " " + tool + " on " + value
	}
	return value
}

// displayAbs shows Claude Code's absolute path spelling //abs as /abs.
// Display only: the rule written and matched keeps the //.
func displayAbs(inner string) string {
	if strings.HasPrefix(inner, "//") {
		return inner[1:]
	}
	return inner
}

// nativeSentence renders a permissions entry from its tool and inner text.
func nativeSentence(v, tool, inner string) string {
	if tool != "Bash" && tool != "WebFetch" {
		inner = displayAbs(inner)
	}
	switch {
	case tool == "Read" && inner != "":
		return v + " reading " + inner
	case tool == "Edit" && inner != "":
		return v + " editing " + inner
	case tool == "Bash" && inner != "":
		return v + " running " + inner
	case tool == "Bash":
		return v + " running any command"
	case tool == "WebFetch" && strings.HasPrefix(inner, "domain:"):
		return v + " fetching from " + strings.TrimPrefix(inner, "domain:")
	case tool == "WebFetch" && inner == "":
		return v + " fetching from the web"
	case tool == "*":
		return v + " every tool"
	case tool == "mcp__*":
		return v + " every MCP tool"
	case strings.HasPrefix(tool, "mcp__") && inner == "":
		server, t, ok := strings.Cut(strings.TrimPrefix(tool, "mcp__"), "__")
		if ok && t != "" {
			return v + " the MCP tool " + t + " on " + server
		}
		return v + " every tool on the MCP server " + server
	case inner != "":
		return v + " " + tool + " " + inner
	}
	return v + " using " + tool
}

// hookSentence renders a user-written hook rule: a regex as /re/, a
// literals-only rule as the list, an argv0-only rule as the programs it
// names. A tool "*" (or "") reads as "any call", with no article; several
// tools joined by | as "a A or B call".
func hookSentence(action, tool string, m manifest.RuleMatch) string {
	head := verb(action) + " any call "
	if tool != "*" && tool != "" {
		head = verb(action) + " a " + strings.ReplaceAll(tool, "|", " or ") + " call "
	}
	switch {
	case m.Regex != "":
		return head + "matching /" + m.Regex + "/"
	case len(m.Literals) > 0:
		return head + "containing " + strings.Join(m.Literals, ", ")
	}
	return head + "running " + strings.Join(m.Argv0, ", ")
}

// sandboxSubjectSentence is a skill or command subject's sentence.
func sandboxSubjectSentence(name string, grant manifest.Effective) string {
	return name + " runs sandboxed: " + grant.Summary()
}

// mcpLaunchSentence is an mcp subject's launch-under-sandbox sentence.
func mcpLaunchSentence(name string) string {
	return "MCP server " + name + " starts under the sandbox"
}

// toolGateSentence is one entry of a tool subject's paths or domains gate;
// several matched tools are joined with ", ".
func toolGateSentence(action string, tools []string, entry string) string {
	return Sentence(KindSubject, action, strings.Join(tools, ", "), entry)
}

// agentSentence is one entry of an agent subject's tools gate.
func agentSentence(agentType, action, tool string) string {
	return "Agent " + agentType + ": " + verb(action) + " " + tool
}

// agentSkillsSentence is an agent subject's skills.allow list: every skill
// not on it is blocked for that agent.
func agentSkillsSentence(agentType string, allowed []string) string {
	if len(allowed) == 0 {
		return "Agent " + agentType + ": Block every skill"
	}
	return "Agent " + agentType + ": Block every skill except " + strings.Join(allowed, ", ")
}
