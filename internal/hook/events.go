package hook

import (
	"encoding/json"
	"strings"

	"github.com/Panda-Taps-LLC/watchdeck/internal/activity"
	"github.com/Panda-Taps-LLC/watchdeck/internal/match"
	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
	"github.com/Panda-Taps-LLC/watchdeck/internal/policy"
	"github.com/Panda-Taps-LLC/watchdeck/internal/shellparse"
	"github.com/Panda-Taps-LLC/watchdeck/internal/skills"
)

// maxToolInput caps the Skill tool's input stored in a record. The input can
// carry prompt text in its args; a larger one is replaced by its skill name.
const maxToolInput = 2 << 10

// recordSkillInvoked logs a PreToolUse of the Skill tool. It never answers:
// a skill invocation is not something watchdeck blocks.
func recordSkillInvoked(in Input, env Env) {
	if env.ActivityPath == "" {
		return
	}
	r := baseRecord(in, activity.KindSkillInvoked)
	r.ToolName = "Skill"
	r.Skill = skillName(in.ToolInput)
	r.ToolInput = capToolInput(in.ToolInput, r.Skill)
	_ = activity.Append(env.ActivityPath, r)
}

// recordDenied logs an auto-mode PermissionDenied event for any tool (the
// hook is registered with matcher "*"). A Skill call keeps its input; a Bash
// command that resolves to a skill or is a single `watchdeck run` keeps the
// command and its skills. Every other call keeps only the tool name and a
// normalised target: a path with the home directory as ~, a host name, an MCP
// tool name, or for Bash the program name alone (redactUntouched). The
// reason is a sentence and is never parsed; it is stored as given, except
// that for a Bash command whose text was dropped every copy of the command
// inside it is replaced by its program name and " …", or by "…" alone when
// the command has no program name (redactReason), as an auto-mode
// classifier's reason can quote the command.
func recordDenied(in Input, env Env) {
	if env.ActivityPath == "" {
		return
	}
	r := baseRecord(in, activity.KindDenied)
	r.Reason = in.Reason
	r.ToolName = in.ToolName
	switch {
	case in.ToolName == "Skill":
		r.Skill = skillName(in.ToolInput)
		r.ToolInput = capToolInput(in.ToolInput, r.Skill)
	case in.ToolName == "Bash":
		command, _ := in.ToolInput["command"].(string)
		if strings.TrimSpace(command) == "" {
			return
		}
		r.Command = command
		r.Skills = sortedSkills(deniedSkills(command, in.Cwd, env))
		redactUntouched(&r, env.Home)
		if r.Command == "" {
			r.Reason = redactReason(r.Reason, command, r.Argv0)
		}
	case in.ToolName == "":
		return
	default:
		cwd := in.Cwd
		if cwd == "" {
			cwd = env.Home
		}
		switch {
		case isFileTool(in.ToolName):
			if t := policy.NormalizePath(rawPath(in), cwd, env.Home); t.OK {
				r.Target = tildeHome(t.Lexical, env.Home)
			}
		case in.ToolName == "WebFetch":
			u, _ := in.ToolInput["url"].(string)
			if t := policy.NormalizeHost(u); t.OK {
				r.Target = t.Lexical
			}
		case strings.HasPrefix(in.ToolName, "mcp__"):
			r.Target = in.ToolName
		}
	}
	_ = activity.Append(env.ActivityPath, r)
}

// redactReason replaces each copy of command in reason, as given and with
// its surrounding space trimmed, by argv0 followed by " …", or by "…" alone
// when argv0 is empty. One pass: the replacement is never rescanned, and the
// space around the untrimmed command is kept.
func redactReason(reason, command, argv0 string) string {
	short := "…"
	if argv0 != "" {
		short = argv0 + " …"
	}
	trimmed := strings.TrimSpace(command)
	if trimmed == "" {
		return reason
	}
	i := strings.Index(command, trimmed)
	lead, trail := command[:i], command[i+len(trimmed):]
	pairs := []string{trimmed, short}
	if command != trimmed {
		pairs = []string{command, lead + short + trail, trimmed, short}
	}
	return strings.NewReplacer(pairs...).Replace(reason)
}

// deniedSkills names the skills a denied Bash command concerns.
func deniedSkills(command, cwd string, env Env) []string {
	if cwd == "" {
		cwd = env.Home
	}
	if strings.Contains(command, paths.BinaryName+" run") {
		if !shellparse.IsSingleWatchdeckRun(command) {
			return nil
		}
		return runSkillFlags(command, cwd, env.Environ)
	}
	roots := skills.Roots{Home: env.Home, Cwd: cwd, Env: map[string]string{}}
	if v := env.Environ["CLAUDE_SKILL_DIR"]; v != "" {
		roots.Env["CLAUDE_SKILL_DIR"] = v
	}
	ix, err := loadIndex(env, roots)
	if err != nil || match.FastReject(command, cwd, ix) {
		return nil
	}
	return match.Resolve(command, cwd, env.Environ, ix).Skills
}

// runSkillFlags returns the --skill (and --subject skill:) values of a single `watchdeck run`
// command (`--skill X` and `--skill=X`), stopping at -c or --.
func runSkillFlags(command, cwd string, environ map[string]string) []string {
	prog, err := shellparse.Parse(command, cwd, environ)
	if err != nil || prog == nil || len(prog.Calls) != 1 {
		return nil
	}
	argv := prog.Calls[0].Argv
	var names []string
	for i := 2; i < len(argv); i++ {
		a := argv[i]
		switch {
		case a == "-c" || a == "--":
			return names
		case a == "--skill" || a == "-skill":
			if i+1 < len(argv) {
				names = append(names, argv[i+1])
				i++
			}
		case strings.HasPrefix(a, "--skill="):
			names = append(names, strings.TrimPrefix(a, "--skill="))
		case strings.HasPrefix(a, "-skill="):
			names = append(names, strings.TrimPrefix(a, "-skill="))
		case (a == "--subject" || a == "-subject") && i+1 < len(argv):
			if n, ok := strings.CutPrefix(argv[i+1], "skill:"); ok {
				names = append(names, n)
			}
			i++
		case strings.HasPrefix(a, "--subject=skill:"):
			names = append(names, strings.TrimPrefix(a, "--subject=skill:"))
		case strings.HasPrefix(a, "-subject=skill:"):
			names = append(names, strings.TrimPrefix(a, "-subject=skill:"))
		}
	}
	return names
}

// skillName is the Skill tool's skill, best effort: tool_input.skill, else
// tool_input.name (the field name is not documented).
func skillName(ti map[string]any) string {
	if s, ok := ti["skill"].(string); ok && s != "" {
		return s
	}
	s, _ := ti["name"].(string)
	return s
}

// capToolInput encodes the Skill tool's input whole when it fits in
// maxToolInput, and otherwise as {"skill": name, "truncated": true}, so the
// record stays valid JSON.
func capToolInput(ti map[string]any, name string) json.RawMessage {
	if ti == nil {
		return nil
	}
	b, err := json.Marshal(ti)
	if err == nil && len(b) <= maxToolInput {
		return b
	}
	small := map[string]any{"truncated": true}
	if name != "" {
		if len(name) > 256 {
			name = name[:256]
		}
		small["skill"] = name
	}
	b, _ = json.Marshal(small)
	return b
}
