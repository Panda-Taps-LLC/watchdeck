package main

import (
	"fmt"
	"io"

	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
)

// advancedUsage lists every command the documented usage leaves out. Each
// one also runs bare ("watchdeck paths" and "watchdeck advanced paths" are
// the same command), so scripts and the plugin keep working. hook and run
// are not listed: Claude Code runs them, people do not type them; both stay
// accepted. advancedUsage is outside the copy lint.
const advancedUsage = `usage: watchdeck advanced <command> [args]
       (every command here also runs without "advanced")

  audit      inventory installed skills, their scripts, capabilities and manifests
             (exits 0 on an invalid manifest; --strict exits 1)
  init       write a PERMISSIONS.yaml request for a skill from a scan
  validate   validate a PERMISSIONS.yaml or a skill directory
  enforce    install | uninstall | status of the hooks in Claude Code settings
  index      rebuild or show the skill index cache; "index sessions" refreshes
             (--rebuild, --purge) the session index
  sessions   list every project's Claude Code sessions (--project, --since,
             --search full text, --json)
  service    install | uninstall | status of the dashboard as a login service
             (launchd on macOS, systemd --user on Linux; --dry-run)
  mcp        experimental: wrap | unwrap | status of user-scope stdio MCP
             servers, so Claude Code starts them under the sandbox
  policy     check: validate overrides.yaml and the project .watchdeck.yaml,
             list ignored project entries and lint gates (exits 1 when invalid)
  activity   show the activity log: decisions, runs, denials (--json, --summary)
  paths      print the config, cache, state and Claude Code locations (--json)
  demo       run a built-in test skill whose network access is denied, and show why
  inbox      what needs you: denials, asks and sandbox refusals since install;
             "inbox resolve <id> add|ack|dismiss|undo"
  allow      widen or revoke the grant for a skill (writes the user overrides
             file; same as "rules grant")
  version    print the version (--json)

used by the plugin and the dashboard:
  ui         open the local dashboard (127.0.0.1 only; one per user: reused when
             running; --ensure starts it in the background, --stop stops it)
`

// cmdAdvanced runs "watchdeck advanced <command> [args]": the same command
// the bare spelling runs, with the same output and exit codes.
func cmdAdvanced(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, advancedUsage)
		return 3
	}
	switch args[0] {
	case "help", "-h", "--help":
		fmt.Fprint(stdout, advancedUsage)
		return 0
	}
	if code, ok := dispatch(args[0], args[1:], stdout, stderr); ok {
		return code
	}
	fmt.Fprintf(stderr, "%s advanced: unknown command %q\n\n%s", paths.BinaryName, args[0], advancedUsage)
	return 3
}
