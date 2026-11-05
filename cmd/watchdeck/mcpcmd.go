package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/manifest"
	"github.com/Panda-Taps-LLC/watchdeck/internal/mcpconfig"
	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
	"github.com/Panda-Taps-LLC/watchdeck/internal/policy"
	"github.com/Panda-Taps-LLC/watchdeck/internal/runner"
	"github.com/Panda-Taps-LLC/watchdeck/internal/sandbox"
)

const mcpUsage = `usage: watchdeck mcp <wrap|unwrap|status> ...   (experimental)

  mcp wrap <name> [--scope user] [--network none|localhost|all] [--caches]
                  [--binary PATH] [--allow-home-cwd] [--dry-run] [--yes]
      Rewrite the user-scope stdio MCP server <name> in Claude Code's user
      config (~/.claude.json, or $CLAUDE_CONFIG_DIR/.claude.json) so Claude
      Code starts it as: <watchdeck> run --subject mcp:<name> -- <command> <args...>
      and add {kind: mcp, name: <name>, launch: {sandbox: true, grant: ...}}
      to your overrides file. The grant passes the server's own env keys;
      network is none unless --network says otherwise. The server refuses to
      start when its working directory is your home directory, unless
      wrapped with --allow-home-cwd.
  mcp unwrap <name> [--dry-run] [--yes]
      Put the original definition back (byte for byte when the entry was not
      edited since wrap). The policy subject is kept.
  mcp status
      List user-scope servers, whether each is wrapped, and its launch policy.

Only user scope is rewritten: project .mcp.json files (committed to a
repository), local-scope entries and plugin servers are never touched.
Every write backs the config up first (0600, in watchdeck's state dir).
Exit codes: 0 done, 1 refused or declined, 2 error, 3 usage.
`

func cmdMCP(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, mcpUsage)
		return 3
	}
	switch args[0] {
	case "wrap":
		return cmdMCPWrap(args[1:], stdout, stderr)
	case "unwrap":
		return cmdMCPUnwrap(args[1:], stdout, stderr)
	case "status":
		return cmdMCPStatus(args[1:], stdout, stderr)
	case "-h", "--help", "help":
		fmt.Fprint(stdout, mcpUsage)
		return 0
	}
	fmt.Fprintf(stderr, "watchdeck mcp: unknown subcommand %q\n\n%s", args[0], mcpUsage)
	return 3
}

// splitMCPArgs separates positional arguments from flags; valued lists the
// flags that take a value.
func splitMCPArgs(args []string, valued ...string) (pos, flags []string) {
	takes := map[string]bool{}
	for _, v := range valued {
		takes["-"+v], takes["--"+v] = true, true
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			pos = append(pos, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			pos = append(pos, a)
			continue
		}
		flags = append(flags, a)
		if takes[a] && i+1 < len(args) {
			flags = append(flags, args[i+1])
			i++
		}
	}
	return pos, flags
}

// savePolicy is policy.Save; tests replace it to exercise the rollback.
var savePolicy = policy.Save

// mcpConsole builds the confirm console; tests replace it so a test run
// from a terminal never blocks on a prompt.
var mcpConsole = newConsole

// sandboxAvailable reports whether run can apply a sandbox here; tests
// replace it.
var sandboxAvailable = sandbox.Available

// mcpEnv is what the mcp commands need from the host.
type mcpEnv struct {
	hp        paths.Paths
	env       map[string]string
	cfgPath   string
	statePath string
	backups   string
}

func loadMCPEnv(stderr io.Writer, cmd string) (mcpEnv, bool) {
	hp, env, err := hostPaths()
	if err != nil {
		fmt.Fprintf(stderr, "watchdeck mcp %s: %v\n", cmd, err)
		return mcpEnv{}, false
	}
	if cd := env["CLAUDE_CONFIG_DIR"]; cd != "" && !filepath.IsAbs(cd) {
		fmt.Fprintf(stderr, "watchdeck mcp %s: CLAUDE_CONFIG_DIR is not an absolute path; refusing\n", cmd)
		return mcpEnv{}, false
	}
	return mcpEnv{
		hp: hp, env: env,
		cfgPath:   mcpconfig.UserConfigPath(hp.Home, env),
		statePath: filepath.Join(hp.StateDir, mcpconfig.StateFile),
		backups:   filepath.Join(hp.StateDir, "mcp-backups"),
	}, true
}

// mcpBinary is the absolute watchdeck path the wrapped entry runs. An
// explicit --binary must be absolute and exist. Otherwise the running
// binary, preferring the PATH spelling of the same file (a Homebrew link
// survives upgrades; the Cellar path does not).
func mcpBinary(flagValue string) (string, []string, error) {
	var warns []string
	if flagValue != "" {
		if !filepath.IsAbs(flagValue) {
			return "", nil, errors.New("--binary must be an absolute path")
		}
		if fi, err := os.Stat(flagValue); err != nil || fi.IsDir() {
			return "", nil, fmt.Errorf("--binary %s: not a file", flagValue)
		}
		return filepath.Clean(flagValue), nil, nil
	}
	self, err := os.Executable()
	if err != nil {
		return "", nil, err
	}
	real, err := filepath.EvalSymlinks(self)
	if err != nil {
		real = self
	}
	bin := real
	if lp, err := exec.LookPath(paths.BinaryName); err == nil && filepath.IsAbs(lp) {
		if r, err := filepath.EvalSymlinks(lp); err == nil && r == real {
			bin = lp
		}
	}
	tmp, _ := filepath.EvalSymlinks(os.TempDir())
	if strings.Contains(bin, "go-build") || (tmp != "" && strings.HasPrefix(bin, tmp+string(filepath.Separator))) {
		warns = append(warns, "the watchdeck binary is under a temp or go-build directory ("+bin+"); it may disappear. Install watchdeck, or pass --binary PATH")
	}
	return bin, warns, nil
}

// validEnvKey is the overrides file's env name rule ([A-Z_][A-Z0-9_]*).
func validEnvKey(k string) bool {
	if k == "" {
		return false
	}
	for i, c := range k {
		switch {
		case c == '_', c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

// renderSubject is the subject as the policy file will hold it, without
// the file header.
func renderSubject(s manifest.PolicySubject) string {
	text := policy.Render(policy.File{Version: 2, Subjects: []manifest.PolicySubject{s}})
	if i := strings.Index(text, "subjects:\n"); i >= 0 {
		return text[i:]
	}
	return text
}

func indentBlock(s, in string) string {
	return in + strings.ReplaceAll(strings.TrimRight(s, "\n"), "\n", "\n"+in)
}

func cmdMCPWrap(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("mcp wrap", flag.ContinueOnError)
	fs.SetOutput(stderr)
	scope := fs.String("scope", "user", "")
	network := fs.String("network", "", "")
	caches := fs.Bool("caches", false, "")
	binFlag := fs.String("binary", "", "")
	dry := fs.Bool("dry-run", false, "")
	yes := fs.Bool("yes", false, "")
	allowHome := fs.Bool("allow-home-cwd", false, "")
	pos, flags := splitMCPArgs(args, "scope", "network", "binary")
	if err := fs.Parse(flags); err != nil {
		return 3
	}
	if len(pos) != 1 {
		fmt.Fprint(stderr, mcpUsage)
		return 3
	}
	name := pos[0]
	fail := func(code int, format string, a ...any) int {
		fmt.Fprintf(stderr, "watchdeck mcp wrap: "+format+"\n", a...)
		return code
	}
	if *scope != "user" {
		return fail(1, "only --scope user is supported: a project .mcp.json is committed to its repository and shared, local scope belongs to one project, and plugin servers belong to their plugin")
	}
	if name == "*" || !manifest.ValidSkillName(name) {
		return fail(3, "invalid server name %q (%s)", name, manifest.SubjectNameRule)
	}
	var net *manifest.Network
	if *network != "" {
		n, err := manifest.ParseNetwork(*network)
		if err != nil {
			return fail(3, "%v", err)
		}
		net = &n
	}
	if !sandboxAvailable() {
		return fail(1, "this machine cannot sandbox (no sandbox-exec or bwrap): a wrapped server would never start")
	}
	me, ok := loadMCPEnv(stderr, "wrap")
	if !ok {
		return 2
	}
	bin, warns, err := mcpBinary(*binFlag)
	if err != nil {
		return fail(2, "%v", err)
	}
	data, real, exists, err := mcpconfig.ReadConfig(me.cfgPath)
	if err != nil {
		return fail(2, "%s: %v", me.cfgPath, err)
	}
	if !exists {
		return fail(1, "no Claude Code user config at %s", me.cfgPath)
	}
	srv, err := mcpconfig.Find(data, name)
	if errors.Is(err, mcpconfig.ErrNotFound) {
		if ps := mcpconfig.LocalScopeProjects(data, name); len(ps) > 0 {
			return fail(1, "%s is a local-scope server (project %s); only user-scope servers are wrapped. Re-add it with `claude mcp add -s user` to wrap it", name, strings.Join(ps, ", "))
		}
		return fail(1, "%s is not a user-scope server in %s (project .mcp.json and plugin servers are not wrapped)", name, me.cfgPath)
	}
	if err != nil {
		return fail(2, "%s: %v", me.cfgPath, err)
	}
	if err := mcpconfig.Wrappable(srv); err != nil {
		return fail(1, "%s: %v", name, err)
	}
	next, orig, wrapped, err := mcpconfig.Wrap(data, name, bin, *allowHome)
	if err != nil {
		return fail(1, "%s: %v", name, err)
	}

	// The policy subject: keep the user's tools gates and any launch grant,
	// turn the sandbox on, add the server's env keys and the flags.
	polPath := me.hp.OverridesFile()
	pf, _, err := policy.LoadFile(polPath)
	if err != nil {
		return fail(2, "%v", err)
	}
	put := manifest.PolicySubject{Kind: manifest.KindMCP, Name: name}
	for _, s := range pf.Subjects {
		if s.Kind == manifest.KindMCP && s.Name == name {
			put = s.Clone()
		}
	}
	launch := &manifest.MCPLaunch{Sandbox: true}
	if put.Launch != nil && put.Launch.Grant != nil {
		g := *put.Launch.Grant
		launch.Grant = &g
	}
	g := manifest.Override{}
	if launch.Grant != nil {
		g = *launch.Grant
	}
	var skipped []string
	have := map[string]bool{}
	for _, k := range g.Env {
		have[k] = true
	}
	for _, k := range srv.EnvKeys {
		switch {
		case !validEnvKey(k):
			skipped = append(skipped, k)
		case !have[k]:
			g.Env = append(g.Env, k)
			have[k] = true
		}
	}
	if net != nil {
		g.Network = net
	}
	if *caches {
		g.Caches = true
	}
	if !manifest.EmptyOverride(g) {
		launch.Grant = &g
	}
	put.Launch = launch
	polChanged, err := policy.Apply(&pf, policy.Edit{Kind: manifest.KindMCP, Name: name, Put: &put})
	if err != nil {
		return fail(2, "policy: %v", err)
	}

	fmt.Fprintf(stdout, "MCP server %s (user scope, %s)\n", name, real)
	fmt.Fprintf(stdout, "  before (env values hidden):\n%s\n", indentBlock(mcpconfig.RedactedEntry(orig), "    "))
	fmt.Fprintf(stdout, "  after:\n%s\n", indentBlock(mcpconfig.RedactedEntry(wrapped), "    "))
	state := "unchanged"
	if polChanged {
		state = "added or updated"
	}
	fmt.Fprintf(stdout, "policy subject in %s (%s):\n%s\n", polPath, state,
		indentBlock(renderSubject(put), "  "))
	for _, w := range warns {
		fmt.Fprintln(stdout, "warning:", w)
	}
	if len(skipped) > 0 {
		fmt.Fprintf(stdout, "warning: env keys not passed (names must match [A-Z_][A-Z0-9_]*): %s\n", strings.Join(skipped, ", "))
	}
	fmt.Fprintln(stdout, "notes:")
	fmt.Fprintln(stdout, "  - network is", networkWord(g.Network), "for this server; widen with --network, or edit launch.grant")
	fmt.Fprintln(stdout, "  - Claude Code's sandbox.excludedCommands entry \""+paths.BinaryName+" run *\" (watchdeck enforce install) already covers this command")
	fmt.Fprintln(stdout, "  - the env keys are captured now; if you change the server's env in Claude Code later, run wrap again")
	fmt.Fprintln(stdout, "  - restart Claude Code sessions to use the new command; `claude mcp list` health checks also run it under the sandbox")
	fmt.Fprintln(stdout, "  - an org allowlist or denylist that matches this server by serverCommand no longer matches the wrapped command")
	if *dry {
		fmt.Fprintln(stdout, "dry run: nothing written")
		return 0
	}
	c := mcpConsole(stdout, stderr, *yes)
	ans, ok := confirmWrite(c, "Write these changes? Quit running Claude Code sessions first.")
	if !ok {
		return fail(1, "no terminal to confirm: rerun with --yes, or --dry-run to preview")
	}
	if !ans {
		fmt.Fprintln(stdout, "nothing written")
		return 1
	}
	// Order: the unwrap record, then the config, then the policy subject. A
	// failure undoes the earlier steps, so a wrapped entry never exists
	// without its record, and a launch subject is never written for a config
	// that was not wrapped.
	st, err := mcpconfig.LoadState(me.statePath)
	if err != nil {
		return fail(2, "%v", err)
	}
	st.Put(mcpconfig.Record{Config: real, Name: name, Original: string(orig), Wrapped: string(wrapped), Binary: bin, WrappedAt: time.Now().UTC().Format(time.RFC3339)})
	if err := mcpconfig.SaveState(me.statePath, st); err != nil {
		return fail(2, "state: %v", err)
	}
	undoState := func() {
		st.Delete(real, name)
		_ = mcpconfig.SaveState(me.statePath, st)
	}
	backup, err := mcpconfig.WriteConfig(real, data, next, me.backups)
	if err != nil {
		undoState()
		return fail(2, "%v", err)
	}
	if polChanged {
		if _, perr := savePolicy(polPath, pf); perr != nil {
			if _, rerr := mcpconfig.WriteConfig(real, next, data, me.backups); rerr != nil {
				return fail(2, "policy: %v; restoring the config also failed (%v): restore it from %s", perr, rerr, backup)
			}
			undoState()
			return fail(2, "policy: %v; the config change was rolled back", perr)
		}
	}
	fmt.Fprintf(stdout, "wrapped %s; backup of the previous config: %s\n", name, backup)
	return 0
}

// confirmWrite asks before a write; --yes answers yes (console.ask with
// --yes answers the default, which is no here).
func confirmWrite(c *console, q string) (yes, ok bool) {
	if c.assume {
		return true, true
	}
	return c.ask(q, false)
}

func networkWord(n *manifest.Network) string {
	if n == nil {
		return "none"
	}
	return n.String()
}

func cmdMCPUnwrap(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("mcp unwrap", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dry := fs.Bool("dry-run", false, "")
	yes := fs.Bool("yes", false, "")
	pos, flags := splitMCPArgs(args)
	if err := fs.Parse(flags); err != nil {
		return 3
	}
	if len(pos) != 1 {
		fmt.Fprint(stderr, mcpUsage)
		return 3
	}
	name := pos[0]
	fail := func(code int, format string, a ...any) int {
		fmt.Fprintf(stderr, "watchdeck mcp unwrap: "+format+"\n", a...)
		return code
	}
	me, ok := loadMCPEnv(stderr, "unwrap")
	if !ok {
		return 2
	}
	data, real, exists, err := mcpconfig.ReadConfig(me.cfgPath)
	if err != nil {
		return fail(2, "%s: %v", me.cfgPath, err)
	}
	if !exists {
		return fail(1, "no Claude Code user config at %s", me.cfgPath)
	}
	st, err := mcpconfig.LoadState(me.statePath)
	if err != nil {
		return fail(2, "%v", err)
	}
	rec, haveRec := st.Get(real, name)
	cur, err := mcpconfig.Find(data, name)
	if errors.Is(err, mcpconfig.ErrNotFound) {
		return fail(1, "%s is not a user-scope server in %s", name, me.cfgPath)
	}
	if err != nil {
		return fail(2, "%v", err)
	}
	next, exact, err := mcpconfig.Unwrap(data, name, []byte(rec.Original), []byte(rec.Wrapped))
	if err != nil {
		return fail(1, "%s: %v", name, err)
	}
	after, _ := mcpconfig.Find(next, name)
	fmt.Fprintf(stdout, "MCP server %s (user scope, %s)\n", name, real)
	fmt.Fprintf(stdout, "  before (env values hidden):\n%s\n", indentBlock(mcpconfig.RedactedEntry(cur.Raw), "    "))
	fmt.Fprintf(stdout, "  after:\n%s\n", indentBlock(mcpconfig.RedactedEntry(after.Raw), "    "))
	switch {
	case exact:
		fmt.Fprintln(stdout, "the original definition is restored byte for byte")
	case !haveRec:
		fmt.Fprintln(stdout, "no wrap record: command and args are rebuilt from the wrapped args; other fields kept as they are")
	default:
		fmt.Fprintln(stdout, "the entry was edited since wrap: command and args are restored, the other edits are kept")
	}
	fmt.Fprintf(stdout, "the policy subject mcp:%s stays in %s; its launch block is unused while the server is unwrapped\n", name, me.hp.OverridesFile())
	if *dry {
		fmt.Fprintln(stdout, "dry run: nothing written")
		return 0
	}
	c := mcpConsole(stdout, stderr, *yes)
	ans, ok := confirmWrite(c, "Write this change? Quit running Claude Code sessions first.")
	if !ok {
		return fail(1, "no terminal to confirm: rerun with --yes, or --dry-run to preview")
	}
	if !ans {
		fmt.Fprintln(stdout, "nothing written")
		return 1
	}
	backup, err := mcpconfig.WriteConfig(real, data, next, me.backups)
	if err != nil {
		return fail(2, "%v", err)
	}
	if haveRec {
		st.Delete(real, name)
		if err := mcpconfig.SaveState(me.statePath, st); err != nil {
			fmt.Fprintf(stderr, "watchdeck mcp unwrap: state: %v\n", err)
		}
	}
	fmt.Fprintf(stdout, "unwrapped %s; backup of the previous config: %s\n", name, backup)
	return 0
}

func cmdMCPStatus(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		fmt.Fprint(stderr, mcpUsage)
		return 3
	}
	me, ok := loadMCPEnv(stderr, "status")
	if !ok {
		return 2
	}
	// Read the config file only: `claude mcp list` and `get` start every
	// server as a health check.
	data, real, exists, err := mcpconfig.ReadConfig(me.cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "watchdeck mcp status: %s: %v\n", me.cfgPath, err)
		return 2
	}
	pf, _, perr := policy.LoadFile(me.hp.OverridesFile())
	if !exists {
		fmt.Fprintf(stdout, "no Claude Code user config at %s\n", me.cfgPath)
		return 0
	}
	list, err := mcpconfig.List(data)
	if err != nil {
		fmt.Fprintf(stderr, "watchdeck mcp status: %s: %v\n", me.cfgPath, err)
		return 2
	}
	fmt.Fprintf(stdout, "user-scope MCP servers in %s (experimental launch sandbox)\n", real)
	if perr != nil {
		fmt.Fprintf(stdout, "warning: overrides file unreadable, no launch policy applies: %v\n", perr)
	}
	if len(list) == 0 {
		fmt.Fprintln(stdout, "  (none)")
	}
	for _, s := range list {
		transport := s.Type
		if transport == "" {
			transport = "stdio"
			if s.URL != "" {
				transport = "url"
			}
		}
		st := "not wrapped"
		switch {
		case !s.Stdio():
			st = "remote (not sandboxable)"
		case s.Wrapped():
			st = "wrapped"
		}
		pol := "no launch policy"
		if sub, ok := runner.MCPLaunchSubject(pf, s.Name); ok {
			n := "none"
			if sub.Launch.Grant != nil && sub.Launch.Grant.Network != nil {
				n = sub.Launch.Grant.Network.String()
			}
			pol = "launch sandbox, network " + n
		}
		fmt.Fprintf(stdout, "  %-24s %-6s %-26s %s\n", s.Name, transport, st, pol)
		if s.Wrapped() {
			if sub, _ := mcpconfig.WrappedSubject(s); sub != s.Name {
				fmt.Fprintf(stdout, "    warning: wrapped for subject mcp:%s, not mcp:%s\n", sub, s.Name)
			}
			if pol == "no launch policy" {
				fmt.Fprintln(stdout, "    warning: wrapped but no launch policy: the server will not start (run watchdeck mcp wrap again or add the subject)")
			}
			if fi, err := os.Stat(s.Command); err != nil || fi.IsDir() {
				fmt.Fprintf(stdout, "    warning: the wrapper binary %s is missing: the server will not start\n", s.Command)
			}
		}
	}
	cwd, _ := os.Getwd()
	if local := mcpconfig.LocalScopeServers(data, cwd); len(local) > 0 {
		fmt.Fprintf(stdout, "local-scope servers for %s (not wrapped by watchdeck):\n", cwd)
		for _, s := range local {
			fmt.Fprintf(stdout, "  %s\n", s.Name)
		}
	}
	return 0
}
