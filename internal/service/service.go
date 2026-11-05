// Package service installs the dashboard as a per-user service (M5.3):
//
//   - macOS: a LaunchAgent, ~/Library/LaunchAgents/com.pandataps.watchdeck.plist,
//     loaded with `launchctl bootstrap gui/<uid>` and removed with `bootout`;
//   - Linux: a systemd user unit, ${XDG_CONFIG_HOME:-~/.config}/systemd/user/watchdeck-ui.service,
//     with `systemctl --user enable --now` and `disable --now`.
//
// Both run `<absolute binary> ui --service` (foreground, no idle exit),
// restart it only when it fails (a clean `ui --stop` exit 0 stays stopped),
// and append its stdout and stderr to <stateDir>/ui.log (0600).
//
// Every external command goes through Options.Runner; there is no default,
// so a caller (cmd/watchdeck) chooses the real one and tests never reach
// launchctl or systemctl. File contents are built as strings (no templates,
// no XML encoder), and the package is init-free.
package service

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
)

// Names.
const (
	Label    = "com.pandataps." + paths.BinaryName
	UnitName = paths.BinaryName + "-ui.service"
	LogFile  = "ui.log"
)

// Runner runs an external command and returns its combined output.
type Runner interface {
	Run(name string, args ...string) (string, error)
}

// Options describe the install.
type Options struct {
	OS      string            // "darwin" or "linux" (runtime.GOOS in the command; tests pin it)
	Paths   paths.Paths       // Home, ConfigDir and StateDir decide every location
	Binary  string            // absolute path of watchdeck
	UID     int               // for gui/<uid> on macOS
	Environ map[string]string // the installer's environment: the location variables set in it are passed to the service
	Runner  Runner
}

// passEnv are the variables that move watchdeck's and Claude Code's
// locations. A service does not inherit the login shell's environment, so
// the ones set at install time are written into the plist or unit; without
// them the service would read and write other dirs than the CLI does.
var passEnv = [...]string{"XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME", "CLAUDE_CONFIG_DIR", "WATCHDECK_ACTIVITY"}

// Errors.
var (
	ErrUnsupported = errors.New("service: only macOS (launchd) and Linux (systemd --user) are supported")
	ErrNoRunner    = errors.New("service: no command runner")
)

func (o Options) check() error {
	switch {
	case o.OS != "darwin" && o.OS != "linux":
		return ErrUnsupported
	case o.Binary == "" || !filepath.IsAbs(o.Binary):
		return fmt.Errorf("service: the binary path %q is not absolute", o.Binary)
	case o.Paths.Home == "" || !filepath.IsAbs(o.Paths.StateDir):
		return errors.New("service: home and state dir must be absolute")
	case strings.ContainsAny(o.Binary+o.Paths.StateDir, "\n\r\x00"):
		return errors.New("service: a path contains a newline or NUL")
	}
	return nil
}

// File is where the plist or unit goes.
func (o Options) File() string {
	if o.OS == "darwin" {
		return filepath.Join(o.Paths.Home, "Library", "LaunchAgents", Label+".plist")
	}
	// ConfigDir is ${XDG_CONFIG_HOME:-~/.config}/watchdeck; systemd
	// reads user units from ${XDG_CONFIG_HOME:-~/.config}/systemd/user.
	return filepath.Join(filepath.Dir(o.Paths.ConfigDir), "systemd", "user", UnitName)
}

// Log is the service's output file.
func (o Options) Log() string { return filepath.Join(o.Paths.StateDir, LogFile) }

// env is the passEnv subset set in Environ, sorted by name.
func (o Options) env() [][2]string {
	var out [][2]string
	for _, k := range passEnv {
		if v := o.Environ[k]; v != "" && !strings.ContainsAny(v, "\n\r\x00") {
			out = append(out, [2]string{k, v})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i][0] < out[j][0] })
	return out
}

// xmlEscape escapes text for a plist <string>.
func xmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;")
	return r.Replace(s)
}

// Plist is the LaunchAgent. KeepAlive with SuccessfulExit false restarts
// the dashboard only after a failure; RunAtLoad starts it at login.
func Plist(o Options) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>` + Label + `</string>
	<key>ProgramArguments</key>
	<array>
		<string>` + xmlEscape(o.Binary) + `</string>
		<string>ui</string>
		<string>--service</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<dict>
		<key>SuccessfulExit</key>
		<false/>
	</dict>
	<key>ProcessType</key>
	<string>Background</string>
	<key>Umask</key>
	<integer>63</integer>
	<key>StandardOutPath</key>
	<string>` + xmlEscape(o.Log()) + `</string>
	<key>StandardErrorPath</key>
	<string>` + xmlEscape(o.Log()) + `</string>
`)
	if env := o.env(); len(env) > 0 {
		b.WriteString("\t<key>EnvironmentVariables</key>\n\t<dict>\n")
		for _, kv := range env {
			b.WriteString("\t\t<key>" + kv[0] + "</key>\n\t\t<string>" + xmlEscape(kv[1]) + "</string>\n")
		}
		b.WriteString("\t</dict>\n")
	}
	b.WriteString("</dict>\n</plist>\n")
	return b.String()
}

// systemdQuote quotes a word for ExecStart and Environment: double quotes,
// with backslash and quote escaped, and % doubled (systemd's specifier
// character).
func systemdQuote(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "%", "%%")
	return `"` + s + `"`
}

// Unit is the systemd user unit.
func Unit(o Options) string {
	var b strings.Builder
	b.WriteString(`[Unit]
Description=watchdeck dashboard (127.0.0.1 only)
Documentation=https://github.com/Panda-Taps-LLC/watchdeck

[Service]
Type=simple
ExecStart=` + systemdQuote(o.Binary) + ` ui --service
Restart=on-failure
RestartSec=5
UMask=0077
StandardOutput=append:` + strings.ReplaceAll(o.Log(), "%", "%%") + `
StandardError=append:` + strings.ReplaceAll(o.Log(), "%", "%%") + `
`)
	for _, kv := range o.env() {
		b.WriteString("Environment=" + systemdQuote(kv[0]+"="+kv[1]) + "\n")
	}
	b.WriteString(`
[Install]
WantedBy=default.target
`)
	return b.String()
}

// Content is the plist or unit for o.OS.
func Content(o Options) string {
	if o.OS == "darwin" {
		return Plist(o)
	}
	return Unit(o)
}

// Plan is what Install or Uninstall will do, for --dry-run and the confirm.
type Plan struct {
	File     string     // the plist or unit
	Content  string     // written by Install; "" for Uninstall
	Log      string     // created 0600 by Install
	Commands [][]string // run in order
}

func (o Options) domain() string { return "gui/" + strconv.Itoa(o.UID) }

// InstallPlan describes Install.
func InstallPlan(o Options) (Plan, error) {
	if err := o.check(); err != nil {
		return Plan{}, err
	}
	p := Plan{File: o.File(), Content: Content(o), Log: o.Log()}
	if o.OS == "darwin" {
		p.Commands = [][]string{
			{"launchctl", "bootout", o.domain() + "/" + Label}, // an older copy, if loaded; its failure is ignored
			{"launchctl", "bootstrap", o.domain(), p.File},
		}
	} else {
		p.Commands = [][]string{
			{"systemctl", "--user", "daemon-reload"},
			{"systemctl", "--user", "enable", "--now", UnitName},
		}
	}
	return p, nil
}

// UninstallPlan describes Uninstall.
func UninstallPlan(o Options) (Plan, error) {
	if err := o.check(); err != nil {
		return Plan{}, err
	}
	p := Plan{File: o.File()}
	if o.OS == "darwin" {
		p.Commands = [][]string{{"launchctl", "bootout", o.domain() + "/" + Label}}
	} else {
		p.Commands = [][]string{
			{"systemctl", "--user", "disable", "--now", UnitName},
			{"systemctl", "--user", "daemon-reload"},
		}
	}
	return p, nil
}

// Install writes the plist or unit (0644, atomically), creates the state
// dir (0700) and ui.log (0600) so the service manager does not create them
// with its own modes, and loads the service.
func Install(o Options) (Plan, error) {
	p, err := InstallPlan(o)
	if err != nil {
		return p, err
	}
	if o.Runner == nil {
		return p, ErrNoRunner
	}
	if err := prepareLog(o.Paths.StateDir, p.Log); err != nil {
		return p, err
	}
	if err := writeFile(p.File, p.Content); err != nil {
		return p, err
	}
	for i, c := range p.Commands {
		out, err := o.Runner.Run(c[0], c[1:]...)
		if err != nil {
			if o.OS == "darwin" && i == 0 {
				continue // bootout of a service that is not loaded
			}
			return p, fmt.Errorf("%s: %v: %s", strings.Join(c, " "), err, strings.TrimSpace(out))
		}
	}
	return p, nil
}

// Uninstall unloads the service and removes its file. A service that is
// not loaded is not an error; a missing file is not either.
func Uninstall(o Options) (Plan, error) {
	p, err := UninstallPlan(o)
	if err != nil {
		return p, err
	}
	if o.Runner == nil {
		return p, ErrNoRunner
	}
	_, statErr := os.Stat(p.File)
	// launchctl bootout fails when nothing is loaded, and so does systemctl
	// disable for a unit that is gone. A failure is reported only when the
	// service was there: on macOS when launchctl print found it loaded, on
	// Linux when the unit file exists. The file is not removed then, so a
	// rerun can try again.
	loaded := false
	if o.OS == "darwin" {
		_, perr := o.Runner.Run("launchctl", "print", o.domain()+"/"+Label)
		loaded = perr == nil
	}
	var firstErr error
	for _, c := range p.Commands {
		out, err := o.Runner.Run(c[0], c[1:]...)
		if err != nil && firstErr == nil && ((o.OS == "darwin" && loaded) || (o.OS == "linux" && c[2] == "disable" && statErr == nil)) {
			firstErr = fmt.Errorf("%s: %v: %s", strings.Join(c, " "), err, strings.TrimSpace(out))
		}
	}
	if firstErr != nil {
		return p, firstErr
	}
	if err := os.Remove(p.File); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return p, err
	}
	return p, nil
}

// StableBinary maps a binary inside a Homebrew Cellar
// (<prefix>/Cellar/watchdeck/<version>/bin/watchdeck, what os.Executable
// resolves to) to the opt symlink <prefix>/opt/watchdeck/bin/watchdeck
// when that resolves to the same file, so a `brew upgrade` (which removes
// the old Cellar dir) does not break the service. Any other path is
// returned as is.
func StableBinary(bin string) string {
	i := strings.Index(bin, "/Cellar/"+paths.BinaryName+"/")
	if i < 0 {
		return bin
	}
	real, err := filepath.EvalSymlinks(bin)
	if err != nil {
		return bin
	}
	for _, cand := range []string{
		filepath.Join(bin[:i], "opt", paths.BinaryName, "bin", paths.BinaryName),
		filepath.Join(bin[:i], "bin", paths.BinaryName),
	} {
		if r, err := filepath.EvalSymlinks(cand); err == nil && r == real {
			return cand
		}
	}
	return bin
}

// State is what Status found.
type State struct {
	Installed bool   // the plist or unit exists
	Loaded    bool   // launchctl print / systemctl is-active succeeded
	File      string // where it is (or would be)
	Detail    string
}

// Status reports whether the service is installed and loaded. It runs a
// command only when the file exists.
func Status(o Options) (State, error) {
	if err := o.check(); err != nil {
		return State{}, err
	}
	st := State{File: o.File()}
	if _, err := os.Stat(st.File); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return st, nil
		}
		return st, err
	}
	st.Installed = true
	if o.Runner == nil {
		return st, ErrNoRunner
	}
	var out string
	var err error
	if o.OS == "darwin" {
		out, err = o.Runner.Run("launchctl", "print", o.domain()+"/"+Label)
	} else {
		out, err = o.Runner.Run("systemctl", "--user", "is-active", UnitName)
	}
	st.Loaded = err == nil
	if o.OS == "linux" {
		st.Detail = strings.TrimSpace(out)
	} else if st.Loaded {
		st.Detail = launchdState(out)
	}
	return st, nil
}

// launchdState picks "state = running" out of `launchctl print`.
func launchdState(out string) string {
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "state = ") {
			return strings.TrimPrefix(l, "state = ")
		}
	}
	return ""
}

// prepareLog creates the state dir 0700 and the log 0600 (append, no
// symlink followed), tightening an existing log.
func prepareLog(stateDir, log string) error {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(log, os.O_WRONLY|os.O_CREATE|os.O_APPEND|oNoFollow, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Chmod(0o600)
}

// writeFile writes content atomically, 0644, creating the directory 0755.
func writeFile(path, content string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".watchdeck-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	_, werr := tmp.WriteString(content)
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Chmod(name, 0o644)
	}
	if werr == nil {
		werr = os.Rename(name, path)
	}
	if werr != nil {
		os.Remove(name)
	}
	return werr
}
