package main

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The fixture-home tests drive scripts/fixture-home.sh (and through it
// scripts/fixture-sessions.py) the way a person does, into a fresh dir under
// /var/tmp (the script's own default; the per-user temp dir is refused by
// `watchdeck run` as an ancestor of HOME). Nothing reads the real home: the
// built binary runs with the fixture's HOME, XDG dirs, CLAUDE_CONFIG_DIR and
// WATCHDECK_ACTIVITY only.

const (
	fixtureSessionA = "a9896c55-0b77-4f85-a0e0-9be2948b8aa6"
	fixtureSessionB = "b0000000-0000-4000-8000-00000000000b"
	fixtureSessionC = "d484a6af-2106-45c4-9d15-1c2212b76809"
	// session L (Plan 08): leak watch, the fixture's own rule and a Claude
	// Code Bash rule, written by fixture-sessions.py into every home
	fixtureSessionL = "e0000000-0000-4000-8000-00000000000e"
)

func fixtureTools(t *testing.T) {
	t.Helper()
	for _, tool := range []string{"bash", "python3"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not found: %v", tool, err)
		}
	}
}

// fixtureOutDir returns a path that does not exist yet, inside a fresh dir
// under /var/tmp that is removed when the test ends.
func fixtureOutDir(t *testing.T) string {
	t.Helper()
	parent, err := os.MkdirTemp("/var/tmp", "watchdeck-fixture-test-")
	if err != nil {
		t.Skipf("no /var/tmp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(parent) })
	return filepath.Join(parent, "fx")
}

// buildFixtureHome runs fixture-home.sh into out with args and returns the
// environment it prints (the export lines), parsed.
func buildFixtureHome(t *testing.T, out string, args ...string) map[string]string {
	t.Helper()
	return buildFixtureHomeIn(t, "", nil, out, args...)
}

// buildFixtureHomeIn is buildFixtureHome run from dir (when not empty) with
// extra environment variables.
func buildFixtureHomeIn(t *testing.T, dir string, extraEnv []string, out string, args ...string) map[string]string {
	t.Helper()
	script := filepath.Join(pkgDir, "..", "..", "scripts", "fixture-home.sh")
	cmd := exec.Command("bash", append([]string{script, out}, args...)...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), extraEnv...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("fixture-home.sh %v: %v\nstdout:\n%s\nstderr:\n%s", args, err, stdout.String(), stderr.String())
	}
	env := map[string]string{}
	exportLine := regexp.MustCompile(`^export ([A-Z_]+)='([^']*)'$`)
	for _, line := range strings.Split(stdout.String(), "\n") {
		if m := exportLine.FindStringSubmatch(line); m != nil {
			env[m[1]] = m[2]
		}
	}
	for _, k := range []string{"HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME", "CLAUDE_CONFIG_DIR", "WATCHDECK_ACTIVITY"} {
		if env[k] == "" {
			t.Fatalf("fixture-home.sh printed no %s:\n%s", k, stdout.String())
		}
	}
	return env
}

// fixtureSessions runs `<bin> advanced sessions --json [extra]` under the
// fixture environment and decodes the rows.
func fixtureSessions(t *testing.T, bin string, env map[string]string, extra ...string) []sessionRow {
	t.Helper()
	cmd := exec.Command(bin, append([]string{"advanced", "sessions", "--json"}, extra...)...)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	cmd.Dir = env["HOME"]
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("sessions %v: %v\n%s", extra, err, stderr.String())
	}
	var rows []sessionRow
	if err := json.Unmarshal(stdout.Bytes(), &rows); err != nil {
		t.Fatalf("sessions %v: not JSON: %v\n%s", extra, err, stdout.String())
	}
	return rows
}

func TestFixtureHomeMany(t *testing.T) {
	fixtureTools(t)
	bin := testBinary(t)
	env := buildFixtureHome(t, fixtureOutDir(t), "--many", "40", "--live", "3", "--seed", "1", "--now", "2026-10-20T00:00:00Z")

	all := fixtureSessions(t, bin, env)
	if len(all) != 47 {
		t.Fatalf("%d sessions, want 47 (A, 3 live derivatives, B, C, L, 40 synthetic)", len(all))
	}
	ids := map[string]bool{}
	projects := map[string]bool{}
	for _, r := range all {
		ids[r.ID] = true
		if strings.HasPrefix(r.Cwd, "/Users/you/work/") {
			projects[filepath.Base(r.Cwd)] = true
		}
	}
	for _, id := range []string{fixtureSessionA, fixtureSessionB, fixtureSessionC, fixtureSessionL,
		"a1000000-0000-4000-8000-000000000001", "a1000000-0000-4000-8000-000000000002", "a1000000-0000-4000-8000-000000000003"} {
		if !ids[id] {
			t.Errorf("session %s missing", id)
		}
	}
	if len(projects) != 9 {
		t.Errorf("%d distinct synthetic project names %v, want 9", len(projects), projects)
	}

	live := fixtureSessions(t, bin, env, "--state", "live")
	liveIDs := map[string]bool{}
	for _, r := range live {
		liveIDs[r.ID] = true
	}
	if len(live) != 4 || !liveIDs[fixtureSessionA] {
		t.Errorf("live sessions %v, want A and the 3 derivatives", liveIDs)
	}
	// The copies carry A's four captured activity records under their own
	// tool use ids, so every record joins: two decisions (an allow and an
	// ask), one run with a sandbox hint (a denial). They do not carry the two
	// records fixture-home.sh stamps for A's Needs you.
	liveProjects := map[string]string{}
	lasts := map[string]string{}
	for _, r := range live {
		name := filepath.Base(r.Cwd)
		if other, dup := liveProjects[name]; dup {
			t.Errorf("%s and %s share the project %s", r.ID, other, name)
		}
		liveProjects[name] = r.ID
		last := r.LastTS.UTC().Format("2006-01-02T15:04:05.000Z")
		if other, dup := lasts[last]; dup {
			t.Errorf("%s and %s share last_ts %s", r.ID, other, last)
		}
		lasts[last] = r.ID
		if r.ID == fixtureSessionA {
			continue
		}
		if !strings.HasPrefix(r.Cwd, "/Users/you/work/") {
			t.Errorf("%s: cwd %s, want one of the /Users/you/work projects", r.ID, r.Cwd)
		}
		if r.Decisions != 2 || r.Denials != 1 || r.Asks != 1 {
			t.Errorf("%s: decisions/denials/asks %d/%d/%d, want 2/1/1", r.ID, r.Decisions, r.Denials, r.Asks)
		}
	}

	ended := fixtureSessions(t, bin, env, "--state", "ended")
	endedIDs := map[string]bool{}
	synthDenials := 0
	for _, r := range ended {
		endedIDs[r.ID] = true
		if strings.HasPrefix(r.Cwd, "/Users/you/work/") && r.Denials > 0 {
			synthDenials++
		}
	}
	if len(ended) != 43 || !endedIDs[fixtureSessionB] || !endedIDs[fixtureSessionC] || !endedIDs[fixtureSessionL] {
		t.Errorf("%d ended sessions (B %v, C %v, L %v), want 43 with B, C and L", len(ended), endedIDs[fixtureSessionB], endedIDs[fixtureSessionC], endedIDs[fixtureSessionL])
	}
	if synthDenials == 0 {
		t.Error("no synthetic ended session has a denial")
	}
}

// fixtureSnapshot copies the deterministic parts of a fixture home: the
// projects tree, the activity log and the lifecycle records.
func fixtureSnapshot(t *testing.T, env map[string]string, dst string) {
	t.Helper()
	state := filepath.Join(env["XDG_STATE_HOME"], "watchdeck")
	if err := os.MkdirAll(dst, 0o700); err != nil {
		t.Fatal(err)
	}
	for src, to := range map[string]string{
		filepath.Join(env["CLAUDE_CONFIG_DIR"], "projects"): filepath.Join(dst, "projects"),
		filepath.Join(state, "activity.jsonl"):              filepath.Join(dst, "activity.jsonl"),
		filepath.Join(state, "sessions.jsonl"):              filepath.Join(dst, "sessions.jsonl"),
	} {
		if out, err := exec.Command("cp", "-Rp", src, to).CombinedOutput(); err != nil {
			t.Fatalf("cp %s: %v\n%s", src, err, out)
		}
	}
}

func TestFixtureHomeDeterministic(t *testing.T) {
	fixtureTools(t)
	out := fixtureOutDir(t)
	args := []string{"--many", "25", "--live", "2", "--seed", "7", "--now", "2026-10-20T00:00:00Z"}
	snaps := t.TempDir()
	// Same OUTDIR twice: the home's absolute paths (transcript_path) are part
	// of the bytes compared.
	for i, name := range []string{"one", "two"} {
		env := buildFixtureHome(t, out, args...)
		fixtureSnapshot(t, env, filepath.Join(snaps, name))
		if i == 0 {
			if err := os.RemoveAll(out); err != nil {
				t.Fatal(err)
			}
		}
	}
	diff := exec.Command("diff", "-r", filepath.Join(snaps, "one"), filepath.Join(snaps, "two"))
	if b, err := diff.CombinedOutput(); err != nil {
		t.Fatalf("two runs with the same seed and now differ: %v\n%s", err, b)
	}
}

func TestFixtureSessionsNoRealData(t *testing.T) {
	fixtureTools(t)
	// The developer's names, read before anything changes HOME; never
	// written into this file.
	user := os.Getenv("USER")
	realHome, _ := os.UserHomeDir()
	env := buildFixtureHome(t, fixtureOutDir(t), "--many", "60", "--live", "2", "--seed", "3")

	needles := []string{"sk-", "AKIA", "ghp_", "-----BEGIN"}
	if user != "" && user != "you" {
		// as a path component: a short name ("ci") is inside ordinary words
		needles = append(needles, "/"+user+"/")
	}
	if realHome != "" && realHome != "/Users/you" {
		needles = append(needles, realHome)
	}
	otherUsers := regexp.MustCompile(`/Users/[A-Za-z0-9._-]+`)
	err := filepath.WalkDir(env["HOME"], func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() { // dirs, and the fixture's symlinks (one loops)
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel := strings.TrimPrefix(p, env["HOME"])
		for _, n := range needles {
			if bytes.Contains(b, []byte(n)) {
				t.Errorf("%s contains %q", rel, n)
			}
		}
		for _, m := range otherUsers.FindAll(b, -1) {
			if string(m) != "/Users/you" {
				t.Errorf("%s names %s", rel, m)
				break
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestFixtureHomeInstalled: --installed copies $WATCHDECK_BIN into
// OUTDIR/bin and installs that path, so the fixture's settings.json names no
// path outside OUTDIR (a binary under the real home would otherwise put a
// login path into screenshots). WATCHDECK_BIN is given relative, from the
// binary's own dir, which the script must resolve before it changes dir.
func TestFixtureHomeInstalled(t *testing.T) {
	fixtureTools(t)
	user := os.Getenv("USER")
	bin := testBinary(t) // built under the per-user temp dir, outside OUTDIR
	out := fixtureOutDir(t)
	parent, err := filepath.EvalSymlinks(filepath.Dir(out)) // the script resolves /var to /private/var
	if err != nil {
		t.Fatal(err)
	}
	outReal := filepath.Join(parent, filepath.Base(out))
	env := buildFixtureHomeIn(t, filepath.Dir(bin), []string{"WATCHDECK_BIN=./" + filepath.Base(bin)}, out,
		"--installed", "--now", "2026-10-20T00:00:00Z")

	b, err := os.ReadFile(filepath.Join(env["CLAUDE_CONFIG_DIR"], "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("settings.json: %v", err)
	}
	absPath := regexp.MustCompile(`(?:^|[\s"'(=])(/[^\s"')]+)`)
	var strs []string
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case string:
			strs = append(strs, x)
		case []any:
			for _, e := range x {
				walk(e)
			}
		case map[string]any:
			for k, e := range x {
				strs = append(strs, k)
				walk(e)
			}
		}
	}
	walk(doc)
	hooked := false
	for _, str := range strs {
		for _, m := range absPath.FindAllStringSubmatch(str, -1) {
			if !strings.HasPrefix(m[1], outReal+"/") {
				t.Errorf("settings.json names a path outside OUTDIR: %q (in %q)", m[1], str)
			}
		}
		if str == filepath.Join(outReal, "bin", "watchdeck") || strings.HasPrefix(str, filepath.Join(outReal, "bin", "watchdeck")+" ") {
			hooked = true
		}
	}
	if !hooked {
		t.Errorf("no hook names %s:\n%s", filepath.Join(outReal, "bin", "watchdeck"), b)
	}
	if strings.Contains(string(b), filepath.Dir(bin)) {
		t.Errorf("settings.json names the source binary's dir %s", filepath.Dir(bin))
	}
	if user != "" && user != "you" && strings.Contains(string(b), "/"+user+"/") {
		t.Error("settings.json contains the login name as a path component")
	}
	if !strings.Contains(string(b), "Read(~/.ssh/id_*)") {
		t.Errorf("recommended rules not installed:\n%s", b)
	}
}

// TestFixtureActivityVariety: the synthetic sessions' Needs-you records name
// real pack rules, several of them, not one rule over and over.
func TestFixtureActivityVariety(t *testing.T) {
	fixtureTools(t)
	env := buildFixtureHome(t, fixtureOutDir(t), "--many", "60", "--seed", "5", "--now", "2026-10-20T00:00:00Z")
	b, err := os.ReadFile(env["WATCHDECK_ACTIVITY"])
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	programs := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var r struct {
			SessionID string `json:"session_id"`
			Argv0     string `json:"argv0"`
			Rules     []struct {
				Pack, ID string
			} `json:"rules"`
		}
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("%v: %s", err, line)
		}
		if r.SessionID == fixtureSessionA {
			continue // the two records fixture-home.sh stamps
		}
		for _, h := range r.Rules {
			ids[h.Pack+"/"+h.ID] = true
		}
		if r.Argv0 != "" {
			programs[r.Argv0] = true
		}
	}
	if len(ids) < 3 || len(programs) < 3 {
		t.Errorf("rules %v, programs %v: want at least three of each", ids, programs)
	}
}

// fixtureRun runs bin with args under the fixture environment, from the
// fixture's project, and returns its stdout.
func fixtureRun(t *testing.T, bin string, env map[string]string, args ...string) []byte {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	cmd.Dir = filepath.Join(env["HOME"], "proj")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("%v: %v\n%s", args, err, stderr.String())
	}
	return stdout.Bytes()
}

// TestFixtureHomePlan08: every home, built with a binary, holds what the
// walk's Plan 08 checks look for: session L with two leak findings (a Read
// result and a reply), the person's rule fixture-prod-db with three ask
// records, the person's Claude Code rule Bash(npm publish *) with one
// record, a pause of persistence/crontab in force, and one intent of four
// rows (the ~/.kube/config path, every route).
func TestFixtureHomePlan08(t *testing.T) {
	fixtureTools(t)
	bin := testBinary(t)
	env := buildFixtureHomeIn(t, "", []string{"WATCHDECK_BIN=" + bin}, fixtureOutDir(t))

	var leakL []sessionindexFinding
	for _, r := range fixtureSessions(t, bin, env) {
		if r.ID == fixtureSessionL {
			for _, f := range r.Findings {
				leakL = append(leakL, sessionindexFinding{f.Pattern, f.Where, f.Tool})
			}
		}
	}
	want := []sessionindexFinding{{"slack-token", "result", "Read"}, {"slack-token", "reply", ""}}
	if len(leakL) != 2 || leakL[0] != want[0] || leakL[1] != want[1] {
		t.Errorf("session L findings %v, want %v", leakL, want)
	}

	b, err := os.ReadFile(env["WATCHDECK_ACTIVITY"])
	if err != nil {
		t.Fatal(err)
	}
	hits := map[string]int{}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var r struct {
			SessionID string `json:"session_id"`
			Decision  string `json:"decision"`
			Rules     []struct{ Pack, ID, Action string }
		}
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("%v: %s", err, line)
		}
		if r.SessionID != fixtureSessionL {
			continue
		}
		for _, h := range r.Rules {
			hits[h.Pack+"/"+h.ID+" "+h.Action+" "+r.Decision]++
		}
	}
	if hits["user/fixture-prod-db ask ask"] != 3 || hits["claude-settings/Bash(npm publish *) deny deny"] != 1 || len(hits) != 2 {
		t.Errorf("session L rule hits %v, want 3 asks by fixture-prod-db and 1 deny by Bash(npm publish *)", hits)
	}

	if out := fixtureRun(t, bin, env, "rules", "pause", "--list"); !bytes.Contains(out, []byte("persistence/crontab")) {
		t.Errorf("no pause of persistence/crontab in force:\n%s", out)
	}

	var book struct {
		Groups []struct {
			Rows []struct {
				ID     string `json:"id"`
				Value  string `json:"value"`
				Intent *struct {
					ID   string `json:"id"`
					Rows int    `json:"rows"`
				} `json:"intent"`
			} `json:"rows"`
		} `json:"groups"`
	}
	if err := json.Unmarshal(fixtureRun(t, bin, env, "rules", "list", "--json"), &book); err != nil {
		t.Fatal(err)
	}
	intentRows := map[string]int{}
	user, native := false, false
	for _, g := range book.Groups {
		for _, r := range g.Rows {
			if r.Intent != nil && r.Intent.Rows == 4 {
				intentRows[r.Intent.ID]++
			}
			user = user || r.ID == "user:fixture-prod-db"
			native = native || r.Value == "Bash(npm publish *)"
		}
	}
	if len(intentRows) != 1 || !user || !native {
		t.Errorf("intents %v (want one of 4 rows), fixture-prod-db %v, Bash(npm publish *) %v", intentRows, user, native)
	}
	for id, n := range intentRows {
		if n != 4 {
			t.Errorf("intent %s lists %d rows, want 4", id, n)
		}
	}
}

type sessionindexFinding struct{ Pattern, Where, Tool string }
