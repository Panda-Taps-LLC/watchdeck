package ui

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/settings"
)

// Every test here injects Options.Settings with paths under t.TempDir():
// nothing may write the developer's ~/.claude/settings.json.

type enforceView struct {
	Targets []struct {
		ID     string         `json:"id"`
		Path   string         `json:"path"`
		Exists bool           `json:"exists"`
		Status map[string]any `json:"status"`
		Error  string         `json:"error"`
		Note   string         `json:"note"`
	} `json:"targets"`
	Nonce           string `json:"nonce"`
	NonceTTLSeconds int    `json:"nonceTtlSeconds"`
}

type enforceResultView struct {
	Change *struct {
		Added   []string `json:"added"`
		Removed []string `json:"removed"`
		Backup  string   `json:"backup"`
	} `json:"change"`
	Status map[string]any `json:"status"`
}

// enforceOptions is a server whose user settings file is user (and project
// file project, "" for none), with a movable clock and a fake binary path.
func enforceOptions(t *testing.T, user, project string) (Options, *atomic.Int64) {
	t.Helper()
	clock := new(atomic.Int64)
	clock.Store(time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC).UnixNano())
	o := emptyOptions(t)
	o.Now = func() time.Time { return time.Unix(0, clock.Load()) }
	o.Binary = filepath.Join(t.TempDir(), "bin", "watchdeck")
	o.Settings = func() (string, string) { return user, project }
	return o, clock
}

func getEnforce(t *testing.T, ts *testServer) enforceView {
	t.Helper()
	resp, b := ts.do(t, req{Path: "/api/enforce", Token: ts.s.Token()})
	if resp.StatusCode != 200 {
		t.Fatalf("GET /api/enforce = %d %s", resp.StatusCode, b)
	}
	var v enforceView
	decode(t, b, &v)
	return v
}

func postEnforce(t *testing.T, ts *testServer, body string) (int, []byte) {
	t.Helper()
	resp, b := ts.do(t, req{Method: "POST", Path: "/api/enforce", Body: body, Origin: "auto", Token: ts.s.Token(), Header: jsonCT()})
	return resp.StatusCode, b
}

func enforceBody(target, action, nonce string) string {
	return `{"target":` + jsonString(target) + `,"action":` + jsonString(action) + `,"nonce":` + jsonString(nonce) + `}`
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestEnforceNonceOneUse(t *testing.T) {
	user := filepath.Join(t.TempDir(), "claude", "settings.json")
	writeFile(t, user, "{}\n")
	o, clock := enforceOptions(t, user, "")
	ts := startServer(t, o)

	v := getEnforce(t, ts)
	if len(v.Nonce) != 2*nonceBytes || strings.Trim(v.Nonce, "0123456789abcdef") != "" {
		t.Fatalf("nonce %q is not 16 bytes of hex", v.Nonce)
	}
	if v.NonceTTLSeconds != 300 || len(v.Targets) != 1 || v.Targets[0].ID != "user" || v.Targets[0].Path != user || !v.Targets[0].Exists {
		t.Fatalf("GET = %+v", v)
	}
	if v2 := getEnforce(t, ts); v2.Nonce == v.Nonce {
		t.Fatal("two GETs returned the same nonce")
	}

	// Install with the nonce: 200, a backup beside the existing file. The
	// default packs watch the file tools, so the install has one extra
	// group (PreToolUse Read|Write|Edit|MultiEdit|NotebookEdit, M6.3).
	code, b := postEnforce(t, ts, enforceBody("user", "install", v.Nonce))
	if code != 200 {
		t.Fatalf("install = %d %s", code, b)
	}
	var res enforceResultView
	decode(t, b, &res)
	if res.Change == nil || len(res.Change.Added) != settings.HookCount+2 || res.Change.Removed == nil || len(res.Change.Removed) != 0 {
		t.Fatalf("install change = %s", b)
	}
	if !strings.HasPrefix(res.Change.Backup, user+".bak-") {
		t.Fatalf("backup = %q, want %s.bak-<ts>", res.Change.Backup, user)
	}
	if _, err := os.Stat(res.Change.Backup); err != nil {
		t.Fatalf("backup file: %v", err)
	}
	if res.Status["complete"] != true || res.Status["hookCommand"] != o.Binary {
		t.Fatalf("status after install = %v", res.Status)
	}
	st, err := settings.Inspect(user)
	if err != nil || !st.Complete {
		t.Fatalf("Inspect after install = %+v, %v", st, err)
	}

	// The same nonce again: spent.
	code, b = postEnforce(t, ts, enforceBody("user", "uninstall", v.Nonce))
	if code != 403 || errorBody(t, b) != "stale nonce" {
		t.Fatalf("reused nonce = %d %s, want 403 stale nonce", code, b)
	}
	// A nonce never issued.
	code, b = postEnforce(t, ts, enforceBody("user", "uninstall", strings.Repeat("ab", nonceBytes)))
	if code != 403 || errorBody(t, b) != "stale nonce" {
		t.Fatalf("unknown nonce = %d %s, want 403", code, b)
	}
	// Expired: one second past the TTL on the injected clock.
	old := getEnforce(t, ts).Nonce
	clock.Add(int64(nonceTTL + time.Second))
	code, b = postEnforce(t, ts, enforceBody("user", "uninstall", old))
	if code != 403 || errorBody(t, b) != "stale nonce" {
		t.Fatalf("expired nonce = %d %s, want 403", code, b)
	}
	// Exactly at the TTL is still valid.
	atTTL := getEnforce(t, ts).Nonce
	clock.Add(int64(nonceTTL))
	if code, b = postEnforce(t, ts, enforceBody("user", "install", atTTL)); code != 200 {
		t.Fatalf("nonce at exactly the TTL = %d %s, want 200", code, b)
	}
	decode(t, b, &res)
	if len(res.Change.Added) != 0 || res.Change.Backup != "" {
		t.Fatalf("second install should change nothing: %s", b)
	}

	// Missing nonce: 400. A malformed request does not spend a nonce.
	n := getEnforce(t, ts).Nonce
	for _, body := range []string{
		`{"target":"user","action":"install"}`,
		enforceBody("user", "install", ""),
		enforceBody("elsewhere", "install", n),
		enforceBody("user", "reinstall", n),
		`{"target":"user","action":"install","nonce":"` + n + `","extra":1}`,
	} {
		if code, b := postEnforce(t, ts, body); code != 400 {
			t.Errorf("POST %s = %d %s, want 400", body, code, b)
		}
	}
	code, b = postEnforce(t, ts, enforceBody("user", "uninstall", n))
	if code != 200 {
		t.Fatalf("uninstall with a nonce that only saw bad requests = %d %s", code, b)
	}
	decode(t, b, &res)
	if len(res.Change.Removed) != settings.HookCount+2 || res.Status["complete"] != false || res.Status["hookInstalled"] != false {
		t.Fatalf("uninstall = %s", b)
	}
	if got, err := os.ReadFile(user); err != nil || strings.TrimSpace(string(got)) != "{}" {
		t.Fatalf("settings after uninstall = %q, %v", got, err)
	}
}

// TestEnforceNonceSpentOnFailure: a nonce is spent even when the action
// fails (no binary path, unparseable settings, no project target).
func TestEnforceNonceSpentOnFailure(t *testing.T) {
	user := filepath.Join(t.TempDir(), "settings.json")
	o, _ := enforceOptions(t, user, "")
	o.Binary = ""
	ts := startServer(t, o)

	n := getEnforce(t, ts).Nonce
	code, b := postEnforce(t, ts, enforceBody("user", "install", n))
	if code != 500 || !strings.Contains(errorBody(t, b), "binary") {
		t.Fatalf("install without Binary = %d %s, want 500", code, b)
	}
	if _, err := os.Stat(user); !os.IsNotExist(err) {
		t.Fatalf("install without Binary wrote the file: %v", err)
	}
	if code, _ = postEnforce(t, ts, enforceBody("user", "uninstall", n)); code != 403 {
		t.Fatalf("nonce after a failed install = %d, want 403", code)
	}

	n = getEnforce(t, ts).Nonce
	if code, b = postEnforce(t, ts, enforceBody("project", "install", n)); code != 400 {
		t.Fatalf("project install with no project = %d %s, want 400", code, b)
	}
	if code, _ = postEnforce(t, ts, enforceBody("user", "uninstall", n)); code != 403 {
		t.Fatalf("nonce after a refused project install = %d, want 403", code)
	}

	writeFile(t, user, "{not json")
	n = getEnforce(t, ts).Nonce
	if code, b = postEnforce(t, ts, enforceBody("user", "uninstall", n)); code != 500 {
		t.Fatalf("uninstall on a malformed file = %d %s, want 500", code, b)
	}
	if got, _ := os.ReadFile(user); string(got) != "{not json" {
		t.Fatalf("malformed file was rewritten: %q", got)
	}
	if code, _ = postEnforce(t, ts, enforceBody("user", "uninstall", n)); code != 403 {
		t.Fatalf("nonce after a failed uninstall = %d, want 403", code)
	}
}

// TestEnforceNonceCap: at most 64 live nonces; the oldest goes first.
func TestEnforceNonceCap(t *testing.T) {
	user := filepath.Join(t.TempDir(), "settings.json")
	o, clock := enforceOptions(t, user, "")
	o.Binary = "" // uninstall only; nothing is written for an absent file
	ts := startServer(t, o)

	first := getEnforce(t, ts).Nonce
	second := ""
	for i := 0; i < maxNonces; i++ {
		clock.Add(int64(time.Millisecond)) // distinct issue times
		n := getEnforce(t, ts).Nonce
		if i == 0 {
			second = n
		}
	}
	ts.s.nonceMu.Lock()
	live := len(ts.s.nonces)
	ts.s.nonceMu.Unlock()
	if live != maxNonces {
		t.Fatalf("live nonces = %d, want %d", live, maxNonces)
	}
	if code, _ := postEnforce(t, ts, enforceBody("user", "uninstall", first)); code != 403 {
		t.Fatalf("oldest nonce past the cap = %d, want 403", code)
	}
	if code, b := postEnforce(t, ts, enforceBody("user", "uninstall", second)); code != 200 {
		t.Fatalf("second-oldest nonce = %d %s, want 200", code, b)
	}

	// Expired nonces are pruned on GET.
	clock.Add(int64(nonceTTL + time.Second))
	getEnforce(t, ts)
	ts.s.nonceMu.Lock()
	live = len(ts.s.nonces)
	ts.s.nonceMu.Unlock()
	if live != 1 {
		t.Fatalf("live nonces after expiry and one GET = %d, want 1", live)
	}
}

func TestEnforceProjectNote(t *testing.T) {
	tmp := t.TempDir()
	user := filepath.Join(tmp, "user", "settings.json")
	project := filepath.Join(tmp, "proj", ".claude", "settings.json")
	o, _ := enforceOptions(t, user, project)
	ts := startServer(t, o)

	v := getEnforce(t, ts)
	if len(v.Targets) != 2 || v.Targets[0].ID != "user" || v.Targets[1].ID != "project" {
		t.Fatalf("targets = %+v", v.Targets)
	}
	p := v.Targets[1]
	if p.Path != project || p.Exists || p.Note != projectNote || p.Status == nil || p.Status["exists"] != false {
		t.Fatalf("project target = %+v", p)
	}
	if v.Targets[0].Note != "" {
		t.Fatalf("user target carries a note: %q", v.Targets[0].Note)
	}
	if !strings.Contains(p.Note, "excludedCommands") || !strings.Contains(p.Note, "admin") {
		t.Fatalf("note = %q", p.Note)
	}

	// Install into the project creates the file (and its .claude dir); no
	// backup because there was nothing to copy. The user file is untouched.
	code, b := postEnforce(t, ts, enforceBody("project", "install", v.Nonce))
	if code != 200 {
		t.Fatalf("project install = %d %s", code, b)
	}
	var res enforceResultView
	decode(t, b, &res)
	if res.Change.Backup != "" || len(res.Change.Added) != settings.HookCount+2 || res.Status["complete"] != true {
		t.Fatalf("project install = %s", b)
	}
	if _, err := os.Stat(project); err != nil {
		t.Fatalf("project settings: %v", err)
	}
	if _, err := os.Stat(user); !os.IsNotExist(err) {
		t.Fatalf("user settings touched: %v", err)
	}

	// A project file that does not parse: the target has error, no status.
	writeFile(t, project, "[1,2")
	v = getEnforce(t, ts)
	p = v.Targets[1]
	if p.Error == "" || p.Status != nil || !p.Exists || p.Note != projectNote {
		t.Fatalf("malformed project target = %+v", p)
	}

	// No project root: only the user target.
	o2, _ := enforceOptions(t, user, "")
	if v := getEnforce(t, startServer(t, o2)); len(v.Targets) != 1 || v.Targets[0].ID != "user" {
		t.Fatalf("no project: targets = %+v", v.Targets)
	}
}

// TestEnforceDefaultSettingsPaths: without the Settings override the user
// target is Paths.ClaudeSettings() and the project target appears only when
// cwd is inside a git repository below home. GET only; home is a temp dir.
func TestEnforceDefaultSettingsPaths(t *testing.T) {
	o := emptyOptions(t)
	home := o.Paths.Home
	v := getEnforce(t, startServer(t, o))
	if len(v.Targets) != 1 || v.Targets[0].Path != filepath.Join(home, ".claude", "settings.json") {
		t.Fatalf("no repo: targets = %+v", v.Targets)
	}

	o = emptyOptions(t)
	home = o.Paths.Home
	repo := filepath.Join(home, "proj")
	if err := os.MkdirAll(filepath.Join(repo, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	o.Cwd = filepath.Join(repo, "sub")
	if err := os.MkdirAll(o.Cwd, 0o755); err != nil {
		t.Fatal(err)
	}
	v = getEnforce(t, startServer(t, o))
	if len(v.Targets) != 2 || v.Targets[1].Path != filepath.Join(repo, ".claude", "settings.json") || v.Targets[1].Note != projectNote {
		t.Fatalf("in repo: targets = %+v", v.Targets)
	}
}

// TestEnforceStatusMatchesInspect: each target's status is settings.Inspect
// field for field (camelCase keys), and agrees with /api/status "hook".
func TestEnforceStatusMatchesInspect(t *testing.T) {
	tmp := t.TempDir()
	user := filepath.Join(tmp, "settings.json")
	o, _ := enforceOptions(t, user, "")
	ts := startServer(t, o)

	partial := `{"sandbox":{"enabled":true,"excludedCommands":["` + settings.ExcludedCommand + `"]},` +
		`"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"/opt/fake/watchdeck","args":["hook"]}]}]}}`
	for _, tc := range []struct {
		name, content string
		install       bool
	}{
		{"absent", "", false},
		{"empty", "{}", false},
		{"partial", partial, false},
		{"complete", "{}", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			os.Remove(user)
			if tc.content != "" {
				writeFile(t, user, tc.content)
			}
			if tc.install {
				if _, err := settings.Install(user, o.Binary); err != nil {
					t.Fatal(err)
				}
			}
			st, err := settings.Inspect(user)
			if err != nil {
				t.Fatal(err)
			}
			want := inspectMap(t, st)

			v := getEnforce(t, ts)
			got := v.Targets[0].Status
			if !reflect.DeepEqual(got, want) {
				t.Errorf("status = %v\nwant     %v", got, want)
			}
			for _, k := range []string{"hookInstalled", "skillHook", "deniedHook", "startHook", "endHook", "promptHook", "excluded", "sandboxEnabled", "complete", "hookCommand", "exists"} {
				if _, ok := got[k]; !ok {
					t.Errorf("status lacks %q", k)
				}
			}
			if v.Targets[0].Exists != st.Exists {
				t.Errorf("exists = %v, Inspect says %v", v.Targets[0].Exists, st.Exists)
			}

			_, b := ts.do(t, req{Path: "/api/status", Token: ts.s.Token()})
			var sv statusView
			decode(t, b, &sv)
			delete(sv.Hook, "path")
			if !reflect.DeepEqual(sv.Hook, want) {
				t.Errorf("/api/status hook = %v\nwant              %v", sv.Hook, want)
			}
		})
	}
}

// inspectMap is st as the page sees it: JSON with lower-cased first letters.
func inspectMap(t *testing.T, st settings.Status) map[string]any {
	t.Helper()
	b, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	out := map[string]any{}
	for k, v := range raw {
		out[strings.ToLower(k[:1])+k[1:]] = v
	}
	return out
}

// TestEnforceRequiresGuard: both methods sit behind the guard, and a
// refused request does not spend the nonce.
func TestEnforceRequiresGuard(t *testing.T) {
	user := filepath.Join(t.TempDir(), "settings.json")
	o, _ := enforceOptions(t, user, "")
	ts := startServer(t, o)

	if resp, _ := ts.do(t, req{Path: "/api/enforce"}); resp.StatusCode != 401 {
		t.Fatalf("GET without token = %d, want 401", resp.StatusCode)
	}
	n := getEnforce(t, ts).Nonce
	body := enforceBody("user", "install", n)
	if resp, _ := ts.do(t, req{Method: "POST", Path: "/api/enforce", Body: body, Origin: "auto", Header: jsonCT()}); resp.StatusCode != 401 {
		t.Fatalf("POST without token = %d, want 401", resp.StatusCode)
	}
	if resp, _ := ts.do(t, req{Method: "POST", Path: "/api/enforce", Body: body, Token: ts.s.Token(), Header: jsonCT()}); resp.StatusCode != 403 {
		t.Fatalf("POST without Origin = %d, want 403", resp.StatusCode)
	}
	if resp, _ := ts.do(t, req{Method: "POST", Path: "/api/enforce", Body: body, Origin: "http://evil.example", Token: ts.s.Token(), Header: jsonCT()}); resp.StatusCode != 403 {
		t.Fatalf("POST cross-origin = %d, want 403", resp.StatusCode)
	}
	if resp, _ := ts.do(t, req{Method: "POST", Path: "/api/enforce", Body: body, Origin: "auto", Token: ts.s.Token()}); resp.StatusCode != 415 {
		t.Fatalf("POST without JSON content type = %d, want 415", resp.StatusCode)
	}
	if _, err := os.Stat(user); !os.IsNotExist(err) {
		t.Fatalf("a refused request wrote settings: %v", err)
	}
	if code, b := postEnforce(t, ts, body); code != 200 {
		t.Fatalf("POST with the nonce after refused attempts = %d %s, want 200", code, b)
	}
	if resp, _ := ts.do(t, req{Method: "PUT", Path: "/api/enforce", Body: "{}", Origin: "auto", Token: ts.s.Token(), Header: jsonCT()}); resp.StatusCode != 405 {
		t.Fatalf("PUT = %d, want 405", resp.StatusCode)
	}
}

// TestNonceCapPerPurpose: the cap is per purpose (final review of Plan 04,
// finding 5, 2026-10-19). A busy Home tab mints a needs nonce on every
// refetch; seventy of them must not evict another tab's rules nonce, while
// the oldest needs nonce still goes first.
func TestNonceCapPerPurpose(t *testing.T) {
	user := filepath.Join(t.TempDir(), "settings.json")
	o, clock := enforceOptions(t, user, "")
	ts := startServer(t, o)
	clock.Add(int64(time.Millisecond))
	rules, err := ts.s.issueNonce(purposeRules)
	if err != nil {
		t.Fatal(err)
	}
	var needs []string
	for i := 0; i < 70; i++ {
		clock.Add(int64(time.Millisecond)) // the rules nonce is the oldest of all
		n, err := ts.s.issueNonce(purposeNeeds)
		if err != nil {
			t.Fatal(err)
		}
		needs = append(needs, n)
	}
	ts.s.nonceMu.Lock()
	perNeeds := 0
	for k := range ts.s.nonces {
		if strings.HasPrefix(k, purposeNeeds+":") {
			perNeeds++
		}
	}
	ts.s.nonceMu.Unlock()
	if perNeeds != maxNonces {
		t.Errorf("live needs nonces = %d, want %d", perNeeds, maxNonces)
	}
	if ts.s.spendNonce(needs[0], purposeNeeds) {
		t.Error("the oldest needs nonce past the cap was still live")
	}
	if !ts.s.spendNonce(needs[69], purposeNeeds) {
		t.Error("the newest needs nonce was not live")
	}
	if !ts.s.spendNonce(rules, purposeRules) {
		t.Error("seventy needs nonces evicted the rules nonce")
	}
}
