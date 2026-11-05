package ui

import (
	"bytes"
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

// M5.5: the Sessions page registers through the barrel. Since Plan 04
// Task 1 (2026-10-19) the nav is Home, Sessions, Rules and a Settings gear;
// Sessions is the second tab, before Rules.
func TestSessionsPageRegistered(t *testing.T) {
	read := func(name string) string {
		b, err := fs.ReadFile(StaticFS, name)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	if !regexp.MustCompile(`import\s+["']\./sessions\.js["']`).MatchString(read("static/pages.js")) {
		t.Error("pages.js does not import ./sessions.js")
	}
	if !strings.Contains(read("static/sessions.js"), `registerPage("sessions"`) {
		t.Error("sessions.js does not register the sessions page")
	}
	idx := read("static/index.html")
	if !strings.Contains(idx, `data-page="sessions" href="#/sessions"`) {
		t.Error("index.html: Sessions tab missing")
	}
	s, r := strings.Index(idx, `data-page="sessions"`), strings.Index(idx, `data-page="rules"`)
	if r < 0 || s > r {
		t.Error("the Sessions tab is not before the Rules tab")
	}
}

// Plan 04 Task 1 (2026-10-19): the Home page is the home page: the default
// route "#/", the brand link and the first tab; Rules is the third tab and
// Settings a gear after it. Each registers through the barrel.
func TestHomePageIsHome(t *testing.T) {
	read := func(name string) string {
		b, err := fs.ReadFile(StaticFS, name)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	barrel := read("static/pages.js")
	for _, mod := range []string{"home", "rules", "settings", "sessions", "map"} {
		if !regexp.MustCompile(`import\s+["']\./` + mod + `\.js["']`).MatchString(barrel) {
			t.Errorf("pages.js does not import ./%s.js", mod)
		}
	}
	if strings.Contains(barrel, "overview.js") {
		t.Error("pages.js still imports overview.js")
	}
	for file, page := range map[string]string{"static/home.js": "home", "static/rules.js": "rules", "static/settings.js": "settings"} {
		if !strings.Contains(read(file), `registerPage("`+page+`"`) {
			t.Errorf("%s does not register the %s page", file, page)
		}
	}
	app := read("static/app.js")
	if !strings.Contains(app, `const DEFAULT_ROUTE = "#/";`) {
		t.Error(`the default route is not "#/"`)
	}
	idx := read("static/index.html")
	if !strings.Contains(idx, `class="brand" href="#/"`) || !strings.Contains(idx, `data-page="home" href="#/"`) {
		t.Error("index.html: brand link or Home tab missing")
	}
	if !strings.Contains(idx, `data-page="rules" href="#/rules"`) {
		t.Error("index.html: Rules tab missing")
	}
	gear := regexp.MustCompile(`<a class="[^"]*\bgear\b[^"]*" data-page="settings" href="#/settings"`)
	if !gear.MatchString(idx) {
		t.Error("index.html: Settings gear missing")
	}
	h, s, r, g := strings.Index(idx, `data-page="home"`), strings.Index(idx, `data-page="sessions"`), strings.Index(idx, `data-page="rules"`), strings.Index(idx, `data-page="settings"`)
	if h < 0 || !(h < s && s < r && r < g) {
		t.Error("nav order is not Home, Sessions, Rules, Settings")
	}
	for _, gone := range []string{`data-page="overview"`, `data-page="flow"`, `data-page="skills"`, `data-page="grants"`, `data-page="enforce"`, `id="session-picker"`} {
		if strings.Contains(idx, gone) {
			t.Errorf("index.html still has %s", gone)
		}
	}
	for _, id := range []string{`id="protect-state"`, `id="protect-light"`, `id="theme-toggle"`} {
		if !strings.Contains(idx, id) {
			t.Errorf("index.html lacks %s", id)
		}
	}
	// Home (Plan 04 Task 9): writes through write.js, the Live now cards
	// from sessions.js, recent rows linking into the map's timeline, and
	// the needs and recent routes.
	home := read("static/home.js")
	for _, re := range []string{
		`import\s*\{[^}]*\bwriteWithConfirm\b[^}]*\}\s*from\s*["']\./write\.js["']`,
		`import\s*\{[^}]*\bliveCard\b[^}]*\}\s*from\s*["']\./sessions\.js["']`,
		`import\s*\{[^}]*\btimelineHash\b[^}]*\}\s*from\s*["']\./map\.js["']`,
	} {
		if !regexp.MustCompile(re).MatchString(home) {
			t.Errorf("home.js lacks the import %s", re)
		}
	}
	for _, s := range []string{"/api/needs", "/api/recent", "/api/sessions?state=live", "/api/enforce", "/api/rules", "liveCard(", "timelineHash(", "writeWithConfirm("} {
		if !strings.Contains(home, s) {
			t.Errorf("home.js does not use %s", s)
		}
	}
	if regexp.MustCompile(`["']\./pages\.js["']`).MatchString(home) {
		t.Error("home.js imports pages.js (the barrel)")
	}
}

// Old links (toasts, the README, bookmarks) still land: app.js keeps a
// table from each old first segment to its new home, and the Flow rows turn
// hide_none into the authority filter.
func TestLegacyRouteTable(t *testing.T) {
	b, err := fs.ReadFile(StaticFS, "static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	app := string(b)
	i := strings.Index(app, "export const LEGACY_ROUTES")
	if i < 0 {
		t.Fatal("app.js does not export LEGACY_ROUTES")
	}
	table := app[i:]
	if end := strings.Index(table, "\n};"); end > 0 {
		table = table[:end]
	}
	for _, key := range []string{"overview", "skills", "grants", "enforce", "flow"} {
		if !regexp.MustCompile(`(?m)^\s*` + key + `\s*[:(]`).MatchString(table) {
			t.Errorf("LEGACY_ROUTES has no %s row", key)
		}
	}
	// The Flow rows share one helper (flowTarget) that reads hide_none and
	// builds a= from AUTHORITY_ALL.
	if !regexp.MustCompile(`query\.hide_none\b`).MatchString(app) {
		t.Error("app.js does not translate hide_none")
	}
	if !strings.Contains(app, "AUTHORITY_ALL.filter(") {
		t.Error("app.js does not build the authority filter from AUTHORITY_ALL")
	}
	if !strings.Contains(app, "LEGACY_ROUTES") || !regexp.MustCompile(`history\.replaceState\(null, "", `).MatchString(app) {
		t.Error("route() does not replace the hash for a legacy route")
	}
}

// The theme toggle: data-theme on <html> forces light or dark; without it
// the OS preference applies. Both dark paths carry the same tokens, and the
// Flow canvas tokens are never themed.
func TestThemeTokens(t *testing.T) {
	b, err := fs.ReadFile(StaticFS, "static/app.css")
	if err != nil {
		t.Fatal(err)
	}
	css := string(b)
	for _, want := range []string{`:root:not([data-theme="light"])`, `:root[data-theme="dark"]`, `:root[data-theme="light"] { color-scheme: light; }`} {
		if !strings.Contains(css, want) {
			t.Errorf("app.css lacks %s", want)
		}
	}
	if n := strings.Count(css, "--tag-net-bg: rgba(242, 107, 107, .12);"); n != 2 {
		t.Errorf("the dark --tag-net-bg appears %d times, want 2 (auto dark and forced dark)", n)
	}
	if strings.Count(css, "--cv-bg:") != 1 {
		t.Error("--cv-bg must be defined once (the Flow canvas is dark in every theme)")
	}
	app, err := fs.ReadFile(StaticFS, "static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(app), `const THEME_KEY = "watchdeck.theme";`) {
		t.Error("app.js lacks the theme key")
	}
}

// sessions.js is served like the other scripts: JavaScript type, the CSP.
func TestSessionsScriptServedWithCSP(t *testing.T) {
	ts := startServer(t, emptyOptions(t))
	resp, body := ts.do(t, req{Path: "/sessions.js"})
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/javascript") || !bytes.Contains(body, []byte(`registerPage("sessions"`)) {
		t.Fatalf("GET /sessions.js = %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.HasPrefix(csp, "default-src 'none'; script-src 'self';") {
		t.Errorf("CSP: %q", csp)
	}
}

// The token never travels in a URL: no EventSource (it cannot send an
// Authorization header), the event stream is read only through rawFetch
// (which sets the header), and no script builds a URL with a token
// parameter.
func TestNoTokenInAnyURL(t *testing.T) {
	err := fs.WalkDir(StaticFS, "static", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !(strings.HasSuffix(p, ".js") || strings.HasSuffix(p, ".html")) {
			return err
		}
		b, err := fs.ReadFile(StaticFS, p)
		if err != nil {
			return err
		}
		if bytes.Contains(b, []byte("EventSource")) && !bytes.Contains(b, []byte("EventSource cannot")) {
			t.Errorf("%s uses EventSource", p)
		}
		if regexp.MustCompile(`[?&](token|access_token|t)=`).Match(b) {
			t.Errorf("%s builds a URL with a token parameter", p)
		}
		if regexp.MustCompile(`["'\x60]/api/events`).Match(b) && p != "static/app.js" {
			t.Errorf("%s opens /api/events itself (only app.js's stream() may)", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	app, _ := fs.ReadFile(StaticFS, "static/app.js")
	if !regexp.MustCompile(`rawFetch\("/api/events"`).Match(app) {
		t.Error("app.js does not read /api/events through rawFetch (the bearer header)")
	}
}

// Plan 04 Task 2 (2026-10-19): the Settings page writes only through
// write.js (confirm, then one POST with a one-use token, one retry), and
// the old Grants and Enforce pages are gone from pages.js.
func TestSettingsPageWritesThroughWriteJS(t *testing.T) {
	read := func(name string) string {
		b, err := fs.ReadFile(StaticFS, name)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	settings := read("static/settings.js")
	if !regexp.MustCompile(`import\s*\{[^}]*\bwriteWithConfirm\b[^}]*\}\s*from\s*["']\./write\.js["']`).MatchString(settings) {
		t.Error("settings.js does not import writeWithConfirm from ./write.js")
	}
	for _, own := range []string{"fetch(", "api.post("} {
		if strings.Contains(settings, own) {
			t.Errorf("settings.js contains %q: writes must go through write.js", own)
		}
	}
	for _, route := range []string{`"/api/enforce"`, `"/api/config"`} {
		if !strings.Contains(settings, route) {
			t.Errorf("settings.js does not use %s", route)
		}
	}
	if !strings.Contains(settings, `registerPage("settings"`) {
		t.Error("settings.js does not register the settings page")
	}
	write := read("static/write.js")
	for _, want := range []string{"export async function writeWithConfirm(", "export function cancelled(", "confirmDialog(", "api.post(", "refetchNonce()", "COPY.common.backupLine("} {
		if !strings.Contains(write, want) {
			t.Errorf("write.js lacks %q", want)
		}
	}
	if strings.Contains(write, "throw ") {
		t.Error("write.js throws: writeWithConfirm must return {ok: false, error} instead")
	}
	pages := read("static/pages.js")
	for _, gone := range []string{`registerPage("grants"`, `registerPage("enforce"`, "function grantsPage(", "function enforcePage(", "function rememberCard(", "export async function enforceChange("} {
		if strings.Contains(pages, gone) {
			t.Errorf("pages.js still has %s", gone)
		}
	}
	// Since Plan 04 Task 12 the shared helpers live in shared.js, exported,
	// so pages import them from there and never from the barrel.
	shared := read("static/shared.js")
	for _, kept := range []string{"export function skillHash(", "export function ungrantedOf(", "export function predictCommand(", "export function askToEdit(", "export function confirmGrant(", "export async function postGrant(", "export function recordLabel(", "export function viewLines(", "export function tildify(", "export function segControl(", "export function switchControl("} {
		if !strings.Contains(shared, kept) {
			t.Errorf("shared.js lacks the shared helper %s", kept)
		}
	}
}

// Plan 04 Task 12 (2026-10-19): the Rules page writes only through
// write.js and mounts the skill drill-in from skill-detail.js; the skill
// grant controls post through postGrant; the barrel registers no page of
// its own and shared.js imports only app.js and copy.js.
func TestRulesPageWritesThroughWriteJS(t *testing.T) {
	read := func(name string) string {
		b, err := fs.ReadFile(StaticFS, name)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	rules := read("static/rules.js")
	for _, mod := range []string{"write", "skill-detail"} {
		if !regexp.MustCompile(`import\s*\{[^}]*\}\s*from\s*["']\./` + mod + `\.js["']`).MatchString(rules) {
			t.Errorf("rules.js does not import from ./%s.js", mod)
		}
	}
	if !strings.Contains(rules, `"/api/rules"`) {
		t.Error(`rules.js does not use "/api/rules"`)
	}
	if !strings.Contains(rules, `registerPage("rules"`) {
		t.Error("rules.js does not register the rules page")
	}
	for _, own := range []string{"fetch(", "api.post("} {
		if strings.Contains(rules, own) {
			t.Errorf("rules.js contains %q: writes must go through write.js", own)
		}
	}
	if !strings.Contains(read("static/skill-detail.js"), "postGrant(") {
		t.Error("skill-detail.js does not grant through postGrant(")
	}
	pages := read("static/pages.js")
	if strings.Contains(pages, "registerPage(") {
		t.Error("pages.js still registers a page: it is the barrel only")
	}
	for _, f := range []string{"rules.js", "skill-detail.js", "home.js", "settings.js", "sessions.js", "map.js", "shared.js"} {
		if regexp.MustCompile(`from\s*["']\./pages\.js["']`).MatchString(read("static/" + f)) {
			t.Errorf("%s imports the barrel pages.js", f)
		}
	}
	shared := read("static/shared.js")
	for _, m := range regexp.MustCompile(`(?m)^import\b[^;]*?from\s*["']([^"']+)["']`).FindAllStringSubmatch(shared, -1) {
		if m[1] != "./app.js" && m[1] != "./copy.js" {
			t.Errorf("shared.js imports %s: only ./app.js and ./copy.js", m[1])
		}
	}
}

// Plan 04 Task 11 (2026-10-19): the live lane map polls each lane's ticks
// view through api.fetch with If-None-Match (the bearer header, never a
// token in a URL), opens no event stream and calls no fetch of its own; the
// Sessions page exports liveCard for the Home page.
func TestLiveMapPollsThroughApi(t *testing.T) {
	read := func(name string) string {
		b, err := fs.ReadFile(StaticFS, name)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	lm := read("static/livemap.js")
	for _, want := range []string{"api.fetch(", "If-None-Match", "export function mountLiveMap(", "view=ticks"} {
		if !strings.Contains(lm, want) {
			t.Errorf("livemap.js does not contain %q", want)
		}
	}
	if strings.Contains(lm, "EventSource") {
		t.Error("livemap.js uses EventSource")
	}
	if regexp.MustCompile(`(^|[^.\w])fetch\(`).MatchString(lm) {
		t.Error("livemap.js calls fetch( of its own; use api.fetch")
	}
	ss := read("static/sessions.js")
	if !strings.Contains(ss, "export function liveCard(") {
		t.Error("sessions.js does not export liveCard")
	}
	if !regexp.MustCompile(`import\s*\{[^}]*\bmountLiveMap\b[^}]*\}\s*from\s*["']\./livemap\.js["']`).MatchString(ss) {
		t.Error("sessions.js does not import mountLiveMap from ./livemap.js")
	}
}

// Plan 04 Task 11 fix round 1 (2026-10-19): one source for live and time. A
// lane's "last call" is the catalog row's last_ts (what the table shows),
// never a tick's ts; the right edge is the client clock, never the ticks
// view's `updated`; a 401 stops every lane. A source check: it pins where
// the values come from, not how the page renders them (the walk and the
// hand check in the Task 11 report cover that).
func TestLiveMapTimeFromRowAndClock(t *testing.T) {
	b, err := fs.ReadFile(StaticFS, "static/livemap.js")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	body := func(name string) string {
		i := strings.Index(src, "function "+name+"(")
		if i < 0 {
			t.Fatalf("livemap.js has no function %s", name)
		}
		rest := src[i+len("function "+name+"("):]
		if j := strings.Index(rest, "\n  function "); j >= 0 {
			rest = rest[:j]
		}
		return rest
	}
	head := body("drawHead")
	if !strings.Contains(head, "last_ts") {
		t.Error("drawHead does not read the row's last_ts")
	}
	if strings.Contains(head, "ticks[") || strings.Contains(head, ".ts") {
		t.Error("drawHead reads a tick's ts; the last call comes from the row only")
	}
	if strings.Contains(src, ".updated") {
		t.Error("livemap.js reads the ticks view's updated; the right edge is the client clock")
	}
	for _, name := range []string{"drawTrack", "placeGlyphs"} {
		if !strings.Contains(body(name), "Date.now()") {
			t.Errorf("%s does not place glyphs against Date.now()", name)
		}
	}
	if !strings.Contains(src, "e.status === 401") || !strings.Contains(src, "lockedOut") {
		t.Error("livemap.js does not stop polling after a 401")
	}
}

// Home fix round 1 (Plan 04 Task 9 review): the leaving row fades in
// place (the class lands on the existing element, the list is rebuilt only
// after the transition), the Undo toast takes focus, pauses while focused
// or hovered and fires once, an install cannot run twice, the install
// button is offered only while the user settings are not complete, and an
// undo failure is a copy sentence.
func TestHomeFixRound1(t *testing.T) {
	read := func(name string) string {
		b, err := fs.ReadFile(StaticFS, name)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	home := read("static/home.js")
	body := func(name string) string {
		i := strings.Index(home, "function "+name+"(")
		if i < 0 {
			t.Fatalf("home.js has no function %s", name)
		}
		rest := home[i+1:]
		j := strings.Index(rest, "\n  function ")
		k := strings.Index(rest, "\n  async function ")
		if j < 0 || (k >= 0 && k < j) {
			j = k
		}
		if j < 0 {
			return rest
		}
		return rest[:j]
	}
	leave := body("leave")
	for _, want := range []string{`classList.add("leaving")`, "transitionend"} {
		if !strings.Contains(leave, want) {
			t.Errorf("leave() lacks %s", want)
		}
	}
	// The rebuild lives only in the finish step that transitionend (or the
	// fallback timeout) runs, never before it.
	fin := strings.Index(leave, "const finish")
	if fin < 0 || strings.Contains(leave[:fin], "renderNeeds(") {
		t.Error("leave() rebuilds the list before the transition")
	}
	if !strings.Contains(body("renderNeeds"), "data.leaving.size") {
		t.Error("renderNeeds() rebuilds the list while a row is fading")
	}
	toastFn := body("undoToast")
	for _, want := range []string{".focus(", "mouseenter", "mouseleave", "focusin", "focusout", "disabled = true"} {
		if !strings.Contains(toastFn, want) {
			t.Errorf("undoToast() lacks %s", want)
		}
	}
	install := body("install")
	if i, j := strings.Index(install, "installing = true"), strings.Index(install, `api.get("/api/enforce")`); i < 0 || j < 0 || i > j {
		t.Error("install() does not mark itself busy before GET /api/enforce")
	}
	if !strings.Contains(install, "finally") {
		t.Error("install() does not reset its busy flag in a finally")
	}
	// The install button only when the user settings hold no hook of ours
	// and a sandbox backend exists; otherwise a link to Settings (the plugin
	// case, a partial install, no backend).
	sentence := body("renderSentence")
	for _, want := range []string{"canInstall(", "C.seeSettings", `href: "#/settings"`} {
		if !strings.Contains(sentence, want) {
			t.Errorf("renderSentence() lacks %s", want)
		}
	}
	can := body("canInstall")
	for _, want := range []string{"enforcementAvailable", "hookInstalled", "skillHook", "deniedHook", "startHook", "endHook", "promptHook"} {
		if !strings.Contains(can, want) {
			t.Errorf("canInstall() does not read %s", want)
		}
	}
	if strings.Contains(home, "C.finishSetup") {
		t.Error("home.js still offers Finish setup")
	}
	if !strings.Contains(body("undo"), "C.undoFailed") {
		t.Error("undo() does not use COPY.home.undoFailed")
	}
}

// Plan 04 Task 13 (2026-10-19): the Add rule sheet asks the server for the
// plan through shared.js's postRulePreview, whose one POST is fixed to
// /api/rules/propose (it takes a request, never a path, so it cannot become
// an unconfirmed write), and writes only the request: the one POST to
// /api/rules that adds a rule goes through writeWithConfirm with an add:
// key, and the page never sends the plan's steps back.
func TestRuleSheetProposesServerSide(t *testing.T) {
	read := func(name string) string {
		b, err := fs.ReadFile(StaticFS, name)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	rules := read("static/rules.js")
	if !strings.Contains(rules, "postRulePreview(") {
		t.Error("rules.js does not preview through postRulePreview(")
	}
	shared := read("static/shared.js")
	fn := regexp.MustCompile(`(?s)export async function postRulePreview\(request\) \{.*?\n\}`).FindString(shared)
	if fn == "" {
		t.Fatal("shared.js does not export postRulePreview(request)")
	}
	posts := regexp.MustCompile(`api\.post\(([^,)]*)`).FindAllStringSubmatch(fn, -1)
	if len(posts) != 1 || posts[0][1] != `"/api/rules/propose"` {
		t.Errorf("postRulePreview posts to %q; want exactly one POST to \"/api/rules/propose\"", posts)
	}
	if strings.Contains(shared, "postPreview(") {
		t.Error("shared.js still has the free-path postPreview(")
	}
	if !regexp.MustCompile(`payload:\s*\{\s*add:`).MatchString(rules) {
		t.Error("rules.js has no write with an add: payload")
	}
	if !strings.Contains(rules, "writeWithConfirm(") {
		t.Error("rules.js does not write through writeWithConfirm(")
	}
	// The page's write() helper is the one caller of writeWithConfirm.
	if n := strings.Count(rules, "writeWithConfirm("); n != 1 {
		t.Errorf("rules.js calls writeWithConfirm( %d times; want one, inside write()", n)
	}
	if m := regexp.MustCompile(`\bsteps\s*:`).FindString(rules); m != "" {
		t.Errorf("rules.js sends a steps key (%q): the server builds the plan from the request", m)
	}
	for _, own := range []string{"fetch(", "api.post("} {
		if strings.Contains(rules, own) {
			t.Errorf("rules.js contains %q", own)
		}
	}
}

// TestRulesRemoveMovesFocus: after a confirmed Remove on the Rules page the
// row and its button are rebuilt away, so rules.js moves focus to the
// heading of the row's group (else the page heading), never leaving it on
// the body (final review of Plan 04, finding 3, 2026-10-19). A source
// assertion: no committed test runs the dashboard's JavaScript.
func TestRulesRemoveMovesFocus(t *testing.T) {
	b, err := fs.ReadFile(StaticFS, "static/rules.js")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	fn := regexp.MustCompile(`(?s)\n  async function remove\(row, whole\) \{.*?\n  \}\n`).FindString(src)
	if fn == "" {
		t.Fatal("rules.js has no remove(row, whole)")
	}
	if !regexp.MustCompile(`(?s)await write\(.*focusAfterRemove\(groupId\)`).MatchString(fn) {
		t.Error("remove() does not call focusAfterRemove(groupId) after the write")
	}
	focus := regexp.MustCompile(`(?s)\n  function focusAfterRemove\(groupId\) \{.*?\n  \}\n`).FindString(src)
	for _, want := range []string{`"#rules-g-" + groupId`, `querySelector("h1")`, `setAttribute("tabindex", "-1")`, ".focus()"} {
		if !strings.Contains(focus, want) {
			t.Errorf("focusAfterRemove lacks %s", want)
		}
	}
	if !strings.Contains(src, `id: hid }, groupTitle(g.id)`) || !strings.Contains(src, `const hid = "rules-g-" + g.id`) {
		t.Error("group headings no longer carry the rules-g-<id> id focusAfterRemove looks for")
	}
}

// staticSrc reads one embedded dashboard file.
func staticSrc(t *testing.T, name string) string {
	t.Helper()
	b, err := fs.ReadFile(StaticFS, name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestRulesSwitchKeepsFocus: after a confirmed on/off switch write, loadBook
// re-renders the list and the old switch is gone, so setEnabled finds the
// new switch by its row id and focuses it; a cancel leaves focus to the
// dialog, which returns it to the switch (Plan 05 Task 6, 2026-10-20). The
// walk's key pass checks it in a browser (scripts/walk/keys.mjs).
func TestRulesSwitchKeepsFocus(t *testing.T) {
	src := staticSrc(t, "static/rules.js")
	fn := regexp.MustCompile(`(?s)\n  async function setEnabled\(row, enabled\) \{.*?\n  \}\n`).FindString(src)
	if fn == "" {
		t.Fatal("rules.js has no setEnabled(row, enabled)")
	}
	if !regexp.MustCompile(`(?s)await write\(.*if \(r === cancelled\(\)\) return;.*focusSwitch\(row\.id\)`).MatchString(fn) {
		t.Error("setEnabled does not call focusSwitch(row.id) after the write (skipping a cancel)")
	}
	focus := regexp.MustCompile(`(?s)\n  function focusSwitch\(id\) \{.*?\n  \}\n`).FindString(src)
	if focus == "" {
		t.Fatal("rules.js has no focusSwitch(id)")
	}
	if !regexp.MustCompile(`li\.dataset\.id [!=]== id`).MatchString(focus) {
		t.Error("focusSwitch does not compare each row's dataset.id with the id")
	}
	for _, want := range []string{`querySelectorAll("li.rule-row")`, `querySelector("button.sw")`, ".focus()"} {
		if !strings.Contains(focus, want) {
			t.Errorf("focusSwitch lacks %s", want)
		}
	}
	if !strings.Contains(src, `class: "rule-row", title: row.hover || null, dataset: { id: row.id }`) {
		t.Error("rule rows no longer carry the row id focusSwitch looks for")
	}
}

// TestMapHeaderDenialsFromAuthority: the map's header counts every refused
// call: totals.blocked_calls (deny rule, auto-mode check, watchdeck's hook,
// also read only from the transcript) plus the sandbox's refusals, so a
// transcript-only session never reads "denied 0" beside "Deny rule 2"; the
// timeline's allow/ask/denied tags are hidden when all three are zero
// (Plan 05 Task 6, 2026-10-20; mapmodel TestTotalsBlockedCalls).
func TestMapHeaderDenialsFromAuthority(t *testing.T) {
	src := staticSrc(t, "static/map.js")
	fn := regexp.MustCompile(`(?s)\n  function renderTotals\(\) \{.*?\n  \}\n`).FindString(src)
	if fn == "" {
		t.Fatal("map.js has no renderTotals()")
	}
	if !strings.Contains(fn, "const refused = num(t.blocked_calls) + sandboxCalls + Math.max(0, num(t.denials) - num(t.deny));") {
		t.Error("renderTotals does not count refusals from totals.blocked_calls plus the sandbox's")
	}
	for _, want := range []string{"M.outcome.denied, refused)", "M.count.denials(refused)", "} else if (num(t.allow) || num(t.ask) || refused) {"} {
		if !strings.Contains(fn, want) {
			t.Errorf("renderTotals lacks %s", want)
		}
	}
	if strings.Contains(fn, "M.outcome.denied, num(t.deny)") {
		t.Error("renderTotals still prints the denied tag from the policy count t.deny")
	}
}

// TestTimelineFitsItsContent: the timeline (first draw, polls before a
// zoom, and the Fit button, which all read st.bounds) is fitted to its
// drawn content (event nodes, their labels, lane headers, time labels),
// not to the server's minimum canvas (1000 × 720), and may scale up to 1.6
// so a short session fills the canvas; the topology keeps ctl.bounds()
// (Plan 05 Task 6, 2026-10-20).
func TestTimelineFitsItsContent(t *testing.T) {
	src := staticSrc(t, "static/map.js")
	if !strings.Contains(src, "st.bounds = contentBounds(ui.stage, { x: 0, y: 0, w: kit.W, h: kit.H });") {
		t.Error("the timeline's bounds are not contentBounds(ui.stage, …)")
	}
	if strings.Contains(src, "st.bounds = { x: 0, y: 0, w: kit.W, h: kit.H };") {
		t.Error("the timeline's bounds are still the whole canvas")
	}
	if !strings.Contains(src, "st.bounds = st.ctl.bounds();") {
		t.Error("the topology no longer fits ctl.bounds()")
	}
	fn := regexp.MustCompile(`(?s)\nfunction contentBounds\(stage, fallback\) \{.*?\n\}\n`).FindString(src)
	if fn == "" {
		t.Fatal("map.js has no contentBounds(stage, fallback)")
	}
	for _, want := range []string{`".nodes .node, .nodes .lab, .nodes .decor > *"`, `stage.style.transform = "none"`, "stage.style.transform = prev", "getBoundingClientRect()", "return fallback"} {
		if !strings.Contains(fn, want) {
			t.Errorf("contentBounds lacks %s", want)
		}
	}
	if !strings.Contains(src, "if (!isUpdate || !st.userZoomed) cv.fit(false);") {
		t.Error("draw no longer fits on the first draw and on polls before a zoom")
	}
	cv := staticSrc(t, "static/canvas.js")
	if !strings.Contains(cv, "const FIT = { timeline: [0.5, 1.6], topology: [13 / 14, 1.3] };") {
		t.Error("canvas.js: the timeline's fit range is not [0.5, 1.6] (topology unchanged)")
	}
	if !strings.Contains(cv, "const ctl = FIT_CTL;") {
		t.Error("canvas.js: fitBox does not keep both views clear of the zoom controls")
	}
	if !strings.Contains(cv, "const b = st.bounds || { w: st.W, h: st.H };") {
		t.Error("canvas.js: fitScale no longer reads st.bounds (the Fit button would not use the content bounds)")
	}
}

// TestRulesShowsRecommendedWarning: POST /api/rules/recommended may carry a
// warning (the reconcile before an install failed; the install still ran);
// rules.js shows it as a toast through copy (Plan 05 Task 6, 2026-10-20).
func TestRulesShowsRecommendedWarning(t *testing.T) {
	src := staticSrc(t, "static/rules.js")
	if !strings.Contains(src, "r.data.warning") || !strings.Contains(src, "C.recommendedWarning(r.data.warning)") {
		t.Error("rules.js does not show the warning from POST /api/rules/recommended through C.recommendedWarning")
	}
	for _, fn := range []string{"install(rule)", "installAll(n)"} {
		body := regexp.MustCompile(`(?s)\n  async function ` + regexp.QuoteMeta(fn) + ` \{.*?\n  \}\n`).FindString(src)
		if !strings.Contains(body, "showWarning(r)") {
			t.Errorf("%s does not call showWarning(r)", fn)
		}
	}
	if !strings.Contains(staticSrc(t, "static/copy.js"), "recommendedWarning: (text) =>") {
		t.Error("copy.js lacks COPY.rules.recommendedWarning")
	}
}

// TestConfirmDialogSettlesEveryOpen: Escape and then Space within a few
// milliseconds reopened the confirm dialog before the first one's close
// event arrived, so the first promise stayed on the buttons and one click
// on the confirm button resolved both: two writes with one nonce, the
// second refused as stale (found by the walk's key pass, Plan 05 Task 6,
// 2026-10-20). confirmDialog settles on cancel as well as close, ignores a
// close event that arrives while the dialog is open again, and a new open
// settles any confirm still waiting as cancelled first.
func TestConfirmDialogSettlesEveryOpen(t *testing.T) {
	src := staticSrc(t, "static/app.js")
	fn := regexp.MustCompile(`(?s)\nexport function confirmDialog\(.*?\n\}\n`).FindString(src)
	if fn == "" {
		t.Fatal("app.js has no confirmDialog")
	}
	for _, want := range []string{
		`if (pendingConfirm) pendingConfirm(false);`,
		`dlg.addEventListener("cancel", onEscape);`,
		`dlg.removeEventListener("cancel", onEscape);`,
		`if (!dlg.open) done(false);`,
		`pendingConfirm = done;`,
		`if (pendingConfirm === done) pendingConfirm = null;`,
	} {
		if !strings.Contains(fn, want) {
			t.Errorf("confirmDialog lacks %s", want)
		}
	}
	if strings.Index(fn, "if (pendingConfirm) pendingConfirm(false);") > strings.Index(fn, "dlg.showModal()") {
		t.Error("confirmDialog settles the waiting confirm after it opens the new one")
	}
}
