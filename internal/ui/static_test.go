package ui

import (
	"bytes"
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

// expectedStatic is the dashboard's file set. Plan 04 Task 1 (2026-10-19)
// replaced the Overview files with the three-tab shell's copy module and
// page stubs; later tasks fill the stubs and must not remove any file here.
var expectedStatic = []string{
	"static/index.html",
	"static/app.css",
	"static/app.js",
	"static/copy.js",
	"static/write.js",
	"static/shared.js",
	"static/pages.js",
	"static/home.js",
	"static/home.css",
	"static/rules.js",
	"static/rules.css",
	"static/settings.js",
	"static/livemap.js",
	"static/canvas.js",
	"static/skill-detail.js",
	"static/map.js",
	"static/map.css",
	"static/topology.js",
	"static/timeline.js",
	"static/sessions.js",
	"static/pages.css",
	"static/sessions.css",
}

func TestStaticFilesPresent(t *testing.T) {
	for _, name := range expectedStatic {
		b, err := fs.ReadFile(StaticFS, name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(b) == 0 {
			t.Fatalf("%s: empty", name)
		}
	}
	// No brackets or spaces in any embedded name (embed-safe, URL-safe).
	err := fs.WalkDir(StaticFS, "static", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if strings.ContainsAny(p, "[] ") {
			t.Errorf("unsafe file name %q", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// The guard's CSP is default-src 'none'; script-src 'self'; style-src 'self'.
// Anything inline in the shell would be blocked, so the shell must not carry
// inline styles, style blocks, event handler attributes or inline scripts.
func TestIndexHasNoInlineStyleOrScript(t *testing.T) {
	b, err := fs.ReadFile(StaticFS, "static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	low := strings.ToLower(s)
	for _, bad := range []string{" style=", "<style", "javascript:"} {
		if strings.Contains(low, bad) {
			t.Errorf("index.html contains %q", bad)
		}
	}
	// on[a-z]+= preceded by whitespace: onclick=, onload=, ... (content= and
	// similar are not handlers and are allowed).
	if m := regexp.MustCompile(`(?i)\son[a-z]+=`).FindString(s); m != "" {
		t.Errorf("index.html has an inline event handler: %q", m)
	}
	// Every <script> must be an external module with a src.
	for _, m := range regexp.MustCompile(`(?is)<script\b[^>]*>`).FindAllString(s, -1) {
		if !strings.Contains(m, `src="/app.js"`) || !strings.Contains(m, `type="module"`) {
			t.Errorf("unexpected script tag %q", m)
		}
	}
	if !strings.Contains(s, `<script type="module" src="/app.js">`) {
		t.Error("index.html lacks the app.js module script")
	}
	// The six stylesheets, in this order: later sheets override earlier ones.
	last := -1
	for _, css := range []string{"app.css", "map.css", "home.css", "pages.css", "sessions.css", "rules.css"} {
		want := `<link rel="stylesheet" href="/` + css + `">`
		i := strings.Index(s, want)
		if i < 0 {
			t.Errorf("index.html lacks %s", want)
			continue
		}
		if i < last {
			t.Errorf("index.html: %s is out of order", css)
		}
		last = i
	}
	if n := strings.Count(s, `rel="stylesheet"`); n != 6 {
		t.Errorf("index.html has %d stylesheets, want 6", n)
	}
	// Nothing external: no http(s) URLs in the shell at all.
	if regexp.MustCompile(`(?i)https?://`).MatchString(s) {
		t.Error("index.html references an external URL")
	}
}

// localAssetFiles are the scripts and stylesheets checked for CSP
// compliance. Phase B appends its files (topology.js, timeline.js, ...)
// here; nothing else in the test needs to change.
var localAssetFiles = []string{
	"static/app.js",
	"static/copy.js",
	"static/write.js",
	"static/shared.js",
	"static/pages.js",
	"static/home.js",
	"static/rules.js",
	"static/settings.js",
	"static/livemap.js",
	"static/canvas.js",
	"static/skill-detail.js",
	"static/map.js",
	"static/topology.js",
	"static/timeline.js",
	"static/sessions.js",
	"static/app.css",
	"static/map.css",
	"static/home.css",
	"static/pages.css",
	"static/sessions.css",
	"static/rules.css",
}

// The JS and CSS the shell ships must not need anything the CSP forbids
// either: no inline style attributes written as markup, no eval, no
// external URLs, no @font-face (the type is the system's; no font file is
// embedded or fetched).
func TestScriptsAndStylesStayLocal(t *testing.T) {
	for _, name := range localAssetFiles {
		b, err := fs.ReadFile(StaticFS, name)
		if err != nil {
			t.Fatal(err)
		}
		s := string(b)
		// The SVG namespace identifier is not a fetch; everything else external is.
		if regexp.MustCompile(`(?i)https?://`).MatchString(strings.ReplaceAll(s, "http://www.w3.org/2000/svg", "")) {
			t.Errorf("%s references an external URL", name)
		}
		if strings.HasSuffix(name, ".js") {
			if regexp.MustCompile(`\bstyle="`).MatchString(s) {
				t.Errorf("%s writes a style= attribute as markup", name)
			}
			if regexp.MustCompile(`\.innerHTML\s*=`).MatchString(s) {
				t.Errorf("%s assigns innerHTML (build DOM with createElement instead)", name)
			}
			if regexp.MustCompile(`\beval\(|new Function\(`).MatchString(s) {
				t.Errorf("%s uses eval", name)
			}
			if regexp.MustCompile(`\son[a-z]+=`).MatchString(s) {
				t.Errorf("%s writes an on*= handler attribute", name)
			}
		}
		if strings.HasSuffix(name, ".css") && strings.Contains(s, "@font-face") {
			t.Errorf("%s declares a @font-face (the dashboard ships no font since 2026-10-28)", name)
		}
		if name == "static/app.css" {
			if !strings.Contains(s, "prefers-color-scheme: dark") {
				t.Errorf("app.css lacks the dark theme block")
			}
			for _, tok := range []string{"--bg:", "--surface:", "--ink:", "--accent:", "--ok:", "--ask:", "--deny:", "--off:", "--cv-bg:", "--cv-teal:", "--tone-ok:", "--tone-deny-bg:", "--font-sans:", "--font-mono:", "--r-card:"} {
				if !strings.Contains(s, tok) {
					t.Errorf("app.css lacks token %s", tok)
				}
			}
		}
	}
}

// Regression guard for the dark theme's network/deny tag: --tag-net-fg
// #F26B6B over --tag-net-bg composited on --surface #15223A is 4.21:1 at
// alpha .18 and 4.59:1 at alpha .12 (WCAG AA for small text needs 4.5:1;
// background blended and rounded to 8 bits, as a browser composites it).
// The amber pair is 5.90:1 and the green pair 5.40:1 at alpha .18, so only
// the red pair needed the lower alpha.
func TestDarkNetTagContrast(t *testing.T) {
	b, err := fs.ReadFile(StaticFS, "static/app.css")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	i := strings.Index(s, "prefers-color-scheme: dark")
	if i < 0 {
		t.Fatal("no dark block")
	}
	dark := s[i:]
	if !strings.Contains(dark, "--tag-net-bg: rgba(242, 107, 107, .12);") {
		t.Error("dark --tag-net-bg must be rgba(242, 107, 107, .12) (4.59:1 against --tag-net-fg); .18 fails AA at 4.21:1")
	}
}

// Plan 04 Task 10 (2026-10-19): the one-session map is part of the Sessions
// page, not a page of its own. sessions.js imports ./map.js and mounts
// mapView(; map.js builds on ./canvas.js, exports mapView and timelineHash
// (Home deep-links into the timeline with it) and registers no page;
// canvas.js exports the kit (makeKit) and the viewport (makeCanvas).
func TestSessionsPageOwnsTheMap(t *testing.T) {
	read := func(name string) []byte {
		b, err := fs.ReadFile(StaticFS, name)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	s := read("static/sessions.js")
	if !regexp.MustCompile(`import\s*\{[^}]*\}\s*from\s+["']\./map\.js["']`).Match(s) {
		t.Error("sessions.js does not import from ./map.js")
	}
	if !bytes.Contains(s, []byte("mapView(")) {
		t.Error("sessions.js does not call mapView(")
	}
	m := read("static/map.js")
	if !regexp.MustCompile(`import\s*\{[^}]*\}\s*from\s+["']\./canvas\.js["']`).Match(m) {
		t.Error("map.js does not import from ./canvas.js")
	}
	for _, re := range []string{`export\s+function\s+mapView\s*\(`, `export\s+function\s+timelineHash\s*\(`} {
		if !regexp.MustCompile(re).Match(m) {
			t.Errorf("map.js does not match %s", re)
		}
	}
	if bytes.Contains(m, []byte("registerPage(")) {
		t.Error("map.js still registers a page")
	}
	c := read("static/canvas.js")
	for _, re := range []string{`export\s+function\s+makeKit\s*\(`, `export\s+function\s+makeCanvas\s*\(`} {
		if !regexp.MustCompile(re).Match(c) {
			t.Errorf("canvas.js does not match %s", re)
		}
	}
}

// TestNoFontFilesEmbedded: the two embedded faces (a sans and a mono, OFL)
// left on 2026-10-28; they had been fallbacks behind the system fonts since
// the Mac-native restyle. Nothing under static/ may be a font file or a
// fonts directory again.
func TestNoFontFilesEmbedded(t *testing.T) {
	err := fs.WalkDir(StaticFS, "static", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if strings.HasSuffix(p, "/fonts") {
				t.Errorf("%s: a fonts directory is back", p)
			}
			return nil
		}
		if i := strings.LastIndexByte(p, '.'); i >= 0 {
			ext := strings.ToLower(p[i:])
			if ext == ".ttf" || ext == ".otf" || strings.HasPrefix(ext, ".woff") {
				t.Errorf("%s: a font file is embedded", p)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestContentType(t *testing.T) {
	cases := map[string]string{
		"index.html":       "text/html; charset=utf-8",
		"/app.js":          "text/javascript; charset=utf-8",
		"static/app.css":   "text/css; charset=utf-8",
		"icon.svg":         "image/svg+xml",
		"shot.PNG":         "image/png",
		"notes/README.md":  "text/plain; charset=utf-8",
		"licenses/OFL.txt": "text/plain; charset=utf-8",
		"noext":            "application/octet-stream",
		"weird.bin":        "application/octet-stream",
	}
	for in, want := range cases {
		if got := ContentType(in); got != want {
			t.Errorf("ContentType(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestNoOverviewCSS: the Overview page went in Plan 04 Task 1; its
// .page-overview and .ov-* rules left app.css in Plan 05 Task 6
// (2026-10-20), and nothing in the dashboard uses those classes.
func TestNoOverviewCSS(t *testing.T) {
	css, err := fs.ReadFile(StaticFS, "static/app.css")
	if err != nil {
		t.Fatal(err)
	}
	if regexp.MustCompile(`\.ov-|\.page-overview`).Match(css) {
		t.Error("app.css still holds .ov- or .page-overview rules")
	}
}

// TestCopyHasObservingOnly (Plan 06 Task 6, S2): shadow mode reads
// "Observing only" on Home, the header pill and the Rules page, and every
// surface prints the command that turns enforcement back on. Source-pinned:
// the strings live in copy.js, protectionWord turns "protected" into
// "observing" from st.shadow, and the pages read it.
func TestCopyHasObservingOnly(t *testing.T) {
	read := func(name string) string {
		t.Helper()
		b, err := fs.ReadFile(StaticFS, "static/"+name)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	cp := read("copy.js")
	for _, want := range []string{`"Observing only"`, "observing:", "watchdeck rules shadow off", "observed: would ", `recentLabel: (tool, what, label, ago, observed) =>`} {
		if !strings.Contains(cp, want) {
			t.Errorf("copy.js lacks %q", want)
		}
	}
	i := strings.Index(cp, "export function protectionWord(")
	if i < 0 {
		t.Fatal("copy.js has no protectionWord")
	}
	body := cp[i:]
	if j := strings.Index(body, "\n}\n"); j >= 0 {
		body = body[:j]
	}
	if !strings.Contains(body, "st.shadow") {
		t.Errorf("protectionWord does not read st.shadow:\n%s", body)
	}
	if !strings.Contains(read("home.js"), `"observing"`) {
		t.Error(`home.js lacks "observing"`)
	}
	for file, want := range map[string]string{
		"app.js":   `observing: "ask"`,
		"rules.js": "status.shadow",
		"home.js":  `C.recentLabel(r.tool, what, label, ago, r.shadow ? C.observed(r.would) : "")`,
	} {
		if !strings.Contains(read(file), want) {
			t.Errorf("%s lacks %q", file, want)
		}
	}
}

// TestHomeWiresLeaksAndAllow (Plan 08 Task 5; the decision sheet of
// 2026-10-28): Home reloads Needs you on the index event (leak watch),
// offers a while only from the item's pausable and allow_for, posts allow
// with its for word and add_rule with its fix and scope (a project scope
// adds ?project=), links a leak's sheet to its timeline, labels the
// every-route fix in the Rule popup, and words a leak's dismiss by how wide
// it hides. The leak authority word stays out of the map's list.
func TestHomeWiresLeaksAndAllow(t *testing.T) {
	read := func(name string) string {
		b, err := fs.ReadFile(StaticFS, "static/"+name)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	home, cp := read("home.js"), read("copy.js")
	for _, want := range []string{
		`payload.name === "index") nudge(loadNeeds)`,
		`const allowFor = it.pausable ? it.allow_for || [] : [];`,
		`body = { action, for: arg };`,
		`body = { action, fix: arg.fix };`,
		`body.scope = "project";`,
		`project = item.project || "";`,
		`timelineHash(it.session_id, it.tool_use_id)`,
		`f.request && f.request.everywhere ? N.ruleEverywhere(f.sentence) : f.sentence`,
		`d.leak_watch === false`,
		// Plan 08 final review: a leak's dismiss says how wide it hides.
		`title: ch.leak ? N.neverAgainLeakTitle(!it.tool_use_id) : N.neverAgainTitle,`,
		`item.kind === "leak" ? C.dismissedLeak(!item.tool_use_id) : C.dismissed`,
		// The sheet closes before the Undo toast takes focus (a modal keeps
		// focus inside it), a write that went through is never dropped, and
		// Escape cannot close the sheet while its write is in flight.
		`if (!done) finish(false);`,
		`resolved(it, msg);`,
		`if (posting) return;`,
	} {
		if !strings.Contains(home, want) {
			t.Errorf("home.js lacks %q", want)
		}
	}
	for _, want := range []string{
		`leak: { label: "Secret seen", glyph: "warn" },`,
		`forSession: "This session",`,
		`forHour: "An hour",`,
		"ruleEverywhere: (sentence) => `${sentence}, by every route`,",
		`leakOff: "Leak watch is off because transcripts are off.",`,
		`Object.keys(AUTHORITY).filter((w) => !INBOX_ONLY.has(w))`,
	} {
		if !strings.Contains(cp, want) {
			t.Errorf("copy.js lacks %q", want)
		}
	}
}

// TestRulesWiresStatsTryIntents pins the Rules page's Plan 08 wiring (Task
// 6): the try box posts through postTry with the page's project, the count
// chips are keyed as the stats route keys them and skip rows that are off,
// an intent row's Remove offers remove_intent with remove as the lesser
// action in one confirm, a temporary ends through end_temporary, and the
// Add sheet sends everywhere for a path or a domain.
func TestRulesWiresStatsTryIntents(t *testing.T) {
	read := func(name string) string {
		b, err := fs.ReadFile(StaticFS, "static/"+name)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	rules, shared, write, app, index, cp := read("rules.js"), read("shared.js"), read("write.js"), read("app.js"), read("index.html"), read("copy.js")
	for _, want := range []string{
		`const STATS = "/api/rules/stats";`,
		`postTry({ what: what.value, value }, (book && book.project_root) || "")`,
		`row.join || row.state !== "on") return null;`,
		`pick(stats.pack, id.slice("pack:".length))`,
		`pick(stats.user, id.slice("user:".length))`,
		`pick(stats.native, row.value)`,
		`payload: { remove_intent: it.id },`,
		`alt: { label: C.intent.onlyThis, payload: { remove: row.id } },`,
		`payload: { end_temporary: t.id },`,
		`everywhere: !!st.everywhere`,
		`everywhere: true, pack:`,
		`if (typeof r.data.warning === "string" && r.data.warning) toast(r.data.warning, "");`,
		// Plan 08 final review: a log or paused last hit reads "matched",
		// a new try clears the last outline, the result is a live region.
		`text = s.last_action === "log" ? C.stats.matched(`,
		`if (root) for (const old of root.querySelectorAll("li.rule-row.is-hit")) old.classList.remove("is-hit");`,
		`"aria-live": "polite"`,
	} {
		if !strings.Contains(rules, want) {
			t.Errorf("rules.js lacks %q", want)
		}
	}
	if !strings.Contains(shared, `const path = "/api/rules/try" + (project ? "?project=" + encodeURIComponent(project) : "");`) {
		t.Error("shared.js lacks postTry's fixed path with ?project=")
	}
	if !strings.Contains(write, `const chosen = choice === "alt" ? alt.payload : payload;`) {
		t.Error("write.js does not post the lesser action's payload when it is chosen")
	}
	if !strings.Contains(app, `const onAlt = () => done(altLabel ? "alt" : false);`) {
		t.Error("app.js confirmDialog does not resolve the lesser action")
	}
	if !strings.Contains(index, `<button type="button" class="btn ghost" id="confirm-alt" hidden></button>`) {
		t.Error("index.html lacks the hidden lesser-action button in the confirm dialog")
	}
	for _, want := range []string{
		`none: "no watchdeck rule applies; Claude Code decides as usual",`,
		`sessionPauses: "Session-bound pauses are not applied here.",`,
		`onlyThis: "Only this rule",`,
		`everywhere: "Cover every route",`,
		`off: "Activity log is off, so rule counts are not kept.",`,
		`never: "never fired",`,
		"matched: (n, ago) => `matched ${n} · last ${ago}, noted only`,",
		"failed: (msg) => (msg ? `Could not try the call: ${msg}` : \"Could not try the call.\"),",
	} {
		if !strings.Contains(cp, want) {
			t.Errorf("copy.js lacks %q", want)
		}
	}
}
