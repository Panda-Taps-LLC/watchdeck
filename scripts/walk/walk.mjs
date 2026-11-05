// Dashboard walkthrough. Developer tool and manual workflow, never the real
// home; scripts/walk.sh runs it against a fixture home.
//
//   node walk.mjs --port N --token-file F --session A
//                 [--session-c C] [--keys] [--axe] [--screenshots DIR [--shot NAME=ROUTE[@dark][#STATE]]...]
//
// Opens the dashboard once through the launch URL (token in the fragment),
// then visits every route by changing location.hash, without reloading, so
// the page keeps the token it stored. For each route it records the final
// hash, console errors and warnings, page errors, failed requests and /api/
// responses with status >= 400. Exit 1 on any of those, or on a legacy hash
// that did not change; exit 2 on a setup problem.
//
// Three routes also carry content checks (CHECKS below): Home must show a
// leak row ("Secret seen", linked to its timeline) and the allow buttons;
// Rules must show a "part of" chip, the Temporary notice with End now, and
// rule counts on the fixture's own rule (fired 3) and its Claude Code Bash
// rule (fired 1). Each check waits up to its timeout (the leak row needs the
// session index, built as the dashboard starts) and a miss is an error on
// that route. They need the fixture scripts/fixture-home.sh builds with a
// binary (scripts/walk.sh passes one): session L, the rule fixture-prod-db,
// the pause and the ~/.kube/config intent.
//
// Modes, in the order they run (the keyboard pass changes the fixture, so it
// goes last):
//   --axe          axe.mjs on every route of the walk, after settle, in the
//                  light and then the dark colour scheme
//   --screenshots  one PNG per --shot (a default set without any), each in a
//                  fresh browser context at 1280x800 CSS px with the colour
//                  scheme emulated and reduced motion
//   --keys         keys.mjs: the key-press script per route
// The same error listeners watch the walk page during the keyboard pass and
// every shot context; an error there fails that key route or that shot.
//
// A shot is exactly NAME=ROUTE, NAME=ROUTE@dark, NAME=ROUTE#STATE or
// NAME=ROUTE@dark#STATE. STATE is confirm-open (Enter on the first Needs
// row's button, so its decision sheet is open), chips-filtered (the "Auto
// check" chip on the map turned off), fit (the map's "Fit to view" button pressed), try-open (on the
// Rules page, "curl https://example.com" tried in the try box, its answer
// showing) or leak-row (on Home, the first "Secret seen" row scrolled to the
// middle of the view). <A> or {A} in ROUTE is the fixture session, <C> or
// {C} the deny session (--session-c).
//
// The launch token never reaches the output: Playwright's navigation errors
// repeat the launch URL, so every error string goes through redact() before
// it is stored or printed (internal/ui TestWalkRedactsToken).
import { readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { chromium } from "playwright";
import { runKeys } from "./keys.mjs";
import { runAxe } from "./axe.mjs";

const argv = process.argv.slice(2);
function arg(name) {
  const i = argv.indexOf("--" + name);
  if (i < 0 || !argv[i + 1]) {
    console.error(`walk: missing --${name}`);
    process.exit(2);
  }
  return argv[i + 1];
}
function flag(name) {
  return argv.includes("--" + name);
}
function all(name) {
  const out = [];
  for (let i = 0; i < argv.length; i++) if (argv[i] === "--" + name && argv[i + 1]) out.push(argv[++i]);
  return out;
}

const token = readFileSync(arg("token-file"), "utf8").trim();

// redact(s): the string with the token, and any t=<value>, rewritten.
function redact(s) {
  let out = String(s ?? "");
  if (token) out = out.replaceAll(token, "<token>");
  return out.replace(/t=[A-Za-z0-9_-]+/g, "t=<token>");
}
process.on("uncaughtException", (e) => {
  console.error(`walk: ${redact(e && e.stack ? e.stack : e)}`);
  process.exit(2);
});
process.on("unhandledRejection", (e) => {
  console.error(`walk: ${redact(e && e.stack ? e.stack : e)}`);
  process.exit(2);
});

const port = arg("port");
const A = arg("session");
const C = argv.includes("--session-c") ? arg("session-c") : null;
const base = `http://127.0.0.1:${port}/`;
const doKeys = flag("keys");
const doAxe = flag("axe");
const shotDir = argv.includes("--screenshots") ? arg("screenshots") : null;

// The screenshot set the workflow takes when no --shot is given.
const DEFAULT_SHOTS = [
  "home=#/",
  "home-dark=#/@dark",
  "needs=#/#confirm-open",
  "sessions=#/sessions",
  "map=#/sessions/<A>",
  "map-timeline=#/sessions/<A>/timeline#chips-filtered",
  "session-map=#/sessions/<C>/timeline",
  "rules=#/rules",
  "rules-try=#/rules#try-open",
  "home-leak=#/#leak-row",
  "settings=#/settings",
];
const STATES = ["confirm-open", "chips-filtered", "fit", "try-open", "leak-row"];
const SHOT_RE = /^([\w.-]+)=(#\/[^#@]*)(@dark)?(?:#([\w-]+))?$/;

function parseShot(spec) {
  const bad = (why) => {
    console.error(`walk: bad --shot ${spec}: ${why}`);
    process.exit(2);
  };
  const m = SHOT_RE.exec(spec);
  if (!m) bad("want NAME=ROUTE, NAME=ROUTE@dark, NAME=ROUTE#STATE or NAME=ROUTE@dark#STATE; ROUTE starts with #/ and holds no other # or @");
  const [, name, rawRoute, dark, state] = m;
  if (state !== undefined && !STATES.includes(state)) bad(`unknown state #${state} (known: ${STATES.join(", ")})`);
  let route = rawRoute.replaceAll("<A>", A).replaceAll("{A}", A);
  if (/<C>|\{C\}/.test(route)) {
    if (!C) bad("names <C> but there is no --session-c (the fixture has no deny session)");
    route = route.replaceAll("<C>", C).replaceAll("{C}", C);
  }
  return { name, route, dark: !!dark, state: state || "" };
}
const shots = shotDir ? (all("shot").length ? all("shot") : DEFAULT_SHOTS).map(parseShot) : [];

// { route, legacy } in visiting order.
const routes = [
  { route: "#/" },
  { route: "#/sessions" },
  { route: `#/sessions/${A}` },
  { route: `#/sessions/${A}/timeline` },
  { route: "#/rules" },
  { route: "#/rules/skill/canary-basic" },
  { route: "#/rules/mcp/none" },
  { route: "#/settings" },
  { route: "#/overview", legacy: true },
  { route: "#/skills", legacy: true },
  { route: "#/skills/canary-basic", legacy: true },
  { route: "#/grants", legacy: true },
  { route: "#/enforce", legacy: true },
  { route: "#/flow", legacy: true },
  { route: `#/flow/${A}`, legacy: true },
  { route: `#/flow/timeline/${A}?hide_none=1&n=x`, legacy: true },
];

// Content checks by route (Plan 08). A check passes when some visible
// element matches sel, holds text (when given) and has a descendant
// matching has whose text holds hasText (when given).
const CHECKS = {
  "#/": [
    { name: "a leak row", sel: 'li.home-need[data-kind="leak"]', text: "Secret seen", timeout: 20000 },
    { name: "a row whose button keeps stopping", sel: "li.home-need", has: "button.need-decide", hasText: "Keep stopping it" },
    { name: "a row whose button lets it through (a while, no rule)", sel: "li.home-need", has: "button.need-decide", hasText: "Let it through" },
    { name: "a row whose button asks next time", sel: "li.home-need", has: "button.need-decide", hasText: "Ask me next time" },
  ],
  "#/rules": [
    { name: "a part-of chip (an intent)", sel: "li.rule-row .rule-intent", text: "part of: " },
    { name: "the Temporary notice", sel: ".card.rules-temp", text: "persistence/crontab", has: "button", hasText: "End now" },
    { name: "your own rule's count", sel: "li.rule-row", text: "prod-db.example.invalid", has: ".rule-stat", hasText: "fired 3" },
    { name: "a Claude Code Bash rule's count", sel: "li.rule-row", text: "npm publish", has: ".rule-stat", hasText: "fired 1" },
  ],
};

// checkContent(p, route) → one error string per check that did not pass.
async function checkContent(p, route) {
  const errs = [];
  for (const c of CHECKS[route] || []) {
    try {
      await p.waitForFunction(
        ({ sel, text, has, hasText }) =>
          [...document.querySelectorAll(sel)].some((el) => {
            const seen = el.checkVisibility ? el.checkVisibility() : el.offsetParent !== null;
            if (!seen || (text && !(el.textContent || "").includes(text))) return false;
            if (!has) return true;
            return [...el.querySelectorAll(has)].some((d) => !hasText || (d.textContent || "").includes(hasText));
          }),
        c,
        { timeout: c.timeout ?? 8000, polling: 250 },
      );
    } catch {
      errs.push(`content: ${c.name} not shown (${c.sel}${c.text ? ` with "${c.text}"` : ""}${c.has ? `, ${c.has}${c.hasText ? ` "${c.hasText}"` : ""}` : ""})`);
    }
  }
  return errs;
}

// API 404s that are part of the page's normal flow, by route.
const expected404 = {
  "#/rules/mcp/none": ["/api/"],
};

// watch(p, sink): records p's errors into sink().errors (redacted), where
// sink() returns the row being recorded (or null: the orphan list). The
// expected 404s are looked up by that row's route.
const orphan = [];
function watch(p, sink) {
  const note = (msg) => {
    const row = sink();
    (row ? row.errors : orphan).push(redact(msg));
  };
  const allowed404 = (url) => {
    const row = sink();
    const list = row && expected404[row.route];
    return !!list && list.some((x) => new URL(url).pathname.startsWith(x));
  };
  p.on("console", (m) => {
    const t = m.type();
    if (t !== "error" && t !== "warning") return;
    const text = m.text();
    // The browser's own line for a failed fetch; the response handler below
    // reports the URL, and filters the expected ones.
    if (/Failed to load resource/.test(text)) return;
    note(`console ${t}: ${text}`);
  });
  p.on("pageerror", (e) => note(`pageerror: ${e.message}`));
  // Chromium reports a 304 answer to a no-store fetch (the If-None-Match
  // polls) as a failed request with net::ERR_ABORTED right after the 304
  // response; such a request is not a failure.
  const notModified = new WeakSet();
  p.on("response", (r) => {
    if (r.status() === 304) notModified.add(r.request());
    const u = new URL(r.url());
    if (!u.pathname.startsWith("/api/") || r.status() < 400) return;
    if (r.status() === 404 && allowed404(r.url())) return;
    note(`${r.status()} ${u.pathname}`);
  });
  p.on("requestfailed", (r) => {
    const u = new URL(r.url());
    // The event stream is aborted when the page navigates away or closes.
    if (u.pathname === "/api/events") return;
    if (notModified.has(r)) return;
    note(`request failed: ${u.pathname} ${r.failure()?.errorText ?? ""}`);
  });
}

async function settleOn(p) {
  // The event stream keeps one request open for good, so networkidle may
  // never come; give it a short chance, then wait the fixed 500 ms.
  await p.waitForLoadState("networkidle", { timeout: 3000 }).catch(() => {});
  await p.waitForTimeout(500);
  await p.waitForSelector("main#page", { timeout: 5000 });
}

async function go(p, route) {
  if ((await p.evaluate(() => location.hash)) === route) return;
  await p.evaluate((h) => {
    location.hash = h;
  }, route);
}

const browser = await chromium.launch();
const context = await browser.newContext();
const page = await context.newPage();
const settle = () => settleOn(page);
let current = null; // the walk page's row being recorded
watch(page, () => current);

// ---------------------------------------------------------------- routes

const rows = [];
const axeRows = [];
current = { route: "(launch)", errors: [], hash: "" };
try {
  await page.goto(`${base}#t=${token}`); // LAUNCH
  await settle();
} catch (e) {
  console.error(`walk: the launch failed: ${redact(e.message)}`);
  await browser.close();
  process.exit(2);
}
rows.push(current);

for (const r of routes) {
  current = { route: r.route, legacy: !!r.legacy, errors: [], hash: "" };
  await go(page, r.route);
  await settle();
  current.hash = await page.evaluate(() => location.hash);
  if (r.legacy && current.hash === r.route) {
    current.errors.push("legacy hash did not change");
  }
  if (!current.hash.startsWith("#/")) current.errors.push(`unexpected hash ${current.hash}`);
  current.errors.push(...(await checkContent(page, r.route)));
  if (doAxe) {
    const bg = {};
    for (const scheme of ["light", "dark"]) {
      try {
        await page.emulateMedia({ colorScheme: scheme });
        await page.waitForTimeout(400); // the theme's colour transitions
        bg[scheme] = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);
        const a = await runAxe(page);
        axeRows.push({ route: r.route, scheme, ...a });
        current.errors.push(...a.failures.map((f) => redact(`[${scheme}] ${f}`)));
      } catch (e) {
        axeRows.push({ route: r.route, scheme, error: redact(e.message) });
        current.errors.push(redact(`[${scheme}] axe did not run: ${e.message}`));
      }
    }
    await page.emulateMedia({ colorScheme: "light" });
    // The dark run must have rendered dark: the page follows the scheme only
    // while its theme is auto.
    if (bg.light && bg.light === bg.dark) current.errors.push(`axe: the dark scheme did not change the page (body background ${bg.light})`);
  }
  rows.push(current);
}

// Errors on the walk page between the route walk and the keyboard pass.
const between = { route: "(between modes)", errors: [], hash: "" };
current = between;

// ---------------------------------------------------------------- screenshots

// applyState(page, state): put the page in the named state before the shot.
async function applyState(page, state) {
  if (state === "confirm-open") {
    // The first Needs row's decision sheet (2026-10-28; the state keeps its name).
    const decide = page.locator("li.home-need button.need-decide").first();
    await decide.waitFor({ state: "visible", timeout: 5000 });
    await decide.focus();
    await page.keyboard.press("Enter");
    await page.locator("dialog.need-sheet[open]").waitFor({ state: "visible", timeout: 3000 });
  } else if (state === "chips-filtered") {
    const chip = page.locator('button.chip[data-chip="Auto check"]');
    await chip.waitFor({ state: "visible", timeout: 5000 });
    if ((await chip.getAttribute("aria-pressed")) !== "true") throw new Error("the Auto check chip is already off");
    await chip.click();
    await page.locator('button.chip[data-chip="Auto check"][aria-pressed="false"]').waitFor({ timeout: 3000 });
    await page.locator('.auth-chips button[data-chip=""]').waitFor({ state: "visible", timeout: 3000 });
    await page.mouse.move(0, 0); // no hover outline in the picture
  } else if (state === "fit") {
    const fit = page.locator('button.fit[aria-label="Fit to view"]');
    await fit.waitFor({ state: "visible", timeout: 5000 });
    await fit.click();
    await page.mouse.move(0, 0); // no hover outline in the picture
  } else if (state === "try-open") {
    const field = page.locator("#rules-try-value");
    await field.waitFor({ state: "visible", timeout: 5000 });
    await field.fill("curl https://example.com");
    await field.press("Enter");
    await page.locator("#rules-try-result .rules-try-verdict, #rules-try-result .rules-try-none").first().waitFor({ state: "visible", timeout: 5000 });
    await page.mouse.move(0, 0); // no hover outline in the picture
  } else if (state === "leak-row") {
    // the session index is built as the dashboard starts; Home reloads Needs
    // you on its index event
    const row = page.locator("li.home-need", { hasText: "Secret seen" }).first();
    await row.waitFor({ state: "visible", timeout: 20000 });
    await row.evaluate((el) => el.scrollIntoView({ block: "center" }));
    await page.mouse.move(0, 0); // no hover outline in the picture
  }
  await page.waitForTimeout(300);
}

// shoot(page, shot): one capture in its own context. The token guard sits on
// the line right above the capture (internal/ui walk_source_test.go checks
// it). The walk's own hash change replaces the launch fragment, and the app
// strips t= as it starts; the guard is the backstop, and it fails closed on
// any route that holds "t=".
async function shoot(page, shot) {
  await page.goto(`${base}#t=${token}`);
  await settleOn(page);
  await go(page, shot.route);
  await settleOn(page);
  await applyState(page, shot.state);
  if (!(await page.locator("section#notice").isHidden())) throw new Error("the token notice is showing");
  if (!(await page.locator("main#page > *").count())) throw new Error("main#page is empty");
  const file = join(shotDir, `${shot.name}.png`);
  if ((await page.evaluate(() => location.hash)).includes("t=")) throw new Error("token in hash");
  // WALK_FULLPAGE=1 captures the whole page (a developer check); the README shots stay one viewport.
  await page.screenshot({ path: file, fullPage: process.env.WALK_FULLPAGE === "1" });
  return file;
}

const shotRows = [];
for (const s of shots) {
  const ctx = await browser.newContext({
    viewport: { width: 1280, height: 800 },
    deviceScaleFactor: 1,
    colorScheme: s.dark ? "dark" : "light",
    reducedMotion: "reduce",
  });
  const p = await ctx.newPage();
  const row = { ...s, route: s.route, file: "", bytes: 0, errors: [] };
  watch(p, () => row);
  try {
    row.file = await shoot(p, s);
    row.bytes = statSync(row.file).size;
  } catch (e) {
    row.errors.push(redact(e.message));
  }
  await ctx.close();
  shotRows.push(row);
}

// ---------------------------------------------------------------- keys

const keyErrs = []; // one row per key route: the walk page's errors during it
const keyRows = doKeys
  ? await runKeys(page, settle, A, (route) => {
      current = { route, errors: [], hash: "" };
      keyErrs.push(current);
    })
  : [];
current = null;
for (const k of keyErrs) {
  if (k.errors.length) keyRows.push({ route: k.route, step: "errors during the route", ok: false, expected: `no errors; got ${k.errors.join(" | ")}`, actual: "" });
}
if (between.errors.length) rows.push(between);
for (const m of orphan) rows[rows.length - 1].errors.push(m);

await browser.close();

// ---------------------------------------------------------------- report

let fail = 0;
const w = Math.max(...rows.map((r) => r.route.length));
let bad = 0;
console.log(`${"route".padEnd(w)}  ->  final hash  .  errors`);
for (const r of rows) {
  const e = r.errors.length ? redact(r.errors.join(" | ")) : "ok";
  if (r.errors.length) bad++;
  console.log(`${r.route.padEnd(w)}  ->  ${redact(r.hash || "-")}  .  ${e}`);
}
console.log(bad ? `walk: FAIL (${bad} of ${rows.length} rows with errors)` : `walk: PASS (${rows.length} rows)`);
fail += bad;

if (doAxe) {
  console.log("");
  console.log(`${"axe route".padEnd(w)}  scheme  rules  pass  viol  incompl  critical  serious  moderate  minor`);
  let axeBad = 0;
  for (const a of axeRows) {
    if (a.error) {
      axeBad++;
      console.log(`${a.route.padEnd(w)}  ${a.scheme.padEnd(6)}  did not run: ${redact(a.error)}`);
      continue;
    }
    if (a.failures.length) axeBad++;
    const c = a.counts;
    console.log(
      `${a.route.padEnd(w)}  ${a.scheme.padEnd(6)}  ${String(a.total).padStart(5)}  ${String(a.passes).padStart(4)}  ${String(a.violations).padStart(4)}  ${String(a.incomplete).padStart(7)}  ${String(c.critical).padStart(8)}  ${String(c.serious).padStart(7)}  ${String(c.moderate).padStart(8)}  ${String(c.minor).padStart(5)}`,
    );
  }
  console.log(axeBad ? `axe: FAIL (${axeBad} of ${axeRows.length} route-scheme runs)` : `axe: PASS (${axeRows.length} route-scheme runs; counts are nodes, rules = passes + violations + incomplete)`);
}

if (shotDir) {
  console.log("");
  let shotBad = 0;
  for (const s of shotRows) {
    if (s.errors.length) shotBad++;
    const what = `${s.name}  ${s.route}${s.dark ? " dark" : " light"}${s.state ? " " + s.state : ""}`;
    console.log(s.errors.length ? `shot ${what}  .  ${redact(s.errors.join(" | "))}` : `shot ${what}  ->  ${s.file} (${s.bytes} bytes)`);
  }
  console.log(shotBad ? `screenshots: FAIL (${shotBad} of ${shotRows.length})` : `screenshots: PASS (${shotRows.length})`);
  fail += shotBad;
}

if (doKeys) {
  console.log("");
  const kw = Math.max(0, ...keyRows.map((k) => k.step.length));
  let keyBad = 0;
  for (const k of keyRows) {
    if (!k.ok) keyBad++;
    const tail = k.ok ? `ok  ${k.actual}` : `FAIL  expected ${k.expected}${k.actual ? "; focus on " + k.actual : ""}`;
    console.log(`keys ${k.route.padEnd(10)}  ${k.step.padEnd(kw)}  ${redact(tail)}`);
  }
  if (!keyRows.length) keyBad++;
  console.log(keyBad ? `keys: FAIL (${keyBad} of ${keyRows.length} steps)` : `keys: PASS (${keyRows.length} steps)`);
  fail += keyBad;
}

process.exit(fail ? 1 : 0);
