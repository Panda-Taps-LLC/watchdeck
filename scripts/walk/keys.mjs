// Keyboard pass for the dashboard walkthrough (walk.mjs --keys).
//
// The script is data: per route, a list of steps run in order. A step does
// one thing, then waits (polling, up to its timeout) until every assertion
// it carries holds:
//
//   focus: "<selector>"       focus that element from script (the start point),
//                             again on every poll until `expect` holds
//   press: "<key>"            page.keyboard.press(key) once
//   type: "<text>"            page.keyboard.type(text) into the focused element
//   press + until: N          press the key up to N times, stopping at the
//                             first press after which `expect` holds
//   expect                    document.activeElement must match: a selector
//                             string, {label: "text"} (aria-label, text or id
//                             contains it), {labelRe: "regexp source"}, or
//                             {same: "<name>"} (the element remembered under
//                             that name: same tag and aria-label, and the same
//                             position among the remembered step's matches)
//   remember: "<name>"        after the step passes, remember the active
//                             element's aria-label and aria-checked (or aria-pressed)
//   visible / hidden          a selector that must (not) match a visible element
//   hash                      location.hash must start with this
//   pressed: {name, changed}  the active element's aria-checked (a switch) or aria-pressed differs from
//                             (changed: true) or equals (false) the remembered one
//
// The first failing step ends its route; the next route still runs. Each
// failure names the route, the step, what was expected and the element that
// had focus.
//
// The pass changes the fixture (a Needs item is dismissed), so walk.mjs runs
// it after the read-only modes. The Rules switch is checked through its
// confirm and Escape, then toggled (Space, Tab to the confirm button, Enter)
// and toggled back, focus staying on the re-rendered switch each time (Plan
// 05 Task 6); the pack rule ends in the state it started in. Before that the
// Rules route tries one call in the try box (Plan 08 Task 6): Tab to its
// field, type a command, Enter shows the answer with focus on it, Escape
// puts focus back in the field. The try writes nothing.
//
// Home (2026-10-28): a row's one button opens its decision sheet with focus
// on the For popup; Escape gives focus back; the For popup set to "This
// session" turns the filled button into "Let it through" and back; "Don't
// show this again" is the one write (an Undo toast follows); a leak row's
// sheet carries its timeline link. On Rules, the Remove of a row that is
// part of an intent opens a confirm with the lesser "Only this rule" button
// showing, and Escape gives focus back. No allow and no rule is written.
//
// An empty script, or a route with no steps, is a failure: the pass must not
// report PASS for nothing.

// A Needs you row's one button opens its decision sheet (2026-10-28).
const DECIDE = 'li.home-need button.need-decide';
const SHEET = "dialog.need-sheet[open]";
const NEVER = SHEET + " button.need-sheet-never";
const LEAK_DECIDE = 'li.home-need[data-kind="leak"] button.need-decide';
const NODE = "button.node";
// The try box's answer: a verdict tag, or the line saying no watchdeck rule applies.
const TRY_ANSWER = "#rules-try-result .rules-try-verdict, #rules-try-result .rules-try-none";
const AUTOSTART = 'button.sw[aria-label="Start the dashboard with each Claude Code session"]';
const INTENT_REMOVE = 'li.rule-row:has(.rule-intent) button[aria-label^="Remove: "]';

export function keyRoutes(A) {
  return [
    {
      route: "#/",
      steps: [
        { name: "start on the skip link", focus: "a.skip", expect: "a.skip" },
        { name: "Tab: brand", press: "Tab", expect: "a.brand" },
        { name: "Tab: Home tab", press: "Tab", expect: 'a.tab[data-page="home"]' },
        { name: "Tab: Sessions tab", press: "Tab", expect: 'a.tab[data-page="sessions"]' },
        { name: "Tab: Rules tab", press: "Tab", expect: 'a.tab[data-page="rules"]' },
        { name: "Tab: settings gear", press: "Tab", expect: 'a.tab.gear[data-page="settings"]' },
        { name: "Tab to the first Needs row's button", press: "Tab", until: 40, expect: DECIDE, remember: "decide" },
        { name: "Enter opens the sheet, focus on the For popup", press: "Enter", expect: "#need-for", visible: SHEET },
        { name: "Escape closes, focus back on the row's button", press: "Escape", expect: { same: "decide" }, hidden: SHEET },
        { name: "Enter opens it again", press: "Enter", expect: "#need-for", visible: SHEET },
        { name: "For: This session makes the filled button Let it through", select: "#need-for", value: "session", expect: "#need-for", visible: SHEET + ' button.need-sheet-primary[data-choice="allow"]' },
        { name: "For: Always brings the Rule popup back", select: "#need-for", value: "always", expect: "#need-for", visible: SHEET + ' button.need-sheet-primary[data-choice="rule"], ' + SHEET + " #need-rule" },
        { name: "Tab to Don't show this again", press: "Tab", until: 8, expect: NEVER },
        { name: "Enter dismisses, the Undo toast holds focus", press: "Enter", expect: ".toast.home-undo .home-undo-btn", hidden: SHEET, timeout: 4000 },
        { name: "Escape closes the toast, focus on the Needs heading", press: "Escape", expect: "#home-needs-h", hidden: ".toast.home-undo" },
        { name: "start on a leak row's button", focus: LEAK_DECIDE, expect: LEAK_DECIDE, remember: "leak" },
        { name: "Enter opens its sheet with the timeline link", press: "Enter", visible: SHEET + ' a[href*="/timeline"]' },
        { name: "Escape closes, focus back on that button", press: "Escape", expect: { same: "leak" }, hidden: SHEET },
      ],
    },
    {
      route: "#/rules",
      steps: [
        { name: "start on the skip link", focus: "a.skip", expect: "a.skip" },
        { name: "Tab to the try field", press: "Tab", until: 20, expect: "#rules-try-value" },
        { name: "type a command", type: "curl https://example.com", expect: "#rules-try-value" },
        { name: "Enter tries it, the answer holds focus", press: "Enter", expect: "#rules-try-result", visible: TRY_ANSWER, timeout: 5000 },
        { name: "Escape returns focus to the field", press: "Escape", expect: "#rules-try-value", visible: TRY_ANSWER },
        { name: "Tab to Add rule (past the Try button)", press: "Tab", until: 4, expect: "#rules-add" },
        { name: "Enter opens the sheet, focus in the kind control", press: "Enter", expect: 'input[name="rule-sheet-kind"]', visible: "dialog.rule-sheet[open]" },
        { name: "Escape closes, focus back on Add rule", press: "Escape", expect: "#rules-add", hidden: "dialog.rule-sheet[open]" },
        { name: "Tab to the first switch", press: "Tab", until: 80, expect: "button.sw", remember: "sw" },
        { name: "Space asks first, focus on Cancel", press: "Space", expect: "#confirm-cancel", visible: "dialog#confirm[open]" },
        { name: "Escape cancels, focus back on the switch, unchanged", press: "Escape", expect: { same: "sw" }, hidden: "dialog#confirm[open]", pressed: { name: "sw", changed: false } },
        { name: "Space asks again, focus on Cancel", press: "Space", expect: "#confirm-cancel", visible: "dialog#confirm[open]" },
        { name: "Tab to the confirm button", press: "Tab", expect: "#confirm-ok" },
        { name: "Enter toggles, focus stays on the switch", press: "Enter", expect: { same: "sw" }, hidden: "dialog#confirm[open]", pressed: { name: "sw", changed: true }, timeout: 4000 },
        { name: "Space asks to switch back", press: "Space", expect: "#confirm-cancel", visible: "dialog#confirm[open]" },
        { name: "Tab to the confirm button", press: "Tab", expect: "#confirm-ok" },
        { name: "Enter toggles back, focus stays on the switch", press: "Enter", expect: { same: "sw" }, hidden: "dialog#confirm[open]", pressed: { name: "sw", changed: false }, timeout: 4000 },
        { name: "start on the Remove of a rule that is part of an intent", focus: INTENT_REMOVE, expect: INTENT_REMOVE, remember: "intent" },
        { name: "Enter asks first: Cancel focused, Only this rule shown", press: "Enter", expect: "#confirm-cancel", visible: "dialog#confirm[open] #confirm-alt" },
        { name: "Escape closes, focus back on that Remove", press: "Escape", expect: { same: "intent" }, hidden: "dialog#confirm[open]" },
      ],
    },
    {
      route: "#/sessions",
      steps: [
        { name: "start on the skip link", focus: "a.skip", expect: "a.skip" },
        { name: "Tab to a live lane", press: "Tab", until: 40, expect: "a.lm-lane" },
        { name: "Enter opens the session", press: "Enter", hash: "#/sessions/", visible: "div.nodes " + NODE, timeout: 6000 },
        { name: "Tab to a map node", press: "Tab", until: 120, expect: NODE },
        { name: "Enter selects it, the card shows it", press: "Enter", expect: NODE + '[aria-pressed="true"]', visible: "section.map-card button" },
        { name: "Escape clears the selection", press: "Escape", hidden: NODE + '[aria-pressed="true"]' },
      ],
    },
    {
      route: "#/settings",
      steps: [
        { name: "start on the skip link", focus: "a.skip", expect: "a.skip" },
        { name: "Tab to Install or Uninstall (whichever is enabled)", press: "Tab", until: 30, expect: { labelRe: "^(Install|Uninstall)$" } },
        { name: "Tab to the autostart switch", press: "Tab", until: 30, expect: AUTOSTART },
      ],
    },
  ];
}

// probe runs in the page: describes the active element and checks one step's
// assertions against it. Pure function of its argument (it is serialized).
function probe({ step, memory }) {
  const a = document.activeElement;
  const desc = (el) => {
    if (!el || el === document.body) return "(body)";
    let s = el.tagName.toLowerCase();
    if (el.id) s += "#" + el.id;
    if (el.classList && el.classList.length) s += "." + [...el.classList].join(".");
    const label = el.getAttribute("aria-label");
    const text = (el.textContent || "").trim().replace(/\s+/g, " ").slice(0, 40);
    if (label) s += ` [aria-label="${label}"]`;
    else if (text) s += ` "${text}"`;
    return s;
  };
  const labelOf = (el) => (el && (el.getAttribute("aria-label") || (el.textContent || "").trim().replace(/\s+/g, " ") || el.id)) || "";
  const visibleMatch = (sel) => [...document.querySelectorAll(sel)].some((el) => el.checkVisibility ? el.checkVisibility() : el.offsetParent !== null);
  const fails = [];
  const e = step.expect;
  if (e !== undefined) {
    let ok = false;
    if (typeof e === "string") ok = !!a && a !== document.body && a.matches(e);
    else if (e.label !== undefined) ok = labelOf(a).includes(e.label);
    else if (e.labelRe !== undefined) ok = new RegExp(e.labelRe).test(labelOf(a));
    else if (e.same !== undefined) {
      const m = memory[e.same];
      ok = !!m && !!a && a !== document.body && labelOf(a) === m.label && a.tagName === m.tag;
      if (ok && m.sel) ok = [...document.querySelectorAll(m.sel)].indexOf(a) === m.idx;
    }
    if (!ok) fails.push(`focus on ${JSON.stringify(e)}`);
  }
  if (step.visible && !visibleMatch(step.visible)) fails.push(`visible ${step.visible}`);
  if (step.hidden && visibleMatch(step.hidden)) fails.push(`hidden ${step.hidden}`);
  if (step.hash && !location.hash.startsWith(step.hash)) fails.push(`hash starting ${step.hash} (got ${location.hash})`);
  if (step.pressed) {
    const m = memory[step.pressed.name];
    const now = a ? a.getAttribute("aria-checked") ?? a.getAttribute("aria-pressed") : null;
    const changed = !!m && now !== null && now !== m.pressed;
    if (!m || now === null || changed !== step.pressed.changed) {
      fails.push(`aria-checked ${step.pressed.changed ? "changed from" : "still"} ${m ? m.pressed : "?"} (now ${now})`);
    }
  }
  return {
    fails,
    actual: desc(a),
    snap: {
      label: labelOf(a),
      tag: a ? a.tagName : "",
      pressed: a ? a.getAttribute("aria-checked") ?? a.getAttribute("aria-pressed") : null,
      sel: typeof e === "string" ? e : null,
      idx: typeof e === "string" ? [...document.querySelectorAll(e)].indexOf(a) : -1,
    },
  };
}

async function check(page, step, memory, timeout) {
  const end = Date.now() + timeout;
  let r;
  for (;;) {
    r = await page.evaluate(probe, { step, memory });
    if (!r.fails.length || Date.now() >= end) return r;
    await page.waitForTimeout(50);
  }
}

// runKeys(page, settle, A, onRoute) → rows of {route, step, ok, expected,
// actual}. onRoute(route) runs before each route, so the caller can file the
// page's errors under it.
export async function runKeys(page, settle, A, onRoute = () => {}) {
  const rows = [];
  const script = keyRoutes(A);
  if (!script.length) rows.push({ route: "(none)", step: "no key routes", ok: false, expected: "at least one route with steps", actual: "" });
  for (const { route, steps } of script) {
    onRoute(route);
    if (!steps || !steps.length) {
      rows.push({ route, step: "route has no steps", ok: false, expected: "at least one step", actual: "" });
      continue;
    }
    if ((await page.evaluate(() => location.hash)) !== route) {
      await page.evaluate((h) => {
        location.hash = h;
      }, route);
    }
    await settle();
    const memory = {};
    let passed = 0;
    for (const step of steps) {
      let r;
      if (step.focus) {
        // Focus again on every poll: a list that re-renders (Home reloads
        // Needs you after a dismiss) replaces the element focused first.
        const end = Date.now() + (step.timeout ?? 2000);
        for (;;) {
          await page.evaluate((sel) => document.querySelector(sel)?.focus(), step.focus);
          r = await check(page, step, memory, 0);
          if (!r.fails.length || Date.now() >= end) break;
          await page.waitForTimeout(100);
        }
      } else if (step.type !== undefined) {
        await page.keyboard.type(step.type);
        r = await check(page, step, memory, step.timeout ?? 2000);
      } else if (step.select) {
        // A popup's value, as a keyboard would set it (the change event
        // fires; the page re-renders and puts focus back on the popup).
        await page.selectOption(step.select, step.value);
        r = await check(page, step, memory, step.timeout ?? 2000);
      } else if (step.until) {
        // Assert after each press with no wait: an element passed on the way
        // must not count, only the first press that lands on the target.
        for (let i = 0; i < step.until; i++) {
          await page.keyboard.press(step.press);
          r = await check(page, step, memory, 0);
          if (!r.fails.length) break;
        }
      } else {
        await page.keyboard.press(step.press);
        r = await check(page, step, memory, step.timeout ?? 2000);
      }
      if (r.fails.length) {
        rows.push({ route, step: step.name, ok: false, expected: r.fails.join("; ") + (step.until ? ` within ${step.until} presses` : ""), actual: r.actual });
        break;
      }
      if (step.remember) memory[step.remember] = r.snap;
      rows.push({ route, step: step.name, ok: true, expected: "", actual: r.actual });
      passed++;
    }
    if (passed < steps.length) {
      for (const s of steps.slice(passed + 1)) rows.push({ route, step: s.name, ok: false, expected: "not run (an earlier step failed)", actual: "" });
    }
  }
  return rows;
}
