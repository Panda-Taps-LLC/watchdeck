# Dashboard walkthrough

A check that every dashboard route renders without errors, with three
optional modes: a keyboard pass, an axe accessibility pass and a screenshot
set. It is a developer tool. It never runs on push, pull request or a
schedule; the only workflow that runs it is dispatched by hand (below).

`scripts/walk.sh` builds the binary into a temp dir, builds a fixture home with
`scripts/fixture-home.sh`, starts the dashboard there, drives Chromium through
`walk.mjs`, stops the dashboard and removes the fixture (also when the build
or the fixture fails). It never touches the
real `~/.claude`, config or state directories: the dashboard and the browser
profile both run under the fixture `HOME`. The only real path named is
Playwright's browser cache, which the browser is launched from.

## Install once

```
cd scripts/walk
npm install
npx playwright install chromium
```

Exact pins in `package.json`, each at least two weeks old when chosen on
2026-10-19: `playwright` 1.63.0, `@axe-core/playwright` 4.13.0 and its
`axe-core` 4.13.0 (4.14.0 of both was under two weeks old). `node_modules` is
gitignored. Chromium is the only browser used.

## Run

```
scripts/walk.sh                          # the 17-row route walk
scripts/walk.sh --keep                   # keep the temp dir for a look
scripts/walk.sh --keys --axe             # plus the keyboard and axe passes
scripts/walk.sh --screenshots /var/tmp/shots \
  --shot home=#/ --shot home-dark=#/@dark --shot needs=#/#confirm-open \
  --shot rules=#/rules --shot 'map=#/sessions/<A>/timeline#chips-filtered'
```

`--many N`, `--live K`, `--installed`, `--seed S` and `--now T` go verbatim to
`fixture-home.sh` (before its output dir), for a bigger or installed fixture.
`--keys`, `--axe`, `--screenshots DIR` and every `--shot` go to `walk.mjs`.

The dashboard token travels only in the launch URL fragment. The script opens
that URL once per browser context, then changes `location.hash` for each
route without reloading; the app strips `t=` from the hash as it starts.

## What it checks

Routes, in order: `#/`, `#/sessions`, the fixture session and its timeline,
`#/rules`, a skill and an MCP rule page, `#/settings`, then the old hashes
(`#/overview`, `#/skills`, `#/skills/<name>`, `#/grants`, `#/enforce`,
`#/flow`, `#/flow/<id>`, `#/flow/timeline/<id>?...`).

For each route it waits for network idle (the event stream is allowed to stay
open) plus 500 ms, then records the final hash, console errors and warnings,
page errors, failed requests and `/api/` responses with status 400 or above.
The expected 404 for an MCP rule lookup is listed in `expected404` in
`walk.mjs`.

The same listeners watch the walk page during the keyboard pass and every
screenshot context, so an error there fails that key route or that shot.
The launch token never reaches the output: every error string goes through
`redact()` (the token and any `t=<value>`) before it is stored or printed,
because Playwright's navigation errors repeat the launch URL
(`internal/ui` `TestWalkRedactsToken`).

Two routes also carry content checks (Plan 08; Home's changed with the
decision sheet of 2026-10-28). Home must show a leak row ("Secret seen")
and a row each whose one button reads "Keep stopping it…", "Let it
through…" and "Ask me next time…". Rules must show a "part of" chip
(a rule added to cover every route), the Temporary notice with the pause of
`persistence/crontab` and End now, and rule counts: "fired 3" on the
fixture's own rule `fixture-prod-db` and "fired 1" on its Claude Code rule
`Bash(npm publish *)`. Each check waits up to 8 s (20 s for the leak row,
which needs the session index the dashboard builds as it starts), and a
miss is an error on that route. The checks need the fixture parts that
`fixture-home.sh` writes with a binary, so `walk.sh` hands it its own
(`WATCHDECK_BIN`). Without the intent the Rules row fails ("a part-of chip
(an intent) not shown"); that was run once on 2026-10-24 to show the checks
are not vacuous.

It prints a table of route, final hash and errors. Exit 1 on any error in any
mode, or on an old hash that did not change. Exit 2 on a setup problem. It
does not check page content beyond the checks above and what the modes below
assert.

The modes run in this order: axe during the route walk, then the
screenshots, then the keyboard pass, because the keyboard pass changes the
fixture (it dismisses a Needs item and switches a built-in rule).

### `--axe`

`axe.mjs` runs axe-core on every route after it settles, once in the light
and once in the dark colour scheme (emulated on the walk page; the row fails
if the page background does not change between them), with the `wcag2a`
and `wcag2aa` tags only (best-practice rules are not run). A route fails on
any violation of impact serious or critical, printed with the rule id, the
first two target selectors, the help URL and the first node's message. A
route also fails when axe evaluated no rule at all (passes, violations and
incomplete all empty), so a blank page cannot pass. Moderate and minor
counts are printed in a table per route and scheme.

### `--keys`

`keys.mjs` holds the key-press script as data: per route, steps of a key
press and the element that must then have focus, by selector or label.
Home goes from the skip link through the brand, the three tabs and the gear,
to the first Needs row's Add rule, opens the confirm with Enter (focus on
Cancel), closes it with Escape (focus back on Add rule), then dismisses the
row (focus on the Undo toast) and closes the toast with Escape (focus on the
Needs heading). Rules opens the Add rule sheet (focus in the kind control)
and closes it, then presses Space on the first built-in rule's switch (the
confirm opens with focus on Cancel) and Escape (focus back on the same
switch, unchanged). The confirmed toggle is not in the script yet: the page
loses focus after that write, and Plan 05 Task 6 fixes it and adds the step. Sessions opens
the live lane, Tabs to a map node, selects it with Enter and clears it with
Escape. Settings Tabs to Install or Uninstall, whichever is enabled, and to
the autostart switch. Two read-only confirm checks need the fixture's Plan 08
parts: on Home, after the dismiss, an "Allow … for this session" button opens
its confirm (focus on Cancel) and Escape gives focus back; on Rules, after the
switch steps, the Remove of a row that is part of an intent opens a confirm
with the lesser "Only this rule" button showing, and Escape gives focus back.
Neither confirm is accepted. A `focus` step focuses its element again on
every poll, because Home re-renders Needs you after the dismiss. A failure prints the route, the step, what was
expected and the element that had focus; the rest of that route is marked
not run. An empty script, or a route with no steps, fails the pass.

### `--screenshots DIR` and `--shot`

A shot is exactly `NAME=ROUTE`, `NAME=ROUTE@dark`, `NAME=ROUTE#STATE` or
`NAME=ROUTE@dark#STATE`, where STATE is `confirm-open` (Enter on the first
Needs row's Add rule), `chips-filtered` (the map's Auto check chip turned
off), `fit` (the map's Fit to view button pressed), `try-open` (the Rules
page's try box with `curl https://example.com` tried) or `leak-row` (Home's
first "Secret seen" row scrolled to the middle of the view). Anything else, such as an unknown state or `#STATE@dark`, exits 2
naming the shot. `<A>` or `{A}` in
the route is the fixture session A, picked by its id (the first live marker
when A is absent). `<C>` or `{C}` is the deny session C, which `walk.sh`
passes as `--session-c` only when the fixture holds its transcript; a shot
naming `<C>` without it is a setup error (exit 2). Each shot gets a fresh context at 1280x800
CSS px, scale 1, the light or dark colour scheme emulated and reduced motion;
the page is not full-page. Before every capture `walk.mjs` checks that the
token notice is hidden, the page has content and the hash holds no `t=`
(`internal/ui` `TestWalkCaptureGuardsToken` pins that guard). Without any
`--shot` it takes a default set: home, home-dark, needs (confirm open),
sessions, map, map-timeline (chips filtered), session-map (session C's
timeline), rules, rules-try, home-leak and settings.

## Manual workflow

`.github/workflows/walk.yml` runs on `workflow_dispatch` only, on
ubuntu-24.04, with inputs `many` (default 400) and `live` (default 3). It runs
`npm ci` and `npx playwright install --with-deps chromium` here, then
`scripts/walk.sh --many … --live … --installed --keys --axe --screenshots out`,
and uploads `out/` (the default screenshot set and `walk.txt`, the printed
tables) as the `walk` artifact, even when the walk fails. Actions are pinned
by commit SHA: checkout and setup-go as in `ci.yml`, `actions/setup-node`
v7.0.0 and `actions/upload-artifact` v7.0.1, each checked against its tag on
2026-10-19.
