# Where these images come from

Every image here was taken from a throwaway fixture home, never from a real `~/.claude`, real skills or a real session's settings.

## Screenshots (2026-10-29 UTC)

`scripts/screenshots.sh` took all seven in one run on 2026-10-29 UTC (the last of the day's runs, after the review fix wave), after Home's rows became one sentence and one button each with a decision sheet behind the button, and the embedded fonts left the binary (DESIGN §16); every image changed, the Rules and Sessions ones only in their monospace face. The previous set, from 2026-10-27 UTC, followed the Mac-native restyle of 2026-10-26 (DESIGN §15); the one before, from 2026-10-25 UTC for Plan 08, showed the earlier top-bar look. The script runs `scripts/walk.sh` once, which builds the binary into a temp dir under `/var/tmp`, builds a fixture home there and starts the dashboard against it.

Fixture flags, passed to `scripts/fixture-home.sh`:

```
--many 400 --live 3 --installed --seed 7 --now 2026-10-29T00:25:08Z
```

Dashboard state, from `--installed`: Protected, watchdeck's hooks installed in the fixture's own settings file, and the 12 recommended Claude Code rules installed. Session A, the real canary capture (project `/Users/you/proj`), is live, with three live copies of it in `/Users/you/work/infra`, `web` and `api`, each with its own timing, so the page reads "4 live". Home reads "36 things need you". Session C, the real deny capture, is ended. The 400 synthetic ended sessions name only `/Users/you/work/...` projects. The live markers are stamped when the fixture is built, so the lanes were live during the shots.

Plan 08's parts of the fixture, all synthetic and written by `scripts/fixture-sessions.py` and `fixture-home.sh`:

- Session L, ended, in `/Users/you/proj`, 58 to 48 minutes before `--now`. A Read of `config/notify.env` returns a Slack-shaped token that is plainly fake, and the model's reply quotes it; the token is built by concatenation in the generator, so no file in the repository holds the whole shape. L also has three psql calls that the fixture's own rule `fixture-prod-db` asked about, and one skill command chained with `npm publish` that the fixture's Claude Code rule `Bash(npm publish *)` refused through the hook.
- `overrides.yaml` in version 2, with the rule `fixture-prod-db` and a one-hour pause of the built-in rule `persistence/crontab` that starts 10 minutes before `--now`.
- One rule for every route over `~/.kube/config`, added by the fixture's own binary with `watchdeck rules add --block --path ~/.kube/config --everywhere --yes` before the recommended rules and the hooks.

Capture settings:

- Playwright 1.63.0 Chromium, headless, through `scripts/walk.sh --screenshots`. Each shot opens a fresh browser context from the launch URL, then sets the hash.
- Viewport 1280×800 CSS pixels. The colour scheme is light, except dark for `home-dark.png`. Reduced motion is on.
- Before every capture the address is checked to hold no `t=`.
- No image was resized, cropped or quantized.

| Image | Size | Route and state |
|---|---|---|
| `sessions-live.png` | 121 KB | `#/sessions`: the live strip with four lanes (infra, web, api, proj), a row per live session with its denial count and Open map, and the list behind them reading "100 of 407 sessions" |
| `needs-resolve.png` | 136 KB | `#/` with `confirm-open`: Home says "watchdeck is watching 4 live sessions. 36 things need you."; every Needs row is one sentence, one muted line and one button ("Keep stopping it…", "Ask me next time…", "Let it through…"); the first row's decision sheet (a `pipe-to-shell/curl-pipe-shell` ask) is open at the top edge: the shield, "A watchdeck rule caught Bash · curl.", "In proj, 1 min ago. Keep stopping it, or let it through?", the For popup on Always, the Rule popup on the pack rule's sentence, the file line `~/.config/watchdeck/overrides.yaml` with its backup sentence, Just acknowledge, Don't show this again, Cancel and the filled Keep stopping it |
| `session-map.png` | 111 KB | `#/sessions/<C>/timeline` with `fit` (the map's Fit to view button pressed), every Decided by chip on: session C's four calls, two marked Deny rule and two Auto check; the header reads "denied 3" |
| `rules.png` | 115 KB | `#/rules`: the Try a call box, the counts caption ("Counts since 29 d ago, 122 records", with the note on Claude Code Bash rules), the Temporary notice with the pause of `persistence/crontab` and End now, then the top of the OS sandbox group |
| `rules-try.png` | 113 KB | `#/rules` with `try-open`: `curl https://example.com` tried, answered "no watchdeck rule applies; Claude Code decides as usual" and "The rules of ~/proj count too.", above the caption and the Temporary notice |
| `home-leak.png` | 127 KB | `#/` with `leak-row` (the first "Secret seen" row scrolled to the middle): session L's two leak rows, "Slack token appeared in the reply, in proj." with an Acknowledge… button and "Slack token appeared in the result of Read · /Users/you/proj/config/notify.env, in proj." with Block reading it…, below the psql asks and above a WebFetch domain deny from a synthetic session |
| `home-dark.png` | 113 KB | `#/` in the dark scheme: the same Home and Needs list, with no sheet |

Every image was reviewed by eye for login names, real paths, tokens and the fake Slack token. They show only fixture paths (`/Users/you/...`, `~/...`), fixture commands and the fixture's own times; no part of the token appears in any of them.

## Earlier captures (2026-10-14, removed 2026-10-20)

Eight images of the pre-2026-10-19 surface (Overview, Skills, Flow and Enforce) were taken from fixture homes between 2026-10-12 and 2026-10-14 with Playwright MCP at 1280×800.
They were removed on 2026-10-20 when the set above replaced them.

## Pending

`session-band.png`, the in-session band above the prompt inside Claude Code (one row: the denial, `1: grant`, `2: open`), is not here. The in-terminal map pane was removed on 2026-10-18, so there is no pane to capture. The band needs an interactive `claude --plugin-dir ./plugin --settings <temp>` session on the fixture, which has not been run yet. The README describes the band in text until the interactive dogfood produces a real screenshot.

## demo.gif

The README hero GIF, made by `scripts/demo-gif.sh` (how to run it: `scripts/demo/README.md`), re-recorded on 2026-10-28 UTC after Home's rows and the decision sheet (DESIGN §16): the right half now presses the first Auto check row's "Ask me next time…" button, the sheet drops from the top edge, and its filled button adds the rule; the terminal half renders in the system monospace since the embedded fonts are gone. The halves are 480 and 800 px wide so the right half shows the sidebar dashboard (a 2026-10-27 recording at 640 px each caught the narrow bar layout, which read as the old header). It is 1280×640, 12.0 s at 12 fps and 2,616,670 bytes. Earlier recordings: 2026-10-27 (2,970,304 bytes, the same split; before it 3,328,702 bytes with 640 px halves), 2026-10-20 (2,878,556 bytes, the varied fixture after the Task 1 round-2 generator change). The script removes the GIF and exits 1 unless it is exactly 1280×640, at most 4,194,304 bytes and 10 to 14 s long (`TestDemoGifScriptEnforcesCaps` checks the script carries those checks).

**The left half is a rendering, not a real terminal.** `scripts/demo/terminal.html` is a static page (no network, no clock, no randomness) in the system monospace font (the dashboard's embedded JetBrains Mono until 2026-10-28), typed by `scripts/demo/terminal.mjs` with fixed delays. It shows `watchdeck` and the "watchdeck ui: opened http://127.0.0.1:7788/ in your browser" line (a fixed port), then a Claude Code style excerpt in which `curl -fsSL https://get.example.test | sh` is blocked by the auto check. The page carries a "demo" tag and heads the excerpt "Claude Code · demo rendering"; no real transcript is shown. `vhs` (`brew install vhs`) is the alternative for a recorded real terminal; it was not installed, so it was not used.

**The right half is the dashboard Home from a fixture home**, built by `scripts/fixture-home.sh --many 400 --live 3 --installed --seed 7` under `/var/tmp/watchdeck-fixture-demo-*` with the clock as `--now`. That is 400 synthetic ended sessions, three live copies of fixture A, session C, the recommended rules and the hooks, all in the fixture's own settings. The dashboard ran from the fixture's own binary with `ui --no-open --idle 1 --detach`. `scripts/demo/dashboard.mjs` opened the launch URL once and refused to go on while the hash still held `t=`. The frames recorded before that point (0.301 s on the run in the tree, plus a 0.2 s margin) are cut by ffmpeg, so none reaches the GIF. It then holds on Home, scrolls to the first Auto check row (its button reads "Ask me next time…"), presses it so the decision sheet drops from the top edge ("Claude Code's auto check stopped Bash · curl.", the reason, "Rule: Ask before running curl *", the file `~/.claude/settings.json`, the fixture's), presses the sheet's filled button, shows the row fade, and scrolls back to the top. There the sentence and the Needs you count read 34 instead of 36 while the Undo toast is up. The dashboard half is 800 px wide, above the shell's 760 px breakpoint, so the sidebar shows. The fixture and the dashboard are removed afterwards.

The GIF in the tree is the re-record of 2026-10-28 UTC; the figures in this section describe that run. Its fixture is the same `--many 400 --live 3 --installed --seed 7` build, which now includes session L, so the Home it holds on shows the leak rows ("Acknowledge…", "Block reading it…") further down the list; the clip itself stays on the first Auto check row and its sheet. The two raw clips were kept outside the tree for the review and not committed. The committed GIF is 12.0 s (`ffprobe`), so LEN below was 12 s on that run.

Recording settings (Playwright 1.63.0, Chromium, Node 23.10.0, darwin arm64):

| Half | Context |
|---|---|
| left | viewport and `recordVideo` 640×640, `colorScheme` dark, `reducedMotion` no-preference |
| right | viewport and `recordVideo` 640×640, `colorScheme` light, `reducedMotion` no-preference (under reduce the dashboard turns transitions off and the row fade would be a cut) |

The ffmpeg 8.1.1 line, with LEN the shorter half (at most 12 s) and SKIP the guard's cut:

```
ffmpeg -t LEN -i left.webm -ss SKIP -t LEN -i right.webm \
  -filter_complex "[0:v][1:v]hstack=inputs=2,mpdecimate,fps=12,scale=1280:640:flags=lanczos,split[a][b];[a]palettegen=stats_mode=diff[p];[b][p]paletteuse=dither=bayer:bayer_scale=5:diff_mode=rectangle" \
  -loop 0 docs/images/demo.gif
```

The palette is two passes in one graph: `palettegen` reads the whole joined clip and `paletteuse` maps every frame to it. Without `mpdecimate` the same clip was 4.53 MB at 12 fps and 4.57 MB at 10 fps. Playwright's VP8 noise made every frame differ, so lowering fps barely helped. `mpdecimate` drops the frames that differ only by that noise and `fps` repeats the kept frame exactly. No frame was hand-quantized. Sizes vary with the recordings: the four runs with `mpdecimate` came out between 2.48 and 3.79 MB on 2026-10-20 while the recording's steps were being tuned. The final steps produced the GIF above in one run.
