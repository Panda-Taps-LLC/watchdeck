# Hero GIF

`scripts/demo-gif.sh` makes `docs/images/demo.gif`, the README's hero GIF. It
is a developer tool. It never runs in CI and never touches the real
`~/.claude`, config or state directories.

- **Left half:** `terminal.html`, a rendering of a terminal and a Claude Code
  excerpt, labelled as a demo in the page itself, typed by `terminal.mjs`
  with fixed delays. It is not a real terminal or transcript.
- **Right half:** the dashboard Home from a fixture home
  (`fixture-home.sh --many 400 --live 3 --installed --seed 7`), recorded by
  `dashboard.mjs` while an Auto check row in Needs you gets its rule added.

ffmpeg joins the two recordings (480×640 and 800×640; the dashboard half is
wider than the shell's 760 px breakpoint so the sidebar shows) into one
1280×640 GIF. The script
removes the GIF and exits 1 unless it is exactly 1280×640, at most 4 MiB
(4,194,304 bytes) and 10 to 14 s long. Provenance and the ffmpeg line are in
`docs/images/README.md`.

## Install once

The recordings reuse the Playwright install of the dashboard walk. They import
it by path (`../walk/node_modules/playwright/index.mjs`), because ES modules
ignore `NODE_PATH`.

```
cd scripts/walk
npm install --no-audit --no-fund
npx playwright install chromium
```

You also need `ffmpeg` and `ffprobe` (`brew install ffmpeg`), Go and Python 3.

## Run

```
scripts/demo-gif.sh                    # writes docs/images/demo.gif
scripts/demo-gif.sh /path/to/out.gif   # somewhere else
DEMO_GIF_KEEP=/some/dir scripts/demo-gif.sh   # also keep the two .webm files
```

It prints the GIF's dimensions, length and byte size, then PASS or FAIL. The
fixture home lives under `/var/tmp/watchdeck-fixture-demo-*` and is removed on
exit, with the dashboard stopped first.

If the GIF comes out over 4 MiB, lower `fps` to 10 in the script, then use
`dither=none` (`bayer_scale` is already 5, its maximum), before shortening the
clip.

## The token

The dashboard token goes to the page only through the launch URL's `#t=`
fragment. `dashboard.mjs` refuses to go on while the hash still holds `t=`.
It writes how long that took to `right.skip`, and the script cuts those first
frames, so no frame recorded before the page stripped the token reaches the
GIF.

## vhs

[vhs](https://github.com/charmbracelet/vhs) records a real terminal from a tape
file and is the alternative for the left half: `brew install vhs`. It was not
installed on 2026-10-20, so the left half is the HTML rendering.
