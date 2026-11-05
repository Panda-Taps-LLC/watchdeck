// Records the right half (800 px of the 1280) of docs/images/demo.gif: the dashboard Home from a
// fixture home (never the real one). Opens the launch URL once; the page
// strips the token from the hash, and the recording refuses to go on if it
// did not. Then scrolls Needs you to the first Auto check row with Add rule
// (else the first row with Add rule), opens Add rule, confirms, shows the row
// fade, then scrolls back to the top and holds on the new count and the Undo
// toast.
//
//   node dashboard.mjs --port N --token-file F --out DIR
//
// Writes DIR/right.webm and DIR/right.skip (seconds to cut from its start).
// Exit 1 when a step is missing (no Needs you row with Add rule, no dialog,
// no Undo toast) or the page threw.
import { mkdirSync, readFileSync, readdirSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { chromium } from "../walk/node_modules/playwright/index.mjs";

function arg(name) {
  const i = process.argv.indexOf("--" + name);
  if (i < 0 || !process.argv[i + 1]) {
    console.error(`dashboard: missing --${name}`);
    process.exit(2);
  }
  return process.argv[i + 1];
}
const port = arg("port");
const token = readFileSync(arg("token-file"), "utf8").trim();
const out = arg("out");
const vids = join(out, "right-raw");
mkdirSync(vids, { recursive: true });

const browser = await chromium.launch();
const context = await browser.newContext({
  // 800 px wide: above the 760 px breakpoint, so the sidebar shows (at 640 the
  // shell wraps into a bar and the GIF looked like the old header layout).
  viewport: { width: 800, height: 640 },
  recordVideo: { dir: vids, size: { width: 800, height: 640 } },
  colorScheme: "light",
  // no-preference, not reduce: under reduce the dashboard turns transitions
  // off, and the row fade the GIF shows would be a cut.
  reducedMotion: "no-preference",
});
const page = await context.newPage();
const t0 = performance.now(); // the video starts with the page
const errors = [];
page.on("pageerror", (e) => errors.push(e.message));

await page.goto(`http://127.0.0.1:${port}/#t=${token}`);
await page.waitForSelector("main#page", { timeout: 10000 });
// The capture guard: never record a frame that could hold the token.
await page.waitForFunction(() => !location.hash.includes("t="), null, { timeout: 5000 }).catch(() => {});
if (await page.evaluate(() => location.hash.includes("t="))) throw new Error("dashboard: the token is still in the hash");
// Frames before this point were recorded while the hash may have held the
// token; demo-gif.sh cuts them (ffmpeg -ss on this input), with a margin.
const skip = (performance.now() - t0) / 1000 + 0.2;

// The row to act on: the first Auto check denial with Add rule, so the two
// halves tell one story (the terminal half shows an auto check block); else
// the first row with Add rule.
const addable = page.locator("li.home-need", { has: page.locator("button.need-decide", { hasText: /Ask me next time|Keep stopping it/ }) });
await addable.first().waitFor({ timeout: 10000 });
const auto = addable.filter({ hasText: "Auto check" }).first();
const row = (await auto.count()) ? auto : addable.first();
// Home first while the terminal half shows the block (about 5 s), then
// Needs you: the row is scrolled to the middle of the view.
await page.waitForTimeout(4000);
await row.evaluate((e) => e.scrollIntoView({ behavior: "smooth", block: "center" }));
await page.waitForTimeout(1200);

await row.locator("button.need-decide").click();
await page.waitForSelector("dialog.need-sheet[open]", { timeout: 5000 });
await page.waitForTimeout(1800);
await page.click("dialog.need-sheet[open] button.need-sheet-primary");
await page.waitForSelector(".toast.home-undo", { timeout: 5000 });
// After the fade, back to the top: the sentence and the Needs you count show
// the lower number while the Undo toast stays up (it lasts 8 s).
await page.waitForTimeout(1000);
await page.evaluate(() => window.scrollTo({ top: 0, behavior: "smooth" }));
await page.waitForTimeout(4000);

await context.close(); // flushes the video
await browser.close();
if (errors.length) {
  console.error("dashboard: page errors:\n" + errors.join("\n"));
  process.exit(1);
}
const [f] = readdirSync(vids).filter((n) => n.endsWith(".webm"));
renameSync(join(vids, f), join(out, "right.webm"));
writeFileSync(join(out, "right.skip"), skip.toFixed(3) + "\n");
console.log(`dashboard: ${join(out, "right.webm")}`);
