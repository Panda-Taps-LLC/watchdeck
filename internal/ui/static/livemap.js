// The live lane map (Plan 04 Task 11): one dark lane per live session on the
// Sessions page, its last 40 calls as glyphs flowing right with "now" at the
// right edge. A glyph's fill is the call's outcome (allow, ask, deny, not
// checked) and its icon says who decided (authorityGlyph), so colour never
// carries the meaning alone; its tooltip is "tool · who decided".
//
// Lanes: exactly the rows the page hands to setSessions(), which come from
// the catalog's lifecycle state (GET /api/sessions?state=live). The ticks
// view only supplies the glyphs; liveness and the header's "last call" come
// from the row (its state and last_ts), never from the ticks. The right edge
// is the client clock: a 10-minute window ending now, older calls clamped to
// the left edge.
//
// Data: GET /api/sessions/<id>/map?view=ticks per lane, through api.fetch
// (bearer header, never a token in a URL) with If-None-Match: a 304 leaves
// the lane as drawn. One scheduler polls the lanes that are due: the first
// six lanes every 2 s, lanes beyond six (shown after "N more") every 15 s;
// a lane whose poll fails (404, any other error status, a body that is not
// JSON, a network error) waits 15 s. A 304 only moves the glyphs along the
// clock. The scheduler stops while the page is hidden, on destroy(), and for
// good once the token is rejected (401: app.js has locked the page).
//
// CSP: DOM through h() and createElementNS; positions are SVG attributes
// (x as a percentage of the lane), never a style attribute.
import { api, h, icon, fmt, replace, ApiError } from "./app.js";
import { COPY, authorityGlyph, authorityLabel } from "./copy.js";
import { svgEl } from "./canvas.js";

const L = COPY.sessions.lanes;
const MAX_TICKS = 40;
const POLLED = 6; // lanes shown and polled fast before "N more"
const FAST_MS = 2000;
const SLOW_MS = 15000;
const SCHED_MS = 500; // how often the scheduler looks for due lanes
const WINDOW_MS = 10 * 60 * 1000; // the lane's width in time; older calls clamp to the left edge
const TRACK_H = 30;
const MID = TRACK_H / 2;
const DOT_R = 8;
const ICON = 10;

/** outcome(policy): the CSS class of a glyph's fill; unknown reads as not checked. */
function outcome(policy) {
  return policy === "allow" || policy === "ask" || policy === "deny" ? policy : "none";
}

function tsOf(v) {
  const t = Date.parse(v || "");
  return Number.isNaN(t) ? null : t;
}

/**
 * mountLiveMap(root, ctx): the lane map into root. Returns
 * {setSessions(rows, lastEnded), destroy()}: rows are the live session rows
 * of GET /api/sessions (newest first); lastEnded is the newest non-live
 * row's last_ts, which dates the sentence shown while nothing is live.
 */
export function mountLiveMap(root, ctx) {
  void ctx; // the page context; lanes navigate through their own links
  let alive = true;
  let rows = [];
  let lastEnded = "";
  let loaded = false;
  let expanded = false;
  let timer = null;
  let lockedOut = false; // a 401: the page is locked, nothing polls again
  const lanes = new Map(); // id -> lane state

  const list = h("div", { class: "lm-lanes" });
  const more = h("button", { type: "button", class: "lm-more", hidden: true, "aria-expanded": "false", on: { click: toggleMore } });
  const axis = h("div", { class: "lm-axis", "aria-hidden": "true" }, h("span", null, L.edge), h("span", null, L.now));
  const none = h("p", { class: "lm-none", role: "status" });
  const box = h("div", { class: "lm", role: "group", "aria-label": L.label, hidden: true }, list, axis, more, none);
  replace(root, box);

  function toggleMore() {
    expanded = !expanded;
    render();
    schedule();
  }

  function pathFor(row) {
    let p = `/api/sessions/${encodeURIComponent(row.id)}/map?view=ticks`;
    // The session's own project: a dashboard started without a cwd (auto or
    // service mode) finds the transcript only through it (map.js does the same).
    if (row.project) p += "&project=" + encodeURIComponent(row.project);
    return p;
  }

  function newLane(row) {
    const head = h("span", { class: "lm-head" });
    const track = svgEl("svg", { class: "lm-track", width: "100%", height: TRACK_H, "aria-hidden": "true", focusable: "false" });
    const link = h("a", { class: "lm-lane", href: "#/sessions/" + encodeURIComponent(row.id) }, head, track);
    return { id: row.id, row, path: pathFor(row), etag: null, ticks: [], glyphs: [], index: 0, nextAt: 0, busy: false, ctl: null, link, head, track };
  }

  function dropLane(lane) {
    if (lane.ctl) lane.ctl.abort();
    lanes.delete(lane.id);
  }

  /** drawHead(lane): "project · N agents · last call <ago>" and the link's name. */
  function drawHead(lane) {
    const r = lane.row;
    const name = r.project_name || r.project || String(r.id).slice(0, 8);
    const agents = 1 + (Number(r.subagents) || 0);
    const last = r.last_ts || ""; // the catalog row only: the same "last" the table shows
    lane.head.textContent = last ? L.head(name, agents, fmt.ago(last)) : L.headIdle(name, agents);
    lane.head.title = r.project || "";
    lane.link.setAttribute("aria-label", L.laneLabel(name, agents, lane.ticks.length));
  }

  /** xOf(at, now): the glyph's x as a percentage; now is the right edge, older than the window clamps left. */
  function xOf(at, now) {
    const p = Math.min(1, Math.max(0, 1 - (now - at) / WINDOW_MS));
    return `${(p * 100).toFixed(3)}%`;
  }

  /** placeGlyphs(lane): move the drawn glyphs along the clock without rebuilding them (an open tooltip stays). */
  function placeGlyphs(lane) {
    const now = Date.now();
    for (const [g, at] of lane.glyphs) g.setAttribute("x", xOf(at, now));
  }

  /** drawTrack(lane): the minute grid and one glyph per tick, x from ts against the clock. */
  function drawTrack(lane) {
    const t = lane.track;
    t.replaceChildren();
    for (let i = 1; i < 10; i++) t.append(svgEl("line", { class: "lm-grid", x1: `${i * 10}%`, x2: `${i * 10}%`, y1: 4, y2: TRACK_H - 4 }));
    t.append(svgEl("line", { class: "lm-base", x1: "0", x2: "100%", y1: MID, y2: MID }));
    t.append(svgEl("line", { class: "lm-now", x1: "100%", x2: "100%", y1: 2, y2: TRACK_H - 2 }));
    const now = Date.now();
    lane.glyphs = [];
    for (const tick of lane.ticks) {
      const at = tsOf(tick.ts);
      if (at === null) continue;
      const g = svgEl("svg", { class: `lm-tick ${outcome(tick.policy)}`, x: xOf(at, now), y: 0, width: 1, height: TRACK_H, overflow: "visible" });
      const title = svgEl("title");
      title.textContent = L.tick(tick.tool || "", authorityLabel(tick.authority));
      const glyph = icon(authorityGlyph(tick.authority), ICON);
      glyph.setAttribute("x", String(-ICON / 2));
      glyph.setAttribute("y", String(MID - ICON / 2));
      glyph.setAttribute("class", "lm-ico");
      g.append(title, svgEl("circle", { class: "lm-dot", cx: 0, cy: MID, r: DOT_R }), glyph);
      t.append(g);
      lane.glyphs.push([g, at]);
    }
  }

  function cadence(lane) {
    return lane.index < POLLED ? FAST_MS : SLOW_MS;
  }

  async function poll(lane) {
    lane.busy = true;
    lane.nextAt = Date.now() + cadence(lane); // the cadence counts from the request's start
    const ctl = new AbortController();
    lane.ctl = ctl;
    const headers = {};
    if (lane.etag) headers["If-None-Match"] = lane.etag;
    try {
      const res = await api.fetch(lane.path, { method: "GET", headers, signal: ctl.signal });
      if (!alive || lanes.get(lane.id) !== lane) return;
      if (res.status === 304) {
        // unchanged: the glyphs only move along the clock
        placeGlyphs(lane);
      } else if (res.ok) {
        const body = await res.json(); // not JSON: throws, and the catch backs off
        if (!alive || lanes.get(lane.id) !== lane) return;
        lane.etag = res.headers.get("ETag") || null;
        const ticks = ((body && body.ticks) || []).slice();
        ticks.sort((a, b) => (tsOf(a.ts) ?? 0) - (tsOf(b.ts) ?? 0));
        lane.ticks = ticks.slice(-MAX_TICKS);
        drawTrack(lane);
      } else {
        lane.nextAt = Date.now() + SLOW_MS;
        if (res.status === 404) {
          // no transcript or activity yet: an empty lane
          lane.etag = null;
          lane.ticks = [];
          drawTrack(lane);
        }
        // any other status: the lane keeps what it had
      }
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) {
        // app.js cleared the token and locked the page: stop every lane for good
        lockedOut = true;
        schedule();
      } else if (!(e && e.name === "AbortError")) {
        lane.nextAt = Date.now() + SLOW_MS; // offline or a bad body: the lane keeps what it had
      }
    } finally {
      if (lane.ctl === ctl) lane.ctl = null;
      lane.busy = false;
      if (alive && lanes.get(lane.id) === lane) drawHead(lane);
    }
  }

  function due() {
    if (!alive || lockedOut || document.visibilityState === "hidden") return;
    const now = Date.now();
    for (const lane of lanes.values()) if (!lane.busy && lane.nextAt <= now) poll(lane);
  }

  /** schedule(): the scheduler runs while lanes exist and the page is visible. */
  function schedule() {
    const want = alive && !lockedOut && lanes.size > 0 && document.visibilityState !== "hidden";
    if (want && !timer) timer = setInterval(due, SCHED_MS);
    if (!want && timer) {
      clearInterval(timer);
      timer = null;
    }
    if (want) due();
  }

  function onVisibility() {
    if (document.visibilityState !== "hidden") for (const lane of lanes.values()) lane.nextAt = 0; // catch up at once
    schedule();
  }

  function render() {
    if (!loaded) return;
    box.hidden = false;
    if (!rows.length) {
      for (const lane of [...lanes.values()]) dropLane(lane);
      expanded = false;
      list.replaceChildren();
      list.hidden = true;
      axis.hidden = true;
      more.hidden = true;
      none.hidden = false;
      none.textContent = lastEnded ? COPY.sessions.noLive(fmt.ago(lastEnded)) : COPY.sessions.noLiveEver;
      box.classList.add("empty");
      return;
    }
    box.classList.remove("empty");
    none.hidden = true;
    none.textContent = "";
    list.hidden = false;
    axis.hidden = false;
    if (rows.length <= POLLED) expanded = false;
    const shown = expanded ? rows : rows.slice(0, POLLED);
    const keep = new Set(shown.map((r) => r.id));
    for (const lane of [...lanes.values()]) if (!keep.has(lane.id)) dropLane(lane);
    const els = [];
    shown.forEach((row, i) => {
      let lane = lanes.get(row.id);
      if (!lane) {
        lane = newLane(row);
        lanes.set(row.id, lane);
        drawTrack(lane);
      } else {
        const path = pathFor(row);
        if (path !== lane.path) {
          lane.path = path;
          lane.etag = null;
          lane.nextAt = 0;
        }
        lane.row = row;
      }
      if (lane.index >= POLLED && i < POLLED) lane.nextAt = 0; // moved up into the fast lanes
      lane.index = i;
      drawHead(lane);
      els.push(lane.link);
    });
    // Only a changed set or order of lanes touches the DOM, so a focused lane
    // and an open tooltip survive a refresh of the list.
    const cur = list.children;
    if (cur.length !== els.length || els.some((el, i) => cur[i] !== el)) list.replaceChildren(...els);
    const hiddenCount = rows.length - POLLED;
    more.hidden = hiddenCount <= 0;
    if (hiddenCount > 0) {
      more.textContent = expanded ? L.fewer : L.more(hiddenCount);
      more.setAttribute("aria-label", expanded ? L.fewer : L.moreLabel(hiddenCount));
      more.setAttribute("aria-expanded", expanded ? "true" : "false");
    }
  }

  document.addEventListener("visibilitychange", onVisibility);

  return {
    setSessions(next, ended) {
      if (!alive) return;
      rows = (next || []).filter((r) => r && r.id);
      lastEnded = ended || "";
      loaded = true;
      render();
      schedule();
    },
    destroy() {
      alive = false;
      if (timer) clearInterval(timer);
      timer = null;
      for (const lane of [...lanes.values()]) dropLane(lane);
      document.removeEventListener("visibilitychange", onVisibility);
      root.replaceChildren();
    },
  };
}
