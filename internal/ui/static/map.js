// The one-session map (Plan 04 Task 10): the Sessions page mounts it under
// #/sessions/<id> (topology) and #/sessions/<id>/timeline.
//
// map.js owns the shell: the route and its query (a= who decided, n= the
// selected node), data fetching with ETag polling, the header (view toggle,
// the who-decided chips, totals), banners, the tick strip, the selection
// card and the side cards. canvas.js holds the drawing kit and the viewport
// (zoom, pan, drag and its storage, the minimap, replay, canvas keys);
// timeline.js and topology.js draw through the kit (DESIGN "The agent map").
//
// Who decided each call (the server's authority word) is shown as a glyph
// and a word from copy.js, never by colour alone; the outcome (allow, ask,
// denied) keeps its colour. Every on-screen string comes from COPY.map.
//
// CSP (default-src 'none'; script-src 'self'; style-src 'self'): DOM is built
// with h()/createElementNS; positions and sizes go through CSSOM.
import { api, store, navigate, fmt, parseRoute, h, icon, confirmDialog, toast, ApiError } from "./app.js";
import { COPY, AUTHORITY_ALL, authorityLabel, authorityGlyph } from "./copy.js";
import { makeKit, makeCanvas, symbolDefs, svgEl, useSym, cls, num, KIND_WORD, ZOOM_STEP } from "./canvas.js";
import * as topology from "./topology.js";
import * as timeline from "./timeline.js";

const M = COPY.map;
const POLL_LIVE_MS = 2000;
const POLL_IDLE_MS = 15000;

// ---------------------------------------------------------------- who decided

/**
 * GROUPS: one chip per authority label ("Auto check" covers two words), in
 * COPY.map.chipOrder; a label missing from that list goes last, in the
 * server's order. Each group is {label, words, glyph}.
 */
const GROUPS = (() => {
  const by = new Map();
  for (const w of AUTHORITY_ALL) {
    const label = authorityLabel(w);
    if (!by.has(label)) by.set(label, []);
    by.get(label).push(w);
  }
  const rank = (label) => {
    const i = M.chipOrder.indexOf(label);
    return i < 0 ? M.chipOrder.length : i;
  };
  return [...by.entries()].sort((a, b) => rank(a[0]) - rank(b[0])).map(([label, words]) => ({ label, words, glyph: authorityGlyph(words[0]) }));
})();

/**
 * contentBounds(stage, fallback): the box fit frames in the timeline: the
 * drawn content (event nodes and their labels, the lane headers and the
 * time labels), measured in canvas units with the stage's transform off,
 * plus CONTENT_PAD. The server's canvas is at least 1000 × 720, so a short
 * session fitted to all of it sat small in the top-left corner (Plan 05
 * Task 6). Nothing measurable (hidden, empty) → fallback.
 */
const CONTENT_PAD = 12;
function contentBounds(stage, fallback) {
  const prev = stage.style.transform;
  stage.style.transform = "none";
  const o = stage.getBoundingClientRect();
  let x0 = Infinity;
  let y0 = Infinity;
  let x1 = -Infinity;
  let y1 = -Infinity;
  for (const el of stage.querySelectorAll(".nodes .node, .nodes .lab, .nodes .decor > *")) {
    const r = el.getBoundingClientRect();
    if (!r.width && !r.height) continue;
    x0 = Math.min(x0, r.left - o.left);
    y0 = Math.min(y0, r.top - o.top);
    x1 = Math.max(x1, r.right - o.left);
    y1 = Math.max(y1, r.bottom - o.top);
  }
  stage.style.transform = prev;
  if (!(x1 > x0 && y1 > y0)) return fallback;
  return { x: x0 - CONTENT_PAD, y: y0 - CONTENT_PAD, w: x1 - x0 + 2 * CONTENT_PAD, h: y1 - y0 + 2 * CONTENT_PAD };
}

/** parseAuth(a): the a= list as known words in the server's order; absent, empty or all unknown → all nine. */
function parseAuth(a) {
  if (a === undefined || a === null) return AUTHORITY_ALL.slice();
  const want = new Set(String(a).split(",").map((s) => s.trim()));
  const out = AUTHORITY_ALL.filter((w) => want.has(w));
  return out.length ? out : AUTHORITY_ALL.slice();
}

function isAll(auth) {
  return !auth || auth.length >= AUTHORITY_ALL.length;
}

function authKey(auth) {
  return isAll(auth) ? "all" : auth.join(",");
}

/** whoDecided(word): the glyph and the word for one authority, as inline content. */
function whoDecided(word, size = 13) {
  return h("span", { class: "auth" }, icon(authorityGlyph(word), size), authorityLabel(word));
}

// ---------------------------------------------------------------- route

// encodeHash(s): a route segment or query value, with ":" and "," readable
// (the same rule as app.js's legacy redirects).
function encodeHash(s) {
  return encodeURIComponent(s).replace(/%3A/gi, ":").replace(/%2C/gi, ",");
}

function routeOf(session, view, query) {
  const q = query || {};
  return { view: view === "timeline" ? "timeline" : "topology", session: session || null, auth: parseAuth(q.a), n: q.n || null };
}

/** readRoute(): {view, session, auth, n} from "#/sessions/<id>[/timeline]?a=&n=". */
export function readRoute(hash = location.hash) {
  const r = parseRoute(hash);
  return routeOf(r.segments[0], r.segments[1], r.query);
}

/** routeHash(view, session, authorities, n): the map's hash; a= only when fewer than all nine words are on. */
export function routeHash(view, session, authorities, n) {
  if (!session) return "#/sessions";
  const q = [];
  if (!isAll(authorities)) q.push("a=" + authorities.join(","));
  if (n) q.push("n=" + encodeHash(n));
  return "#/sessions/" + encodeHash(session) + (view === "timeline" ? "/timeline" : "") + (q.length ? "?" + q.join("&") : "");
}

/**
 * timelineHash(session, toolUseId, skill): a deep link to one call in the
 * timeline, selecting the server's event node "ev:<tool_use_id>" or, for a
 * call that ran a skill, "ev:<tool_use_id>:skill:<skill>".
 */
export function timelineHash(session, toolUseId, skill) {
  const n = toolUseId ? `ev:${toolUseId}${skill ? ":skill:" + skill : ""}` : null;
  return routeHash("timeline", session, null, n);
}

/** API path for a skill; "*" must be sent as %2A (same rule as pages.js). */
function skillPath(name) {
  return "/api/skills/" + encodeURIComponent(name).replace(/\*/g, "%2A");
}

function basename(p) {
  const s = String(p || "").replace(/\/+$/, "");
  return s.slice(s.lastIndexOf("/") + 1) || s;
}

// ---------------------------------------------------------------- evidence and badge words (Spec B §1c, §3.3)

function toneTag(tone) {
  const t = cls(tone || "none");
  return t === "allow" ? "ok" : ["ok", "ask", "deny", "none"].includes(t) ? t : "none";
}

/** outcomeWord(policy): "allow" | "ask" | "denied", or null when watchdeck's evidence has none. */
function outcomeWord(policy) {
  const t = toneTag(policy);
  return t === "ok" ? M.outcome.allow : t === "ask" ? M.outcome.ask : t === "deny" ? M.outcome.denied : null;
}

function grantWhat(edit) {
  const parts = [];
  for (const [k, v] of Object.entries(edit)) {
    if (k === "network") parts.push(M.grant.network(v));
    else if (k === "addWrite" || k === "write") parts.push(M.grant.write([].concat(v).join(", ")));
    else if (k === "caches") parts.push(v ? M.grant.caches : M.grant.noCaches);
    else if (k === "addEnv" || k === "env") parts.push(M.grant.env([].concat(v).join(", ")));
    else parts.push(M.grant.other(k, typeof v === "string" ? v : JSON.stringify(v)));
  }
  return parts.join(", ") || M.grant.fallback;
}

// ---------------------------------------------------------------- the view

/**
 * mapView(ctx): one session's map, mounted by the Sessions page into a root
 * it owns. mount(root, sessionId, view, query) builds it; update(sessionId,
 * view, query) follows a hash change (view toggle, chips, selection, another
 * session); unmount() stops timers and listeners (the root stays the
 * caller's). view is "timeline" or anything else for the topology; query is
 * parseRoute()'s query object (a=, n=).
 */
export function mapView(ctx) {
  const go = (hash) => ((ctx && ctx.navigate) || navigate)(hash);
  let root = null;
  /** freshState(): per-mount state; mount() replaces st so nothing leaks from an earlier visit. */
  const freshState = (seq = 0) => ({
    view: "topology",
    session: null,
    auth: AUTHORITY_ALL.slice(), // the authority words shown; all nine is no filter
    sel: null,
    graph: null,
    etag: null,
    key: "",
    seq,
    project: null, // the session's project in display form ("~/x"), sent as ?project= so a cwd-less server finds its transcript
    projectName: null,
    projectFor: null, // the session id project belongs to
    error: null,
    scale: 1,
    userZoomed: false,
    tf: { s: 1, tx: 0, ty: 0 }, // stage transform: screen = canvas * s + t
    ctl: null, // topology controller (topology.js), null in the timeline
    bounds: null, // content box in canvas units, for fit and the minimap
    gesture: null, // the pointer gesture in progress: {kind: "drag"|"pan"|"pinch", ...}
    pointers: new Map(), // active pointers on the canvas: id → {x, y}
    parked: null, // a graph that arrived mid-drag, drawn on release
    hover: null, // node id whose neighbourhood is lit
    replay: null, // {k, timer}: replay on, k ticks revealed
    swallow: false, // the next node click follows a drag
    miniOpen: false, // the minimap panel, closed by default
    timer: null,
    unsub: null,
    lastOffset: 0,
    activeTick: null,
    pickedTick: null,
    cardSig: null,
    grantNote: null, // one-shot {skill, what, cmd, path, changed}: the POST answer, shown until the next graph arrives
  });
  let st = freshState();
  const page = {
    nodeEls: new Map(),
    select,
    clear,
    swallowClick() {
      const s = st.swallow;
      st.swallow = false;
      return s;
    },
  };
  const ui = {};
  let cv = null; // makeCanvas(): the viewport, rebuilt on each mount
  const off = []; // [target, type, fn, opts] to remove on unmount

  function listen(target, type, fn, opts) {
    target.addEventListener(type, fn, opts);
    off.push([target, type, fn, opts]);
  }

  // ------------------------------------------------ skeleton

  function build() {
    ui.back = h("a", { class: "btn link small map-back", href: "#/sessions" }, M.back);
    ui.title = h("h1", { class: "h1" }, M.heading);
    ui.seg = h("div", { class: "seg", role: "group", "aria-label": M.viewGroup });
    for (const v of ["topology", "timeline"]) {
      ui.seg.appendChild(
        h(
          "button",
          { type: "button", "aria-pressed": "false", dataset: { view: v }, on: { click: () => v !== st.view && goTo({ view: v, n: crossSel(v) }) } },
          M.views[v],
        ),
      );
    }
    ui.lead = h("span", { class: "lead" });
    ui.totals = h("div", { class: "flow-totals", "aria-label": M.totalsLabel });
    ui.chips = h("div", { class: "auth-chips", role: "group", "aria-label": M.chipsLabel });
    ui.banners = h("div", { class: "flow-banners" });

    ui.cv = h("div", { class: "cv", tabindex: "0" });
    ui.stage = h("div", { class: "stage" });
    ui.cv.appendChild(ui.stage);
    ui.resetBtn = h(
      "button",
      { type: "button", class: "fit", "aria-label": M.canvas.reset, title: M.canvas.resetTitle, disabled: true, on: { click: () => cv.resetLayout() } },
      M.canvas.resetText,
    );
    ui.ctl = h(
      "div",
      { class: "ctl", role: "group", "aria-label": M.canvas.controls },
      h("button", { type: "button", "aria-label": M.canvas.zoomIn, title: M.canvas.zoomInTitle, on: { click: () => cv.zoomBy(ZOOM_STEP) } }, M.canvas.zoomInText),
      h("button", { type: "button", "aria-label": M.canvas.zoomOut, title: M.canvas.zoomOutTitle, on: { click: () => cv.zoomBy(1 / ZOOM_STEP) } }, M.canvas.zoomOutText),
      h("button", { type: "button", class: "fit", "aria-label": M.canvas.fit, title: M.canvas.fitTitle, on: { click: () => cv.fit(true) } }, M.canvas.fitText),
      ui.resetBtn,
    );
    // The minimap stays closed behind this button, shown only while the
    // content overflows the canvas; it opens as a panel beside the controls.
    ui.miniBtn = h(
      "button",
      { type: "button", class: "fit", hidden: true, "aria-expanded": "false", "aria-controls": "flow-minimap", "aria-label": M.canvas.minimap, title: M.canvas.minimapTitle, on: { click: () => cv.setMini(!st.miniOpen, false) } },
      M.canvas.minimapText,
    );
    ui.ctl.appendChild(ui.miniBtn);
    ui.mini = h("div", { class: "minimap", id: "flow-minimap", hidden: true, role: "group", "aria-label": M.canvas.minimapPanel });
    ui.legend = h("div", { class: "cv-legend", "aria-label": M.legend.label });
    ui.box = h("div", { class: "cv-box" }, symbolDefs(), h("div", { class: "cv-wrap" }, ui.cv, ui.ctl, ui.mini), ui.legend);

    ui.ticks = h("div", { class: "ticks", role: "toolbar", "aria-label": M.ticks.label });
    ui.t0 = h("span", { class: "when" });
    ui.t1 = h("span", { class: "when" });
    ui.replayBtn = h("button", { type: "button", class: "pill small", "aria-pressed": "false", on: { click: () => cv.toggleReplay() } }, M.replay.button);
    ui.strip = h("div", { class: "card strip" }, ui.t0, ui.ticks, ui.t1, ui.replayBtn);

    ui.rpPlay = h("button", { type: "button", class: "btn ghost small", on: { click: () => cv.playPause() } }, M.replay.play);
    ui.rpStep = h("button", { type: "button", class: "btn ghost small", "aria-label": M.replay.stepLabel, on: { click: () => cv.stepReplay(1) } }, M.replay.step);
    ui.rpRange = h("input", { type: "range", min: "0", max: "0", step: "1", value: "0", "aria-label": M.replay.position, on: { input: (e) => cv.setReplay(Number(e.target.value)) } });
    ui.rpText = h("span", { class: "rp-text", "aria-live": "polite" });
    ui.replay = h("div", { class: "card replay", hidden: true, role: "group", "aria-label": M.replay.label }, ui.rpPlay, ui.rpStep, ui.rpRange, ui.rpText);

    ui.main = h("section", { class: "flow-main", "aria-label": M.heading }, ui.box, ui.strip, ui.replay);
    ui.card = h("section", { class: "card map-card", "aria-live": "polite", "aria-label": M.card.label });
    ui.extra = h("div", { class: "stack" });
    ui.aside = h("aside", { class: "flow-aside", "aria-label": M.card.aside }, ui.card, ui.extra);
    ui.body = h("div", { class: "flow-split" }, ui.main, ui.aside);
    ui.empty = h("div", { class: "card empty", hidden: true });

    root.append(h("div", { class: "flow-head" }, ui.back, ui.title, ui.seg, ui.lead, ui.totals), ui.chips, ui.banners, ui.empty, ui.body);

    cv = makeCanvas(ui, st, { draw, applyHover, markTicks, select, clear, reveal, alive: () => !!root, page });
    listen(ui.stage, "pointerover", (e) => hoverFrom(e.target));
    listen(ui.stage, "pointerout", (e) => {
      if (!e.relatedTarget || !ui.stage.contains(e.relatedTarget)) hoverFrom(null);
      else hoverFrom(e.relatedTarget);
    });
    listen(ui.stage, "focusin", (e) => hoverFrom(e.target));
    listen(ui.stage, "focusout", (e) => {
      if (!e.relatedTarget || !ui.stage.contains(e.relatedTarget)) hoverFrom(null);
    });
    listen(window, "resize", () => cv.sizeCanvas());
    listen(ui.ticks, "keydown", onTickKey);
    listen(document, "keydown", (e) => cv.onDocKey(e));
    listen(document, "visibilitychange", () => {
      if (!document.hidden) poll(false);
    });
  }

  // ------------------------------------------------ navigation

  function goTo({ view = st.view, session = st.session, auth = st.auth, n = st.sel } = {}) {
    go(routeHash(view, session, auth, n));
  }

  /** crossSel(view): carry the selection to the other view when an equivalent node exists there. */
  function crossSel(view) {
    if (view === st.view || !st.sel || !st.graph) return null;
    const n = (st.graph.nodes || []).find((x) => x.id === st.sel);
    return n ? equivalentId(n, view) : null;
  }

  function equivalentId(n, view) {
    if (view === "topology") {
      if (n.kind === "skill") return "skill:" + n.label;
      if (n.kind === "sandbox") return "sandbox";
      if (n.kind === "tool") return "tool:" + n.label;
      if (n.kind === "you") return "you";
      return null;
    }
    return n.id; // resolved against the timeline's events by resolveSel
  }

  function resolveSel(id) {
    if (!id || !st.graph) return null;
    const nodes = st.graph.nodes || [];
    if (nodes.some((x) => x.id === id)) return id;
    if (isEdge(id)) return id;
    if (st.view !== "timeline") return null;
    // A deep link to "ev:<id>" whose call also ran a skill: its call event is "ev:<id>:tool".
    if (/^ev:[^:]+$/.test(id) && nodes.some((x) => x.id === id + ":tool")) return id + ":tool";
    const m = /^(skill|tool|sandbox|you)(?::(.*))?$/.exec(id);
    if (!m) return null;
    const kind = m[1];
    const label = m[2];
    const hit = nodes.find((x) => x.kind === kind && (label === undefined || x.label === label) && (kind !== "tool" || x.tone !== "none")) || nodes.find((x) => x.kind === kind && (label === undefined || x.label === label));
    return hit ? hit.id : null;
  }

  async function apply(r, initial) {
    const changed = initial || r.view !== st.view || r.session !== st.session || authKey(r.auth) !== authKey(st.auth);
    st.view = r.view;
    st.auth = r.auth;
    st.session = r.session;
    for (const b of ui.seg.children) b.setAttribute("aria-pressed", String(b.dataset.view === st.view));
    renderChips();
    ui.lead.textContent = M.lead[st.view];
    if (st.projectFor !== st.session) await resolveProject();
    if (!root || st.session !== r.session) return;
    ui.title.textContent = st.projectName ? M.headingFor(st.projectName) : M.heading;
    ui.cv.setAttribute("aria-label", M.canvas.label[st.view]);
    ui.replayBtn.hidden = st.view !== "topology";
    ui.resetBtn.hidden = st.view !== "topology";
    if (changed) {
      cv.stopReplay();
      st.sel = r.n;
      st.graph = null;
      st.etag = null;
      st.userZoomed = false;
      await poll(true);
    } else if (r.n !== st.sel) {
      select(r.n, { from: "route" });
    }
  }

  // ------------------------------------------------ chips

  /** renderChips(): one toggle per authority label; the last one on cannot be turned off (no chips would show nothing). */
  function renderChips() {
    const on = new Set(st.auth);
    const isOn = (g) => g.words.some((w) => on.has(w));
    const lit = GROUPS.filter(isOn).length;
    const act = document.activeElement;
    const focused = act && ui.chips.contains(act) && act.dataset ? act.dataset.chip : null;
    const btns = GROUPS.map((g) => {
      const pressed = isOn(g);
      const last = pressed && lit === 1;
      return h(
        "button",
        {
          type: "button",
          class: "pill small chip",
          "aria-pressed": String(pressed),
          "aria-disabled": last ? "true" : null,
          title: last ? M.chipLast : pressed ? M.chipHide(g.label) : M.chipShow(g.label),
          dataset: { chip: g.label },
          on: { click: () => toggleGroup(g) },
        },
        icon(g.glyph, 13),
        g.label,
      );
    });
    const all = isAll(st.auth) ? null : h("button", { type: "button", class: "btn link small", dataset: { chip: "" }, on: { click: () => goTo({ auth: AUTHORITY_ALL.slice() }) } }, M.chipsAll);
    ui.chips.replaceChildren(h("span", { class: "lbl" }, M.chipsTitle), ...btns, ...(all ? [all] : []));
    if (focused !== null) {
      // The focused control is redrawn: focus its new copy. "Show all" goes
      // away once it has worked, so focus then moves to the first chip,
      // never to the body.
      const again = [...ui.chips.querySelectorAll("button")].find((b) => b.dataset.chip === focused) || ui.chips.querySelector("button.chip");
      if (again) again.focus({ preventScroll: true });
    }
  }

  function toggleGroup(g) {
    const on = new Set(st.auth);
    const pressed = g.words.some((w) => on.has(w));
    for (const w of g.words) {
      if (pressed) on.delete(w);
      else on.add(w);
    }
    const next = AUTHORITY_ALL.filter((w) => on.has(w));
    if (!next.length) return; // the last chip stays on
    goTo({ auth: next });
  }

  // ------------------------------------------------ session

  /** resolveProject(): the session's project, from GET /api/sessions/{id}. */
  async function resolveProject() {
    const id = st.session;
    let d = null;
    try {
      d = await api.get(`/api/sessions/${encodeURIComponent(id)}`);
    } catch (_) {
      d = null; // unknown here: the map route answers 404 and the page says so
    }
    if (st.session !== id) return;
    st.project = (d && d.project) || null;
    st.projectName = (d && (d.project_name || basename(d.project))) || null;
    st.projectFor = id;
  }

  function showGone() {
    ui.body.hidden = true;
    ui.empty.hidden = false;
    ui.totals.replaceChildren();
    ui.banners.replaceChildren();
    ui.empty.replaceChildren(icon("warn", 28), h("p", { class: "ink" }, M.gone), h("p", { class: "muted small" }, M.goneHint), h("a", { class: "btn ghost small", href: "#/sessions" }, M.allSessions));
  }

  // ------------------------------------------------ fetching

  async function poll(force) {
    clearTimeout(st.timer);
    st.timer = null;
    if (!root || !st.session) return;
    if (document.hidden && !force) return schedule();
    const key = `${st.session}|${st.view}|${authKey(st.auth)}`;
    if (key !== st.key) {
      st.key = key;
      st.etag = null;
    }
    const seq = ++st.seq;
    let path = `/api/sessions/${encodeURIComponent(st.session)}/map?view=${st.view}`;
    // The who-decided filter: sent only when some words are off, so the
    // unfiltered map keeps one ETag.
    if (!isAll(st.auth)) path += "&authority=" + encodeURIComponent(st.auth.join(","));
    // The session's own project: a dashboard started without a cwd (auto or
    // service mode) finds the transcript only through it.
    if (st.project && st.projectFor === st.session) path += "&project=" + encodeURIComponent(st.project);
    const headers = {};
    if (st.etag && !force) headers["If-None-Match"] = st.etag;
    try {
      const res = await api.fetch(path, { method: "GET", headers });
      if (seq !== st.seq || !root) return;
      if (res.status === 304) {
        st.error = null;
      } else if (!res.ok) {
        let msg = `${res.status} ${res.statusText}`.trim();
        try {
          const b = await res.json();
          if (b && b.error) msg = b.error;
        } catch (_) {
          /* not JSON */
        }
        if (res.status === 404) {
          st.graph = null;
          st.error = null;
          showGone();
          return; // nothing to poll for an unknown session
        }
        st.error = M.loadFailed(msg);
        renderBanners();
      } else {
        const g = await res.json();
        if (seq !== st.seq || !root) return;
        const before = st.graph;
        st.grantNote = null; // the card now renders only from this graph
        st.etag = res.headers.get("ETag") || (g && g.etag ? `"${g.etag}"` : null);
        st.error = null;
        if (st.gesture && st.gesture.kind === "drag") {
          st.parked = g; // redrawing now would replace the node under the pointer; drawn on release
        } else {
          st.graph = g;
          draw(!!before);
        }
      }
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) return;
      if (seq !== st.seq || !root) return;
      st.error = M.loadFailed(e.message || e);
      renderBanners();
    }
    schedule();
  }

  function schedule() {
    clearTimeout(st.timer);
    if (!root) return;
    const live = st.graph && st.graph.session && st.graph.session.live;
    st.timer = setTimeout(() => poll(false), live ? POLL_LIVE_MS : POLL_IDLE_MS);
  }

  function onActivity(event, _store, payload) {
    if (event === "event" && root && payload) {
      // Nudges from GET /api/events: new activity for this session.
      if (payload.name === "activity" && st.session && payload.data && Array.isArray(payload.data.sessions) && payload.data.sessions.includes(st.session)) poll(false);
      return;
    }
    if (event !== "activity" || !root || !st.session) return;
    const recs = store.activity.records || [];
    let hit = false;
    let max = st.lastOffset;
    for (const r of recs) {
      const o = num(r.offset, -1);
      if (o > max) max = o;
      if (o > st.lastOffset && r.session_id === st.session) hit = true;
    }
    st.lastOffset = max;
    if (hit) poll(false);
  }

  // ------------------------------------------------ drawing

  function draw(isUpdate) {
    const g = st.graph;
    const act = document.activeElement;
    const focusNode = act && ui.stage.contains(act) && act.dataset ? act.dataset.id : null;
    const focusTick = act && ui.ticks.contains(act) && act.dataset ? act.dataset.id : null;
    ui.body.hidden = false;
    ui.empty.hidden = true;
    renderTotals();
    renderBanners();
    page.nodeEls = new Map();
    ui.stage.replaceChildren();
    ui.stage.className = `stage view-${st.view}${g.session && g.session.live ? " live" : ""}`;
    const kit = makeKit(ui.stage, g, page);
    st.W = kit.W;
    st.H = kit.H;
    if (st.view === "topology") {
      st.ctl = topology.render(g, kit, { saved: cv.loadLayout(), onMove: () => cv.renderMini() });
      st.bounds = st.ctl.bounds();
      ui.resetBtn.disabled = !cv.hasLayout();
    } else {
      st.ctl = null;
      timeline.render(g, kit);
      st.bounds = contentBounds(ui.stage, { x: 0, y: 0, w: kit.W, h: kit.H });
    }
    renderLegend();
    renderTicks();
    cv.sizeCanvas();
    if (!isUpdate || !st.userZoomed) cv.fit(false);
    else cv.applyTransform();
    applyHover();
    if (st.replay) cv.setReplay(st.replay.k, true);
    const resolved = resolveSel(st.sel);
    if (st.sel && resolved !== st.sel) {
      st.sel = resolved;
      writeSel();
    }
    markSelection();
    renderCardIfChanged();
    renderExtra();
    if (focusNode && page.nodeEls.has(focusNode)) page.nodeEls.get(focusNode).focus({ preventScroll: true });
    if (!draw.fontsHooked && document.fonts && document.fonts.status !== "loaded") {
      // Labels were measured with fallback metrics; lay out again once the page's fonts are in.
      draw.fontsHooked = true;
      document.fonts.ready.then(() => {
        if (root && st.graph) draw(true);
      });
    }
    if (focusTick) {
      const tb = [...ui.ticks.children].find((b) => b.dataset.id === focusTick);
      if (tb) tb.focus({ preventScroll: true });
    }
    if (isUpdate) {
      const live = ui.stage.querySelector(".node[aria-current='true']");
      if (live) {
        live.classList.add("flash");
        setTimeout(() => live.classList.remove("flash"), 950);
      }
    }
  }

  /**
   * renderTotals(): the topology's structure (agents, models, tools, MCP
   * servers, skills, denials) or the timeline's outcomes (allow, ask,
   * denied), then calls per who decided ("Sandbox 2") from
   * totals.by_authority, then "showing N calls" (graph.shown) while the
   * chips filter.
   */
  function renderTotals() {
    const g = st.graph || {};
    const t = g.totals || {};
    const by = t.by_authority && typeof t.by_authority === "object" ? t.by_authority : {};
    const tags = [];
    // refused: every call refused, whoever refused it. blocked_calls is
    // the deny rule, the auto-mode check and watchdeck's hook (also read
    // only from the transcript); the sandbox's refusals are the calls it
    // decided plus runs no call claims (denials minus the policy deny
    // count). So a transcript-only session never reads "denied 0" beside
    // "Deny rule 2" (Plan 05 Task 6).
    const sandboxCalls = Object.prototype.hasOwnProperty.call(by, "sandbox") ? num(by.sandbox) : 0;
    const refused = num(t.blocked_calls) + sandboxCalls + Math.max(0, num(t.denials) - num(t.deny));
    if (st.view === "topology") {
      tags.push(h("span", { class: "tag" }, M.count.agents(num(t.agents))));
      tags.push(h("span", { class: "tag" }, M.count.models(num(t.models))));
      tags.push(h("span", { class: "tag" }, M.count.tools(num(t.tools))));
      if (num(t.mcp)) tags.push(h("span", { class: "tag" }, M.count.mcp(num(t.mcp))));
      tags.push(h("span", { class: "tag" }, M.count.skills(num(t.skills))));
      tags.push(h("span", { class: refused ? "tag deny" : "tag" }, M.count.denials(refused)));
    } else if (num(t.allow) || num(t.ask) || refused) {
      // With all three zero the tags say nothing and are left out.
      tags.push(h("span", { class: "tag ok" }, M.outcomeCount(M.outcome.allow, num(t.allow))));
      tags.push(h("span", { class: "tag ask" }, M.outcomeCount(M.outcome.ask, num(t.ask))));
      tags.push(h("span", { class: "tag deny" }, M.outcomeCount(M.outcome.denied, refused)));
    }
    for (const grp of GROUPS) {
      const n = grp.words.reduce((s, w) => s + (Object.prototype.hasOwnProperty.call(by, w) ? num(by[w]) : 0), 0);
      if (n) tags.push(h("span", { class: "tag auth" }, icon(grp.glyph, 12), M.authCount(grp.label, n)));
    }
    if (!isAll(st.auth)) tags.push(h("span", { class: "tag shown" }, M.showing(num(g.shown))));
    ui.totals.replaceChildren(...tags);
  }

  function renderBanners() {
    const out = [];
    const s = (st.graph && st.graph.session) || {};
    if (st.error) out.push(h("div", { class: "banner deny", role: "alert" }, st.error));
    if (s.no_transcripts) out.push(h("div", { class: "banner" }, M.banner.noTranscripts));
    else if (s.transcript_missing) out.push(h("div", { class: "banner" }, M.banner.missing(s.transcript_path)));
    if (s.truncated) out.push(h("div", { class: "banner" }, M.banner.truncated));
    ui.banners.replaceChildren(...out);
  }

  function renderLegend() {
    const sw = (vb, ...kids) => {
      const s = svgEl("svg", { width: 14, height: 14, viewBox: vb, "aria-hidden": "true", focusable: "false" });
      s.append(...kids);
      return s;
    };
    const item = (svg, text, k) => h("span", { class: `leg node kind-${k}` }, svg, text);
    const L = M.legend;
    ui.legend.replaceChildren(
      item(sw("0 0 44 44", useSym("g-you", { width: 44, height: 44 })), L.you, "you"),
      h("span", { class: "leg node kind-agent role-subagent" }, sw("0 0 60 60", useSym("g-agent-sub", { width: 60, height: 60 })), L.agent),
      item(sw("0 0 44 44", useSym("g-model", { width: 44, height: 44 })), L.model, "model"),
      item(sw("0 0 54 54", useSym("g-tool", { width: 54, height: 54 })), L.tool, "tool"),
      item(sw("0 0 60 60", useSym("g-mcp", { width: 60, height: 60 })), L.mcp, "mcp"),
      h("span", { class: "leg node kind-skill tone-ask" }, sw("0 0 24 24", useSym("g-skill-outer", { width: 24, height: 24 }), useSym("g-skill-inner", { width: 24, height: 24 })), L.skill),
      h("span", { class: "leg node kind-sandbox tone-deny" }, sw("0 0 92 92", useSym("g-sandbox", { width: 92, height: 92 })), L.sandbox),
      h("span", { class: "leg" }, sw("0 0 26 26", useSym("g-cut", { width: 26, height: 26 })), L.cut),
      h("span", { class: "leg" }, h("span", { class: "bar", "aria-hidden": "true" }), L.width),
      h("span", { class: "leg leg-title" }, L.decided),
      ...GROUPS.map((g) => h("span", { class: "leg auth" }, icon(g.glyph, 13), g.label)),
    );
  }

  // ------------------------------------------------ tick strip

  function tickNode(t) {
    const nodes = (st.graph && st.graph.nodes) || [];
    if (t.node) return t.node;
    if (st.view === "timeline") {
      const ev = nodes.filter((n) => n.tool_use_id === t.id);
      return (ev.find((n) => n.kind === "tool") || ev[0] || {}).id || null;
    }
    const tool = String(t.tool || "");
    const m = /^mcp__(.+?)__(.+)$/.exec(tool);
    const id = m ? "mcp:" + m[1] : "tool:" + tool;
    return nodes.some((n) => n.id === id) ? id : null;
  }

  function renderTicks() {
    const ticks = (st.graph && Array.isArray(st.graph.ticks) && st.graph.ticks) || [];
    const s = (st.graph && st.graph.session) || {};
    const filtered = !isAll(st.auth);
    const shownWords = new Set(st.auth);
    ui.t0.textContent = ticks.length ? fmt.time(ticks[0].ts) : fmt.time(s.started);
    ui.t1.textContent = s.live ? M.ticks.now : ticks.length ? fmt.time(ticks[ticks.length - 1].ts) : fmt.time(s.last);
    if (!ticks.find((t) => t.id === st.activeTick)) st.activeTick = ticks.length ? ticks[0].id : null;
    ui.ticks.replaceChildren(
      ...ticks.map((t) => {
        const pol = toneTag(t.policy) === "ok" ? "allow" : cls(t.policy || "none");
        const tool = String(t.tool || "");
        const spawn = tool === "Agent" || tool === "Task";
        const who = t.authority ? authorityLabel(t.authority) : null;
        const hidden = filtered && !spawn && !!t.authority && !shownWords.has(t.authority);
        return h("button", {
          type: "button",
          class: `tick policy-${pol}${spawn ? " spawn" : ""}${hidden ? " filtered" : ""}`,
          title: M.ticks.title(tool, fmt.time(t.ts), who),
          "aria-label": M.ticks.aria(tool, fmt.time(t.ts), spawn, outcomeWord(t.policy), who, hidden),
          "aria-pressed": "false",
          tabindex: t.id === st.activeTick ? "0" : "-1",
          dataset: { id: t.id },
          on: { click: () => pickTick(t) },
        });
      }),
    );
    markTicks(st.pickedTick);
  }

  function pickTick(t) {
    st.activeTick = t.id;
    st.pickedTick = t.id;
    for (const b of ui.ticks.children) b.tabIndex = b.dataset.id === t.id ? 0 : -1;
    const id = tickNode(t);
    for (const el of ui.stage.querySelectorAll(".node.hl")) el.classList.remove("hl");
    if (id) {
      select(id, { from: "tick" });
      if (st.view === "topology" && t.skill) {
        const sk = page.nodeEls.get("skill:" + t.skill);
        if (sk) sk.classList.add("hl");
      }
      reveal(id);
    } else if (t.tool === "Agent" || t.tool === "Task") {
      toast(M.ticks.spawnToast);
    } else {
      toast(M.ticks.noNode(t.tool, !isAll(st.auth)));
    }
    markTicks(t.id);
  }

  function markTicks(id) {
    for (const b of ui.ticks.children) b.setAttribute("aria-pressed", String(!!id && b.dataset.id === id));
  }

  function onTickKey(e) {
    const btns = [...ui.ticks.children];
    const i = btns.indexOf(document.activeElement);
    if (i < 0) return;
    let j = -1;
    if (e.key === "ArrowRight") j = Math.min(btns.length - 1, i + 1);
    else if (e.key === "ArrowLeft") j = Math.max(0, i - 1);
    else if (e.key === "Home") j = 0;
    else if (e.key === "End") j = btns.length - 1;
    if (j < 0) return;
    e.preventDefault();
    for (const b of btns) b.tabIndex = -1;
    btns[j].tabIndex = 0;
    st.activeTick = btns[j].dataset.id;
    btns[j].focus();
  }

  // ------------------------------------------------ selection

  function writeSel() {
    history.replaceState(null, "", routeHash(st.view, st.session, st.auth, st.sel));
  }

  function select(id, opts = {}) {
    const resolved = id ? resolveSel(id) : null;
    st.sel = resolved;
    if (opts.from !== "route") writeSel();
    markSelection();
    renderCard();
  }

  function clear() {
    st.pickedTick = null;
    select(null);
    markTicks();
  }

  function markSelection() {
    for (const [id, el] of page.nodeEls) el.setAttribute("aria-pressed", String(id === st.sel));
    if (st.ctl) st.ctl.mark("sel", isEdge(st.sel) ? { nodes: new Set(), edges: new Set([st.sel]) } : null);
  }

  function isEdge(id) {
    return !!id && !!st.graph && st.view === "topology" && (st.graph.edges || []).some((e) => e.id === id);
  }

  /** nodePos(id): a node's centre in canvas units (the topology's live position, else the server's). */
  function nodePos(id) {
    if (st.ctl && st.ctl.has(id)) return st.ctl.pos(id);
    const n = ((st.graph && st.graph.nodes) || []).find((x) => x.id === id);
    return n ? { x: num(n.x), y: num(n.y) } : null;
  }

  /** reveal(id): pan so the node is in view (keeps zoom). */
  function reveal(id) {
    const p = nodePos(id);
    if (!p) return;
    const { s, tx, ty } = st.tf;
    const cx = p.x * s + tx;
    const cy = p.y * s + ty;
    const vw = ui.cv.clientWidth;
    const vh = ui.cv.clientHeight;
    if (cx < 40 || cx > vw - 40) st.tf.tx += vw / 2 - cx;
    if (cy < 40 || cy > vh - 40) st.tf.ty += vh / 2 - cy;
    cv.applyTransform();
  }

  // ------------------------------------------------ hover neighbourhood

  function hoverFrom(target) {
    const el = target && target.closest ? target.closest(".node") : null;
    const id = el && el.dataset ? el.dataset.id : null;
    if (id === st.hover) return;
    st.hover = id;
    applyHover();
  }

  function applyHover() {
    if (!st.ctl) return;
    const set = st.hover && st.ctl.has(st.hover) && !(st.gesture && st.gesture.kind === "pan") ? st.ctl.neighbours(st.hover) : null;
    ui.stage.classList.toggle("dim", !!set);
    st.ctl.mark("nb", set);
  }

  // ------------------------------------------------ card

  function nodeLabel(id) {
    const n = ((st.graph && st.graph.nodes) || []).find((x) => x.id === id);
    if (n) return n.label || id;
    return String(id || "").replace(/^[a-z]+:/, "");
  }

  /** Re-render the card only when the selected node's data changed, so a poll never steals focus from it. */
  function cardSig() {
    const g = st.graph;
    const n = g && st.sel ? (g.nodes || []).find((x) => x.id === st.sel) || (g.edges || []).find((x) => x.id === st.sel) : null;
    const ticks = n && isEdge(st.sel) ? (g.ticks || []).length : 0;
    return `${st.view}|${st.sel}|${JSON.stringify(n || "")}|${ticks}|${st.grantNote ? 1 : 0}`;
  }

  function renderCardIfChanged() {
    if (cardSig() === st.cardSig) return;
    renderCard();
  }

  function renderCard() {
    const g = st.graph;
    const n = g && st.sel ? (g.nodes || []).find((x) => x.id === st.sel) : null;
    st.cardSig = cardSig();
    ui.card.className = "card map-card";
    if (!n && isEdge(st.sel)) {
      ui.card.replaceChildren(...edgeCard((g.edges || []).find((x) => x.id === st.sel)));
      return;
    }
    if (!n) {
      ui.card.replaceChildren(h("p", { class: "lbl" }, M.card.selection), h("p", { class: "muted" }, M.card.hint[st.view]));
      return;
    }
    const d = n.detail || {};
    const isSkill = !!(d.outcome || d.requested || d.fix || d.grant || n.kind === "skill");
    const tone = isSkill ? toneTag((d.outcome && d.outcome.tone) || n.tone) : toneTag(n.tone);
    if (isSkill && tone !== "none") ui.card.classList.add(`tone-${tone}`);
    const out = [cardHead(n, d, isSkill ? tone : null)];
    if (d.command) out.push(h("div", { class: "code wrap" }, d.command));
    if (isSkill) out.push(...skillBody(n, d));
    else out.push(...genericBody(n, d));
    const conn = connections(n.id);
    if (conn) out.push(conn);
    ui.card.replaceChildren(...out);
  }

  function edgeWord(e) {
    return Object.prototype.hasOwnProperty.call(M.edge, e.kind) ? M.edge[e.kind] : e.kind || M.edge.fallback;
  }

  function edgeName(e) {
    return M.edgeName(nodeLabel(e.from), nodeLabel(e.to));
  }

  /** connections(id): the node's edges as buttons, so an edge's card is reachable without a pointer. */
  function connections(id) {
    if (st.view !== "topology" || !st.graph) return null;
    const es = (st.graph.edges || []).filter((e) => e.from === id || e.to === id);
    if (!es.length) return null;
    return h(
      "div",
      { class: "stack-sm" },
      h("p", { class: "lbl" }, M.card.connections),
      h(
        "div",
        { class: "conn" },
        es.map((e) =>
          h(
            "button",
            { type: "button", class: "btn link small", on: { click: () => select(e.id, { from: "card" }) } },
            edgeName(e),
            h("span", { class: "muted" }, M.edgeMeta(e.label || edgeWord(e), e.count)),
          ),
        ),
      ),
    );
  }

  /** callsBehind(e): the ticks an edge stands for (topology ticks carry agent, node, skill and ran). */
  function callsBehind(e) {
    const ticks = (st.graph && st.graph.ticks) || [];
    const skillOf = (id) => (String(id).startsWith("skill:") ? String(id).slice(6) : null);
    switch (e.kind) {
      case "call":
        return ticks.filter((t) => t.agent === e.from && t.node === e.to);
      case "spawn":
        return ticks.filter((t) => t.node === e.to && (t.tool === "Agent" || t.tool === "Task"));
      case "skill_run":
      case "invoke":
        return ticks.filter((t) => t.node === e.from && t.skill === skillOf(e.to));
      case "sandbox":
        return ticks.filter((t) => t.skill === skillOf(e.from) && t.ran);
    }
    return [];
  }

  function edgeCard(e) {
    const tone = toneTag(e.policy || e.tone);
    if (tone !== "none") ui.card.classList.add(`tone-${tone}`);
    const head = h(
      "div",
      { class: "card-head" },
      h("span", { class: `ico${tone !== "none" ? " tone-" + tone : ""}`, "aria-hidden": "true" }, icon("flow", 22)),
      h("strong", { class: "name" }, edgeName(e)),
      h("span", { class: `tag${tone !== "none" ? " " + tone : ""}` }, edgeWord(e)),
      e.count ? h("span", { class: "meta" }, e.kind === "sandbox" || e.kind === "skill_run" ? M.count.runs(num(e.count)) : M.count.calls(num(e.count))) : null,
      h("button", { type: "button", class: "btn link small x", "aria-label": M.card.clear, title: M.card.clearTitle, on: { click: () => clear() } }, icon("x", 14)),
    );
    const out = [head];
    if (e.label) out.push(h("p", { class: "small" }, h("span", { class: `tag ${tone}` }, e.label)));
    const calls = callsBehind(e);
    if (calls.length) {
      const shown = calls.slice(-40);
      out.push(
        h("p", { class: "lbl" }, M.card.callsBehind(shown.length, calls.length)),
        h(
          "ol",
          { class: "calls" },
          shown.map((t) => {
            const pol = toneTag(t.policy);
            const word = outcomeWord(t.policy);
            return h(
              "li",
              null,
              h("span", { class: "when" }, fmt.time(t.ts)),
              h("span", { class: "mono" }, t.tool || "?"),
              t.skill ? h("span", { class: "muted" }, t.skill) : null,
              word ? h("span", { class: `tag ${pol}` }, word) : null,
              t.authority ? h("span", { class: "tag auth" }, icon(authorityGlyph(t.authority), 12), authorityLabel(t.authority)) : null,
            );
          }),
        ),
      );
    } else if (e.kind === "runs_on") out.push(h("p", { class: "muted small" }, M.card.runsOn(nodeLabel(e.to), nodeLabel(e.from))));
    else if (e.kind === "prompt") out.push(h("p", { class: "muted small" }, M.card.prompts(num(e.count))));
    else out.push(h("p", { class: "muted small" }, M.card.noCalls));
    out.push(
      h(
        "div",
        { class: "actions" },
        h("button", { type: "button", class: "btn ghost", on: { click: () => select(e.from, { from: "card" }) } }, nodeLabel(e.from)),
        h("button", { type: "button", class: "btn ghost", on: { click: () => select(e.to, { from: "card" }) } }, nodeLabel(e.to)),
      ),
    );
    return out;
  }

  function cardHead(n, d, tone) {
    const kindWord =
      n.kind === "agent" && n.role === "subagent" ? M.card.subagent : n.event ? M.card.event(n.kind) : KIND_WORD[n.kind] ? KIND_WORD[n.kind].toLowerCase() : n.kind || M.card.node;
    const ico = h("span", { class: `ico${tone ? " tone-" + tone : ""}`, "aria-hidden": "true" }, icon(n.kind === "sandbox" ? "lock" : n.kind === "skill" ? "shield" : "flow", 22));
    let meta = "";
    if (n.event && n.ts) meta = fmt.time(n.ts) + (n.tool_use_id ? ` · ${String(n.tool_use_id).slice(0, 12)}…` : "");
    else if (n.kind === "skill" && n.count) meta = M.count.runs(num(n.count));
    else if (n.count) meta = n.kind === "sandbox" ? M.count.runs(num(n.count)) : M.count.calls(num(n.count));
    return h(
      "div",
      { class: "card-head" },
      ico,
      h("strong", { class: "name" }, n.label || n.id),
      h("span", { class: `tag${tone ? " " + tone : ""}` }, kindWord),
      meta ? h("span", { class: "meta" }, meta) : null,
      h("button", { type: "button", class: "btn link small x", "aria-label": M.card.clear, title: M.card.clearTitle, on: { click: () => clear() } }, icon("x", 14)),
    );
  }

  function lines(xs) {
    return [].concat(xs || []).map((l) => h("div", null, String(l)));
  }

  function skillBody(n, d) {
    const out = [];
    const C = M.card;
    if (n.sub) out.push(h("p", { class: "muted small" }, n.sub));
    if (d.requested || d.granted || d.ran_under) {
      out.push(
        h(
          "div",
          { class: "flow3" },
          h("div", { class: "box ask" }, h("div", { class: "box-title" }, C.requested), h("div", { class: "box-body" }, lines(d.requested || [C.noManifest]))),
          h("div", { class: "box" }, h("div", { class: "box-title" }, C.granted), h("div", { class: "box-body" }, lines(d.granted || [C.defaultGrant]))),
          h("div", { class: "box dark" }, h("div", { class: "box-title" }, C.ranUnder), h("div", { class: "box-body" }, lines(d.ran_under || [C.notRun]))),
        ),
      );
    }
    const kv = [];
    const row = (k, ...v) => kv.push(h("span", { class: "k" }, k), h("span", { class: "v" }, ...v));
    if (n.authority) row(C.decidedBy, whoDecided(n.authority));
    if (d.called_by) row(C.calledBy, d.called_by);
    if (d.skill) row(C.skill, d.skill);
    if (d.decision) row(C.decision, d.decision);
    const o = d.outcome;
    if (o) {
      const bits = [];
      if (o.exit !== undefined && o.exit !== null) bits.push(C.exit(o.exit));
      if (o.ts) bits.push(fmt.time(o.ts));
      row(C.outcome, h("span", { class: `tag ${toneTag(o.tone)}` }, o.label || o.tone || "?"), bits.length ? " " + bits.join(" · ") : "");
      if (o.evidence) row(C.evidence, o.evidence === "hint" && o.stream === "stdout" ? M.evidence.stdout : Object.prototype.hasOwnProperty.call(M.evidence, o.evidence) ? M.evidence[o.evidence] : o.evidence);
    }
    const dv = d.declared_vs_did;
    if (dv) {
      const [vt, vw] = verdict(dv.verdict);
      row(C.declaredVsDid, h("span", { class: `tag ${vt}` }, vw), " " + C.declaredDid(dv.declared, dv.did));
    }
    if (kv.length) out.push(h("div", { class: "kv" }, kv));
    if (dv && dv.floor) out.push(h("p", { class: "floor" }, M.floor));
    const skill = (d.grant && d.grant.skill) || (n.kind === "skill" ? n.label : null);
    const note = st.grantNote && st.grantNote.skill === skill ? st.grantNote : null;
    if (o && toneTag(o.tone) === "deny" && (d.fix || d.grant) && !note) out.push(h("p", { class: "why" }, C.why));
    if (d.fix && !note) out.push(h("div", { class: "code wrap", "aria-label": C.equivalent }, d.fix));
    const actions = [];
    const err = h("div", { class: "banner deny card-error", role: "alert" });
    if (d.grant && typeof d.grant === "object" && skill) {
      const edit = Object.fromEntries(Object.entries(d.grant).filter(([k]) => k !== "skill"));
      const what = grantWhat(edit);
      if (!note) {
        const btn = h("button", { type: "button", class: "btn red", dataset: { k: "grant" } }, M.grant.button(what));
        btn.addEventListener("click", () => grant(skill, edit, what, d.fix, btn, err));
        actions.push(btn);
        actions.push(h("button", { type: "button", class: "btn ghost", on: { click: () => clear() } }, M.grant.keep));
      }
    }
    const other = st.view === "topology" ? "timeline" : "topology";
    actions.push(h("button", { type: "button", class: "btn ghost", on: { click: () => goTo({ view: other, n: crossSel(other) }) } }, C.showIn[other]));
    if (note) out.push(grantNoteBlock(note));
    out.push(h("div", { class: "actions" }, actions), err);
    return out;
  }

  function verdict(v) {
    return Object.prototype.hasOwnProperty.call(M.verdict, v) ? M.verdict[v] : ["none", v || M.verdict.unknown[1]];
  }

  /** grantNoteBlock(note): the server's answer to the POST, shown once until the refetched graph replaces the card. */
  function grantNoteBlock(note) {
    return h(
      "div",
      { class: "stack-sm grant-note", role: "status" },
      h("p", { class: "small" }, note.changed === false ? M.grant.unchanged(note.what, note.skill) : M.grant.saved(note.what, note.skill)),
      note.cmd ? h("div", { class: "code wrap", "aria-label": M.card.equivalent }, note.cmd) : null,
      note.path ? h("p", { class: "muted small" }, M.grant.file, h("code", null, note.path)) : null,
    );
  }

  function policyTags(p) {
    return h(
      "span",
      { class: "tags" },
      h("span", { class: "tag ok" }, M.outcomeCount(M.outcome.allow, num(p.allow))),
      h("span", { class: "tag ask" }, M.outcomeCount(M.outcome.ask, num(p.ask))),
      h("span", { class: "tag deny" }, M.outcomeCount(M.outcome.denied, num(p.deny))),
      h("span", { class: "tag none" }, M.outcomeCount(M.outcome.unchecked, num(p.none))),
    );
  }

  function genericBody(n, d) {
    const out = [];
    const C = M.card;
    if (n.sub) out.push(h("p", { class: "muted small" }, n.sub));
    if (n.sub2) out.push(h("p", { class: "muted small" }, n.sub2));
    const kv = [];
    const row = (k, ...v) => kv.push(h("span", { class: "k" }, k), h("span", { class: "v" }, ...v));
    const used = new Set(["command"]);
    if (n.authority) row(C.decidedBy, whoDecided(n.authority));
    if (d.model) {
      row(C.model, nodeLabel(d.model));
      used.add("model");
    }
    if (d.calls !== undefined) {
      row(C.calls, String(d.calls));
      used.add("calls");
    }
    if (Array.isArray(d.tools)) {
      row(C.tools, d.tools.length ? d.tools.map((t) => `${t.name} ×${t.count}`).join(", ") : C.none);
      used.add("tools");
    }
    if (Array.isArray(d.spawned)) {
      row(C.spawned, d.spawned.length ? d.spawned.map(nodeLabel).join(", ") : C.none);
      used.add("spawned");
    }
    if (d.skill_runs !== undefined) {
      row(C.skillRuns, String(d.skill_runs));
      used.add("skill_runs");
    }
    if (Array.isArray(d.by_agent)) {
      row(C.calledBy, d.by_agent.map((a) => `${nodeLabel(a.agent)} ×${a.count}`).join(", "));
      used.add("by_agent");
    }
    if (d.policy && typeof d.policy === "object") {
      row(C.policy, policyTags(d.policy));
      used.add("policy");
    }
    // M6.4: rule hits (tool cards: name/count; event cards: strings)
    if (Array.isArray(d.rules) && d.rules.length) {
      row(C.ruleHits, d.rules.map((r) => (typeof r === "string" ? r : `${r.name} ×${r.count}`)).join(", "));
      used.add("rules");
    }
    if (Array.isArray(n.subjects) && n.subjects.length && !d.subject) row(C.policy, n.subjects.join(", "));
    if (n.kind === "agent" && n.ring && !d.policy) row(C.policy, policyTags(n.ring));
    for (const [k, v] of Object.entries(d)) {
      if (used.has(k) || v === null || v === undefined) continue;
      if (typeof v === "string" || typeof v === "number" || typeof v === "boolean") row(k.replace(/_/g, " "), String(v));
    }
    if (kv.length) out.push(h("div", { class: "kv" }, kv));
    if (n.kind === "tool" || n.kind === "mcp") {
      const pol = d.policy;
      const touched = pol && (num(pol.allow) || num(pol.ask) || num(pol.deny));
      if (!touched) out.push(h("p", { class: "muted small" }, C.ownTool));
    }
    return out;
  }

  async function grant(skill, edit, what, fix, btn, err) {
    const ok = await confirmDialog({
      title: M.grant.title(what, skill),
      body: [h("p", null, M.grant.body(skill, what, !!fix)), fix ? h("code", null, fix) : null],
      confirmLabel: M.grant.confirm,
      danger: true,
    });
    if (!ok || !root) return;
    btn.disabled = true;
    err.textContent = "";
    try {
      const r = (await api.post(skillPath(skill) + "/grant", edit)) || {};
      if (!root) return;
      const changed = r.changed !== false;
      st.grantNote = { skill, what, cmd: r.allowCommand || null, path: r.overridesPath || null, changed };
      toast(changed ? r.allowCommand || M.grant.toast(what) : M.grant.toastSame(skill, what), changed ? "ok" : "");
      store.refreshSkills().catch(() => {});
      renderCard();
      st.etag = null;
      poll(true); // no If-None-Match: the card is re-rendered from the refetched graph only
    } catch (e) {
      if (!root) return;
      btn.disabled = false;
      err.textContent = e.message || M.grant.failed;
    }
  }

  function renderExtra() {
    const g = st.graph || {};
    const nodes = g.nodes || [];
    const out = [];
    const X = M.extra;
    const agents = nodes.filter((n) => n.kind === "agent" && !n.event);
    if (agents.length) {
      const kv = [];
      for (const a of agents) {
        const d = a.detail || {};
        const bits = [];
        if (d.calls !== undefined || a.count !== undefined) bits.push(M.count.calls(num(d.calls !== undefined ? d.calls : a.count)));
        if (Array.isArray(d.spawned) && d.spawned.length) bits.push(X.spawned(d.spawned.map(nodeLabel).join(", ")));
        if (Array.isArray(d.tools) && d.tools.length && a.role === "subagent") bits.push(d.tools.map((t) => t.name).join(", "));
        if (d.skill_runs !== undefined) bits.push(d.skill_runs ? M.count.skillRuns(num(d.skill_runs)) : X.noSkill);
        kv.push(h("span", { class: "k" }, a.label || a.id), h("span", { class: "v" }, bits.join(" · ")));
      }
      out.push(h("div", { class: "card stack-sm" }, h("p", { class: "lbl" }, X.agents), h("div", { class: "kv" }, kv)));
    }
    const seen = new Set();
    const rows = [];
    for (const n of nodes) {
      if (n.kind !== "skill" || seen.has(n.label)) continue;
      seen.add(n.label);
      const dv = (n.detail && n.detail.declared_vs_did) || null;
      const [vt, vw] = dv ? verdict(dv.verdict) : M.verdict.unknown;
      // One block per skill: name and badge on one line, then declared and
      // did as label/value rows; each did phrase on its own line.
      const declared = dv && dv.declared ? String(dv.declared).split(", ") : ["—"];
      const did = dv ? (Array.isArray(dv.did_items) && dv.did_items.length ? dv.did_items : [dv.did || "—"]) : ["—"];
      const quiet = !dv || !dv.declared || /^no(t)? /.test(dv.declared);
      rows.push(
        h(
          "div",
          { class: "dvd-row" },
          h("div", { class: "dvd-head" }, h("strong", { class: "dvd-name" }, n.label), h("span", { class: `tag ${vt}` }, vw)),
          h(
            "dl",
            { class: "dvd-kv" },
            h("dt", null, X.declared),
            h("dd", { class: quiet ? "muted" : "mono" }, declared.join(" · ")),
            h("dt", null, X.did),
            h("dd", null, h("ul", { class: "dvd-did mono" }, did.map((x) => h("li", null, String(x))))),
          ),
        ),
      );
    }
    if (rows.length) {
      out.push(h("div", { class: "card stack-sm" }, h("p", { class: "lbl" }, X.dvd), h("div", { class: "dvd" }, rows), h("p", { class: "floor" }, M.floor)));
    } else if (st.graph) {
      out.push(h("div", { class: "card stack-sm" }, h("p", { class: "lbl" }, X.scripts), h("p", { class: "muted small" }, X.noScripts)));
    }
    out.push(
      h(
        "div",
        { class: "card stack-sm" },
        h("p", { class: "lbl" }, X.whereTitle),
        h("p", { class: "small" }, X.where),
        h("p", { class: "privacy" }, X.privacy, h("code", null, X.privacyCmd), X.privacyEnd),
      ),
    );
    ui.extra.replaceChildren(...out);
  }

  // ------------------------------------------------ lifecycle

  return {
    mount(r, sessionId, view, query) {
      st = freshState(st.seq + 1); // in-flight responses from an earlier visit see a different seq and are dropped
      root = r;
      build();
      const recs = store.activity.records || [];
      st.lastOffset = recs.reduce((m, x) => Math.max(m, num(x.offset, -1)), -1);
      st.unsub = store.subscribe(onActivity);
      apply(routeOf(sessionId, view, query), true);
    },
    update(sessionId, view, query) {
      if (!root) return;
      apply(routeOf(sessionId, view, query), false);
    },
    unmount() {
      clearTimeout(st.timer);
      if (st.replay) clearInterval(st.replay.timer);
      st.timer = null;
      if (st.unsub) st.unsub();
      st.unsub = null;
      for (const [t, type, fn, opts] of off) t.removeEventListener(type, fn, opts);
      off.length = 0;
      if (cv) cv.destroy();
      cv = null;
      st.seq++;
      root = null;
    },
  };
}
