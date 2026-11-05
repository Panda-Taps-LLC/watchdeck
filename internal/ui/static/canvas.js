// The map canvas (Plan 04 Task 10, moved out of map.js): the glyph symbols,
// the drawing primitives and the kit the two views draw with (makeKit), and
// the viewport machinery one session map needs (makeCanvas): layout
// persistence, zoom, fit and pan, pointer drag, pan and pinch, the minimap,
// replay and the canvas keys. map.js owns the page around it (route, fetch,
// header, tick strip, selection, card); timeline.js and topology.js place the
// nodes through the kit.
//
// CSP (default-src 'none'; script-src 'self'; style-src 'self'): DOM is built
// with createElement/createElementNS; positions and sizes go through CSSOM
// (el.style.transform / background-*), never a style attribute. The glyph
// symbols are one static, data-free SVG string parsed once with DOMParser.
import { fmt, h, icon } from "./app.js";

const SVGNS = "http://www.w3.org/2000/svg";
// Fit: the timeline keeps its 0.5–1 range. The topology fits at most 1.3 (a
// four-node graph should not be gigantic) and prefers at least 13/14, where
// a 14 px subtitle renders at 13 px; to keep every column on screen it goes
// down to 12/14 (12 px text), and only past that pans, with the minimap.
// The timeline fits its drawn content and may scale up to 1.6 so a short
// session fills the canvas; never beyond (Plan 05 Task 6).
const FIT = { timeline: [0.5, 1.6], topology: [13 / 14, 1.3] };
const FIT_TOPOLOGY_LOW = 12 / 14;
const FIT_PAD = 20;
const FIT_CTL = 48; // the zoom controls on the canvas's right edge: 34 px buttons, 14 px in
export const ZOOM_STEP = 1.2;
const ZOOM_MIN = 0.25;
const ZOOM_MAX = 3;
const DRAG_THRESHOLD = 4; // px of pointer travel before a press on a node becomes a drag
const KEY_STEP = 8;
const KEY_STEP_BIG = 32;
const REPLAY_MS = 900;
const LAYOUT_KEY = "watchdeck.flow.layout.v1:";
const CV_MIN_H = 380; // map.css .cv min-height says the same
const MINI_SLACK = 24; // screen px of overflow that does not offer the minimap
const CV_MAX_H = 720;
const LAYOUT_KEEP = 50; // session layouts kept in localStorage, most recently written first

// ---------------------------------------------------------------- glyph symbols (static, data-free)

const SYMBOLS = `<svg xmlns="http://www.w3.org/2000/svg" class="cv-defs" width="0" height="0" aria-hidden="true" focusable="false"><defs>
<symbol id="g-robot" viewBox="0 0 24 24"><rect class="gi" x="5" y="8.5" width="14" height="10" rx="3"/><circle class="gd" cx="9.5" cy="13.5" r="1.3"/><circle class="gd" cx="14.5" cy="13.5" r="1.3"/><path class="gi" d="M12 8.5V5.5M10 5.5h4M2.5 12.5v3M21.5 12.5v3M9.5 16.5h5"/></symbol>
<symbol id="g-person" viewBox="0 0 24 24"><circle class="gi" cx="12" cy="8" r="4"/><path class="gi" d="M4 21a8 8 0 0116 0"/></symbol>
<symbol id="g-cpu" viewBox="0 0 24 24"><rect class="gi" x="7" y="7" width="10" height="10" rx="2"/><rect class="gd" x="10.5" y="10.5" width="3" height="3" rx=".5"/><path class="gi" d="M9 7V3.5M15 7V3.5M9 17v3.5M15 17v3.5M7 9H3.5M7 15H3.5M17 9h3.5M17 15h3.5"/></symbol>
<symbol id="g-lock" viewBox="0 0 24 24"><rect class="gi" x="5" y="11" width="14" height="10" rx="2"/><path class="gi" d="M8 11V7a4 4 0 018 0v4"/><circle class="gd" cx="12" cy="16" r="1.3"/></symbol>
<symbol id="g-you" viewBox="0 0 44 44"><circle class="gf" cx="22" cy="22" r="20"/><use href="#g-person" x="10" y="10" width="24" height="24" stroke-width="2"/></symbol>
<symbol id="g-agent-main" viewBox="0 0 104 104"><circle class="gf" cx="52" cy="52" r="38"/><use href="#g-robot" x="30" y="30" width="44" height="44" stroke-width="2"/></symbol>
<symbol id="g-agent-sub" viewBox="0 0 60 60"><circle class="gf" cx="30" cy="30" r="27" stroke-width="2.5"/><circle class="gs" cx="30" cy="30" r="21" stroke-width="1" opacity=".4"/><use href="#g-robot" x="17" y="17" width="26" height="26" stroke-width="2"/></symbol>
<symbol id="g-model" viewBox="0 0 44 44"><rect class="gf" x="3" y="3" width="38" height="38" rx="9" stroke-width="2"/><use href="#g-cpu" x="10" y="10" width="24" height="24" stroke-width="1.9"/></symbol>
<symbol id="g-tool" viewBox="0 0 54 54"><path class="gf" d="M15 4h24l12 23-12 23H15L3 27z" stroke-width="2"/></symbol>
<symbol id="g-bash" viewBox="0 0 24 24"><path class="gi" d="M4 17l6-5-6-5M12 19h8" stroke-width="2.2"/></symbol>
<symbol id="g-read" viewBox="0 0 24 24"><path class="gi" d="M6 3h9l5 5v13H6z" stroke-width="2"/><path class="gi" d="M14 3v6h6M9 13h6M9 17h6" stroke-width="2"/></symbol>
<symbol id="g-grep" viewBox="0 0 24 24"><circle class="gi" cx="11" cy="11" r="6.5" stroke-width="2"/><path class="gi" d="M20 20l-4.2-4.2M8 11h6" stroke-width="2"/></symbol>
<symbol id="g-glob" viewBox="0 0 24 24"><path class="gi" d="M3 6h6l2 2h10v11H3z" stroke-width="2"/><path class="gi" d="M12 11v5M9.8 12.2l4.4 2.6M14.2 12.2l-4.4 2.6" stroke-width="1.8"/></symbol>
<symbol id="g-edit" viewBox="0 0 24 24"><path class="gi" d="M4 20l1.5-5.5L16 4l4 4L9.5 18.5z" stroke-width="2"/><path class="gi" d="M13 7l4 4" stroke-width="2"/></symbol>
<symbol id="g-write" viewBox="0 0 24 24"><path class="gi" d="M6 3h9l5 5v13H6z" stroke-width="2"/><path class="gi" d="M9 17l1-3 5-5 2 2-5 5z" stroke-width="1.8"/></symbol>
<symbol id="g-webfetch" viewBox="0 0 24 24"><circle class="gi" cx="12" cy="12" r="9" stroke-width="1.9"/><path class="gi" d="M3 12h18M12 3c-3.5 4-3.5 14 0 18M12 3c3.5 4 3.5 14 0 18" stroke-width="1.9"/></symbol>
<symbol id="g-websearch" viewBox="0 0 24 24"><circle class="gi" cx="10" cy="10" r="7" stroke-width="1.9"/><path class="gi" d="M3 10h14M10 3c-2.5 3-2.5 11 0 14M10 3c2.5 3 2.5 11 0 14M15.5 15.5L21 21" stroke-width="1.9"/></symbol>
<symbol id="g-agent-tool" viewBox="0 0 24 24"><use href="#g-robot" width="24" height="24" stroke-width="2"/></symbol>
<symbol id="g-skill-tool" viewBox="0 0 24 24"><path class="gi" d="M12 3l8 3v6c0 4.5-3.4 8.2-8 9-4.6-.8-8-4.5-8-9V6l8-3z" stroke-width="2"/></symbol>
<symbol id="g-generic" viewBox="0 0 24 24"><path class="gi" d="M14.7 6.3a4 4 0 00-5.4 5.4L4 17l3 3 5.3-5.3a4 4 0 005.4-5.4l-2.5 2.5-2.1-.6-.6-2.1z" stroke-width="1.9"/></symbol>
<symbol id="g-mcp" viewBox="0 0 60 60"><rect class="gf" x="11" y="11" width="38" height="38" rx="8" transform="rotate(45 30 30)" stroke-width="2.2" stroke-dasharray="5 4"/><path class="gi" d="M25 26v-4M35 26v-4M23 26h14v3a7 7 0 01-14 0zM30 36v3" stroke-width="2"/></symbol>
<symbol id="g-skill-outer" viewBox="0 0 24 24"><path class="gs" d="M12 1.6l9.4 3.5v7c0 5.3-4 9.6-9.4 10.6C6.6 21.7 2.6 17.4 2.6 12.1v-7L12 1.6z" stroke-width=".9" stroke-dasharray="1.4 1"/></symbol>
<symbol id="g-skill-inner" viewBox="0 0 24 24"><path class="gf" d="M12 4.2l7 2.6v5.2c0 4-3 7.2-7 7.9-4-.7-7-3.9-7-7.9V6.8l7-2.6z" stroke-width="1.1"/><path class="gi" d="M10.5 8.6h-.75a.75.75 0 00-.75.75v5.25a.75.75 0 00.75.75h4.5a.75.75 0 00.75-.75V9.35a.75.75 0 00-.75-.75h-.75" stroke-width=".8"/><rect class="gi" x="10.5" y="8.06" width="3" height="1.5" rx=".38" stroke-width=".8"/><path class="gi" d="M10.9 12.4l.75.75 1.5-1.5" stroke-width=".8"/></symbol>
<symbol id="g-sandbox" viewBox="0 0 92 92"><rect class="gf" x="4" y="4" width="84" height="84" rx="16" stroke-width="2.5"/><rect class="gs" x="13" y="13" width="66" height="66" rx="11" stroke-width="1.2" stroke-dasharray="4 3" opacity=".8"/><use href="#g-lock" x="26" y="26" width="40" height="40" stroke-width="2.2"/></symbol>
<symbol id="g-cut" viewBox="0 0 26 26"><circle class="cut-c" cx="13" cy="13" r="11" stroke-width="2.5"/><path class="cut-x" d="M8 8l10 10M18 8L8 18" stroke-width="2.5"/></symbol>
<marker id="m-grey" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="10" markerHeight="10" markerUnits="userSpaceOnUse" orient="auto"><path class="mk" d="M0 1L9 5 0 9z"/></marker>
<marker id="m-teal" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="10" markerHeight="10" markerUnits="userSpaceOnUse" orient="auto"><path class="mk mk-teal" d="M0 1L9 5 0 9z"/></marker>
<marker id="m-violet" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="10" markerHeight="10" markerUnits="userSpaceOnUse" orient="auto"><path class="mk mk-violet" d="M0 1L9 5 0 9z"/></marker>
<marker id="m-ask" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="10" markerHeight="10" markerUnits="userSpaceOnUse" orient="auto"><path class="mk mk-ask" d="M0 1L9 5 0 9z"/></marker>
<marker id="m-ok" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="10" markerHeight="10" markerUnits="userSpaceOnUse" orient="auto"><path class="mk mk-ok" d="M0 1L9 5 0 9z"/></marker>
<marker id="m-deny" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="10" markerHeight="10" markerUnits="userSpaceOnUse" orient="auto"><path class="mk mk-deny" d="M0 1L9 5 0 9z"/></marker>
<marker id="m-blue" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="10" markerHeight="10" markerUnits="userSpaceOnUse" orient="auto"><path class="mk mk-blue" d="M0 1L9 5 0 9z"/></marker>
<marker id="m-light" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="10" markerHeight="10" markerUnits="userSpaceOnUse" orient="auto"><path class="mk mk-light" d="M0 1L9 5 0 9z"/></marker>
</defs></svg>`;

let symbolsNode = null;
export function symbolDefs() {
  if (!symbolsNode) {
    const doc = new DOMParser().parseFromString(SYMBOLS, "image/svg+xml");
    symbolsNode = doc.documentElement;
  }
  return document.importNode(symbolsNode, true);
}

const GLYPHS = new Set(["bash", "read", "grep", "glob", "edit", "write", "webfetch", "websearch", "agent-tool", "skill-tool", "generic"]);
const MARKER_TONES = { grey: "grey", none: "grey", teal: "teal", violet: "violet", ask: "ask", ok: "ok", allow: "ok", deny: "deny", blue: "blue", light: "light" };

/** cls(s): a value safe to use as a class-name fragment (server strings never become selectors or markup). */
export function cls(s) {
  return typeof s === "string" && /^[A-Za-z][A-Za-z0-9_-]{0,40}$/.test(s) ? s.toLowerCase() : "x";
}
export function num(v, d = 0) {
  const n = Number(v);
  return Number.isFinite(n) ? n : d;
}
export function plural(n, one, many) {
  return `${n} ${n === 1 ? one : many || one + "s"}`;
}

// ---------------------------------------------------------------- drawing primitives (shared by both views)

/** svgEl(tag, attrs): an SVG element with presentation attributes (never style). */
export function svgEl(tag, attrs) {
  const n = document.createElementNS(SVGNS, tag);
  if (attrs) for (const [k, v] of Object.entries(attrs)) if (v !== undefined && v !== null && v !== false) n.setAttribute(k, String(v));
  return n;
}

export function useSym(id, attrs) {
  return svgEl("use", { href: "#" + id, ...attrs });
}

function glyphOf(n) {
  const g = cls(n.glyph || "");
  if (GLYPHS.has(g)) return g;
  const l = cls((n.label || "").replace(/[^A-Za-z]/g, ""));
  if (GLYPHS.has(l)) return l;
  if (l === "agent" || l === "task") return "agent-tool";
  if (l === "skill") return "skill-tool";
  return "generic";
}

function ringArcs(svg, ring) {
  const parts = [["none", num(ring.none)], ["allow", num(ring.allow)], ["ask", num(ring.ask)], ["deny", num(ring.deny)]];
  const total = parts.reduce((s, p) => s + p[1], 0);
  svg.appendChild(svgEl("circle", { class: "ring-track", cx: 52, cy: 52, r: 48, "stroke-width": 5 }));
  if (!total) return;
  let start = 0;
  for (const [k, v] of parts) {
    if (v <= 0) continue;
    const len = (v / total) * 100;
    svg.appendChild(
      svgEl("circle", {
        class: `ring-arc ring-${k}`,
        cx: 52,
        cy: 52,
        r: 48,
        "stroke-width": 5,
        pathLength: 100,
        "stroke-dasharray": `${len.toFixed(2)} ${(100 - len).toFixed(2)}`,
        "stroke-dashoffset": `${(-start).toFixed(2)}`,
        transform: "rotate(-90 52 52)",
      }),
    );
    start += len;
  }
}

/** shapeFor(n): the node's glyph as an <svg> sized w×h (server units). */
function shapeFor(n, w, hgt) {
  const kind = n.kind;
  const box = (vb) => svgEl("svg", { width: w, height: hgt, viewBox: vb, "aria-hidden": "true", focusable: "false" });
  let svg;
  if (kind === "agent" && n.role !== "subagent") {
    svg = box("0 0 104 104");
    if (n.ring) ringArcs(svg, n.ring);
    svg.appendChild(useSym("g-agent-main", { width: 104, height: 104 }));
    if (n.live) svg.appendChild(svgEl("circle", { class: "ring-live pulse", cx: 52, cy: 52, r: 48, "stroke-width": 1 }));
  } else if (kind === "agent") {
    svg = box("0 0 60 60");
    svg.appendChild(useSym("g-agent-sub", { width: 60, height: 60 }));
    if (n.live) svg.appendChild(svgEl("circle", { class: "ring-live pulse", cx: 30, cy: 30, r: 29, "stroke-width": 1 }));
  } else if (kind === "you") {
    svg = box("0 0 44 44");
    svg.appendChild(useSym("g-you", { width: 44, height: 44 }));
  } else if (kind === "model") {
    svg = box("0 0 44 44");
    svg.appendChild(useSym("g-model", { width: 44, height: 44 }));
  } else if (kind === "mcp") {
    svg = box("0 0 60 60");
    svg.appendChild(useSym("g-mcp", { width: 60, height: 60 }));
  } else if (kind === "skill") {
    svg = box("0 0 24 24");
    if (n.requested) svg.appendChild(useSym("g-skill-outer", { width: 24, height: 24 }));
    svg.appendChild(useSym("g-skill-inner", { width: 24, height: 24 }));
  } else if (kind === "sandbox") {
    svg = box("0 0 92 92");
    svg.appendChild(useSym("g-sandbox", { width: 92, height: 92 }));
  } else {
    svg = box("0 0 54 54");
    svg.appendChild(useSym("g-tool", { width: 54, height: 54 }));
    svg.appendChild(useSym("g-" + glyphOf(n), { x: 15, y: 15, width: 24, height: 24 }));
  }
  return svg;
}

export const KIND_WORD = { you: "You", agent: "Agent", model: "Model", tool: "Tool", mcp: "MCP server", skill: "Skill", sandbox: "Sandbox" };

function nodeName(n) {
  const kind = n.kind === "agent" && n.role === "subagent" ? "Subagent" : KIND_WORD[n.kind] || "Node";
  const parts = [n.kind === "you" ? "You" : `${kind} ${n.label || n.id}`];
  if (n.count) parts.push(plural(num(n.count), n.kind === "you" ? "prompt" : n.kind === "skill" || n.kind === "sandbox" ? "run" : "call"));
  if (n.sub) parts.push(n.sub);
  if (n.sub2) parts.push(n.sub2);
  if (num(n.rule_hits) > 0) parts.push(plural(num(n.rule_hits), "rule hit"));
  if (n.subjects && n.subjects.length) parts.push("policy: " + n.subjects.join(", "));
  if (n.live) parts.push("live");
  return parts.join(", ");
}

/**
 * makeKit(stage, graph, page): the drawing kit a view uses. node(n, {lab})
 * places a <button class="node"> at the server's centre (x, y) via a CSSOM
 * transform; edge(e) draws the path (and glow, cut and pill); text helpers
 * place headers and ticks. Views append in the order they want Tab to follow.
 */
export function makeKit(stage, graph, page) {
  const W = num(graph.canvas && graph.canvas.w, 1000);
  const H = num(graph.canvas && graph.canvas.h, 720);
  const svg = svgEl("svg", { class: "edges", width: W, height: H, viewBox: `0 0 ${W} ${H}`, "aria-hidden": "true", focusable: "false" });
  const under = svgEl("g", { class: "under" });
  const glows = svgEl("g", { class: "glows" });
  const lines = svgEl("g", { class: "lines" });
  const over = svgEl("g", { class: "over" });
  const hits = svgEl("g", { class: "hits" });
  svg.append(under, glows, lines, over, hits);
  const overlay = h("div", { class: "nodes", role: "group", "aria-label": graph.view === "timeline" ? "Session events" : "Agents, tools, skills and the sandbox" });
  stage.append(svg, overlay);
  const decor = h("div", { class: "decor", "aria-hidden": "true" });
  overlay.appendChild(decor);

  function place(el, x, y, extra = "") {
    el.style.transform = `translate(${x}px, ${y}px)${extra}`;
    return el;
  }

  return {
    W,
    H,
    svg,
    under,
    lines,
    over,
    hits,
    overlay,
    markerTone: (tone) => MARKER_TONES[tone] || null,
    decor,
    place,
    svgEl,
    useSym,
    h,
    icon,
    num,
    cls,
    node(n, opts = {}) {
      const w = num(n.w, 44);
      const hh = num(n.h, 44);
      const tone = n.tone ? ` tone-${cls(n.tone)}` : "";
      const role = n.role ? ` role-${cls(n.role)}` : "";
      const b = h("button", {
        type: "button",
        class: `node kind-${cls(n.kind)}${role}${tone}${n.event ? " event" : ""}`,
        "aria-pressed": "false",
        "aria-label": nodeName(n),
        dataset: { id: n.id },
      });
      if (n.live && n.kind === "agent") b.setAttribute("aria-current", "true");
      b.style.width = `${w}px`;
      b.style.height = `${hh}px`;
      place(b, num(n.x) - w / 2, num(n.y) - hh / 2);
      const shape = h("span", { class: "shape" }, shapeFor(n, w, hh));
      if (n.count !== undefined && n.count !== null && num(n.count) > 0) shape.appendChild(h("span", { class: "cnt", "aria-hidden": "true" }, String(n.count)));
      b.appendChild(shape);
      const lab = h("span", { class: `lab lab-${opts.lab || "right"}`, "aria-hidden": "true" }, h("span", { class: "t" }, n.label || n.id));
      // split: one line per " · " phrase, so a label is narrow and never wraps mid-phrase.
      const subLines = (s) => (opts.split ? String(s).split(" · ") : [String(s)]);
      if (n.sub) for (const s of subLines(n.sub)) lab.appendChild(h("span", { class: "s" }, s));
      if (n.sub2) for (const s of subLines(n.sub2)) lab.appendChild(h("span", { class: "s s2" }, s));
      // M6.4: rule-hit badge, as a label line (no inline style under the CSP)
      if (num(n.rule_hits) > 0) lab.appendChild(h("span", { class: "s s2" }, plural(num(n.rule_hits), "rule hit")));
      b.appendChild(lab);
      b.addEventListener("click", () => {
        if (page.swallowClick()) return; // the press was a drag
        page.select(n.id, { from: "click" });
      });
      overlay.appendChild(b);
      page.nodeEls.set(n.id, b);
      return b;
    },
    edge(e) {
      if (typeof e.d !== "string" || !e.d) return;
      const tone = cls(e.tone || "grey");
      const width = Math.max(0.5, Math.min(14, num(e.width, 1.5)));
      const kind = cls(e.kind || "call");
      if (e.glow) lines.appendChild(svgEl("path", { d: e.d, class: `edge glow tone-${tone}`, "stroke-width": (width * 3.2).toFixed(1) }));
      const classes = [`edge kind-${kind} tone-${tone}`];
      if (e.flow) classes.push("flow");
      if (e.pending) classes.push("pending");
      const marker = !e.cut && !e.flow && MARKER_TONES[tone] && kind !== "prompt" && kind !== "return" ? `url(#m-${MARKER_TONES[tone]})` : null;
      const attrs = { d: e.d, class: classes.join(" "), "stroke-width": width, "marker-end": marker, "data-id": e.id };
      if (e.dash && !e.flow && /^[0-9 .,]+$/.test(String(e.dash))) attrs["stroke-dasharray"] = String(e.dash);
      if (e.dotted) attrs["stroke-dasharray"] = "1 5";
      (kind === "call" || kind === "runs_on" || kind === "prompt" ? under : lines).appendChild(svgEl("path", attrs));
      if (e.cut && Number.isFinite(Number(e.cut.x)) && Number.isFinite(Number(e.cut.y))) {
        over.appendChild(useSym("g-cut", { class: "cut", x: num(e.cut.x) - 13, y: num(e.cut.y) - 13, width: 26, height: 26, "data-x": e.cut.x, "data-y": e.cut.y }));
      }
      if (e.label && Number.isFinite(Number(e.lx)) && Number.isFinite(Number(e.ly))) {
        const pill = h("span", { class: `el tone-${tone}${e.unsandboxed ? " dashed" : ""}`, "aria-hidden": "true" }, e.label);
        place(pill, num(e.lx), num(e.ly), " translate(-50%, -50%)");
        decor.appendChild(pill);
      }
    },
  };
}


// ---------------------------------------------------------------- the viewport

/**
 * makeCanvas(ui, st, hooks): the viewport of one map. ui is the page's element
 * bag (cv, stage, box, body, legend, strip, replay, replayBtn, resetBtn,
 * miniBtn, mini, rpPlay, rpRange, rpText); st is the page's per-mount state,
 * shared and mutated in place (tf, scale, userZoomed, bounds, W, H, gesture,
 * pointers, parked, swallow, replay, miniOpen, mini, ctl, graph, session,
 * view, sel); hooks are the page's callbacks: draw(isUpdate),
 * applyHover(), markTicks(id), select(id, opts), clear(), reveal(id),
 * alive() (the page is mounted) and page (the kit's page object, whose
 * nodeEls the keyboard walks). makeCanvas attaches its own canvas, minimap
 * and resize listeners; destroy() removes them.
 */
export function makeCanvas(ui, st, hooks) {
  const { draw, applyHover, markTicks, select, clear, reveal, alive, page } = hooks;
  const off = [];

  function listen(target, type, fn, opts) {
    target.addEventListener(type, fn, opts);
    off.push([target, type, fn, opts]);
  }

  // ------------------------------------------------ layout persistence

  function layoutKey() {
    return LAYOUT_KEY + (st.session || "");
  }

  /**
   * loadLayout(): the reader's dragged positions for this session; anything
   * malformed is ignored. Stored as {"t": <ms written>, "p": {id: [x, y]}}.
   */
  function loadLayout() {
    const out = new Map();
    try {
      const raw = localStorage.getItem(layoutKey());
      const val = raw ? JSON.parse(raw) : null;
      const obj = val && typeof val === "object" ? val.p : null;
      if (obj && typeof obj === "object") {
        for (const [id, p] of Object.entries(obj)) {
          if (Array.isArray(p) && p.length === 2 && Number.isFinite(p[0]) && Number.isFinite(p[1]) && Math.abs(p[0]) < 1e5 && Math.abs(p[1]) < 1e5) out.set(id, { x: p[0], y: p[1] });
        }
      }
    } catch (_) {
      /* storage blocked or malformed: auto layout */
    }
    return out;
  }

  function hasLayout() {
    try {
      return !!localStorage.getItem(layoutKey());
    } catch (_) {
      return false;
    }
  }

  function saveLayout(id) {
    if (!st.ctl) return;
    const saved = loadLayout();
    const p = st.ctl.pos(id);
    const a = st.ctl.autoPos(id);
    if (p && a && Math.abs(p.x - a.x) < 0.5 && Math.abs(p.y - a.y) < 0.5) saved.delete(id);
    else if (p) saved.set(id, p);
    try {
      if (saved.size) {
        const p = Object.fromEntries([...saved].map(([k, v]) => [k, [Math.round(v.x * 10) / 10, Math.round(v.y * 10) / 10]]));
        localStorage.setItem(layoutKey(), JSON.stringify({ t: Date.now(), p }));
        pruneLayouts();
      } else localStorage.removeItem(layoutKey());
    } catch (_) {
      /* storage blocked: the layout lasts until the next redraw */
    }
    ui.resetBtn.disabled = !hasLayout();
  }

  /** pruneLayouts(): keep the LAYOUT_KEEP most recently written session layouts; unreadable ones go first. */
  function pruneLayouts() {
    try {
      const keys = [];
      for (let i = 0; i < localStorage.length; i++) {
        const k = localStorage.key(i);
        if (k && k.startsWith(LAYOUT_KEY)) {
          let t = 0;
          try {
            const v = JSON.parse(localStorage.getItem(k));
            t = v && Number.isFinite(v.t) ? v.t : 0;
          } catch (_) {
            t = 0;
          }
          keys.push([k, t]);
        }
      }
      if (keys.length <= LAYOUT_KEEP) return;
      keys.sort((a, b) => b[1] - a[1]);
      for (const [k] of keys.slice(LAYOUT_KEEP)) localStorage.removeItem(k);
    } catch (_) {
      /* storage blocked */
    }
  }

  function resetLayout() {
    try {
      localStorage.removeItem(layoutKey());
    } catch (_) {
      /* nothing stored */
    }
    ui.resetBtn.disabled = true;
    if (st.graph) {
      st.userZoomed = false;
      draw(true);
    }
  }

  // ------------------------------------------------ zoom, fit, pan
  //
  // The viewport is a transform, not a scroll box: screen = canvas × s + t.
  // Pan moves t, zoom changes s around a point, fit frames the content box.

  /**
   * sizeCanvas(): the canvas takes the window's height minus what sits above
   * it and what must stay visible under it (legend, tick strip, an open
   * replay bar), within 380–720 px. The ResizeObserver then refits.
   */
  function sizeCanvas() {
    if (!alive() || !ui.cv || ui.body.hidden) return;
    const top = ui.cv.getBoundingClientRect().top + window.scrollY;
    const gap = 10; // .flow-main gap
    let below = ui.legend.offsetHeight + gap + ui.strip.offsetHeight + 20;
    if (!ui.replay.hidden) below += gap + ui.replay.offsetHeight;
    const hgt = Math.max(CV_MIN_H, Math.min(CV_MAX_H, Math.floor(window.innerHeight - top - below)));
    if (Math.abs(ui.cv.offsetHeight - hgt) >= 1) ui.cv.style.height = `${hgt}px`;
  }

  /**
   * fitBox(): the viewport area content is fitted into, clear of the zoom
   * controls on the right in both views (the timeline fits its drawn
   * content, so its right lane header would sit under them; Plan 05 Task 6).
   */
  function fitBox() {
    const ctl = FIT_CTL;
    return { x: FIT_PAD, y: FIT_PAD, w: Math.max(1, ui.cv.clientWidth - 2 * FIT_PAD - ctl), h: Math.max(1, ui.cv.clientHeight - 2 * FIT_PAD) };
  }

  function fitScale() {
    const b = st.bounds || { w: st.W, h: st.H };
    const box = fitBox();
    const [lo, hi] = FIT[st.view] || FIT.timeline;
    const sw = box.w / b.w;
    const s = Math.min(hi, sw, box.h / b.h);
    if (s >= lo) return s;
    // Topology: rather than clip a column, go below the 13 px floor down to
    // 12 px text to fit the width; the height pans.
    if (st.view === "topology") return Math.max(FIT_TOPOLOGY_LOW, Math.min(lo, sw));
    return lo;
  }

  function fit(byUser) {
    if (!st.W) return;
    const s = fitScale();
    const b = st.bounds || { x: 0, y: 0, w: st.W, h: st.H };
    const box = fitBox();
    // Centre what fits. What does not: the timeline anchors its start (left,
    // top); the topology anchors its right edge, so the Enforcement column
    // stays on screen and the Models side pans.
    let tx;
    if (b.w * s <= box.w) tx = box.x + (box.w - b.w * s) / 2 - b.x * s;
    else if (st.view === "topology") tx = box.x + box.w - (b.x + b.w) * s;
    else tx = box.x - b.x * s;
    const ty = b.h * s <= box.h ? box.y + (box.h - b.h * s) / 2 - b.y * s : box.y - b.y * s;
    st.scale = s;
    st.tf = { s, tx, ty };
    if (byUser) st.userZoomed = false;
    applyTransform();
  }

  /** clampPan(): keep at least 80 px of the content on screen. */
  function clampPan() {
    const b = st.bounds;
    if (!b) return;
    const { s } = st.tf;
    const vw = ui.cv.clientWidth;
    const vh = ui.cv.clientHeight;
    const keep = 80;
    st.tf.tx = Math.min(vw - keep - b.x * s, Math.max(keep - (b.x + b.w) * s, st.tf.tx));
    st.tf.ty = Math.min(vh - keep - b.y * s, Math.max(keep - (b.y + b.h) * s, st.tf.ty));
  }

  function applyTransform() {
    if (!st.W) return;
    clampPan();
    const { s, tx, ty } = st.tf;
    ui.stage.style.transform = `translate(${tx}px, ${ty}px) scale(${s})`;
    // The dot grid lives on the viewport so it never ends while panning.
    ui.cv.style.backgroundSize = `${22 * s}px ${22 * s}px`;
    ui.cv.style.backgroundPosition = `${tx}px ${ty}px`;
    renderMini();
  }

  function zoomBy(f, px, py) {
    if (!st.W) return;
    const ax = px === undefined ? ui.cv.clientWidth / 2 : px;
    const ay = py === undefined ? ui.cv.clientHeight / 2 : py;
    const { s, tx, ty } = st.tf;
    const ns = Math.max(ZOOM_MIN, Math.min(ZOOM_MAX, s * f));
    const cx = (ax - tx) / s;
    const cy = (ay - ty) / s;
    st.scale = ns;
    st.tf = { s: ns, tx: ax - cx * ns, ty: ay - cy * ns };
    st.userZoomed = true;
    applyTransform();
  }

  function local(e) {
    const r = ui.cv.getBoundingClientRect();
    return { x: e.clientX - r.left, y: e.clientY - r.top };
  }

  function onWheel(e) {
    if (!st.W) return;
    e.preventDefault();
    const p = local(e);
    const dy = e.deltaMode === 1 ? e.deltaY * 16 : e.deltaY;
    const dx = e.deltaMode === 1 ? e.deltaX * 16 : e.deltaX;
    // Canvas-tool convention: a wheel or two-finger scroll pans (Shift turns
    // a vertical wheel sideways); ctrl/⌘ + wheel zooms around the pointer,
    // which is also what a trackpad pinch sends.
    if (e.ctrlKey || e.metaKey) {
      zoomBy(Math.exp(-dy * 0.01), p.x, p.y);
    } else {
      const sideways = e.shiftKey && !dx;
      st.tf.tx -= sideways ? dy : dx;
      st.tf.ty -= sideways ? 0 : dy;
      applyTransform();
    }
  }

  // ------------------------------------------------ pointer: drag a node, pan, pinch

  function capture(id) {
    try {
      ui.cv.setPointerCapture(id);
    } catch (_) {
      /* the pointer is already gone */
    }
  }

  function onPointerDown(e) {
    if (e.button !== 0 && e.pointerType === "mouse") return;
    if (e.target.closest && e.target.closest(".ctl, .minimap")) return;
    // Capture only once a press becomes a gesture: a plain click must still
    // reach the node button or edge it started on.
    st.pointers.set(e.pointerId, local(e));
    if (st.pointers.size === 2) {
      for (const id of st.pointers.keys()) capture(id);
      // Second finger: whatever the first one started becomes a pinch.
      const [a, b] = [...st.pointers.values()];
      st.gesture = { kind: "pinch", d: Math.hypot(a.x - b.x, a.y - b.y) || 1, mid: { x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 } };
      return;
    }
    if (st.pointers.size > 2) return;
    const p = local(e);
    const nodeEl = e.target.closest && e.target.closest(".node");
    if (nodeEl && st.ctl && st.ctl.has(nodeEl.dataset.id) && !st.replay) {
      const start = st.ctl.pos(nodeEl.dataset.id);
      st.gesture = { kind: "press", id: nodeEl.dataset.id, x: p.x, y: p.y, start, el: nodeEl };
    } else if (!nodeEl) {
      st.gesture = { kind: "pan-press", x: p.x, y: p.y, tx: st.tf.tx, ty: st.tf.ty };
    }
  }

  function onPointerMove(e) {
    if (!st.pointers.has(e.pointerId)) return;
    const p = local(e);
    st.pointers.set(e.pointerId, p);
    const g = st.gesture;
    if (!g) return;
    if (g.kind === "pinch") {
      if (st.pointers.size < 2) return;
      const [a, b] = [...st.pointers.values()];
      const d = Math.hypot(a.x - b.x, a.y - b.y) || 1;
      const mid = { x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 };
      st.tf.tx += mid.x - g.mid.x;
      st.tf.ty += mid.y - g.mid.y;
      zoomBy(d / g.d, mid.x, mid.y);
      g.d = d;
      g.mid = mid;
      return;
    }
    const dx = p.x - g.x;
    const dy = p.y - g.y;
    if (g.kind === "press" || g.kind === "pan-press") {
      if (Math.hypot(dx, dy) < DRAG_THRESHOLD) return;
      g.kind = g.kind === "press" ? "drag" : "pan";
      capture(e.pointerId);
      ui.cv.classList.add(g.kind === "drag" ? "dragging" : "panning");
      if (g.kind === "pan") applyHover();
    }
    if (g.kind === "drag") {
      const s = st.tf.s;
      st.ctl.moveTo(g.id, g.start.x + dx / s, g.start.y + dy / s);
    } else if (g.kind === "pan") {
      st.tf.tx = g.tx + dx;
      st.tf.ty = g.ty + dy;
      applyTransform();
    }
  }

  function onPointerUp(e) {
    if (!st.pointers.has(e.pointerId)) return;
    st.pointers.delete(e.pointerId);
    const g = st.gesture;
    if (g && g.kind === "pinch") {
      if (st.pointers.size === 0) st.gesture = null;
      return;
    }
    if (st.pointers.size) return;
    st.gesture = null;
    ui.cv.classList.remove("dragging", "panning");
    if (!g) return;
    if (g.kind === "drag") {
      st.swallow = true; // the click that follows this release is not a selection
      setTimeout(() => {
        st.swallow = false;
      }, 0);
      saveLayout(g.id);
      st.bounds = st.ctl.bounds();
      renderMini();
      if (st.parked) {
        st.graph = st.parked;
        st.parked = null;
        draw(true);
      }
    } else if (g.kind === "pan") {
      applyHover();
    }
  }

  /** onCanvasClick: a click on an edge's hit path selects the edge; one on the bare canvas clears nothing. */
  function onCanvasClick(e) {
    const hit = e.target.closest && e.target.closest("path.hit");
    if (hit && hit.dataset && hit.dataset.id && !st.swallow) select(hit.dataset.id, { from: "click" });
  }

  // ------------------------------------------------ minimap

  /** setMini(open, focusBtn): the minimap panel opens beside the controls; closed by default. */
  function setMini(open, focusBtn) {
    st.miniOpen = !!open;
    ui.miniBtn.setAttribute("aria-expanded", String(st.miniOpen));
    if (focusBtn) ui.miniBtn.focus();
    renderMini();
  }

  function renderMini() {
    if (!ui.mini) return;
    const b = st.bounds;
    if (!b || !st.W || !st.graph) {
      ui.mini.hidden = true;
      return;
    }
    const { s, tx, ty } = st.tf;
    const vw = ui.cv.clientWidth;
    const vh = ui.cv.clientHeight;
    const view = { x: -tx / s, y: -ty / s, w: vw / s, h: vh / s };
    // Overflow smaller than MINI_SLACK screen px on every side does not count.
    const m = MINI_SLACK / s;
    const outside = view.x > b.x + m || view.y > b.y + m || view.x + view.w < b.x + b.w - m || view.y + view.h < b.y + b.h - m;
    ui.miniBtn.hidden = !outside;
    if (!outside && st.miniOpen) setMini(false, false);
    ui.mini.hidden = !(outside && st.miniOpen);
    if (ui.mini.hidden) return;
    const W = 140;
    const k = W / b.w;
    const H = Math.max(40, Math.min(100, b.h * k));
    const sk = Math.min(W / b.w, H / b.h);
    const svg = svgEl("svg", { width: W, height: H, viewBox: `${b.x} ${b.y} ${W / sk} ${H / sk}`, focusable: "false" });
    if (st.ctl) {
      const snap = st.ctl.snapshot();
      for (const e of snap.edges) if (!e.off) svg.appendChild(svgEl("line", { class: `mm-edge tone-${cls(e.tone)}`, x1: e.x1, y1: e.y1, x2: e.x2, y2: e.y2, "stroke-width": 2 / sk }));
      for (const n of snap.nodes) if (!n.off) svg.appendChild(svgEl("rect", { class: `mm-node kind-${cls(n.kind)} tone-${cls(n.tone || "none")}`, x: n.x - n.w / 2, y: n.y - n.h / 2, width: n.w, height: n.h, rx: Math.min(n.w, n.h) / 4 }));
    } else {
      for (const n of (st.graph && st.graph.nodes) || []) svg.appendChild(svgEl("rect", { class: `mm-node kind-${cls(n.kind)}`, x: num(n.x) - 6, y: num(n.y) - 6, width: 12, height: 12, rx: 3 }));
    }
    svg.appendChild(svgEl("rect", { class: "mm-view", x: view.x, y: view.y, width: view.w, height: view.h, "stroke-width": 2 / sk }));
    st.mini = { b, sk };
    ui.mini.replaceChildren(svg);
  }

  /** onMiniPointer: a press or drag on the minimap centres the viewport there. */
  function onMiniPointer(e) {
    if (!st.mini) return;
    e.preventDefault();
    e.stopPropagation();
    const r = ui.mini.getBoundingClientRect();
    const cx = st.mini.b.x + (e.clientX - r.left) / st.mini.sk;
    const cy = st.mini.b.y + (e.clientY - r.top) / st.mini.sk;
    const { s } = st.tf;
    st.tf.tx = ui.cv.clientWidth / 2 - cx * s;
    st.tf.ty = ui.cv.clientHeight / 2 - cy * s;
    applyTransform();
  }

  // ------------------------------------------------ replay

  /** replaySet(k): what the first k ticks revealed: nodes, edges, and the node of tick k-1. */
  function replaySet(k) {
    const g = st.graph || {};
    const nodes = new Set();
    const pairs = new Set();
    const ticks = (g.ticks || []).slice(0, k);
    const main = (g.nodes || []).find((n) => n.kind === "agent" && n.role !== "subagent");
    if ((g.nodes || []).some((n) => n.id === "you")) nodes.add("you");
    if (main) nodes.add(main.id);
    const drawn = new Set((g.nodes || []).map((n) => n.id));
    let cur = null;
    for (const t of ticks) {
      cur = null; // the newest tick's node, or none when it has no node on the canvas
      const agent = t.agent || (main && main.id);
      if (agent) nodes.add(agent);
      if (t.node) {
        nodes.add(t.node);
        if (agent) pairs.add(agent + "|" + t.node);
        cur = t.node;
      }
      if (t.skill) {
        const sk = "skill:" + t.skill;
        nodes.add(sk);
        if (t.node) pairs.add(t.node + "|" + sk);
        if (t.ran) {
          nodes.add("sandbox");
          pairs.add(sk + "|sandbox");
          cur = "sandbox";
        } else cur = sk;
      }
      if (cur && !drawn.has(cur)) cur = drawn.has(t.node) ? t.node : null;
    }
    const edges = new Set();
    for (const e of g.edges || []) {
      if (pairs.has(e.from + "|" + e.to)) edges.add(e.id);
      else if (e.kind === "runs_on" && nodes.has(e.to)) {
        nodes.add(e.from);
        edges.add(e.id);
      } else if (e.kind === "prompt" && nodes.has(e.from) && nodes.has(e.to)) edges.add(e.id);
    }
    return { nodes, edges, cur };
  }

  function toggleReplay() {
    if (st.replay) stopReplay();
    else startReplay();
  }

  function startReplay() {
    if (!st.ctl || !st.graph) return;
    st.replay = { k: 0, timer: null };
    ui.replay.hidden = false;
    ui.replayBtn.setAttribute("aria-pressed", "true");
    setReplay(0, true);
    sizeCanvas(); // shorter, so the filled-in replay bar stays on screen
    ui.rpPlay.focus({ preventScroll: true });
  }

  function stopReplay() {
    if (!st.replay) return;
    clearInterval(st.replay.timer);
    st.replay = null;
    ui.replay.hidden = true;
    sizeCanvas();
    ui.replayBtn.setAttribute("aria-pressed", "false");
    ui.rpPlay.textContent = "Play";
    if (st.ctl) st.ctl.reveal(null);
    renderMini();
  }

  function setReplay(k, quiet) {
    if (!st.replay || !st.ctl) return;
    const ticks = (st.graph && st.graph.ticks) || [];
    k = Math.max(0, Math.min(ticks.length, Math.round(num(k))));
    st.replay.k = k;
    const set = replaySet(k);
    st.ctl.reveal(set, set.cur);
    ui.rpRange.max = String(ticks.length);
    ui.rpRange.value = String(k);
    const t = ticks[k - 1];
    ui.rpText.textContent = k === 0 ? `0 of ${ticks.length} calls · the session starts` : `${k} of ${ticks.length} · ${fmt.time(t.ts)} ${t.tool}${t.skill ? " → " + t.skill : ""}${t.policy && t.policy !== "none" ? " · " + (t.policy === "deny" ? "denied" : t.policy) : ""}`;
    if (!quiet && t && t.node) markTicks(t.id);
    if (k >= ticks.length && st.replay.timer) playPause();
    renderMini();
  }

  function stepReplay(d) {
    if (!st.replay) return;
    setReplay(st.replay.k + d);
  }

  function playPause() {
    if (!st.replay) return;
    if (st.replay.timer) {
      clearInterval(st.replay.timer);
      st.replay.timer = null;
      ui.rpPlay.textContent = "Play";
      return;
    }
    const ticks = (st.graph && st.graph.ticks) || [];
    if (st.replay.k >= ticks.length) setReplay(0);
    ui.rpPlay.textContent = "Pause";
    st.replay.timer = setInterval(() => stepReplay(1), REPLAY_MS);
  }

  // ------------------------------------------------ keyboard

  function onCanvasKey(e) {
    if (e.altKey || e.ctrlKey || e.metaKey) return;
    const t = e.target;
    if (t.closest && t.closest(".ctl")) return;
    if (e.key === "+" || e.key === "=") {
      e.preventDefault();
      zoomBy(ZOOM_STEP);
      return;
    }
    if (e.key === "-" || e.key === "_") {
      e.preventDefault();
      zoomBy(1 / ZOOM_STEP);
      return;
    }
    if (e.key === "0") {
      e.preventDefault();
      fit(true);
      return;
    }
    if (!e.key.startsWith("Arrow")) return;
    const cur = t.closest && t.closest(".node");
    if (!cur) return;
    // Topology: arrows move the focused node.
    if (st.ctl && st.ctl.has(cur.dataset.id) && !st.replay) {
      e.preventDefault();
      const step = e.shiftKey ? KEY_STEP_BIG : KEY_STEP;
      const p = st.ctl.pos(cur.dataset.id);
      const dx = e.key === "ArrowLeft" ? -step : e.key === "ArrowRight" ? step : 0;
      const dy = e.key === "ArrowUp" ? -step : e.key === "ArrowDown" ? step : 0;
      st.ctl.moveTo(cur.dataset.id, p.x + dx, p.y + dy);
      saveLayout(cur.dataset.id);
      st.bounds = st.ctl.bounds();
      return;
    }
    // Timeline: arrows walk between events.
    const nodes = ((st.graph && st.graph.nodes) || []).filter((n) => page.nodeEls.has(n.id));
    if (!nodes.length) return;
    e.preventDefault();
    let next = null;
    {
      const me = nodes.find((n) => n.id === cur.dataset.id);
      if (!me) return;
      const col = (n) => Math.round(num(n.x));
      const cols = [...new Set(nodes.map(col))].sort((a, b) => a - b);
      const ci = cols.indexOf(col(me));
      if (e.key === "ArrowUp" || e.key === "ArrowDown") {
        const same = nodes.filter((n) => col(n) === col(me)).sort((a, b) => num(a.y) - num(b.y));
        const i = same.indexOf(me);
        next = same[e.key === "ArrowUp" ? i - 1 : i + 1] || null;
      } else {
        const target = cols[e.key === "ArrowLeft" ? ci - 1 : ci + 1];
        if (target !== undefined) {
          const cand = nodes.filter((n) => col(n) === target);
          cand.sort((a, b) => Math.abs(num(a.y) - num(me.y)) - Math.abs(num(b.y) - num(me.y)));
          next = cand[0] || null;
        }
      }
    }
    if (next) {
      const el = page.nodeEls.get(next.id);
      if (el) {
        el.focus();
        reveal(next.id);
      }
    }
  }

  function onDocKey(e) {
    if (e.key !== "Escape" || !alive()) return;
    if (document.querySelector("dialog[open]")) return;
    if (st.miniOpen) {
      setMini(false, true);
      return;
    }
    if (st.replay && ui.replay.contains(document.activeElement)) {
      stopReplay();
      ui.replayBtn.focus();
      return;
    }
    if (!st.sel) return;
    clear();
  }

  listen(ui.cv, "wheel", onWheel, { passive: false });
  listen(ui.cv, "pointerdown", onPointerDown);
  listen(ui.cv, "pointermove", onPointerMove);
  listen(ui.cv, "pointerup", onPointerUp);
  listen(ui.cv, "pointercancel", onPointerUp);
  listen(ui.cv, "lostpointercapture", onPointerUp);
  listen(ui.cv, "click", onCanvasClick);
  listen(ui.mini, "pointerdown", onMiniPointer);
  listen(ui.mini, "pointermove", (e) => {
    if (e.buttons) onMiniPointer(e);
  });
  listen(ui.box, "keydown", onCanvasKey);
  if (typeof ResizeObserver === "function") {
    const ro = new ResizeObserver(() => {
      if (!st.userZoomed) fit(false);
      else applyTransform();
    });
    ro.observe(ui.cv);
    off.push([{ removeEventListener: () => ro.disconnect() }, "", null]);
  }

  return {
    fit,
    zoomBy,
    applyTransform,
    sizeCanvas,
    resetLayout,
    loadLayout,
    saveLayout,
    hasLayout,
    setMini,
    renderMini,
    setReplay,
    toggleReplay,
    stopReplay,
    stepReplay,
    playPause,
    onKey: onCanvasKey,
    onDocKey,
    destroy() {
      if (st.replay) clearInterval(st.replay.timer);
      for (const [t, type, fn, opts] of off) t.removeEventListener(type, fn, opts);
      off.length = 0;
    },
  };
}
