// Timeline view of the session map (Spec B §3.10, §5.3): time runs down, one
// lane per agent (with its model), a skill-scripts lane and a sandbox lane.
// Lanes, rows, time ticks and event positions all come from the server; the
// client draws them and emits the event buttons row by row (Tab order).
// Every event built from a call also prints who decided it (the server's
// authority word, as a glyph and a word from copy.js).
import { authorityLabel, authorityGlyph, COPY } from "./copy.js";

const LANE_TITLES = COPY.map.lanes;
const LANE_ICON = { agent: "g-robot", skills: "g-skill-tool", sandbox: "g-lock" };

/**
 * labelSide(n): events with an outgoing policy edge keep their label off the
 * edge: skills above the shield, policy Bash calls up and to the right (rows
 * are 50 px apart, so a label fully above would reach the previous row).
 */
function labelSide(n) {
  if (n.kind === "sandbox") return "below";
  if (n.kind === "skill") return "above";
  if (n.kind === "tool" && (n.tone === "ask" || n.tone === "ok" || n.tone === "deny")) return "upright";
  return "right";
}

function laneHeader(kit, lane) {
  const { h, svgEl, useSym, cls } = kit;
  const kind = cls(lane.kind || "agent");
  const glyph = LANE_ICON[kind] || "g-robot";
  const ico = svgEl("svg", { width: 13, height: 13, viewBox: "0 0 24 24", "aria-hidden": "true", focusable: "false", class: "lane-ico" });
  ico.appendChild(useSym(glyph, { width: 24, height: 24, "stroke-width": 2.2 }));
  const title = String(lane.label || LANE_TITLES[kind] || lane.id || "");
  const head = h("span", { class: `laneh lane-${kind}`, title }, ico, h("span", { class: "lt" }, title));
  if (lane.model) {
    const cpu = svgEl("svg", { width: 13, height: 13, viewBox: "0 0 24 24", "aria-hidden": "true", focusable: "false" });
    cpu.appendChild(useSym("g-cpu", { width: 24, height: 24, "stroke-width": 2 }));
    head.appendChild(h("span", { class: "model" }, cpu, String(lane.model)));
  }
  return head;
}

/**
 * decided(kit, b, word): who decided the event, on its label's title line
 * (a new line would push labels that grow upward into the row above), and in
 * its accessible name.
 */
function decided(kit, b, word) {
  const label = authorityLabel(word);
  const title = b.querySelector(".lab .t");
  if (title) title.appendChild(kit.h("span", { class: `auth auth-${kit.cls(word)}` }, kit.icon(authorityGlyph(word), 11), label));
  b.setAttribute("aria-label", COPY.map.decidedName(b.getAttribute("aria-label") || "", label));
}

export function render(g, kit) {
  const { h, svgEl, num, cls } = kit;
  const W = kit.W;
  const H = kit.H;
  const ticks = Array.isArray(g.ticks_y) ? g.ticks_y : [];
  const lanes = Array.isArray(g.lanes) ? g.lanes : [];

  if (ticks.length) {
    const d = ticks.map((t) => `M100 ${num(t.y)}H${W - 20}`).join("");
    kit.under.appendChild(svgEl("path", { class: "grid", d }));
  }
  for (const lane of lanes) {
    const x = num(lane.x);
    kit.under.appendChild(svgEl("path", { class: "guide", d: `M${x} 48V${H - 20}` }));
    if (lane.spine && Number.isFinite(Number(lane.y0)) && Number.isFinite(Number(lane.y1))) {
      kit.under.appendChild(svgEl("path", { class: `spine spine-${cls(lane.spine)}`, d: `M${x} ${num(lane.y0)}V${num(lane.y1)}` }));
    }
    kit.decor.appendChild(kit.place(laneHeader(kit, lane), x, 0, " translateX(-50%)"));
  }
  for (const t of ticks) {
    const tk = h("span", { class: `tk${t.tone ? " tone-" + cls(t.tone) : ""}` }, String(t.label || ""));
    kit.decor.appendChild(kit.place(tk, 0, num(t.y), " translateY(-50%)"));
  }
  const now = ticks.find((t) => t.label === "now");
  const firstAgent = lanes.find((l) => l.kind === "agent");
  if (now && firstAgent && g.session && g.session.live) {
    const x = num(firstAgent.x);
    const y = num(now.y);
    kit.over.appendChild(svgEl("circle", { class: "now-dot", cx: x, cy: y, r: 7 }));
    kit.over.appendChild(svgEl("circle", { class: "now-ring pulse", cx: x, cy: y, r: 10 }));
  }

  for (const e of g.edges || []) kit.edge(e);

  const nodes = (g.nodes || []).slice().sort((a, b) => num(a.y) - num(b.y) || num(a.x) - num(b.x) || String(a.id).localeCompare(String(b.id)));
  for (const n of nodes) {
    const b = kit.node(n, { lab: labelSide(n) });
    if (n.authority) decided(kit, b, n.authority);
  }

  if (!nodes.length) {
    kit.decor.appendChild(kit.place(h("span", { class: "cv-note" }, COPY.map.noEvents), 24, H - 48));
  }
}
