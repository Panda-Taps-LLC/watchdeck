// Topology view of the Flow page (Spec B §3.9, §5.3), drawn as an
// interactive graph. The server's Graph JSON gives the nodes, their column
// (x) and order within it (y), and the edges with their policy styling; this
// module lays the columns out from the measured label sizes so labels sit
// under their shapes and never overlap, routes every edge from the current
// node positions (so a dragged node keeps its connections), and places each
// edge pill at a point on its edge clear of node bodies, labels and other
// pills. map.js owns the viewport (zoom, pan, drag input, persistence) and
// calls the controller render() returns.

const PAD = 20; // canvas margin around the content
const HEAD = 36; // room for the column headers above the content
const COL_GAP = 36; // minimum horizontal gap between two columns' footprints
const PILL_ROOM = 10; // margin either side of the widest pill in a column gap
const V_GAP = 22; // minimum vertical gap between two footprints in a column
const LAB_GAP_BELOW = 8; // .lab-below sits this far under the shape (map.css)
const LAB_GAP_ABOVE = 6; // .lab-above sits this far over the shape (map.css)
const PORT = 4; // edges start and end this far off the shape's box
const OBSTACLE_MARGIN = 4;

// Server column centres (mapmodel/topology.go) → header words, used when the
// graph carries no `columns` (whose x is the header's, about 28 px left of
// the column centre).
const SERVER_COLS = [
  [60, "Models"],
  [170, "Agents"],
  [430, "Tools"],
  [700, "Skill scripts"],
  [884, "Enforcement"],
];

/** labelSide(n): every label sits under its shape except You's, which sits over it (the prompt edge leaves You downwards). */
function labelSide(n) {
  return n.kind === "you" ? "above" : "below";
}

function headerFor(x, columns, num) {
  const list = Array.isArray(columns) && columns.length ? columns.map((c) => [num(c.x) + 28, String(c.label || "")]) : SERVER_COLS;
  let best = null;
  for (const [cx, word] of list) if (!best || Math.abs(cx - x) < Math.abs(best[0] - x)) best = [cx, word];
  return best && Math.abs(best[0] - x) < 80 ? best[1] : "";
}

// ------------------------------------------------------------ geometry

/** ports(a, b): where the edge leaves a and enters b; horizontal unless the shapes overlap horizontally. */
export function ports(a, b) {
  const dx = b.x - a.x;
  const dy = b.y - a.y;
  if (Math.abs(dx) > (a.w + b.w) / 2 + 12 || Math.abs(dy) < 1) {
    const s = dx >= 0 ? 1 : -1;
    return { x1: a.x + s * (a.w / 2 + PORT), y1: a.y, x2: b.x - s * (b.w / 2 + PORT), y2: b.y, hz: true };
  }
  const s = dy >= 0 ? 1 : -1;
  return { x1: a.x, y1: a.y + s * (a.h / 2 + PORT), x2: b.x, y2: b.y - s * (b.h / 2 + PORT), hz: false };
}

/** curve(p): the cubic's four points; control points sit at the midpoint along the port axis. */
function curve(p) {
  if (p.hz) {
    const mx = (p.x1 + p.x2) / 2;
    return [p.x1, p.y1, mx, p.y1, mx, p.y2, p.x2, p.y2];
  }
  const my = (p.y1 + p.y2) / 2;
  return [p.x1, p.y1, p.x1, my, p.x2, my, p.x2, p.y2];
}

/** loop(a, b): a cubic from a's left side to b's left side, bowing far enough left that its middle clears both columns' labels. */
function loop(a, b) {
  const x1 = a.x - a.w / 2 - PORT;
  const x2 = b.x - b.w / 2 - PORT;
  const left = Math.min(x1, x2);
  const reach = Math.min(a.x - (a.half || a.w / 2), b.x - (b.half || b.w / 2)) - 18; // the label edge to clear
  // A cubic whose control points share x = xc reaches 3/4 of the way to xc at t = 0.5.
  const xc = left - Math.max(36, (left - Math.min(reach, left)) / 0.75);
  return [x1, a.y, xc, a.y, xc, b.y, x2, b.y];
}

function at(c, t) {
  const u = 1 - t;
  const a = u * u * u;
  const b = 3 * u * u * t;
  const d = 3 * u * t * t;
  const e = t * t * t;
  return { x: a * c[0] + b * c[2] + d * c[4] + e * c[6], y: a * c[1] + b * c[3] + d * c[5] + e * c[7] };
}

function tangent(c, t) {
  const u = 1 - t;
  const x = 3 * u * u * (c[2] - c[0]) + 6 * u * t * (c[4] - c[2]) + 3 * t * t * (c[6] - c[4]);
  const y = 3 * u * u * (c[3] - c[1]) + 6 * u * t * (c[5] - c[3]) + 3 * t * t * (c[7] - c[5]);
  const l = Math.hypot(x, y) || 1;
  return { x: x / l, y: y / l };
}

/** split(c, t): the first part of the cubic, [0, t] (de Casteljau). */
function split(c, t) {
  const lerp = (a, b) => a + (b - a) * t;
  const x01 = lerp(c[0], c[2]);
  const y01 = lerp(c[1], c[3]);
  const x12 = lerp(c[2], c[4]);
  const y12 = lerp(c[3], c[5]);
  const x23 = lerp(c[4], c[6]);
  const y23 = lerp(c[5], c[7]);
  const xa = lerp(x01, x12);
  const ya = lerp(y01, y12);
  const xb = lerp(x12, x23);
  const yb = lerp(y12, y23);
  return [c[0], c[1], x01, y01, xa, ya, lerp(xa, xb), lerp(ya, yb)];
}

function length(c) {
  let l = 0;
  let p = at(c, 0);
  for (let i = 1; i <= 16; i++) {
    const q = at(c, i / 16);
    l += Math.hypot(q.x - p.x, q.y - p.y);
    p = q;
  }
  return l;
}

const f1 = (v) => (Math.round(v * 10) / 10).toString();

function pathD(c) {
  if (Math.abs(c[1] - c[7]) < 0.5 && Math.abs(c[1] - c[3]) < 0.5) return `M${f1(c[0])} ${f1(c[1])} H${f1(c[6])}`;
  if (Math.abs(c[0] - c[6]) < 0.5 && Math.abs(c[0] - c[2]) < 0.5) return `M${f1(c[0])} ${f1(c[1])} V${f1(c[7])}`;
  return `M${f1(c[0])} ${f1(c[1])} C${f1(c[2])} ${f1(c[3])} ${f1(c[4])} ${f1(c[5])} ${f1(c[6])} ${f1(c[7])}`;
}

function overlap(a, b) {
  const w = Math.min(a.x + a.w, b.x + b.w) - Math.max(a.x, b.x);
  const h = Math.min(a.y + a.h, b.y + b.h) - Math.max(a.y, b.y);
  return w > 0 && h > 0 ? w * h : 0;
}

function grow(r, m) {
  return { x: r.x - m, y: r.y - m, w: r.w + 2 * m, h: r.h + 2 * m };
}

// ------------------------------------------------------------ render

/**
 * render(g, kit, opts): draws the topology and returns its controller.
 * opts.saved: Map id → {x, y} of positions the reader dragged (validated by map.js).
 */
export function render(g, kit, opts = {}) {
  const { h, num, svgEl, useSym, cls } = kit;
  const saved = opts.saved instanceof Map ? opts.saved : new Map();
  const nodes = (g.nodes || []).slice().sort((a, b) => num(a.x) - num(b.x) || num(a.y) - num(b.y) || String(a.id).localeCompare(String(b.id)));
  const byId = new Map();

  // 1. Nodes (DOM first, so labels can be measured).
  for (const n of nodes) {
    const side = labelSide(n);
    const el = kit.node(n, { lab: side, split: true });
    const lab = el.querySelector(".lab");
    byId.set(n.id, { n, el, lab, side, w: num(n.w, 44), h: num(n.h, 44), x: num(n.x), y: num(n.y), lw: 0, lh: 0 });
  }
  for (const v of byId.values()) {
    v.lw = v.lab ? v.lab.offsetWidth : 0;
    v.lh = v.lab ? v.lab.offsetHeight : 0;
  }

  // 2. Edges (DOM), pills measured.
  const edges = [];
  for (const e of g.edges || []) {
    const a = byId.get(e.from);
    const b = byId.get(e.to);
    if (!a || !b) continue;
    edges.push(makeEdge(e, a, b));
  }

  function makeEdge(e, a, b) {
    const tone = cls(e.tone || "grey");
    const width = Math.max(0.5, Math.min(14, num(e.width, 1.5)));
    const kind = cls(e.kind || "call");
    const parts = { e, a, b, tone, width, kind, els: [] };
    if (e.glow) {
      parts.glow = svgEl("path", { class: `edge glow tone-${tone}`, "stroke-width": (width * 3.2).toFixed(1), "data-id": e.id });
      kit.lines.appendChild(parts.glow);
      parts.els.push(parts.glow);
    }
    const classes = [`edge kind-${kind} tone-${tone}`];
    if (e.flow) classes.push("flow");
    if (e.pending) classes.push("pending");
    const dashed = (e.dash && !e.flow && /^[0-9 .,]+$/.test(String(e.dash))) || e.dotted;
    if (!e.flow && !dashed) classes.push("solid");
    const markerTone = kit.markerTone(tone);
    const marker = !e.cut && !e.flow && markerTone && kind !== "prompt" && kind !== "return" ? `url(#m-${markerTone})` : null;
    const attrs = { class: classes.join(" "), "stroke-width": width, "marker-end": marker, "data-id": e.id };
    if (e.dash && !e.flow && /^[0-9 .,]+$/.test(String(e.dash))) attrs["stroke-dasharray"] = String(e.dash);
    if (e.dotted) attrs["stroke-dasharray"] = "1 5";
    parts.path = svgEl("path", attrs);
    (kind === "call" || kind === "runs_on" || kind === "prompt" ? kit.under : kit.lines).appendChild(parts.path);
    parts.els.push(parts.path);
    parts.hit = svgEl("path", { class: "hit", "data-id": e.id, "stroke-width": Math.max(14, width + 10) });
    kit.hits.appendChild(parts.hit);
    if (e.cut) {
      parts.cut = useSym("g-cut", { class: "cut", width: 26, height: 26 });
      kit.over.appendChild(parts.cut);
      parts.els.push(parts.cut);
    }
    if (e.label) {
      parts.pill = h("span", { class: `el tone-${tone}${e.unsandboxed ? " dashed" : ""}`, "aria-hidden": "true", dataset: { id: e.id } }, e.label);
      kit.decor.appendChild(parts.pill);
      parts.pw = parts.pill.offsetWidth;
      parts.ph = parts.pill.offsetHeight;
    }
    return parts;
  }

  // 3. Columns: x from the measured footprints and the pills between them.
  const colXs = [...new Set(nodes.map((n) => Math.round(num(n.x))))].sort((p, q) => p - q);
  const colOf = new Map();
  const cols = colXs.map((cx, i) => {
    const vs = [...byId.values()].filter((v) => Math.round(v.x) === cx).sort((p, q) => p.y - q.y || String(p.n.id).localeCompare(String(q.n.id)));
    for (const v of vs) colOf.set(v.n.id, i);
    const half = Math.max(...vs.map((v) => Math.max(v.w, v.lw) / 2));
    return { cx, vs, half, word: headerFor(cx, g.columns, num) };
  });
  const gapAfter = cols.map(() => COL_GAP);
  for (const p of edges) {
    if (!p.pill) continue;
    const i = colOf.get(p.a.n.id);
    const j = colOf.get(p.b.n.id);
    const lo = Math.min(i, j);
    if (Math.abs(i - j) === 1) gapAfter[lo] = Math.max(gapAfter[lo], p.pw + 2 * PILL_ROOM - Math.min(cols[i].half - p.a.w / 2, 24) - Math.min(cols[j].half - p.b.w / 2, 24));
  }
  let x = PAD;
  cols.forEach((c, i) => {
    c.x = x + c.half;
    x = c.x + c.half + gapAfter[i];
  });

  // 4. Rows: each column keeps the server's order and spacing as a minimum
  // and is pushed apart until no two footprints touch.
  const top = (v) => (v.side === "above" ? v.h / 2 + LAB_GAP_ABOVE + v.lh : v.h / 2);
  const bottom = (v) => (v.side === "below" ? v.h / 2 + LAB_GAP_BELOW + v.lh : v.h / 2);
  for (const c of cols) {
    let prev = null;
    for (const v of c.vs) {
      v.x = c.x;
      v.half = c.half;
      if (prev) v.y = Math.max(v.y, prev.y + bottom(prev) + V_GAP + top(v));
      prev = v;
    }
  }
  let minTop = Infinity;
  for (const v of byId.values()) minTop = Math.min(minTop, v.y - top(v));
  const dy = PAD + HEAD - minTop;
  for (const v of byId.values()) v.y += dy;
  const auto = new Map([...byId].map(([id, v]) => [id, { x: v.x, y: v.y }]));

  // 5. Saved positions override the auto layout.
  for (const [id, p] of saved) {
    const v = byId.get(id);
    if (v) {
      v.x = p.x;
      v.y = p.y;
    }
  }

  // Column headers.
  // Column headers, centred on their column; the outer two are pulled in so a
  // header wider than its column ("ENFORCEMENT") never widens the content.
  const heads = cols.map((c, i) => {
    const el = h("span", { class: "colh" }, c.word);
    kit.decor.appendChild(el);
    const w = el.offsetWidth;
    let cx = c.x;
    if (w / 2 > c.half && i === cols.length - 1 && i > 0) cx = c.x + c.half - w / 2;
    else if (w / 2 > c.half && i === 0 && cols.length > 1) cx = c.x - c.half + w / 2;
    kit.place(el, cx - w / 2, PAD - 4);
    return { cx, w, h: el.offsetHeight || 14 };
  });

  // ---------------------------------------------------------- placement

  const bodyRect = (v) => ({ x: v.x - v.w / 2, y: v.y - v.h / 2, w: v.w, h: v.h });
  const labRect = (v) =>
    v.side === "above"
      ? { x: v.x - v.lw / 2, y: v.y - v.h / 2 - LAB_GAP_ABOVE - v.lh, w: v.lw, h: v.lh }
      : { x: v.x - v.lw / 2, y: v.y + v.h / 2 + LAB_GAP_BELOW, w: v.lw, h: v.lh };

  function placeNode(v) {
    kit.place(v.el, v.x - v.w / 2, v.y - v.h / 2);
  }

  function routeEdge(p) {
    const pt = ports(p.a, p.b);
    // Stacked nodes: only the prompt edge (You's label sits above You) runs
    // straight down; any other edge loops out to the left of both nodes'
    // labels instead of running through the shapes and labels between them.
    const c = !pt.hz && p.kind !== "prompt" ? loop(p.a, p.b) : curve(pt);
    p.c = c;
    let drawn = c;
    if (p.cut) {
      const len = length(c);
      const tc = 0.72;
      const cp = at(c, tc);
      const tEnd = Math.max(0.05, tc - 15 / Math.max(len, 1));
      drawn = split(c, tEnd);
      p.cut.setAttribute("x", f1(cp.x - 13));
      p.cut.setAttribute("y", f1(cp.y - 13));
      p.cutRect = { x: cp.x - 13, y: cp.y - 13, w: 26, h: 26 };
    }
    const d = pathD(drawn);
    p.path.setAttribute("d", d);
    if (p.glow) p.glow.setAttribute("d", d);
    p.hit.setAttribute("d", pathD(c));
  }

  /** placePills(): each pill at the first candidate point on its edge that clears every obstacle, else the least-overlapping one. */
  function placePills() {
    const obstacles = [];
    for (const v of byId.values()) {
      if (v.off) continue;
      obstacles.push(grow(bodyRect(v), OBSTACLE_MARGIN));
      if (v.lw) obstacles.push(grow(labRect(v), 2));
    }
    for (const p of edges) if (p.cutRect && !p.off) obstacles.push(p.cutRect);
    const ts = [0.5, 0.42, 0.58, 0.34, 0.66, 0.26, 0.74, 0.18, 0.82];
    const offs = [-1, 1, -1.9, 1.9, 0];
    for (const p of edges) {
      if (!p.pill) continue;
      const base = p.cut ? ts.map((t) => t * 0.8) : ts;
      let best = null;
      for (const t of base) {
        const q = at(p.c, t);
        const tg = tangent(p.c, t);
        const nx = -tg.y;
        const ny = tg.x;
        // "Up" for a horizontal edge: the normal pointing to smaller y.
        const sgn = ny > 0 ? -1 : 1;
        for (const o of offs) {
          const d = o * (p.ph / 2 + 5);
          const cx = q.x + sgn * nx * d;
          const cy = q.y + sgn * ny * d;
          const r = { x: cx - p.pw / 2, y: cy - p.ph / 2, w: p.pw, h: p.ph };
          let cost = 0;
          for (const ob of obstacles) cost += overlap(r, ob);
          if (!best || cost < best.cost) best = { cost, cx, cy, r };
          if (cost === 0) break;
        }
        if (best && best.cost === 0) break;
      }
      p.pr = best.r;
      kit.place(p.pill, best.cx, best.cy, " translate(-50%, -50%)");
      if (!p.off) obstacles.push(grow(best.r, 2));
    }
  }

  function layoutAll() {
    for (const v of byId.values()) placeNode(v);
    for (const p of edges) routeEdge(p);
    placePills();
  }
  layoutAll();

  if (!nodes.some((n) => n.kind === "skill" || n.kind === "sandbox") && nodes.length) {
    const b = bounds();
    kit.decor.appendChild(kit.place(h("span", { class: "cv-note" }, "No skill script ran in this session."), b.x, b.y + b.h + 16));
  }

  // ---------------------------------------------------------- controller

  function bounds() {
    let x0 = Infinity;
    let y0 = Infinity;
    let x1 = -Infinity;
    let y1 = -Infinity;
    const add = (r) => {
      x0 = Math.min(x0, r.x);
      y0 = Math.min(y0, r.y);
      x1 = Math.max(x1, r.x + r.w);
      y1 = Math.max(y1, r.y + r.h);
    };
    for (const v of byId.values()) {
      add(bodyRect(v));
      if (v.lw) add(labRect(v));
    }
    for (const p of edges) {
      if (p.pr) add(p.pr);
      if (p.c) {
        const m = at(p.c, 0.5);
        add({ x: m.x - 2, y: m.y - 2, w: 4, h: 4 });
      }
    }
    for (const { cx, w, h: hh } of heads) add({ x: cx - w / 2, y: PAD - 4, w, h: hh });
    if (!Number.isFinite(x0)) return { x: 0, y: 0, w: kit.W, h: kit.H };
    return { x: x0 - 12, y: y0 - 12, w: x1 - x0 + 24, h: y1 - y0 + 24 };
  }

  const incident = new Map();
  for (const p of edges) {
    for (const id of [p.a.n.id, p.b.n.id]) {
      if (!incident.has(id)) incident.set(id, []);
      incident.get(id).push(p);
    }
  }

  let frame = 0;
  const dirty = new Set();
  function flush() {
    frame = 0;
    for (const id of dirty) {
      const v = byId.get(id);
      if (v) placeNode(v);
      for (const p of incident.get(id) || []) routeEdge(p);
    }
    dirty.clear();
    placePills();
    if (opts.onMove) opts.onMove();
  }

  return {
    has: (id) => byId.has(id),
    pos: (id) => {
      const v = byId.get(id);
      return v ? { x: v.x, y: v.y } : null;
    },
    autoPos: (id) => auto.get(id) || null,
    /** moveTo(id, x, y): moves a node; edges and pills follow on the next animation frame. */
    moveTo(id, nx, ny) {
      const v = byId.get(id);
      if (!v || !Number.isFinite(nx) || !Number.isFinite(ny)) return;
      v.x = nx;
      v.y = ny;
      dirty.add(id);
      if (!frame) frame = requestAnimationFrame(flush);
    },
    bounds,
    /** neighbours(id): the node, its adjacent nodes and incident edge ids. */
    neighbours(id) {
      const ns = new Set([id]);
      const es = new Set();
      for (const p of incident.get(id) || []) {
        es.add(p.e.id);
        ns.add(p.a.n.id);
        ns.add(p.b.n.id);
      }
      return { nodes: ns, edges: es };
    },
    edgeEnds(id) {
      const p = edges.find((x) => x.e.id === id);
      return p ? { nodes: new Set([p.a.n.id, p.b.n.id]), edges: new Set([id]) } : null;
    },
    /** mark(cls, set): toggles a class on nodes and edge parts (ids in set.nodes / set.edges); null clears. */
    mark(name, set) {
      for (const [id, v] of byId) v.el.classList.toggle(name, !!set && set.nodes.has(id));
      for (const p of edges) {
        const on = !!set && set.edges.has(p.e.id);
        for (const el of p.els) el.classList.toggle(name, on);
        if (p.pill) p.pill.classList.toggle(name, on);
      }
    },
    /** reveal(set): replay visibility; null shows everything. Pills of hidden edges leave the obstacle set. */
    reveal(set, current) {
      for (const [id, v] of byId) {
        v.off = !!set && !set.nodes.has(id);
        v.el.classList.toggle("rp-off", v.off);
        v.el.classList.toggle("rp-cur", !!set && id === current);
      }
      for (const p of edges) {
        p.off = !!set && !set.edges.has(p.e.id);
        for (const el of [...p.els, p.hit]) el.classList.toggle("rp-off", p.off);
        if (p.pill) p.pill.classList.toggle("rp-off", p.off);
      }
      placePills();
    },
    /** snapshot(): shapes for the minimap. */
    snapshot() {
      return {
        nodes: [...byId.values()].map((v) => ({ id: v.n.id, x: v.x, y: v.y, w: v.w, h: v.h, kind: v.n.kind, tone: v.n.tone, off: !!v.off })),
        edges: edges.map((p) => ({ x1: p.c[0], y1: p.c[1], x2: p.c[6], y2: p.c[7], tone: p.tone, off: !!p.off })),
      };
    },
  };
}
