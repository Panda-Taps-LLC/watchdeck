// Sessions page (M5.5): every Claude Code session the machine knows, across
// every project: "Live now" (the live lane map from livemap.js over the
// live and idle cards), then a filterable, searchable table; a row opens its
// map (#/sessions/<id>). liveCard is exported for the Home page.
// With a session id in the route (#/sessions/<id>[/timeline]) the page shows
// that session's map instead (map.js mapView); update() switches between the
// two without a page reload.
// Data: GET /api/sessions, /api/projects, /api/search (all through api.get,
// so the token stays in the Authorization header). Live updates arrive as
// store "event" nudges from app.js's stream(); polling every 15 s is the
// fallback. All DOM through h(); the CSP forbids inline styles. Every
// on-screen string comes from COPY.sessions (copy.js).
import { api, registerPage, store, fmt, slots, h, icon, replace, ApiError, live } from "./app.js";
import { COPY } from "./copy.js";
import { mapView } from "./map.js";
import { mountLiveMap } from "./livemap.js";

const C = COPY.sessions;

const PAGE = 100;
const LIVE_CARDS = 12;
const POLL_MS = 15000;
const SEARCH_DEBOUNCE_MS = 250;
const NUDGE_DEBOUNCE_MS = 400;
const FILTER_KEY = "watchdeck.sessions.filters.v1";
const STATES = [
  ["", C.states.any],
  ["live", C.states.live],
  ["idle", C.states.idle],
  ["ended", C.states.ended],
  ["unknown", C.states.unknown],
];
const STATE_WORD = C.stateWord;
const STATE_LIGHT = { live: "ok", idle: "ask", ended: "off", unknown: "off" };

function flowHash(id) {
  return "#/sessions/" + encodeURIComponent(id);
}

/** rich(parts): strings and {code} parts (COPY rich text) as nodes. */
function rich(parts) {
  return (Array.isArray(parts) ? parts : [parts]).map((p) => (p && typeof p === "object" ? h("code", null, p.code) : String(p)));
}

function loadFilters() {
  try {
    const v = JSON.parse(sessionStorage.getItem(FILTER_KEY) || "null");
    if (v && typeof v === "object") return v;
  } catch (_) {
    /* storage blocked or a bad value: defaults */
  }
  return {};
}

function saveFilters(f) {
  try {
    sessionStorage.setItem(FILTER_KEY, JSON.stringify(f));
  } catch (_) {
    /* storage blocked: filters last for this visit only */
  }
}

/** localDayStart("2026-10-13", end): RFC3339 of local midnight (the next one when end). */
function localDay(v, end) {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(v || "");
  if (!m) return "";
  const d = new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]) + (end ? 1 : 0));
  return Number.isNaN(d.getTime()) ? "" : d.toISOString();
}

/**
 * marked(text, q): text with every case-insensitive occurrence of q in
 * <mark>, as text nodes and elements (never markup). The query is escaped
 * into a RegExp with the "iu" flags, so the match length comes from the
 * text itself (lowercasing can change a string's length, which a plain
 * indexOf on lowercased copies would get wrong outside ASCII).
 */
function marked(text, q) {
  const s = String(text || "");
  if (!q) return [s];
  let re;
  try {
    re = new RegExp(q.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "giu");
  } catch (_) {
    return [s];
  }
  const out = [];
  let i = 0;
  for (const m of s.matchAll(re)) {
    if (!m[0]) break;
    if (m.index > i) out.push(s.slice(i, m.index));
    out.push(h("mark", null, m[0]));
    i = m.index + m[0].length;
  }
  if (i < s.length) out.push(s.slice(i));
  return out;
}

function stateBadge(state) {
  const s = state || "unknown";
  return h("span", { class: `sx-state ${s}` }, h("span", { class: `light sm ${STATE_LIGHT[s] || "off"}`, "aria-hidden": "true" }), STATE_WORD[s] || s);
}

/** denyCount(n, d): a small red "n denied" (no chip); the last denial's label and time in the tooltip and for screen readers. */
function denyCount(count, d, short) {
  const why = d ? C.deny.last(d.label, d.skill, fmt.ago(d.ts)) : "";
  return h(
    "span",
    { class: "sx-deny", title: C.deny.title(count, why, d ? fmt.time(d.ts) : "") },
    short ? String(count) : C.deny.word(count),
    short ? h("span", { class: "sr" }, C.deny.srShort(why)) : why ? h("span", { class: "sr" }, C.deny.srLong(why)) : null,
  );
}

/**
 * liveCard(s): one Live now card for a session row of GET /api/sessions
 * (project name, title, branch · model, running skill, denials, a link to
 * its map). Exported: the Home page shows the same cards.
 */
export function liveCard(s) {
  const st = s.state || "unknown";
  const model = (s.models || [])[0];
  const d = s.last_denial;
  const denials = s.denials || (d ? 1 : 0);
  const meta = [s.branch, model].filter(Boolean).join(" · ");
  const name = s.project_name || s.project || C.card.session;
  return h(
    "article",
    { class: `card sx-live ${st}`, "aria-label": C.card.label(s.project_name || C.card.session, st) },
    h(
      "div",
      { class: "row sx-top" },
      h("span", { class: `light ${STATE_LIGHT[st] || "off"}`, title: st, "aria-hidden": "true" }),
      h("span", { class: "card-title sx-name", title: s.project || "" }, name),
      h("span", { class: "grow" }),
      h("span", { class: "src nowrap" }, st === "live" ? C.card.live : C.card.idle(fmt.ago(s.last_ts))),
    ),
    s.title ? h("p", { class: "sx-title" }, s.title) : h("p", { class: "sx-title muted" }, C.card.untitled),
    meta || s.running_skill || denials
      ? h(
          "div",
          { class: "row sx-meta" },
          meta ? h("span", { class: "src mono", title: [s.branch ? C.card.branch(s.branch) : "", model ? C.card.model(model) : ""].filter(Boolean).join(" · ") }, meta) : null,
          s.running_skill ? h("span", { class: "tag ok", title: C.card.runningTitle }, C.card.running, s.running_skill) : null,
          denials ? denyCount(denials, d, false) : null,
        )
      : null,
    h(
      "div",
      { class: "row sx-foot" },
      h("span", { class: "src mono sx-path", title: s.project || "" }, s.project || ""),
      h("a", { class: "btn small", href: flowHash(s.id), "aria-label": C.card.openLabel(s.project_name) }, icon("flow", 13), C.card.open),
    ),
  );
}

function sessionsPage() {
  let root = null;
  let unsub = null;
  let timer = null;
  let nudgeTimer = null;
  let searchTimer = null;
  let listCtl = null; // AbortController of the in-flight table request
  let laneMap = null; // mountLiveMap() handle while the list is shown
  let pageCtx = null;
  let seq = 0;
  let f = {};
  const n = {}; // nodes
  const data = { rows: [], next: "", total: 0, transcripts: true, searchDisabled: false, live: [], idle: [], projects: [], loaded: false, error: null };

  // ------------------------------------------------ requests

  function query(cursor) {
    const p = new URLSearchParams();
    if (f.project) p.set("project", f.project);
    if (f.state) p.set("state", f.state);
    if (f.denials) p.set("denials", "1");
    const since = localDay(f.since, false);
    const until = localDay(f.until, true);
    if (since) p.set("since", since);
    if (until) p.set("until", until);
    if (f.q) p.set("q", f.q);
    if (cursor) p.set("cursor", cursor);
    p.set("limit", String(PAGE));
    return "/api/sessions?" + p.toString();
  }

  /** loadTable(more): first page (replacing rows) or the next page. Aborts an older request. */
  async function loadTable(more = false) {
    if (listCtl) listCtl.abort();
    const ctl = new AbortController();
    listCtl = ctl;
    const my = ++seq;
    if (!more) n.count.textContent = f.q ? C.searching : C.loading;
    try {
      const res = await api.fetch(query(more ? data.next : ""), { method: "GET", signal: ctl.signal });
      const body = await res.json().catch(() => null);
      if (my !== seq || !root) return;
      if (!res.ok) throw new ApiError(res.status, (body && body.error) || `${res.status}`);
      data.rows = more ? data.rows.concat(body.sessions || []) : body.sessions || [];
      data.next = body.next_cursor || "";
      data.total = body.total || 0;
      data.transcripts = body.transcripts !== false;
      data.searchDisabled = !!body.search_disabled;
      data.loaded = true;
      data.error = null;
    } catch (e) {
      if (e && e.name === "AbortError") return;
      if (e instanceof ApiError && e.status === 401) return;
      if (my !== seq || !root) return;
      data.error = e.message || C.requestFailed;
    } finally {
      if (listCtl === ctl) listCtl = null;
    }
    renderTable();
  }

  /**
   * loadLive(): the live and idle cards, and the lane map's lanes. Live has
   * one source, the catalog's lifecycle state (state=live). With nothing
   * live, the newest row of the whole catalog is the newest non-live one
   * (rows come newest first), which dates the lane map's "last ended".
   */
  async function loadLive() {
    let ok = false;
    try {
      const [lv, idle] = await Promise.all([api.get(`/api/sessions?state=live&limit=${LIVE_CARDS}`), api.get(`/api/sessions?state=idle&limit=${LIVE_CARDS}`)]);
      if (!root) return;
      data.live = (lv && lv.sessions) || [];
      data.idle = (idle && idle.sessions) || [];
      data.lastEnded = "";
      if (!data.live.length) {
        const newest = await api.get("/api/sessions?limit=1");
        if (!root) return;
        const r = ((newest && newest.sessions) || [])[0];
        data.lastEnded = (r && r.state !== "live" && r.last_ts) || "";
      }
      ok = true;
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) return;
      if (!root) return;
    }
    if (ok && laneMap) laneMap.setSessions(data.live, data.lastEnded);
    renderLive();
  }

  async function loadProjects() {
    try {
      const r = await api.get("/api/projects");
      if (!root) return;
      data.projects = (r && r.projects) || [];
    } catch (_) {
      /* the select keeps what it had */
    }
    renderProjects();
  }

  function reloadAll() {
    loadLive();
    loadProjects();
    loadTable(false);
  }

  function nudge() {
    clearTimeout(nudgeTimer);
    nudgeTimer = setTimeout(() => {
      if (!document.hidden) reloadAll();
    }, NUDGE_DEBOUNCE_MS);
  }

  // ------------------------------------------------ rendering

  function renderStreamState() {
    if (!n.streamState) return;
    n.streamState.replaceChildren(
      h("span", { class: `light sm ${live.connected ? "ok" : "off"}`, "aria-hidden": "true" }),
      live.connected ? C.stream.on : C.stream.off,
    );
    n.streamState.title = live.connected ? C.stream.onTitle : C.stream.offTitle;
  }

  function renderLive() {
    if (!n.live) return;
    const cards = data.live.concat(data.idle);
    if (!cards.length) {
      replace(
        n.live,
        // The lane map above already says nothing is live and when the last one ended.
        h("div", { class: "sx-none" }, h("p", { class: "muted small" }, rich(C.noneHelp))),
      );
      return;
    }
    replace(n.live, cards.map(liveCard));
  }

  function renderProjects() {
    if (!n.project) return;
    const cur = f.project || "";
    const opts = [h("option", { value: "" }, C.allProjects)];
    let seen = !cur;
    for (const p of data.projects) {
      if (p.project === cur) seen = true;
      opts.push(h("option", { value: p.project }, C.projectOption(p.name || p.project, p.sessions, p.live, p.project)));
    }
    if (!seen) opts.push(h("option", { value: cur }, cur));
    replace(n.project, opts);
    n.project.value = cur;
  }

  function emptyState() {
    if (data.error) return h("div", { class: "banner deny" }, C.listFailed(data.error));
    if (data.searchDisabled) {
      return h(
        "div",
        { class: "card empty" },
        icon("search", 28),
        h("p", { class: "ink" }, C.searchOff),
        h("p", { class: "muted small" }, C.searchOffText),
      );
    }
    if (isFiltered()) {
      return h(
        "div",
        { class: "card empty" },
        icon("search", 28),
        h("p", { class: "ink" }, f.q ? C.noMatchQuery(f.q) : C.noMatch),
        h("button", { type: "button", class: "btn ghost small", on: { click: clearFilters } }, C.clearFilters),
      );
    }
    return h(
      "div",
      { class: "card empty sx-first" },
      icon("shield", 28),
      h("p", { class: "ink" }, C.noSessions),
      h(
        "ol",
        { class: "list small sx-steps" },
        C.firstSteps.map((step) => h("li", null, rich(step))),
      ),
      data.transcripts ? null : h("p", { class: "muted small" }, C.noTranscripts),
    );
  }

  // Columns: State, Session (project, then branch · model, path on hover), Title, Last active, Tools, Denials.
  const COLUMNS = [
    ["state", ""],
    ["session", ""],
    ["title", "sx-titlecell"],
    ["last", ""],
    ["tools", "num sx-tools"],
    ["denials", "num"],
  ];

  function row(s) {
    const st = s.state || "unknown";
    const model = (s.models || [])[0] || "";
    const title = s.title || (s.direct ? C.byHand : "");
    const meta = [s.branch, model].filter(Boolean).join(" · ");
    const cells = [
      h("td", { class: "nowrap" }, stateBadge(st)),
      h(
        "td",
        { class: "sx-projcell", title: s.project || "" },
        h("a", { class: "plain", href: flowHash(s.id), "aria-label": C.rowLabel(s.project_name || C.card.session, title) }, s.project_name || s.project || s.id.slice(0, 8)),
        h("div", { class: "src mono sx-path" }, meta || s.project || ""),
      ),
      h(
        "td",
        { class: "sx-titlecell" },
        h("div", { class: "sx-title" }, title || h("span", { class: "muted" }, C.dash)),
        s.snippet ? h("div", { class: "sx-snippet" }, "…", marked(s.snippet, f.q), "…") : null,
      ),
      h("td", { class: "nowrap src", title: s.last_ts ? new Date(s.last_ts).toLocaleString() : "" }, s.last_ts ? fmt.ago(s.last_ts) : C.dash),
      h("td", { class: "nowrap num sx-tools" }, s.tool_calls ? String(s.tool_calls) : h("span", { class: "muted" }, C.zero)),
      h("td", { class: "nowrap num" }, s.denials ? denyCount(s.denials, s.last_denial, true) : h("span", { class: "muted" }, C.zero)),
    ];
    return h("tr", { class: "click", on: { click: (e) => onRowClick(e, s) } }, cells);
  }

  function onRowClick(e, s) {
    if (e.target.closest("a, button")) return; // the link handles itself
    if (window.getSelection && String(window.getSelection())) return; // selecting text is not a click
    location.hash = flowHash(s.id);
  }

  function renderTable() {
    if (!n.table) return;
    const shown = data.rows.length;
    n.count.textContent = data.loaded ? (data.total === shown ? C.count(data.total) : C.countOf(shown, data.total)) : "";
    if (!data.rows.length) {
      replace(n.table, data.loaded || data.error ? emptyState() : h("div", { class: "card empty" }, h("p", { class: "muted" }, C.indexing)));
      n.more.hidden = true;
      return;
    }
    const head = h(
      "tr",
      null,
      COLUMNS.map(([k, cls]) => h("th", { scope: "col", class: cls || null }, k === "title" && f.q ? C.columns.titleMatch : C.columns[k])),
    );
    replace(n.table, h("div", { class: "table-wrap" }, h("table", { class: "table sx-table" }, h("caption", { class: "sr" }, C.caption), h("thead", null, head), h("tbody", null, data.rows.map(row)))));
    n.more.hidden = !data.next;
  }

  // ------------------------------------------------ filters

  function isFiltered() {
    return !!(f.project || f.state || f.denials || f.since || f.until || f.q);
  }

  /** syncControls(): Clear shows only while a filter is on; the Dates summary names an active range. */
  function syncControls() {
    if (n.clear) n.clear.hidden = !isFiltered();
    if (n.datesLabel) {
      const on = !!(f.since || f.until);
      n.datesLabel.textContent = on ? C.dateRange(f.since, f.until) : C.dates;
      n.dates.classList.toggle("on", on);
    }
  }

  function onDocClick(e) {
    if (n.dates && n.dates.open && !n.dates.contains(e.target)) n.dates.open = false;
  }

  function setFilter(patch, debounce = false) {
    Object.assign(f, patch);
    saveFilters(f);
    syncControls();
    clearTimeout(searchTimer);
    if (debounce) searchTimer = setTimeout(() => loadTable(false), SEARCH_DEBOUNCE_MS);
    else loadTable(false);
  }

  function clearFilters() {
    f = {};
    saveFilters(f);
    n.state.value = "";
    n.project.value = "";
    n.denials.checked = false;
    n.since.value = "";
    n.until.value = "";
    n.search.value = "";
    n.dates.open = false;
    syncControls();
    loadTable(false);
  }

  function onKey(e) {
    if (e.key !== "/" || e.ctrlKey || e.metaKey || e.altKey) return;
    const a = document.activeElement;
    if (a && (a.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(a.tagName))) return;
    if (document.querySelector("dialog[open]")) return;
    e.preventDefault();
    n.search.focus();
    n.search.select();
  }

  function build() {
    f = loadFilters();
    n.search = h("input", {
      type: "search",
      id: "sessions-search",
      placeholder: C.searchPlaceholder,
      autocomplete: "off",
      spellcheck: "false",
      maxlength: "256",
      value: f.q || "",
      on: {
        input: () => setFilter({ q: n.search.value.trim() }, true),
        keydown: (e) => {
          if (e.key === "Escape" && n.search.value) {
            n.search.value = "";
            setFilter({ q: "" });
          }
        },
      },
    });
    slots.topSlot.replaceChildren(h("label", { class: "search", for: "sessions-search" }, h("span", { class: "sr" }, C.searchLabel), icon("search"), n.search));

    n.streamState = h("span", { class: "src sx-stream", role: "status" });
    n.lanes = h("div", { class: "sx-lanes" });
    n.live = h("div", { class: "cards sx-cards", "aria-live": "polite" });

    n.project = h("select", { id: "sx-project", on: { change: () => setFilter({ project: n.project.value }) } });
    n.state = h("select", { id: "sx-state", on: { change: () => setFilter({ state: n.state.value }) } }, STATES.map(([v, t]) => h("option", { value: v }, t)));
    n.state.value = f.state || "";
    n.denials = h("input", { type: "checkbox", id: "sx-denials", on: { change: () => setFilter({ denials: n.denials.checked }) } });
    n.denials.checked = !!f.denials;
    n.since = h("input", { type: "date", id: "sx-since", value: f.since || "", on: { change: () => setFilter({ since: n.since.value }) } });
    n.until = h("input", { type: "date", id: "sx-until", value: f.until || "", on: { change: () => setFilter({ until: n.until.value }) } });
    n.count = h("span", { class: "src sx-count", "aria-live": "polite", role: "status" });
    n.clear = h("button", { type: "button", class: "btn link small sx-clear", hidden: true, on: { click: clearFilters } }, C.clearFilters);
    n.datesLabel = h("span", null, C.dates);
    n.dates = h(
      "details",
      {
        class: "sx-more",
        on: {
          keydown: (e) => {
            if (e.key !== "Escape" || !n.dates.open) return;
            e.stopPropagation();
            n.dates.open = false;
            n.dates.querySelector("summary").focus();
          },
        },
      },
      h("summary", { title: C.datesTitle }, n.datesLabel),
      h(
        "div",
        { class: "sx-dates", role: "group", "aria-label": C.dateGroup },
        h("label", { class: "sx-field", for: "sx-since" }, h("span", { class: "lbl" }, C.from), n.since),
        h("label", { class: "sx-field", for: "sx-until" }, h("span", { class: "lbl" }, C.to), n.until),
      ),
    );
    n.table = h("div", { class: "sx-tablehost" });
    n.more = h("button", { type: "button", class: "btn ghost", hidden: true, on: { click: () => loadTable(true) } }, C.loadMore);

    const filters = h(
      "div",
      { class: "toolbar sx-filters", role: "group", "aria-label": C.filtersLabel },
      h("label", { class: "sx-field", for: "sx-project" }, h("span", { class: "sr" }, C.project), n.project),
      h("label", { class: "sx-field", for: "sx-state" }, h("span", { class: "sr" }, C.state), n.state),
      h("label", { class: "check sx-check", for: "sx-denials" }, n.denials, C.hasDenials),
      n.dates,
      n.clear,
      h("span", { class: "grow" }),
      n.count,
    );

    root.append(
      h(
        "div",
        { class: "page-head" },
        h("h1", { class: "h1" }, C.heading),
        h("p", { class: "lead" }, C.lead),
        h("span", { class: "grow" }),
        n.streamState,
      ),
      h("section", { class: "stack", "aria-labelledby": "sx-live-h" }, h("h2", { class: "lbl", id: "sx-live-h" }, C.liveHeading), n.lanes, n.live),
      h("section", { class: "stack", "aria-labelledby": "sx-all-h" }, h("h2", { class: "lbl", id: "sx-all-h" }, C.allHeading), filters, n.table, h("div", { class: "row" }, n.more)),
    );
    laneMap = mountLiveMap(n.lanes, pageCtx);
    renderProjects();
    renderStreamState();
    renderLive();
    renderTable();
    syncControls();
  }

  /** startList(r, ctx): the list into r (the old mount). */
  function startList(r, ctx) {
    root = r;
    pageCtx = ctx;
    build();
    unsub = store.subscribe((ev, _s, payload) => {
      if (ev === "stream") renderStreamState();
      else if (ev === "event" && payload && (payload.name === "session" || payload.name === "index" || payload.name === "activity")) nudge();
    });
    document.addEventListener("keydown", onKey);
    document.addEventListener("click", onDocClick);
    timer = setInterval(() => {
      if (!document.hidden && !live.connected) reloadAll();
    }, POLL_MS);
    reloadAll();
  }

  /** stopList(): the list's timers, requests and listeners stop (the old unmount). */
  function stopList() {
    if (unsub) unsub();
    unsub = null;
    clearInterval(timer);
    clearTimeout(nudgeTimer);
    clearTimeout(searchTimer);
    if (listCtl) listCtl.abort();
    listCtl = null;
    document.removeEventListener("keydown", onKey);
    document.removeEventListener("click", onDocClick);
    if (laneMap) laneMap.destroy();
    laneMap = null;
    slots.topSlot.replaceChildren();
    root = null;
  }

  let pageRoot = null; // the router's root for this page
  let mode = null; // "list" | "detail"
  let map = null; // mapView(), made on the first detail visit

  /** show(params, ctx): segments[0] is a session id → its map; none → the list. */
  function show(params, ctx) {
    const segs = (params && params.segments) || [];
    const id = segs[0];
    if (id) {
      if (mode === "detail") {
        map.update(id, segs[1], params.query);
        return;
      }
      if (mode === "list") stopList();
      pageRoot.replaceChildren();
      slots.topSlot.replaceChildren();
      mode = "detail";
      if (!map) map = mapView(ctx);
      map.mount(pageRoot, id, segs[1], params.query);
      return;
    }
    if (mode === "list") return;
    if (mode === "detail") map.unmount();
    pageRoot.replaceChildren();
    mode = "list";
    startList(pageRoot, ctx);
  }

  return {
    title: C.title,
    mount(r, params, ctx) {
      pageRoot = r;
      mode = null;
      show(params, ctx);
    },
    update(params, ctx) {
      if (!pageRoot) return;
      show(params, ctx);
    },
    unmount() {
      if (mode === "detail") map.unmount();
      else if (mode === "list") stopList();
      mode = null;
      pageRoot = null;
    },
  };
}

registerPage("sessions", sessionsPage());
