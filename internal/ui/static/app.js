// watchdeck dashboard shell (Spec A §1e). Vanilla ES module, no build step,
// no framework, no external requests. Everything that renders goes through
// createElement; the page's CSP forbids inline styles and scripts, so dynamic
// values use classes, data-* attributes and CSSOM properties only.
//
// Exports (the contract the pages build on):
//   api { get, post, fetch }      registerPage(name, def)     store
//   navigate(hash)                fmt { time, ago, shortHash, summary }
//   slots { topSlot, liveSessions }   parseRoute()   LEGACY_ROUTES
// plus helpers pages share: ApiError, h, icon, confirmDialog, toast, el.
//
// Copy (Plan 04, 2026-10-19): every string a person reads comes from
// copy.js. renderShell() fills the shell's text and labels from it at load;
// pages import COPY themselves.
//
// Live updates (M5.5): stream() reads GET /api/events with fetch and a
// streaming body reader, so the token goes in the Authorization header like
// every other call (EventSource cannot send one, and a token never goes in a
// URL). Each server event is passed to store subscribers as ("event",
// {name, data}); connection changes as ("stream", {connected}). Polling
// stays on as the fallback: slower while the stream is up, the old 2 s
// rhythm while it is down.

import { COPY, AUTHORITY_ALL, protectionWord, protectionLabel } from "./copy.js";

const TOKEN_KEY = "watchdeck.token";
const DEFAULT_ROUTE = "#/";
const HOME_PAGE = "home";
const THEME_KEY = "watchdeck.theme";
const THEMES = ["auto", "light", "dark"];
const ACTIVITY_POLL_MS = 2000;
const ACTIVITY_POLL_STREAMING_MS = 15000; // while /api/events is connected; an "activity" nudge polls at once
const STREAM_BACKOFF_MIN_MS = 1000;
const STREAM_BACKOFF_MAX_MS = 60000;
const STREAM_WATCHDOG_FACTOR = 2.5; // no frame for this many keepalive periods: the socket is presumed dead
const STATUS_POLL_MS = 10000;
const ACTIVITY_FIRST_TAIL = 200;
const ACTIVITY_KEEP = 2000;

// ---------------------------------------------------------------- DOM helpers

/** el(id) → the shell element with that id (index.html). */
export function el(id) {
  return document.getElementById(id);
}

/**
 * h(tag, attrs, ...children): build an element. attrs keys: class, id,
 * href, type, title, role, for, value, placeholder, hidden, disabled,
 * tabindex, aria-* / data-* (as written), dataset {k: v}, on {event: fn},
 * style {prop: value} (CSSOM, never a style attribute). Children: strings
 * become text nodes; null/false/undefined are skipped; arrays are flattened.
 */
export function h(tag, attrs, ...children) {
  const node = document.createElement(tag);
  if (attrs) {
    for (const [k, v] of Object.entries(attrs)) {
      if (v === null || v === undefined || v === false) continue;
      if (k === "class") node.className = v;
      else if (k === "dataset") Object.assign(node.dataset, v);
      else if (k === "on") for (const [ev, fn] of Object.entries(v)) node.addEventListener(ev, fn);
      else if (k === "style") Object.assign(node.style, v);
      else if (k === "hidden") node.hidden = true;
      else if (k === "disabled") node.disabled = true;
      else if (k === "value") node.value = v;
      else if (k === "text") node.textContent = v;
      else node.setAttribute(k, v === true ? "" : String(v));
    }
  }
  append(node, children);
  return node;
}

/** replace(node, ...children): clear node and append children (null/false skipped, arrays flattened). */
export function replace(node, ...children) {
  node.replaceChildren();
  append(node, children);
  return node;
}

function append(node, children) {
  for (const c of children) {
    if (c === null || c === undefined || c === false || c === "") continue;
    if (Array.isArray(c)) append(node, c);
    else if (c instanceof Node) node.appendChild(c);
    else node.appendChild(document.createTextNode(String(c)));
  }
}

const ICONS = {
  shield: ["M12 3l8 3v6c0 4.5-3.4 8.2-8 9-4.6-.8-8-4.5-8-9V6l8-3z", "M9 12l2 2 4-4"],
  flow: ["M6 6m-2.5 0a2.5 2.5 0 1 0 5 0a2.5 2.5 0 1 0-5 0", "M18 12m-2.5 0a2.5 2.5 0 1 0 5 0a2.5 2.5 0 1 0-5 0", "M8 18m-2.5 0a2.5 2.5 0 1 0 5 0a2.5 2.5 0 1 0-5 0", "M8 7.5l7.5 3.5M16 13.5l-6 3"],
  search: ["M11 11m-7 0a7 7 0 1 0 14 0a7 7 0 1 0-14 0", "M20 20l-3.5-3.5"],
  warn: ["M12 9v4M12 17h.01", "M10.3 3.9L1.8 18a2 2 0 001.7 3h17a2 2 0 001.7-3L13.7 3.9a2 2 0 00-3.4 0z"],
  check: ["M5 12l4 4L19 6"],
  x: ["M6 6l12 12M18 6L6 18"],
  plus: ["M12 5v14M5 12h14"],
  file: ["M6 3h9l5 5v13H6z", "M14 3v6h6M9 13h6M9 17h6"],
  lock: ["M6 11h12v10H6z", "M9 11V7a3 3 0 016 0v4"],
  refresh: ["M20 12a8 8 0 01-14.5 4.6M4 12a8 8 0 0114.5-4.6", "M20 4v4h-4M4 20v-4h4"],
  external: ["M14 4h6v6", "M20 4l-9 9", "M19 14v5a1 1 0 01-1 1H5a1 1 0 01-1-1V6a1 1 0 011-1h5"],
  // authorityGlyph (copy.js) names these for who decided a call: shield, check, eye, person, box, circle.
  eye: ["M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z", "M12 12m-3 0a3 3 0 1 0 6 0a3 3 0 1 0-6 0"],
  person: ["M12 8m-4 0a4 4 0 1 0 8 0a4 4 0 1 0-8 0", "M4 21a8 8 0 0116 0"],
  box: ["M4 4h16v16H4z", "M9 9h6v6H9z"],
  circle: ["M12 12m-8 0a8 8 0 1 0 16 0a8 8 0 1 0-16 0"],
};

/** icon(name, size): inline SVG with presentation attributes only (CSP-safe). */
export function icon(name, size = 15) {
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("width", size);
  svg.setAttribute("height", size);
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "2");
  svg.setAttribute("stroke-linecap", "round");
  svg.setAttribute("stroke-linejoin", "round");
  svg.setAttribute("aria-hidden", "true");
  for (const d of ICONS[name] || []) {
    const p = document.createElementNS(ns, "path");
    p.setAttribute("d", d);
    svg.appendChild(p);
  }
  return svg;
}

/** toast(message, kind): transient status message; kind "" | "ok" | "error". */
export function toast(message, kind = "") {
  const host = el("toasts");
  if (!host) return;
  const t = h("div", { class: "toast" + (kind ? " " + kind : "") }, message);
  host.appendChild(t);
  setTimeout(() => t.remove(), kind === "error" ? 7000 : 3500);
}

/** pendingConfirm: the open confirm's settle function, or null. */
let pendingConfirm = null;

/**
 * confirmDialog({title, body, confirmLabel, danger, altLabel}) →
 * Promise<boolean | "alt">. body: string or Node (or array). Uses the
 * <dialog> in index.html. altLabel shows a second, lesser action between
 * Cancel and the confirm button; choosing it resolves "alt" (Plan 08: the
 * Rules page's "Only this rule"). Without altLabel that button stays hidden
 * and the answer is a boolean, as before.
 */
export function confirmDialog({ title, body, confirmLabel = COPY.common.confirm, danger = false, altLabel = "" }) {
  const dlg = el("confirm");
  if (!dlg || typeof dlg.showModal !== "function") {
    return Promise.resolve(window.confirm(typeof body === "string" ? `${title}\n\n${body}` : title));
  }
  // A confirm still waiting (Escape closed it, its close event not yet
  // delivered) is cancelled now, so it never stays on the buttons and
  // resolves with the next one's click (Plan 05 Task 6).
  if (pendingConfirm) pendingConfirm(false);
  el("confirm-title").textContent = title;
  const bodyEl = el("confirm-body");
  bodyEl.replaceChildren();
  append(bodyEl, [typeof body === "string" ? h("p", null, body) : body]);
  const ok = el("confirm-ok");
  const cancel = el("confirm-cancel");
  const alt = el("confirm-alt");
  ok.textContent = confirmLabel;
  ok.className = "btn" + (danger ? " red" : "");
  if (alt) {
    alt.textContent = altLabel || "";
    alt.hidden = !altLabel;
  }
  return new Promise((resolve) => {
    const done = (v) => {
      if (pendingConfirm === done) pendingConfirm = null;
      ok.removeEventListener("click", onOk);
      cancel.removeEventListener("click", onCancel);
      if (alt) {
        alt.removeEventListener("click", onAlt);
        alt.hidden = true;
      }
      dlg.removeEventListener("close", onClose);
      dlg.removeEventListener("cancel", onEscape);
      if (dlg.open) dlg.close();
      resolve(v);
    };
    const onOk = () => done(true);
    const onCancel = () => done(false);
    const onAlt = () => done(altLabel ? "alt" : false);
    // A close event that arrives while the dialog is open again belongs to
    // an earlier open: not this one's answer.
    const onClose = () => {
      if (!dlg.open) done(false);
    };
    // Escape fires cancel at once, before the queued close event. done
    // closes the dialog now, so a caller that moves focus after a cancel
    // is not blocked by a modal still open; the late close event then
    // finds this open settled (or a newer one open) and does nothing.
    const onEscape = () => done(false);
    ok.addEventListener("click", onOk);
    cancel.addEventListener("click", onCancel);
    if (alt && altLabel) alt.addEventListener("click", onAlt);
    dlg.addEventListener("close", onClose);
    dlg.addEventListener("cancel", onEscape);
    pendingConfirm = done;
    dlg.showModal();
    cancel.focus();
  });
}

// ---------------------------------------------------------------- shell copy

/** copyAt("nav.home") → the COPY entry at that dotted path, or undefined. */
function copyAt(path) {
  let v = COPY;
  for (const k of path.split(".")) {
    if (v === null || typeof v !== "object" || !Object.prototype.hasOwnProperty.call(v, k)) return undefined;
    v = v[k];
  }
  return v;
}

/** rich(parts): copy.js rich text (strings and {code} parts) as nodes. */
function rich(parts) {
  return (Array.isArray(parts) ? parts : [parts]).map((p) => (p && typeof p === "object" ? h("code", null, p.code) : String(p)));
}

/**
 * renderShell(): fill index.html's strings from copy.js. Each [data-copy]
 * element gets its text, each [data-copy-label] element its aria-label;
 * the token notice gets its rich text. Runs once at load, before the theme
 * toggle and anything else reads the shell.
 */
function renderShell() {
  for (const node of document.querySelectorAll("[data-copy]")) {
    const v = copyAt(node.dataset.copy);
    if (typeof v === "string") node.textContent = v;
  }
  for (const node of document.querySelectorAll("[data-copy-label]")) {
    const v = copyAt(node.dataset.copyLabel);
    if (typeof v === "string") node.setAttribute("aria-label", v);
  }
  const text = el("notice-text");
  if (text) text.replaceChildren(...rich(COPY.common.token.missingText));
  const line = el("hookline");
  if (line) line.title = COPY.pill.checking;
}

renderShell();

// ---------------------------------------------------------------- theme

// Light / dark / auto (2026-10-14). "auto" follows the OS (the
// prefers-color-scheme block in app.css); "light" and "dark" set data-theme
// on <html>, which app.css honours over the OS. The choice is a per-browser
// convenience in localStorage; blocked storage means auto, every time. The
// Flow canvas is dark in every theme (its --cv-* tokens never change).

function themeGet() {
  try {
    const v = localStorage.getItem(THEME_KEY);
    return THEMES.includes(v) ? v : "auto";
  } catch (_) {
    return "auto";
  }
}

function themeApply(v) {
  const root = document.documentElement;
  if (v === "light" || v === "dark") root.dataset.theme = v;
  else delete root.dataset.theme;
}

/** theme(): the stored choice, "auto" | "light" | "dark". */
export function theme() {
  return themeGet();
}

/** setTheme(v): apply and remember (best effort) "auto" | "light" | "dark". */
export function setTheme(v) {
  if (!THEMES.includes(v)) v = "auto";
  themeApply(v);
  try {
    if (v === "auto") localStorage.removeItem(THEME_KEY);
    else localStorage.setItem(THEME_KEY, v);
  } catch (_) {
    /* storage blocked: the choice lasts until the tab closes */
  }
  renderThemeToggle(v);
}

const THEME_LABEL = COPY.common.theme.label;
const THEME_ICON = {
  auto: ["M12 12m-8 0a8 8 0 1 0 16 0a8 8 0 1 0-16 0", "M12 4v16", "M12 4a8 8 0 010 16z"],
  light: ["M12 12m-4 0a4 4 0 1 0 8 0a4 4 0 1 0-8 0", "M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"],
  dark: ["M20 14.5A8 8 0 019.5 4a8 8 0 1010.5 10.5z"],
};

function renderThemeToggle(v) {
  const btn = el("theme-toggle");
  if (!btn) return;
  const next = THEMES[(THEMES.indexOf(v) + 1) % THEMES.length];
  btn.dataset.theme = v;
  const nextWord = COPY.common.theme.word[next];
  btn.setAttribute("aria-label", COPY.common.theme.aria(THEME_LABEL[v], nextWord));
  btn.title = COPY.common.theme.title(THEME_LABEL[v], nextWord);
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  for (const [k, val] of [["width", 16], ["height", 16], ["viewBox", "0 0 24 24"], ["fill", "none"], ["stroke", "currentColor"], ["stroke-width", "2"], ["stroke-linecap", "round"], ["stroke-linejoin", "round"], ["aria-hidden", "true"]]) svg.setAttribute(k, val);
  for (const d of THEME_ICON[v]) {
    const p = document.createElementNS(ns, "path");
    p.setAttribute("d", d);
    svg.appendChild(p);
  }
  const word = document.createElement("span");
  word.className = "theme-word";
  word.textContent = COPY.common.theme.word[v];
  btn.replaceChildren(svg, word);
}

themeApply(themeGet());
{
  const btn = el("theme-toggle");
  if (btn) {
    renderThemeToggle(themeGet());
    btn.addEventListener("click", () => {
      const cur = themeGet();
      setTheme(THEMES[(THEMES.indexOf(cur) + 1) % THEMES.length]);
    });
  }
}

// ---------------------------------------------------------------- token

let token = null;
let locked = false;

// "Remember me on this computer" (opt-in, M5.3): the token is also kept in
// localStorage on this fixed origin (127.0.0.1:<stable port>), so a new tab
// or a browser restart needs no launch link. Off by default: the token then
// lives in this tab's sessionStorage only. A remembered token that the
// server rejects (rotated with watchdeck ui --rotate-token, or another
// state dir) is deleted at once.
function localGet() {
  try {
    return localStorage.getItem(TOKEN_KEY);
  } catch (_) {
    return null;
  }
}

function localSet(v) {
  try {
    if (v) localStorage.setItem(TOKEN_KEY, v);
    else localStorage.removeItem(TOKEN_KEY);
    return true;
  } catch (_) {
    return false;
  }
}

/** Whether this browser remembers the token (localStorage holds it). */
export function remembered() {
  return !!localGet();
}

/** Turn "remember me" on or off; returns false when storage is blocked. */
export function setRemembered(on) {
  return localSet(on ? token : null);
}

function readToken() {
  // Launch URL: 127.0.0.1:<port>/#t=<token> (printed by watchdeck ui). Take it out of the
  // fragment immediately so routes never carry it.
  const m = /^#t=([A-Za-z0-9_-]+)$/.exec(location.hash);
  if (m) {
    try {
      sessionStorage.setItem(TOKEN_KEY, m[1]);
    } catch (_) {
      /* storage blocked: keep the in-memory copy only */
    }
    // A remembered token is replaced by the new launch link's.
    if (remembered()) localSet(m[1]);
    token = m[1];
    history.replaceState(null, "", DEFAULT_ROUTE);
    return;
  }
  // No token in the fragment: this tab's copy, else a remembered one, else
  // any in-memory copy (a launch link adopted while storage is blocked).
  try {
    token = sessionStorage.getItem(TOKEN_KEY) || localGet() || token;
  } catch (_) {
    token = localGet() || token;
  }
}

/** lockOut(title, parts): show the token screen; parts is copy.js rich text. */
function lockOut(title, parts) {
  locked = true;
  stopPolling();
  const notice = el("notice");
  if (title) el("notice-title").textContent = title;
  if (parts) el("notice-text").replaceChildren(...rich(parts));
  notice.hidden = false;
  document.body.classList.add("locked");
  document.title = COPY.nav.brand;
}

// ---------------------------------------------------------------- api

export class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

async function rawFetch(path, init = {}) {
  const headers = new Headers(init.headers || {});
  if (token) headers.set("Authorization", "Bearer " + token);
  const res = await fetch(path, { ...init, headers, credentials: "omit", cache: "no-store" });
  if (res.status === 401) {
    // The token is no good here: forget every stored copy, so a rejected
    // remembered token is never sent again.
    const wasRemembered = remembered();
    localSet(null);
    try {
      sessionStorage.removeItem(TOKEN_KEY);
    } catch (_) {
      /* storage blocked */
    }
    token = null;
    lockOut(COPY.common.token.rejectedTitle, COPY.common.token.rejectedText(wasRemembered));
    throw new ApiError(401, "unauthorized");
  }
  return res;
}

async function jsonOf(res) {
  const text = await res.text();
  let body = null;
  if (text) {
    try {
      body = JSON.parse(text);
    } catch (_) {
      body = null;
    }
  }
  if (!res.ok) {
    const msg = (body && body.error) || `${res.status} ${res.statusText}`.trim();
    throw new ApiError(res.status, msg);
  }
  return body;
}

export const api = {
  /** GET path → parsed JSON. Throws ApiError{status, message}; 401 → token screen. */
  async get(path) {
    return jsonOf(await rawFetch(path, { method: "GET" }));
  },
  /** POST path with a JSON body → parsed JSON. Same errors. */
  async post(path, body) {
    return jsonOf(
      await rawFetch(path, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body === undefined ? {} : body),
      }),
    );
  },
  /** Raw Response with Authorization added and 401 handled (If-None-Match / 304 polling). */
  fetch(path, init) {
    return rawFetch(path, init);
  },
};

// ---------------------------------------------------------------- fmt

function pad2(n) {
  return String(n).padStart(2, "0");
}

export const fmt = {
  /** time(ts): local HH:MM:SS from an RFC3339 string, a Date or epoch ms. */
  time(ts) {
    const d = ts instanceof Date ? ts : new Date(ts);
    if (Number.isNaN(d.getTime())) return "";
    return `${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}`;
  },
  /** ago(ts): "just now", "12 s ago", "3 min ago", "2 h ago", "4 d ago" (COPY.common.ago). */
  ago(ts) {
    const d = ts instanceof Date ? ts : new Date(ts);
    const s = Math.round((Date.now() - d.getTime()) / 1000);
    if (Number.isNaN(s)) return "";
    const a = COPY.common.ago;
    if (s < 5) return a.now;
    if (s < 60) return a.seconds(s);
    if (s < 3600) return a.minutes(Math.floor(s / 60));
    if (s < 86400) return a.hours(Math.floor(s / 3600));
    return a.days(Math.floor(s / 86400));
  },
  /** shortHash(h): first 8 characters. */
  shortHash(hash) {
    return (hash || "").slice(0, 8);
  },
  /** summary(view): manifest.View → "network=… write=… env=… [exec=…]" (uses view.summary when present). */
  summary(view) {
    if (!view) return "";
    if (view.summary) return view.summary;
    const j = (xs) => (xs && xs.length ? xs.join(",") : "-");
    return COPY.common.summary(view.network || "none", j(view.write), j(view.env), view.execAny === false ? j(view.exec) : undefined);
  },
};

// ---------------------------------------------------------------- store

const subscribers = new Set();

export const store = {
  skills: null, // audit.Report (+generatedAt) from /api/skills
  status: null, // /api/status
  activity: { records: [], next: 0 },
  /**
   * subscribe(fn): fn(event, store, payload) with event "skills" | "status" |
   * "activity", or "event" (payload {name, data}: a nudge from GET /api/events)
   * and "stream" (payload {connected}); returns unsubscribe.
   */
  subscribe(fn) {
    subscribers.add(fn);
    return () => subscribers.delete(fn);
  },
  /** refreshSkills(force): reload /api/skills (force=true re-scans with ?refresh=1). */
  async refreshSkills(force = false) {
    const report = await api.get(force ? "/api/skills?refresh=1" : "/api/skills");
    store.skills = report;
    notify("skills");
    return report;
  },
  async refreshStatus() {
    const st = await api.get("/api/status");
    store.status = st;
    renderProtection(st);
    notify("status");
    return st;
  },
};

function notify(event, payload) {
  for (const fn of subscribers) {
    try {
      fn(event, store, payload);
    } catch (e) {
      console.error("subscriber failed", e);
    }
  }
}

/** pick(obj, key): tolerate camelCase, PascalCase and snake_case JSON keys. */
export function pick(obj, key) {
  if (!obj) return undefined;
  if (key in obj) return obj[key];
  const pascal = key[0].toUpperCase() + key.slice(1);
  if (pascal in obj) return obj[pascal];
  const snake = key.replace(/[A-Z]/g, (c) => "_" + c.toLowerCase());
  if (snake in obj) return obj[snake];
  return undefined;
}

const PILL_LIGHT = { protected: "ok", observing: "ask", partial: "ask", off: "off" };

/**
 * renderProtection(st): the header pill from GET /api/status. Text is
 * protectionLabel(protectionWord(st)) plus " · N live" when sessions are
 * live; the tooltip says in plain words what is in place.
 */
function renderProtection(st) {
  const light = el("protect-light");
  const state = el("protect-state");
  const line = el("hookline");
  if (!light || !state) return;
  const word = protectionWord(st);
  light.className = "light sm " + PILL_LIGHT[word];
  state.textContent = protectionLabel(word);
  const live = st && Number(st.live) > 0 ? Number(st.live) : 0;
  if (slots.liveSessions) slots.liveSessions.textContent = live ? COPY.pill.live(live) : "";
  const p = COPY.pill;
  const hook = st && st.hook;
  const details = [];
  if (hook && hook.error) details.push(p.unreadable(hook.error));
  else if (hook) {
    details.push(p.commands(!!hook.hookInstalled));
    details.push(p.skills(!!hook.skillHook));
    details.push(p.denials(!!hook.deniedHook));
    details.push(p.lifecycle(!!(hook.startHook && hook.endHook && hook.promptHook)));
    details.push(p.exclusion(!!hook.excluded));
  }
  if (st && st.enforcementAvailable === false) details.push(p.noBackend(st.platform));
  // Shadow mode names itself in every protection state, partial included.
  if (st && st.shadow === true) details.push(COPY.shadow.pill);
  const last = st && st.activity ? st.activity.lastDecision : "";
  if (last) details.push(p.lastSeen(fmt.time(last), fmt.ago(last)));
  if (hook && !hook.error && word === "partial" && !protectAny(hook)) details.push(p.elsewhere);
  if (hook) details.push(p.settings(hook.path, hook.exists === false));
  if (line) line.title = details.join("\n") || p.unknown;
}

// protectAny(hook): whether any watchdeck registration is in these settings.
function protectAny(hook) {
  return ["hookInstalled", "skillHook", "deniedHook", "startHook", "endHook", "promptHook", "excluded"].some((k) => hook[k] === true);
}

let activityTimer = null;
let activityTimerMs = 0;
let statusTimer = null;
let activityBusy = false;

async function pollActivity() {
  if (activityBusy || locked) return;
  activityBusy = true;
  try {
    const first = store.activity.next === 0;
    const path = first
      ? `/api/activity?after=0&tail=${ACTIVITY_FIRST_TAIL}`
      : `/api/activity?after=${store.activity.next}`;
    const r = await api.get(path);
    let changed = false;
    // A first load (next 0) replaces what is held: next is also 0 right after a
    // rotation leaves no current file, and re-tailing must not duplicate records.
    if (r.reset || (first && store.activity.records.length)) {
      store.activity.records = [];
      changed = true;
    }
    if (Array.isArray(r.records) && r.records.length) {
      store.activity.records.push(...r.records);
      if (store.activity.records.length > ACTIVITY_KEEP) {
        store.activity.records.splice(0, store.activity.records.length - ACTIVITY_KEEP);
      }
      changed = true;
    }
    if (typeof r.next === "number") store.activity.next = r.next;
    store.activity.path = r.path;
    store.activity.enabled = r.enabled;
    store.activity.loaded = true; // the Overview's skeletons end here
    if (changed || first) notify("activity");
  } catch (e) {
    if (!(e instanceof ApiError)) console.warn("activity poll failed", e);
  } finally {
    activityBusy = false;
  }
}

async function pollStatus() {
  if (locked) return;
  try {
    await store.refreshStatus();
  } catch (e) {
    if (!(e instanceof ApiError)) console.warn("status poll failed", e);
  }
}

function startActivityPolling() {
  if (locked) return;
  const ms = live.connected ? ACTIVITY_POLL_STREAMING_MS : ACTIVITY_POLL_MS;
  if (activityTimer && activityTimerMs === ms) return;
  const first = !activityTimer;
  if (activityTimer) clearInterval(activityTimer);
  if (first) pollActivity();
  activityTimer = setInterval(pollActivity, ms);
  activityTimerMs = ms;
}

function stopActivityPolling() {
  if (activityTimer) clearInterval(activityTimer);
  activityTimer = null;
  activityTimerMs = 0;
}

function startPolling() {
  if (locked) return;
  if (document.visibilityState === "visible") {
    startActivityPolling();
    stream();
  }
  if (!statusTimer) {
    pollStatus();
    statusTimer = setInterval(pollStatus, STATUS_POLL_MS);
  }
}

function stopPolling() {
  stopActivityPolling();
  stopStream();
  if (statusTimer) clearInterval(statusTimer);
  statusTimer = null;
}

document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible") {
    startActivityPolling();
    stream();
  } else {
    stopActivityPolling();
    stopStream();
  }
});

// ---------------------------------------------------------------- live updates

/** live: the event stream's state, read by pages ("live updates" vs "polling"). */
export const live = { connected: false, since: null, failures: 0 };

let streamCtl = null; // AbortController of the open stream, null when none
let streamRetry = null; // reconnect timer
let streamWatchdog = null;
let streamKeepMs = 25000;

function setConnected(on) {
  if (live.connected === on) return;
  live.connected = on;
  live.since = on ? new Date() : null;
  // The fallback polls slowly while the stream carries nudges, quickly while it is down.
  if (activityTimer) startActivityPolling();
  notify("stream", { connected: on });
}

function stopStream() {
  if (streamRetry) clearTimeout(streamRetry);
  streamRetry = null;
  if (streamWatchdog) clearTimeout(streamWatchdog);
  streamWatchdog = null;
  if (streamCtl) streamCtl.abort();
  streamCtl = null;
  setConnected(false);
}

function retryStream(ms) {
  if (streamRetry || locked) return;
  streamRetry = setTimeout(() => {
    streamRetry = null;
    stream();
  }, ms);
}

function backoffMs() {
  const n = Math.min(live.failures, 6);
  const ms = Math.min(STREAM_BACKOFF_MAX_MS, STREAM_BACKOFF_MIN_MS * 2 ** n);
  return ms / 2 + Math.random() * (ms / 2); // jitter, so tabs do not reconnect in step
}

function armWatchdog(ctl) {
  if (streamWatchdog) clearTimeout(streamWatchdog);
  streamWatchdog = setTimeout(() => {
    // A half-open socket never errors: no frame (not even a keepalive) for
    // 2.5 periods means the stream is gone. Abort and reconnect.
    if (streamCtl === ctl) ctl.abort();
  }, streamKeepMs * STREAM_WATCHDOG_FACTOR);
}

/**
 * stream(): open GET /api/events (idempotent). Frames are "event: <name>" and
 * "data: <json>" lines ended by a blank line; ":" lines are keepalives. On
 * an error or end it reconnects with exponential backoff (1 s → 60 s, with
 * jitter); a 429 (eight streams already open) honours Retry-After. Polling
 * keeps running throughout, so a page never depends on the stream.
 */
export async function stream() {
  if (streamCtl || streamRetry || locked || !token || document.visibilityState !== "visible") return;
  const ctl = new AbortController();
  streamCtl = ctl;
  let retryAfter = 0;
  try {
    const res = await rawFetch("/api/events", { method: "GET", signal: ctl.signal, headers: { Accept: "text/event-stream" } });
    if (!res.ok || !res.body || typeof res.body.getReader !== "function") {
      if (res.status === 429) retryAfter = (Number(res.headers.get("Retry-After")) || 30) * 1000;
      if (res.status === 404) retryAfter = STREAM_BACKOFF_MAX_MS; // an older server without the stream
      throw new Error(`events: ${res.status}`);
    }
    const reader = res.body.getReader();
    const dec = new TextDecoder();
    let buf = "";
    armWatchdog(ctl);
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      armWatchdog(ctl);
      buf += dec.decode(value, { stream: true });
      let cut;
      while ((cut = buf.indexOf("\n\n")) >= 0) {
        const block = buf.slice(0, cut);
        buf = buf.slice(cut + 2);
        let name = "";
        let data = "";
        for (const line of block.split("\n")) {
          if (line.startsWith("event: ")) name = line.slice(7);
          else if (line.startsWith("data: ")) data += line.slice(6);
        }
        if (!name) continue; // a keepalive comment or a retry line
        let payload = null;
        try {
          payload = data ? JSON.parse(data) : null;
        } catch (_) {
          payload = null;
        }
        if (name === "hello") {
          if (payload && Number(payload.keepalive_ms) > 0) streamKeepMs = Number(payload.keepalive_ms);
          live.failures = 0;
          setConnected(true);
          armWatchdog(ctl);
          continue;
        }
        if (name === "activity") pollActivity();
        notify("event", { name, data: payload });
      }
    }
  } catch (e) {
    if (e instanceof ApiError && e.status === 401) return; // lockOut already ran
  } finally {
    if (streamCtl === ctl) {
      streamCtl = null;
      if (streamWatchdog) clearTimeout(streamWatchdog);
      streamWatchdog = null;
      setConnected(false);
      if (!locked && document.visibilityState === "visible") {
        live.failures++;
        retryStream(retryAfter || backoffMs());
      }
    }
  }
}

// ---------------------------------------------------------------- slots

export const slots = {
  /** Top bar middle: a page may mount its search box here (cleared on unmount). */
  topSlot: el("top-slot"),
  /** The pill's " · N live" part. renderProtection writes it from /api/status; pages only read it. */
  liveSessions: el("live-sessions"),
};

// ---------------------------------------------------------------- pages & router

const pages = new Map();
let current = null; // { name, def, root }
let booted = false;

/**
 * registerPage(name, {title, mount(root, params, ctx), unmount(), update?(params, ctx)}).
 * name: "home" | "sessions" | "rules" | "settings" (later tasks add more).
 * params is parseRoute()'s {page, segments, query, hash} plus path. update
 * is optional: when the route changes within the same page it is called
 * instead of unmount+mount.
 */
export function registerPage(name, def) {
  pages.set(name, def);
  if (booted) route();
}

/** navigate(hash): go to "#/", "#/sessions/<id>", "#/rules", ... */
export function navigate(hash) {
  if (!hash.startsWith("#")) hash = "#" + (hash.startsWith("/") ? "" : "/") + hash;
  if (location.hash === hash) route();
  else location.hash = hash;
}

function decodeSegment(s) {
  try {
    return decodeURIComponent(s);
  } catch (_) {
    return s;
  }
}

/**
 * parseRoute(hash = location.hash) → {page, segments, query, hash}.
 * page: the first segment ("home" for "#/" and "#"); segments: the rest,
 * each decoded; query: a plain object from the text after the first "?"
 * (which is cut from the last segment); hash: the raw fragment.
 *   "#/sessions/abc/timeline?a=hook,user&n=ev:x" →
 *   {page: "sessions", segments: ["abc", "timeline"], query: {a: "hook,user", n: "ev:x"}}
 */
export function parseRoute(hash = location.hash) {
  const raw = hash || "";
  let body = raw.startsWith("#/") ? raw.slice(2) : raw.startsWith("#") ? raw.slice(1) : "";
  let qs = "";
  const qi = body.indexOf("?");
  if (qi >= 0) {
    qs = body.slice(qi + 1);
    body = body.slice(0, qi);
  }
  const parts = body.split("/").filter(Boolean).map(decodeSegment);
  const query = Object.fromEntries(new URLSearchParams(qs));
  return { page: parts[0] || HOME_PAGE, segments: parts.slice(1), query, hash: raw };
}

// encodeHash(s): a route segment or query value, with ":" and "," kept readable.
function encodeHash(s) {
  return encodeURIComponent(s).replace(/%3A/gi, ":").replace(/%2C/gi, ",");
}

// flowTarget(id, timeline, query): the session page for an old Flow link.
// n= (the selected node) is carried over; hide_none=1 or no hide_none
// becomes the authority filter without "none"; hide_none=0 adds nothing.
function flowTarget(id, timeline, query) {
  if (!id) return "#/sessions";
  const q = [];
  if (query.hide_none !== "0") q.push("a=" + AUTHORITY_ALL.filter((w) => w !== "none").join(","));
  if (query.n) q.push("n=" + encodeHash(query.n));
  return "#/sessions/" + encodeHash(id) + (timeline ? "/timeline" : "") + (q.length ? "?" + q.join("&") : "");
}

/**
 * LEGACY_ROUTES: old first segment → (segments, query) => new hash. route()
 * consults it before the pages and replaces the hash, so links from old
 * toasts, the README and bookmarks still land.
 */
export const LEGACY_ROUTES = {
  overview: () => "#/",
  skills: (segments) => (segments[0] ? "#/rules/skill/" + encodeHash(segments[0]) : "#/rules"),
  grants: () => "#/rules",
  enforce: () => "#/settings",
  flow: (segments, query) => {
    const [first, second] = segments;
    if (first === "topology") return flowTarget(second, false, query);
    if (first === "timeline") return flowTarget(second, true, query);
    return flowTarget(first, false, query);
  },
};

function ctxFor() {
  return { api, store, fmt, navigate, slots, h, icon, confirmDialog, toast, el, pick, ApiError };
}

function route(redirected = false) {
  if (locked) return;
  const r = parseRoute();
  const page = r.page;
  if (!redirected && Object.prototype.hasOwnProperty.call(LEGACY_ROUTES, page)) {
    history.replaceState(null, "", LEGACY_ROUTES[page](r.segments, r.query));
    return route(true);
  }
  const params = { ...r, path: "/" + [page, ...r.segments].join("/") };
  if (!pages.has(page)) {
    if (pages.has(HOME_PAGE)) history.replaceState(null, "", DEFAULT_ROUTE);
    if (page !== HOME_PAGE && pages.has(HOME_PAGE)) return route(true);
    return;
  }
  const def = pages.get(page);
  const main = el("page");
  for (const a of document.querySelectorAll(".top [data-page]")) {
    if (a.dataset.page === page) a.setAttribute("aria-current", "page");
    else a.removeAttribute("aria-current");
  }
  document.title = COPY.common.pageTitle(def.title || page);
  if (current && current.name === page && typeof def.update === "function") {
    def.update(params, ctxFor());
    return;
  }
  if (current) {
    try {
      current.def.unmount && current.def.unmount();
    } catch (e) {
      console.error("unmount failed", e);
    }
    current.root.remove();
    slots.topSlot.replaceChildren();
  }
  const root = h("div", { class: `page page-${page}` });
  main.replaceChildren(root);
  current = { name: page, def, root };
  try {
    def.mount(root, params, ctxFor());
  } catch (e) {
    console.error("mount failed", e);
    root.replaceChildren(h("div", { class: "banner deny" }, COPY.common.pageFailed(page, e.message)));
  }
}

window.addEventListener("hashchange", () => {
  const hash = location.hash;
  // A new launch link pasted into an open tab: adopt the token.
  if (/^#t=/.test(hash)) {
    readToken();
    if (locked) {
      locked = false;
      el("notice").hidden = true;
      document.body.classList.remove("locked");
    }
    // A tab that opened without a token never imported the pages: boot now
    // (its readToken keeps the token just adopted; startPolling is idempotent).
    if (!booted) {
      boot();
      return;
    }
    startPolling();
    route();
    return;
  }
  // Only "#/..." fragments are routes. In-page anchors such as the skip
  // link's "#page" must not reset the route to the home page.
  if (!hash.startsWith("#/")) return;
  route();
});

// The skip link moves focus to <main> without touching the fragment.
const skipLink = document.querySelector("a.skip");
if (skipLink) {
  skipLink.addEventListener("click", (e) => {
    e.preventDefault();
    const main = el("page");
    if (main) {
      main.focus();
      main.scrollIntoView({ block: "start" });
    }
  });
}

// ---------------------------------------------------------------- boot

async function boot() {
  readToken();
  if (!token) {
    lockOut();
    return;
  }
  if (!location.hash || !location.hash.startsWith("#/")) history.replaceState(null, "", DEFAULT_ROUTE);
  // pages.js is the barrel that registers the pages; dynamic import so this
  // module is fully initialised before any page calls registerPage.
  try {
    await import("./pages.js");
  } catch (e) {
    console.error("pages failed to load", e);
    el("page").replaceChildren(h("div", { class: "banner deny" }, COPY.common.pagesFailed(e.message)));
  }
  booted = true;
  route();
  startPolling();
}

boot();
