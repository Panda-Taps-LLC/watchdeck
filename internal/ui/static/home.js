// Home page (registered "home", the default route "#/"). Plan 04 Task 9;
// the rows and the decision sheet from 2026-10-28 (DESIGN section 16).
//
// Four parts, top to bottom:
//   1. One sentence from the protection word (GET /api/status through
//      store.status), the live count and the open Needs you count, with a
//      "Turn it on" button that installs into the user settings through
//      write.js (GET /api/enforce for the confirmation) when nothing of
//      watchdeck's is there yet, else a link to Settings (canInstall).
//   2. Needs you: GET /api/needs items, one cell of rows. A row is one
//      sentence (COPY.home.need.sentence, the item's what in mono), one
//      muted line (who decided, when) and one filled button
//      that opens the item's decision sheet (openSheet): a <dialog> with
//      For (Always, This session, An hour), Rule (the item's fixes) and
//      Where (Everywhere, Only in <project>) popups, the file line, the
//      lesser actions "Just acknowledge" and "Don't show this again", and
//      one filled button whose label follows the choice. The sheet is the
//      confirmation: it names the file, then POSTs /api/needs/<id>
//      (add_rule with fix and scope, allow with for, acknowledge or
//      dismiss; a 403 fetches a fresh token and retries once), then the
//      row fades for 300 ms and an 8 s Undo toast follows (POST undo,
//      which also ends an allow). A leak row's sheet links to its call in
//      the timeline; a skill request's to its drill-in. Refetched on
//      activity, on index events (leak watch) and every 15 s; each
//      response's one-use confirmation token replaces the last one. One
//      GET /api/rules on mount decides the "Show recommended rules" link.
//   3. Live now: liveCard (sessions.js) per row of
//      GET /api/sessions?state=live&limit=12, the one source of "live",
//      plus a last call line.
//   4. Recent decisions: GET /api/recent?limit=12, each row a link into its
//      session's timeline (timelineHash, map.js).
// Every on-screen string is COPY.home (copy.js). This file never imports
// pages.js (the barrel).
import { api, registerPage, h, replace, icon, toast, store, fmt, el, ApiError } from "./app.js";
import { COPY, protectionWord, authorityLabel, authorityGlyph } from "./copy.js";
import { writeWithConfirm, cancelled } from "./write.js";
import { liveCard } from "./sessions.js";
import { timelineHash } from "./map.js";
import { skillHash } from "./shared.js";

const C = COPY.home;
const N = C.need;
const POLL_MS = 15000;
const NUDGE_MS = 300;
const FADE_MS = 300;
const UNDO_MS = 8000;
const LIVE_LIMIT = 12;
const RECENT_LIMIT = 12;
const NEEDS = "/api/needs";

// A recent row's outcome as a small coloured dot (decoration; the row's
// text carries the meaning).
// shadow: observed only, nothing happened, so the light stays grey.
const OUTCOME_LIGHT = { deny: "deny", refused: "deny", ask: "ask", rewrite: "ok", allow: "ok", shadow: "off" };

function needPath(id, project) {
  return NEEDS + "/" + encodeURIComponent(id) + (project ? "?project=" + encodeURIComponent(project) : "");
}

/** skillOf(what): the skill a skill request names ("Bash · canary-request"), or "" for several or none. */
function skillOf(what) {
  const i = String(what || "").indexOf(C.sep);
  const s = i >= 0 ? what.slice(i + C.sep.length) : "";
  return s && !s.includes(",") ? s : "";
}

/** projName(p): the project's name for a sentence: the last part of its path ("~/work/api" → "api"), or "" without one. */
function projName(p) {
  const s = String(p || "").replace(/\/+$/, "");
  if (!s) return "";
  const i = s.lastIndexOf("/");
  return i >= 0 ? s.slice(i + 1) || s : s;
}

/** claudeRule(it): the Claude Code rule an ask item names, as written, or "". */
function claudeRule(it) {
  const id = (it.rule_ids || []).find((x) => x.startsWith("claude-settings/"));
  return id ? id.slice("claude-settings/".length) : "";
}

/** authTag(word): the glyph and the plain label of who decided. */
function authTag(word) {
  return h("span", { class: "home-auth src nowrap" }, icon(authorityGlyph(word), 13), authorityLabel(word));
}

/**
 * sentenceNodes(it, withProject): the row's sentence as nodes: COPY's
 * parts, with the WHAT, RULE and SKILL tokens rendered in mono from the
 * item; the sheet's title leaves the project out (its lead names it).
 */
function sentenceNodes(it, withProject = true) {
  const parts = N.sentence(it, withProject ? projName(it.project) : "");
  return parts.map((p) => {
    if (p === N.WHAT) return h("span", { class: "mono need-what" }, it.what);
    if (p === N.RULE) return h("span", { class: "mono need-what" }, claudeRule(it));
    if (p === N.SKILL) return h("span", { class: "mono need-what" }, skillOf(it.what) || it.what);
    return p;
  });
}

/** choices(it): what the item offers: its first fix's action, whether it can be allowed for a while, and its lesser links. */
function choices(it) {
  const fixes = it.fixes || [];
  const allowFor = it.pausable ? it.allow_for || [] : [];
  const first = fixes[0] || null;
  const fix = first ? (first.request && first.request.action) || "deny" : "";
  const leak = it.kind === "leak";
  // The default verb: the first fix, else a while, else acknowledge.
  let verb = N.acknowledge;
  if (fix === "deny") verb = leak ? N.blockReading : N.keepStopping;
  else if (fix === "ask") verb = N.askNext;
  else if (allowFor.length) verb = N.letThrough;
  return { fixes, allowFor, first, fix, leak, verb };
}

function homePage() {
  let root = null;
  let unsub = null;
  let timer = null;
  let nudgeTimer = null;
  let installing = false;
  let sheet = null; // the open decision sheet: {finish}
  const n = {}; // nodes
  const seq = { needs: 0, live: 0, recent: 0 };
  const data = {
    needs: null, // GET /api/needs body
    needsError: null,
    nonce: "", // the needs routes' one-use confirmation token
    live: null, // live session rows
    liveTotal: 0,
    liveError: null,
    recent: null,
    recentError: null,
    recommended: 0, // recommended rules not installed and not declined
    busy: new Set(), // item ids with a write in flight
    leaving: new Set(), // item ids fading out
  };

  // ------------------------------------------------------------ loads

  function takeNeeds(body) {
    data.needs = body || { items: [], count: 0 };
    data.needsError = null;
    if (body && body.nonce) data.nonce = body.nonce;
  }

  async function loadNeeds() {
    const my = ++seq.needs;
    try {
      const body = await api.get(NEEDS);
      if (!root || my !== seq.needs) return;
      takeNeeds(body);
    } catch (e) {
      if (!root || my !== seq.needs) return;
      if (e instanceof ApiError && e.status === 401) return;
      data.needsError = e.message || String(e);
    }
    renderNeeds();
    renderSentence();
  }

  /** refetchNonce(): a fresh needs token (re-GETs the list). */
  async function refetchNonce() {
    const body = await api.get(NEEDS);
    if (root) {
      seq.needs++;
      takeNeeds(body);
      renderNeeds();
      renderSentence();
    }
    return (body && body.nonce) || "";
  }

  async function loadLive() {
    const my = ++seq.live;
    try {
      const body = await api.get(`/api/sessions?state=live&limit=${LIVE_LIMIT}`);
      if (!root || my !== seq.live) return;
      data.live = (body && body.sessions) || [];
      data.liveTotal = body && typeof body.total === "number" ? body.total : data.live.length;
      data.liveError = null;
    } catch (e) {
      if (!root || my !== seq.live) return;
      if (e instanceof ApiError && e.status === 401) return;
      data.liveError = e.message || String(e);
    }
    renderLive();
    renderSentence();
  }

  async function loadRecent() {
    const my = ++seq.recent;
    try {
      const body = await api.get(`/api/recent?limit=${RECENT_LIMIT}`);
      if (!root || my !== seq.recent) return;
      data.recent = (body && body.items) || [];
      data.recentError = null;
    } catch (e) {
      if (!root || my !== seq.recent) return;
      if (e instanceof ApiError && e.status === 401) return;
      data.recentError = e.message || String(e);
    }
    renderRecent();
  }

  /** loadRules(): once per mount; counts recommended rules still to add. */
  async function loadRules() {
    try {
      const book = await api.get("/api/rules");
      if (!root) return;
      data.recommended = ((book && book.recommended) || []).filter((r) => !r.declined).length;
    } catch (_) {
      data.recommended = 0;
    }
    renderNeeds();
  }

  function reloadAll() {
    loadNeeds();
    loadLive();
    loadRecent();
  }

  /** nudge(fn): run fn once 300 ms after the last nudge; every function nudged meanwhile runs. */
  const nudged = new Set();
  function nudge(fn) {
    nudged.add(fn);
    clearTimeout(nudgeTimer);
    nudgeTimer = setTimeout(() => {
      const fns = [...nudged];
      nudged.clear();
      for (const f of fns) f();
    }, NUDGE_MS);
  }

  // ------------------------------------------------------------ writes

  /**
   * postNeed(id, body, wording, project): POST /api/needs/<id> (with
   * ?project= when the write is scoped to one). On a 403 (the token
   * expired or was spent) it fetches a fresh one and retries once. Returns
   * the answer, or null after a toast.
   */
  async function postNeed(id, body, wording = (msg) => msg, project = "") {
    const send = (nonce) => api.post(needPath(id, project), { ...body, nonce });
    let err = null;
    try {
      return await send(data.nonce);
    } catch (e) {
      err = e;
    }
    if (err instanceof ApiError && err.status === 403) {
      try {
        const fresh = await refetchNonce();
        if (fresh) return await send(fresh);
      } catch (e2) {
        err = e2;
      }
    }
    toast(wording(err && err.status === 403 ? COPY.common.expired : (err && err.message) || ""), "error");
    if (root) loadNeeds(); // a spent token: fetch the next one
    return null;
  }

  /** rowOf(id): the item's <li> now on screen, or null. */
  function rowOf(id) {
    if (!n.needsBody) return null;
    for (const li of n.needsBody.querySelectorAll("li.home-need")) if (li.dataset.id === id) return li;
    return null;
  }

  /**
   * write(item, action, arg): one write from the sheet: add_rule (arg:
   * {fix, scope}), allow (arg: "session" | "1h"), acknowledge or dismiss.
   * Returns the toast's sentence when the write went through, else "".
   */
  async function write(item, action, arg) {
    if (data.busy.has(item.id) || data.leaving.has(item.id)) return "";
    data.busy.add(item.id);
    let done = action === "dismiss" ? (item.kind === "leak" ? C.dismissedLeak(!item.tool_use_id) : C.dismissed) : C.acknowledged;
    let body = { action };
    let project = "";
    if (action === "add_rule") {
      body = { action, fix: arg.fix };
      if (arg.scope === "project") {
        body.scope = "project";
        project = item.project || "";
      }
      done = C.added;
    } else if (action === "allow") {
      body = { action, for: arg };
      done = C.allowed(arg);
    }
    const res = await postNeed(item.id, body, (msg) => msg, project);
    data.busy.delete(item.id);
    if (!res) return "";
    if (res.nonce) data.nonce = res.nonce;
    if (res.warning) toast(res.warning, "");
    return done;
  }

  /** resolved(item, done): after a write: the row fades, the count goes down and Undo is offered. */
  function resolved(item, done) {
    leave(item);
    undoToast(item, done);
  }

  /** leave(item): the row fades for 300 ms, the count goes down, then the list is fetched again (a dismiss can hide more than one row). */
  function leave(item) {
    data.leaving.add(item.id);
    const li = rowOf(item.id);
    let done = false;
    const finish = () => {
      if (done) return;
      done = true;
      data.leaving.delete(item.id);
      if (!root || !data.needs) return;
      const before = (data.needs.items || []).length;
      data.needs.items = (data.needs.items || []).filter((x) => x.id !== item.id);
      if (data.needs.items.length < before) data.needs.count = Math.max(0, (data.needs.count || 0) - 1);
      renderNeeds();
      renderSentence();
      loadNeeds();
    };
    if (li) {
      // The class goes on the row already on screen, so its opacity
      // transitions from 1; the list is rebuilt only once the fade ends
      // (renderNeeds leaves the list alone while a row is leaving). The
      // timeout covers reduced motion, where no transition runs.
      for (const b of li.querySelectorAll("button")) b.disabled = true;
      // Only the row's own opacity: the button's transitions bubble here too.
      const onEnd = (e) => {
        if (e.target !== li || e.propertyName !== "opacity") return;
        li.removeEventListener("transitionend", onEnd);
        finish();
      };
      li.addEventListener("transitionend", onEnd);
      li.classList.add("leaving");
    }
    setTimeout(finish, FADE_MS + 60);
  }

  /**
   * focusAfterToast(): when the Undo toast closes with focus inside it,
   * focus goes to the Needs you heading, which does nothing on Enter. (A
   * row's button would take a repeated Enter and open its sheet.)
   */
  function focusAfterToast() {
    if (root && n.needsHead) n.needsHead.focus();
  }

  /**
   * undoToast(item, message): a toast with an Undo button for 8 s. Focus
   * moves to Undo; the timer pauses while the toast has focus or the
   * pointer, and resumes with the time that was left. Escape closes it.
   * Undo fires once. When the toast closes with focus inside it, focus
   * returns to Needs you.
   */
  function undoToast(item, message) {
    const host = el("toasts");
    if (!host) return;
    let t = null;
    let tid = 0;
    let left = UNDO_MS;
    let since = 0;
    let closed = false;
    let used = false;
    const run = () => {
      since = Date.now();
      tid = setTimeout(() => close(), left);
    };
    const pause = () => {
      if (!tid) return;
      clearTimeout(tid);
      tid = 0;
      left = Math.max(0, left - (Date.now() - since));
    };
    const resume = (focusTo) => {
      if (closed || tid) return;
      if (t.matches(":hover") || (focusTo && t.contains(focusTo))) return;
      left = Math.max(left, 1500); // a moment to read it again
      run();
    };
    const close = () => {
      if (closed) return;
      closed = true;
      clearTimeout(tid);
      const hadFocus = t.contains(document.activeElement);
      t.remove();
      if (hadFocus) focusAfterToast();
    };
    const btn = h(
      "button",
      {
        type: "button",
        class: "btn small ghost home-undo-btn",
        "aria-label": C.undoLabel(item.what),
        on: {
          click: () => {
            if (used) return;
            used = true;
            btn.disabled = true;
            close();
            undo(item);
          },
        },
      },
      C.undo,
    );
    t = h(
      "div",
      {
        class: "toast home-undo",
        role: "status",
        on: {
          mouseenter: pause,
          mouseleave: () => resume(document.activeElement),
          focusin: pause,
          focusout: (e) => resume(e.relatedTarget),
          keydown: (e) => {
            if (e.key === "Escape") close();
          },
        },
      },
      h("span", null, message),
      btn,
    );
    host.appendChild(t);
    run();
    btn.focus();
  }

  async function undo(item) {
    // An undo needs no ?project=: the server reads the project from the
    // resolution it cancels.
    const res = await postNeed(item.id, { action: "undo" }, C.undoFailed);
    if (!res) return;
    if (res.nonce) data.nonce = res.nonce;
    toast(C.undone, "ok");
    if (root) loadNeeds();
  }

  /** install(): "Turn it on": watchdeck into the user settings, confirmed like the Settings page. */
  async function install() {
    if (installing) return;
    installing = true; // from the first click: a second one does nothing
    renderSentence();
    try {
      const S = COPY.settings;
      let enf = null;
      try {
        enf = await api.get("/api/enforce");
      } catch (e) {
        if (!(e instanceof ApiError && e.status === 401)) toast(e.message || String(e), "error");
        return;
      }
      const t = ((enf && enf.targets) || []).find((x) => x.id === "user");
      if (!t) return;
      const lines = [S.installBody];
      if (!t.exists) lines.push(S.newFile);
      const r = await writeWithConfirm({
        title: S.installTitle("user"),
        body: lines,
        file: t.path,
        backup: !!t.exists,
        confirmLabel: S.install,
        path: "/api/enforce",
        payload: { target: "user", action: "install" },
        nonce: enf.nonce,
        refetchNonce: async () => {
          const again = await api.get("/api/enforce");
          return (again && again.nonce) || "";
        },
      });
      if (r === cancelled() || !r.ok) return;
      toast(C.installed, "ok");
      try {
        await store.refreshStatus();
      } catch (_) {
        /* the status event will come with the next poll */
      }
    } finally {
      installing = false;
      renderSentence();
    }
  }

  // ------------------------------------------------------------ the sheet

  /** popup(id, options, value, onChange): a <select class="pop"> in its wrapper; options are [value, label]. */
  function popup(id, options, value, onChange) {
    const sel = h(
      "select",
      { id, class: "pop", on: { change: (e) => onChange(e.target.value) } },
      options.map(([v, label]) => h("option", { value: v, selected: v === value ? true : null }, label)),
    );
    return { wrap: h("span", { class: "pop-wrap" }, sel), sel };
  }

  /**
   * openSheet(it): the item's decision sheet (the A2 board), a modal
   * <dialog> inside the page root. One sheet at a time. Escape or Cancel
   * closes it and focus returns to the row's button; a write that went
   * through closes it and the Undo toast takes focus.
   */
  function openSheet(it) {
    if (sheet || !root) return;
    const ch = choices(it);
    const proj = projName(it.project);
    const ago = fmt.ago(it.ts);
    const st = {
      for: ch.first ? "always" : ch.allowFor[0] || "",
      fix: ch.first ? ch.first.index : -1,
      where: "user",
    };
    let done = false;
    let posting = false;
    const ids = { title: "need-sheet-title", lead: "need-sheet-lead", for: "need-for", rule: "need-rule", where: "need-where" };

    const fixAt = (i) => ch.fixes.find((f) => f.index === i) || null;
    const chosenFix = () => fixAt(st.fix);
    const canProject = () => {
      const f = chosenFix();
      return !!(f && it.project && (f.project_files || []).length);
    };
    const filesOf = () => {
      const f = chosenFix();
      if (!f) return [];
      if (st.where === "project" && canProject()) return f.project_files;
      return f.files && f.files.length ? f.files : f.file ? [f.file] : [];
    };
    /** choice(): what the filled button does: "rule", "allow" or "ack". */
    const choice = () => (st.for === "always" && chosenFix() ? "rule" : st.for && ch.allowFor.includes(st.for) ? "allow" : "ack");
    const primaryLabel = () => {
      const c = choice();
      if (c === "allow") return N.letThrough;
      if (c === "ack") return N.acknowledge;
      const f = chosenFix();
      const action = (f.request && f.request.action) || "deny";
      if (action === "ask") return N.askNext;
      return ch.leak ? N.blockReading : N.keepStopping;
    };

    // The lead: where and when, then the question.
    const question = N.question({ fix: ch.fix, allow: ch.allowFor.length > 0, leak: ch.leak });
    const links = [];
    const skill = it.kind === "skill_request" ? skillOf(it.what) : "";
    if (skill) links.push(h("a", { class: "need-sheet-link", href: skillHash(skill) }, N.openSkill));
    const timeline = it.kind === "leak" && it.session_id ? timelineHash(it.session_id, it.tool_use_id) : "";
    if (timeline) links.push(h("a", { class: "need-sheet-link need-sheet-timeline", href: timeline }, N.openTimeline));

    // The reason box: the item's why (a skill request: what it asked for).
    let why = it.why || "";
    if (it.kind === "skill_request" && (it.ungranted || []).length) why = (it.ungranted || []).map((e) => C.grantWord(e.field, e.value)).join(", ");
    if (ch.leak) why = ""; // the sentence already says it

    const form = h("div", { class: "need-sheet-form" });
    const primary = h("button", { type: "button", class: "btn need-sheet-primary", on: { click: () => submit() } });
    const cancelBtn = h("button", { type: "button", class: "btn ghost", on: { click: () => finish(true) } }, COPY.common.cancel);
    const ackBtn = h("button", { type: "button", class: "btn small need-sheet-ack", on: { click: () => lesser("acknowledge") } }, N.justAck);
    const neverBtn = h(
      "button",
      { type: "button", class: "btn small need-sheet-never", title: ch.leak ? N.neverAgainLeakTitle(!it.tool_use_id) : N.neverAgainTitle, on: { click: () => lesser("dismiss") } },
      N.neverAgain,
    );

    function setBusy(on) {
      posting = on;
      for (const b of dlg.querySelectorAll("button, select")) b.disabled = on;
    }

    /** renderForm(): the popups and lines for the current choice (rebuilt on each change; focus stays on the popup that changed). */
    function renderForm() {
      const kids = [];
      const forOptions = [];
      if (ch.first) forOptions.push(["always", N.forAlways]);
      if (ch.allowFor.includes("session")) forOptions.push(["session", N.forSession]);
      if (ch.allowFor.includes("1h")) forOptions.push(["1h", N.forHour]);
      const grid = [];
      if (forOptions.length > 1) {
        const p = popup(ids.for, forOptions, st.for, (v) => {
          st.for = v;
          renderForm();
          dlg.querySelector("#" + ids.for)?.focus();
        });
        grid.push(h("label", { class: "need-sheet-k", for: ids.for }, N.forLabel), p.wrap);
      }
      if (choice() === "rule") {
        if (ch.fixes.length > 1) {
          const opts = ch.fixes.map((f) => [String(f.index), f.request && f.request.everywhere ? N.ruleEverywhere(f.sentence) : f.sentence]);
          const p = popup(ids.rule, opts, String(st.fix), (v) => {
            st.fix = Number(v);
            if (!canProject()) st.where = "user";
            renderForm();
            dlg.querySelector("#" + ids.rule)?.focus();
          });
          grid.push(h("label", { class: "need-sheet-k", for: ids.rule }, N.ruleLabel), p.wrap);
        } else if (ch.first) {
          grid.push(h("span", { class: "need-sheet-k" }, N.ruleLabel), h("span", { class: "need-sheet-v" }, ch.first.sentence));
        }
        if (canProject()) {
          const p = popup(ids.where, [["user", N.whereEverywhere], ["project", N.whereOnly(proj)]], st.where, (v) => {
            st.where = v;
            renderForm();
            dlg.querySelector("#" + ids.where)?.focus();
          });
          grid.push(h("label", { class: "need-sheet-k", for: ids.where }, N.whereLabel), p.wrap);
        }
        const files = filesOf();
        if (files.length) {
          grid.push(
            h("span", { class: "need-sheet-k" }, files.length > 1 ? N.filesLabel : COPY.common.fileLabel),
            h("span", { class: "need-sheet-v" }, files.map((f, i) => [i ? ", " : null, h("code", null, f)])),
          );
        }
        kids.push(h("div", { class: "need-sheet-grid" }, grid));
        if (files.length) kids.push(h("p", { class: "src need-sheet-backup" }, files.length > 1 ? N.backupAny : N.backupIfAny(files[0])));
      } else if (choice() === "allow") {
        if (grid.length) kids.push(h("div", { class: "need-sheet-grid" }, grid));
        const lines = [];
        if (it.kind === "ask") {
          lines.push(C.allowRules(it.rule_ids || [], st.for));
        } else {
          const by = new Map();
          for (const e of it.ungranted || []) {
            if (!by.has(e.skill)) by.set(e.skill, []);
            by.get(e.skill).push(C.grantWord(e.field, e.value));
          }
          for (const [name, grants] of by) lines.push(C.allowSkill(name, grants));
        }
        lines.push(C.allowStill);
        const file = (data.needs && data.needs.allow_file) || "";
        kids.push(h("div", { class: "need-sheet-allow" }, lines.map((l) => h("p", null, l))));
        if (file) kids.push(h("p", { class: "src need-sheet-backup" }, COPY.common.fileLabel, h("code", null, file), " ", N.backupIfAny(file)));
      } else if (grid.length) {
        kids.push(h("div", { class: "need-sheet-grid" }, grid));
      }
      replace(form, kids);
      primary.textContent = primaryLabel();
      primary.dataset.choice = choice();
      // With nothing to add or allow, the filled button acknowledges and the lesser one is only "Don't show this again".
      ackBtn.hidden = choice() === "ack";
    }

    /** submit(): the filled button: a rule, a while, or an acknowledge. */
    function submit() {
      const c = choice();
      if (c === "rule") return post("add_rule", { fix: st.fix, scope: canProject() ? st.where : "user" });
      if (c === "allow") return post("allow", st.for);
      return post("acknowledge");
    }

    /** lesser(action): "Just acknowledge" or "Don't show this again". */
    function lesser(action) {
      return post(action);
    }

    /**
     * post(action, arg): the write; on success the sheet closes first (a
     * modal keeps focus inside it) and then the row fades and the Undo
     * toast takes focus; on failure the sheet stays with its buttons back.
     */
    async function post(action, arg) {
      if (posting || done) return;
      setBusy(true);
      const msg = await write(it, action, arg);
      if (!msg) {
        if (!done) setBusy(false);
        return;
      }
      // A write that went through always fades the row and offers Undo,
      // even if the sheet was closed meanwhile (the page was unmounted).
      if (!done) finish(false);
      resolved(it, msg);
    }

    /** finish(focus): close and remove the sheet once; focus the row's button again when asked. */
    function finish(focus) {
      if (done) return;
      done = true;
      if (dlg.open) dlg.close();
      dlg.remove();
      sheet = null;
      if (focus && root) {
        const li = rowOf(it.id);
        const b = li && li.querySelector("button.need-decide");
        if (b) b.focus();
        else if (n.needsHead) n.needsHead.focus();
      }
    }

    const dlg = h(
      "dialog",
      {
        class: "dialog need-sheet",
        "aria-labelledby": ids.title,
        "aria-describedby": ids.lead,
        dataset: { kind: it.kind },
        on: {
          close: () => finish(true),
          cancel: (e) => {
            // Escape: close now, so focus can move at once (the queued close
            // event then finds it done). While a write is in flight the
            // sheet stays: its answer decides what happens next.
            e.preventDefault();
            if (posting) return;
            finish(true);
          },
        },
      },
      h(
        "div",
        { class: "need-sheet-head" },
        h("span", { class: "need-sheet-ico", "aria-hidden": "true" }, icon("shield", 24)),
        h(
          "div",
          { class: "need-sheet-text" },
          h("h2", { class: "need-sheet-title", id: ids.title }, sentenceNodes(it, false)), // the lead names the project
          h("p", { class: "need-sheet-lead", id: ids.lead }, N.lead(proj, ago, question), links.length ? " " : null, links),
          why ? h("p", { class: "need-sheet-why" }, why) : null,
          form,
        ),
      ),
      h("div", { class: "dialog-actions need-sheet-actions" }, h("div", { class: "need-sheet-lesser" }, ackBtn, neverBtn), h("div", { class: "need-sheet-main" }, cancelBtn, primary)),
    );
    sheet = { finish };
    renderForm();
    root.appendChild(dlg);
    dlg.showModal();
    const first = dlg.querySelector("select.pop");
    (first || primary).focus();
  }

  // ------------------------------------------------------------ render

  /** keepFocus(node): true while keyboard focus is inside node (a poll then leaves it alone). */
  function keepFocus(node) {
    return node && document.activeElement && node.contains(document.activeElement) && document.activeElement !== node;
  }

  /**
   * canInstall(st): the user-settings install is offered only when those
   * settings hold no watchdeck check at all and a sandbox backend exists.
   * Any other state links to Settings: some checks already in the file (a
   * partial install), checks that run from the plugin or another settings
   * file (protectionWord's "seen in the last 24 h", or only the sandbox
   * exclusion here), or no backend, where an install would double-register
   * next to the plugin or add nothing useful. /api/status has no plugin
   * field, so "partial without a check of ours" stands for the plugin.
   */
  function canInstall(st) {
    const k = (st && st.hook) || {};
    if (st.enforcementAvailable === false || k.error) return false;
    const ours = [k.hookInstalled, k.skillHook, k.deniedHook, k.startHook, k.endHook, k.promptHook].some((v) => v === true);
    return !ours && protectionWord(st) === "off";
  }

  function renderSentence() {
    if (!n.sentence) return;
    const st = store.status;
    const protection = st ? protectionWord(st) : null;
    const counted = data.live !== null && data.needs !== null;
    if (!protection || ((protection === "protected" || protection === "observing") && !counted)) {
      replace(n.sentence, h("p", { class: "home-sentence muted" }, C.checking));
      return;
    }
    const kids = [h("p", { class: "home-sentence" }, C.sentence({ protection, live: data.liveTotal, needs: (data.needs && data.needs.count) || 0 }))];
    if (canInstall(st)) {
      kids.push(h("button", { type: "button", class: "btn", disabled: installing, on: { click: install } }, C.turnOn));
    } else if (protection === "observing") {
      kids.push(h("p", { class: "src" }, COPY.shadow.how, h("code", { class: "mono" }, COPY.shadow.command)));
    } else if (protection !== "protected") {
      kids.push(h("a", { class: "btn ghost", href: "#/settings" }, C.seeSettings));
    }
    replace(n.sentence, kids);
  }

  /** needRow(it): one sentence, one muted line, one button that opens the sheet. */
  function needRow(it) {
    const ch = choices(it);
    const busy = data.busy.has(it.id) || data.leaving.has(it.id);
    const label = authorityLabel(it.authority);
    const ago = fmt.ago(it.ts);
    const meta = N.meta(label, ago); // the reason waits in the sheet's box
    return h(
      "li",
      { class: "home-need" + (data.leaving.has(it.id) ? " leaving" : ""), dataset: { id: it.id, kind: it.kind } },
      h(
        "div",
        { class: "need-text" },
        h("p", { class: "need-sentence" }, sentenceNodes(it)),
        h("p", { class: "need-meta", title: `${label} · ${fmt.time(it.ts)}` }, meta),
      ),
      h("button", { type: "button", class: "btn small need-decide", disabled: busy, "aria-label": N.decideLabel(it.what, ch.verb), on: { click: () => openSheet(it) } }, N.decide(ch.verb)),
    );
  }

  function renderNeeds() {
    if (!n.needsBody) return;
    const d = data.needs;
    const count = d ? d.count || 0 : 0;
    replace(n.needsCount, d && count ? h("span", { class: "count-pill", title: C.needsCount(count) }, String(count)) : null);
    replace(n.needsLink, data.recommended > 0 ? h("a", { class: "btn link small", href: "#/rules", title: C.showRecommendedTitle }, C.showRecommended) : null);
    // A row is fading: leave the list as it is until leave() finishes.
    if (data.leaving.size) return;
    if (keepFocus(n.needsBody)) {
      // Leave a focused row alone; the next refresh without focus redraws.
      const ids = new Set(((d && d.items) || []).map((x) => x.id));
      const shown = [...n.needsBody.querySelectorAll("li.home-need")].map((x) => x.dataset.id);
      if (shown.length === ids.size && shown.every((id) => ids.has(id))) return;
    }
    if (data.needsError && !d) {
      replace(n.needsBody, h("div", { class: "banner deny", role: "alert" }, C.needsFailed(data.needsError)));
      return;
    }
    if (!d) {
      replace(n.needsBody, h("p", { class: "muted" }, C.loading));
      return;
    }
    const items = d.items || [];
    const leakOff = d.leak_watch === false ? h("p", { class: "muted" }, C.leakOff) : null;
    if (d.activity_enabled === false) {
      // Leak watch reads transcripts, not the activity log (Plan 08 D4): its items still show.
      const off = h("p", { class: "muted" }, d.leak_watch ? C.needsOffLeaks : C.needsOff);
      replace(n.needsBody, items.length ? [off, h("ul", { class: "home-needs card" }, items.map(needRow))] : [off, leakOff]);
      return;
    }
    if (!items.length) {
      replace(n.needsBody, [h("p", { class: "muted" }, C.needsNone), leakOff]);
      return;
    }
    replace(n.needsBody, h("ul", { class: "home-needs card" }, items.map(needRow)));
  }

  /** lastLine(s): the session's last denial, else its last call. */
  function lastLine(s) {
    const d = s.last_denial;
    if (d && d.ts) return C.lastDenial(d.label || "", fmt.ago(d.ts));
    if (s.last_ts) return C.lastCall(fmt.ago(s.last_ts));
    return "";
  }

  function renderLive() {
    if (!n.liveBody) return;
    if (data.liveError && !data.live) {
      replace(n.liveBody, h("div", { class: "banner deny", role: "alert" }, data.liveError));
      return;
    }
    if (!data.live) {
      replace(n.liveBody, h("p", { class: "muted" }, C.loading));
      return;
    }
    if (!data.live.length) {
      replace(n.liveBody, h("p", { class: "muted" }, C.noLive));
      return;
    }
    if (keepFocus(n.liveBody)) return;
    replace(
      n.liveBody,
      h(
        "div",
        { class: "cards sx-cards home-cards" },
        data.live.map((s) => {
          const card = liveCard(s);
          const line = lastLine(s);
          if (line) {
            const foot = card.querySelector(".sx-foot");
            const p = h("p", { class: "src home-last" }, line);
            if (foot) card.insertBefore(p, foot);
            else card.appendChild(p);
          }
          return card;
        }),
      ),
    );
  }

  function recentRow(r) {
    const label = authorityLabel(r.authority);
    const what = r.what && r.what !== r.tool ? r.what : "";
    // A record that names several skills has no single timeline node; link the call.
    const skill = r.skill && !r.skill.includes(",") ? r.skill : "";
    const ago = fmt.ago(r.ts);
    return h(
      "li",
      null,
      h(
        "a",
        { class: "home-recent-row", href: timelineHash(r.session_id, r.tool_use_id, skill), "aria-label": C.recentLabel(r.tool, what, label, ago, r.shadow ? C.observed(r.would) : "") },
        h("span", { class: `light sm ${OUTCOME_LIGHT[r.outcome] || "off"}`, "aria-hidden": "true" }),
        h("span", { class: "home-tool mono" }, r.tool),
        what ? h("span", { class: "home-what mono" }, what) : null,
        authTag(r.authority),
        r.shadow ? h("span", { class: "tag none" }, C.observed(r.would)) : null,
        h("span", { class: "grow" }),
        h("span", { class: "src nowrap", title: fmt.time(r.ts) }, ago),
      ),
    );
  }

  function renderRecent() {
    if (!n.recentBody) return;
    if (data.recentError && !data.recent) {
      replace(n.recentBody, h("div", { class: "banner deny", role: "alert" }, C.recentFailed(data.recentError)));
      return;
    }
    if (!data.recent) {
      replace(n.recentBody, h("p", { class: "muted" }, C.loading));
      return;
    }
    if (!data.recent.length) {
      replace(n.recentBody, h("p", { class: "muted" }, C.recentEmpty));
      return;
    }
    if (keepFocus(n.recentBody)) return;
    replace(n.recentBody, h("ol", { class: "home-recent card", "aria-label": C.recentCaption }, data.recent.map(recentRow)));
  }

  function section(id, heading, extra, body) {
    return h("section", { class: "home-section", "aria-labelledby": id }, h("div", { class: "row home-section-head" }, h("h2", { class: "lbl", id }, heading), extra), body);
  }

  function build() {
    n.sentence = h("div", { class: "row home-lead", "aria-live": "polite" });
    n.needsCount = h("span", { class: "home-count", "aria-live": "polite" });
    n.needsLink = h("span", { class: "home-rec" });
    n.needsBody = h("div", { class: "home-body" });
    n.liveBody = h("div", { class: "home-body", "aria-live": "polite" });
    n.recentBody = h("div", { class: "home-body" });
    replace(
      root,
      h("div", { class: "page-head" }, h("h1", { class: "sr" }, C.heading), n.sentence),
      section("home-needs-h", [C.needsHeading, " ", n.needsCount], [h("span", { class: "grow" }), n.needsLink], n.needsBody),
      section("home-live-h", C.liveHeading, null, n.liveBody),
      section("home-recent-h", C.recentHeading, null, n.recentBody),
    );
    n.needsHead = root.querySelector("#home-needs-h");
    if (n.needsHead) n.needsHead.setAttribute("tabindex", "-1"); // focus lands here when the Undo toast closes
    renderSentence();
    renderNeeds();
    renderLive();
    renderRecent();
  }

  return {
    title: C.title,
    mount(r) {
      root = r;
      build();
      unsub = store.subscribe((ev, _s, payload) => {
        if (ev === "status") renderSentence();
        else if (ev === "activity") {
          nudge(loadNeeds);
          nudge(loadRecent);
        } else if (ev === "event" && payload && payload.name === "session") nudge(loadLive);
        else if (ev === "event" && payload && payload.name === "index") nudge(loadNeeds); // leak watch
      });
      timer = setInterval(() => {
        if (!document.hidden) reloadAll();
      }, POLL_MS);
      reloadAll();
      loadRules();
    },
    unmount() {
      if (sheet) sheet.finish(false);
      if (unsub) unsub();
      unsub = null;
      clearInterval(timer);
      clearTimeout(nudgeTimer);
      nudged.clear();
      timer = null;
      root = null;
      for (const k of Object.keys(n)) delete n[k];
      data.busy.clear();
      data.leaving.clear();
    },
  };
}

registerPage("home", homePage());
