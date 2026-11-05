// Rules page (registered "rules"): every rule that limits an agent on this
// machine, in the rulebook's five groups (GET /api/rules), with the
// Recommended block on top while any recommended rule is missing, and two
// drill-ins: "#/rules/skill/<name>" (skill-detail.js; "*" is the defaults
// for every skill) and "#/rules/mcp/<name>" (read-only).
//
// Controls per row: a native rule watchdeck added → Remove; a built-in pack
// rule → an on/off switch; a policy-file regex rule and the first row of a
// skill, command, MCP server, tool or agent entry → Remove (the second says
// every entry of that thing goes); later entry rows → nothing; any other
// row → nothing, with "edit <file> by hand" on hover. The sandbox group
// also lists, client-side, each skill with scripts that has no row of its
// own (from the skills audit) and each MCP server watchdeck wraps (GET
// /api/mcp). A row id renders once. Every write goes through write.js.
//
// Add rule opens a sheet (a modal dialog): a kind, one or two fields, a
// live preview of the plan the server builds (POST /api/rules/propose), and
// a confirmed write of the request alone (POST /api/rules {add}). For a
// path or a domain "Cover every route" is on by default (Plan 08 D8): the
// request carries everywhere and the preview lists every rule it adds.
//
// Plan 08 adds, around the list: a caption saying what the rule counts
// cover (GET /api/rules/stats) and a count chip on built-in, own and Claude
// Code Bash block or ask rows that are on (D11); a "Try a call" box in the
// page head, before Add rule, that asks the saved rules about one call
// (POST /api/rules/try, read-only, no confirmation; D12) and links each
// matched rule to its row; a "part of" chip on rows added together to
// cover every route, whose Remove offers "Remove all N" (remove_intent) or
// "Only this rule" (remove) in one confirm (R5); and a Temporary notice
// above the groups listing paused rules and timed grants with "End now"
// (end_temporary). The page head (title, try box, Add rule) is built once
// per mount and kept across list renders, so typing in the try box never
// loses focus to a render.
//
// The server's kind words include ones the copy lint keeps out of string
// literals, so they are derived from unquoted object keys ("_" → "-").
import { api, registerPage, store, fmt, h, icon, toast, replace } from "./app.js";
import { COPY, groupTitle, ownerLabel, enforcementLabel, scopeLabel, setHome, tildify } from "./copy.js";
import { writeWithConfirm, cancelled } from "./write.js";
import { mountSkillDetail } from "./skill-detail.js";
import { hasScripts, postRulePreview, postTry, skillHash } from "./shared.js";

const C = COPY.rules;
const RULES = "/api/rules";
const RECOMMENDED = "/api/rules/recommended";
const STATS = "/api/rules/stats";
const BUILTIN = "$defaults";

const WIRE = Object.freeze(
  Object.fromEntries(Object.keys({ pack: 1, hook_regex: 1, subject: 1, hook_gate: 1 }).map((k) => [k, k.replace(/_/g, "-")])),
);
const NATIVE_PREFIX = "native:";
// The try answer's enforcement words (the activity log's) as the rulebook's,
// for enforcementLabel: watchdeck's own check, or the OS sandbox a skill
// script runs in.
const TRY_ENFORCEMENT = Object.freeze({ gate: WIRE.hook_gate, sandbox: "os" });
// The Add rule sheet's kinds (COPY.rules.sheet.kinds) and path tools.
const SHEET_KINDS = ["block", "ask", "path", "domain", "mcp", "pack"];
const PATH_TOOLS = ["Both", "Read", "Edit"];
const ADD_ID = "rules-add";
// The try box: the kinds of call POST /api/rules/try takes, in its order.
const TRY_WHATS = ["command", "read", "edit", "write", "url", "mcp", "skill"];
const TRY_INPUT = "rules-try-value";
const TRY_RESULT = "rules-try-result";
// Claude Code block and ask rows: the only Claude Code rows with counts,
// and only for Bash (D11).
const NATIVE_COUNTED = new Set(["native-deny", "native-ask"]);
// How long a row the try box pointed at stays highlighted.
const HIT_MS = 3000;

function has(obj, k) {
  return Object.prototype.hasOwnProperty.call(obj, k);
}

/** subjectParts(id) → {kind, name, entry} for a policy-file entry row id, else null (split as the server does: at most three parts). */
function subjectParts(id) {
  const prefix = WIRE.subject + ":";
  if (!String(id).startsWith(prefix)) return null;
  const rest = id.slice(prefix.length);
  const i = rest.indexOf(":");
  if (i < 0) return null;
  const kind = rest.slice(0, i);
  const tail = rest.slice(i + 1);
  const j = tail.indexOf(":");
  return j < 0 ? { kind, name: tail, entry: false } : { kind, name: tail.slice(0, j), entry: true };
}

function kindWord(k) {
  return has(C.kinds, k) ? C.kinds[k] : k;
}

function mcpHref(name) {
  return "#/rules/mcp/" + encodeURIComponent(name);
}

function rulesPage() {
  let root = null;
  let view = null; // "list" | "skill" | "mcp"
  let viewName = null;
  let book = null; // GET /api/rules
  let bookError = null;
  let mcp = null; // GET /api/mcp
  let mcpError = null;
  let showDeclined = false;
  let busy = false;
  let detail = null; // mountSkillDetail handle
  let unsub = null;
  let gen = 0; // bumps on every view change; late answers for an old view are dropped
  let sheet = null; // {finish(focus)} while the Add rule sheet is open
  let renderPending = false; // a list render waited for the sheet to close
  let stats = null; // GET /api/rules/stats, or null (not loaded, or it failed: no chips)
  let shell = null; // {head, body, input, result}: the list view's kept head and the body renders fill
  let trySeq = 0; // bumps on every try; a late answer for an older one is dropped
  let hitTimer = null;

  // ------------------------------------------------------------ data

  async function loadBook() {
    const g = gen;
    try {
      const b = await api.get(RULES);
      if (g !== gen) return book ? book.nonce : "";
      book = b;
      bookError = null;
      setHome(b.home || "");
    } catch (e) {
      if (g !== gen) return "";
      bookError = e.message;
    }
    if (view === "list") renderList();
    return book ? book.nonce : "";
  }

  async function loadMCP() {
    const g = gen;
    try {
      const m = await api.get("/api/mcp");
      if (g !== gen) return;
      mcp = m;
      mcpError = null;
    } catch (e) {
      if (g !== gen) return;
      mcpError = e.message;
    }
    if (view === "list") renderList();
    if (view === "mcp") renderMCP();
  }

  /** loadStats(): the rule counts; a failure leaves no chips and no caption (the counts are extra). */
  async function loadStats() {
    const g = gen;
    try {
      const st = await api.get(STATS);
      if (g !== gen) return;
      stats = st;
    } catch (_) {
      if (g !== gen) return;
      stats = null;
    }
    if (view === "list") renderList();
  }

  /** write(opts): one confirmed write with the page's current token; reloads the rules afterwards. */
  async function write(opts) {
    if (busy || !book) return cancelled();
    const r = await writeWithConfirm({
      ...opts,
      nonce: book.nonce,
      refetchNonce: loadBook,
      onStart: () => {
        busy = true;
      },
    });
    busy = false;
    if (r === cancelled()) return r;
    if (r.ok && r.data && r.data.nonce) book.nonce = r.data.nonce;
    await loadBook();
    store.refreshStatus().catch(() => {});
    return r;
  }

  function fileFor(scope) {
    const f = ((book && book.files) || []).find((x) => x.scope === scope);
    return f ? f.path : "";
  }

  // ------------------------------------------------------------ actions

  /** showWarning(r): the recommended install's optional warning (its reconcile failed; the install still ran). */
  function showWarning(r) {
    if (r.ok && r.data && typeof r.data.warning === "string" && r.data.warning) toast(C.recommendedWarning(r.data.warning), "error");
  }

  async function install(rule) {
    const file = fileFor(rule.scope || "user");
    const r = await write({ title: C.installTitle, body: [rule.sentence], file: tildify(file), backup: true, confirmLabel: C.add, path: RECOMMENDED, payload: { action: "install", ids: [rule.id] } });
    if (r.ok) toast((r.data.written || []).length ? C.added((r.data.row_ids || []).length || 1) : C.nothingAdded, "ok");
    showWarning(r);
  }

  async function installAll(n) {
    const file = fileFor("user");
    const r = await write({ title: C.installAllTitle(n), body: [C.installAllBody], file: tildify(file), backup: true, confirmLabel: C.addAll, path: RECOMMENDED, payload: { action: "install" } });
    if (r.ok) toast((r.data.written || []).length ? C.added((r.data.row_ids || []).length) : C.nothingAdded, "ok");
    showWarning(r);
  }

  async function decline(rule, undo) {
    const r = await write({
      title: undo ? C.undeclineTitle : C.declineTitle,
      body: [rule.sentence, undo ? C.undeclineBody : C.declineBody],
      confirmLabel: undo ? C.undecline : C.decline,
      path: RECOMMENDED,
      payload: { action: undo ? "undecline" : "decline", ids: [rule.id] },
    });
    if (r.ok) toast(undo ? C.undeclined : C.declined, "ok");
  }

  /** groupOf(id): the id of the group whose rows hold the row id, or "". */
  function groupOf(id) {
    for (const g of (book && book.groups) || []) if ((g.rows || []).some((r) => r.id === id)) return g.id;
    return "";
  }

  /**
   * focusAfterRemove(groupId): after a Remove the row and its button are
   * rebuilt away, so focus goes to the heading of the group the row lived in,
   * else the page heading, never the body (final review of Plan 04, finding 3).
   */
  function focusAfterRemove(groupId) {
    if (!root) return;
    const target = (groupId && root.querySelector("#rules-g-" + groupId)) || root.querySelector("h1");
    if (!target) return;
    target.setAttribute("tabindex", "-1");
    target.focus();
  }

  /** intentRows(id): every row of the book that belongs to the intent, each once. */
  function intentRows(id) {
    const out = [];
    const seen = new Set();
    for (const g of (book && book.groups) || []) {
      for (const r of g.rows || []) {
        if (!r.intent || r.intent.id !== id || seen.has(r.id)) continue;
        seen.add(r.id);
        out.push(r);
      }
    }
    return out;
  }

  /**
   * removeIntent(row): one confirm for a row added together with others to
   * cover every route (R5). It lists every row of the intent; the main
   * button removes them all (remove_intent), the lesser one only this row
   * (remove, as for any row).
   */
  async function removeIntent(row) {
    const it = row.intent;
    const rows = intentRows(it.id);
    const n = Math.max(rows.length, 1);
    const files = [...new Set(rows.map((r) => tildify((r.source && r.source.file) || "")).filter(Boolean))];
    const one = files.length === 1 ? files[0] : "";
    const groupId = groupOf(row.id);
    const r = await write({
      title: C.intent.removeTitle(n),
      body: [
        C.intent.lead(it.sentence),
        h("ul", { class: "list small" }, rows.map((x) => h("li", null, x.sentence))),
        files.length > 1 ? C.intent.filesLine(files) : null,
        files.length > 1 ? C.intent.backups : null,
        C.intent.onlyNote,
      ],
      file: one,
      backup: !!one,
      confirmLabel: C.intent.removeAll(n),
      danger: true,
      path: RULES,
      payload: { remove_intent: it.id },
      alt: { label: C.intent.onlyThis, payload: { remove: row.id } },
    });
    if (r === cancelled()) return;
    // Remove all takes rows from several groups: focus the page heading.
    focusAfterRemove(r.choice === "alt" ? groupId : "");
    if (r.ok) {
      const k = (r.data.row_ids || []).length;
      toast(k > 1 ? C.removedMany(k) : C.removed, "ok");
    }
  }

  /** endTemporary(t): end one paused rule or timed grant now (end_temporary). */
  async function endTemporary(t) {
    const file = tildify((store.status && store.status.overridesPath) || "");
    const r = await write({
      title: C.temp.endTitle,
      body: [t.sentence, C.temp.endBody],
      file,
      backup: !!file,
      confirmLabel: C.temp.end,
      path: RULES,
      payload: { end_temporary: t.id },
    });
    if (r === cancelled()) return;
    // The row is gone; the notice's heading, else the page heading, takes focus.
    const target = (root && root.querySelector("#rules-temp-h")) || (root && root.querySelector("h1"));
    if (target) {
      target.setAttribute("tabindex", "-1");
      target.focus();
    }
    if (r.ok) toast(C.temp.ended, "ok");
  }

  async function remove(row, whole) {
    // An intent with one row left is removed as any one row is.
    if (whole === "intent" && intentRows(row.intent.id).length > 1) return removeIntent(row);
    if (whole === "intent") whole = null;
    const file = tildify((row.source && row.source.file) || "");
    const groupId = groupOf(row.id);
    const r = await write({
      title: whole ? C.removeAllTitle(kindWord(whole.kind), whole.name) : C.removeTitle,
      body: [whole ? C.removeAllBody(kindWord(whole.kind), whole.name) : C.removeBody(row.sentence)],
      file,
      backup: !!file,
      confirmLabel: C.remove,
      danger: true,
      path: RULES,
      payload: { remove: row.id },
    });
    if (r === cancelled()) return;
    focusAfterRemove(groupId);
    if (r.ok) {
      const n = (r.data.row_ids || []).length;
      toast(n > 1 ? C.removedMany(n) : C.removed, "ok");
    }
  }

  /**
   * focusSwitch(id): after a confirmed switch write loadBook rebuilt the
   * list, so the switch the reader pressed is gone; focus its replacement
   * in the row with that id, never leaving focus on the body (Plan 05
   * Task 6). Row ids hold "/" and ":", so rows are compared, not selected.
   */
  function focusSwitch(id) {
    if (!root) return;
    for (const li of root.querySelectorAll("li.rule-row")) {
      if (li.dataset.id !== id) continue;
      const sw = li.querySelector("button.sw");
      if (sw) sw.focus();
      return;
    }
  }

  async function setEnabled(row, enabled) {
    const r = await write({
      title: enabled ? C.switchOnTitle : C.switchOffTitle,
      body: [row.sentence, C.switchBody],
      confirmLabel: enabled ? COPY.settings.turnOn : COPY.settings.turnOff,
      path: RULES,
      payload: { set: { id: row.id, enabled } },
    });
    if (r === cancelled()) return;
    focusSwitch(row.id);
    if (r.ok) toast(enabled ? C.switchedOn : C.switchedOff, "ok");
  }

  // ------------------------------------------------------------ rows

  /** handHint(row): the hover text for a row the dashboard does not change. */
  function handHint(row) {
    const f = row.source && row.source.file;
    return f ? C.editByHandNote(tildify(f)) : null;
  }

  /** control(row) → a Node, or null (and the row gets the hand-edit hover). */
  function control(row) {
    if (row.join) return null;
    if (row.kind === WIRE.pack) {
      const on = row.state === "on";
      return h("button", {
        type: "button",
        class: "sw",
        role: "switch",
        "aria-checked": String(on),
        "aria-label": C.switchLabel(row.sentence),
        title: C.switchLabel(row.sentence),
        disabled: busy,
        on: { click: () => setEnabled(row, !on) },
      });
    }
    const removeBtn = (whole) =>
      h("button", { type: "button", class: "btn ghost small", "aria-label": C.removeLabel(row.sentence), disabled: busy, on: { click: () => remove(row, whole) } }, C.remove);
    // A row added with others to cover every route: its Remove offers all
    // of them or only this one, wherever the rows live (R5).
    if (row.intent && row.intent.id && row.state !== "removed") return removeBtn("intent");
    const sp = subjectParts(row.id);
    if (sp) {
      // Only the first row of a thing can go (it takes every entry with it);
      // "*" (the defaults) and project files are edited by hand.
      if (sp.entry || row.scope === "project" || (sp.kind === "skill" && sp.name === "*")) return null;
      return removeBtn(sp);
    }
    if (row.kind === WIRE.hook_regex) return row.scope === "project" ? null : removeBtn(null);
    if (String(row.id).startsWith(NATIVE_PREFIX) && row.owner === "us" && row.state !== "removed") return removeBtn(null);
    return null;
  }

  /** isNativeBash(row): a Claude Code Bash block or ask rule (the only Claude Code rows with counts). */
  function isNativeBash(row) {
    return NATIVE_COUNTED.has(row.kind) && row.tool === "Bash" && String(row.id).startsWith(NATIVE_PREFIX);
  }

  /**
   * statOf(row) → {native, s} for a row that gets a count chip (s null when
   * it never fired), or null for one that gets none: built-in rows by
   * "<pack>/<id>", the person's own rules by id, Claude Code Bash block and
   * ask rows by the rule as written; only rows that are on, and only while
   * the counts loaded and the log is on (D11).
   */
  function statOf(row) {
    if (!stats || stats.activity_enabled === false || row.join || row.state !== "on") return null;
    const id = String(row.id);
    const pick = (m, k) => (m && has(m, k) ? m[k] : null);
    if (row.kind === WIRE.pack && id.startsWith("pack:")) return { native: false, s: pick(stats.pack, id.slice("pack:".length)) };
    if (row.kind === WIRE.hook_regex && id.startsWith("user:")) return { native: false, s: pick(stats.user, id.slice("user:".length)) };
    if (isNativeBash(row)) return { native: true, s: pick(stats.native, row.value) };
    return null;
  }

  function statChip(row) {
    const st = statOf(row);
    if (!st) return null;
    const s = st.s;
    let text = C.stats.never;
    if (s && s.fired > 0) {
      // A paused or note-only rule matched but changed nothing: say so.
      text = s.last_action === "log" ? C.stats.matched(s.fired, fmt.ago(s.last_ts)) : C.stats.fired(s.fired, fmt.ago(s.last_ts));
      if (s.shadow > 0) text += " · " + C.stats.observed(s.shadow);
    }
    const title = C.stats.chipTitle(text) + (st.native ? " " + C.stats.nativeNote : "");
    return h("span", { class: "tag none rule-stat", title }, text);
  }

  function intentChip(row) {
    const it = row.intent;
    if (!it || !it.id) return null;
    return h("span", { class: "tag none rule-intent", title: C.intent.chipTitle(it.sentence) }, C.intent.chip(it.sentence, it.rows || 1));
  }

  function ruleRow(row) {
    const ctl = control(row);
    const builtin = row.value === BUILTIN;
    const file = row.source && row.source.file;
    const entry = subjectParts(row.id);
    // A row the dashboard does not change says so in visible text (not only a
    // hover title), so keyboard and touch users see why it has no control.
    const hint = ctl || row.join || (entry && entry.entry) ? null : handHint(row);
    return h(
      "li",
      { class: "rule-row", title: row.hover || null, dataset: { id: row.id } },
      h(
        "div",
        { class: "rule-main" },
        h("span", { class: "rule-sentence" }, builtin ? C.builtinList : row.sentence),
        row.detail_href ? h("a", { class: "btn link small", href: row.detail_href }, C.details) : null,
      ),
      h(
        "div",
        { class: "rule-meta" },
        h("span", { class: "tag none", title: C.whereLabel + (row.where || scopeLabel(row.scope, file)) }, row.where || scopeLabel(row.scope, file)),
        h("span", { class: "tag none", title: C.byLabel + ownerLabel(row.owner) }, C.byLabel + ownerLabel(row.owner)),
        h("span", { class: "tag none", title: C.enforcedLabel + enforcementLabel(row.enforcement) }, enforcementLabel(row.enforcement)),
        h("span", { class: `tag ${row.state === "on" ? "ok" : row.state === "removed" ? "ask" : "none"}`, title: C.stateLabel + stateWord(row.state) }, stateWord(row.state)),
        statChip(row),
        intentChip(row),
        file ? h("span", { class: "src mono rule-file" }, C.fileLabel + tildify(file)) : null,
      ),
      hint ? h("p", { class: "src rule-hint" }, hint) : null,
      ctl ? h("div", { class: "rule-ctl" }, ctl) : null,
    );
  }

  function stateWord(s) {
    return has(C.state, s) ? C.state[s] : COPY.common.other;
  }

  /** joinRows(seen): the sandbox rows the rulebook does not list: skills with scripts and wrapped MCP servers. */
  function joinRows(hrefs) {
    const out = [];
    const skills = (store.skills && store.skills.skills) || [];
    for (const s of skills) {
      if (!hasScripts(s) || hrefs.has("#/rules/skill/" + s.name)) continue;
      const view = s.effectiveDetail || s.grant || null;
      out.push({
        id: "sandbox-skill:" + s.name,
        join: true,
        sentence: C.skillSandbox(s.name, view),
        hover: fmt.summary(view),
        where: s.source === "project" && book && book.project_root ? tildify(book.project_root) : scopeLabel("user", ""),
        owner: "us",
        enforcement: "os",
        state: "on",
        source: { file: "" },
        detail_href: skillHash(s.name),
      });
    }
    for (const m of (mcp && mcp.servers) || []) {
      if (!m.wrapped || hrefs.has("#/rules/mcp/" + m.name)) continue;
      out.push({
        id: "sandbox-mcp:" + m.name,
        join: true,
        sentence: C.mcpSandbox(m.name),
        where: scopeLabel("user", ""),
        owner: "us",
        enforcement: "os",
        state: "on",
        source: { file: "" },
        detail_href: mcpHref(m.name),
      });
    }
    return out;
  }

  // ------------------------------------------------------------ list view

  function recommendedBlock() {
    const all = (book && book.recommended) || [];
    if (!all.length) return null;
    const open = all.filter((r) => !r.declined);
    const declined = all.filter((r) => r.declined);
    const recRow = (rule, isDeclined) =>
      h(
        "li",
        { class: "rule-row rec-row", dataset: { id: rule.id } },
        h("div", { class: "rule-main" }, h("span", { class: "rule-sentence" }, rule.sentence)),
        h("div", { class: "rule-meta" }, h("span", { class: "src mono" }, rule.value)),
        h(
          "div",
          { class: "rule-ctl" },
          h("button", { type: "button", class: "btn small", disabled: busy, on: { click: () => install(rule) } }, C.add),
          h("button", { type: "button", class: "btn ghost small", disabled: busy, on: { click: () => decline(rule, isDeclined) } }, isDeclined ? C.undecline : C.decline),
        ),
      );
    return h(
      "section",
      { class: "card rec-block", "aria-labelledby": "rules-rec-h" },
      h(
        "div",
        { class: "row" },
        h("h2", { class: "card-title grow", id: "rules-rec-h" }, C.recTitle),
        open.length ? h("button", { type: "button", class: "btn small", disabled: busy, on: { click: () => installAll(open.length) } }, C.addAll) : null,
      ),
      h("p", { class: "src" }, C.recLead),
      open.length ? h("ul", { class: "rule-list" }, open.map((r) => recRow(r, false))) : null,
      declined.length
        ? h(
            "button",
            {
              type: "button",
              class: "btn link small",
              "aria-expanded": String(showDeclined),
              on: {
                click: () => {
                  showDeclined = !showDeclined;
                  renderList();
                },
              },
            },
            C.declinedToggle(declined.length, showDeclined),
          )
        : null,
      declined.length && showDeclined ? h("ul", { class: "rule-list declined" }, declined.map((r) => recRow(r, true))) : null,
    );
  }

  function noticeBlock() {
    const out = [];
    // Shadow mode: the dashboard only says so; the command is the way back.
    if (store.status && store.status.shadow === true)
      out.push(h("div", { class: "banner" }, h("p", { class: "lbl" }, COPY.shadow.rulesTitle), h("p", null, COPY.shadow.rulesBody, COPY.shadow.how, h("code", { class: "mono" }, COPY.shadow.command))));
    for (const f of (book && book.files) || []) if (f.error) out.push(h("div", { class: "banner deny" }, C.fileError(tildify(f.path), f.error)));
    // The server also lists a broken file under warnings; show it once.
    const broken = ((book && book.files) || []).filter((f) => f.error).map((f) => f.path);
    const warnings = ((book && book.warnings) || []).filter((w) => !broken.some((p) => p && String(w).includes(p)));
    if (warnings.length) out.push(h("div", { class: "banner" }, h("p", { class: "lbl" }, C.warningsTitle), h("ul", { class: "list small" }, warnings.map((w) => h("li", null, w)))));
    const drift = (book && book.drift) || [];
    if (drift.length) out.push(h("div", { class: "banner" }, h("p", { class: "lbl" }, C.driftTitle), h("ul", { class: "list small" }, drift.map((d) => h("li", null, C.driftLine(d.value, tildify(d.file)))))));
    return out;
  }

  /** statsCaption(): what the counts cover, under the page head; null until they load. */
  function statsCaption() {
    if (!stats) return null;
    if (stats.activity_enabled === false) return h("p", { class: "src rules-window" }, C.stats.off);
    const w = stats.window || {};
    const parts = [w.records > 0 && w.since ? C.stats.window(fmt.ago(w.since), w.records) : C.stats.empty];
    if (w.rotated) parts.push(C.stats.rotated);
    let native = false;
    for (const g of (book && book.groups) || []) for (const r of g.rows || []) if (isNativeBash(r) && r.state === "on") native = true;
    if (native) parts.push(C.stats.nativeNote);
    return h("p", { class: "src rules-window" }, parts.join(" "));
  }

  /** tempBlock(): the paused rules and timed grants in force, each with End now; null when there are none. */
  function tempBlock() {
    const list = (book && book.temporaries) || [];
    if (!list.length) return null;
    const T = C.temp;
    return h(
      "section",
      { class: "card rules-temp", "aria-labelledby": "rules-temp-h" },
      h("h2", { class: "card-title", id: "rules-temp-h" }, T.title),
      h("p", { class: "src" }, T.lead),
      h(
        "ul",
        { class: "rule-list" },
        list.map((t) =>
          h(
            "li",
            { class: "rule-row", dataset: { temporary: t.id } },
            h("div", { class: "rule-main" }, h("span", { class: "rule-sentence" }, t.sentence)),
            h("div", { class: "rule-meta" }, h("span", { class: "src" }, t.session ? T.untilSession(endTime(t.until)) : T.until(endTime(t.until)))),
            h(
              "div",
              { class: "rule-ctl" },
              h("button", { type: "button", class: "btn ghost small", "aria-label": T.endLabel(t.sentence), disabled: busy, on: { click: () => endTemporary(t) } }, T.end),
            ),
          ),
        ),
      ),
    );
  }

  // ------------------------------------------------------------ try a call

  /** rowById(id): the book's row with that id, or null. */
  function rowById(id) {
    for (const g of (book && book.groups) || []) for (const r of g.rows || []) if (r.id === id) return r;
    return null;
  }

  /**
   * hitRow(hit) → {id, label}: the row a rule the try matched lives on (id
   * "" when this page does not list it). Claude Code rules are found by
   * the rule as written, since their row id carries a hash of it.
   */
  function hitRow(hit) {
    let id = "";
    let label = hit.pack + "/" + hit.id;
    if (hit.pack === "user") {
      id = "user:" + hit.id;
      label = hit.id;
    } else if (hit.pack === "claude-settings") {
      label = hit.id;
      for (const g of (book && book.groups) || []) for (const r of g.rows || []) if (!id && NATIVE_COUNTED.has(r.kind) && r.value === hit.id) id = r.id;
    } else {
      id = "pack:" + hit.pack + "/" + hit.id;
    }
    const row = id ? rowById(id) : null;
    return row ? { id, label: row.sentence } : { id: "", label };
  }

  /** showRow(id): scroll to the row with that id, highlight it for a moment and focus it. */
  function showRow(id) {
    if (!root) return;
    for (const li of root.querySelectorAll("li.rule-row")) {
      if (li.dataset.id !== id) continue;
      for (const old of root.querySelectorAll("li.rule-row.is-hit")) old.classList.remove("is-hit");
      li.classList.add("is-hit");
      li.setAttribute("tabindex", "-1");
      const still = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
      li.scrollIntoView({ block: "center", behavior: still ? "auto" : "smooth" });
      li.focus({ preventScroll: true });
      clearTimeout(hitTimer);
      hitTimer = setTimeout(() => li.classList.remove("is-hit"), HIT_MS);
      return;
    }
  }

  /** endTime(ts): the local time, with the day in front when it is not today. */
  function endTime(ts) {
    const d = new Date(ts);
    if (Number.isNaN(d.getTime())) return "";
    if (d.toDateString() === new Date().toDateString()) return fmt.time(d);
    return C.temp.onDay(d.toLocaleDateString(undefined, { month: "short", day: "numeric" }), fmt.time(d));
  }

  /** tryResult(d): the result card's contents for one explain document. */
  function tryResult(d) {
    const T = C.try;
    const v = d.verdict;
    const out = [];
    if (has(T.verdict, v)) {
      out.push(
        h(
          "div",
          { class: "rules-try-verdict" },
          h("span", { class: "tag " + (v === "allow" ? "ok" : v) }, T.verdict[v]),
          has(TRY_ENFORCEMENT, d.enforcement) ? h("span", { class: "tag none" }, T.enforced(enforcementLabel(TRY_ENFORCEMENT[d.enforcement]))) : null,
        ),
      );
    } else {
      out.push(h("p", { class: "rules-try-none" }, T.none));
    }
    if (d.reason) out.push(h("p", { class: "rules-try-reason" }, d.reason));
    const hits = [];
    const seen = new Set();
    for (const hit of d.rules || []) {
      const x = hitRow(hit);
      const key = x.id || x.label;
      if (seen.has(key)) continue;
      seen.add(key);
      hits.push(x);
    }
    const sub = d[WIRE.subject];
    if (sub && sub.kind && sub.name) {
      const id = WIRE.subject + ":" + sub.kind + ":" + sub.name;
      const row = rowById(id);
      if (row && !seen.has(id)) hits.push({ id, label: row.sentence });
    }
    if (hits.length) {
      out.push(
        h(
          "div",
          { class: "rules-try-hits" },
          h("span", { class: "src" }, T.matched),
          hits.map((x) =>
            x.id
              ? h("button", { type: "button", class: "btn link small", "aria-label": T.ruleLink(x.label), on: { click: () => showRow(x.id) } }, x.label)
              : h("span", { class: "src" }, T.notListed(x.label)),
          ),
        ),
      );
    }
    const nr = d.native_rule;
    if (nr && nr.value) out.push(h("p", { class: "src" }, T.native(nr.value, has(T.nativeWhere, nr.scope) ? T.nativeWhere[nr.scope] : nr.scope, nr.kind)));
    if (d.rewritten) out.push(h("p", { class: "src" }, T.rewrite), h("code", { class: "mono rules-try-rewrite" }, d.rewritten));
    if (d.shadow && d.shadow.on) out.push(h("p", { class: "src" }, T.shadow(has(T.would, d.shadow.would) ? T.would[d.shadow.would] : d.shadow.would, d.shadow.would_reason)));
    if (d.project_scope && book && book.project_root) out.push(h("p", { class: "src" }, T.inProject(tildify(book.project_root))));
    if (((book && book.temporaries) || []).some((t) => t.session)) out.push(h("p", { class: "src" }, T.sessionPauses));
    return out;
  }

  /**
   * buildShell(): the list view's head (title, the try box, Add rule) and
   * the body every render refills. Built once per mount; renders never
   * rebuild the head, so the try box keeps its text, its result and focus.
   */
  function buildShell() {
    const T = C.try;
    const result = h("div", { id: TRY_RESULT, class: "rules-try-result", tabindex: "-1", role: "region", "aria-label": T.resultLabel, "aria-live": "polite", hidden: true });
    const input = h("input", {
      type: "text",
      id: TRY_INPUT,
      class: "rule-sheet-input rules-try-input",
      "aria-label": T.valueLabel,
      "aria-describedby": "rules-try-lead",
      placeholder: T.placeholders.command,
      autocomplete: "off",
      autocapitalize: "off",
      spellcheck: "false",
      on: { input: () => (button.disabled = !input.value.trim()) },
    });
    const what = h(
      "select",
      {
        id: "rules-try-what",
        class: "rule-sheet-input rules-try-what",
        "aria-label": T.whatLabel,
        on: {
          change: () => {
            input.placeholder = T.placeholders[what.value] || "";
          },
        },
      },
      TRY_WHATS.map((w) => h("option", { value: w }, T.whats[w])),
    );
    const button = h("button", { type: "submit", class: "btn small", disabled: true }, T.button);
    const show = (nodes) => {
      result.hidden = false;
      replace(result, nodes);
    };
    async function submit(e) {
      e.preventDefault();
      const value = input.value.trim();
      if (!value) {
        input.focus();
        return;
      }
      const my = ++trySeq;
      // A new try drops the outline the last one's rule link left.
      clearTimeout(hitTimer);
      if (root) for (const old of root.querySelectorAll("li.rule-row.is-hit")) old.classList.remove("is-hit");
      show(h("p", { class: "src" }, T.trying));
      // ?project= whenever the page has a project, so its rules count (the
      // route uses no project without it).
      const r = await postTry({ what: what.value, value }, (book && book.project_root) || "");
      if (my !== trySeq || !shell) return;
      show(r.ok && r.data ? tryResult(r.data) : h("p", { class: "rules-try-error" }, T.failed(r.ok ? "" : r.error)));
      // The result takes focus so a keyboard or screen reader user meets it
      // at once; only when focus is still in the box (they did not move on).
      const a = document.activeElement;
      if (!a || a === document.body || form.contains(a)) result.focus();
    }
    const form = h(
      "form",
      {
        class: "rules-try",
        "aria-labelledby": "rules-try-h",
        novalidate: true,
        on: {
          submit,
          // Escape anywhere in the box (the result, a rule link) goes back to the field.
          keydown: (e) => {
            if (e.key !== "Escape" || document.activeElement === input) return;
            e.preventDefault();
            input.focus();
          },
        },
      },
      h("h2", { class: "lbl", id: "rules-try-h" }, T.title),
      h("div", { class: "rules-try-row" }, what, input, button),
      h("p", { class: "src", id: "rules-try-lead" }, T.lead),
      result,
    );
    const head = h(
      "div",
      { class: "page-head rules-head" },
      h("div", { class: "rules-title" }, h("h1", { class: "h1" }, C.title), h("p", { class: "lead" }, C.lead)),
      h(
        "div",
        { class: "rules-tools" },
        form,
        h("button", { type: "button", id: ADD_ID, class: "btn small", "aria-haspopup": "dialog", on: { click: openSheet } }, icon("plus", 12), C.addRule),
      ),
    );
    return { head, body: h("div", { class: "rules-body" }), input, result };
  }

  /** ensureShell(): the kept head and body, put back into the page root when a drill-in replaced them. */
  function ensureShell() {
    if (!shell) shell = buildShell();
    if (shell.head.parentNode !== root || shell.body.parentNode !== root) replace(root, shell.head, shell.body);
    return shell;
  }

  function renderList() {
    if (!root || view !== "list") return;
    // The sheet lives in the page root; a render would remove it mid-edit.
    if (sheet) {
      renderPending = true;
      return;
    }
    const sh = ensureShell();
    if (!book) {
      replace(sh.body, bookError ? h("div", { class: "banner deny" }, C.loadFailed(bookError)) : h("p", { class: "muted" }, C.loading));
      return;
    }
    const seen = new Set();
    const hrefs = new Set();
    for (const g of book.groups || []) for (const r of g.rows || []) if (r.detail_href) hrefs.add(r.detail_href);
    const groups = (book.groups || []).map((g) => {
      const rows = [...(g.rows || []), ...(g.id === "sandbox" ? joinRows(hrefs) : [])].filter((r) => {
        if (seen.has(r.id)) return false;
        seen.add(r.id);
        return true;
      });
      const hid = "rules-g-" + g.id;
      return h(
        "section",
        { class: "rules-group", "aria-labelledby": hid, dataset: { group: g.id } },
        h("h2", { class: "lbl", id: hid }, groupTitle(g.id)),
        rows.length ? h("ul", { class: "rule-list card" }, rows.map(ruleRow)) : h("p", { class: "src" }, C.emptyGroup),
      );
    });
    replace(sh.body, statsCaption(), ...noticeBlock(), tempBlock(), recommendedBlock(), ...groups);
  }

  // ------------------------------------------------------------ Add rule sheet
  //
  // A modal <dialog> in the page root. The person picks a kind and fills one
  // or two fields; the sheet sends the request (an AddRequest, nothing else)
  // to the propose route 250 ms after the last change and shows the plan the
  // server returns. Confirm writes the same request through write(), so the
  // server builds the plan again from it; the page never sends a plan back.

  /** packChoices(): the built-in watchdeck rules the sheet can raise to deny (each pack row once). */
  function packChoices() {
    const out = [];
    const seen = new Set();
    for (const g of (book && book.groups) || []) {
      for (const r of g.rows || []) {
        if (r.kind !== WIRE.pack || !r.value || seen.has(r.value)) continue;
        seen.add(r.value);
        out.push(r);
      }
    }
    return out;
  }

  /** sentenceCase(msg): the server's refusal reason with a capital first letter. */
  function sentenceCase(msg) {
    const t = String(msg || "");
    return t.charAt(0).toUpperCase() + t.slice(1);
  }

  function focusAdd() {
    const b = root && root.querySelector("#" + ADD_ID);
    if (b) b.focus();
  }

  function closeSheet() {
    if (!sheet) return;
    renderPending = false;
    sheet.finish(false);
  }

  function openSheet() {
    if (sheet || !book || !root || view !== "list") return;
    const S = C.sheet;
    const projectRoot = book.project_root || "";
    const packs = packChoices();
    // everywhere: "Cover every route" for a path or a domain, on by default
    // and again whenever the kind changes (D8).
    const st = { kind: SHEET_KINDS[0], values: {}, fullText: false, tool: PATH_TOOLS[0], scope: "user", twin: false, everywhere: true, pack: packs.length ? packs[0].value : "" };
    let plan = null; // the last plan the server returned
    let planKey = ""; // JSON of the request that plan answers
    let seq = 0;
    let timer = null;
    let done = false;
    const ids = { title: "rule-sheet-title", lead: "rule-sheet-lead", value: "rule-sheet-value", hint: "rule-sheet-hint", error: "rule-sheet-error", full: "rule-sheet-full", twin: "rule-sheet-twin", preview: "rule-sheet-preview-h", every: "rule-sheet-every", everyNote: "rule-sheet-every-note" };

    const isCommand = () => st.kind === "block" || st.kind === "ask";
    const canEverywhere = () => st.kind === "path" || st.kind === "domain";
    const labelKey = () => (isCommand() ? (st.fullText ? "text" : "command") : st.kind);
    const storeKey = () => (isCommand() ? "command" : st.kind);
    // Rules in watchdeck's own file (exact text, built-in rules) apply everywhere.
    const userOnly = () => !projectRoot || st.kind === "pack" || (isCommand() && st.fullText);

    /** request(): the AddRequest for the sheet's state: only the server's keys. */
    function request() {
      const scope = userOnly() ? "user" : st.scope;
      const action = st.kind === "ask" ? "ask" : "deny";
      const value = st.values[storeKey()] || "";
      if (isCommand()) return st.fullText ? { action, what: "text", value, tool: "Bash", scope } : { action, what: "command", value, scope, twin: st.twin };
      if (st.kind === "path") return { action, what: "path", value, tool: st.tool, scope, everywhere: !!st.everywhere };
      if (st.kind === "domain") return { action, what: "host", value, scope, everywhere: !!st.everywhere };
      if (st.kind === "mcp") return { action, what: "mcp", value, scope };
      return { action, what: "pack-rule", value: st.pack, scope };
    }

    const errorEl = h("p", { id: ids.error, class: "rule-sheet-error", "aria-live": "polite" });
    // The value field is rebuilt per kind; the error region between it and
    // the extras (hint, full-text toggle, path tools) never moves, so a
    // screen reader keeps announcing it.
    const valueBox = h("div", { class: "rule-sheet-fields" });
    const extrasBox = h("div", { class: "rule-sheet-fields" });
    const fieldsBox = h("div", { class: "rule-sheet-fields" }, valueBox, errorEl, extrasBox);
    const twinInput = h("input", {
      type: "checkbox",
      id: ids.twin,
      on: {
        change: (e) => {
          st.twin = e.target.checked;
          schedule();
        },
      },
    });
    const twinRow = h("label", { class: "check rule-sheet-twin", for: ids.twin, hidden: true }, twinInput, S.twin);
    const scopeBox = h("div", { class: "rule-sheet-scope" });
    // The live region changes only when a result differs from what it shows;
    // "Checking…" goes in a line outside it, so typing announces nothing
    // until the server answers.
    const previewBody = h("div", { class: "rule-sheet-preview-body", "aria-live": "polite" });
    const waitEl = h("p", { class: "src rule-sheet-wait", hidden: true }, S.previewWaiting);
    let shownKey = null; // what previewBody shows: "empty", "none", or the plan's JSON
    const confirmBtn = h("button", { type: "submit", class: "btn", disabled: true }, S.confirm);
    const cancelBtn = h("button", { type: "button", class: "btn ghost", on: { click: () => finish(true) } }, S.cancel);

    const radio = (name, value, label, checked, onPick) =>
      h(
        "label",
        { class: "check", for: `rule-sheet-${name}-${value}` },
        h("input", { type: "radio", name: "rule-sheet-" + name, id: `rule-sheet-${name}-${value}`, value, checked, on: { change: onPick } }),
        label,
      );

    const kindBox = h(
      "fieldset",
      { class: "rule-sheet-set rule-sheet-kinds" },
      h("legend", { class: "lbl" }, S.kindLegend),
      SHEET_KINDS.map((k) =>
        radio("kind", k, S.kinds[k], k === st.kind, () => {
          st.kind = k;
          st.twin = false;
          st.everywhere = true;
          renderFields();
          renderScope();
          schedule();
        }),
      ),
    );

    function renderFields() {
      const out = [];
      const described = ids.hint + " " + ids.error;
      if (st.kind === "pack") {
        if (!packs.length) {
          out.push(h("p", { class: "src" }, S.noPacks));
        } else {
          const sel = h(
            "select",
            {
              id: ids.value,
              class: "rule-sheet-input",
              "aria-describedby": described,
              on: {
                change: (e) => {
                  st.pack = e.target.value;
                  schedule();
                },
              },
            },
            packs.map((r) => h("option", { value: r.value, selected: r.value === st.pack }, r.state === "off" ? S.packOff(r.sentence) : r.sentence)),
          );
          out.push(h("label", { class: "rule-sheet-label", for: ids.value }, S.labels.pack), sel);
        }
      } else {
        const lk = labelKey();
        const input = h("input", {
          type: "text",
          id: ids.value,
          class: "rule-sheet-input",
          value: st.values[storeKey()] || "",
          placeholder: S.placeholders[lk],
          autocomplete: "off",
          autocapitalize: "off",
          spellcheck: "false",
          "aria-describedby": described,
          on: {
            input: (e) => {
              st.values[storeKey()] = e.target.value;
              schedule();
            },
          },
        });
        out.push(h("label", { class: "rule-sheet-label", for: ids.value }, S.labels[lk]), input);
      }
      replace(valueBox, out);
      const hint = S.hints[labelKey()] + (st.kind === "path" && st.everywhere ? " " + S.pathEverywhere(!!projectRoot) : "");
      const extras = [h("p", { id: ids.hint, class: "src" }, hint)];
      if (isCommand()) {
        extras.push(
          h(
            "label",
            { class: "check", for: ids.full },
            h("input", {
              type: "checkbox",
              id: ids.full,
              checked: st.fullText,
              on: {
                change: (e) => {
                  st.fullText = e.target.checked;
                  st.twin = false;
                  renderFields();
                  renderScope();
                  schedule();
                  const again = dlg.querySelector("#" + ids.full);
                  if (again) again.focus();
                },
              },
            }),
            S.fullText,
          ),
        );
      }
      if (st.kind === "path") {
        extras.push(
          h(
            "fieldset",
            { class: "rule-sheet-set" },
            h("legend", { class: "lbl" }, S.toolLegend),
            h(
              "div",
              { class: "rule-sheet-choices" },
              PATH_TOOLS.map((t) =>
                radio("tool", t, S.tools[t], t === st.tool, () => {
                  st.tool = t;
                  schedule();
                }),
              ),
            ),
          ),
        );
      }
      if (canEverywhere()) {
        // Cover every route: the preview lists each rule it adds; the
        // notes say what else it stops and what it cannot (D6).
        extras.push(
          h(
            "label",
            { class: "check", for: ids.every },
            h("input", {
              type: "checkbox",
              id: ids.every,
              checked: st.everywhere,
              "aria-describedby": ids.everyNote,
              on: {
                change: (e) => {
                  st.everywhere = e.target.checked;
                  renderFields();
                  schedule();
                  const again = dlg.querySelector("#" + ids.every);
                  if (again) again.focus();
                },
              },
            }),
            S.everywhere,
          ),
          h(
            "div",
            { id: ids.everyNote, class: "src rule-sheet-every" },
            st.everywhere ? [h("p", null, S.everywhereNote[st.kind]), h("p", null, S.everywhereGap)] : h("p", null, S.everywhereGap),
          ),
        );
      }
      replace(extrasBox, extras);
    }

    function renderScope() {
      if (userOnly()) {
        replace(scopeBox, h("p", { class: "src" }, projectRoot ? S.scopeUserOnly : S.scopeEverywhere));
        return;
      }
      const opts = [
        ["user", scopeLabel("user", "")],
        ["project", scopeLabel("project", projectRoot + "/.claude/settings.json")],
      ];
      replace(
        scopeBox,
        h(
          "fieldset",
          { class: "rule-sheet-set" },
          h("legend", { class: "lbl" }, S.scopeLegend),
          h(
            "div",
            { class: "rule-sheet-choices" },
            opts.map(([v, label]) =>
              radio("scope", v, label, v === st.scope, () => {
                st.scope = v;
                schedule();
              }),
            ),
          ),
        ),
      );
    }

    function setError(msg) {
      errorEl.textContent = msg || "";
      const field = dlg.querySelector("#" + ids.value);
      if (!field) return;
      if (msg) field.setAttribute("aria-invalid", "true");
      else field.removeAttribute("aria-invalid");
    }

    /** strengthWord(step, action): who enforces what the step writes. */
    function strengthWord(step, action) {
      if (step.mechanism === "native") return enforcementLabel(action === "ask" ? "native-prompt" : "native-deny");
      return enforcementLabel(WIRE.hook_gate);
    }

    /** packRow(): the pack row the select names, or null. */
    const packRow = () => packs.find((r) => r.value === st.pack) || null;

    /** showResult(key, nodes): fill the live region only when what it shows changes. */
    function showResult(key, nodes) {
      waitEl.hidden = true;
      previewBody.classList.remove("is-stale");
      if (key === shownKey) return;
      shownKey = key;
      replace(previewBody, nodes);
    }

    /** showWaiting(): a proposal is on its way; the region dims but is not rewritten. */
    function showWaiting() {
      waitEl.hidden = false;
      previewBody.classList.add("is-stale");
    }

    function renderPlan() {
      const action = JSON.parse(planKey).action;
      const off = st.kind === "pack" && packRow() && packRow().state === "off";
      showResult(JSON.stringify([plan, off]), [
        (plan.steps || []).map((step, i) =>
          h(
            "div",
            { class: "rule-sheet-step" + (i === 0 ? " first" : "") },
            h("p", { class: "rule-sheet-sentence" }, step.sentence),
            h("p", { class: "src mono rule-sheet-mech" }, S.mechanism(step)),
            h("span", { class: "tag none" }, S.strength(strengthWord(step, action))),
          ),
        ),
        off ? h("p", { class: "banner rule-sheet-off" }, S.staysOff) : null,
      ]);
    }

    function showTwin() {
      // The watchdeck twin exists for a command prefix only: offered while the
      // server suggests it, and kept visible once chosen.
      twinInput.checked = st.twin;
      twinRow.hidden = !(isCommand() && !st.fullText && (st.twin || (plan && plan.suggested)));
    }

    const ready = () => !!plan && (plan.steps || []).length > 0 && planKey === JSON.stringify(request());

    function updateConfirm() {
      confirmBtn.disabled = busy || !ready();
    }

    function schedule() {
      seq++;
      plan = null;
      clearTimeout(timer);
      setError("");
      // The checkbox follows st.twin at once (a kind or full-text change
      // clears it); for a command prefix the row's visibility waits for the
      // server's suggestion.
      twinInput.checked = st.twin;
      if (!isCommand() || st.fullText) showTwin();
      const req = request();
      if (st.kind === "pack" && !packs.length) {
        showResult("none", null);
        updateConfirm();
        return;
      }
      if (!String(req.value || "").trim()) {
        showResult("empty", h("p", { class: "src" }, S.previewEmpty));
        updateConfirm();
        return;
      }
      showWaiting();
      updateConfirm();
      const my = seq;
      timer = setTimeout(() => propose(req, my), 250);
    }

    async function propose(req, my) {
      const r = await postRulePreview(req);
      if (done || my !== seq) return;
      if (r.ok && r.data && r.data.plan) {
        plan = r.data.plan;
        planKey = JSON.stringify(req);
        renderPlan();
      } else {
        // A refusal is a 200 with the reason in refused; anything else
        // (the server down, a malformed body) is a failed check.
        plan = null;
        const refused = r.ok && r.data && typeof r.data.refused === "string" && r.data.refused ? r.data.refused : "";
        setError(refused ? sentenceCase(refused) : S.previewFailed(r.ok ? S.noAnswer : r.error));
        showResult("none", null);
      }
      showTwin();
      updateConfirm();
    }

    async function submit(e) {
      e.preventDefault();
      if (busy || !ready()) return;
      const req = request();
      const first = plan.steps[0];
      const lines = [];
      for (const step of plan.steps) lines.push(step.sentence, S.mechanism(step));
      // An everywhere plan writes to more than one file: name them all.
      const files = [...new Set(plan.steps.map((x) => tildify(x.file)).filter(Boolean))];
      if (files.length > 1) lines.push(S.filesLine(files));
      confirmBtn.disabled = true;
      const r = await write({
        title: S.confirmTitle,
        body: lines,
        file: tildify(first.file),
        backup: first.mechanism === "native",
        confirmLabel: S.confirm,
        path: RULES,
        payload: { add: req },
      });
      if (done) return;
      if (r === cancelled() || !r.ok) {
        // The button was disabled while the confirm dialog was up, so focus
        // could not return to it; put it back for keyboard users.
        updateConfirm();
        if (!confirmBtn.disabled) confirmBtn.focus();
        return;
      }
      const n = (r.data.row_ids || []).length;
      finish(true);
      toast((r.data.written || []).length ? S.added(n, first.sentence) : S.already, "ok");
      // A Grep and Glob rule that is not watched yet (Task 2): the server's sentence says what to run.
      if (typeof r.data.warning === "string" && r.data.warning) toast(r.data.warning, "");
    }

    /** finish(focus): close and remove the sheet once; run a list render that waited; focus Add rule. */
    function finish(focus) {
      if (done) return;
      done = true;
      seq++;
      clearTimeout(timer);
      if (dlg.open) dlg.close();
      dlg.remove();
      sheet = null;
      if (renderPending) {
        renderPending = false;
        renderList();
      }
      if (focus) focusAdd();
    }

    const dlg = h(
      "dialog",
      { class: "dialog rule-sheet", "aria-labelledby": ids.title, "aria-describedby": ids.lead, on: { close: () => finish(true) } },
      h(
        "form",
        { class: "rule-sheet-form", novalidate: true, on: { submit } },
        h("h2", { class: "dialog-title", id: ids.title }, S.title),
        h("p", { id: ids.lead, class: "src" }, S.lead),
        kindBox,
        fieldsBox,
        twinRow,
        scopeBox,
        h("section", { class: "rule-sheet-preview", "aria-labelledby": ids.preview }, h("h3", { class: "lbl", id: ids.preview }, S.previewTitle), waitEl, previewBody),
        h("div", { class: "dialog-actions" }, cancelBtn, confirmBtn),
      ),
    );

    sheet = { finish };
    renderFields();
    renderScope();
    schedule();
    root.appendChild(dlg);
    dlg.showModal();
    const kindInput = dlg.querySelector('input[name="rule-sheet-kind"]:checked');
    if (kindInput) kindInput.focus();
  }

  // ------------------------------------------------------------ drill-ins

  function backLink() {
    return h("a", { class: "btn link small rules-back", href: "#/rules" }, C.back);
  }

  function showSkill(name) {
    const host = h("div", { class: "rules-drill" });
    replace(root, backLink(), host);
    detail = mountSkillDetail(host, name, null);
  }

  function renderMCP() {
    if (!root || view !== "mcp") return;
    const M = C.mcp;
    if (!mcp) {
      replace(root, backLink(), mcpError ? h("div", { class: "banner deny" }, M.loadFailed(mcpError)) : h("p", { class: "muted" }, C.loading));
      return;
    }
    const s = (mcp.servers || []).find((x) => x.name === viewName);
    if (!s) {
      replace(root, backLink(), mcp.error_text ? h("div", { class: "banner deny" }, M.configError(mcp.error_text)) : null, h("p", { class: "muted" }, C.unknown(viewName)));
      return;
    }
    const arg = /^[A-Za-z0-9._-]+$/.test(s.name) ? s.name : "'" + s.name.replace(/'/g, "'\\''") + "'";
    replace(
      root,
      backLink(),
      h(
        "section",
        { class: "card stack", "aria-label": M.title(s.name) },
        h("h1", { class: "card-title" }, M.title(s.name)),
        h(
          "div",
          { class: "kv" },
          h("span", { class: "k" }, M.runsAs),
          h("span", null, s.stdio ? M.stdio : M.remote, s.url ? h("code", { class: "mcp-url" }, s.url) : null),
          h("span", { class: "k" }, M.wrapped),
          h("span", null, s.wrapped ? M.yes : M.no),
          h("span", { class: "k" }, M.config),
          h("code", null, tildify(mcp.config_path || "")),
        ),
        // Only a local (stdio) server can be wrapped; a remote one has no CLI line.
        s.stdio || s.wrapped ? h("p", { class: "src" }, M.cliLead) : h("p", { class: "src" }, M.remoteNote),
        s.stdio || s.wrapped ? h("pre", { class: "code wrap" }, s.wrapped ? M.unwrap(arg) : M.wrap(arg)) : null,
      ),
    );
  }

  // ------------------------------------------------------------ routing

  function teardown() {
    if (detail) {
      try {
        detail.unmount();
      } catch (_) {
        /* ignore */
      }
    }
    detail = null;
  }

  function show(params) {
    const [kind, name] = params.segments || [];
    const nextView = kind === "skill" && name ? "skill" : kind === "mcp" && name ? "mcp" : "list";
    if (nextView === "skill" && view === "skill" && detail) {
      viewName = name;
      detail.update(name);
      return;
    }
    gen++;
    closeSheet();
    teardown();
    view = nextView;
    viewName = name || null;
    if (view === "skill") {
      showSkill(name);
    } else if (view === "mcp") {
      renderMCP();
      loadMCP();
    } else {
      renderList();
      loadBook();
      loadMCP();
      loadStats();
      if (!store.skills) store.refreshSkills().catch(() => {});
    }
  }

  return {
    title: C.title,
    mount(r, params) {
      root = r;
      if (store.status && store.status.claudeDir && store.status.claudeDir.endsWith("/.claude")) setHome(store.status.claudeDir.slice(0, -"/.claude".length));
      // Status polls every few seconds; the list is rebuilt for it only when
      // shadow mode changed (the banner), so focus is not lost on each poll.
      let shadowShown = !!(store.status && store.status.shadow === true);
      unsub = store.subscribe((ev) => {
        if (ev === "status") {
          const now = !!(store.status && store.status.shadow === true);
          if (now === shadowShown) return;
          shadowShown = now;
        }
        if ((ev === "skills" || ev === "status") && view === "list") renderList();
      });
      show(params);
    },
    update(params) {
      show(params);
    },
    unmount() {
      gen++;
      closeSheet();
      teardown();
      if (unsub) unsub();
      unsub = null;
      root = null;
      view = null;
      book = null;
      mcp = null;
      stats = null;
      shell = null;
      trySeq++;
      clearTimeout(hitTimer);
      busy = false;
      showDeclined = false;
    },
  };
}

registerPage("rules", rulesPage());
