// One skill's sandbox on the Rules page ("#/rules/skill/<name>"), moved
// from the old Skills page's detail panel in Plan 04 Task 12: what the
// skill requests, what you grant, what its scripts run under, the grant
// controls (network, write paths, caches, auto-allow), code references,
// audit notes, recent activity and the manifest. "*" ("%2A" in the hash)
// shows the defaults every skill starts from (GET /api/overrides), with the
// same grant controls. Every grant goes through confirmGrant, then
// postGrant.
import { api, store, fmt, h, icon, toast, replace } from "./app.js";
import { COPY } from "./copy.js";
import { skillPath, shellArg, hasScripts, ungrantedOf, viewLines, tildify, predictCommand, askToEdit, confirmGrant, postGrant, recordLabel, segControl, switchControl } from "./shared.js";

const D = COPY.rules.detail;
const CAP_ORDER = ["net", "cred", "exec", "env", "enc", "fs", "instr"];

function needsNet(row) {
  return Array.isArray(row.caps) && row.caps.includes("net");
}

/** Traffic light: prose-only → off; invalid manifest → deny; asks more → ask; else ok, unless the code needs network nothing grants. */
function light(row) {
  if (!hasScripts(row)) return "off";
  if (row.manifest === "invalid") return "deny";
  if (ungrantedOf(row).length) return "ask";
  if (row.manifest === "ok") return "ok";
  if (needsNet(row) && (row.effectiveDetail || {}).network === "none") return "deny";
  return "ok";
}

function lightLabel(row) {
  switch (light(row)) {
    case "off":
      return D.light.off;
    case "ask":
      return D.light.ask;
    case "deny":
      return row.manifest === "invalid" ? D.light.invalid : D.light.needsNet;
    default:
      return D.light.ok;
  }
}

function lightDot(row) {
  return h("span", { class: `light ${light(row)}`, role: "img", "aria-label": lightLabel(row), title: lightLabel(row) });
}

function capTag(cat) {
  const cls = cat === "net" ? "net" : cat === "cred" ? "cred" : "";
  return h("span", { class: `tag ${cls}`.trim(), title: D.caps[cat] || cat }, cat);
}

function overridesPath() {
  return (store.status && store.status.overridesPath) || "~/.config/watchdeck/overrides.yaml";
}

function restoreFocus(container, key) {
  if (!key || !container) return;
  const n = container.querySelector(`[data-k="${key.replace(/"/g, '\\"')}"]`);
  if (n) n.focus();
}
function focusedKey(container) {
  const a = document.activeElement;
  return container && a && container.contains(a) && a.dataset && a.dataset.k ? a.dataset.k : null;
}

/**
 * mountSkillDetail(root, name, ctx) → {update(name), unmount()}. Renders
 * into root; the Rules page owns the back link above it.
 */
export function mountSkillDetail(root, name) {
  let selected = name;
  let detail = null; // GET /api/skills/{name}: {row, override, defaults, manifestText, parseError?}
  let detailError = null;
  let echo = null; // last allowCommand echo {cmd, path, changed}
  let showAllHits = false;
  let showManifest = false;
  let showCmd = false;
  let addingPath = false;
  let addDraft = "";
  let alive = true;
  const isDefaults = () => selected === "*";

  const body = h("section", { class: "card detail rules-detail", "aria-label": D.yourGrant });
  replace(root, body);

  function rowByName(n) {
    const rows = (store.skills && store.skills.skills) || [];
    return rows.find((r) => r.name === n) || null;
  }

  async function load() {
    detail = null;
    detailError = null;
    render();
    const want = selected;
    try {
      if (want === "*") {
        const ov = await api.get("/api/overrides");
        if (!alive || want !== selected) return;
        detail = { override: ov.defaults || {}, defaults: ov.defaults || {}, parseError: ov.parseError || "", path: ov.path };
      } else {
        const d = await api.get(skillPath(want));
        if (!alive || want !== selected) return;
        detail = d;
        if (d && d.row && store.skills && Array.isArray(store.skills.skills)) {
          const i = store.skills.skills.findIndex((x) => x.name === want);
          if (i >= 0) store.skills.skills[i] = d.row;
        }
      }
    } catch (e) {
      if (!alive || want !== selected) return;
      detailError = e.status === 404 ? D.noSkill(want) : e.message;
    }
    render();
  }

  /** Confirm, then post. Resolves false when the dialog was cancelled (nothing posted). */
  async function grant(n, edit, label) {
    const key = focusedKey(body);
    if (!(await confirmGrant(n, edit))) {
      restoreFocus(body, key);
      return false;
    }
    try {
      const r = await postGrant(n, edit);
      echo = { cmd: r.allowCommand, path: r.overridesPath || overridesPath(), changed: r.changed };
      toast(r.changed ? label || D.saved : D.noChange, r.changed ? "ok" : "");
      await load();
      store.refreshSkills().catch(() => {});
      restoreFocus(body, key);
    } catch (e) {
      toast(e.message || D.requestFailed, "error");
    }
    return true;
  }

  function box(title, lines, extra = "") {
    return h("div", { class: `box ${extra}`.trim() }, h("div", { class: "box-title" }, title), h("div", { class: "box-body" }, lines.map((l) => h("div", null, l))));
  }

  function flowStrip(r) {
    const req = r.request
      ? box(D.request, viewLines(r.request, true))
      : box(D.request, [r.manifest === "invalid" ? D.invalidManifest : D.noManifest], "none");
    return h("div", { class: "flow3" }, req, box(D.grant, viewLines(r.grant)), box(D.runsUnder, viewLines(r.effectiveDetail), "dark"));
  }

  function editTheFileNote() {
    return h("span", { class: "ask-note", title: overridesPath() }, D.noFlag(tildify(overridesPath())));
  }

  function askBox(r) {
    const asks = ungrantedOf(r);
    if (!asks.length) return null;
    return h(
      "div",
      { class: "askbox", role: "region", "aria-label": D.asksTitle },
      h("div", { class: "ask-title" }, icon("warn"), D.asksTitle),
      asks.map((item) => {
        const edit = askToEdit(item);
        return h(
          "div",
          { class: "ask-item" },
          h("span", { class: "mono" }, item),
          edit
            ? h("button", { type: "button", class: "btn amber small", dataset: { k: `ask:${item}` }, on: { click: () => grant(r.name, edit, D.granted(item)) } }, D.grantButton)
            : editTheFileNote(),
        );
      }),
    );
  }

  // grantControls(n, grantView, asks): the network, write, caches and
  // auto-allow controls for skill n ("*" for the defaults block).
  function grantControls(n, grantView, asks) {
    const ov = (detail && detail.override) || {};
    const ovWrite = new Set(ov.write || []);
    const defWrite = new Set(((detail && detail.defaults) || {}).write || []);
    const netCur = grantView.network || "none";

    const writeTags = (grantView.write || []).map((p) => {
      const removable = ovWrite.has(p);
      return h(
        "span",
        { class: "tag", title: defWrite.has(p) && !removable ? D.fromDefaults : removable ? D.yourOverride : D.builtIn },
        p,
        removable
          ? h("button", { type: "button", class: "x", "aria-label": D.removeWrite(p), dataset: { k: `rmw:${p}` }, on: { click: () => grant(n, { removeWrite: [p] }, D.writeRemoved) } }, icon("x", 11))
          : null,
      );
    });

    const addRow = addingPath
      ? (() => {
          const input = h("input", { type: "text", placeholder: D.addPathPlaceholder, "aria-label": D.addPathLabel, dataset: { k: "addw:input" } });
          input.value = addDraft;
          const close = () => {
            addingPath = false;
            addDraft = "";
            render();
          };
          const submit = async () => {
            const v = input.value.trim();
            if (!v) return;
            addingPath = false;
            addDraft = "";
            if (!(await grant(n, { addWrite: [v] }, D.writeAdded(v)))) {
              // Cancelled: nothing was posted; reopen the input with the text.
              addingPath = true;
              addDraft = v;
              render();
              restoreFocus(body, "addw:input");
            }
          };
          input.addEventListener("keydown", (e) => {
            if (e.key === "Enter") {
              // Without this, the same Enter press activates the confirm
              // dialog's focused Cancel button and the grant is dropped.
              e.preventDefault();
              submit();
            }
            if (e.key === "Escape") close();
          });
          return h(
            "div",
            { class: "field" },
            input,
            h("button", { type: "button", class: "btn small", on: { click: submit } }, D.add),
            h("button", { type: "button", class: "btn ghost small", on: { click: close } }, D.cancel),
          );
        })()
      : null;

    const cachesOn = ov.caches === true;
    const autoOn = grantView.autoAllow === true;

    const echoText = echo
      ? echo.cmd || D.noCliEcho(tildify(echo.path))
      : (() => {
          const first = (asks || []).map(askToEdit).find(Boolean);
          return first ? predictCommand(n, first) : D.showLine(shellArg(n));
        })();

    return h(
      "div",
      { class: "stack" },
      h("p", { class: "lbl" }, D.yourGrant),
      h("div", { class: "grant-row" }, h("span", { class: "k" }, D.network), segControl(D.network, ["none", "localhost", "all"], netCur, (v) => v !== netCur && grant(n, { network: v }, D.networkSet(v)), "net")),
      h(
        "div",
        { class: "grant-row" },
        h("span", { class: "k" }, D.write),
        h(
          "span",
          { class: "tags" },
          writeTags,
          addingPath
            ? null
            : h(
                "button",
                {
                  type: "button",
                  class: "btn ghost small",
                  dataset: { k: "addw" },
                  on: {
                    click: () => {
                      addingPath = true;
                      render();
                      const i = body.querySelector('[data-k="addw:input"]');
                      if (i) i.focus();
                    },
                  },
                },
                icon("plus", 12),
                D.addPath,
              ),
        ),
      ),
      addRow,
      h(
        "div",
        { class: "grant-row" },
        h("span", { class: "k" }, D.caches),
        switchControl(D.cachesLabel, cachesOn, (on) => grant(n, { caches: on }, on ? D.cachesAllowed : D.cachesRevoked), "caches"),
        h("span", { class: "src" }, cachesOn ? D.cachesOnText : D.offText),
      ),
      h(
        "div",
        { class: "grant-row" },
        h("span", { class: "k" }, D.autoAllow),
        switchControl(D.autoLabel, autoOn, (on) => grant(n, { autoAllow: on }, on ? D.autoOn : D.autoOff), "auto"),
        h("span", { class: "src" }, autoOn ? D.autoOnText : D.autoOffText),
      ),
      h(
        "details",
        {
          class: "sk-cmd",
          open: showCmd,
          on: {
            toggle: (e) => {
              showCmd = e.currentTarget.open;
            },
          },
        },
        h("summary", null, D.showCommand),
        h("pre", { class: `code wrap${echo && !echo.cmd ? " quiet" : ""}`, title: D.commandTitle }, echoText),
      ),
    );
  }

  function codeRefs(r) {
    const hits = [...(Array.isArray(r.hits) ? r.hits : [])].sort((a, b) => CAP_ORDER.indexOf(a.category) - CAP_ORDER.indexOf(b.category) || a.file.localeCompare(b.file) || a.line - b.line);
    if (!hits.length) return hasScripts(r) ? h("p", { class: "src" }, D.noRefs) : null;
    const shown = showAllHits ? hits : hits.slice(0, 6);
    return h(
      "div",
      { class: "stack-sm" },
      h("p", { class: "lbl" }, D.refs(hits.length)),
      h(
        "div",
        { class: "kv refs" },
        shown.flatMap((x) => [capTag(x.category), h("span", { class: "ref", title: x.pattern }, h("span", { class: "loc" }, `${x.file}:${x.line} `), x.snippet)]),
      ),
      hits.length > 6
        ? h(
            "button",
            {
              type: "button",
              class: "btn link small",
              "aria-expanded": String(showAllHits),
              on: {
                click: () => {
                  showAllHits = !showAllHits;
                  render();
                },
              },
            },
            showAllHits ? D.showFewer : D.showAll(hits.length),
          )
        : null,
    );
  }

  function notes(r) {
    const items = [];
    if (r.manifestError) items.push(D.manifestNote(r.manifestError));
    for (const p of r.problems || []) items.push(p);
    for (const p of r.ignored || []) items.push(p);
    if (!items.length) return null;
    return h("div", { class: "stack-sm" }, h("p", { class: "lbl" }, D.notesTitle), h("ul", { class: "list small" }, items.map((t) => h("li", null, t))));
  }

  function recent(r) {
    const recs = ((store.activity && store.activity.records) || []).filter((x) => Array.isArray(x.skills) && x.skills.includes(r.name)).slice(-5).reverse();
    if (!recs.length) return null;
    return h(
      "div",
      { class: "stack-sm" },
      h("p", { class: "lbl" }, D.recentTitle),
      h(
        "div",
        { class: "act" },
        recs.flatMap((x) => [
          h("span", { class: "t", title: x.ts }, fmt.time(x.ts)),
          h("span", { class: `tag ${x.kind === "denied" || (x.hints && x.hints.length) ? "deny" : x.kind === "run" ? (x.outcome === "ok" ? "ok" : "ask") : "none"}` }, x.kind),
          h("span", { class: "small wrap" }, recordLabel(x)),
        ]),
      ),
    );
  }

  function manifestViewer(r) {
    if (!showManifest) return null;
    if (!detail) return h("pre", { class: "code quiet" }, D.loading);
    const text = detail.manifestText;
    if (text) return h("pre", { class: "code" }, text);
    return h("pre", { class: "code quiet" }, r.manifest === "invalid" ? D.manifestInvalid(r.manifestPath, r.manifestError) : D.manifestNone);
  }

  function renderDefaults() {
    if (!detail) {
      replace(body, h("div", { class: "empty" }, h("p", null, detailError || D.loading)));
      return;
    }
    const d = detail.defaults || {};
    const empty = !d.network && !(d.write && d.write.length) && !d.caches && d.autoAllow === undefined;
    const grantView = { network: d.network || "none", write: d.write || [], autoAllow: d.autoAllow === true };
    replace(
      body,
      h("div", null, h("div", { class: "row" }, h("span", { class: "name lg" }, D.defaultsTitle)), h("p", { class: "muted small mt6" }, D.defaultsLead)),
      detail.parseError ? h("div", { class: "banner deny" }, D.overridesBroken(detail.parseError)) : null,
      empty ? h("p", { class: "src" }, D.defaultsNone) : null,
      detail.parseError ? null : grantControls("*", grantView, []),
    );
  }

  function render() {
    if (!alive) return;
    const key = focusedKey(body);
    const typing = body.querySelector('[data-k="addw:input"]');
    const typed = typing ? typing.value : null;
    if (isDefaults()) {
      renderDefaults();
    } else {
      const r = rowByName(selected) || (detail && detail.row) || null;
      if (!r) {
        replace(body, h("div", { class: "empty" }, h("p", null, detailError || (store.skills && detail ? D.noSkill(selected) : D.loading))));
        return;
      }
      const scripts = hasScripts(r);
      replace(
        body,
        h(
          "div",
          null,
          h("div", { class: "row" }, lightDot(r), h("span", { class: "name lg" }, r.name), h("span", { class: "src right" }, r.pluginId ? `${r.source} · ${r.pluginId}` : r.source)),
          h("div", { class: "src mono wrap" }, `${tildify(r.root)} · ${fmt.shortHash(r.hash)}`),
          r.description ? h("p", { class: "muted small mt6" }, r.description) : null,
          !scripts ? h("p", { class: "src mt6" }, D.proseOnly) : null,
        ),
        detailError ? h("div", { class: "banner deny" }, detailError) : null,
        scripts ? h("div", null, h("p", { class: "lbl" }, D.flowTitle), flowStrip(r)) : null,
        scripts ? askBox(r) : null,
        scripts ? grantControls(r.name, r.grant || {}, ungrantedOf(r)) : null,
        codeRefs(r),
        notes(r),
        recent(r),
        h(
          "div",
          { class: "row" },
          h("a", { class: "btn ghost", href: "#/sessions" }, D.seeSessions),
          h(
            "button",
            {
              type: "button",
              class: "btn ghost",
              "aria-expanded": String(showManifest),
              dataset: { k: "manifest" },
              on: {
                click: () => {
                  showManifest = !showManifest;
                  render();
                },
              },
            },
            icon("file", 14),
            D.manifestButton,
          ),
        ),
        manifestViewer(r),
      );
    }
    if (typed !== null) {
      const again = body.querySelector('[data-k="addw:input"]');
      if (again) again.value = typed;
    }
    restoreFocus(body, key);
  }

  // Polls must not re-render the panel (that drops focus, text selection
  // and a half-typed write path): re-render on the first status (it carries
  // claudeDir, for ~ paths), when this skill's row changes, and when a new
  // activity record names this skill.
  let sawStatus = !!store.status;
  let rowSig = sigOf(rowByName(selected));
  let actSig = recentSig();
  function sigOf(row) {
    return row ? JSON.stringify(row) : "";
  }
  function recentSig() {
    const recs = ((store.activity && store.activity.records) || []).filter((x) => Array.isArray(x.skills) && x.skills.includes(selected));
    const last = recs[recs.length - 1];
    return last ? `${recs.length}:${last.ts}` : "";
  }
  const unsub = store.subscribe((ev) => {
    if (addingPath) return;
    if (ev === "status") {
      if (sawStatus) return;
      sawStatus = true;
      render();
    } else if (ev === "skills") {
      const sig = sigOf(rowByName(selected));
      if (sig === rowSig) return;
      rowSig = sig;
      render();
    } else if (ev === "activity") {
      const sig = recentSig();
      if (sig === actSig) return;
      actSig = sig;
      render();
    }
  });
  if (!store.skills) store.refreshSkills().catch(() => {});
  load();

  return {
    update(n) {
      if (n === selected) return;
      selected = n;
      rowSig = sigOf(rowByName(n));
      actSig = recentSig();
      echo = null;
      showAllHits = false;
      showManifest = false;
      addingPath = false;
      addDraft = "";
      load();
    },
    unmount() {
      alive = false;
      unsub();
    },
  };
}
