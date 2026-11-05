// Settings page (registered "settings", the header's gear, "#/settings").
// Two cards: "Claude Code" (watchdeck's entries in each settings file, from
// GET /api/enforce, with Install and Uninstall) and "Dashboard" (autostart
// through /api/config, Remember me, theme). Every write goes through
// write.js; this file sends no POST of its own.
import { api, registerPage, h, replace, icon, toast, store, el, theme, setTheme, remembered, setRemembered } from "./app.js";
import { COPY } from "./copy.js";
import { writeWithConfirm, cancelled } from "./write.js";

const C = COPY.settings;
const THEMES = ["auto", "light", "dark"];

// A switch (role="switch" with aria-checked), the same .sw control the other pages use.
function switchButton(label, on, onToggle, disabled) {
  return h("button", { type: "button", class: "sw", role: "switch", "aria-checked": String(!!on), "aria-label": label, title: label, disabled: !!disabled, on: { click: () => onToggle(!on) } });
}

function statusLine({ on, text, warn }) {
  return h(
    "div",
    { class: "status-line" },
    h("span", { class: `mark ${warn ? "warn" : on ? "on" : "off"}`, "aria-hidden": "true" }, icon(warn ? "warn" : on ? "check" : "x", 12)),
    h("span", { class: "sr" }, warn ? C.warning : on ? C.present : C.absent),
    h("span", { class: "wrap" }, text),
  );
}

/** stateOf(status) → "installed" | "partial" | "none". */
function stateOf(st) {
  const s = st || {};
  if (s.complete === true) return "installed";
  const any = [s.hookInstalled, s.skillHook, s.deniedHook, s.startHook, s.endHook, s.promptHook, s.excluded].some((v) => v === true);
  return any ? "partial" : "none";
}

function settingsPage() {
  let root = null;
  let claudeBody = null;
  let dashBody = null;
  let enforce = null; // GET /api/enforce: {targets, nonce, nonceTtlSeconds}
  let enforceError = null;
  let config = null; // GET /api/config: {path, autostart, installed_at, nonce, nonce_ttl_seconds}
  let configError = null;
  let results = {}; // target id → {action, change}
  let busy = false;
  let unsub = null;
  let themeBtn = null;

  async function loadEnforce() {
    try {
      enforce = await api.get("/api/enforce");
      enforceError = null;
    } catch (e) {
      enforceError = e.message;
    }
    renderClaude();
    return enforce ? enforce.nonce : "";
  }

  async function loadConfig() {
    try {
      config = await api.get("/api/config");
      configError = null;
    } catch (e) {
      configError = e.message;
    }
    renderDash();
    return config ? config.nonce : "";
  }

  // ------------------------------------------------------------ Claude Code

  async function act(t, action) {
    if (busy || !enforce) return;
    const install = action === "install";
    const lines = [install ? C.installBody : C.uninstallBody];
    if (!t.exists) lines.push(C.newFile);
    if (install && t.id === "project") lines.push(h("p", { class: "small muted" }, C.projectNote));
    const r = await writeWithConfirm({
      title: install ? C.installTitle(t.id) : C.uninstallTitle(t.id),
      body: lines,
      file: t.path,
      backup: !!t.exists,
      confirmLabel: install ? C.install : C.uninstall,
      danger: !install,
      path: "/api/enforce",
      payload: { target: t.id, action },
      nonce: enforce.nonce,
      refetchNonce: loadEnforce,
      onStart: () => {
        busy = true;
        renderClaude();
      },
    });
    if (r === cancelled()) return;
    busy = false;
    if (r.ok) {
      results[t.id] = { action, change: r.data && r.data.change };
      toast(install ? C.installed : C.removed, "ok");
      store.refreshStatus().catch(() => {});
    }
    await loadEnforce();
  }

  function unreadableBlock(t) {
    return h(
      "div",
      { class: "card warn", "aria-label": C.target(t.id) },
      h("div", { class: "row" }, h("span", { class: "card-title" }, C.target(t.id)), h("span", { class: "tag deny" }, C.state.unreadable)),
      h("div", { class: "src mono wrap" }, t.path),
      h("div", { class: "banner deny", role: "alert" }, h("div", { class: "stack-sm" }, h("strong", null, C.unreadable), h("div", { class: "mono small wrap" }, t.error), h("div", null, C.unreadableFix))),
    );
  }

  function targetBlock(t) {
    if (t.error) return unreadableBlock(t);
    const st = t.status || {};
    const state = stateOf(st);
    const lines = C.lines(st);
    const res = results[t.id];
    const change = res && res.change;
    const tagClass = state === "installed" ? "ok" : state === "partial" ? "ask" : "none";
    return h(
      "div",
      { class: `card${state === "partial" ? " warn" : ""}`, "aria-label": C.target(t.id) },
      h(
        "div",
        { class: "row" },
        h("span", { class: "card-title" }, C.target(t.id)),
        h("span", { class: `tag ${tagClass}` }, C.state[state]),
        t.exists ? null : h("span", { class: "tag none", title: C.fileMissingTitle }, C.fileMissing),
      ),
      h("div", { class: "src mono wrap" }, t.path),
      h("div", { class: "status-list" }, lines.map(statusLine)),
      lines.some((l) => l.warn) ? h("div", { class: "banner", role: "note" }, C.sandboxWarn) : null,
      t.id === "project" ? h("div", { class: "banner", role: "note" }, C.projectNote) : null,
      change
        ? h(
            "div",
            { class: `banner ${res.action === "install" ? "ok" : ""}` },
            h(
              "div",
              { class: "stack-sm" },
              h("strong", null, res.action === "install" ? C.installed : C.removed),
              h("div", { class: "small" }, C.changed((change.added || []).length, (change.removed || []).length)),
              change.backup ? h("div", { class: "small" }, C.backupAt, h("span", { class: "mono" }, change.backup)) : null,
            ),
          )
        : null,
      h(
        "div",
        { class: "row" },
        h("button", { type: "button", class: "btn ghost", disabled: busy || state === "installed", on: { click: () => act(t, "install") } }, C.install),
        h("button", { type: "button", class: "btn ghost", disabled: busy || state === "none", on: { click: () => act(t, "uninstall") } }, C.uninstall),
        h("span", { class: "src mono right set-cli" }, C.cli(state === "installed" ? "uninstall" : "install", t.id === "project")),
      ),
    );
  }

  function renderClaude() {
    if (!claudeBody) return;
    const kids = [];
    const st = store.status;
    if (st && st.enforcementAvailable === false) kids.push(h("div", { class: "banner deny" }, COPY.pill.noBackend(st.platform)));
    if (enforceError) kids.push(h("div", { class: "banner deny", role: "alert" }, C.loadFailed(enforceError)));
    else if (!enforce) kids.push(h("div", { class: "empty" }, C.loading));
    else {
      const targets = enforce.targets || [];
      kids.push(h("div", { class: "cards" }, targets.map(targetBlock)));
      if (!targets.some((t) => t.id === "project")) kids.push(h("p", { class: "src" }, C.noProject));
    }
    replace(claudeBody, ...kids);
  }

  // ------------------------------------------------------------ Dashboard

  async function toggleAutostart(on) {
    if (busy || !config) return;
    const r = await writeWithConfirm({
      title: on ? C.autostartOnTitle : C.autostartOffTitle,
      body: [on ? C.autostartOnBody : C.autostartOffBody],
      file: config.path,
      backup: false,
      confirmLabel: on ? C.turnOn : C.turnOff,
      danger: false,
      path: "/api/config",
      payload: { autostart: on },
      nonce: config.nonce,
      refetchNonce: loadConfig,
      onStart: () => {
        busy = true;
        renderDash();
      },
    });
    if (r === cancelled()) return;
    busy = false;
    if (r.ok && r.data) {
      config.autostart = !!r.data.autostart;
      if (r.data.nonce) config.nonce = r.data.nonce;
      toast(config.autostart ? C.autostartOn : C.autostartOff, "ok");
      renderDash();
    } else {
      await loadConfig();
    }
  }

  function autostartBlock() {
    if (configError) return h("div", { class: "banner deny", role: "alert" }, C.configFailed(configError));
    if (!config) return h("div", { class: "empty" }, C.loading);
    const on = config.autostart === true;
    const at = config.installed_at ? new Date(config.installed_at) : null;
    return h(
      "div",
      { class: "card" },
      h("div", { class: "row" }, h("span", { class: "card-title grow" }, C.autostartLabel), switchButton(C.autostartLabel, on, toggleAutostart, busy)),
      h("p", { class: "src" }, C.autostartHelp, config.autostart === null || config.autostart === undefined ? " " + C.autostartUnset : ""),
      h("p", { class: "src" }, C.savedIn, h("span", { class: "mono" }, config.path)),
      h("p", { class: "src" }, at && !Number.isNaN(at.getTime()) ? C.setUpOn(at.toLocaleDateString()) : C.notSetUp),
    );
  }

  function rememberBlock() {
    const box = h("input", {
      type: "checkbox",
      id: "remember-me",
      checked: remembered(),
      on: {
        change: () => {
          if (!setRemembered(box.checked)) {
            box.checked = false;
            toast(C.rememberBlocked, "error");
            return;
          }
          toast(box.checked ? C.rememberOn : C.rememberOff);
        },
      },
    });
    return h("div", { class: "card" }, h("p", { class: "lbl" }, C.rememberTitle), h("label", { class: "check", for: "remember-me" }, box, " ", C.rememberLabel), h("p", { class: "src" }, C.rememberHelp));
  }

  function themeBlock() {
    const cur = theme();
    return h(
      "div",
      { class: "card" },
      h("p", { class: "lbl" }, C.themeTitle),
      h(
        "div",
        { class: "seg", role: "group", "aria-label": C.themeTitle },
        THEMES.map((v) =>
          h(
            "button",
            {
              type: "button",
              "aria-pressed": String(v === cur),
              title: COPY.common.theme.label[v],
              on: {
                click: () => {
                  setTheme(v);
                  renderDash();
                },
              },
            },
            COPY.common.theme.word[v],
          ),
        ),
      ),
      h("p", { class: "src" }, C.themeHelp),
    );
  }

  function renderDash() {
    if (!dashBody) return;
    replace(dashBody, h("div", { class: "cards" }, autostartBlock(), rememberBlock(), themeBlock()));
  }

  return {
    title: C.title,
    mount(r) {
      root = r;
      claudeBody = h("div", { class: "stack" });
      dashBody = h("div", { class: "stack" });
      root.append(
        h("div", { class: "page-head" }, h("h1", { class: "h1" }, C.title), h("p", { class: "lead" }, C.lead)),
        h("section", { class: "stack", "aria-labelledby": "set-claude-h" }, h("h2", { class: "lbl", id: "set-claude-h" }, C.claudeTitle), h("p", { class: "src" }, C.claudeLead), claudeBody),
        h("section", { class: "stack", "aria-labelledby": "set-dash-h" }, h("h2", { class: "lbl", id: "set-dash-h" }, C.dashboardTitle), dashBody),
      );
      renderClaude();
      renderDash();
      loadEnforce();
      loadConfig();
      unsub = store.subscribe((ev) => {
        if (ev === "status") renderClaude();
      });
      // The top bar's theme button changes the same setting; keep the
      // three-way control here in step (app.js's listener runs first).
      themeBtn = el("theme-toggle");
      if (themeBtn) themeBtn.addEventListener("click", renderDash);
    },
    update() {
      loadEnforce();
      loadConfig();
    },
    unmount() {
      if (unsub) unsub();
      if (themeBtn) themeBtn.removeEventListener("click", renderDash);
      unsub = null;
      themeBtn = null;
      root = null;
      claudeBody = null;
      dashBody = null;
      enforce = null;
      config = null;
      results = {};
      busy = false;
    },
  };
}

registerPage("settings", settingsPage());
