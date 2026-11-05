// Helpers shared by the pages (Plan 04 Task 12 moved them here from
// pages.js, the barrel, so a page never imports the barrel). This module
// imports app.js and copy.js only. Exported: skillPath, skillHash, shellArg,
// hasScripts, ungrantedOf, predictCommand, askToEdit, confirmGrant,
// postGrant, postRulePreview, postTry, recordLabel, viewLines, tildify,
// segControl, switchControl.
// All DOM is built with h(); the CSP forbids inline styles.
import { api, store, h, confirmDialog } from "./app.js";
import { COPY } from "./copy.js";

const DEFAULT_ENV = ["PATH", "HOME", "LANG", "TMPDIR"];
const NET_RANK = { none: 0, localhost: 1, all: 2 };

/** API path for a skill; "*" (the defaults block) must be sent as %2A. */
export function skillPath(name) {
  return "/api/skills/" + encodeURIComponent(name).replace(/\*/g, "%2A");
}
/** skillHash(name): the skill's drill-in on the Rules page. */
export function skillHash(name) {
  return "#/rules/skill/" + encodeURIComponent(name).replace(/\*/g, "%2A");
}
export function hasScripts(row) {
  return Array.isArray(row.scripts) && row.scripts.length > 0;
}
export function ungrantedOf(row) {
  return Array.isArray(row.ungranted) ? row.ungranted : [];
}

function abbrevPath(p) {
  if (p === "${CWD}") return "cwd";
  if (p === "${TMP}") return "tmp";
  return p.replace(/^\$\{HOME\}/, "~");
}

/** Short lines for the Request → Grant → Runs-under strip (COPY.grant.view). */
export function viewLines(view, isRequest) {
  if (!view) return [];
  const V = COPY.grant.view;
  const out = [];
  out.push(V.net(view.network || "none"));
  if (view.write) out.push(V.write(view.write.length ? view.write.map(abbrevPath).join(",") : "-"));
  else if (!isRequest) out.push(V.write("-"));
  if (view.env) {
    const extra = view.env.filter((e) => !DEFAULT_ENV.includes(e));
    out.push(extra.length ? V.envExtra(extra.length) : V.envDefault);
  } else if (!isRequest) out.push(V.envDefault);
  if (view.execAny === false) out.push(V.exec((view.exec || []).length));
  if (view.autoAllow) out.push(V.autoAllow);
  if (isRequest && view.read && view.read.length) out.push(V.read(view.read.length));
  return out;
}

function homeDir() {
  const cd = store.status && store.status.claudeDir;
  if (cd && cd.endsWith("/.claude")) return cd.slice(0, -"/.claude".length);
  return null;
}
/** tildify(p): p with the home directory (from /api/status) shown as "~". */
export function tildify(p) {
  const home = homeDir();
  if (home && p && p.startsWith(home + "/")) return "~" + p.slice(home.length);
  return p || "";
}

function overridesPath() {
  return (store.status && store.status.overridesPath) || "~/.config/watchdeck/overrides.yaml";
}

/** Mirror of manifest.shellArg: single-quote s unless every byte is shell-neutral. */
export function shellArg(s) {
  if (s !== "" && /^[A-Za-z0-9._\-/:@%+,=]+$/.test(s)) return s;
  return "'" + s.replace(/'/g, "'\\''") + "'";
}

/** Mirror of manifest.AllowCommand (§1c): the exact line the server answers with. */
export function predictCommand(name, edit) {
  const who = shellArg(name);
  if (edit.reset) return `watchdeck allow ${who} --reset`;
  if (["clearNetwork", "clearAutoAllow", "addRead", "removeRead", "addEnv", "removeEnv"].some((k) => edit[k] !== undefined)) return null;
  const parts = [];
  if (edit.network !== undefined) parts.push("--network", edit.network);
  for (const p of edit.addWrite || []) parts.push("--write", shellArg(p));
  for (const p of edit.removeWrite || []) parts.push("--remove-write", shellArg(p));
  if (edit.caches !== undefined) parts.push(edit.caches ? "--caches" : "--no-caches");
  if (edit.autoAllow !== undefined) parts.push(edit.autoAllow ? "--auto" : "--no-auto");
  return parts.length ? `watchdeck allow ${who} ${parts.join(" ")}` : null;
}

/** Parse "network: all" → {kind: "network", value: "all"}. */
function parseAsk(s) {
  const i = s.indexOf(":");
  if (i < 0) return { kind: s.trim(), value: "" };
  return { kind: s.slice(0, i).trim(), value: s.slice(i + 1).trim() };
}

/** The EditJSON a Grant button sends for an item asked for but not granted, or null when only the file can do it. */
export function askToEdit(item) {
  const { kind, value } = parseAsk(item);
  if (kind === "network" && value in NET_RANK) return { network: value };
  if (kind === "write" && value) return { addWrite: [value] };
  return null;
}

/**
 * confirmGrant(name, edit) → Promise<boolean>. Every grant change goes
 * through this dialog first: it names the target (a skill, or "*" for every
 * skill) and the exact `watchdeck allow` line the server will apply
 * (predictCommand mirrors manifest.AllowCommand). Cancel posts nothing.
 */
export function confirmGrant(name, edit) {
  const C = COPY.grant;
  const cmd = predictCommand(name, edit);
  return confirmDialog({
    title: C.title(name),
    body: h(
      "div",
      { class: "stack-sm" },
      h("p", null, C.skillLabel, h("code", null, C.who(name))),
      cmd ? h("p", null, C.sameAs) : h("p", null, C.noCli(tildify(overridesPath()))),
      h("code", null, cmd || JSON.stringify(edit)),
    ),
    confirmLabel: C.apply,
    danger: true,
  });
}

/** postGrant(name, edit): POST the edit; patches store.skills with the answer's row. */
export async function postGrant(name, edit) {
  const r = await api.post(skillPath(name) + "/grant", edit);
  if (r && r.row && store.skills && Array.isArray(store.skills.skills)) {
    const i = store.skills.skills.findIndex((x) => x.name === name);
    if (i >= 0) store.skills.skills[i] = r.row;
  }
  return r;
}

/**
 * postRulePreview(request) → Promise<{ok: true, data} | {ok: false, status,
 * error}>: POST /api/rules/propose with {request}, the one route that
 * builds a plan and writes nothing. The path is fixed so this can never
 * become an unconfirmed write; writes go through write.js. data is
 * {plan, refused}: plan null and refused the reason when the rulebook
 * refuses the request. It never toasts and never throws.
 */
export async function postRulePreview(request) {
  try {
    return { ok: true, data: await api.post("/api/rules/propose", { request }) };
  } catch (e) {
    return { ok: false, status: (e && e.status) || 0, error: (e && e.message) || String(e) };
  }
}

/**
 * postTry(body, project) → Promise<{ok: true, data} | {ok: false, status,
 * error}>: POST /api/rules/try with {what, value}, the route that says what
 * the saved rules answer for one call and writes nothing (Plan 08 Task 4),
 * so it takes no confirmation. project (the page's project root, "" for
 * none) goes in ?project= so the project's own rules count. The path is
 * fixed, like postRulePreview's. data is the explain document plus
 * project_scope. It never toasts and never throws.
 */
export async function postTry(body, project) {
  const path = "/api/rules/try" + (project ? "?project=" + encodeURIComponent(project) : "");
  try {
    return { ok: true, data: await api.post(path, { what: body.what, value: body.value }) };
  } catch (e) {
    return { ok: false, status: (e && e.status) || 0, error: (e && e.message) || String(e) };
  }
}

export function segControl(label, options, current, onPick, key) {
  return h(
    "div",
    { class: "seg", role: "group", "aria-label": label },
    options.map((o) =>
      h(
        "button",
        { type: "button", "aria-pressed": String(o === current), dataset: { k: `${key}:${o}` }, on: { click: () => onPick(o) } },
        o,
      ),
    ),
  );
}

export function switchControl(label, on, onToggle, key) {
  // A switch (role="switch" with aria-checked), which VoiceOver announces as one.
  return h("button", {
    type: "button",
    class: "sw",
    role: "switch",
    "aria-checked": String(!!on),
    "aria-label": label,
    title: label,
    dataset: { k: key },
    on: { click: () => onToggle(!on) },
  });
}

/** recordLabel(r): one activity record as a short line. */
export function recordLabel(r) {
  const C = COPY.grant.record;
  switch (r.kind) {
    case "decision":
      return C.decision(r.decision, r.confidence === "low");
    case "run":
      return C.run(r.outcome, typeof r.exit === "number" ? r.exit : null, r.hints && r.hints.length ? r.hints[0].kind : "");
    case "denied":
      return C.denied(r.reason || "");
    case "skill_invoked":
      return C.invoked;
    default:
      return r.kind;
  }
}
