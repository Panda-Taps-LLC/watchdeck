// Confirmed dashboard writes (Plan 04 Task 2). Every write the dashboard
// makes goes through writeWithConfirm: a confirm dialog that names the
// file, then one POST carrying the page's one-use confirmation token, and
// one retry with a fresh token when the server says the old one expired.
// It never throws; callers get {ok, data}, {ok: false, error} or the
// cancelled() sentinel.
import { api, confirmDialog, h, toast } from "./app.js";
import { COPY } from "./copy.js";

const CANCELLED = Object.freeze({ ok: false, cancelled: true, error: null });

/** cancelled(): the one result for a declined dialog (nothing was posted); test with r === cancelled(). */
export function cancelled() {
  return CANCELLED;
}

/** bodyOf(file, lines, backup): the dialog body: file line, the caller's lines, then the backup line. */
function bodyOf(file, lines, backup) {
  const para = (x) => (x instanceof Node ? x : h("p", null, x));
  return h(
    "div",
    { class: "stack-sm" },
    file ? h("p", null, COPY.common.fileLabel, h("code", null, file)) : null,
    (Array.isArray(lines) ? lines : lines ? [lines] : []).filter((x) => x !== null && x !== undefined && x !== "").map(para),
    backup && file ? h("p", null, COPY.common.backupLine(file)) : null,
  );
}

/** messageOf(e): the toast text: a fixed line for an expired confirmation, else the server's error text. */
function messageOf(e) {
  if (e && e.status === 403) return COPY.common.expired;
  return (e && e.message) || String(e);
}

/**
 * writeWithConfirm({title, body, file, backup, confirmLabel, danger, path,
 * payload, alt, nonce, refetchNonce, onStart}) → Promise<{ok: true, data,
 * choice} | {ok: false, error, choice} | cancelled()>.
 *
 * body: lines (strings or Nodes) under the file line; backup adds
 * COPY.common.backupLine(file). On confirm, onStart() runs (pages mark
 * themselves busy there), then POST path with {...payload, nonce}. On a
 * 403 it calls refetchNonce() once and retries once with that value (a
 * refetch that fails or returns "" is no retry, only the expired toast). Any
 * failure is toasted with the server's text and returned; nothing throws.
 *
 * alt: {label, payload} offers a second, lesser action in the same dialog
 * (confirmDialog's altLabel); choosing it posts alt.payload to the same
 * path instead of payload. choice is "alt" then, else "ok".
 */
export async function writeWithConfirm({ title, body, file, backup = false, confirmLabel, danger = false, path, payload, alt = null, nonce, refetchNonce, onStart } = {}) {
  let ok = false;
  const altLabel = alt && alt.label && alt.payload ? alt.label : "";
  try {
    ok = await confirmDialog({ title, body: bodyOf(file, body, backup), confirmLabel: confirmLabel || COPY.common.confirm, danger: !!danger, altLabel });
  } catch (e) {
    const error = messageOf(e);
    toast(error, "error");
    return { ok: false, error };
  }
  if (!ok) return CANCELLED;
  const choice = ok === "alt" && altLabel ? "alt" : "ok";
  const chosen = choice === "alt" ? alt.payload : payload;
  try {
    if (onStart) onStart();
  } catch (_) {
    /* a page's busy marker failing must not stop the write */
  }
  const send = (n) => api.post(path, { ...(chosen || {}), nonce: n });
  try {
    return { ok: true, data: await send(nonce), choice };
  } catch (e) {
    if (e && e.status === 403 && typeof refetchNonce === "function") {
      try {
        let fresh = "";
        try {
          fresh = await refetchNonce();
        } catch (_) {
          fresh = "";
        }
        if (typeof fresh !== "string" || fresh === "") {
          // No fresh confirmation to retry with: say it expired rather
          // than post an empty one and toast the server's 400 text.
          toast(COPY.common.expired, "error");
          return { ok: false, error: COPY.common.expired, choice };
        }
        return { ok: true, data: await send(fresh), choice };
      } catch (e2) {
        const error = messageOf(e2);
        toast(error, "error");
        return { ok: false, error, choice };
      }
    }
    const error = messageOf(e);
    toast(error, "error");
    return { ok: false, error, choice };
  }
}
