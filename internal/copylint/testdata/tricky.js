// Fixture for TestScanJS. Every line after this header ends with a comment
// "want: <word>" (the banned word Scan must report on that line) or
// "want: none". Comments are never scanned, so these notes cannot hit.
const a1 = "the hook ran"; // want: hook
const a2 = 'Hooks are on'; // want: Hooks
const a3 = `${x} has no opinion`; // want: no opinion
const hookInstalled = true; // want: none
// the hook // want: none
const r1 = /hook"s/; // want: none
const r2 = foo(/"/, "a matcher here"); // want: matcher
const d1 = a / b / c; // want: none
const n1 = "navigate home"; // want: none
const p1 = "profile hash"; // want: profile hash
const p2 = "PreToolUse"; // want: PreToolUse
const k1 = { nonce: 1 }; // want: none
const k2 = { "nonce": 1 }; // want: nonce
const t1 = `outer ${pick(o, "the subject") || "?"} tail`; // want: subject
const t2 = `deep ${`inner ${"gate"}`} end`; // want: gate
const d2 = (n) / 2 + "fine"; // want: none
const r3 = s.replace(/[/"]hooks/g, "x"); // want: none
const r4 = cond ? /classifier/ : "plain"; // want: none
const r5 = typeof /x/ === "object" ? "ungranted" : ""; // want: ungranted
const e1 = "escaped\nhook"; // want: hook
const b1 = "hook-gate"; // want: hook gate
/* a block comment with hook inside */ const b2 = "ok"; // want: none
