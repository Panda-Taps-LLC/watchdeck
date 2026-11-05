// Accessibility pass for the dashboard walkthrough (walk.mjs --axe).
//
// Runs axe-core (through @axe-core/playwright, exact pins in package.json)
// on the page as it stands after settle, with the WCAG 2 A and AA rule tags
// only (best-practice rules are not run). A route fails on any violation of
// impact serious or critical, and on a run in which axe evaluated no rule at
// all: a page that never rendered, or an axe that never loaded, would
// otherwise pass with zero violations.
import { AxeBuilder } from "@axe-core/playwright";

const FAIL_IMPACTS = new Set(["serious", "critical"]);

// runAxe(page) → {total, passes, incomplete, counts: {critical, serious,
// moderate, minor}, failures: [line], vacuous}
export async function runAxe(page) {
  const results = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa"]).analyze();
  const counts = { critical: 0, serious: 0, moderate: 0, minor: 0 };
  const failures = [];
  for (const v of results.violations) {
    const impact = v.impact || "minor";
    counts[impact] = (counts[impact] || 0) + v.nodes.length;
    if (!FAIL_IMPACTS.has(impact)) continue;
    const targets = v.nodes.slice(0, 2).map((n) => n.target.join(" ")).join(" ; ");
    const why = ((v.nodes[0].any[0] || v.nodes[0].all[0] || {}).message || "").slice(0, 160);
    failures.push(`axe ${impact} ${v.id} (${v.nodes.length} node${v.nodes.length === 1 ? "" : "s"}): ${targets} ${v.helpUrl}${why ? " [" + why + "]" : ""}`);
  }
  const vacuous = results.passes.length + results.violations.length + results.incomplete.length === 0;
  if (vacuous) failures.push("axe evaluated no rule on this page");
  return {
    total: results.passes.length + results.violations.length + results.incomplete.length,
    passes: results.passes.length,
    violations: results.violations.length,
    incomplete: results.incomplete.length,
    counts,
    failures,
    vacuous,
  };
}
