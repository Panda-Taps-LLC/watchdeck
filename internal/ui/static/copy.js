// watchdeck dashboard copy: every sentence, label, title, aria-label and
// placeholder a person reads lives here, grouped by page. Pages import COPY
// and the label helpers; no page writes an on-screen string of its own.
//
// The copy lint (internal/copylint, TestCopyLint) scans the string literals
// of every static/*.js file, this one included, for internal vocabulary
// that never goes on screen. The wire values the server sends include some
// of those words (the authority "classifier", the enforcement "hook-gate").
// So this file names wire values only as unquoted object keys, which the
// lint does not read, derives AUTHORITY_ALL from the keys, and folds "-" to
// "_" before a lookup ("hook-gate" is looked up as hook_gate).
//
// This module imports nothing, so app.js can import it statically without
// a cycle.

const yesNo = (on) => (on ? "yes" : "no");
const plural = (n, one, many) => `${n} ${n === 1 ? one : many || one + "s"}`;

export const COPY = {
  nav: {
    brand: "watchdeck",
    brandLabel: "watchdeck home",
    sections: "Sections",
    skip: "Skip to content",
    home: "Home",
    sessions: "Sessions",
    rules: "Rules",
    settings: "Settings",
  },
  // Shadow mode (mode: shadow in the user overrides.yaml): watchdeck's own
  // rules are recorded with what they would have done, never enforced. One
  // block for Home, the header pill and the Rules banner; the command is
  // the only way back (the dashboard does not write the mode).
  shadow: {
    word: "Observing only",
    command: "watchdeck rules shadow off",
    how: "Turn enforcement on with: ",
    pill: "Observing only: rules are recorded, not enforced. Turn enforcement on with: watchdeck rules shadow off",
    rulesTitle: "Observing only",
    rulesBody: "The rules in the watchdeck checks group are recorded with what they would have done, but none of them blocks or asks. Claude Code's own rules and the sandbox are unaffected. ",
  },
  pill: {
    checking: "Checking…",
    live: (n) => ` · ${n} live`,
    commands: (on) => `Checks commands before they run: ${yesNo(on)}`,
    skills: (on) => `Checks skills: ${yesNo(on)}`,
    denials: (on) => `Records denials: ${yesNo(on)}`,
    lifecycle: (on) => `Tracks session start and end: ${yesNo(on)}`,
    exclusion: (on) => `Sandbox exclusion: ${on ? "set" : "missing"}`,
    settings: (path, missing) => `Settings: ${path || "?"}${missing ? " (missing)" : ""}`,
    unreadable: (err) => `Your Claude Code settings could not be read: ${err}`,
    lastSeen: (time, ago) => `Last check logged: ${time} (${ago})`,
    elsewhere: "Not in your settings: watchdeck ran from the plugin or another settings file.",
    noBackend: (platform) => `No sandbox backend was found on this ${platform} machine.`,
    unknown: "Protection status unknown",
  },
  home: {
    title: "Home",
    heading: "Home",
    // The one sentence at the top, from the protection word (protectionWord),
    // the live session count and the open Needs you count.
    sentence: ({ protection, live, needs }) => {
      const l = live === 0 ? "no live session" : plural(live, "live session");
      const n = needs === 0 ? "Nothing needs you." : needs === 1 ? "1 thing needs you." : `${needs} things need you.`;
      if (protection === "off") return "watchdeck is not installed in Claude Code yet.";
      if (protection === "partial") return "watchdeck is watching but not enforcing: finish setup.";
      if (protection === "observing") return `watchdeck is observing only, ${l}: its rules are recorded, not enforced. ${n}`;
      return `watchdeck is watching ${l}. ${n}`;
    },
    // The tag on a Recent row shadow mode observed: what the rule would have done.
    observed: (would) => `observed: would ${would}`,
    checking: "Checking what watchdeck sees…",
    turnOn: "Turn it on",
    seeSettings: "See what is missing in Settings",
    installed: "watchdeck is on in your user settings.",
    // Needs you: inbox items from the activity log.
    needsHeading: "Needs you",
    needsCount: (n) => `${n} open`,
    needsNone: "Nothing needs you.",
    needsOff: "The activity log is off (WATCHDECK_ACTIVITY=off), so nothing can show here.",
    // With the activity log off, leak watch still lists secrets seen in transcripts (Plan 08 D4).
    needsOffLeaks: "The activity log is off (WATCHDECK_ACTIVITY=off), so only secrets seen in transcripts show here.",
    leakOff: "Leak watch is off because transcripts are off.",
    needsFailed: (msg) => `What needs you could not be loaded: ${msg}`,
    // A Needs you row (2026-10-28, the A3 board): one sentence, one muted
    // line and one filled button that opens the decision sheet. The
    // sentence is parts: strings, and the tokens WHAT, RULE and SKILL that
    // home.js renders in mono from the item. proj is the project's name
    // ("api"), "" when the item has none.
    need: {
      WHAT: "{what}",
      RULE: "{rule}",
      SKILL: "{skill}",
      sentence: (it, proj) => {
        const W = "{what}";
        const where = proj ? ` in ${proj}.` : ".";
        const whereComma = proj ? `, in ${proj}.` : ".";
        switch (it.kind) {
          case "denial":
            return ["Claude Code's auto check stopped ", W, where];
          case "ask":
            return (it.rule_ids || []).some((id) => id.startsWith("claude-settings/")) ? ["Your Claude Code rule ", "{rule}", " stopped ", W, where] : ["A watchdeck rule caught ", W, where];
          case "sandbox_refusal":
            return ["The sandbox refused ", W, where];
          case "skill_request":
            return ["The skill ", "{skill}", " asked for more than it has", whereComma];
          case "rejection":
            return ["You said no to ", W, where];
          case "leak":
            return it.what && it.what !== "Reply" ? [it.why || "A secret was seen", " of ", W, whereComma] : [it.why || "A secret was seen", whereComma];
          default:
            return [W, " needs a decision", whereComma];
        }
      },
      // The muted line under the sentence: who decided and when (the A3
      // board's "Stopped by watchdeck, 2 minutes ago"); the reason waits in
      // the sheet.
      meta: (label, ago) => `${label}, ${ago}`,
      // The row's one button: the sheet's default choice, with an ellipsis
      // because a sheet follows. Its label for assistive tech names the item.
      decide: (verb) => `${verb}…`,
      decideLabel: (what, verb) => `Decide on ${what}: ${verb}`,
      // The sheet.
      lead: (proj, ago, question) => `${proj ? `In ${proj}, ` : ""}${ago}. ${question}`,
      question: ({ fix, allow, leak }) => {
        if (fix === "deny" && leak) return "Stop Claude reading that file, or leave it?";
        if (fix === "deny" && allow) return "Keep stopping it, or let it through?";
        if (fix === "deny") return "Keep stopping it?";
        if (fix === "ask" && allow) return "Ask next time, or let it through?";
        if (fix === "ask") return "Ask next time?";
        if (allow) return "Let it through for a while, or leave it?";
        return "Nothing to add as a rule: acknowledge it, or hide it for good.";
      },
      openSkill: "Open the skill to grant what it asked for",
      openTimeline: "Open it in the timeline",
      // The popups.
      forLabel: "For:",
      forAlways: "Always",
      forSession: "This session",
      forHour: "An hour",
      ruleLabel: "Rule:",
      ruleEverywhere: (sentence) => `${sentence}, by every route`,
      whereLabel: "Where:",
      whereEverywhere: "Everywhere",
      whereOnly: (proj) => `Only in ${proj}`,
      filesLabel: "Files: ",
      backupIfAny: (file) => `If the file exists, a copy is saved as ${String(file || "").split("/").pop()}.bak-<time> first.`,
      backupAny: "If a file exists, a copy is saved as <name>.bak-<time> first.",
      // The one filled button, by the choice made.
      keepStopping: "Keep stopping it",
      blockReading: "Block reading it",
      askNext: "Ask me next time",
      letThrough: "Let it through",
      acknowledge: "Acknowledge",
      // The lesser, text actions.
      justAck: "Just acknowledge",
      neverAgain: "Don't show this again",
      neverAgainTitle: "Hide it, and the same thing next time",
      // A leak is hidden by kind of secret, tool, target and place; a reply
      // has no target, so one dismiss hides that kind of secret in every reply.
      neverAgainLeakTitle: (reply) =>
        reply ? "Hide it, and this kind of secret in every later reply, in any session" : "Hide it, and this kind of secret from the same tool and target, in any session",
    },
    // Allow for a while (Plan 08 D9), the sheet's lines when For is a while:
    // watchdeck's own rules paused, or a skill's grant widened.
    allowRules: (ids, forWord) => {
      const one = ids.length === 1;
      const when = forWord === "session" ? "for the rest of this session (8 hours at most)" : "for the next hour";
      return `${one ? "The rule" : "The rules"} ${ids.join(", ")} ${one ? "is" : "are"} paused ${when}: ${one ? "it" : "they"} will not ask or block until then.`;
    },
    allowSkill: (skill, grants) => `Skill ${skill} also gets ${grants.join(", ")} for the next hour. It still asks before each run.`,
    grantWord: (field, value) =>
      field === "network" ? `network ${value}` : field === "write" ? `writing to ${value}` : field === "read" ? `reading ${value}` : field === "env" ? `the variable ${value}` : "its cache folders",
    allowStill: "Claude Code's own rules still apply: nothing they stop is let through.",
    allowed: (forWord) => (forWord === "session" ? "Allowed for this session." : "Allowed for an hour."),
    added: "Rule added.",
    acknowledged: "Acknowledged.",
    dismissed: "Dismissed. The same thing will not show again.",
    dismissedLeak: (reply) =>
      reply ? "Dismissed. This kind of secret in a reply will not show again." : "Dismissed. This kind of secret from the same tool and target will not show again.",
    undo: "Undo",
    undoLabel: (what) => `Undo for ${what}`,
    undone: "Undone.",
    undoFailed: (msg) => (msg ? `Could not undo: ${msg}` : "Could not undo."),
    showRecommended: "Show recommended rules",
    showRecommendedTitle: "Recommended rules that are not in your settings yet",
    // Live now: one card per live session (the Sessions page's card).
    liveHeading: "Live now",
    noLive: "No session is live.",
    lastCall: (ago) => `last call ${ago}`,
    lastDenial: (label, ago) => `last denial: ${label}, ${ago}`,
    // Recent decisions: the newest calls someone decided on.
    recentHeading: "Recent decisions",
    recentEmpty: "No decision yet. When Claude Code calls a tool, who decided it shows here.",
    recentFailed: (msg) => `Recent decisions could not be loaded: ${msg}`,
    // observed: COPY.home.observed(would) on a row shadow mode observed, else "".
    recentLabel: (tool, what, label, ago, observed) => `Open in the timeline: ${tool}${what ? " " + what : ""}, ${label}${observed ? ", " + observed : ""}, ${ago}`,
    recentCaption: "Newest first; a row opens the call in its session's timeline",
    sep: " · ",
    loading: "Loading…",
  },
  sessions: {
    title: "Sessions",
    heading: "Sessions",
    lead: "Every Claude Code session on this machine. Open one to see its map.",
    liveHeading: "Live now",
    allHeading: "All sessions",
    stream: {
      on: "Live updates",
      off: "Polling every 15 s",
      onTitle: "Connected to the dashboard's event stream: sessions starting, ending and new activity show up within a second or two.",
      offTitle: "The event stream is not connected (it reconnects on its own); the page refreshes every 15 seconds meanwhile.",
    },
    // The State filter's options, by the catalog's state word ("" is any).
    states: { any: "Any state", live: "Live", idle: "Idle", ended: "Ended", unknown: "Unknown (no lifecycle record)" },
    stateWord: { live: "live", idle: "idle", ended: "ended", unknown: "—" },
    // A denial count: "3 denied", the last denial in the tooltip and for screen readers.
    deny: {
      word: (n) => `${n} denied`,
      last: (label, skill, ago) => `last: ${label}${skill ? ` (${skill})` : ""}, ${ago}`,
      title: (n, why, time) => (why ? `${n} denied; ${why} · ${time}` : `${n} denied`),
      srShort: (why) => (why ? ` denied; ${why}` : " denied"),
      srLong: (why) => `; ${why}`,
    },
    // The Live now cards (liveCard, which the Home page reuses).
    card: {
      label: (name, state) => `${name}, ${state}`,
      session: "session",
      live: "live",
      idle: (ago) => `idle · ${ago}`,
      untitled: "Untitled session",
      branch: (b) => `branch ${b}`,
      model: (m) => `model ${m}`,
      running: "running ",
      runningTitle: "a skill script is running under watchdeck run",
      open: "Open map",
      openLabel: (name) => `Open the map of ${name || "this session"}`,
    },
    // Rich text: strings and {code} parts.
    noneHelp: ["Sessions appear here within seconds of starting once watchdeck tracks session start and end (", { code: "watchdeck setup" }, ")."],
    // The live lane map (livemap.js): one dark lane per live session.
    lanes: {
      label: "Live sessions, the last 10 minutes",
      head: (name, agents, ago) => `${name} · ${plural(agents, "agent")} · last call ${ago}`,
      headIdle: (name, agents) => `${name} · ${plural(agents, "agent")} · no calls yet`,
      laneLabel: (name, agents, calls) => `Open the map of ${name}: ${plural(agents, "agent")}, ${plural(calls, "recent call")}, newest at the right`,
      tick: (tool, label) => `${tool} · ${label}`,
      now: "now",
      edge: "10 min ago",
      more: (n) => `${n} more`,
      moreLabel: (n) => `Show ${plural(n, "more live session")}`,
      fewer: "Show fewer",
    },
    noLive: (ago) => `No session is live; the last ended ${ago}.`,
    noLiveEver: "No session is live.",
    allProjects: "All projects",
    projectOption: (name, sessions, live, project) => `${name} (${sessions})${live ? ` · ${live} live` : ""} — ${project}`,
    listFailed: (msg) => `Sessions could not be listed: ${msg}`,
    requestFailed: "request failed",
    searchOff: "Search is off.",
    searchOffText: "This dashboard runs with --no-transcripts, so no session text is indexed. Restart it without that flag to search.",
    noMatchQuery: (q) => `Nothing matches “${q}” with these filters.`,
    noMatch: "No session matches these filters.",
    clearFilters: "Clear filters",
    noSessions: "No sessions yet.",
    // Rich text steps: strings and {code} parts.
    firstSteps: [
      ["Turn watchdeck on: ", { code: "watchdeck setup" }, "."],
      ["See a denial in under a minute: ", { code: "watchdeck demo" }, "."],
      ["Start Claude Code anywhere. Every session, in every project, appears here."],
    ],
    noTranscripts: "Transcripts are off (--no-transcripts): only sessions that watchdeck's records or the activity log name are listed, without titles.",
    columns: { state: "State", session: "Session", title: "Title", titleMatch: "Title and match", last: "Last active", tools: "Tools", denials: "Denials" },
    byHand: "watchdeck run typed by hand",
    rowLabel: (name, title) => `Open the map of ${name}${title ? `: ${title}` : ""}`,
    dash: "—",
    zero: "0",
    searching: "Searching…",
    loading: "Loading…",
    count: (n) => plural(n, "session"),
    countOf: (shown, total) => `${shown} of ${total} sessions`,
    indexing: "Indexing sessions… the first visit reads every transcript once.",
    caption: "Sessions, newest first; a row opens its map",
    loadMore: "Load more",
    dates: "Dates",
    dateRange: (since, until) => `${since || "…"} – ${until || "…"}`,
    datesTitle: "Filter by date of last activity",
    dateGroup: "Date range",
    from: "From",
    to: "To",
    searchPlaceholder: "Search every session  ( / )",
    searchLabel: "Search the full text of every session",
    filtersLabel: "Filter sessions",
    project: "Project",
    state: "State",
    hasDenials: "Has denials",
  },
  map: {
    title: "Session map",
    heading: "Session map",
    headingFor: (project) => `Session map · ${project}`,
    back: "← All sessions",
    allSessions: "All sessions",
    viewGroup: "View",
    views: { topology: "Topology", timeline: "Timeline" },
    lead: {
      topology: "who called what, and who decided each call",
      timeline: "time runs down; each lane is an agent, the skill scripts it ran, and the sandbox they ran in",
    },
    totalsLabel: "Totals",
    decidedName: (name, label) => `${name}, decided by ${label}`,
    noEvents: "No events to show.",
    lanes: { skills: "Skill scripts", sandbox: "Sandbox" },
    // The who-decided chips: one per label, in this order (the labels come from authorityLabel).
    chipsLabel: "Show calls decided by",
    chipsTitle: "Decided by",
    chipOrder: ["Auto check", "Deny rule", "Allow rule", "You", "watchdeck", "Sandbox", "Blocked", "No check"],
    chipsAll: "Show all",
    chipHide: (label) => `Hide calls decided by: ${label}`,
    chipShow: (label) => `Show calls decided by: ${label}`,
    chipLast: "At least one kind stays shown",
    authCount: (label, n) => `${label} ${n}`,
    showing: (n) => `showing ${plural(n, "call")}`,
    outcome: { allow: "allow", ask: "ask", denied: "denied", unchecked: "not checked" },
    outcomeCount: (word, n) => `${word} ${n}`,
    count: {
      agents: (n) => plural(n, "agent"),
      models: (n) => plural(n, "model"),
      tools: (n) => plural(n, "tool"),
      mcp: (n) => plural(n, "MCP server"),
      skills: (n) => plural(n, "skill"),
      denials: (n) => plural(n, "denial"),
      calls: (n) => plural(n, "call"),
      runs: (n) => plural(n, "run"),
      skillRuns: (n) => plural(n, "skill run"),
    },
    loadFailed: (msg) => `The map could not be loaded: ${msg}`,
    gone: "This session is not known to watchdeck (it may have been removed, or the link is from another machine).",
    goneHint: "Find it on the Sessions page.",
    banner: {
      noTranscripts: "Transcripts off: showing watchdeck's own events only. Denials a script reports only on its own output are not visible here.",
      missing: (path) => `Transcript not found${path ? " at " + path : ""}: showing watchdeck's own events only.`,
      truncated: "Large transcript: showing the last 32 MB; earlier spawns and prompts may be missing.",
    },
    canvas: {
      label: {
        topology:
          "Session map canvas. Tab walks the nodes; arrow keys move the focused node (Shift moves further). Plus and minus zoom, 0 fits. Drag a node to move it, drag the background to pan.",
        timeline: "Session map timeline. Plus and minus zoom, 0 fits, arrows move between events.",
      },
      controls: "Canvas controls",
      zoomIn: "Zoom in",
      zoomInTitle: "Zoom in (+)",
      zoomInText: "+",
      zoomOut: "Zoom out",
      zoomOutTitle: "Zoom out (-)",
      zoomOutText: "−",
      fit: "Fit to view",
      fitTitle: "Fit (0)",
      fitText: "fit",
      reset: "Reset layout",
      resetTitle: "Reset layout: put dragged nodes back",
      resetText: "↺",
      minimap: "Minimap",
      minimapTitle: "Minimap (Escape closes)",
      minimapText: "map",
      minimapPanel: "Minimap: press or drag to move the view",
    },
    legend: {
      label: "Legend",
      you: "you",
      agent: "agent",
      model: "model",
      tool: "tool",
      mcp: "MCP",
      skill: "skill · dashed asked, solid granted",
      sandbox: "sandbox",
      cut: "cut by policy",
      width: "width = calls",
      decided: "decided by:",
    },
    ticks: {
      label: "Tool calls in order",
      now: "now",
      title: (tool, time, who) => `${tool} · ${time}${who ? " · " + who : ""}`,
      aria: (tool, time, spawn, outcome, who, hidden) =>
        `${tool} at ${time}${spawn ? ", spawned a subagent" : outcome ? ", " + outcome : ""}${who ? ", decided by " + who : ""}${hidden ? ", not shown" : ""}`,
      spawnToast: "Agent calls are drawn as spawn edges from the agent that made them.",
      noNode: (tool, filtered) => `${tool || "That call"} has no node in this view${filtered ? " (the decided-by filter hides it)" : ""}.`,
    },
    replay: {
      button: "replay",
      label: "Replay",
      play: "Play",
      step: "Step",
      stepLabel: "Step forward one call",
      position: "Replay position",
    },
    edge: { prompt: "prompts", runs_on: "runs on", spawn: "spawned", call: "calls", skill_run: "skill run", invoke: "Skill tool", sandbox: "sandbox run", return: "returned", fallback: "edge" },
    edgeName: (from, to) => `${from} → ${to}`,
    edgeMeta: (word, count) => ` · ${word}${count ? " ×" + count : ""}`,
    evidence: {
      hint: "the sandbox's stderr, heuristic",
      stdout: "the script's stdout, heuristic",
      result_text: "the script's own output reported the denial",
      denied: "Claude Code's auto-mode denial",
      denied_record: "Claude Code's auto-mode denial",
      hook_attachment: "watchdeck's decision recorded in the transcript",
      run: "the run's exit status",
    },
    verdict: {
      as_declared: ["ok", "as declared"],
      undeclared: ["ask", "undeclared"],
      clean: ["ok", "clean"],
      unknown: ["none", "unknown"],
    },
    floor: "A floor, not a ceiling: the sandbox reports what it refused, not everything the script did.",
    card: {
      label: "Selected node",
      aside: "Details",
      selection: "Selection",
      hint: {
        topology: "Select a node or an edge, or a tick in the strip, to see what it did and who decided it. Drag nodes to rearrange; Tab walks the nodes; Escape clears.",
        timeline: "Select a node, or a tick in the strip, to see what it did and who decided it. Tab walks the nodes column by column; Escape clears.",
      },
      clear: "Clear selection",
      clearTitle: "Clear selection (Escape)",
      connections: "Connections",
      callsBehind: (shown, total) => (total > shown ? `Calls behind it · last ${shown} of ${total}` : "Calls behind it"),
      runsOn: (model, agent) => `${model} runs on ${agent}.`,
      prompts: (n) => `${plural(n, "prompt")} from you to the main agent.`,
      noCalls: "No calls recorded for this edge.",
      subagent: "subagent",
      event: (kind) => `${kind} event`,
      node: "node",
      requested: "requested",
      granted: "granted",
      ranUnder: "ran under",
      noManifest: "no manifest",
      defaultGrant: "default",
      notRun: "not run",
      decidedBy: "who decided",
      calledBy: "called by",
      skill: "skill",
      decision: "decision",
      outcome: "outcome",
      evidence: "evidence",
      exit: (code) => `exit ${code}`,
      declaredVsDid: "declared vs did",
      declaredDid: (declared, did) => `declared ${declared || "nothing"}; did ${did || "nothing recorded"}`,
      why: "The policy caused this, not a bug in the script. Grant it for this skill, or keep it denied and let the agent report it.",
      equivalent: "Equivalent command",
      showIn: { timeline: "Show in timeline", topology: "Show in topology" },
      model: "model",
      calls: "calls",
      tools: "tools",
      spawned: "spawned",
      skillRuns: "skill runs",
      policy: "policy",
      ruleHits: "rule hits",
      none: "none",
      ownTool: "watchdeck's sandbox covers skill scripts run through Bash; this tool is the agent's own, so Claude Code's settings decided these calls (see who decided).",
    },
    grant: {
      network: (v) => `network: ${v}`,
      write: (paths) => `write: ${paths}`,
      caches: "interpreter caches",
      noCaches: "no caches",
      env: (names) => `env: ${names}`,
      other: (k, v) => `${k}: ${v}`,
      fallback: "grant",
      button: (what) => `Grant ${what}`,
      keep: "Keep denied",
      title: (what, skill) => `Grant ${what} to ${skill}?`,
      body: (skill, what, hasFix) => `Every later run of ${skill}'s scripts gets ${what}. This writes your user overrides file${hasFix ? ", the same as running:" : "."}`,
      confirm: "Grant",
      toast: (what) => `Granted ${what}`,
      toastSame: (skill, what) => `No change: ${skill} already has ${what}`,
      failed: "Request failed",
      unchanged: (what, skill) => `No change: the overrides file already grants ${what} to ${skill}.`,
      saved: (what, skill) => `Saved ${what} for ${skill}. Refreshing the map from the server…`,
      file: "Overrides file: ",
    },
    extra: {
      agents: "Agents in this session",
      spawned: (names) => `spawned ${names}`,
      noSkill: "touched no skill",
      dvd: "Declared vs did · this session",
      declared: "declared",
      did: "did",
      scripts: "Skill scripts",
      noScripts: "No skill script ran in this session.",
      whereTitle: "Where the sandbox applied",
      where:
        "Only Bash calls that run a skill's script pass through the sandbox. Read, Edit, WebFetch and MCP calls are the agent's own tools; Claude Code's settings decide them, and each card says who decided.",
      privacy: "Built from watchdeck's own event log joined with this machine's Claude Code transcripts, read-only. Nothing is stored or sent. ",
      privacyCmd: "watchdeck ui --no-transcripts",
      privacyEnd: " shows only watchdeck's own events.",
    },
  },
  // Grant changes for a skill's sandbox and activity lines (shared.js; the
  // Rules page's skill drill-in and Home use them).
  grant: {
    who: (name) => (name === "*" ? "every skill (the defaults for all skills)" : name),
    title: (name) => (name === "*" ? "Change the grant for every skill?" : `Change the grant for ${name}?`),
    skillLabel: "Skill: ",
    sameAs: "This writes your user overrides file, the same as running:",
    noCli: (path) => `No CLI equivalent; this edits ${path} directly:`,
    apply: "Apply",
    view: {
      net: (v) => `net ${v}`,
      write: (list) => `write ${list}`,
      envDefault: "env default",
      envExtra: (n) => `env +${n}`,
      exec: (n) => `exec ${n} paths`,
      autoAllow: "auto-allow",
      read: (n) => `read ${n} paths`,
    },
    record: {
      decision: (d, low) => `decision: ${d}${low ? " (low confidence)" : ""}`,
      run: (outcome, exit, refused) => `run: ${outcome}${exit === null ? "" : ` · exit ${exit}`}${refused ? ` · ${refused} refused` : ""}`,
      denied: (reason) => `denied in auto mode${reason ? `: ${reason}` : ""}`,
      invoked: "Skill tool invoked",
    },
  },
  rules: {
    title: "Rules",
    lead: "Everything that limits what an agent can do on this machine, in one list.",
    addRule: "Add rule",
    loading: "Loading rules…",
    loadFailed: (msg) => `Could not read the rules: ${msg}`,
    emptyGroup: "Nothing here yet.",
    // Recommended block
    recTitle: "Recommended",
    recLead: "Rules most people want. Each one goes into your Claude Code settings, and you can remove it later.",
    add: "Add",
    addAll: "Add all",
    decline: "Decline",
    undecline: "Bring back",
    declinedToggle: (n, open) => `${n} declined · ${open ? "hide" : "show"}`,
    installTitle: "Add this rule?",
    installAllTitle: (n) => `Add ${n} recommended rule${n === 1 ? "" : "s"}?`,
    installAllBody: "watchdeck adds every recommended rule you have not declined to this file.",
    declineTitle: "Decline this rule?",
    declineBody: "It moves to the declined list, and Add all skips it. Bring it back at any time.",
    undeclineTitle: "Bring this rule back?",
    undeclineBody: "It goes back into the recommended list. Nothing is written to your Claude Code settings.",
    added: (n) => (n === 1 ? "Rule added." : `${n} rules added.`),
    nothingAdded: "Nothing to add: those rules are already in your settings.",
    recommendedWarning: (text) => `Could not first check for recommended rules you removed by hand: ${text}`,
    declined: "Rule declined.",
    undeclined: "Rule is back in Recommended.",
    // One row
    state: { on: "on", off: "off", removed: "removed by hand" },
    stateLabel: "State: ",
    whereLabel: "Applies: ",
    byLabel: "Added by ",
    enforcedLabel: "Enforced by ",
    fileLabel: "In ",
    details: "Details",
    editByHandNote: (file) => `Not changed here: edit ${file} by hand.`,
    builtinList: "Claude Code's built-in list; see /permissions in Claude Code",
    remove: "Remove",
    removeLabel: (sentence) => `Remove: ${sentence}`,
    removeTitle: "Remove this rule?",
    removeBody: (sentence) => `"${sentence}" goes. watchdeck removes exactly this entry and nothing else.`,
    removeAllTitle: (kind, name) => `Remove every rule for the ${kind} ${name}?`,
    removeAllBody: (kind, name) => `Every entry for the ${kind} ${name} goes, not only the one on this row.`,
    removed: "Rule removed.",
    removedMany: (n) => `${n} rules removed.`,
    // kinds of thing a policy file names, by the server's word
    kinds: { skill: "skill", command: "command", mcp: "MCP server", tool: "tool", agent: "agent" },
    switchLabel: (sentence) => `On or off: ${sentence}`,
    switchOnTitle: "Turn this rule on?",
    switchOffTitle: "Turn this rule off?",
    switchBody: "watchdeck saves the change in its overrides file.",
    switchedOn: "Rule turned on.",
    switchedOff: "Rule turned off.",
    // Rows the page adds from the skills audit and the MCP list
    skillSandbox: (name, view) => {
      const v = view || {};
      const net = { none: "no network", localhost: "this machine only", all: "any network" }[v.network] || "no network";
      const where = (v.write || []).map((p) => (p === "${CWD}" ? "the working folder" : p === "${TMP}" ? "temp" : String(p).replace(/^\$\{HOME\}/, "~")));
      return `${name} scripts: ${net}, writes ${where.length ? where.join(", ") : "nowhere"}`;
    },
    mcpSandbox: (name) => `MCP server ${name} runs in a sandbox`,
    unknown: (name) => `Nothing named ${name} here.`,
    back: "← All rules",
    warningsTitle: "Some settings need a look",
    driftTitle: "Changed since watchdeck added them",
    driftLine: (value, file) => `${value} in ${file}`,
    fileError: (path, err) => `${path} could not be read: ${err}`,
    // How often each rule fired (GET /api/rules/stats, Plan 08): a caption
    // under the page head and a chip on built-in, own and Claude Code Bash
    // block or ask rows.
    stats: {
      window: (ago, n) => `Counts since ${ago}, ${n} record${n === 1 ? "" : "s"}.`,
      empty: "No activity recorded yet, so every rule shows never fired.",
      rotated: "Older records were rotated out of the log.",
      off: "Activity log is off, so rule counts are not kept.",
      nativeNote: "A Claude Code Bash rule counts only the calls watchdeck checked before sandboxing a skill script.",
      fired: (n, ago) => `fired ${n} · last ${ago}`,
      // The newest hit only noted the call (a paused rule, or a rule that notes): it changed nothing.
      matched: (n, ago) => `matched ${n} · last ${ago}, noted only`,
      observed: (n) => `${n} observed only`,
      never: "never fired",
      chipTitle: (text) => `In the activity log: ${text}`,
    },
    // Try a call (POST /api/rules/try, Plan 08): what the saved rules answer
    // for one call the person types.
    try: {
      title: "Try a call",
      lead: "Tries the rules you have saved. A rule you are still drafting in Add rule is not included.",
      whatLabel: "Kind of call",
      valueLabel: "The call to try",
      whats: { command: "Command", read: "Read a file", edit: "Edit a file", write: "Write a file", url: "Fetch a URL", mcp: "MCP tool", skill: "Skill" },
      placeholders: { command: "curl example.com", read: "/path/to/.env", edit: "/path/to/file", write: "/path/to/file", url: "example.com/page", mcp: "mcp__server__tool", skill: "skill-name" },
      button: "Try",
      trying: "Trying…",
      failed: (msg) => (msg ? `Could not try the call: ${msg}` : "Could not try the call."),
      resultLabel: "Result of the try",
      verdict: { allow: "allowed", ask: "asks first", deny: "blocked" },
      none: "no watchdeck rule applies; Claude Code decides as usual",
      matched: "Matched:",
      ruleLink: (label) => `Show the rule: ${label}`,
      notListed: (id) => `${id} (not on this page)`,
      native: (value, where, kind) => `Claude Code's own rule ${value} in ${where} matches this call, so Claude Code ${kind === "ask" ? "asks first" : "blocks it"}. watchdeck did not check it.`,
      nativeWhere: { managed: "managed settings", user: "your settings", project: "this project's settings", local: "this project's local settings" },
      rewrite: "watchdeck runs it in its sandbox as:",
      would: { allow: "allowed it", ask: "asked first", deny: "blocked it" },
      shadow: (would, why) => `Observing only: watchdeck would have ${would}${why ? `: ${why}` : ""}.`,
      sessionPauses: "Session-bound pauses are not applied here.",
      inProject: (dir) => `The rules of ${dir} count too.`,
      enforced: (word) => `Enforced by ${word}`,
    },
    // Rules added together to cover every route (Plan 08 intents).
    intent: {
      chip: (sentence, n) => `part of: ${sentence} · ${n} rule${n === 1 ? "" : "s"}`,
      chipTitle: (sentence) => `Added together to cover every route: ${sentence}`,
      removeTitle: (n) => `Remove all ${n} rules added together?`,
      lead: (sentence) => `This rule was added with others to cover every route: ${sentence}. Its rules:`,
      onlyNote: "Only this rule keeps the others; the route this one covers is open again.",
      removeAll: (n) => `Remove all ${n}`,
      onlyThis: "Only this rule",
      filesLine: (files) => `Files: ${files.join(", ")}`,
      backups: "A copy of each file is saved as <name>.bak-<time> first.",
    },
    // Paused rules and timed grants in force (Plan 08 temporaries).
    temp: {
      title: "Temporary",
      lead: "Paused rules and timed grants. Each one ends by itself.",
      until: (time) => `ends at ${time}`,
      untilSession: (time) => `ends with its session, at ${time} at the latest`,
      onDay: (day, time) => `${day}, ${time}`,
      end: "End now",
      endLabel: (sentence) => `End now: ${sentence}`,
      endTitle: "End this now?",
      endBody: "It ends now instead of at its time: a paused rule asks or blocks again, and a skill loses its extra grant.",
      ended: "Ended.",
    },
    // The Add rule sheet (rules.js): the server builds the plan; the sheet
    // shows it before anything is written.
    sheet: {
      title: "Add a rule",
      lead: "Pick what the rule does and fill in the field. You see exactly what gets written before anything is.",
      kindLegend: "What the rule does",
      kinds: {
        block: "Block a command",
        ask: "Ask before a command",
        path: "Keep a path private",
        domain: "Block a domain",
        mcp: "Block an MCP tool",
        pack: "Raise a watchdeck rule to deny",
      },
      labels: { command: "Command", text: "Text", path: "Path", domain: "Domain", mcp: "MCP tool", pack: "watchdeck rule" },
      placeholders: { command: "rm -rf /", text: "rm -rf /", path: "~/secrets/**", domain: "example.com", mcp: "mcp__server__tool" },
      hints: {
        command: "Matches every command that starts with this.",
        text: "Matches this exact text anywhere in a command.",
        path: "A file, a folder, or a pattern such as ~/secrets/**.",
        domain: "A bare host such as example.com: no http prefix and no path.",
        mcp: "mcp__<server>__<tool>, or mcp__<server> for every tool of that server.",
        pack: "The rule's action becomes deny.",
      },
      fullText: "Match the full text, not only the start",
      toolLegend: "Keep it from",
      tools: { Read: "Reading", Edit: "Editing", Both: "Reading and editing" },
      scopeLegend: "Applies",
      scopeEverywhere: "Applies everywhere.",
      scopeUserOnly: "Applies everywhere: this kind of rule lives in watchdeck's own file.",
      twin: "Also add the watchdeck twin: it matches the exact text, even when the command is wrapped in another one",
      everywhere: "Cover every route",
      everywhereNote: {
        path: "Also stops Grep and Glob searches of it and shell commands that name it.",
        domain: "Also adds it to Claude Code's sandbox block list and stops WebFetch and shell commands such as curl that name it.",
      },
      everywhereGap: "Skill scripts that watchdeck runs in its sandbox are not covered: that sandbox has no per-path or per-host block you can add.",
      pathEverywhere: (project) => `With every route covered, use ~/… or a full path${project ? "; a relative path needs this project's scope" : ""}.`,
      filesLine: (files) => `Files: ${files.join(", ")}`,
      noPacks: "No watchdeck rules are listed to raise.",
      packOff: (sentence) => `${sentence} (off)`,
      staysOff: "This rule is switched off. It stays off until you switch it on in the list.",
      previewTitle: "What gets written",
      previewEmpty: "Fill in the field to see the rule.",
      previewWaiting: "Checking…",
      previewFailed: (msg) => `Could not check the rule: ${msg}`,
      noAnswer: "no answer from the dashboard",
      mechanism: (step) => `Written to ${tildify(step.file)} as ${step.key}: ${step.value}`,
      strength: (word) => `Enforced by ${word}`,
      confirm: "Add rule",
      cancel: "Cancel",
      confirmTitle: "Add this rule?",
      added: (n, sentence) => (n > 1 ? `${n} rules added: ${sentence}` : `Rule added: ${sentence}`),
      already: "That rule is already there.",
    },
    // The skill drill-in (skill-detail.js)
    detail: {
      loading: "Loading…",
      noSkill: (name) => `No skill named ${name}.`,
      light: {
        off: "Prose only: nothing to sandbox",
        ask: "Asks more than granted",
        invalid: "Manifest invalid: run refuses it (exit 125)",
        needsNet: "Code needs network, nothing grants it",
        ok: "Fits its grant",
      },
      proseOnly: "Prose only: nothing to sandbox. Instructions are declared only.",
      flowTitle: "Request, grant, and what runs",
      request: "Request",
      grant: "Grant",
      runsUnder: "Runs under",
      invalidManifest: "invalid manifest",
      noManifest: "no manifest",
      asksTitle: "Asks more than granted",
      grantButton: "Grant",
      granted: (item) => `Granted ${item}`,
      noFlag: (path) => `no CLI flag: edit ${path}`,
      yourGrant: "Your grant",
      network: "Network",
      write: "Write",
      caches: "Caches",
      autoAllow: "Auto-allow",
      fromDefaults: "from the defaults for every skill",
      yourOverride: "your override",
      builtIn: "built-in default",
      removeWrite: (p) => `Remove write path ${p}`,
      writeRemoved: "Write path removed",
      addPath: "path",
      addPathLabel: "Write path to grant",
      addPathPlaceholder: "/path or ${CWD}/subdir",
      add: "Add",
      cancel: "Cancel",
      writeAdded: (p) => `Write path added: ${p}`,
      networkSet: (v) => `Network: ${v}`,
      cachesLabel: "Allow interpreter caches",
      cachesOnText: "interpreter cache dirs writable",
      offText: "off",
      cachesAllowed: "Caches allowed",
      cachesRevoked: "Caches revoked",
      autoLabel: "Run without asking",
      autoOnText: "runs without a prompt",
      autoOffText: "prompt once per run until on",
      autoOn: "Auto-allow on",
      autoOff: "Auto-allow off",
      showCommand: "Show command",
      showLine: (arg) => `watchdeck allow ${arg} --show`,
      commandTitle: "The equivalent CLI command",
      noCliEcho: (path) => `# no CLI equivalent for that change; it was written to ${path}`,
      saved: "Saved",
      noChange: "No change",
      requestFailed: "Request failed",
      refs: (n) => `Code references (${n})`,
      noRefs: "No capability references found in the scripts.",
      showFewer: "Show fewer",
      showAll: (n) => `Show all ${n}`,
      notesTitle: "Audit notes",
      manifestNote: (e) => `manifest: ${e}`,
      recentTitle: "Recent activity",
      seeSessions: "See it in Sessions",
      manifestButton: "PERMISSIONS.yaml",
      manifestInvalid: (path, err) => `# ${path || "PERMISSIONS.yaml"} is invalid\n# ${err || ""}`,
      manifestNone: "# no PERMISSIONS.yaml: the skill runs under the default sandbox",
      caps: {
        net: "network: opens sockets or fetches URLs",
        cred: "credentials: touches key or token files",
        exec: "exec: spawns other programs",
        env: "env: reads environment variables",
        enc: "encoding: base64 or similar obfuscation",
        fs: "filesystem: writes outside the usual places",
        instr: "instruction: SKILL.md tells the agent to relocate or exfiltrate",
      },
      defaultsTitle: "Every skill",
      defaultsLead: "The defaults every skill's scripts start from. A skill's own grant adds to them.",
      defaultsNone: "No defaults set: every skill starts from the built-in sandbox.",
      overridesBroken: (err) => `Your overrides file does not parse: ${err}`,
    },
    // The MCP drill-in (read-only)
    mcp: {
      title: (name) => `MCP server ${name}`,
      runsAs: "Runs as",
      stdio: "a local program (stdio)",
      remote: "a remote server",
      wrapped: "Sandboxed by watchdeck",
      yes: "yes",
      no: "no",
      config: "Config file",
      cliLead: "This page only shows the server. Change it from a terminal:",
      remoteNote: "This page only shows the server. A remote server runs elsewhere, so watchdeck cannot sandbox it.",
      wrap: (name) => `watchdeck advanced mcp wrap ${name}`,
      unwrap: (name) => `watchdeck advanced mcp unwrap ${name}`,
      loadFailed: (msg) => `Could not read the MCP servers: ${msg}`,
      configError: (text) => `The MCP config could not be read: ${text}`,
    },
  },
  settings: {
    title: "Settings",
    lead: "Your Claude Code settings and this dashboard. Every change is confirmed first.",
    claudeTitle: "Claude Code",
    claudeLead: "watchdeck's entries in your Claude Code settings files.",
    dashboardTitle: "Dashboard",
    loading: "Loading…",
    loadFailed: (msg) => `Could not read the Claude Code settings: ${msg}`,
    configFailed: (msg) => `Could not read the dashboard settings: ${msg}`,
    target: (scope) => (scope === "project" ? "This project's settings" : "Your user settings"),
    state: { installed: "Installed", partial: "Partly installed", none: "Not installed", unreadable: "Unreadable" },
    fileMissing: "File not created yet",
    fileMissingTitle: "Install creates the file.",
    // lines(status): the plain-word install state of one settings file, in
    // order, as {on, text, warn}. The first five read like the header pill's tooltip.
    lines: (st) => {
      const s = st || {};
      const lifecycle = s.startHook === true && s.endHook === true && s.promptHook === true;
      const sandbox = s.sandboxEnabled === true;
      const excluded = s.excluded === true;
      return [
        { on: s.hookInstalled === true, text: COPY.pill.commands(s.hookInstalled === true) },
        { on: s.skillHook === true, text: COPY.pill.skills(s.skillHook === true) },
        { on: s.deniedHook === true, text: COPY.pill.denials(s.deniedHook === true) },
        { on: lifecycle, text: COPY.pill.lifecycle(lifecycle) },
        { on: excluded, text: COPY.pill.exclusion(excluded), warn: sandbox && !excluded },
        { on: sandbox, text: `Claude Code sandbox: ${sandbox ? "on" : "off"}` },
      ];
    },
    present: "yes: ",
    absent: "no: ",
    warning: "warning: ",
    sandboxWarn: "Claude Code's sandbox is on and watchdeck's exclusion is missing, so skill scripts fail closed until you install.",
    projectNote: "If an admin requires Claude Code's sandbox, the sandbox exclusion in project settings is ignored.",
    noProject: "No project settings: the dashboard did not start inside a git repository.",
    unreadable: "This settings file could not be read.",
    unreadableFix: "Fix or remove this file, then reload.",
    install: "Install",
    uninstall: "Uninstall",
    installTitle: (scope) => (scope === "project" ? "Install into this project's settings?" : "Install into your user settings?"),
    uninstallTitle: (scope) => (scope === "project" ? "Uninstall from this project's settings?" : "Uninstall from your user settings?"),
    installBody: "watchdeck adds its checks (commands, skills, denials, session start and end) and the sandbox exclusion to this file. Existing entries are never changed.",
    uninstallBody: "watchdeck removes exactly the entries it added and nothing else.",
    newFile: "The file does not exist yet and will be created.",
    installed: "watchdeck's checks are installed.",
    removed: "watchdeck's checks were removed.",
    changed: (added, removed) => `${added} added, ${removed} removed.`,
    backupAt: "Backup: ",
    cli: (action, project) => `Same as: watchdeck enforce ${action}${project ? " --project" : ""}`,
    autostartLabel: "Start the dashboard with each Claude Code session",
    autostartHelp: "When a session starts and the dashboard is not running, watchdeck starts it in the background.",
    autostartUnset: "Not chosen yet, so it stays off.",
    autostartOnTitle: "Start the dashboard with each session?",
    autostartOffTitle: "Stop starting the dashboard with each session?",
    autostartOnBody: "Each new Claude Code session starts this dashboard in the background when it is not already running.",
    autostartOffBody: "New sessions no longer start the dashboard. A running dashboard keeps running.",
    autostartOn: "The dashboard now starts with each session.",
    autostartOff: "The dashboard no longer starts with each session.",
    turnOn: "Turn on",
    turnOff: "Turn off",
    savedIn: "Saved in ",
    setUpOn: (date) => `watchdeck was set up on ${date}.`,
    notSetUp: "watchdeck setup has not been completed on this account.",
    rememberTitle: "This browser",
    rememberLabel: "Remember me on this computer",
    rememberHelp:
      "Keeps the token in this browser's local storage for 127.0.0.1 on this port, so new tabs and restarts open without a launch link. Anyone who can use this browser profile can then use the dashboard. While the dashboard is not running, another local program could listen on this port and read a remembered token when this browser opens the page; the dashboard rotates the token whenever it finds its port taken, but the token was readable until then. Off, the token lives only in this tab. watchdeck ui --rotate-token ends every remembered token.",
    rememberBlocked: "This browser blocks local storage; the token stays in this tab only.",
    rememberOn: "This browser now remembers the dashboard token.",
    rememberOff: "The remembered token was removed from this browser.",
    themeTitle: "Theme",
    themeHelp: "Saved in this browser only. The button in the top bar changes it too.",
  },
  common: {
    building: "This page is being built.",
    other: "other",
    cancel: "Cancel",
    confirm: "Confirm",
    fileLabel: "File: ",
    backupLine: (file) => `A copy is saved as ${String(file || "").split("/").pop()}.bak-<time> first.`,
    expired: "That confirmation expired. Please try again.",
    pageTitle: (title) => `${title} · watchdeck`,
    pageFailed: (page, msg) => `The ${page} page failed to render: ${msg}`,
    pagesFailed: (msg) => `The dashboard pages failed to load: ${msg}`,
    ago: {
      now: "just now",
      seconds: (n) => `${n} s ago`,
      minutes: (n) => `${n} min ago`,
      hours: (n) => `${n} h ago`,
      days: (n) => `${n} d ago`,
    },
    summary: (network, write, env, exec) => `network=${network} write=${write} env=${env}${exec === undefined ? "" : ` exec=${exec}`}`,
    theme: {
      label: { auto: "Theme: auto (follows your system)", light: "Theme: light", dark: "Theme: dark" },
      word: { auto: "auto", light: "light", dark: "dark" },
      aria: (label, next) => `${label}. Switch to ${next}.`,
      title: (label, next) => `${label} · click for ${next}`,
    },
    // The token screen. Rich text is an array of strings and {code} parts;
    // app.js renders {code} as a <code> element.
    token: {
      missingTitle: "No session token",
      missingText: ["Open the link printed by ", { code: "watchdeck ui" }, ", or go back to the tab it opened."],
      where: "Where is the token kept?",
      whereText:
        "The dashboard is reachable only from this machine. The token lives in the URL fragment of the launch link and in this tab's session storage (or, if you chose \"Remember me\" in Settings, this browser's local storage); it is never sent in a URL.",
      rejectedTitle: "Session token rejected",
      rejectedText: (wasRemembered) => [
        "Run ",
        { code: "watchdeck ui" },
        " in a terminal: it opens this dashboard with a fresh link. ",
        wasRemembered
          ? "The token this browser remembered was cleared; the token was probably rotated (watchdeck ui --rotate-token)."
          : "The token was probably rotated, or this tab belongs to another dashboard.",
      ],
    },
  },
};

// AUTHORITY names who decided a call, by the server's authority word, as
// {label, glyph}. Glyphs (icon names the pages draw):
//   shield  something stopped the call: a deny rule, watchdeck, a block
//   eye     Claude Code's own auto check looked at it
//   check   an allow rule let it through
//   person  you decided
//   box     the OS sandbox
//   circle  nothing checked it
//   warn    a secret showed up in a transcript (leak, Needs you only)
// An unknown word reads as "Blocked" with the shield.
const AUTHORITY = {
  deny_rule: { label: "Deny rule", glyph: "shield" },
  classifier: { label: "Auto check", glyph: "eye" },
  auto: { label: "Auto check", glyph: "eye" },
  allow_rule: { label: "Allow rule", glyph: "check" },
  user: { label: "You", glyph: "person" },
  hook: { label: "watchdeck", glyph: "shield" },
  sandbox: { label: "Sandbox", glyph: "box" },
  blocked: { label: "Blocked", glyph: "shield" },
  none: { label: "No check", glyph: "circle" },
  leak: { label: "Secret seen", glyph: "warn" },
};

// leak (Plan 08) is a Needs you word only: the map never draws it, and its
// filter refuses it, so it stays out of AUTHORITY_ALL.
const INBOX_ONLY = new Set(["leak"]);

/** AUTHORITY_ALL: every authority word the map draws, strongest first, in the server's order. */
export const AUTHORITY_ALL = Object.freeze(Object.keys(AUTHORITY).filter((w) => !INBOX_ONLY.has(w)));

function lookup(table, key) {
  const k = String(key === undefined || key === null ? "" : key).replace(/-/g, "_");
  return Object.prototype.hasOwnProperty.call(table, k) ? table[k] : undefined;
}

/** authorityLabel(word): "Deny rule", "Auto check", ...; unknown → "Blocked". */
export function authorityLabel(word) {
  const a = lookup(AUTHORITY, word);
  return a ? a.label : AUTHORITY.blocked.label;
}

/** authorityGlyph(word): shield | check | person | box | eye | circle (see AUTHORITY). */
export function authorityGlyph(word) {
  const a = lookup(AUTHORITY, word);
  return a ? a.glyph : AUTHORITY.blocked.glyph;
}

// The watchdeck registrations in the status JSON's hook object that count
// toward "partly protected" (path, exists, error and the user's own
// sandbox.enabled do not).
const PROTECT_FIELDS = ["hookInstalled", "skillHook", "deniedHook", "startHook", "endHook", "promptHook", "excluded"];

const SEEN_MS = 24 * 3600 * 1000;

/**
 * baseProtectionWord(st) → "protected" | "partial" | "off", from GET /api/status.
 * Protected when the install is complete (and a sandbox backend exists);
 * partial when any watchdeck registration is present, or when watchdeck
 * logged a check in the last 24 h without being in these settings (the
 * plugin or a claude --settings file); off otherwise, and when the settings
 * file could not be read.
 */
function baseProtectionWord(st) {
  const hook = st && st.hook;
  if (!hook || hook.error) return "off";
  if (hook.complete) return st.enforcementAvailable === false ? "partial" : "protected";
  if (PROTECT_FIELDS.some((k) => hook[k] === true)) return "partial";
  const last = st.activity && st.activity.lastDecision;
  const seenMs = last ? Date.now() - Date.parse(last) : NaN;
  if (Number.isFinite(seenMs) && seenMs < SEEN_MS) return "partial";
  return "off";
}

/**
 * protectionWord(st) → "protected" | "observing" | "partial" | "off": the
 * base word, with "protected" read as "observing" while shadow mode is on
 * (st.shadow). Off and partial keep their words: nothing runs to observe
 * when off, and a partial install needs setup finished first.
 */
export function protectionWord(st) {
  const w = baseProtectionWord(st);
  return w === "protected" && st && st.shadow === true ? "observing" : w;
}

const PROTECTION = { protected: "Protected", observing: "Observing only", partial: "Partly protected", off: "Not protected" };

/** protectionLabel(word): "Protected" | "Observing only" | "Partly protected" | "Not protected". */
export function protectionLabel(word) {
  return lookup(PROTECTION, word) || PROTECTION.off;
}

const GROUPS = {
  sandbox: "Sandbox (the OS enforces)",
  blocked: "Blocked before Claude decides",
  automode: "Auto check (Claude's own rules)",
  watchdeck: "watchdeck checks",
  ask: "Ask (you decide each time)",
};

/** groupTitle(id): the Rules page's group heading; unknown ids read as themselves. */
export function groupTitle(id) {
  return lookup(GROUPS, id) || String(id);
}

const OWNERS = { us: "watchdeck", user: "you", claude_default: "Claude Code", project: "project", managed: "managed" };

/** ownerLabel(o): who added a rule; unknown → "other". */
export function ownerLabel(o) {
  return lookup(OWNERS, o) || COPY.common.other;
}

const ENFORCEMENT = {
  os: "OS sandbox",
  native_deny: "Claude Code settings",
  native_prompt: "Claude Code settings",
  classifier: "Auto check",
  hook_gate: "watchdeck",
  hook_sandbox: "watchdeck",
  advisory: "log only",
  allow: "allowed",
};

/** enforcementLabel(e): who enforces a rule; unknown → "other". */
export function enforcementLabel(e) {
  return lookup(ENFORCEMENT, e) || COPY.common.other;
}

let homeDir = "";

/** setHome(dir): the home directory scopeLabel shows as "~" (app.js or a page sets it when known). */
export function setHome(dir) {
  homeDir = typeof dir === "string" ? dir.replace(/\/+$/, "") : "";
}

/** tildify(path, home): path with the home prefix shown as "~". */
export function tildify(path, home = homeDir) {
  const p = String(path || "");
  if (home && (p === home || p.startsWith(home + "/"))) return "~" + p.slice(home.length);
  return p;
}

/**
 * scopeLabel(scope, file, home?): where a rule applies. user and managed →
 * "everywhere"; project and local → the project directory holding the file
 * (the directory above its .claude folder, or the file's own directory),
 * with the home prefix shown as "~".
 */
export function scopeLabel(scope, file, home = homeDir) {
  if (scope === "user" || scope === "managed") return "everywhere";
  let dir = String(file || "").replace(/\/[^/]*$/, "");
  if (dir.endsWith("/.claude")) dir = dir.slice(0, -"/.claude".length);
  return tildify(dir || "/", home);
}
