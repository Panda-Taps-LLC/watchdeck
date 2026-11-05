package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Panda-Taps-LLC/watchdeck/internal/activity"
)

const activityUsage = `usage: watchdeck activity [--json] [--summary] [--session ID] [--after N]
                          [--tail N] [--limit N] [--since RFC3339] [--kinds k1,k2]

Reads the activity log (hook decisions, sandboxed runs, Skill invocations and
auto-mode denials), joined the way the dashboard joins it. --json prints the
body of the dashboard's GET /api/activity:
  {"records":[...],"next":N,"reset":bool,"skipped":N,"path":"...","enabled":bool}
Pass "next" back as --after to read only what was appended since. Paging
matches the API: --limit defaults to 500, --limit and --tail are capped at
2000, and --tail applies only with --after 0. With no paging flag the text
form shows the newest 50 records instead. --summary counts decisions, runs and denials and names
the last denial (JSON with --json). Kinds: decision, run, skill_invoked,
denied. WATCHDECK_ACTIVITY=off turns the log off ("enabled": false).
Exit 0 even when the log is absent or off; 2 when it cannot be read; 3 usage.

`

// activityPage is the JSON body of `activity --json`, field for field the
// body of the dashboard's GET /api/activity (Spec A §1e).
type activityPage struct {
	Records []activity.Record `json:"records"`
	Next    int64             `json:"next"`
	Reset   bool              `json:"reset"`
	Skipped int               `json:"skipped"`
	Path    string            `json:"path"`
	Enabled bool              `json:"enabled"`
}

// activitySummary is `activity --summary --json`.
type activitySummary struct {
	Decisions map[string]int `json:"decisions"` // ask, allow
	Runs      map[string]int `json:"runs"`      // per outcome; total in RunsTotal
	RunsTotal int            `json:"runsTotal"`
	// Denied counts the records that show a denial: auto-mode `denied`
	// records, plus runs with a denial hint or a policy_error, no_sandbox or
	// usage outcome (the map's rule, decision 3).
	Denied int `json:"denied"`
	// DeniedBy splits Denied: one count per hint kind (a run with two kinds
	// counts under each), "auto_mode" for denied records, and the outcome
	// name for runs refused before the script ran.
	DeniedBy   map[string]int   `json:"deniedBy"`
	LastDenial *activity.Record `json:"lastDenial"`
	Skipped    int              `json:"skipped"`
	Path       string           `json:"path"`
	Enabled    bool             `json:"enabled"`
}

const (
	activityAPILimit = 500  // the dashboard API's default page
	activityMaxPage  = 2000 // the dashboard API's cap on limit and tail
	activityTextTail = 50   // the text form's default: newest records
)

func cmdActivity(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("activity", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, activityUsage)
		fs.PrintDefaults()
	}
	asJSON := fs.Bool("json", false, "machine-readable output")
	summary := fs.Bool("summary", false, "print counts and the last denial instead of records")
	session := fs.String("session", "", "only records of this Claude Code session id")
	after := fs.Int64("after", 0, "byte offset to read from (the previous \"next\")")
	tail := fs.Int("tail", 0, "with --after 0: only the newest N records")
	limit := fs.Int("limit", 0, "at most N records, oldest first")
	since := fs.String("since", "", "only records at or after this RFC3339 time")
	kinds := fs.String("kinds", "", "comma-separated record kinds")
	if err := fs.Parse(args); err != nil {
		return 3
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "watchdeck activity: unexpected argument %q\n", fs.Arg(0))
		return 3
	}
	if *after < 0 || *tail < 0 || *limit < 0 {
		fmt.Fprintln(stderr, "watchdeck activity: --after, --tail and --limit must not be negative")
		return 3
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })

	o := activity.ReadOptions{After: *after, SessionID: *session}
	if *since != "" {
		t, err := time.Parse(time.RFC3339, *since)
		if err != nil {
			fmt.Fprintf(stderr, "watchdeck activity: --since: want RFC3339 (2026-10-12T09:00:00Z): %v\n", err)
			return 3
		}
		o.Since = t
	}
	if *kinds != "" {
		for _, k := range strings.Split(*kinds, ",") {
			k = strings.TrimSpace(k)
			if k == "" {
				continue
			}
			switch k {
			case activity.KindDecision, activity.KindRun, activity.KindSkillInvoked, activity.KindDenied:
				o.Kinds = append(o.Kinds, k)
			default:
				fmt.Fprintf(stderr, "watchdeck activity: --kinds: unknown kind %q (want decision, run, skill_invoked, denied)\n", k)
				return 3
			}
		}
	}
	if !*summary {
		// The API's paging rules: limit defaults to 500, both caps are 2000,
		// and tail only counts from offset 0. The text form with no paging
		// flag shows the newest 50 instead.
		o.Tail, o.Limit = min(*tail, activityMaxPage), min(*limit, activityMaxPage)
		if !*asJSON && !set["after"] && !set["tail"] && !set["limit"] {
			o.Tail = activityTextTail
		}
		if o.Limit == 0 {
			o.Limit = activityAPILimit
		}
	}

	hp, _, err := hostPaths()
	if err != nil {
		fmt.Fprintln(stderr, "watchdeck activity:", err)
		return 2
	}
	path := hp.Activity
	res, err := activity.Read(path, o)
	if err != nil {
		fmt.Fprintln(stderr, "watchdeck activity:", err)
		return 2
	}
	if res.Records == nil {
		res.Records = []activity.Record{}
	}

	if *summary {
		s := summarize(res.Records)
		s.Skipped, s.Path, s.Enabled = res.Skipped, path, path != ""
		if *asJSON {
			return writeJSON(stdout, stderr, s)
		}
		printSummary(stdout, s)
		return 0
	}
	if *asJSON {
		return writeJSON(stdout, stderr, activityPage{
			Records: res.Records, Next: res.Next, Reset: res.Reset,
			Skipped: res.Skipped, Path: path, Enabled: path != "",
		})
	}
	if path == "" {
		fmt.Fprintln(stdout, "activity log is off (WATCHDECK_ACTIVITY=off)")
		return 0
	}
	if len(res.Records) == 0 {
		fmt.Fprintf(stdout, "no activity in %s\n", path)
		return 0
	}
	for _, r := range res.Records {
		printRecord(stdout, r)
	}
	return 0
}

func writeJSON(stdout, stderr io.Writer, v any) int {
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		fmt.Fprintln(stderr, "watchdeck:", err)
		return 2
	}
	return 0
}

// denial reports whether r shows a denial and the DeniedBy keys it counts under.
func denial(r activity.Record) (bool, []string) {
	switch r.Kind {
	case activity.KindDenied:
		return true, []string{"auto_mode"}
	case activity.KindRun:
		if len(r.Hints) > 0 {
			var keys []string
			seen := map[string]bool{}
			for _, h := range r.Hints {
				if !seen[h.Kind] {
					seen[h.Kind] = true
					keys = append(keys, h.Kind)
				}
			}
			return true, keys
		}
		switch r.Outcome {
		case activity.OutcomePolicyError, activity.OutcomeNoSandbox, activity.OutcomeUsage:
			return true, []string{r.Outcome}
		}
	}
	return false, nil
}

func summarize(recs []activity.Record) activitySummary {
	s := activitySummary{
		Decisions: map[string]int{"ask": 0, "allow": 0},
		Runs: map[string]int{
			activity.OutcomeOK: 0, activity.OutcomeFailed: 0, activity.OutcomeSignaled: 0,
			activity.OutcomePolicyError: 0, activity.OutcomeNoSandbox: 0, activity.OutcomeUsage: 0,
		},
		DeniedBy: map[string]int{},
	}
	for i := range recs {
		r := recs[i]
		switch r.Kind {
		case activity.KindDecision:
			if r.Decision != "" {
				s.Decisions[r.Decision]++
			}
		case activity.KindRun:
			s.RunsTotal++
			if r.Outcome != "" {
				s.Runs[r.Outcome]++
			}
		}
		if ok, keys := denial(r); ok {
			s.Denied++
			for _, k := range keys {
				s.DeniedBy[k]++
			}
			s.LastDenial = &recs[i]
		}
	}
	return s
}

func printSummary(w io.Writer, s activitySummary) {
	if !s.Enabled {
		fmt.Fprintln(w, "activity log is off (WATCHDECK_ACTIVITY=off)")
		return
	}
	fmt.Fprintf(w, "log:        %s\n", clean(s.Path))
	fmt.Fprintf(w, "decisions:  %d ask, %d allow\n", s.Decisions["ask"], s.Decisions["allow"])
	fmt.Fprintf(w, "runs:       %d%s\n", s.RunsTotal, countList(s.Runs))
	fmt.Fprintf(w, "denials:    %d%s\n", s.Denied, countList(s.DeniedBy))
	if d := s.LastDenial; d != nil {
		fmt.Fprintf(w, "last:       %s  %s  %s\n", clean(d.TS), clean(recordSkills(*d)), clean(denialText(*d)))
	} else {
		fmt.Fprintln(w, "last:       none")
	}
	if s.Skipped > 0 {
		fmt.Fprintf(w, "skipped:    %d unreadable line(s)\n", s.Skipped)
	}
}

// countList renders the non-zero counts as " (a 1, b 2)", sorted by key.
func countList(m map[string]int) string {
	var keys []string
	for k, n := range m {
		if n > 0 {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return ""
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = k + " " + strconv.Itoa(m[k])
	}
	return " (" + strings.Join(parts, ", ") + ")"
}

func denialText(r activity.Record) string {
	switch {
	case len(r.Hints) > 0:
		return r.Hints[0].Text
	case r.Kind == activity.KindDenied:
		if r.Reason != "" {
			return "auto mode denied: " + r.Reason
		}
		return "auto mode denied the call"
	case r.Error != "":
		return r.Outcome + ": " + r.Error
	}
	return r.Outcome
}

func recordSkills(r activity.Record) string {
	if len(r.Skills) > 0 {
		return strings.Join(r.Skills, ",")
	}
	if r.Skill != "" {
		return r.Skill
	}
	return "-"
}

// printRecord prints one record on one line: ts kind skills status command.
func printRecord(w io.Writer, r activity.Record) {
	status := "-"
	switch r.Kind {
	case activity.KindDecision:
		status = r.Decision
		if r.Shadow {
			status += " (would " + r.Would + ")"
		}
		if r.Confidence == "low" {
			status += "(low)"
		}
	case activity.KindRun:
		status = r.Outcome
		if r.Exit != nil {
			status += " exit " + strconv.Itoa(*r.Exit)
		}
		if n := len(r.Hints); n > 0 {
			status += " hints " + strconv.Itoa(n)
		}
	case activity.KindDenied:
		status = "denied"
	case activity.KindSkillInvoked:
		status = "invoked"
	}
	cmd := r.Command
	if cmd == "" && r.ToolName != "" {
		cmd = r.ToolName
	}
	fmt.Fprintf(w, "%s  %-13s  %s  %s  %s\n", clean(r.TS), clean(r.Kind), clean(recordSkills(r)), clean(status), clean(truncate(cmd, 120)))
}

func truncate(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n]) + "…"
}

// clean escapes control characters so a logged command cannot drive the
// terminal (the log records whatever text the agent ran).
func clean(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0):
			fmt.Fprintf(&b, `\x%02x`, r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
