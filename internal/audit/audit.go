// Package audit builds the inventory report behind `watchdeck audit`.
package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"text/tabwriter"

	"github.com/Panda-Taps-LLC/watchdeck/internal/inventory"
	"github.com/Panda-Taps-LLC/watchdeck/internal/manifest"
	"github.com/Panda-Taps-LLC/watchdeck/internal/scan"
	"github.com/Panda-Taps-LLC/watchdeck/internal/skills"
)

// Options controls a report.
type Options struct {
	Roots       skills.Roots
	UserCfgDir  string // where overrides.yaml lives
	ProjectRoot string // where .watchdeck.yaml lives ("" = none)
	Verbose     bool   // keep scan hits in rows
}

// Row is one skill in the report. The JSON keys are a documented interface
// (`audit --json`): existing keys keep their names and types; `effective`
// stays the summary string and the structured views sit beside it.
type Row struct {
	Name        string `json:"name"`
	Source      string `json:"source"`
	PluginID    string `json:"pluginId,omitempty"`
	Root        string `json:"root"`
	RealRoot    string `json:"realRoot"`
	Enabled     bool   `json:"enabled"`
	Description string `json:"description,omitempty"` // SKILL.md frontmatter description

	Scripts        []inventory.Script `json:"scripts"`
	ScriptsSummary string             `json:"scriptsSummary"`
	Caps           []scan.Category    `json:"caps"`
	CapsSummary    string             `json:"capsSummary"`
	Hits           []scan.Hit         `json:"hits,omitempty"`

	ManifestStatus string   `json:"manifest"` // none | ok | invalid
	ManifestPath   string   `json:"manifestPath,omitempty"`
	ManifestError  string   `json:"manifestError,omitempty"`
	Profile        string   `json:"profile"` // table cell
	Effective      string   `json:"effective,omitempty"`
	Ungranted      []string `json:"ungranted,omitempty"`
	Ignored        []string `json:"ignored,omitempty"` // project override entries dropped
	Hash           string   `json:"hash"`
	Problems       []string `json:"problems,omitempty"`

	// Structured policy views. Request is the manifest as written and is
	// null when the skill has none or it is invalid; Grant is Default()
	// widened by the overrides, before Clip; EffectiveDetail is what run uses.
	Request         *manifest.View `json:"request"`
	Grant           manifest.View  `json:"grant"`
	EffectiveDetail manifest.View  `json:"effectiveDetail"`
}

// Report is the whole audit.
type Report struct {
	Rows   []Row    `json:"skills"`
	Totals Totals   `json:"totals"`
	Errors []string `json:"errors,omitempty"` // non-fatal per-skill errors (unreadable dirs)
}

// Totals summarises a report.
type Totals struct {
	Skills       int      `json:"skills"`
	WithScripts  int      `json:"withScripts"`
	WithManifest int      `json:"withManifest"`
	Invalid      int      `json:"invalidManifests"`
	NetSkills    []string `json:"networkSkills"`
	WithProblems int      `json:"withProblems"`
}

// Build discovers skills and fills every row.
func Build(o Options) (Report, error) {
	found, err := skills.Scan(o.Roots)
	if err != nil {
		return Report{}, err
	}
	user, project, err := manifest.LoadOverrides(o.UserCfgDir, o.ProjectRoot)
	if err != nil {
		return Report{}, err
	}
	var rep Report
	rows := make([]Row, len(found))
	errs := make([][]string, len(found))
	var wg sync.WaitGroup
	sem := make(chan struct{}, runtime.NumCPU())
	for i := range found {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			rows[i], errs[i] = buildRow(found[i], user, project, o.Verbose)
		}(i)
	}
	wg.Wait()
	rep.Rows = rows
	for _, e := range errs {
		rep.Errors = append(rep.Errors, e...)
	}
	rep.Totals = totals(rep.Rows)
	return rep, nil
}

// BuildOne builds the row for a single skill, exactly as Build would (the
// dashboard uses it after a grant edit). Discovery runs with o.Roots, so a
// disabled plugin's skill is found only with Roots.All; when several sources
// carry the same name the first in discovery order wins, as in Build. The
// second result is false when no skill has that name. Non-fatal per-skill
// problems (unreadable dirs) are dropped; Build reports them in Errors.
func BuildOne(name string, o Options) (Row, bool, error) {
	found, err := skills.Scan(o.Roots)
	if err != nil {
		return Row{}, false, err
	}
	var pick *skills.Skill
	for i := range found {
		if found[i].Name == name {
			pick = &found[i]
			break
		}
	}
	if pick == nil {
		return Row{}, false, nil
	}
	user, project, err := manifest.LoadOverrides(o.UserCfgDir, o.ProjectRoot)
	if err != nil {
		return Row{}, false, err
	}
	row, _ := buildRow(*pick, user, project, o.Verbose)
	return row, true, nil
}

// buildRow fills one row; errs collects non-fatal problems.
func buildRow(s skills.Skill, user, project manifest.Overrides, verbose bool) (Row, []string) {
	var errs []string
	row := Row{
		Name: s.Name, Source: s.Kind.String(), PluginID: s.PluginID,
		Root: s.Root, RealRoot: s.RealRoot, Enabled: s.Enabled,
		Description: s.Frontmatter.Description,
		Problems:    append([]string(nil), s.Problems...),
	}
	if s.Kind == skills.Plugin && s.PluginID != "" {
		row.Source = "plugin:" + s.PluginID
	}

	// manifest (request)
	var req manifest.Manifest
	hasReq := false
	mp := filepath.Join(s.RealRoot, "PERMISSIONS.yaml")
	if m, perr := manifest.Parse(mp); perr == nil {
		req, hasReq = m, true
		row.ManifestStatus, row.ManifestPath = "ok", mp
	} else if isNotExist(perr) {
		row.ManifestStatus = "none"
	} else {
		row.ManifestStatus, row.ManifestPath, row.ManifestError = "invalid", mp, perr.Error()
	}

	// scripts
	globs := manifest.Default().Scripts
	if hasReq && len(req.Scripts) > 0 {
		globs = append(append([]string(nil), globs...), req.Scripts...)
	}
	scripts, serr := inventory.Scripts(s.RealRoot, globs)
	if serr != nil {
		errs = append(errs, fmt.Sprintf("%s: scripts: %v", s.Name, serr))
	}
	row.Scripts = scripts
	row.ScriptsSummary = inventory.Summary(scripts)

	// capability scan
	hits, herr := scan.Dir(s.RealRoot)
	if herr != nil {
		errs = append(errs, fmt.Sprintf("%s: scan: %v", s.Name, herr))
	}
	row.Caps = scan.Flags(hits)
	row.CapsSummary = scan.Summary(hits)
	if verbose {
		row.Hits = hits
	}

	// hash
	if h, err := inventory.Hash(s.RealRoot); err == nil {
		row.Hash = h
	}

	// effective policy
	grant, ignored := manifest.Grant(s.Name, user, project)
	row.Ignored = ignored
	eff := grant
	if hasReq {
		eff, row.Ungranted = manifest.Clip(req, grant)
		rv := req.View()
		row.Request = &rv
	}
	row.Grant = grant.View()
	row.EffectiveDetail = eff.View()
	row.Effective = eff.Summary()
	row.Profile = ProfileCell(row, eff, hasReq)
	return row, errs
}

func isNotExist(err error) bool {
	s := err.Error()
	return strings.Contains(s, "no such file") || strings.Contains(s, "not exist")
}

func hasCap(caps []scan.Category, c scan.Category) bool {
	for _, x := range caps {
		if x == c {
			return true
		}
	}
	return false
}

// ProfileCell renders the PROFILE column: "n/a" without scripts, "default"
// for the untouched default grant, otherwise a compact diff from it, with
// "(needs net)" when the scan found network use and nothing grants it, and
// "asks[...]" when the manifest requested more than it was granted. It reads
// row.Scripts, row.Caps and row.Ungranted.
func ProfileCell(row Row, eff manifest.Effective, hasReq bool) string {
	if len(row.Scripts) == 0 {
		return "n/a"
	}
	def := manifest.Default()
	var parts []string
	if eff.Network != def.Network {
		parts = append(parts, "net="+eff.Network.String())
	}
	if extra := len(eff.Write) - len(def.Write); extra > 0 {
		parts = append(parts, fmt.Sprintf("+write:%d", extra))
	}
	if extra := len(eff.Env) - len(def.Env); extra > 0 {
		parts = append(parts, fmt.Sprintf("+env:%d", extra))
	}
	if !eff.ExecAny {
		parts = append(parts, fmt.Sprintf("exec:%d", len(eff.Exec)))
	}
	if eff.AutoAllow {
		parts = append(parts, "auto")
	}
	cell := "default"
	if len(parts) > 0 {
		cell = strings.Join(parts, " ")
	}
	if eff.Network == manifest.NetNone && hasCap(row.Caps, scan.Network) {
		cell += " (needs net)"
	}
	if hasReq && len(row.Ungranted) > 0 {
		cell += " asks[" + strings.Join(row.Ungranted, "; ") + "]"
	}
	return cell
}

func totals(rows []Row) Totals {
	var t Totals
	t.Skills = len(rows)
	for _, r := range rows {
		if len(r.Scripts) > 0 {
			t.WithScripts++
		}
		if r.ManifestStatus == "ok" {
			t.WithManifest++
		}
		if r.ManifestStatus == "invalid" {
			t.Invalid++
			t.WithManifest++
		}
		if hasCap(r.Caps, scan.Network) {
			t.NetSkills = append(t.NetSkills, r.Name)
		}
		if len(r.Problems) > 0 {
			t.WithProblems++
		}
	}
	sort.Strings(t.NetSkills)
	return t
}

// Table writes the human report.
func (r Report) Table(w io.Writer, verbose bool) {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "SKILL\tSOURCE\tSCRIPTS\tCAPS\tMANIFEST\tPROFILE\tHASH")
	for _, row := range r.Rows {
		m := row.ManifestStatus
		if m == "invalid" {
			m = "invalid(" + firstLine(row.ManifestError) + ")"
		}
		h := row.Hash
		if len(h) > 8 {
			h = h[:8]
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", row.Name, shortSource(row.Source), row.ScriptsSummary, row.CapsSummary, m, row.Profile, h)
		if verbose {
			for _, p := range row.Problems {
				fmt.Fprintf(tw, "  !\t%s\t\t\t\t\t\n", p)
			}
			for _, ig := range row.Ignored {
				fmt.Fprintf(tw, "  !\t%s\t\t\t\t\t\n", ig)
			}
			seen := map[scan.Category]bool{}
			for _, h := range row.Hits {
				if seen[h.Category] {
					continue
				}
				seen[h.Category] = true
				fmt.Fprintf(tw, "  %s\t%s:%d\t%s\t\t\t\t\n", h.Category, h.File, h.Line, h.Snippet)
			}
		}
	}
	tw.Flush()
	t := r.Totals
	fmt.Fprintf(w, "\n%d skills, %d ship scripts, %d have manifests", t.Skills, t.WithScripts, t.WithManifest)
	if t.Invalid > 0 {
		fmt.Fprintf(w, " (%d invalid)", t.Invalid)
	}
	fmt.Fprint(w, ".")
	if len(t.NetSkills) > 0 {
		fmt.Fprintf(w, " %d reference network calls: %s.", len(t.NetSkills), strings.Join(t.NetSkills, ", "))
	}
	if t.WithProblems > 0 {
		fmt.Fprintf(w, " %d have SKILL.md problems (--verbose).", t.WithProblems)
	}
	fmt.Fprintln(w)
	for _, e := range r.Errors {
		fmt.Fprintln(w, "warning:", e)
	}
}

func shortSource(s string) string {
	if strings.HasPrefix(s, "plugin:") {
		id := strings.TrimPrefix(s, "plugin:")
		if i := strings.Index(id, "@"); i > 0 {
			return "plugin:" + id[:i]
		}
		return s
	}
	return s
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 60 {
		s = s[:57] + "..."
	}
	return s
}

// JSON writes the machine report.
func (r Report) JSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
