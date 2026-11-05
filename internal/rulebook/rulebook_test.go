package rulebook

import (
	"bytes"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Panda-Taps-LLC/watchdeck/internal/claudesettings"
	"github.com/Panda-Taps-LLC/watchdeck/internal/manifest"
	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
)

const composeSettings = `{
  "permissions": {
    "deny": ["Read(~/.ssh/id_*)", "Bash(curl *)"],
    "ask": ["Bash(git push *)"],
    "allow": ["Bash(ls *)"]
  },
  "autoMode": {"hard_deny": ["$defaults", "no prod"]},
  "sandbox": {"network": {"allowedDomains": ["example.com"]}}
}`

const composeOverrides = `version: 2
packs: {exfil: {action: deny}}
rules:
  - {id: no-prod-db, tool: Bash, match: {regex: 'psql .*prod'}, action: deny}
subjects:
  - {kind: command, name: make, match: {argv0: [make]}}
`

func saveLedger(t *testing.T, stateDir string, entries ...claudesettings.LedgerEntry) {
	t.Helper()
	led := &claudesettings.Ledger{V: 1, Entries: entries}
	if err := led.Save(stateDir); err != nil {
		t.Fatal(err)
	}
}

func TestListComposes(t *testing.T) {
	p := testEnv(t)
	settings := p.ClaudeSettings()
	writeFile(t, settings, composeSettings)
	writeFile(t, p.OverridesFile(), composeOverrides)
	saveLedger(t, p.StateDir, claudesettings.LedgerEntry{
		Path: settings, Key: claudesettings.KeyDeny, Value: "Read(~/.ssh/id_*)", RuleIDs: []string{IntentPrefix + IntentID("Read(~/.ssh/id_*)")},
	})

	book, err := List(Input{Paths: p})
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, g := range book.Groups {
		ids = append(ids, g.ID)
		if g.Title == "" {
			t.Errorf("group %s has no title", g.ID)
		}
	}
	if got := strings.Join(ids, ","); got != "sandbox,blocked,automode,watchdeck,ask" {
		t.Fatalf("groups %s", got)
	}
	if len(book.Warnings) != 0 {
		t.Errorf("warnings %v", book.Warnings)
	}
	if len(book.Drift) != 0 {
		t.Errorf("drift %+v", book.Drift)
	}
	if len(book.Recommended) != 11 {
		t.Errorf("Recommended %d, want 11", len(book.Recommended))
	}
	if len(book.Files) == 0 || book.Updated.IsZero() {
		t.Errorf("files %d updated %v", len(book.Files), book.Updated)
	}

	user := claudesettings.ScopeUser
	type want struct {
		id, group              string
		kind                   Kind
		owner                  Owner
		enf                    Enforcement
		state                  State
		action, sentence, tool string
		recommended            bool
		twin, href             string
	}
	wants := []want{
		{RowID(KindNativeDeny, user, claudesettings.KeyDeny, "Read(~/.ssh/id_*)"), GroupBlocked, KindNativeDeny, OwnerUs, EnforceNativeDeny, StateOn,
			"deny", "Block reading ~/.ssh/id_*", "Read", true, "secrets-read/read-ssh-private-key", ""},
		{RowID(KindNativeDeny, user, claudesettings.KeyDeny, "Bash(curl *)"), GroupBlocked, KindNativeDeny, OwnerUser, EnforceNativeDeny, StateOn,
			"deny", "Block running curl *", "Bash", false, "", ""},
		{RowID(KindNativeAsk, user, claudesettings.KeyAsk, "Bash(git push *)"), GroupAsk, KindNativeAsk, OwnerUser, EnforceNativePrompt, StateOn,
			"ask", "Ask before running git push *", "Bash", false, "", ""},
		{RowID(KindNativeAllow, user, claudesettings.KeyAllow, "Bash(ls *)"), GroupAsk, KindNativeAllow, OwnerUser, EnforceAllow, StateOn,
			"allow", "Allow without asking running ls *", "Bash", false, "", ""},
		{RowID(KindAutoModeHard, user, claudesettings.KeyHardDeny, "$defaults"), GroupAutoMode, KindAutoModeHard, OwnerClaudeDefault, EnforceClassifier, StateOn,
			"deny", "Claude Code's built-in list", "", false, "", ""},
		{RowID(KindAutoModeHard, user, claudesettings.KeyHardDeny, "no prod"), GroupAutoMode, KindAutoModeHard, OwnerUser, EnforceClassifier, StateOn,
			"deny", "Auto mode blocks: no prod", "", false, "", ""},
		{RowID(KindSandboxDomain, user, claudesettings.KeyAllowedDomains, "example.com"), GroupSandbox, KindSandboxDomain, OwnerUser, EnforceOS, StateOn,
			"allow", "Sandboxed commands may reach example.com", "", false, "", ""},
		{"subject:command:make", GroupSandbox, KindSubject, OwnerUser, EnforceOS, StateOn,
			"", "make runs sandboxed: " + manifest.Default().Summary(), "Bash", false, "", ""},
		{"user:no-prod-db", GroupWatchdeck, KindHookRegex, OwnerUser, EnforceHookGate, StateOn,
			"deny", "Block a Bash call matching /psql .*prod/", "Bash", false, "", ""},
	}
	for _, w := range wants {
		r, group, ok := findRow(book, w.id)
		if !ok {
			t.Errorf("no row %s", w.id)
			continue
		}
		if group != w.group || r.Kind != w.kind || r.Owner != w.owner || r.Enforcement != w.enf || r.State != w.state ||
			r.Action != w.action || r.Sentence != w.sentence || r.Tool != w.tool || r.Recommended != w.recommended ||
			r.Twin != w.twin || r.DetailHref != w.href || r.Harness != HarnessClaudeCode {
			t.Errorf("row %s in %s:\n got  %+v\n want %+v", w.id, group, r, w)
		}
	}
	if r, _, _ := findRow(book, wants[0].id); r.Source.File != settings || r.Source.Key != claudesettings.KeyDeny || r.Source.Index != 0 || r.Scope != user {
		t.Errorf("source %+v scope %s", r.Source, r.Scope)
	}
	if r, _, _ := findRow(book, wants[1].id); r.Value != "Bash(curl *)" || r.Source.Index != 1 {
		t.Errorf("value %q index %d", r.Value, r.Source.Index)
	}

	// Pack rows: exfil set to deny, prompt-injection off by default, log rules advisory.
	sawExfil, sawOff, sawAdvisory := false, false, false
	seen := map[string]bool{}
	for _, g := range book.Groups {
		for _, r := range g.Rows {
			if seen[r.ID] {
				t.Errorf("duplicate row id %s", r.ID)
			}
			seen[r.ID] = true
			if r.Kind != KindPack {
				continue
			}
			if g.ID != GroupWatchdeck || r.Owner != OwnerUs || r.Sentence == "" {
				t.Errorf("pack row %+v in %s", r, g.ID)
			}
			switch {
			case strings.HasPrefix(r.ID, "pack:exfil/"):
				sawExfil = true
				if r.Action != "deny" || r.Enforcement != EnforceHookGate || r.State != StateOn {
					t.Errorf("exfil row %+v", r)
				}
			case strings.HasPrefix(r.ID, "pack:prompt-injection/"):
				sawOff = true
				if r.State != StateOff {
					t.Errorf("prompt-injection row on: %+v", r)
				}
			}
			if r.Action == "log" {
				sawAdvisory = true
				if r.Enforcement != EnforceAdvisory {
					t.Errorf("log row %+v", r)
				}
			}
		}
	}
	if !sawExfil || !sawOff || !sawAdvisory {
		t.Errorf("pack rows: exfil %v off %v advisory %v", sawExfil, sawOff, sawAdvisory)
	}
}

func TestListDriftRow(t *testing.T) {
	p := testEnv(t)
	settings := p.ClaudeSettings()
	writeFile(t, settings, `{"permissions": {"deny": ["Bash(curl *)"]}}`)
	writeFile(t, p.OverridesFile(), composeOverrides)
	saveLedger(t, p.StateDir, claudesettings.LedgerEntry{
		Path: settings, Key: claudesettings.KeyDeny, Value: "Read(~/.aws/credentials)", RuleIDs: []string{IntentPrefix + IntentID("Read(~/.aws/credentials)")},
	})
	ledgerPath := p.StateDir + "/" + claudesettings.LedgerFile
	before := map[string][]byte{
		ledgerPath:        readBytes(t, ledgerPath),
		settings:          readBytes(t, settings),
		p.OverridesFile(): readBytes(t, p.OverridesFile()),
	}

	book, err := List(Input{Paths: p})
	if err != nil {
		t.Fatal(err)
	}
	for path, b := range before {
		if !bytes.Equal(b, readBytes(t, path)) {
			t.Errorf("List changed %s", path)
		}
	}
	if len(book.Drift) != 1 || book.Drift[0].Entry.Value != "Read(~/.aws/credentials)" || book.Drift[0].Reason != claudesettings.ReasonRemovedByUser {
		t.Fatalf("drift %+v", book.Drift)
	}
	id := RowID(KindNativeDeny, claudesettings.ScopeUser, claudesettings.KeyDeny, "Read(~/.aws/credentials)")
	r, group, ok := findRow(book, id)
	if !ok {
		t.Fatalf("no drift row %s", id)
	}
	if group != GroupBlocked || r.State != StateRemoved || r.Owner != OwnerUs || r.Sentence != "Block reading ~/.aws/credentials" ||
		r.Source.File != settings || r.Source.Key != claudesettings.KeyDeny {
		t.Errorf("drift row %+v in %s", r, group)
	}
	// The removed recommended string is reported missing again.
	foundMissing := false
	for _, m := range book.Recommended {
		foundMissing = foundMissing || m.Value == "Read(~/.aws/credentials)"
	}
	if !foundMissing {
		t.Error("removed recommended string not in Book.Recommended")
	}

	// A caller's ledger is not mutated by the reconcile inside List.
	led, err := claudesettings.LoadLedger(p.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := List(Input{Paths: p, Ledger: led}); err != nil {
		t.Fatal(err)
	}
	if len(led.Entries) != 1 {
		t.Errorf("List mutated the caller's ledger: %+v", led.Entries)
	}
	if !bytes.Equal(before[ledgerPath], readBytes(t, ledgerPath)) {
		t.Error("second List changed the ledger file")
	}
}

func TestListUnreadableFileWarns(t *testing.T) {
	p := testEnv(t)
	settings := p.ClaudeSettings()
	writeFile(t, settings, `{"permissions": {"deny": [`)
	writeFile(t, p.OverridesFile(), composeOverrides)

	book, err := List(Input{Paths: p})
	if err != nil {
		t.Fatal(err)
	}
	named := false
	for _, w := range book.Warnings {
		named = named || strings.Contains(w, settings)
	}
	if !named {
		t.Errorf("warnings %v do not name %s", book.Warnings, settings)
	}
	if _, _, ok := findRow(book, "user:no-prod-db"); !ok {
		t.Error("user rule row missing")
	}
	if _, _, ok := findRow(book, "subject:command:make"); !ok {
		t.Error("subject row missing")
	}
	packs := 0
	for _, g := range book.Groups {
		for _, r := range g.Rows {
			if r.Kind == KindPack {
				packs++
			}
		}
	}
	if packs == 0 {
		t.Error("no pack rows")
	}
}

func TestListSubjectRows(t *testing.T) {
	p := testEnv(t)
	writeFile(t, p.OverridesFile(), `version: 2
subjects:
  - {kind: skill, name: pdf, grant: {network: all}}
  - {kind: mcp, name: github, tools: {'delete_*': deny, 'create_*': ask}, launch: {sandbox: true}}
  - {kind: tool, name: files, match: {tools: [Write, Edit]}, paths: {deny: ['~/.zshrc'], ask: ['**/.git/config']}}
  - {kind: agent, name: researcher, match: {agent_type: researcher}, tools: {deny: [Bash]}, skills: {allow: [pdf]}}
`)
	book, err := List(Input{Paths: p})
	if err != nil {
		t.Fatal(err)
	}
	type row struct{ group, sentence, href string }
	got := map[string]row{}
	seen := map[string]bool{}
	for _, g := range book.Groups {
		for _, r := range g.Rows {
			if seen[r.ID] {
				t.Errorf("duplicate id %s", r.ID)
			}
			seen[r.ID] = true
			if r.Kind == KindSubject {
				if !strings.HasPrefix(r.ID, "subject:") || r.Owner != OwnerUser || r.Source.Key != "subjects" {
					t.Errorf("subject row %+v", r)
				}
				got[r.Sentence] = row{g.ID, r.Sentence, r.DetailHref}
			}
		}
	}
	wants := []row{
		{GroupSandbox, "pdf runs sandboxed: ", "#/rules/skill/pdf"},
		{GroupSandbox, "MCP server github starts under the sandbox", "#/rules/mcp/github"},
		{GroupWatchdeck, "Block the MCP tool delete_* on github", "#/rules/mcp/github"},
		{GroupAsk, "Ask before the MCP tool create_* on github", "#/rules/mcp/github"},
		{GroupWatchdeck, "Block Write, Edit on ~/.zshrc", ""},
		{GroupAsk, "Ask before Write, Edit on **/.git/config", ""},
		{GroupWatchdeck, "Agent researcher: Block Bash", ""},
		{GroupWatchdeck, "Agent researcher: Block every skill except pdf", ""},
	}
	for _, w := range wants {
		var r row
		var ok bool
		for s, v := range got {
			if s == w.sentence || (strings.HasSuffix(w.sentence, ": ") && strings.HasPrefix(s, w.sentence)) {
				r, ok = v, true
			}
		}
		if !ok || r.group != w.group || r.href != w.href {
			t.Errorf("want %+v, got %+v (ok %v); all: %v", w, r, ok, got)
		}
	}
	// Each subject's first row has the bare id; later rows add the hash of "<list>:<entry>".
	idWants := map[string]string{
		"subject:mcp:github":                                      "MCP server github starts under the sandbox",
		"subject:mcp:github:" + hash8("tools:create_*"):           "Ask before the MCP tool create_* on github",
		"subject:mcp:github:" + hash8("tools:delete_*"):           "Block the MCP tool delete_* on github",
		"subject:tool:files":                                      "Block Write, Edit on ~/.zshrc",
		"subject:tool:files:" + hash8("paths.ask:**/.git/config"): "Ask before Write, Edit on **/.git/config",
		"subject:agent:researcher":                                "Agent researcher: Block Bash",
		"subject:agent:researcher:" + hash8("skills.allow:pdf"):   "Agent researcher: Block every skill except pdf",
	}
	for id, want := range idWants {
		if r, _, ok := findRow(book, id); !ok || r.Sentence != want {
			t.Errorf("row %s: ok %v sentence %q, want %q", id, ok, r.Sentence, want)
		}
	}
	if r, _, ok := findRow(book, "subject:skill:pdf"); !ok || !strings.Contains(r.Sentence, "network=all") || r.Enforcement != EnforceOS {
		t.Errorf("skill row %+v", r)
	}
}

// TestListOwnerlessLedgerEntryIsUser: a legacy ledger entry no rule id
// claims owns nothing (claudesettings.Ledger.Owners is nil), so List shows
// its string as the person's, and Remove refuses it: the two agree.
func TestListOwnerlessLedgerEntryIsUser(t *testing.T) {
	p := testEnv(t)
	settings := p.ClaudeSettings()
	writeFile(t, settings, `{"permissions": {"deny": ["Bash(curl *)"]}}`)
	saveLedger(t, p.StateDir, claudesettings.LedgerEntry{Path: settings, Key: claudesettings.KeyDeny, Value: "Bash(curl *)"})
	book, err := List(Input{Paths: p})
	if err != nil {
		t.Fatal(err)
	}
	id := RowID(KindNativeDeny, claudesettings.ScopeUser, claudesettings.KeyDeny, "Bash(curl *)")
	r, _, ok := findRow(book, id)
	if !ok {
		t.Fatalf("no row %s", id)
	}
	if r.Owner != OwnerUser {
		t.Errorf("owner %q, want %q", r.Owner, OwnerUser)
	}
	if _, err := Remove(Input{Paths: p}, id); !errors.Is(err, ErrNotOwned) {
		t.Errorf("Remove: err = %v, want ErrNotOwned", err)
	}
}

// TestExcludedRowOwnedByWatchdeck: the sandbox.excludedCommands entry that
// `enforce install` writes (paths.BinaryName + " run *") is watchdeck's own,
// so its row says "Added by watchdeck" and its sentence says why; any other
// excluded command stays the person's (Plan 05 Task 6, 2026-10-20).
func TestExcludedRowOwnedByWatchdeck(t *testing.T) {
	p := testEnv(t)
	userFile := filepath.Join(p.ClaudeDir, "settings.json")
	ours := paths.BinaryName + " run *"
	other := "othertool run *"
	eff := claudesettings.Effective{}
	eff.Sandbox.Excluded = []claudesettings.Entry{
		{Value: ours, Scope: claudesettings.ScopeUser, Path: userFile, Index: 0},
		{Value: other, Scope: claudesettings.ScopeUser, Path: userFile, Index: 1},
	}
	book, err := List(Input{Paths: p, Effective: &eff})
	if err != nil {
		t.Fatal(err)
	}
	r, _, ok := findRow(book, RowID(KindSandboxExcluded, claudesettings.ScopeUser, claudesettings.KeyExcluded, ours))
	if !ok {
		t.Fatalf("no row for %q", ours)
	}
	if r.Owner != OwnerUs {
		t.Errorf("%q: owner = %q, want %q", ours, r.Owner, OwnerUs)
	}
	if !strings.Contains(r.Sentence, ours) || !strings.Contains(r.Sentence, "so "+paths.BinaryName+" can apply its own sandbox") {
		t.Errorf("%q: sentence = %q, want it to name the command and say watchdeck added it for its own sandbox", ours, r.Sentence)
	}
	o, _, ok := findRow(book, RowID(KindSandboxExcluded, claudesettings.ScopeUser, claudesettings.KeyExcluded, other))
	if !ok {
		t.Fatalf("no row for %q", other)
	}
	if o.Owner != OwnerUser {
		t.Errorf("%q: owner = %q, want %q", other, o.Owner, OwnerUser)
	}
	if o.Sentence != "Runs outside Claude Code's sandbox: "+other {
		t.Errorf("%q: sentence = %q", other, o.Sentence)
	}
}
