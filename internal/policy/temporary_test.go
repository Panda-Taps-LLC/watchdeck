package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/manifest"
)

// tempV2 is a full v2 file in Render's exact form with two temporaries.
const tempV2 = `# watchdeck policy file. Edited by ` + "`watchdeck allow`" + ` and the dashboard; hand edits are fine (comments are not kept).
version: 2
rules:
  - id: "no-prod-db"
    tool: "Bash"
    match:
      regex: "psql .*prod"
    action: deny
subjects:
  - kind: skill
    name: "canary"
    grant:
      write: ["/tmp/out"]
temporary:
  - id: "t-0a1b2c3d"
    kind: rule
    rule: "user/no-prod-db"
    session: "s1"
    until: "2026-10-24T18:00:00Z"
    added: "2026-10-24T10:00:00Z"
  - id: "t-4e5f6071"
    kind: grant
    skill: "canary"
    grant:
      network: all
      write: ["/tmp/more"]
    until: "2026-10-24T11:00:00Z"
    added: "2026-10-24T10:00:00Z"
`

func TestParseTemporaryRoundTrip(t *testing.T) {
	f, err := manifest.ParsePolicyFile([]byte(tempV2))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Temporary) != 2 {
		t.Fatalf("temporary %+v", f.Temporary)
	}
	r, g := f.Temporary[0], f.Temporary[1]
	if r.ID != "t-0a1b2c3d" || r.Kind != manifest.TempRule || r.Rule != "user/no-prod-db" || r.Session != "s1" ||
		!r.Until.Equal(time.Date(2026, 10, 24, 18, 0, 0, 0, time.UTC)) || !r.Added.Equal(time.Date(2026, 10, 24, 10, 0, 0, 0, time.UTC)) {
		t.Errorf("rule entry %+v", r)
	}
	if g.Kind != manifest.TempGrant || g.Skill != "canary" || g.Grant == nil || g.Grant.Network == nil || *g.Grant.Network != manifest.NetAll {
		t.Errorf("grant entry %+v", g)
	}
	text := Render(f)
	if text != tempV2 {
		t.Fatalf("render differs:\n%s\n---\n%s", text, tempV2)
	}
	back, err := manifest.ParsePolicyFile([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	if Render(back) != text {
		t.Fatal("render not stable")
	}
	// Clone is deep: changing the clone's grant leaves the original.
	c := f.Clone()
	c.Temporary[1].Grant.Write[0] = "/elsewhere"
	if f.Temporary[1].Grant.Write[0] != "/tmp/more" {
		t.Fatal("Clone shares the grant")
	}
	// A file with an offset and fractions renders canonically (UTC, seconds).
	off := strings.Replace(tempV2, `until: "2026-10-24T18:00:00Z"`, `until: "2026-10-24T20:00:00.5+02:00"`, 1)
	of, err := manifest.ParsePolicyFile([]byte(off))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(Render(of), `until: "2026-10-24T18:00:00Z"`) {
		t.Errorf("not canonical:\n%s", Render(of))
	}
}

func TestNewAtDropsExpired(t *testing.T) {
	f, err := manifest.ParsePolicyFile([]byte(tempV2))
	if err != nil {
		t.Fatal(err)
	}
	at := func(h, m int) time.Time { return time.Date(2026, 10, 24, h, m, 0, 0, time.UTC) }
	p, _ := NewAt(at(10, 30), Layer{File: f, Exists: true}, Layer{})
	if n := len(p.Temporaries()); n != 2 {
		t.Fatalf("at 10:30: %d temporaries", n)
	}
	if eff, _ := p.SkillGrant("canary"); eff.Network != manifest.NetAll {
		t.Errorf("at 10:30 the timed grant is missing: %v", eff.Network)
	}
	// until is exclusive: at 11:00 the grant has ended.
	p, _ = NewAt(at(11, 0), Layer{File: f, Exists: true}, Layer{})
	ts := p.Temporaries()
	if len(ts) != 1 || ts[0].ID != "t-0a1b2c3d" {
		t.Fatalf("at 11:00: %+v", ts)
	}
	if eff, _ := p.SkillGrant("canary"); eff.Network != manifest.NetNone {
		t.Errorf("at 11:00 the grant still widens: %v", eff.Network)
	}
	p, _ = NewAt(at(18, 0), Layer{File: f, Exists: true}, Layer{})
	if len(p.Temporaries()) != 0 {
		t.Fatalf("at 18:00: %+v", p.Temporaries())
	}
	// A project layer's temporaries never apply (and New warns).
	pp, warns := NewAt(at(10, 30), Layer{}, Layer{File: f, Exists: true})
	if len(pp.Temporaries()) != 0 {
		t.Fatalf("project temporaries applied: %+v", pp.Temporaries())
	}
	if eff, _ := pp.SkillGrant("canary"); eff.Network != manifest.NetNone {
		t.Errorf("project timed grant applied: %v", eff.Network)
	}
	found := false
	for _, w := range warns {
		if w.Field == "temporary" {
			found = true
		}
	}
	if !found {
		t.Errorf("no warning for project temporaries: %+v", warns)
	}
	// The project file loader refuses the file outright.
	dir := t.TempDir()
	proj := filepath.Join(dir, manifest.ProjectOverridesFile)
	writeFile(t, proj, tempV2)
	if _, _, err := LoadProjectFile(proj); err == nil || !strings.Contains(err.Error(), "temporary: not allowed in a project file") {
		t.Fatalf("LoadProjectFile: %v", err)
	}
}

func TestPausedMatchesSessionOrAny(t *testing.T) {
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	f := File{Version: 2, Temporary: []manifest.Temporary{
		{ID: "t-00000001", Kind: manifest.TempRule, Rule: "exfil/curl-data-file", Added: now.Add(-time.Hour), Until: now.Add(time.Hour)},
		{ID: "t-00000002", Kind: manifest.TempRule, Rule: "user/no-prod-db", Session: "s1", Added: now.Add(-time.Hour), Until: now.Add(7 * time.Hour)},
		{ID: "t-00000003", Kind: manifest.TempRule, Rule: "secrets-read/env-file", Added: now.Add(-2 * time.Hour), Until: now.Add(-time.Hour)},
	}}
	p, _ := NewAt(now, Layer{File: f, Exists: true}, Layer{})
	cases := []struct {
		pack, id, session string
		want              string
	}{
		{"exfil", "curl-data-file", "s1", "t-00000001"},
		{"exfil", "curl-data-file", "", "t-00000001"},
		{"user", "no-prod-db", "s1", "t-00000002"},
		{"user", "no-prod-db", "s2", ""},
		{"user", "no-prod-db", "", ""},
		{"secrets-read", "env-file", "s1", ""}, // expired
		{"exfil", "other", "s1", ""},
	}
	for _, c := range cases {
		id, ok := p.Paused(c.pack, c.id, c.session)
		if ok != (c.want != "") || id != c.want {
			t.Errorf("Paused(%s, %s, %q) = %q %v, want %q", c.pack, c.id, c.session, id, ok, c.want)
		}
	}
	// A grant temporary is not a pause.
	g := File{Version: 2, Temporary: []manifest.Temporary{{ID: "t-00000004", Kind: manifest.TempGrant, Skill: "canary",
		Grant: &manifest.Override{Caches: true}, Added: now.Add(-time.Hour), Until: now.Add(time.Hour)}}}
	pg, _ := NewAt(now, Layer{File: g, Exists: true}, Layer{})
	if _, ok := pg.Paused("canary", "", ""); ok {
		t.Error("grant matched as a pause")
	}
}

// TestPolicyCacheVersionIsThree: a version 2 cache doc (an older binary,
// which held "unknown field temporary" for a file with temporaries) is
// never read: the file is parsed again and the cache rewritten at 3.
func TestPolicyCacheVersionIsThree(t *testing.T) {
	if CacheVersion != 3 {
		t.Fatalf("CacheVersion %d", CacheVersion)
	}
	dir := t.TempDir()
	up := filepath.Join(dir, "cfg", "overrides.yaml")
	writeFile(t, up, "version: 2\ntemporary:\n  - {id: \"t-00000001\", kind: rule, rule: \"exfil/x\", until: \"2999-01-01T00:00:00Z\", added: \"2026-10-24T10:00:00Z\"}\n")
	cache := filepath.Join(dir, "state", CacheFile)
	doc := cacheDoc{V: 2, User: keyOf(up), Project: keyOf(""), UserErr: "invalid overrides: unknown field"}
	writeCache(cache, doc)
	l := LoadCached(cache, up, "")
	if !l.Rebuilt || l.UserErr != nil {
		t.Fatalf("loaded: rebuilt=%v err=%v", l.Rebuilt, l.UserErr)
	}
	if _, ok := l.Policy.Paused("exfil", "x", "any"); !ok {
		t.Fatal("pause not in force")
	}
	got, err := os.ReadFile(cache)
	if err != nil || !strings.Contains(string(got), `"v":3`) || strings.Contains(string(got), "user_err") {
		t.Fatalf("cache after: %s %v", got, err)
	}
	// A cache hit re-applies the clock: the cached file still holds the
	// pause, and NewAt runs on every load.
	l2 := LoadCached(cache, up, "")
	if l2.Rebuilt {
		t.Fatal("second load rebuilt")
	}
	if _, ok := l2.Policy.Paused("exfil", "x", "any"); !ok {
		t.Fatal("pause lost on a cache hit")
	}
	if same, ok := CacheMatchesFresh(cache, up, ""); !ok || !same {
		t.Fatalf("CacheMatchesFresh = %v %v", same, ok)
	}
}

func TestSavePrunesExpiredTemporaries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "overrides.yaml")
	now := time.Now().UTC().Truncate(time.Second)
	// written as bytes: Save would already prune
	writeFile(t, path, "version: 2\ntemporary:\n"+
		"  - {id: \"t-00000001\", kind: rule, rule: \"exfil/x\", until: \""+now.Add(-time.Minute).Format(time.RFC3339)+"\", added: \""+now.Add(-time.Hour).Format(time.RFC3339)+"\"}\n"+
		"  - {id: \"t-00000002\", kind: rule, rule: \"exfil/y\", until: \""+now.Add(time.Hour).Format(time.RFC3339)+"\", added: \""+now.Add(-time.Hour).Format(time.RFC3339)+"\"}\n")
	f, _, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Temporary) != 2 {
		t.Fatalf("loaded %+v", f.Temporary)
	}
	changed, err := Apply(&f, Edit{SetMode: manifest.ModeShadow})
	if err != nil || !changed {
		t.Fatalf("apply %v %v", changed, err)
	}
	if _, err := Save(path, f); err != nil {
		t.Fatal(err)
	}
	if len(f.Temporary) != 2 {
		t.Fatal("Save changed the caller's file")
	}
	back, _, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(back.Temporary) != 1 || back.Temporary[0].ID != "t-00000002" {
		t.Fatalf("after save %+v", back.Temporary)
	}
}

func TestApplyAddAndEndTemporary(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	f := File{Version: 2}
	tmp := manifest.Temporary{Kind: manifest.TempRule, Rule: "exfil/curl-data-file", Added: now, Until: now.Add(time.Hour)}
	changed, err := Apply(&f, Edit{AddTemporary: &tmp})
	if err != nil || !changed {
		t.Fatalf("add %v %v", changed, err)
	}
	if len(f.Temporary) != 1 || !manifest.ValidTemporaryID(f.Temporary[0].ID) || f.Temporary[0].ID != manifest.TemporaryID(tmp) {
		t.Fatalf("added %+v", f.Temporary)
	}
	id := f.Temporary[0].ID
	// the same entry again is no change
	if changed, err := Apply(&f, Edit{AddTemporary: &tmp}); err != nil || changed {
		t.Fatalf("re-add %v %v", changed, err)
	}
	// an auto_allow grant is refused by the round-trip check
	yes := true
	bad := manifest.Temporary{Kind: manifest.TempGrant, Skill: "canary", Grant: &manifest.Override{AutoAllow: &yes}, Added: now, Until: now.Add(time.Hour)}
	if _, err := Apply(&f, Edit{AddTemporary: &bad}); err == nil || !strings.Contains(err.Error(), "auto_allow") {
		t.Fatalf("auto_allow grant: %v", err)
	}
	if changed, err := Apply(&f, Edit{EndTemporary: "t-ffffffff"}); err != nil || changed {
		t.Fatalf("end unknown %v %v", changed, err)
	}
	if changed, err := Apply(&f, Edit{EndTemporary: id}); err != nil || !changed || len(f.Temporary) != 0 {
		t.Fatalf("end %v %v %+v", changed, err, f.Temporary)
	}
}

// TestApplySkillKeepsTemporaryOutOfGrant: a skill edit (watchdeck allow,
// the dashboard) never writes a timed grant into the permanent one.
func TestApplySkillKeepsTemporaryOutOfGrant(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	all := manifest.NetAll
	f := File{Version: 2, Subjects: []manifest.PolicySubject{{Kind: KindSkill, Name: "canary", Grant: &manifest.Override{Write: []string{"/tmp/out"}}}},
		Temporary: []manifest.Temporary{{ID: "t-00000001", Kind: manifest.TempGrant, Skill: "canary", Grant: &manifest.Override{Network: &all},
			Added: now, Until: now.Add(time.Hour)}}}
	changed, err := Apply(&f, Edit{Kind: KindSkill, Name: "canary", Grant: manifest.Edit{AddWrite: []string{"/tmp/also"}}})
	if err != nil || !changed {
		t.Fatalf("apply %v %v", changed, err)
	}
	g := f.Subjects[0].Grant
	if g.Network != nil {
		t.Fatalf("timed network written into the permanent grant: %+v", g)
	}
	if len(g.Write) != 2 || len(f.Temporary) != 1 {
		t.Fatalf("grant %+v temporary %+v", g, f.Temporary)
	}
}
