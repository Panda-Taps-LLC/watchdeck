package policy

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/Panda-Taps-LLC/watchdeck/internal/manifest"
)

// Shadow mode (Phase 6): mode: shadow in the user file.

func TestPolicyModeRenderRoundTrip(t *testing.T) {
	text := Render(File{Version: 2, Mode: manifest.ModeShadow})
	header, rest, _ := strings.Cut(text, "\n")
	if !strings.HasPrefix(header, "# ") || rest != "version: 2\nmode: shadow\n" {
		t.Fatalf("render:\n%s", text)
	}
	back, err := manifest.ParsePolicyFile([]byte(text))
	if err != nil || back.Mode != manifest.ModeShadow {
		t.Fatalf("parse back: %+v %v", back, err)
	}
	if Render(back) != text {
		t.Fatal("re-render differs")
	}
	if e := Render(File{Version: 2, Mode: manifest.ModeEnforce}); strings.Contains(e, "mode:") {
		t.Fatalf("enforce rendered a mode line:\n%s", e)
	}
	p := filepath.Join(t.TempDir(), "overrides.yaml")
	if _, err := Save(p, File{Version: 2, Mode: manifest.ModeShadow}); err != nil {
		t.Fatal(err)
	}
	if f, _, err := LoadFile(p); err != nil || f.Mode != manifest.ModeShadow {
		t.Fatalf("LoadFile after Save: %+v %v", f, err)
	}
}

func TestPolicyModeApply(t *testing.T) {
	var f File
	if ch, err := Apply(&f, Edit{SetMode: manifest.ModeShadow}); err != nil || !ch {
		t.Fatalf("shadow: changed=%v err=%v", ch, err)
	}
	if f.Version != 2 || f.Mode != manifest.ModeShadow {
		t.Fatalf("after shadow: %+v", f)
	}
	if ch, err := Apply(&f, Edit{SetMode: manifest.ModeShadow}); err != nil || ch {
		t.Fatalf("shadow again: changed=%v err=%v", ch, err)
	}
	if ch, err := Apply(&f, Edit{SetMode: manifest.ModeEnforce}); err != nil || !ch || f.Mode != "" {
		t.Fatalf("enforce: changed=%v err=%v mode=%q", ch, err, f.Mode)
	}
	if ch, err := Apply(&f, Edit{SetMode: manifest.ModeEnforce}); err != nil || ch {
		t.Fatalf("enforce again: changed=%v err=%v", ch, err)
	}
	before := Render(f)
	if ch, err := Apply(&f, Edit{SetMode: "x"}); err == nil || ch {
		t.Fatalf("bad mode: changed=%v err=%v", ch, err)
	}
	if Render(f) != before {
		t.Fatal("a refused mode changed the file")
	}
	if _, err := Apply(&f, Edit{}); err == nil || err.Error() != "edit: nothing to change" {
		t.Fatalf("empty edit: %v", err)
	}
}

// TestPolicyModeSurvivesApply pins the Clone trap: Apply starts from
// f.Clone(), so a Clone that dropped Mode would switch shadow mode off on
// every other edit.
func TestPolicyModeSurvivesApply(t *testing.T) {
	f := File{Version: 2, Mode: manifest.ModeShadow}
	if f.Clone().Mode != manifest.ModeShadow {
		t.Fatal("Clone dropped Mode")
	}
	r := manifest.PolicyRule{ID: "user-0000abcd", Tool: "Bash", Match: manifest.RuleMatch{Literals: []string{"MARKED"}}, Action: "deny"}
	for name, e := range map[string]Edit{
		"rule":  {PutRule: &r},
		"grant": {Kind: KindSkill, Name: "docx", Grant: manifest.Edit{Caches: ptr(true)}},
		"pack":  {Pack: "exfil", PackSetting: &manifest.Toggle{Action: "ask"}},
	} {
		if ch, err := Apply(&f, e); err != nil || !ch {
			t.Fatalf("%s: changed=%v err=%v", name, ch, err)
		}
		if f.Mode != manifest.ModeShadow {
			t.Fatalf("%s dropped mode", name)
		}
	}
}

func TestPolicyShadowOn(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "cfg", "overrides.yaml")
	if on, err := ShadowOn(p); on || err != nil {
		t.Fatalf("absent: %v %v", on, err)
	}
	writeFile(t, p, "version: 2\nmode: shadow\n")
	if on, err := ShadowOn(p); !on || err != nil {
		t.Fatalf("shadow: %v %v", on, err)
	}
	writeFile(t, p, "version: 2\npacks: {exfil: on}\n")
	if on, err := ShadowOn(p); on || err != nil {
		t.Fatalf("plain: %v %v", on, err)
	}
	writeFile(t, p, "version: 9\n")
	on, err := ShadowOn(p)
	if on || err == nil {
		t.Fatalf("invalid: %v %v", on, err)
	}
	if !strings.Contains(err.Error(), manifest.DisplayPath(p)) || strings.Contains(err.Error(), "version: 9") {
		t.Fatalf("invalid err %q", err)
	}
}

func TestPolicyShadowProjectWarns(t *testing.T) {
	want := Warning{Source: manifest.SourceProject, Field: "mode", Reason: "only the user file can set the mode"}
	hasWarn := func(ws []Warning) bool {
		for _, w := range ws {
			if w == want {
				return true
			}
		}
		return false
	}
	p, ws := New(Layer{}, Layer{Exists: true, File: File{Version: 2, Mode: manifest.ModeShadow}})
	if p.Shadow() || !hasWarn(ws) {
		t.Fatalf("project only: shadow=%v warnings=%v", p.Shadow(), ws)
	}
	p, ws = New(Layer{Exists: true, File: File{Version: 2, Mode: manifest.ModeShadow}}, Layer{Exists: true, File: File{Version: 2, Mode: manifest.ModeShadow}})
	if !p.Shadow() || !hasWarn(ws) {
		t.Fatalf("both: shadow=%v warnings=%v", p.Shadow(), ws)
	}
	if want.String() != "project policy ignored: mode (only the user file can set the mode)" {
		t.Fatalf("warning text %q", want.String())
	}
}
