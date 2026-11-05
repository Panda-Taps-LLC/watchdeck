package manifest

import (
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestParseOverrides(t *testing.T) {
	tests := []struct {
		name    string
		src     string
		wantErr string
		check   func(t *testing.T, o Overrides)
	}{
		{
			name: "contract example",
			src:  "version: 1\ndefaults:\n  auto_allow: false\nskills:\n  pdf:\n    network: all\n    write: [\"~/Library/Caches/pip\"]\n    caches: true\n    auto_allow: true\n",
			check: func(t *testing.T, o Overrides) {
				if o.Defaults.AutoAllow == nil || *o.Defaults.AutoAllow {
					t.Errorf("Defaults.AutoAllow = %v, want false", o.Defaults.AutoAllow)
				}
				pdf, ok := o.Skills["pdf"]
				if !ok {
					t.Fatalf("Skills = %v", o.Skills)
				}
				if pdf.Network == nil || *pdf.Network != NetAll {
					t.Errorf("pdf.Network = %v", pdf.Network)
				}
				if !reflect.DeepEqual(pdf.Write, []string{"~/Library/Caches/pip"}) || !pdf.Caches || pdf.AutoAllow == nil || !*pdf.AutoAllow {
					t.Errorf("pdf = %+v", pdf)
				}
			},
		},
		{name: "unknown field", src: "version: 1\nskills:\n  pdf:\n    netwrk: all\n", wantErr: `[4:5] unknown field`},
		{name: "unknown top-level", src: "version: 1\nskill:\n  pdf: {}\n", wantErr: `[2:1] unknown field`},
		{name: "version 9", src: "version: 9\n", wantErr: "version: must be 1 or 2 (got 9)"},
		{name: "missing version", src: "defaults:\n  caches: true\n", wantErr: "version: required"},
		{name: "bad network", src: "version: 1\ndefaults:\n  network: wifi\n", wantErr: "network: must be one of"},
		{name: "bad env", src: "version: 1\nskills:\n  pdf:\n    env: [\"api-key\"]\n", wantErr: `skills.pdf.env[0]: invalid name (must match ^[A-Z_][A-Z0-9_]*$)`},
		{name: "grant built-in deny", src: "version: 1\nskills:\n  pdf:\n    write: [\"~/.ssh\"]\n", wantErr: `skills.pdf.write[0]: cannot grant built-in deny path ~/.ssh`},
		{name: "grant under built-in deny", src: "version: 1\ndefaults:\n  read: [\"${HOME}/.aws/credentials\"]\n", wantErr: `cannot grant built-in deny path ~/.aws`},
		{name: "grant .env", src: "version: 1\ndefaults:\n  write: [\"${CWD}/.env\"]\n", wantErr: "cannot grant built-in deny pattern **/.env"},
		{
			name: "parent of a deny is allowed in overrides",
			src:  "version: 1\nskills:\n  pdf:\n    write: [\"~\"]\n",
			check: func(t *testing.T, o Overrides) {
				if !reflect.DeepEqual(o.Skills["pdf"].Write, []string{"~"}) {
					t.Errorf("pdf.Write = %q", o.Skills["pdf"].Write)
				}
			},
		},
		{
			name: "relative paths are rooted at ${CWD}",
			src:  "version: 1\ndefaults:\n  write: [\"build\", \"./out/\", \".\", \"./\"]\n  read: [\"data\"]\n",
			check: func(t *testing.T, o Overrides) {
				if want := []string{"${CWD}/build", "${CWD}/out/", "${CWD}", "${CWD}"}; !reflect.DeepEqual(o.Defaults.Write, want) {
					t.Errorf("Write = %q, want %q", o.Defaults.Write, want)
				}
				if want := []string{"${CWD}/data"}; !reflect.DeepEqual(o.Defaults.Read, want) {
					t.Errorf("Read = %q, want %q", o.Defaults.Read, want)
				}
			},
		},
		{name: "relative dotdot rejected", src: "version: 1\ndefaults:\n  write: [\"../x\"]\n", wantErr: "'..' segments are not allowed"},
		{name: "relative .env rejected", src: "version: 1\ndefaults:\n  write: [\".env\"]\n", wantErr: "cannot grant built-in deny pattern **/.env"},
		{
			name: "empty skill block",
			src:  "version: 1\nskills:\n  pdf:\n",
			check: func(t *testing.T, o Overrides) {
				if _, ok := o.Skills["pdf"]; !ok {
					t.Errorf("Skills = %v", o.Skills)
				}
			},
		},
		{
			name: "no blocks",
			src:  "version: 1\n",
			check: func(t *testing.T, o Overrides) {
				if o.Skills != nil || o.Defaults.Network != nil || o.Defaults.AutoAllow != nil {
					t.Errorf("o = %+v", o)
				}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			o, err := ParseOverrides([]byte(tc.src))
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("ParseOverrides = nil error, want %q", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %q, want substring %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseOverrides error: %v", err)
			}
			if tc.check != nil {
				tc.check(t, o)
			}
		})
	}
}

func TestWidenUser(t *testing.T) {
	base := Default()

	got, ignored := Widen(base, Override{Caches: true}, SourceUser)
	want := []string{"${CWD}", "${TMP}", "~/Library/Caches", "~/.cache", "~/.npm/_cacache"}
	if !reflect.DeepEqual(got.Write, want) {
		t.Errorf("caches Write = %q, want %q", got.Write, want)
	}
	if ignored != nil {
		t.Errorf("user override ignored = %q, want nothing", ignored)
	}
	if !reflect.DeepEqual(base.Write, []string{"${CWD}", "${TMP}"}) {
		t.Error("Widen mutated its input")
	}

	got = widen(got, Override{Write: []string{"${HOME}/.cache/", "~/Library/Caches/pip"}, Env: []string{"PATH", "API_KEY"}})
	want = append(want, "~/Library/Caches/pip")
	if !reflect.DeepEqual(got.Write, want) {
		t.Errorf("dedupe Write = %q, want %q", got.Write, want)
	}
	if wantEnv := []string{"PATH", "HOME", "LANG", "TMPDIR", "API_KEY"}; !reflect.DeepEqual(got.Env, wantEnv) {
		t.Errorf("Env = %q, want %q", got.Env, wantEnv)
	}

	// Network only goes up.
	got = widen(widen(base, Override{Network: netPtr(NetAll)}), Override{Network: netPtr(NetLocalhost)})
	if got.Network != NetAll {
		t.Errorf("Network = %s, want all (max)", got.Network)
	}

	// Read stays nil when unrestricted; appends when restricted.
	if got := widen(base, Override{Read: []string{"~/Documents"}}); got.Read != nil {
		t.Errorf("Read = %q, want nil", got.Read)
	}
	restricted := Default()
	restricted.Read = []string{"${CWD}"}
	if got := widen(restricted, Override{Read: []string{"~/Documents"}}); !reflect.DeepEqual(got.Read, []string{"${CWD}", "~/Documents"}) {
		t.Errorf("Read = %q", got.Read)
	}

	// AutoAllow is set only when given.
	if got := widen(widen(base, Override{AutoAllow: boolPtr(true)}), Override{}); !got.AutoAllow {
		t.Error("AutoAllow reset by an empty override")
	}
	if got := widen(widen(base, Override{AutoAllow: boolPtr(true)}), Override{AutoAllow: boolPtr(false)}); got.AutoAllow {
		t.Error("AutoAllow not overridden to false")
	}
}

func TestWidenProject(t *testing.T) {
	tests := []struct {
		name        string
		o           Override
		wantIgnored []string
		check       func(t *testing.T, eff Effective)
	}{
		{
			name:        "network all is ignored",
			o:           Override{Network: netPtr(NetAll)},
			wantIgnored: []string{"project override ignored: network: all (only the user override can grant this)"},
			check: func(t *testing.T, eff Effective) {
				if eff.Network != NetNone {
					t.Errorf("Network = %s, want none", eff.Network)
				}
			},
		},
		{
			name: "network localhost is kept",
			o:    Override{Network: netPtr(NetLocalhost)},
			check: func(t *testing.T, eff Effective) {
				if eff.Network != NetLocalhost {
					t.Errorf("Network = %s, want localhost", eff.Network)
				}
			},
		},
		{
			name: "write under cwd and tmp is kept",
			o:    Override{Write: []string{"${CWD}/build", "${TMP}/x/", "${CWD}"}},
			check: func(t *testing.T, eff Effective) {
				if want := []string{"${CWD}", "${TMP}", "${CWD}/build", "${TMP}/x"}; !reflect.DeepEqual(eff.Write, want) {
					t.Errorf("Write = %q, want %q", eff.Write, want)
				}
			},
		},
		{
			name:        "write outside cwd is ignored",
			o:           Override{Write: []string{"~/x", "/opt/data", "${HOME}/Library/Caches/pip", "${SKILL_DIR}/out", "~", "/"}},
			wantIgnored: []string{"project override ignored: write: ~/x (outside ${CWD})", "project override ignored: write: /opt/data (outside ${CWD})", "project override ignored: write: ~/Library/Caches/pip (outside ${CWD})", "project override ignored: write: ${SKILL_DIR}/out (outside ${CWD})", "project override ignored: write: ~ (outside ${CWD})", "project override ignored: write: / (outside ${CWD})"},
			check: func(t *testing.T, eff Effective) {
				if !reflect.DeepEqual(eff.Write, Default().Write) {
					t.Errorf("Write = %q, want default", eff.Write)
				}
			},
		},
		{
			name:        "read outside cwd is ignored, inside is a no-op on an unrestricted read",
			o:           Override{Read: []string{"~/Documents", "${CWD}/data"}},
			wantIgnored: []string{"project override ignored: read: ~/Documents (outside ${CWD})"},
			check: func(t *testing.T, eff Effective) {
				if eff.Read != nil {
					t.Errorf("Read = %q, want nil", eff.Read)
				}
			},
		},
		{
			name:        "caches is ignored",
			o:           Override{Caches: true},
			wantIgnored: []string{"project override ignored: caches"},
			check: func(t *testing.T, eff Effective) {
				if !reflect.DeepEqual(eff.Write, Default().Write) {
					t.Errorf("Write = %q, want default", eff.Write)
				}
			},
		},
		{
			name:        "env is ignored",
			o:           Override{Env: []string{"API_KEY", "TOKEN"}},
			wantIgnored: []string{"project override ignored: env: API_KEY", "project override ignored: env: TOKEN"},
			check: func(t *testing.T, eff Effective) {
				if !reflect.DeepEqual(eff.Env, Default().Env) {
					t.Errorf("Env = %q, want default", eff.Env)
				}
			},
		},
		{
			name:        "auto_allow is ignored",
			o:           Override{AutoAllow: boolPtr(true)},
			wantIgnored: []string{"project override ignored: auto_allow"},
			check: func(t *testing.T, eff Effective) {
				if eff.AutoAllow {
					t.Error("AutoAllow = true")
				}
			},
		},
		{
			name:        "everything at once, in field order",
			o:           Override{Network: netPtr(NetAll), Write: []string{"./build", "~/x"}, Caches: true, Env: []string{"API_KEY"}, AutoAllow: boolPtr(true)},
			wantIgnored: []string{"project override ignored: network: all (only the user override can grant this)", "project override ignored: write: ~/x (outside ${CWD})", "project override ignored: caches", "project override ignored: env: API_KEY", "project override ignored: auto_allow"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			eff, ignored := Widen(Default(), tc.o, SourceProject)
			if !reflect.DeepEqual(ignored, tc.wantIgnored) {
				t.Errorf("ignored = %q\n       want %q", ignored, tc.wantIgnored)
			}
			if tc.check != nil {
				tc.check(t, eff)
			}
		})
	}
}

func TestSourceString(t *testing.T) {
	if SourceProject.String() != "project" || SourceUser.String() != "user" {
		t.Errorf("Source strings: %s %s", SourceProject, SourceUser)
	}
}

// writeOverrides places a fixture at the path LoadOverrides expects.
func writeOverrides(t *testing.T, dir, name, src string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(fixture(name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestLoadOverrides(t *testing.T) {
	userDir, projDir := t.TempDir(), t.TempDir()

	// Missing files are empty, not errors.
	user, project, err := LoadOverrides(userDir, projDir)
	if err != nil {
		t.Fatalf("LoadOverrides with no files: %v", err)
	}
	if !reflect.DeepEqual(user, Overrides{}) || !reflect.DeepEqual(project, Overrides{}) {
		t.Errorf("want empty overrides, got %+v / %+v", user, project)
	}

	// Empty dir arguments are skipped.
	if _, _, err := LoadOverrides("", ""); err != nil {
		t.Fatalf("LoadOverrides(\"\", \"\"): %v", err)
	}

	writeOverrides(t, userDir, UserOverridesFile, readFixture(t, "overrides/user.yaml"))
	writeOverrides(t, projDir, ProjectOverridesFile, readFixture(t, "overrides/project.yaml"))
	user, project, err = LoadOverrides(userDir, projDir)
	if err != nil {
		t.Fatalf("LoadOverrides: %v", err)
	}
	if pdf := user.Skills["pdf"]; pdf.Network == nil || *pdf.Network != NetAll {
		t.Errorf("user pdf = %+v", pdf)
	}
	if project.Defaults.AutoAllow == nil || !*project.Defaults.AutoAllow {
		t.Errorf("project defaults = %+v", project.Defaults)
	}

	// A malformed file is an error naming the path.
	writeOverrides(t, projDir, ProjectOverridesFile, readFixture(t, "overrides/bad.yaml"))
	_, _, err = LoadOverrides(userDir, projDir)
	if err == nil {
		t.Fatal("LoadOverrides with a bad project file returned nil error")
	}
	if !strings.Contains(err.Error(), filepath.Join(projDir, ProjectOverridesFile)) || !strings.Contains(err.Error(), `unknown field`) {
		t.Errorf("error = %q", err)
	}
}

func TestGrantChain(t *testing.T) {
	user, err := ParseOverrides([]byte(readFixture(t, "overrides/user.yaml")))
	if err != nil {
		t.Fatal(err)
	}
	project, err := ParseOverrides([]byte(readFixture(t, "overrides/project.yaml")))
	if err != nil {
		t.Fatal(err)
	}
	const ignAuto = "project override ignored: auto_allow"

	// pdf: user grants network all and a cache path; project default auto_allow is ignored.
	pdf, ignored := Grant("pdf", user, project)
	if pdf.Network != NetAll {
		t.Errorf("Grant(pdf).Network = %s, want all", pdf.Network)
	}
	if want := []string{"${CWD}", "${TMP}", "~/Library/Caches/pip"}; !reflect.DeepEqual(pdf.Write, want) {
		t.Errorf("Grant(pdf).Write = %q, want %q", pdf.Write, want)
	}
	if pdf.AutoAllow {
		t.Error("Grant(pdf).AutoAllow = true, want false (user says false, project may not say true)")
	}
	if !reflect.DeepEqual(ignored, []string{ignAuto}) {
		t.Errorf("Grant(pdf) ignored = %q", ignored)
	}

	// xlsx: the user's pdf grant must not leak; project caches ignored, cwd/tmp writes kept.
	xlsx, ignored := Grant("xlsx", user, project)
	if xlsx.Network != NetNone {
		t.Errorf("Grant(xlsx).Network = %s, want none", xlsx.Network)
	}
	if want := []string{"${CWD}", "${TMP}", "${CWD}/build", "${TMP}/xlsx"}; !reflect.DeepEqual(xlsx.Write, want) {
		t.Errorf("Grant(xlsx).Write = %q, want %q", xlsx.Write, want)
	}
	if xlsx.AutoAllow {
		t.Error("Grant(xlsx).AutoAllow = true, want false (project auto_allow is ignored)")
	}
	if want := []string{ignAuto, "project override ignored: caches"}; !reflect.DeepEqual(ignored, want) {
		t.Errorf("Grant(xlsx) ignored = %q, want %q", ignored, want)
	}

	// csv: project may raise network to localhost.
	csv, ignored := Grant("csv", user, project)
	if csv.Network != NetLocalhost || !reflect.DeepEqual(csv.Write, Default().Write) {
		t.Errorf("Grant(csv) = network %s write %q", csv.Network, csv.Write)
	}
	if !reflect.DeepEqual(ignored, []string{ignAuto}) {
		t.Errorf("Grant(csv) ignored = %q", ignored)
	}

	// docx: project asks for all/~/x/env and is ignored; the user then grants all and auto_allow.
	docx, ignored := Grant("docx", user, project)
	if docx.Network != NetAll {
		t.Errorf("Grant(docx).Network = %s, want all from the user layer", docx.Network)
	}
	if !docx.AutoAllow {
		t.Error("Grant(docx).AutoAllow = false, want the user's true")
	}
	if !reflect.DeepEqual(docx.Write, Default().Write) || !reflect.DeepEqual(docx.Env, Default().Env) {
		t.Errorf("Grant(docx) write %q env %q, want defaults", docx.Write, docx.Env)
	}
	wantIgnored := []string{
		ignAuto,
		"project override ignored: network: all (only the user override can grant this)",
		"project override ignored: write: ~/x (outside ${CWD})",
		"project override ignored: env: API_KEY",
	}
	if !reflect.DeepEqual(ignored, wantIgnored) {
		t.Errorf("Grant(docx) ignored = %q\n              want %q", ignored, wantIgnored)
	}

	other, ignored := Grant("other", user, project)
	if other.Network != NetNone || other.AutoAllow || !reflect.DeepEqual(other.Write, Default().Write) {
		t.Errorf("Grant(other) = %+v", other)
	}
	if !reflect.DeepEqual(ignored, []string{ignAuto}) {
		t.Errorf("Grant(other) ignored = %q", ignored)
	}

	// No overrides at all is exactly Default() with nothing ignored.
	got, ignored := Grant("pdf", Overrides{}, Overrides{})
	if !reflect.DeepEqual(got, Default()) || ignored != nil {
		t.Errorf("Grant with no overrides = %+v, ignored %q", got, ignored)
	}
}

func TestGrantUserAutoAllowPrecedence(t *testing.T) {
	user, err := ParseOverrides([]byte("version: 1\ndefaults:\n  auto_allow: true\nskills:\n  pdf:\n    auto_allow: false\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := grant("xlsx", user, Overrides{}); !got.AutoAllow {
		t.Error("Grant(xlsx).AutoAllow = false, want user default true")
	}
	if got := grant("pdf", user, Overrides{}); got.AutoAllow {
		t.Error("Grant(pdf).AutoAllow = true, want per-skill false to win over the user default")
	}
}

func TestGrantStarSynonym(t *testing.T) {
	user, err := ParseOverrides([]byte("version: 1\nskills:\n  \"*\":\n    network: localhost\n    auto_allow: true\n  pdf:\n    auto_allow: false\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := grant("xlsx", user, Overrides{}); got.Network != NetLocalhost || !got.AutoAllow {
		t.Errorf("Grant(xlsx) = network %s auto %v", got.Network, got.AutoAllow)
	}
	if got := grant("pdf", user, Overrides{}); got.Network != NetLocalhost || got.AutoAllow {
		t.Errorf("Grant(pdf) = network %s auto %v, want per-skill false to win over *", got.Network, got.AutoAllow)
	}
}

func TestGrantThenClipEndToEnd(t *testing.T) {
	// The documented flow: request above grant → clipped, named, not fatal.
	req, err := Parse(fixture("request_wide.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	user, _ := ParseOverrides([]byte(readFixture(t, "overrides/user.yaml")))
	project, _ := ParseOverrides([]byte(readFixture(t, "overrides/project.yaml")))

	eff, ungranted := Clip(req, grant("pdf", user, project))
	if !reflect.DeepEqual(ungranted, []string{"env: API_KEY"}) {
		t.Errorf("pdf ungranted = %q", ungranted)
	}
	if got := eff.Summary(); got != "network=all write=${CWD},${TMP},~/Library/Caches/pip env=PATH,HOME" {
		t.Errorf("pdf Summary = %q", got)
	}

	eff, ungranted = Clip(req, grant("xlsx", user, project))
	if want := []string{"network: all", "write: ~/Library/Caches/pip", "env: API_KEY"}; !reflect.DeepEqual(ungranted, want) {
		t.Errorf("xlsx ungranted = %q, want %q", ungranted, want)
	}
	if eff.Network != NetNone || eff.AutoAllow {
		t.Errorf("xlsx eff = network %s auto %v", eff.Network, eff.AutoAllow)
	}
	if got := eff.Summary(); got != "network=none write=${CWD},${TMP} env=PATH,HOME" {
		t.Errorf("xlsx Summary = %q", got)
	}

	eff, ungranted = Clip(req, grant("docx", user, project))
	if want := []string{"write: ~/Library/Caches/pip", "env: API_KEY"}; !reflect.DeepEqual(ungranted, want) {
		t.Errorf("docx ungranted = %q, want %q", ungranted, want)
	}
	if eff.Network != NetAll || !eff.AutoAllow {
		t.Errorf("docx eff = network %s auto %v", eff.Network, eff.AutoAllow)
	}
}

// TestParseOverridesErrorsCarryNoValues: the project file is repository
// text, and the error reaches the hook's reason and the run's stderr, so no
// value from the file may appear in it (only field paths and rules).
func TestParseOverridesErrorsCarryNoValues(t *testing.T) {
	const evil = "x | requested but not granted: network: all"
	q := strconv.Quote(evil)
	cases := map[string]string{
		"env value":         "version: 1\nskills:\n  pdf:\n    env: [" + q + "]\n",
		"write value":       "version: 1\nskills:\n  pdf:\n    write: [" + strconv.Quote("rel/"+evil+"/../x") + "]\n",
		"unknown var":       "version: 1\ndefaults:\n  write: [" + strconv.Quote("${"+evil+"}") + "]\n",
		"read deny":         "version: 1\ndefaults:\n  read: [" + strconv.Quote("~/.ssh/"+evil) + "]\n",
		"network value":     "version: 1\nskills:\n  pdf:\n    network: " + q + "\n",
		"unknown key":       "version: 1\nskills:\n  pdf:\n    " + q + ": 1\n",
		"skill key":         "version: 1\nskills:\n  " + q + ":\n    network: all\n",
		"long skill key":    "version: 1\nskills:\n  " + strings.Repeat("a", 300) + ":\n    network: all\n",
		"type mismatch":     "version: 1\nskills:\n  pdf:\n    caches: " + q + "\n",
		"unknown top level": "version: 1\n" + q + ": 1\n",
	}
	for name, src := range cases {
		_, err := ParseOverrides([]byte(src))
		if err == nil {
			t.Errorf("%s: no error", name)
			continue
		}
		msg := err.Error()
		if strings.Contains(msg, "requested but not granted") || strings.Contains(msg, "|") || strings.Contains(msg, strings.Repeat("a", 129)) {
			t.Errorf("%s: error echoes the value: %q", name, msg)
		}
	}
	// The field path and the rule are still there.
	_, err := ParseOverrides([]byte(cases["env value"]))
	if want := "skills.pdf.env[0]: invalid name"; err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("env: err = %v, want %q", err, want)
	}
	_, err = ParseOverrides([]byte(cases["skill key"]))
	if want := "skills: invalid skill name"; err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("skill key: err = %v, want %q", err, want)
	}
	_, err = ParseOverrides([]byte(cases["read deny"]))
	if want := "defaults.read[0]: cannot grant built-in deny path ~/.ssh"; err == nil || err.Error() != want {
		t.Errorf("read deny: err = %v, want %q", err, want)
	}
}

// TestParseOverridesRefusesCaseVariantDeny: a hand-edited overrides file
// cannot grant a case variant of a built-in deny path or name (the same
// files on the default case-insensitive macOS filesystem); Apply refuses
// the same spellings. Look-alikes stay accepted.
func TestParseOverridesRefusesCaseVariantDeny(t *testing.T) {
	for _, c := range []struct{ path, want string }{
		{"~/.SSH", "defaults.write[0]: cannot grant built-in deny path ~/.ssh"},
		{"~/.Ssh/x", "defaults.write[0]: cannot grant built-in deny path ~/.ssh"},
		{"${HOME}/.AWS", "defaults.write[0]: cannot grant built-in deny path ~/.aws"},
		{"~/.Docker/Config.json", "defaults.write[0]: cannot grant built-in deny path ~/.docker/config.json"},
		{"${CWD}/.ENV", "defaults.write[0]: cannot grant built-in deny pattern **/.env"},
		{"./sub/.Env", "defaults.write[0]: cannot grant built-in deny pattern **/.env"},
		// Unicode simple folding (U+017F long s, U+212A Kelvin sign).
		{"~/.ſſh", "defaults.write[0]: cannot grant built-in deny path ~/.ssh"},
		{"~/.ſsh/x", "defaults.write[0]: cannot grant built-in deny path ~/.ssh"},
		{"~/.awſ", "defaults.write[0]: cannot grant built-in deny path ~/.aws"},
		{"~/.docKer/config.json", "defaults.write[0]: cannot grant built-in deny path ~/.docker/config.json"},
	} {
		_, err := ParseOverrides([]byte("version: 1\ndefaults:\n  write: [\"" + c.path + "\"]\n"))
		if err == nil || err.Error() != c.want {
			t.Errorf("%s: err = %v, want %q", c.path, err, c.want)
		}
	}
	for _, ok := range []string{"~/.sshx", "${CWD}/.envrc", "~/proj/.ENV-example"} {
		if _, err := ParseOverrides([]byte("version: 1\ndefaults:\n  write: [\"" + ok + "\"]\n")); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
}

func TestDisplayPath(t *testing.T) {
	long := "/" + strings.Repeat("a", 200)
	longUTF8 := "/" + strings.Repeat("é", 100) // 2 bytes each: the cut must not split a rune
	tests := []struct{ in, want string }{
		{"/opt/data", "/opt/data"},
		{"${CWD}/out", "${CWD}/out"},
		{"~/Library/Caches/pip", "~/Library/Caches/pip"},
		{"/x | requested but not granted: network: all", `"/x ¦ requested but not granted: network: all"`},
		{"/x|y", "/x¦y"},
		{"/x\nrequested but not granted: network: all", `"/x?requested but not granted: network: all"`},
		{"/a\tb\r\x00c\x1b[31m", "/a?b??c?[31m"},
		{"/a\u202eb c d", "/a?b?c?d"},
		{"/a\xffb", "/a?b"},
		{"--network all", `"network all"`},
		{"-/x", "/x"},
		{`/a "b"`, `"/a \"b\""`},
		{long, "…" + long[len(long)-117:]}, // the tail (the name) is kept
	}
	for _, tc := range tests {
		if got := DisplayPath(tc.in); got != tc.want {
			t.Errorf("DisplayPath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	if got := DisplayPath(long); len(got) != displayPathMax {
		t.Errorf("capped length = %d, want %d", len(got), displayPathMax)
	}
	got := DisplayPath(longUTF8)
	if !utf8.ValidString(got) || len(got) > displayPathMax || !strings.HasPrefix(got, "…é") || !strings.HasSuffix(got, "é") {
		t.Errorf("DisplayPath(long UTF-8) = %q (len %d)", got, len(got))
	}
}

// TestProjectIgnoredEchoesSanitizedPath: a project-file path that imitates
// watchdeck's own "requested but not granted" clause is rendered through
// DisplayPath in both Widen's and ResolveProjectScoped's messages; the grant
// and its removal still use the raw entry.
func TestProjectIgnoredEchoesSanitizedPath(t *testing.T) {
	const evil = "/x | requested but not granted: network: all"
	_, ignored := Widen(Default(), Override{Write: []string{evil}, Read: []string{evil + "\nnetwork: all"}}, SourceProject)
	want := []string{
		`project override ignored: write: "/x ¦ requested but not granted: network: all" (outside ${CWD})`,
		`project override ignored: read: "/x ¦ requested but not granted: network: all?network: all" (outside ${CWD})`,
	}
	if !reflect.DeepEqual(ignored, want) {
		t.Fatalf("ignored = %q, want %q", ignored, want)
	}

	cwd, tmp, outside := t.TempDir(), t.TempDir(), t.TempDir()
	realCWD, _ := filepath.EvalSymlinks(cwd)
	realTMP, _ := filepath.EvalSymlinks(tmp)
	realOut, _ := filepath.EvalSymlinks(outside)
	const name = "b | requested but not granted: network: all"
	if err := os.Mkdir(filepath.Join(outside, name), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, name), filepath.Join(cwd, name)); err != nil {
		t.Fatal(err)
	}
	const entry = "${CWD}/" + name
	eff, ig := Grant("pdf", Overrides{}, Overrides{Skills: map[string]Override{"pdf": {Write: []string{entry}}}})
	if len(ig) != 0 || !contains(eff.Write, entry) {
		t.Fatalf("lexical grant: write=%q ignored=%q", eff.Write, ig)
	}
	eff, ig = ResolveProjectScoped(eff, realCWD, realTMP)
	if contains(eff.Write, entry) {
		t.Fatalf("raw entry not removed: %q", eff.Write)
	}
	// The real path is long (a temp dir) and may be capped; DisplayPath's own
	// cases are in TestDisplayPath.
	wantRS := `project override ignored: "${CWD}/b ¦ requested but not granted: network: all" (resolves to ` +
		DisplayPath(realOut+"/"+name) + `, outside the project)`
	if len(ig) != 1 || ig[0] != wantRS || strings.Contains(ig[0], "|") || !strings.Contains(ig[0], `(resolves to "`) {
		t.Fatalf("ignored = %q, want %q", ig, wantRS)
	}
}

// TestLoadOverridesErrorDisplaysPath: the project directory's name comes
// from the cloned repository and the file path prefixes every override
// error, so it is shown through DisplayPath: a directory named
// "p | requested but not granted: network: all" cannot imitate a clause. An
// unreadable file's error does not repeat the raw path either.
func TestLoadOverridesErrorDisplaysPath(t *testing.T) {
	proj := filepath.Join(t.TempDir(), "p | requested but not granted: network: all")
	if err := os.Mkdir(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(proj, ProjectOverridesFile)
	if err := os.WriteFile(file, []byte("version: 9\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, err := LoadOverrides("", proj)
	if err == nil {
		t.Fatal("no error")
	}
	if want := DisplayPath(file) + ": version: must be 1 or 2 (got 9)"; err.Error() != want || strings.Contains(err.Error(), "|") {
		t.Fatalf("err = %q, want %q", err, want)
	}

	// A directory where the file should be: ReadFile fails with a *PathError.
	os.Remove(file)
	if err := os.Mkdir(file, 0o755); err != nil {
		t.Fatal(err)
	}
	_, _, err = LoadOverrides("", proj)
	if err == nil || strings.Contains(err.Error(), "|") || !strings.HasPrefix(err.Error(), DisplayPath(file)+": ") {
		t.Fatalf("read error = %v", err)
	}
}
