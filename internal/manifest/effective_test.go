package manifest

import (
	"reflect"
	"testing"
)

func mustParse(t *testing.T, src string) Manifest {
	t.Helper()
	m, err := ParseBytes([]byte(src))
	if err != nil {
		t.Fatalf("ParseBytes: %v\n%s", err, src)
	}
	return m
}

func TestDefault(t *testing.T) {
	d := Default()
	if !reflect.DeepEqual(d.Scripts, []string{"scripts/**"}) {
		t.Errorf("Scripts = %q", d.Scripts)
	}
	if d.Read != nil {
		t.Errorf("Read = %q, want nil (everything except deny)", d.Read)
	}
	if !reflect.DeepEqual(d.Write, []string{"${CWD}", "${TMP}"}) {
		t.Errorf("Write = %q", d.Write)
	}
	wantDeny := []string{"~/.ssh", "~/.aws", "~/.gnupg", "~/.claude", "~/.config/gcloud", "~/.netrc", "~/.docker/config.json"}
	if !reflect.DeepEqual(d.Deny, wantDeny) {
		t.Errorf("Deny = %q, want %q", d.Deny, wantDeny)
	}
	if !reflect.DeepEqual(d.DenyPatterns, []string{"**/.env"}) {
		t.Errorf("DenyPatterns = %q", d.DenyPatterns)
	}
	if d.Network != NetNone || !d.ExecAny || d.Exec != nil || d.AutoAllow {
		t.Errorf("unexpected defaults: %+v", d)
	}
	if !reflect.DeepEqual(d.Env, []string{"PATH", "HOME", "LANG", "TMPDIR"}) {
		t.Errorf("Env = %q", d.Env)
	}

	// Each call returns fresh slices.
	d.Write[0] = "mutated"
	if Default().Write[0] != "${CWD}" {
		t.Error("Default() shares slices between calls")
	}
}

func TestSummaryGolden(t *testing.T) {
	tests := []struct {
		name string
		eff  Effective
		want string
	}{
		{"default", Default(), "network=none write=${CWD},${TMP} env=PATH,HOME,LANG,TMPDIR"},
		{"widened", widenU(Default(), Override{Network: netPtr(NetAll), Caches: true, Env: []string{"API_KEY"}}),
			"network=all write=${CWD},${TMP},~/Library/Caches,~/.cache,~/.npm/_cacache env=PATH,HOME,LANG,TMPDIR,API_KEY"},
		{"exec list", Effective{Network: NetLocalhost, Write: []string{"${CWD}"}, Env: []string{"PATH"}, Exec: []string{"/usr/bin/python3", "/usr/bin/qpdf"}},
			"network=localhost write=${CWD} env=PATH exec=/usr/bin/python3,/usr/bin/qpdf"},
		{"empty lists", Effective{Exec: []string{}}, "network=none write=- env=- exec=-"},
		// Paths are display text: a project write path under ${CWD} cannot
		// imitate a clause; the Effective keeps the raw values.
		{"paths through DisplayPath", Effective{Write: []string{"${CWD}", "${CWD}/x | requested but not granted: network: all", "${CWD}/a\nb"}, Env: []string{"PATH"}, Exec: []string{"/usr/bin/a|b"}},
			`network=none write=${CWD},"${CWD}/x ¦ requested but not granted: network: all",${CWD}/a?b env=PATH exec=/usr/bin/a¦b`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.eff.Summary(); got != tc.want {
				t.Errorf("Summary() = %q\n                want %q", got, tc.want)
			}
		})
	}
}

func netPtr(n Network) *Network { return &n }
func boolPtr(b bool) *bool      { return &b }

// widen applies a trusted (user) override and drops the ignored list.
func widen(base Effective, o Override) Effective {
	eff, _ := Widen(base, o, SourceUser)
	return eff
}

// grant resolves the grant and drops the ignored list.
func grant(skill string, user, project Overrides) Effective {
	eff, _ := Grant(skill, user, project)
	return eff
}

func TestClip(t *testing.T) {
	cachesGrant := widenU(Default(), Override{Caches: true})
	execListGrant := Default()
	execListGrant.ExecAny = false
	execListGrant.Exec = []string{"/usr/bin/python3", "/usr/bin/node"}
	extraDenyGrant := Default()
	extraDenyGrant.Deny = append(extraDenyGrant.Deny, "~/Secrets")
	autoGrant := Default()
	autoGrant.AutoAllow = true

	tests := []struct {
		name          string
		request       string
		grant         Effective
		wantUngranted []string
		check         func(t *testing.T, eff Effective)
	}{
		{
			name:          "network all against default",
			request:       "version: 1\nnetwork: all\n",
			grant:         Default(),
			wantUngranted: []string{"network: all"},
			check: func(t *testing.T, eff Effective) {
				if eff.Network != NetNone {
					t.Errorf("Network = %s, want none", eff.Network)
				}
			},
		},
		{
			name:    "network localhost within an all grant",
			request: "version: 1\nnetwork: localhost\n",
			grant:   widenU(Default(), Override{Network: netPtr(NetAll)}),
			check: func(t *testing.T, eff Effective) {
				if eff.Network != NetLocalhost {
					t.Errorf("Network = %s, want localhost", eff.Network)
				}
			},
		},
		{
			name:          "write cache dir against default",
			request:       "version: 1\nfilesystem:\n  write: [\"${CWD}\", \"${TMP}\", \"~/Library/Caches/pip\"]\n",
			grant:         Default(),
			wantUngranted: []string{"write: ~/Library/Caches/pip"},
			check: func(t *testing.T, eff Effective) {
				if want := []string{"${CWD}", "${TMP}"}; !reflect.DeepEqual(eff.Write, want) {
					t.Errorf("Write = %q, want %q", eff.Write, want)
				}
			},
		},
		{
			name:    "write cache dir against caches grant",
			request: "version: 1\nfilesystem:\n  write: [\"${CWD}\", \"${HOME}/Library/Caches/pip/\"]\n",
			grant:   cachesGrant,
			check: func(t *testing.T, eff Effective) {
				if want := []string{"${CWD}", "~/Library/Caches/pip"}; !reflect.DeepEqual(eff.Write, want) {
					t.Errorf("Write = %q, want %q", eff.Write, want)
				}
			},
		},
		{
			name:    "write subpath of grant is kept",
			request: "version: 1\nfilesystem:\n  write: [\"${CWD}/out/\"]\n",
			grant:   Default(),
			check: func(t *testing.T, eff Effective) {
				if want := []string{"${CWD}/out"}; !reflect.DeepEqual(eff.Write, want) {
					t.Errorf("Write = %q, want %q", eff.Write, want)
				}
			},
		},
		{
			name:          "write nothing granted leaves an empty list",
			request:       "version: 1\nfilesystem:\n  write: [\"/opt/data\"]\n",
			grant:         Default(),
			wantUngranted: []string{"write: /opt/data"},
			check: func(t *testing.T, eff Effective) {
				if eff.Write == nil || len(eff.Write) != 0 {
					t.Errorf("Write = %#v, want empty non-nil", eff.Write)
				}
			},
		},
		{
			name:    "omitted fields inherit the grant",
			request: "version: 1\n",
			grant:   cachesGrant,
			check: func(t *testing.T, eff Effective) {
				if !reflect.DeepEqual(eff.Write, cachesGrant.Write) || !reflect.DeepEqual(eff.Env, cachesGrant.Env) || !reflect.DeepEqual(eff.Scripts, cachesGrant.Scripts) || eff.Read != nil || !eff.ExecAny {
					t.Errorf("eff = %+v, want grant %+v", eff, cachesGrant)
				}
			},
		},
		{
			name:          "env extra name",
			request:       "version: 1\nenv: [\"PATH\", \"HOME\", \"API_KEY\"]\n",
			grant:         Default(),
			wantUngranted: []string{"env: API_KEY"},
			check: func(t *testing.T, eff Effective) {
				if want := []string{"PATH", "HOME"}; !reflect.DeepEqual(eff.Env, want) {
					t.Errorf("Env = %q, want %q", eff.Env, want)
				}
			},
		},
		{
			name:    "env granted by override",
			request: "version: 1\nenv: [\"PATH\", \"API_KEY\"]\n",
			grant:   widenU(Default(), Override{Env: []string{"API_KEY"}}),
			check: func(t *testing.T, eff Effective) {
				if want := []string{"PATH", "API_KEY"}; !reflect.DeepEqual(eff.Env, want) {
					t.Errorf("Env = %q, want %q", eff.Env, want)
				}
			},
		},
		{
			name:    "exec list narrows an any grant",
			request: "version: 1\nexec: [\"/usr/bin/python3\", \"/usr/bin/qpdf\"]\n",
			grant:   Default(),
			check: func(t *testing.T, eff Effective) {
				if eff.ExecAny {
					t.Error("ExecAny = true")
				}
				if want := []string{"/usr/bin/python3", "/usr/bin/qpdf"}; !reflect.DeepEqual(eff.Exec, want) {
					t.Errorf("Exec = %q, want %q", eff.Exec, want)
				}
			},
		},
		{
			name:          "exec list against list is the intersection",
			request:       "version: 1\nexec: [\"/usr/bin/python3\", \"/usr/bin/qpdf\"]\n",
			grant:         execListGrant,
			wantUngranted: []string{"exec: /usr/bin/qpdf"},
			check: func(t *testing.T, eff Effective) {
				if eff.ExecAny || !reflect.DeepEqual(eff.Exec, []string{"/usr/bin/python3"}) {
					t.Errorf("ExecAny=%v Exec=%q", eff.ExecAny, eff.Exec)
				}
			},
		},
		{
			name:    "exec any against list takes the grant list",
			request: "version: 1\nexec: any\n",
			grant:   execListGrant,
			check: func(t *testing.T, eff Effective) {
				if eff.ExecAny || !reflect.DeepEqual(eff.Exec, execListGrant.Exec) {
					t.Errorf("ExecAny=%v Exec=%q", eff.ExecAny, eff.Exec)
				}
			},
		},
		{
			name:          "read under an extra deny",
			request:       "version: 1\nfilesystem:\n  read: [\"${CWD}\", \"~/Secrets/db\"]\n",
			grant:         extraDenyGrant,
			wantUngranted: []string{"read: ~/Secrets/db"},
			check: func(t *testing.T, eff Effective) {
				if !reflect.DeepEqual(eff.Read, []string{"${CWD}"}) {
					t.Errorf("Read = %q", eff.Read)
				}
			},
		},
		{
			name:    "request deny entries are added",
			request: "version: 1\nfilesystem:\n  deny: [\"~/.ssh\", \"~/.aws\", \"~/.gnupg\", \"~/.claude\", \"~/.config/gcloud\", \"~/.netrc\", \"~/.docker/config.json\", \"**/.env\", \"~/Secrets/\", \"**/*.pem\"]\n",
			grant:   Default(),
			check: func(t *testing.T, eff Effective) {
				if !contains(eff.Deny, "~/Secrets") || len(eff.Deny) != len(Default().Deny)+1 {
					t.Errorf("Deny = %q", eff.Deny)
				}
				if !reflect.DeepEqual(eff.DenyPatterns, []string{"**/.env", "**/*.pem"}) {
					t.Errorf("DenyPatterns = %q", eff.DenyPatterns)
				}
			},
		},
		{
			name:    "scripts come from the request",
			request: "version: 1\nscripts: [\"scripts/**\", \"bin/*.sh\"]\n",
			grant:   Default(),
			check: func(t *testing.T, eff Effective) {
				if !reflect.DeepEqual(eff.Scripts, []string{"scripts/**", "bin/*.sh"}) {
					t.Errorf("Scripts = %q", eff.Scripts)
				}
			},
		},
		{
			name:          "several ungranted items in field order",
			request:       "version: 1\nfilesystem:\n  write: [\"${CWD}\", \"${TMP}\", \"~/Library/Caches/pip\"]\nnetwork: all\nenv: [\"PATH\", \"HOME\", \"API_KEY\"]\n",
			grant:         Default(),
			wantUngranted: []string{"network: all", "write: ~/Library/Caches/pip", "env: API_KEY"},
		},
		{
			name:    "auto_allow comes from the grant",
			request: "version: 1\n",
			grant:   autoGrant,
			check: func(t *testing.T, eff Effective) {
				if !eff.AutoAllow {
					t.Error("AutoAllow = false")
				}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			eff, ungranted := Clip(mustParse(t, tc.request), tc.grant)
			if !reflect.DeepEqual(ungranted, tc.wantUngranted) {
				t.Errorf("ungranted = %q, want %q", ungranted, tc.wantUngranted)
			}
			if tc.check != nil {
				tc.check(t, eff)
			}
		})
	}
}

func TestClipFixtureAgainstDefault(t *testing.T) {
	req, err := Parse(fixture("request_wide.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	eff, ungranted := Clip(req, Default())
	want := []string{"network: all", "write: ~/Library/Caches/pip", "env: API_KEY"}
	if !reflect.DeepEqual(ungranted, want) {
		t.Errorf("ungranted = %q, want %q", ungranted, want)
	}
	if got := eff.Summary(); got != "network=none write=${CWD},${TMP} env=PATH,HOME" {
		t.Errorf("Summary = %q", got)
	}

	// The same request under a grant that covers it reports nothing.
	wide := widenU(Default(), Override{Network: netPtr(NetAll), Caches: true, Env: []string{"API_KEY"}})
	eff, ungranted = Clip(req, wide)
	if len(ungranted) != 0 {
		t.Errorf("ungranted = %q, want none", ungranted)
	}
	if got := eff.Summary(); got != "network=all write=${CWD},${TMP},~/Library/Caches/pip env=PATH,HOME,API_KEY" {
		t.Errorf("Summary = %q", got)
	}
}

func TestClipDoesNotAliasGrant(t *testing.T) {
	grant := Default()
	eff, _ := Clip(mustParse(t, "version: 1\nfilesystem:\n  deny: [\"~/.ssh\", \"~/.aws\", \"~/.gnupg\", \"~/.claude\", \"~/.config/gcloud\", \"~/.netrc\", \"~/.docker/config.json\", \"**/.env\", \"~/Secrets\"]\n"), grant)
	if len(eff.Deny) == len(grant.Deny) {
		t.Fatal("deny not added")
	}
	if contains(grant.Deny, "~/Secrets") {
		t.Error("Clip mutated the grant's Deny slice")
	}
}

func TestIntersect(t *testing.T) {
	a := widenU(Default(), Override{Network: netPtr(NetAll), Caches: true, Env: []string{"API_KEY"}})
	a.AutoAllow = true
	b := widenU(Default(), Override{Network: netPtr(NetLocalhost), Write: []string{"~/.cache", "${CWD}/out"}, Env: []string{"TOKEN"}})
	b.AutoAllow = true

	got := Intersect(a, b)
	if got.Network != NetLocalhost {
		t.Errorf("Network = %s, want localhost (min)", got.Network)
	}
	if want := []string{"${CWD}", "${TMP}", "~/.cache", "${CWD}/out"}; !reflect.DeepEqual(got.Write, want) {
		t.Errorf("Write = %q, want %q", got.Write, want)
	}
	if want := []string{"PATH", "HOME", "LANG", "TMPDIR"}; !reflect.DeepEqual(got.Env, want) {
		t.Errorf("Env = %q, want %q", got.Env, want)
	}
	if !got.ExecAny {
		t.Error("ExecAny = false, want true when both are any")
	}
	if got.Read != nil {
		t.Errorf("Read = %q, want nil (both unrestricted)", got.Read)
	}
	if !reflect.DeepEqual(got.Deny, Default().Deny) || !reflect.DeepEqual(got.DenyPatterns, Default().DenyPatterns) {
		t.Errorf("Deny = %q / %q", got.Deny, got.DenyPatterns)
	}
	if !got.AutoAllow {
		t.Error("AutoAllow = false, want true when both allow")
	}

	// Exec: any ∩ list = list; list ∩ list = common entries.
	c := Default()
	c.ExecAny, c.Exec = false, []string{"/usr/bin/python3", "/usr/bin/qpdf"}
	if got := Intersect(a, c); got.ExecAny || !reflect.DeepEqual(got.Exec, c.Exec) {
		t.Errorf("any ∩ list: ExecAny=%v Exec=%q", got.ExecAny, got.Exec)
	}
	d := Default()
	d.ExecAny, d.Exec = false, []string{"/usr/bin/qpdf", "/usr/bin/node"}
	if got := Intersect(c, d); got.ExecAny || !reflect.DeepEqual(got.Exec, []string{"/usr/bin/qpdf"}) {
		t.Errorf("list ∩ list: ExecAny=%v Exec=%q", got.ExecAny, got.Exec)
	}
	e := Default()
	e.ExecAny, e.Exec = false, []string{"/usr/bin/node"}
	if got := Intersect(c, e); got.ExecAny || got.Exec == nil || len(got.Exec) != 0 {
		t.Errorf("disjoint lists: ExecAny=%v Exec=%#v, want empty", got.ExecAny, got.Exec)
	}

	// Read: nil is the identity; two lists intersect by subpath.
	r1, r2 := Default(), Default()
	r1.Read = []string{"${CWD}", "~/Documents"}
	r2.Read = []string{"~/Documents/reports", "/opt"}
	if got := Intersect(r1, r2); !reflect.DeepEqual(got.Read, []string{"~/Documents/reports"}) {
		t.Errorf("Read = %q", got.Read)
	}
	if got := Intersect(r1, Default()); !reflect.DeepEqual(got.Read, r1.Read) {
		t.Errorf("Read with nil identity = %q", got.Read)
	}

	// AutoAllow needs both.
	if got := Intersect(a, Default()); got.AutoAllow {
		t.Error("AutoAllow = true with one side false")
	}
}
