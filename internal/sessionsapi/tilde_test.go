package sessionsapi

import "testing"

func TestTildeAtPathBoundary(t *testing.T) {
	for in, want := range map[string]string{
		"/Users/a":                    "~",
		"/Users/a/x and /Users/a":     "~/x and ~",
		"/Users/ab/x":                 "/Users/ab/x",
		"cd /Users/ab; ls /Users/a/k": "cd /Users/ab; ls ~/k",
		"/Users/a.bak":                "/Users/a.bak",
		"no path":                     "no path",
		"cd /Users/a && ls":           "cd ~ && ls",
		`"/Users/a"`:                  `"~"`,
		"(/Users/a)":                  "(~)",
		"/Users/a:":                   "~:",
		"/Users/a\tx":                 "~\tx",
		"/Users/a_old /Users/a-1":     "/Users/a_old /Users/a-1",
	} {
		if got := tildeAt(in, "/Users/a"); got != want {
			t.Errorf("tildeAt(%q) = %q, want %q", in, got, want)
		}
	}
}
