package mapapi

import (
	"net/http"
	"testing"
)

// TestCwdlessSessionsAndMap: with no Deps.Cwd (auto or service mode) the
// routes still list and map fixture A (its transcript is found through the
// path its records name and its recorded cwd), and ?project= is taken only
// for a known root.
func TestCwdlessSessionsAndMap(t *testing.T) {
	e := newEnv(t, func(d *Deps) {
		d.Cwd = ""
		d.ProjectRoots = func() []string { return []string{cwdA} }
	})
	rows := e.sessions(t)
	if len(rows) != 1 || rows[0].ID != sidA || rows[0].Source != "both" {
		t.Fatalf("cwd-less sessions = %+v", rows)
	}
	if resp, b := e.get(t, mapPath(sidA, "topology", false), nil); resp.StatusCode != 200 {
		t.Fatalf("cwd-less map = %d %s", resp.StatusCode, b)
	}
	if resp, b := e.get(t, "/api/sessions?project="+cwdA, nil); resp.StatusCode != 200 {
		t.Fatalf("sessions?project=known = %d %s", resp.StatusCode, b)
	}
	for _, bad := range []string{"/Users/you/other", "relative", cwdA + "/../proj", "/"} {
		for _, p := range []string{"/api/sessions?project=" + bad, mapPath(sidA, "topology", false) + "&project=" + bad} {
			if resp, b := e.get(t, p, nil); resp.StatusCode != http.StatusBadRequest {
				t.Errorf("%s = %d %s, want 400", p, resp.StatusCode, b)
			}
		}
	}
}
