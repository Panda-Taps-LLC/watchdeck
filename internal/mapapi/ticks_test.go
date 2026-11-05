package mapapi

import (
	"encoding/json"
	"net/http"
	"testing"
)

// TestTicksView: ?view=ticks answers {session, ticks, totals, shown,
// updated} only, every tick names its authority, and the ETag works as for the full
// views (its own tag; 304 on a match).
func TestTicksView(t *testing.T) {
	e := newEnv(t)
	path := "/api/sessions/" + sidA + "/map?view=ticks"
	resp, b := e.get(t, path, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s = %d %s", path, resp.StatusCode, b)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("%v: %.300s", err, b)
	}
	for _, k := range []string{"session", "ticks", "totals", "shown", "updated"} {
		if _, ok := raw[k]; !ok {
			t.Errorf("missing %q", k)
		}
	}
	if len(raw) != 5 {
		keys := []string{}
		for k := range raw {
			keys = append(keys, k)
		}
		t.Errorf("keys = %v, want exactly session, ticks, totals, shown, updated", keys)
	}
	var body struct {
		Session struct {
			ID string `json:"id"`
		} `json:"session"`
		Ticks []struct {
			ID        string `json:"id"`
			Tool      string `json:"tool"`
			Authority string `json:"authority"`
		} `json:"ticks"`
		Totals struct {
			ByAuthority map[string]int `json:"by_authority"`
		} `json:"totals"`
		Updated string `json:"updated"`
	}
	if err := json.Unmarshal(b, &body); err != nil {
		t.Fatal(err)
	}
	if body.Session.ID != sidA || body.Updated == "" {
		t.Errorf("session %q updated %q", body.Session.ID, body.Updated)
	}
	if len(body.Ticks) != 6 {
		t.Fatalf("%d ticks, want 6", len(body.Ticks))
	}
	n := 0
	for _, tk := range body.Ticks {
		if tk.Authority == "" {
			t.Errorf("tick %s %s has no authority", tk.Tool, tk.ID)
		}
	}
	for _, c := range body.Totals.ByAuthority {
		n += c
	}
	if n != len(body.Ticks) {
		t.Errorf("by_authority %v sums to %d, want %d", body.Totals.ByAuthority, n, len(body.Ticks))
	}

	tag := resp.Header.Get("ETag")
	if tag == "" {
		t.Fatal("no ETag")
	}
	resp, b = e.get(t, path, map[string]string{"If-None-Match": tag})
	if resp.StatusCode != http.StatusNotModified || len(b) != 0 || resp.Header.Get("ETag") != tag {
		t.Fatalf("conditional GET = %d %q %q", resp.StatusCode, resp.Header.Get("ETag"), b)
	}
	// The topology tag is another view's tag.
	_, topoTag := e.mapOK(t, sidA, "topology", false)
	if topoTag == tag {
		t.Error("ticks and topology share a tag")
	}
	resp, _ = e.get(t, path, map[string]string{"If-None-Match": topoTag})
	if resp.StatusCode != http.StatusOK {
		t.Errorf("ticks with the topology tag = %d", resp.StatusCode)
	}
}
