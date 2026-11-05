package ui

import (
	"encoding/json"
	"os"
	"regexp"
	"testing"

	"github.com/Panda-Taps-LLC/watchdeck/internal/userconfig"
)

// Every test here uses emptyOptions: ConfigFile() is under t.TempDir().

type configView struct {
	Path            string  `json:"path"`
	Autostart       *bool   `json:"autostart"`
	InstalledAt     *string `json:"installed_at"`
	Nonce           string  `json:"nonce"`
	NonceTTLSeconds int     `json:"nonce_ttl_seconds"`
}

func getConfig(t *testing.T, ts *testServer) (configView, map[string]json.RawMessage) {
	t.Helper()
	resp, b := ts.do(t, req{Path: "/api/config", Token: ts.s.Token()})
	if resp.StatusCode != 200 {
		t.Fatalf("GET /api/config = %d %s", resp.StatusCode, b)
	}
	var v configView
	decode(t, b, &v)
	var raw map[string]json.RawMessage
	decode(t, b, &raw)
	return v, raw
}

func postConfig(t *testing.T, ts *testServer, body string) (int, []byte) {
	t.Helper()
	resp, b := ts.do(t, req{Method: "POST", Path: "/api/config", Body: body, Origin: "auto", Token: ts.s.Token(), Header: jsonCT()})
	return resp.StatusCode, b
}

func TestConfigGetShape(t *testing.T) {
	o := emptyOptions(t)
	ts := startServer(t, o)
	v, raw := getConfig(t, ts)
	if v.Path != o.Paths.ConfigFile() {
		t.Errorf("path = %q, want %q", v.Path, o.Paths.ConfigFile())
	}
	for _, k := range []string{"autostart", "installed_at"} {
		if string(raw[k]) != "null" {
			t.Errorf("%s = %s, want null on a fresh home", k, raw[k])
		}
	}
	if !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(v.Nonce) {
		t.Errorf("nonce = %q, want 32 hex", v.Nonce)
	}
	if v.NonceTTLSeconds != 300 {
		t.Errorf("nonce_ttl_seconds = %d, want 300", v.NonceTTLSeconds)
	}
	for k := range raw {
		switch k {
		case "path", "autostart", "installed_at", "nonce", "nonce_ttl_seconds":
		default:
			t.Errorf("unexpected key %q", k)
		}
	}
	if _, err := os.Stat(o.Paths.ConfigFile()); err == nil {
		t.Error("GET created the config file")
	}

	// A recorded answer and date come back.
	writeFile(t, o.Paths.ConfigFile(), "ui:\n  autostart: false\ninstalled_at: \"2026-10-19T08:30:15Z\"\n")
	v, _ = getConfig(t, ts)
	if v.Autostart == nil || *v.Autostart {
		t.Errorf("autostart = %v, want false", v.Autostart)
	}
	if v.InstalledAt == nil || *v.InstalledAt != "2026-10-19T08:30:15Z" {
		t.Errorf("installed_at = %v", v.InstalledAt)
	}
}

func TestConfigPostWritesAutostart(t *testing.T) {
	o := emptyOptions(t)
	ts := startServer(t, o)
	v, _ := getConfig(t, ts)
	code, b := postConfig(t, ts, `{"nonce":`+jsonString(v.Nonce)+`,"autostart":true}`)
	if code != 200 {
		t.Fatalf("POST = %d %s", code, b)
	}
	var res struct {
		Autostart *bool  `json:"autostart"`
		Nonce     string `json:"nonce"`
	}
	decode(t, b, &res)
	if res.Autostart == nil || !*res.Autostart {
		t.Errorf("response autostart = %v, want true", res.Autostart)
	}
	if res.Nonce == "" || res.Nonce == v.Nonce {
		t.Errorf("response nonce = %q, want a fresh one (spent %q)", res.Nonce, v.Nonce)
	}
	c, err := userconfig.Load(o.Paths.ConfigFile())
	if err != nil {
		t.Fatal(err)
	}
	if on, set := c.AutostartUI(); !on || !set {
		t.Errorf("file autostart = %v set=%v, want true", on, set)
	}

	// The fresh nonce is good for the next write.
	code, b = postConfig(t, ts, `{"nonce":`+jsonString(res.Nonce)+`,"autostart":false}`)
	if code != 200 {
		t.Fatalf("second POST = %d %s", code, b)
	}
	c, _ = userconfig.Load(o.Paths.ConfigFile())
	if on, set := c.AutostartUI(); on || !set {
		t.Errorf("file autostart = %v set=%v, want false", on, set)
	}
}

func TestConfigNonceOneUse(t *testing.T) {
	o := emptyOptions(t)
	ts := startServer(t, o)
	v, _ := getConfig(t, ts)
	body := `{"nonce":` + jsonString(v.Nonce) + `,"autostart":true}`
	if code, b := postConfig(t, ts, body); code != 200 {
		t.Fatalf("first POST = %d %s", code, b)
	}
	code, b := postConfig(t, ts, body)
	if code != 403 {
		t.Fatalf("second POST with the same nonce = %d %s, want 403", code, b)
	}
	var res struct {
		Error string `json:"error"`
		Nonce string `json:"nonce"`
	}
	decode(t, b, &res)
	if res.Nonce == "" {
		t.Error("403 carries no fresh nonce")
	}
	// A nonce of another purpose is refused too.
	en := getEnforce(t, ts).Nonce
	if code, _ := postConfig(t, ts, `{"nonce":`+jsonString(en)+`,"autostart":true}`); code != 403 {
		t.Errorf("enforce nonce on /api/config = %d, want 403", code)
	}
}

func TestConfigPostValidation(t *testing.T) {
	o := emptyOptions(t)
	ts := startServer(t, o)
	v, _ := getConfig(t, ts)
	for _, body := range []string{
		`{"autostart":true}`,
		`{"nonce":` + jsonString(v.Nonce) + `}`,
		`{"nonce":` + jsonString(v.Nonce) + `,"autostart":"yes"}`,
		`{"nonce":` + jsonString(v.Nonce) + `,"autostart":true,"extra":1}`,
	} {
		if code, b := postConfig(t, ts, body); code != 400 {
			t.Errorf("POST %s = %d %s, want 400", body, code, b)
		}
	}
	// None of those spent the nonce.
	if code, b := postConfig(t, ts, `{"nonce":`+jsonString(v.Nonce)+`,"autostart":true}`); code != 200 {
		t.Errorf("valid POST after 400s = %d %s", code, b)
	}
}
