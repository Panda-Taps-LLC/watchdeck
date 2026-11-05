package manifest

import (
	"strings"
	"testing"
)

// TestPolicyModeParse: mode (shadow mode, Phase 6) parses to "" or
// "shadow"; enforce is normalised to ""; any other value, a non-string and
// a v1 file are errors that never echo the value. ParseOverrides agrees on
// error-ness for every row (the fuzz invariant).
func TestPolicyModeParse(t *testing.T) {
	for _, c := range []struct {
		name, in string
		want     string // Mode on success
		err      string // "" = no error; else a substring of the error
		exact    bool   // err must equal the message
		noValue  string // a value the error must not contain
	}{
		{"absent", "version: 2\n", "", "", false, ""},
		{"enforce", "version: 2\nmode: enforce\n", "", "", false, ""},
		{"shadow", "version: 2\nmode: shadow\n", ModeShadow, "", false, ""},
		{"case", "version: 2\nmode: Shadow\n", "", "mode: must be enforce or shadow", true, ""},
		// go-yaml decodes a scalar 1 into the string "1": the mode switch
		// refuses it, value-free like the decoder's own error.
		{"int", "version: 2\nmode: 1\n", "", "mode: must be enforce or shadow", true, ""},
		{"list", "version: 2\nmode: [shadow]\n", "", "invalid overrides", false, "[shadow]"},
		{"duplicate", "version: 2\nmode: shadow\nmode: shadow\n", "", "invalid overrides", false, ""},
		{"v1", "version: 1\nmode: shadow\n", "", "unknown field", false, "shadow"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f, err := ParsePolicyFile([]byte(c.in))
			_, oerr := ParseOverrides([]byte(c.in))
			if (err == nil) != (oerr == nil) {
				t.Fatalf("ParsePolicyFile err %v, ParseOverrides err %v", err, oerr)
			}
			if c.err == "" {
				if err != nil {
					t.Fatalf("err %v", err)
				}
				if f.Mode != c.want {
					t.Fatalf("Mode %q, want %q", f.Mode, c.want)
				}
				return
			}
			if err == nil {
				t.Fatalf("no error, Mode %q", f.Mode)
			}
			if c.exact && err.Error() != c.err {
				t.Fatalf("err %q, want %q", err, c.err)
			}
			if !strings.Contains(err.Error(), c.err) {
				t.Fatalf("err %q lacks %q", err, c.err)
			}
			if c.noValue != "" && strings.Contains(err.Error(), c.noValue) {
				t.Fatalf("err %q echoes the value", err)
			}
		})
	}
}
