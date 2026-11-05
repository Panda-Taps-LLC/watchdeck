package ui

import (
	"io/fs"
	"math"
	"strconv"
	"strings"
	"testing"
)

// cssBlock returns the declarations of the first rule whose selector text
// is exactly sel (up to its closing brace).
func cssBlock(t *testing.T, css, sel string) string {
	t.Helper()
	i := strings.Index(css, sel+" {")
	if i < 0 {
		t.Fatalf("no %s block", sel)
	}
	rest := css[i+len(sel)+2:]
	j := strings.Index(rest, "}")
	if j < 0 {
		t.Fatalf("%s block not closed", sel)
	}
	return rest[:j]
}

// cssToken reads "--name: value;" from the first block that defines it,
// resolving one var(--x) level against the same block list.
func cssToken(t *testing.T, blocks []string, name string) string {
	t.Helper()
	for _, b := range blocks {
		k := strings.Index(b, name+":")
		if k < 0 {
			continue
		}
		v := b[k+len(name)+1:]
		v = strings.TrimSpace(v[:strings.Index(v, ";")])
		if strings.HasPrefix(v, "var(") {
			return cssToken(t, blocks, strings.TrimSuffix(strings.TrimPrefix(v, "var("), ")"))
		}
		return v
	}
	t.Fatalf("token %s not defined", name)
	return ""
}

func relLum(t *testing.T, hex string) float64 {
	t.Helper()
	h := strings.TrimPrefix(hex, "#")
	if len(h) != 6 {
		t.Fatalf("not a #rrggbb colour: %q", hex)
	}
	var c [3]float64
	for i := range c {
		n, err := strconv.ParseUint(h[2*i:2*i+2], 16, 8)
		if err != nil {
			t.Fatalf("bad colour %q", hex)
		}
		x := float64(n) / 255
		if x <= 0.04045 {
			c[i] = x / 12.92
		} else {
			c[i] = math.Pow((x+0.055)/1.055, 2.4)
		}
	}
	return 0.2126*c[0] + 0.7152*c[1] + 0.0722*c[2]
}

func contrastRatio(t *testing.T, a, b string) float64 {
	la, lb := relLum(t, a), relLum(t, b)
	if la < lb {
		la, lb = lb, la
	}
	return (la + 0.05) / (lb + 0.05)
}

// Plan 05 Task 7 (2026-10-20): axe-core 4.13 measured three small-text
// pairs below WCAG AA (4.5:1): teal links #0E7C86 on --bg #EEF2F7 (4.39),
// live-map axis labels --cv-dim #6B7A90 on --cv-bg #0F1B2D (3.96), and the
// Settings command hint (--muted at opacity .85, #6F7A89 on #FFF, 4.35).
// Each text role is checked against the backgrounds it sits on in both
// themes; the floor is 4.6:1 so rounding never flips it. --accent itself
// is also a non-text fill (focus rings, switches, buttons with white text):
// white on it must stay 4.5:1 and it must keep 3:1 on the dark surfaces.
func TestThemeContrastPairs(t *testing.T) {
	b, err := fs.ReadFile(StaticFS, "static/app.css")
	if err != nil {
		t.Fatal(err)
	}
	css := string(b)
	light := []string{cssBlock(t, css, ":root")}
	dark := []string{cssBlock(t, css, `:root[data-theme="dark"]`), light[0]}
	themes := map[string][]string{"light": light, "dark": dark}

	type pair struct {
		fg, bg string
		min    float64
	}
	pairs := []pair{
		{"--link", "--bg", 4.6},
		{"--link", "--surface", 4.6},
		{"--link-hover", "--bg", 4.6},
		{"--link-hover", "--surface", 4.6},
		{"--cv-dim", "--cv-bg", 4.6},
		{"--cv-dim", "--cv-panel", 4.6},
		{"--muted", "--surface", 4.6},
		{"--muted", "--bg", 4.6},
	}
	for name, blocks := range themes {
		for _, p := range pairs {
			fg, bg := cssToken(t, blocks, p.fg), cssToken(t, blocks, p.bg)
			if r := contrastRatio(t, fg, bg); r < p.min {
				t.Errorf("%s: %s %s on %s %s = %.2f:1, want at least %.1f:1", name, p.fg, fg, p.bg, bg, r, p.min)
			}
		}
		acc := cssToken(t, blocks, "--accent")
		if r := contrastRatio(t, "#FFFFFF", acc); r < 4.5 {
			t.Errorf("%s: white on --accent %s = %.2f:1, want 4.5:1", name, acc, r)
		}
		if name == "dark" {
			for _, bg := range []string{"--bg", "--surface"} {
				if r := contrastRatio(t, acc, cssToken(t, blocks, bg)); r < 3 {
					t.Errorf("dark: --accent %s on %s = %.2f:1, want 3:1 (non-text)", acc, bg, r)
				}
			}
		}
	}

	// The hint's colour is --muted itself: an opacity on it is what pulled
	// it below AA, so it must carry none.
	p, err := fs.ReadFile(StaticFS, "static/pages.css")
	if err != nil {
		t.Fatal(err)
	}
	if blk := cssBlock(t, string(p), ".page-settings .set-cli"); strings.Contains(blk, "opacity") {
		t.Errorf(".set-cli sets an opacity (%s); it blends --muted below 4.5:1", strings.TrimSpace(blk))
	}
	// The auto-dark block must say the same as the forced one.
	i := strings.Index(css, "prefers-color-scheme: dark")
	auto := cssBlock(t, css[i:], `:root:not([data-theme="light"])`)
	for _, tok := range []string{"--accent", "--link", "--link-hover", "--muted"} {
		if a, d := strings.Contains(auto, tok+":"), strings.Contains(dark[0], tok+":"); a != d {
			t.Errorf("%s defined in one dark block only (auto %v, forced %v)", tok, a, d)
		} else if a && cssToken(t, []string{auto}, tok) != cssToken(t, dark[:1], tok) {
			t.Errorf("%s differs between the auto and forced dark blocks", tok)
		}
	}
}
