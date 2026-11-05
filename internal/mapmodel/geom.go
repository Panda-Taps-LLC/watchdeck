package mapmodel

import (
	"math"
	"strconv"
	"strings"
)

// The arithmetic below is the one the Flow page was built against (B3's
// gen.py): endpoints offset by half the node width plus 4 px, a cubic with
// both control points at the horizontal midpoint, "H" when the ends are
// level, the cut at t = 0.7 shifted 14 px right with the path ending 13 px
// before it, labels at t = 0.5 lifted 14 px. Points are rounded to 0.1 px,
// widths to 0.01.

func r1(v float64) float64 { return math.Round(v*10) / 10 }

func num(v float64) string { return strconv.FormatFloat(r1(v), 'f', -1, 64) }

// width is §3.4's edge width for a call count.
func width(n int) float64 {
	if n <= 0 {
		return 1.5
	}
	w := 1.5 + 1.5*math.Log2(float64(n))
	w = math.Max(1.5, math.Min(6, w))
	return math.Round(w*100) / 100
}

// curve is the edge path from (x1,y1) to (x2,y2).
func curve(x1, y1, x2, y2 float64) string {
	if math.Abs(y1-y2) < 2 {
		return "M" + num(x1) + " " + num(y1) + " H" + num(x2)
	}
	mx := (x1 + x2) / 2
	var b strings.Builder
	b.WriteString("M" + num(x1) + " " + num(y1))
	b.WriteString(" C" + num(mx) + " " + num(y1) + " " + num(mx) + " " + num(y2) + " " + num(x2) + " " + num(y2))
	return b.String()
}

// bez is the point at t on curve's cubic.
func bez(x1, y1, x2, y2, t float64) (float64, float64) {
	mx := (x1 + x2) / 2
	u := 1 - t
	x := u*u*u*x1 + 3*u*u*t*mx + 3*u*t*t*mx + t*t*t*x2
	y := u*u*u*y1 + 3*u*u*t*y1 + 3*u*t*t*y2 + t*t*t*y2
	return r1(x), r1(y)
}

// link is an edge between two placed nodes, left to right. label, when
// set, sits at the midpoint; cut ends the path short of a cut mark.
func link(id, kind string, a, b *Node, label string, cut bool) Edge {
	x1 := a.X + a.W/2 + 4
	x2 := b.X - b.W/2 - 4
	y1, y2 := a.Y, b.Y
	e := Edge{ID: id, Kind: kind, From: a.ID, To: b.ID}
	if cut {
		cx, cy := bez(x1, y1, x2, y2, 0.7)
		cx = r1(cx + 14)
		e.D = curve(x1, y1, cx-13, cy)
		e.Cut = &Point{X: cx, Y: cy}
	} else {
		e.D = curve(x1, y1, x2, y2)
	}
	if label != "" {
		mx, my := bez(x1, y1, x2, y2, 0.5)
		e.Label, e.LX, e.LY = label, mx, r1(my-14)
	}
	return e
}
