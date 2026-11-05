package mapmodel

import (
	"fmt"
	"math"
	"unicode/utf8"
)

// Label geometry, so edge pills can be placed where no event label is.
// It mirrors the page: timeline.js labelSide and map.css .lab-right
// (left: 100% + 12px, centred), .lab-below (top: 100% + 8px, centred),
// .lab-above (bottom: 100% + 6px, left-aligned, sub clipped at 240px),
// .lab-upright (left: 100% + 10px, bottom: 50% + 5px, sub clipped at
// 240px); title 13px semibold, sub 11.5px mono, line-height 1.25; pills
// 11px mono with 8px side padding and a 1px border. Character widths are
// generous averages (mono is 0.6em), so the boxes err on the large side.
const (
	charTitle = 8.0
	charSub   = 7.0
	charPill  = 6.7
	lineTitle = 16.25
	lineSub   = 14.4
	subClip   = 240.0
	pillH     = 20.0
	pillPad   = 18.0 // padding plus border, both sides
	pillGap   = 4.0  // clearance kept around a pill
)

type box struct{ x0, y0, x1, y1 float64 }

func (a box) hits(b box) bool { return a.x0 < b.x1 && b.x0 < a.x1 && a.y0 < b.y1 && b.y0 < a.y1 }

func (a box) area(b box) float64 {
	w := math.Min(a.x1, b.x1) - math.Max(a.x0, b.x0)
	h := math.Min(a.y1, b.y1) - math.Max(a.y0, b.y0)
	if w <= 0 || h <= 0 {
		return 0
	}
	return w * h
}

func textW(s string, per float64) float64 { return float64(utf8.RuneCountInString(s)) * per }

// timelineLabelSide is timeline.js labelSide.
func timelineLabelSide(n Node) string {
	switch {
	case n.Kind == "sandbox":
		return "below"
	case n.Kind == "skill":
		return "above"
	case n.Kind == "tool" && (n.Tone == "ask" || n.Tone == "ok" || n.Tone == "deny"):
		return "upright"
	}
	return "right"
}

// labelBox is where the page draws a timeline event's label.
func labelBox(n Node) box {
	side := timelineLabelSide(n)
	sw := math.Max(textW(n.Sub, charSub), textW(n.Sub2, charSub))
	if side == "upright" || side == "above" {
		sw = math.Min(sw, subClip)
	}
	w := math.Max(textW(n.Label, charTitle), sw)
	h := lineTitle
	if n.Sub != "" {
		h += lineSub
	}
	if n.Sub2 != "" {
		h += lineSub
	}
	switch side {
	case "below":
		return box{n.X - w/2, n.Y + n.H/2 + 8, n.X + w/2, n.Y + n.H/2 + 8 + h}
	case "above":
		x0, y1 := n.X-n.W/2, n.Y-n.H/2-6
		return box{x0, y1 - h, x0 + w, y1}
	case "upright":
		x0, y1 := n.X+n.W/2+10, n.Y-5
		return box{x0, y1 - h, x0 + w, y1}
	}
	x0 := n.X + n.W/2 + 12
	return box{x0, n.Y - h/2, x0 + w, n.Y + h/2}
}

func nodeBox(n Node) box { return box{n.X - n.W/2, n.Y - n.H/2, n.X + n.W/2, n.Y + n.H/2} }

// pillBox is an edge label's pill centred on (x, y), with clearance.
func pillBox(label string, x, y float64) box {
	w := textW(label, charPill) + pillPad
	return box{x - w/2 - pillGap, y - pillH/2 - pillGap, x + w/2 + pillGap, y + pillH/2 + pillGap}
}

// placePills moves each labelled timeline edge's pill to the first spot
// along the edge, toward its target end first, above then below the line,
// that covers no event label, no node, no cut mark and no pill placed
// before it. When no spot is free the one with the least overlap wins.
func placePills(nodes []Node, edges []Edge) {
	byID := map[string]*Node{}
	var obstacles []box
	for i := range nodes {
		byID[nodes[i].ID] = &nodes[i]
		obstacles = append(obstacles, labelBox(nodes[i]), nodeBox(nodes[i]))
	}
	for _, e := range edges {
		if e.Cut != nil {
			obstacles = append(obstacles, box{e.Cut.X - 13, e.Cut.Y - 13, e.Cut.X + 13, e.Cut.Y + 13})
		}
	}
	ts := []float64{0.75, 0.85, 0.65, 0.55, 0.45, 0.35, 0.25, 0.95, 0.15}
	dys := []float64{-14, 14, -26, 26}
	for i := range edges {
		e := &edges[i]
		if e.Label == "" {
			continue
		}
		at, ok := edgeGeometry(e, byID)
		if !ok {
			continue
		}
		bestCost := math.Inf(1)
		var best [2]float64
	search:
		for ring := 0; ring < len(dys); ring += 2 {
			for _, t := range ts {
				px, py := at(t)
				for _, dy := range dys[ring : ring+2] {
					b := pillBox(e.Label, px, py+dy)
					cost := 0.0
					for _, o := range obstacles {
						cost += b.area(o)
					}
					if cost < bestCost {
						bestCost, best = cost, [2]float64{px, py + dy}
					}
					if bestCost == 0 {
						break search
					}
				}
			}
		}
		e.LX, e.LY = r1(best[0]), r1(best[1])
		obstacles = append(obstacles, pillBox(e.Label, e.LX, e.LY))
	}
}

// edgeGeometry returns the point at t along the visible part of an edge.
func edgeGeometry(e *Edge, byID map[string]*Node) (func(float64) (float64, float64), bool) {
	var x1, y1, x2 float64
	if n, _ := fmt.Sscanf(e.D, "M%g %g H%g", &x1, &y1, &x2); n == 3 {
		return func(t float64) (float64, float64) { return x1 + t*(x2-x1), y1 }, true
	}
	a, b := byID[e.From], byID[e.To]
	if a == nil || b == nil {
		return nil, false
	}
	x1, y1 = a.X+a.W/2+4, a.Y
	x2, y2 := b.X-b.W/2-4, b.Y
	span := 1.0
	if e.Cut != nil {
		span = 0.7 // the path stops at the cut
	}
	return func(t float64) (float64, float64) { return bez(x1, y1, x2, y2, t*span) }, true
}
