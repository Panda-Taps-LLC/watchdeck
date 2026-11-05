package ui

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The walkthrough (scripts/walk) is a Node developer tool, not Go code, so
// these tests read its source and pin the two checks a later edit must not
// drop.

func readWalkSource(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("../../scripts/walk/" + name)
	if err != nil {
		t.Fatalf("read scripts/walk/%s: %v", name, err)
	}
	return string(b)
}

// TestWalkAxeAssertsRuleCount: axe.mjs fails a route on which axe ran no rule
// at all (passes + violations + incomplete == 0), so a page that never
// rendered, or an axe that never loaded, cannot pass vacuously.
func TestWalkAxeAssertsRuleCount(t *testing.T) {
	src := readWalkSource(t, "axe.mjs")
	re := regexp.MustCompile(`passes\.length\s*\+\s*\w+\.violations\.length\s*\+\s*\w+\.incomplete\.length\s*===\s*0`)
	if !re.MatchString(src) {
		t.Fatal("scripts/walk/axe.mjs has no zero-rules check (passes + violations + incomplete === 0)")
	}
}

// TestWalkCaptureGuardsToken: every screenshot call in walk.mjs (any
// receiver: page., p., a locator) is preceded, within the three lines before
// it, by the guard that throws when the hash still holds the token.
func TestWalkCaptureGuardsToken(t *testing.T) {
	src := readWalkSource(t, "walk.mjs")
	const guard = `if ((await page.evaluate(() => location.hash)).includes("t=")) throw new Error("token in hash")`
	shotCall := regexp.MustCompile(`\.screenshot\(`)
	lines := strings.Split(src, "\n")
	shots := 0
	for i, l := range lines {
		if !shotCall.MatchString(l) {
			continue
		}
		shots++
		found := false
		for j := i - 1; j >= 0 && j >= i-3; j-- {
			if strings.Contains(lines[j], guard) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("walk.mjs:%d: screenshot without the token guard in the three lines before it", i+1)
		}
	}
	if shots == 0 {
		t.Fatal("walk.mjs has no page.screenshot call")
	}
}

// TestWalkRedactsToken pins the launch token out of everything the walk
// prints (the workflow tees it into an uploaded artifact). Playwright's
// navigation errors repeat the launch URL, "#t=<token>" included. It checks,
// at grep level, in walk.mjs:
//   - a redact() helper exists that rewrites t=[A-Za-z0-9_-]+ and the token;
//   - every catch block uses redact( within its first three lines;
//   - every console.log / console.error line that prints an error-carrying
//     value (.message, .stack, .errors, .error, .expected, .actual, .failures)
//     goes through redact(;
//   - the launch goto sits inside a try, and uncaught errors and unhandled
//     rejections are printed through redact( too;
//   - the route table prints its final-hash cell as redact(r.hash ...), and
//     no print line shows r.hash bare.
//
// It does not prove every string is redacted at runtime; it stops a new
// catch or print line from skipping the helper.
func TestWalkRedactsToken(t *testing.T) {
	src := readWalkSource(t, "walk.mjs")
	if !regexp.MustCompile(`function redact\(`).MatchString(src) {
		t.Fatal("walk.mjs has no redact() helper")
	}
	if !strings.Contains(src, "t=[A-Za-z0-9_-]+") {
		t.Error("redact() does not rewrite t=[A-Za-z0-9_-]+")
	}
	for _, ev := range []string{`process.on("uncaughtException"`, `process.on("unhandledRejection"`} {
		if !strings.Contains(src, ev) {
			t.Errorf("walk.mjs has no %s handler", ev)
		}
	}
	lines := strings.Split(src, "\n")
	catchRe := regexp.MustCompile(`catch \(\w+\)\s*\{|\.catch\(\(?\w*\)?\s*=>`)
	printRe := regexp.MustCompile(`console\.(log|error)\(`)
	errField := regexp.MustCompile(`\.(message|stack|errors|error|expected|actual|failures)\b`)
	launch, hashCell := false, false
	for i, l := range lines {
		if catchRe.MatchString(l) && !strings.Contains(l, "() => {}") {
			ok := false
			for j := i; j < len(lines) && j <= i+3; j++ {
				if strings.Contains(lines[j], "redact(") {
					ok = true
					break
				}
			}
			if !ok {
				t.Errorf("walk.mjs:%d: catch without redact( in its first three lines", i+1)
			}
		}
		if printRe.MatchString(l) && errField.MatchString(printRe.ReplaceAllString(l, "")) && !strings.Contains(l, "redact(") {
			t.Errorf("walk.mjs:%d: prints an error value without redact(", i+1)
		}
		if printRe.MatchString(l) && strings.Contains(l, "r.hash") {
			if strings.Contains(l, "redact(r.hash") {
				hashCell = true
			} else {
				t.Errorf("walk.mjs:%d: prints the route table's hash cell without redact(", i+1)
			}
		}
		if strings.Contains(l, "page.goto(`${base}#t=${token}`)") && strings.Contains(l, "LAUNCH") {
			launch = true
			if i == 0 || !strings.Contains(lines[i-1], "try {") {
				t.Errorf("walk.mjs:%d: the launch goto is not the first line of a try block", i+1)
			}
		}
	}
	if !launch {
		t.Error("walk.mjs: no launch goto marked LAUNCH")
	}
	if !hashCell {
		t.Error("walk.mjs: the route table's hash cell is not printed through redact(r.hash")
	}
}

// TestWalkKeysNotVacuous: walk.mjs fails the keyboard pass when it ran no
// step (no routes, or a route with no steps).
func TestWalkKeysNotVacuous(t *testing.T) {
	src := readWalkSource(t, "keys.mjs")
	if !strings.Contains(src, "no key routes") || !strings.Contains(src, "route has no steps") {
		t.Error("keys.mjs does not fail an empty key script or a route with no steps")
	}
}
